#!/usr/bin/env bash
# One disposable GH-hosted kernel and distro NGINX; not a deployed fence.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "${RUNNER_OS:-}" == Linux ]]
[[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]{1,16}$ && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]{1,4}$ && "$(id -u)" == 0 ]]
suffix="${GITHUB_RUN_ID: -7}${GITHUB_RUN_ATTEMPT}"
sender="uter-proxy-s-$suffix";receiver="uter-proxy-r-$suffix"
sender_if="ps$suffix";receiver_if="pr$suffix"
[[ ${#sender_if} -le 15 && ${#receiver_if} -le 15 ]]
sender_created=0;receiver_created=0;link_created=0
server_pid='';proxy_pid='';client_pid='';workdir=''
cleanup() {
  local previous=$? failed=0
  trap - EXIT; set +e
  # Every child is owned by a timeout supervisor with a hard kill deadline.
  # Wait for those bounded supervisors; never signal a bare, reusable PID.
  for pid in "$client_pid" "$proxy_pid" "$server_pid"; do
    if [[ -n "$pid" ]]; then wait "$pid" 2>/dev/null; fi
  done
  if [[ "$link_created" == 1 ]] && ip link show dev "$sender_if" >/dev/null 2>&1; then ip link del "$sender_if" || failed=1; fi
  for entry in "$sender_created:$sender" "$receiver_created:$receiver"; do
    if [[ "${entry%%:*}" == 1 ]]; then
      ns="${entry#*:}"
      pids="$(ip netns pids "$ns")"; result=$?
      if [[ "$result" != 0 || -n "$pids" ]]; then
        echo 'Namespace still has processes or cannot be inspected' >&2
        failed=1
      else
        ip netns del "$ns" || failed=1
      fi
    fi
  done
  if [[ -n "$workdir" ]]; then
    rm -f -- "$workdir/server.log" "$workdir/nginx.log" "$workdir/nginx.conf" "$workdir/nginx.pid" "$workdir/release"
    rmdir -- "$workdir" || failed=1
  fi
  if [[ "$failed" == 1 ]]; then previous=1; fi
  exit "$previous"
}
trap cleanup EXIT
ip netns add "$sender";sender_created=1
ip netns add "$receiver";receiver_created=1
ip link add "$sender_if" type veth peer name "$receiver_if";link_created=1
ip link set "$sender_if" netns "$sender"
ip link set "$receiver_if" netns "$receiver"
ip -n "$sender" addr add 198.18.192.1/30 dev "$sender_if"
ip -n "$receiver" addr add 198.18.192.2/30 dev "$receiver_if"
ip -n "$sender" link set lo up;ip -n "$receiver" link set lo up
ip -n "$sender" link set "$sender_if" up;ip -n "$receiver" link set "$receiver_if" up
workdir="$(mktemp -d /tmp/uter-proxy-drain.XXXXXXXX)"
cat >"$workdir/nginx.conf" <<EOF
daemon off;
master_process on;
pid $workdir/nginx.pid;
worker_processes 1;
error_log stderr notice;
events { worker_connections 64; }
http {
  access_log off;
  server { listen 198.18.192.2:8080; location / { proxy_pass http://198.18.192.2:8000; proxy_buffering off; } }
}
EOF
timeout -s TERM -k 2s 25s ip netns exec "$receiver" /usr/bin/python3 -u scripts/compose_proxy_drain_ci_fixture.py server "$workdir/release" >"$workdir/server.log" 2>&1 &
server_pid=$!
for _ in {1..100}; do
  if [[ -s "$workdir/server.log" ]]; then break; fi
  kill -0 "$server_pid" 2>/dev/null || exit 1
  sleep .05
done
[[ "$(cat "$workdir/server.log")" == READY ]]
timeout -s TERM -k 2s 25s ip netns exec "$receiver" /usr/sbin/nginx -c "$workdir/nginx.conf" >"$workdir/nginx.log" 2>&1 &
proxy_pid=$!
for _ in {1..100}; do
  if [[ -s "$workdir/nginx.pid" ]]; then break; fi
  kill -0 "$proxy_pid" 2>/dev/null || { cat "$workdir/nginx.log" >&2; exit 1; }
  sleep .05
done
nginx_pid="$(cat "$workdir/nginx.pid")"
[[ "$nginx_pid" =~ ^[1-9][0-9]{0,9}$ ]]
coproc CLIENT { timeout 20s ip netns exec "$sender" /usr/bin/python3 -u scripts/compose_proxy_drain_ci_fixture.py client; }
client_pid=$CLIENT_PID
read -r -t 10 first <&"${CLIENT[0]}"
[[ "$first" == STREAM ]]
# Pin the exact process with pidfd before checking the unique configuration,
# executable and netns; a recycled numeric PID cannot receive this signal.
/usr/bin/python3 -c 'import os,signal,sys
pid=int(sys.argv[1]); fd=os.pidfd_open(pid)
try:
    if os.path.realpath("/proc/%d/exe"%pid)!=os.path.realpath("/usr/sbin/nginx"): raise ValueError()
    if os.fsencode(sys.argv[2]) not in open("/proc/%d/cmdline"%pid,"rb").read(): raise ValueError()
    if os.stat("/proc/%d/ns/net"%pid).st_ino!=os.stat("/run/netns/"+sys.argv[3]).st_ino: raise ValueError()
    signal.pidfd_send_signal(fd,signal.SIGQUIT)
finally: os.close(fd)' "$nginx_pid" "$workdir/nginx.conf" "$receiver"
# The upstream remains blocked until release. Verify the public listener stops
# accepting new connections while the original response is still in flight.
closed=0
for _ in {1..100}; do
  if ip netns exec "$sender" /usr/bin/python3 -c 'import socket; s=socket.socket(); s.settimeout(.1); result=s.connect_ex(("198.18.192.2",8080)); s.close(); raise SystemExit(0 if result else 1)'; then
    closed=1;break
  fi
  kill -0 "$proxy_pid" 2>/dev/null || { echo 'Proxy exited before releasing the stream' >&2; exit 1; }
  sleep .05
done
[[ "$closed" == 1 ]]
kill -0 "$proxy_pid" 2>/dev/null
touch "$workdir/release"
read -r -t 15 result <&"${CLIENT[0]}"
[[ "$result" == COMPLETE ]]
wait "$client_pid";client_pid=''
wait "$proxy_pid";proxy_pid=''
ip netns exec "$sender" /usr/bin/python3 -c 'import socket; s=socket.socket(); s.settimeout(1); result=s.connect_ex(("198.18.192.2",8080)); s.close(); raise SystemExit(0 if result else 1)'
echo 'Observed: NGINX QUIT completed one active streamed response and closed its listener.'
echo 'This experiment does not verify bypass prevention, process identity, restart fencing, Redis or recovery.'
