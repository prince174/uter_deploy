#!/usr/bin/env bash
# Disposable, GitHub-hosted CI only. This is a keepalive experiment,
# not an ingress fence and not a production control.
set -euo pipefail

[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "${RUNNER_OS:-}" == Linux ]]
[[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]{1,16}$ && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]{1,4}$ ]]
[[ "$(id -u)" == 0 ]]
suffix="${GITHUB_RUN_ID: -7}${GITHUB_RUN_ATTEMPT}"
sender="uter-probe-s-$suffix"
receiver="uter-probe-r-$suffix"
sender_if="us$suffix"
receiver_if="ur$suffix"
[[ ${#sender_if} -le 15 && ${#receiver_if} -le 15 ]]
sender_created=0
receiver_created=0
link_created=0
server_pid=''
client_pid=''
workdir=''
cleanup() {
  local previous=$? failed=0
  trap - EXIT
  set +e
  if [[ -n "$client_pid" ]]; then kill "$client_pid" 2>/dev/null; wait "$client_pid" 2>/dev/null; fi
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null; wait "$server_pid" 2>/dev/null; fi
  if [[ "$link_created" == 1 ]] && ip link show dev "$sender_if" >/dev/null 2>&1; then
    ip link del "$sender_if" || failed=1
  fi
  if [[ "$sender_created" == 1 ]]; then ip netns del "$sender" || failed=1; fi
  if [[ "$receiver_created" == 1 ]]; then ip netns del "$receiver" || failed=1; fi
  if [[ -n "$workdir" ]]; then rm -f -- "$workdir/server.log"; rmdir -- "$workdir" || failed=1; fi
  if [[ "$failed" == 1 ]]; then previous=1; fi
  exit "$previous"
}
trap cleanup EXIT

# Never remove a pre-existing namespace if a name collision occurs.
ip netns add "$sender"
sender_created=1
ip netns add "$receiver"
receiver_created=1
ip link add "$sender_if" type veth peer name "$receiver_if"
link_created=1
ip link set "$sender_if" netns "$sender"
ip link set "$receiver_if" netns "$receiver"
ip -n "$sender" addr add 198.18.192.1/30 dev "$sender_if"
ip -n "$receiver" addr add 198.18.192.2/30 dev "$receiver_if"
ip -n "$sender" link set lo up
ip -n "$receiver" link set lo up
ip -n "$sender" link set "$sender_if" up
ip -n "$receiver" link set "$receiver_if" up

workdir="$(mktemp -d /tmp/uter-keepalive-probe.XXXXXXXX)"
ip netns exec "$receiver" /usr/bin/python3 -u scripts/compose_keepalive_ci_fixture.py server >"$workdir/server.log" 2>&1 &
server_pid=$!
for _ in {1..100}; do
  if [[ -s "$workdir/server.log" ]]; then break; fi
  kill -0 "$server_pid" 2>/dev/null || { echo 'Fixture server exited' >&2; exit 1; }
  sleep .05
done
[[ "$(cat "$workdir/server.log")" == READY ]]
coproc CLIENT { timeout 15s ip netns exec "$sender" /usr/bin/python3 -u scripts/compose_keepalive_ci_fixture.py client; }
client_pid=$CLIENT_PID
read -r -t 10 first <&"${CLIENT[0]}"
[[ "$first" == FIRST ]]
ip netns exec "$receiver" iptables -w -I INPUT 1 -p tcp --dport 8000 -m conntrack --ctstate NEW -j DROP
# A different TCP connection is denied while the already established one can
# still send another HTTP request over the identical socket.
ip netns exec "$sender" /usr/bin/python3 -c 'import socket; s=socket.socket(); s.settimeout(1); result=s.connect_ex(("198.18.192.2",8000)); s.close(); raise SystemExit(0 if result else 1)'
printf 'next\n' >&"${CLIENT[1]}"
read -r -t 10 second <&"${CLIENT[0]}"
[[ "$second" == SECOND ]]
wait "$client_pid"
client_pid=''
echo 'Observed: NEW connections were denied, but an established HTTP keepalive accepted a second request.'
echo 'This is one kernel experiment, not a complete ingress, quiescence, Redis or recovery proof.'
