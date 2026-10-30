#!/usr/bin/env bash
# Disposable, GitHub-hosted CI only. This is a kernel behavior experiment,
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
cleanup() {
  local previous=$? failed=0
  trap - EXIT
  set +e
  if [[ "$link_created" == 1 ]] && ip link show dev "$sender_if" >/dev/null 2>&1; then
    ip link del "$sender_if" || failed=1
  fi
  if [[ "$sender_created" == 1 ]]; then ip netns del "$sender" || failed=1; fi
  if [[ "$receiver_created" == 1 ]]; then ip netns del "$receiver" || failed=1; fi
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

ip netns exec "$receiver" iptables -w -A INPUT -p tcp --dport 8000 -m conntrack --ctstate ESTABLISHED -j ACCEPT
ip netns exec "$receiver" iptables -w -A INPUT -p tcp --dport 8000 -j DROP
ip netns exec "$sender" iptables -w -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
send_ack() {
  ip netns exec "$sender" /usr/bin/python3 -c \
    'import sys; from scapy.all import IP,TCP,send; send(IP(src="198.18.192.1",dst="198.18.192.2")/TCP(sport=int(sys.argv[1]),dport=8000,flags="A",seq=1,ack=1),verbose=False)' "$1"
}
send_reply_ack() {
  ip netns exec "$receiver" /usr/bin/python3 -c \
    'import sys; from scapy.all import IP,TCP,send; send(IP(src="198.18.192.2",dst="198.18.192.1")/TCP(sport=8000,dport=int(sys.argv[1]),flags="A",seq=1,ack=1),verbose=False)' "$1"
}
probe() {
  # conntrack distinguishes its TCP protocol state from the firewall's
  # ESTABLISHED classification, which also requires a reply direction.
  send_ack "$1"
  send_reply_ack "$1"
  send_ack "$1"
}
accepted() {
  ip netns exec "$receiver" iptables -w -nvxL INPUT | awk '$3 == "ACCEPT" { print $1 }'
}
set_loose() {
  ip netns exec "$receiver" sysctl -q -w "net.netfilter.nf_conntrack_tcp_loose=$1"
  [[ "$(ip netns exec "$receiver" sysctl -n net.netfilter.nf_conntrack_tcp_loose)" == "$1" ]]
}

set_loose 1
probe 41001
observed="$(accepted)"
[[ "$observed" == 1 ]] || {
  printf 'Loose-mode ESTABLISHED packet count was %s, expected 1\n' "$observed" >&2
  ip netns exec "$receiver" iptables -w -nvxL INPUT >&2
  exit 1
}
ip netns exec "$receiver" iptables -w -Z INPUT
set_loose 0
probe 41002
observed="$(accepted)"
[[ "$observed" == 0 ]] || {
  printf 'Strict-mode ESTABLISHED packet count was %s, expected 0\n' "$observed" >&2
  ip netns exec "$receiver" iptables -w -nvxL INPUT >&2
  exit 1
}
echo 'Observed: loose mode classified an unrelated ACK as ESTABLISHED; strict mode did not.'
echo 'This is one kernel experiment, not a complete ingress, quiescence, Redis or recovery proof.'
