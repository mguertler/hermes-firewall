#!/bin/bash
# Packet-level test of the generated nft rules WITHOUT root and without touching
# the host: a private user+network namespace plays the Hermes host (router +
# firewall) with a sandbox, a LAN and an Internet namespace, IPv4 and IPv6.
# Needs nft (NFT=/path/to/nft to override), unshare, nsenter, ip, python3.
set -Eeuo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
if [[ ${HFW_NETNS_INSIDE:-} != 1 ]]; then
    export HFW_NETNS_INSIDE=1 NFT=${NFT:-nft}
    exec unshare -rn --fork "$BASH" "${BASH_SOURCE[0]}"
fi

work=$(mktemp -d)
pids=()
# shellcheck disable=SC2317  # called via trap
cleanup() { kill "${pids[@]}" 2>/dev/null || true; rm -rf -- "$work"; }
trap cleanup EXIT

# Firewall input as hermes-firewall generates it from this configuration:
# LAN 192.168.0.0/24, fd00:1::/64 and 2a01:db8:1:2::/64, LAN host lanhost.test
# resolving to its external address 93.184.1.7, DNS 192.168.0.5 and
# 2606:4700:4700::1111, allow 192.168.0.2 tcp 8088 and 203.0.113.0/24 (all
# ports), Hermes egress proxy 172.17.0.1:9090 (docker0 of the host).
read -r bridge subnet6 < <(python3 -I - "$here/../hermes_firewall.py" "$work" <<'PY'
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("fw", sys.argv[1])
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)
out = Path(sys.argv[2])
fw.resolve_host = lambda host, servers: ["93.184.1.7"]
fw.nat64_prefixes = lambda servers: [fw.NAT64_WKP]
conf = {"lan_networks": ["192.168.0.0/24", "fd00:1::/64", "2a01:db8:1:2::/64"], "lan_hosts": ["lanhost.test"],
        "dns": ["192.168.0.5", "2606:4700:4700::1111"], "egress_proxy": True,
        "allow": [{"net": "192.168.0.2/32", "tcp": [8088], "udp": []},
                  {"net": "203.0.113.0/24", "tcp": [], "udp": []}]}
sets = {**fw.common_sets(conf), "host_ports_v4": ["172.17.0.1 . tcp . 9090"]}
(out / "rules.nft").write_text(fw.rules("netns-test", sets))
for name, kinds in (("lan", ("lan",)), ("internet", ("internet",)), ("all", fw.KINDS)):
    (out / f"open-{name}.nft").write_text(fw.lease_transaction("netns-test")
                                          + fw.lease_transaction("netns-test", kinds, 600))
(out / "closed.nft").write_text(fw.lease_transaction("netns-test"))
item = fw.identity("netns-test")
print(item["bridge"], item["subnet6"].split("::")[0])
PY
)

cat > "$work/serve.py" <<'PY'
import socket, subprocess, threading
def tcp(port):
    s = socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.bind(("::", port)); s.listen()
    while True:
        s.accept()[0].close()
def udp(address, port):
    # One socket per address, so replies come from the queried address like real DNS.
    s = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((address, port))
    while True:
        data, peer = s.recvfrom(64); s.sendto(data, peer)
threads = [(tcp, (port,)) for port in (80, 53, 8088, 9090)]
threads += [(udp, (a, 53)) for a in subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split()]
for target, arguments in threads:
    threading.Thread(target=target, args=arguments, daemon=True).start()
threading.Event().wait()
PY
cat > "$work/probe.py" <<'PY'
import socket, sys, threading
targets = [line.split() for line in sys.stdin.read().splitlines() if line.strip()]
results = [None] * len(targets)
def probe(index, kind, host, port):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        if kind == "tcp":
            s = socket.socket(family); s.settimeout(1.5); s.connect((host, int(port))); s.close()
        else:
            # Retry once like real resolvers: the first packet may wait for neighbour discovery.
            s = socket.socket(family, socket.SOCK_DGRAM); s.settimeout(0.75)
            for attempt in (1, 2):
                s.sendto(b"q", (host, int(port)))
                try:
                    s.recvfrom(64)
                    break
                except socket.timeout:
                    if attempt == 2:
                        raise
        results[index] = "open"
    except OSError:
        results[index] = "blocked"
threads = [threading.Thread(target=probe, args=(i, *t[1:])) for i, t in enumerate(targets)]
for t in threads: t.start()
for t in threads: t.join()
print(" ".join(results))
PY

spawn() { unshare -n sleep 300 >/dev/null 2>&1 & pids+=("$!"); }
ns() { local pid=$1; shift; nsenter -t "$pid" -n --preserve-credentials "$@"; }
spawn; sandbox=${pids[-1]}; spawn; lan=${pids[-1]}; spawn; internet=${pids[-1]}
sleep 0.3

echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
ip link set lo up
ip link add docker0 type dummy; ip addr add 172.17.0.1/16 dev docker0; ip link set docker0 up
ip link add "$bridge" type bridge
ip addr add 172.30.0.1/24 dev "$bridge"; ip addr add "$subnet6::1/64" dev "$bridge" nodad
ip link set "$bridge" up
ip link add vs type veth peer name eth0 netns "$sandbox"; ip link set vs master "$bridge" up
ip link add vl type veth peer name eth0 netns "$lan"
ip addr add 192.168.0.1/24 dev vl; ip addr add fd00:1::1/64 dev vl nodad; ip addr add 2a01:db8:1:2::1/64 dev vl nodad
ip link set vl up
ip link add vi type veth peer name eth0 netns "$internet"
ip addr add 93.184.0.1/24 dev vi; ip addr add 2001:db8:ff::1/64 dev vi nodad; ip link set vi up
ip route add default via 93.184.0.10
ip -6 route add default via 2001:db8:ff::10
ns "$sandbox" sh -c "ip link set lo up; ip addr add 172.30.0.2/24 dev eth0; ip addr add $subnet6::2/64 dev eth0 nodad
                     ip link set eth0 up; ip route add default via 172.30.0.1; ip -6 route add default via $subnet6::1"
# shellcheck disable=SC2016  # $a expands in the inner shell
ns "$lan" sh -c 'ip link set lo up; for a in 10 5 2; do ip addr add 192.168.0.$a/24 dev eth0; done
                 ip addr add fd00:1::10/64 dev eth0 nodad; ip addr add 2a01:db8:1:2::10/64 dev eth0 nodad
                 ip link set eth0 up; ip route add default via 192.168.0.1; ip -6 route add default via fd00:1::1'
# shellcheck disable=SC2016  # $a expands in the inner shell
ns "$internet" sh -c 'ip link set lo up; ip addr add 93.184.0.10/24 dev eth0; ip addr add 2001:db8:ff::10/64 dev eth0 nodad
                      for a in 93.184.1.7 9.9.9.9 203.0.113.50 10.0.0.1; do ip addr add $a/32 dev eth0; done
                      for a in 2606:4700::10 2606:4700:4700::1111 64:ff9b::5db8:a 64:ff9b::c0a8:a 64:ff9b::a00:1 \
                               2002:c0a8:a::1; do ip addr add $a/128 dev eth0 nodad; done
                      ip link set eth0 up; ip route add default via 93.184.0.1; ip -6 route add default via 2001:db8:ff::1'
ns "$lan" python3 -I "$work/serve.py" >/dev/null 2>&1 & pids+=("$!")
ns "$internet" python3 -I "$work/serve.py" >/dev/null 2>&1 & pids+=("$!")
python3 -I "$work/serve.py" >/dev/null 2>&1 & pids+=("$!")   # services on the host itself
sleep 0.5
"$NFT" -f "$work/rules.nft"

# name  target  expected in: closed  open-lan  open-internet  open-all  (o = open, - = blocked)
matrix="
lan-host       tcp 192.168.0.10 80          - o - o
lan-ext-addr   tcp 93.184.1.7 80            - o - o
internet       tcp 93.184.0.10 80           - - o o
dns-udp        udp 192.168.0.5 53           o o o o
dns-tcp        tcp 192.168.0.5 53           o o o o
allow-port     tcp 192.168.0.2 8088         o o o o
lan-other-port tcp 192.168.0.2 80           - o - o
public-dns     udp 9.9.9.9 53               - - o o
lan-port-53    udp 192.168.0.10 53          - o - o
allow-net      tcp 203.0.113.50 80          o o o o
other-private  tcp 10.0.0.1 80              - - - -
host-via-lan   tcp 192.168.0.1 80           - - - -
host-bridge    tcp 172.30.0.1 80            - - - -
egress-proxy   tcp 172.17.0.1 9090          o o o o
host-other     tcp 172.17.0.1 80            - - - -
lan6-ula       tcp fd00:1::10 80            - o - o
lan6-global    tcp 2a01:db8:1:2::10 80      - o - o
internet6      tcp 2606:4700::10 80         - - o o
dns6           udp 2606:4700:4700::1111 53  o o o o
nat64-public   tcp 64:ff9b::5db8:a 80       - - o o
nat64-lan      tcp 64:ff9b::c0a8:a 80       - o - o
nat64-private  tcp 64:ff9b::a00:1 80        - - - -
6to4           tcp 2002:c0a8:a::1 80        - - - -
host6-bridge   tcp $subnet6::1 80           - - - -
"
targets=$(awk 'NF {print $1, $2, $3, $4}' <<< "$matrix")
targets=${targets//\$subnet6/$subnet6}
failed=0
# Warm-up round (not evaluated): fills the IPv6 neighbour caches of all namespaces.
"$NFT" -f "$work/open-all.nft"
ns "$sandbox" python3 -I "$work/probe.py" <<< "$targets" >/dev/null
for state in closed open-lan open-internet open-all closed; do
    column=$(( $(tr ' ' '\n' <<< "closed open-lan open-internet open-all" | grep -nx "$state" | cut -d: -f1) + 4 ))
    expected=$(awk -v c="$column" 'NF {print ($c == "o" ? "open" : "blocked")}' <<< "$matrix" | tr '\n' ' ')
    "$NFT" -f "$work/$state.nft"
    got=$(ns "$sandbox" python3 -I "$work/probe.py" <<< "$targets")
    read -ra got_list <<< "$got"; read -ra expected_list <<< "$expected"
    wrong=()
    for i in "${!expected_list[@]}"; do
        [[ ${got_list[i]} == "${expected_list[i]}" ]] \
            || wrong+=("$(awk -v n=$((i + 1)) 'NF && ++k == n {print $1}' <<< "$matrix")=${got_list[i]}")
    done
    if ((${#wrong[@]})); then
        printf '%-14s FAIL: %s\n' "$state" "${wrong[*]}"; failed=1
    else
        printf '%-14s ok (%d targets)\n' "$state" "${#expected_list[@]}"
    fi
done
exit "$failed"
