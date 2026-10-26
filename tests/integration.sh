#!/bin/bash
# Opt-in live test with real Docker on a host where hermes-firewall is installed.
# Use an UNUSED test profile that was added before:  sudo hermes-firewall add fwtest
# NEVER use a profile somebody works with: the test opens and closes its leases.
#   sudo bash tests/integration.sh fwtest
set -Eeuo pipefail
export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset DOCKER_CONTEXT DOCKER_CONFIG
export DOCKER_HOST=unix:///var/run/docker.sock
[[ $EUID -eq 0 && $# -eq 1 ]] || { echo 'Run: sudo bash tests/integration.sh UNUSED_TEST_PROFILE' >&2; exit 1; }
profile=$1
network=hermes-fw-$profile
hermes-firewall status "$profile" >/dev/null
[[ -z $(docker ps -aq --filter "network=$network") ]] || { echo 'The profile network is in use; refusing test.' >&2; exit 1; }
mapfile -t dns < <(python3 -I -c 'import tomllib; [print(s) for s in tomllib.load(open("/etc/hermes-firewall/config.toml", "rb"))["sandbox"]["dns"]]')
dns_args=()
for server in "${dns[@]}"; do dns_args+=("--dns=$server"); done
name="hermes-firewall-check-$$"
cleanup() {
    local code=$?
    trap - EXIT
    hermes-firewall close "$profile" >/dev/null || code=1
    docker rm -f "$name" >/dev/null 2>&1 || true
    exit "$code"
}
trap cleanup EXIT
sandbox() {
    docker run --rm -i --name "$name" --network "$network" "${dns_args[@]}" --cap-drop ALL \
        --security-opt no-new-privileges --pids-limit 64 --memory 128m python:3.13-alpine python - "$@"
}
docker pull -q python:3.13-alpine >/dev/null

echo '1. CLOSED: names resolve (DNS is always open), but no connection gets out.'
hermes-firewall close "$profile"
sandbox <<'PY'
import socket
address = socket.gethostbyname("example.com")
print("PASS: DNS works while CLOSED", flush=True)
for target in ((address, 443), ("1.1.1.1", 443)):
    try:
        socket.create_connection(target, timeout=3).close()
    except OSError:
        print(f"PASS: {target[0]} blocked", flush=True)
    else:
        raise SystemExit(f"FAIL: {target[0]} is reachable while CLOSED")
PY

echo '2. OPEN internet 30s: HTTPS works, then the kernel closes the lease, also for open connections.'
hermes-firewall open "$profile" 30s
sandbox <<'PY'
import socket, time, urllib.request
with urllib.request.urlopen("https://example.com/", timeout=8) as response:
    assert response.read(1), "Empty HTTPS response"
print("PASS: HTTPS works while OPEN", flush=True)
connection = socket.create_connection((socket.gethostbyname("example.com"), 80), timeout=3)
try:
    socket.create_connection(("2606:4700:4700::1111", 443), timeout=3).close()
    print("INFO: IPv6 Internet reachable", flush=True)
except OSError:
    print("INFO: no IPv6 Internet from the sandbox (ipv6 off or host without IPv6)", flush=True)
print("Waiting 32s for the lease to expire ...", flush=True)
time.sleep(32)
connection.settimeout(3)
try:
    connection.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    payload = connection.recv(1024)
except socket.timeout:
    print("PASS: the open connection gets no answer after expiry", flush=True)
else:
    raise SystemExit("FAIL/INCONCLUSIVE: expected a timeout, received %r" % payload[:80])
finally:
    connection.close()
try:
    socket.create_connection(("1.1.1.1", 443), timeout=3).close()
except OSError:
    print("PASS: new connections blocked after expiry", flush=True)
else:
    raise SystemExit("FAIL: still open after expiry")
PY

echo '3. The host itself stays blocked, also with an open lease.'
hermes-firewall open "$profile" all 1m
gateway=$(docker network inspect "$network" --format '{{range .IPAM.Config}}{{.Gateway}} {{end}}' \
          | tr ' ' '\n' | grep -m1 '\.')
sandbox "$gateway" <<'PY'
import socket, sys
try:
    socket.create_connection((sys.argv[1], 22), timeout=3).close()
except OSError:
    print("PASS: host blocked", flush=True)
else:
    raise SystemExit("FAIL: the host is reachable from the sandbox")
PY
hermes-firewall close "$profile"
echo 'Network tests passed. Boot ordering and the real Hermes sandbox still need a manual check (see TESTING.md).'
