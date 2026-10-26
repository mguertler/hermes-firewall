#!/bin/bash
# Portability check in containers of other distributions: required programs and
# paths, Python version, unit tests, the generated rules with that distribution's
# nft and the sudoers file with its visudo. Needs Docker (any test host).
#   bash tests/distros.sh [IMAGE ...]
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
images=("$@")
((${#images[@]})) || images=(debian:12 debian:13 ubuntu:24.04 fedora:42 archlinux:latest opensuse/tumbleweed:latest)

# shellcheck disable=SC2016  # runs inside the container
check='set -e
cd /src
PATH=/usr/sbin:/usr/bin:/sbin:/bin
for c in python3 nft ip ss runuser visudo; do command -v "$c" >/dev/null || { echo "missing: $c"; exit 1; }; done
python3 -c "import sys; sys.exit(sys.version_info < (3, 11))" || { echo "Python too old: $(python3 -V)"; exit 1; }
python3 -B -m unittest discover -s tests >/tmp/unit.log 2>&1 || { tail -20 /tmp/unit.log; exit 1; }
python3 -I -B - <<PY
import importlib.util
spec = importlib.util.spec_from_file_location("fw", "hermes_firewall.py")
fw = importlib.util.module_from_spec(spec); spec.loader.exec_module(fw)
sets = {"lan_v4": ["192.168.0.0/24"], "lan_v6": ["fd00::/64"], "dns_v4": ["192.168.0.5"],
        "allow_ports_v4": ["192.168.0.2/32 . tcp . 8088"], "non_public_v6": list(fw.NONPUBLIC_V6),
        "host_ports_v4": ["172.17.0.1 . tcp . 9090"]}
open("/tmp/rules.nft", "w").write(fw.rules("distro-check", sets) + fw.lease_transaction("distro-check", fw.KINDS, 60))
open("/tmp/sudoers", "w").write(fw.sudoers_text({"version": 2, "profiles": {"distro-check": {
    "user": "root", "ipv6": False, "label": "distro-check", "dns": []}}}))
PY
nft -c -f /tmp/rules.nft
visudo -cf /tmp/sudoers >/dev/null
main=/etc/sudoers; [[ -e $main ]] || main=/usr/etc/sudoers
grep -Eq "^[@#]includedir[[:space:]]+/etc/sudoers.d" "$main" || echo "note: $main has no includedir /etc/sudoers.d"
echo "ok: $(. /etc/os-release; echo "$PRETTY_NAME"), $(python3 -V), $(nft --version | cut -d" " -f1-2)"'

failed=0
for image in "${images[@]}"; do
    case $image in
        debian*|ubuntu*) install='apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 nftables iproute2 sudo util-linux >/dev/null' ;;
        fedora*) install='dnf -y -q install python3 nftables iproute sudo util-linux >/dev/null' ;;
        archlinux*) install='pacman -Sy --noconfirm --quiet python nftables iproute2 sudo util-linux >/dev/null' ;;
        opensuse*) install='zypper -q -n install python3 nftables iproute2 sudo util-linux >/dev/null' ;;
        *) echo "$image: unknown package manager"; failed=1; continue ;;
    esac
    printf '%-28s ' "$image"
    # NET_ADMIN only inside the container's own network namespace, for nft -c.
    docker run --rm --cap-add NET_ADMIN -v "$root:/src:ro" "$image" bash -c "$install && $check" 2>&1 | tail -3 \
        || failed=1
done
exit "$failed"
