#!/bin/bash
# Installs or upgrades hermes-firewall on THIS host. Run from the repository:
#   sudo ./install.sh
set -Eeuo pipefail
[[ $# -eq 0 ]] || { echo 'Usage: sudo ./install.sh' >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo 'Run with sudo: sudo ./install.sh' >&2; exit 1; }
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

fail() { echo "ERROR: $*" >&2; exit 1; }
for command in python3 nft docker systemctl ip ss runuser visudo; do
    PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v "$command" >/dev/null || fail "missing program: $command"
done
python=$(PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v python3)
"$python" -c 'import sys; sys.exit(sys.version_info < (3, 11))' || fail "Python 3.11 or newer is required"
[[ -d /run/systemd/system ]] || fail "systemd is required"

# Root runs the files from a private copy, so nobody can change them in between.
work=$(mktemp -d /tmp/hermes-firewall-install.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/plugin/hermes-firewall"
cp -- "$here/hermes_firewall.py" "$here/config.example.toml" "$work/"
cp -- "$here/plugin/hermes-firewall/plugin.yaml" "$here/plugin/hermes-firewall/__init__.py" "$work/plugin/hermes-firewall/"

if [[ -e /etc/hermes-firewall/profiles.json ]]; then
    "$python" -I "$work/hermes_firewall.py" --bundle="$work" upgrade
else
    "$python" -I "$work/hermes_firewall.py" --bundle="$work" install
    # The installer has exited and released its lock before ExecStart takes it.
    systemctl start hermes-firewall.service hermes-firewall-refresh.timer
fi
