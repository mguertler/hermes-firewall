#!/bin/bash
# Removes hermes-firewall from THIS host (first: sudo hermes-firewall remove PROFILE).
#   sudo ./uninstall.sh            keep /etc/hermes-firewall/config.toml
#   sudo ./uninstall.sh --purge    also remove the settings
set -Eeuo pipefail
[[ $# -eq 0 || ( $# -eq 1 && $1 == --purge ) ]] || { echo 'Usage: sudo ./uninstall.sh [--purge]' >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo 'Run with sudo: sudo ./uninstall.sh' >&2; exit 1; }
exec /usr/local/bin/hermes-firewall uninstall "$@"
