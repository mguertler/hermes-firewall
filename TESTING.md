# Testing

## Automatic tests (no root)

```bash
python3 -m unittest discover -s tests -v     # unit tests: program and plugin, no root/daemons/network
bash tests/netns.sh                          # packet test of the real rules, needs nft (NFT=/path/to/nft)
shellcheck install.sh uninstall.sh tests/*.sh
```

`tests/netns.sh` runs in a private user + network namespace: the namespace plays the
Hermes host (router + firewall, docker0 with an egress proxy), with a sandbox, a LAN and
an Internet namespace, IPv4 and IPv6. It loads the generated rules with nft and checks
24 targets in the states closed / lan / internet / all / closed again: LAN hosts, the
public address of a LAN host, Internet, DNS (IPv4 and IPv6), `[[allow]]` address and
network, other private networks, the host itself, the egress proxy, IPv6 ULA and global
LAN prefixes, NAT64 (public, LAN and private embedded addresses) and 6to4. It must pass
after every rule change. A quick mutation check (e.g. let `nat64()` return `[]`) shows
that it catches bypasses.

The CI workflow (`.github/workflows/ci.yml`) runs all three on Ubuntu.

### nft without root

If nft is not installed, unpack the Debian packages locally:

```bash
S=$(mktemp -d); cd "$S"
apt-get download nftables libnftables1 libnftnl11 libjansson4 libmnl0 libxtables12 libedit2 libbsd0 libmd0
for d in *.deb; do dpkg-deb -x "$d" root; done
printf '#!/bin/sh\nLD_LIBRARY_PATH=%s/root/usr/lib/x86_64-linux-gnu exec %s/root/usr/sbin/nft "$@"\n' "$S" "$S" > nft
chmod +x nft; cd -; NFT=$S/nft bash tests/netns.sh
```

On Ubuntu 24.04+ unprivileged user namespaces may need
`sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`.

## Live test (root, Docker; opt-in)

Only on a host where nothing important runs, with an unused test profile:

```bash
hermes profile create fwtest                 # or any unused Hermes profile
sudo ./install.sh
sudo hermes-firewall add fwtest
sudo bash tests/integration.sh fwtest        # closed / open 30s / expiry / host blocked
sudo hermes-firewall remove fwtest
```

## Manual checks before a release

Not covered automatically; record the result (distribution, versions, date) below.

1. Boot: after a reboot `status` shows all profiles closed; Docker started after the
   firewall; with `docker_requires_firewall = true` a broken firewall keeps Docker down.
2. A real Hermes session (gateway + `/firewall open`, `/firewall status`, `/firewall close`)
   and a sandbox command (`curl`) in each state.
3. `add` on a profile with an existing persistent sandbox: it is moved; a sandbox with
   `--network=host` asks for a reset.
4. `remove`: new sessions have no network; `add` again works.
5. IPv6 (host with IPv6): `open` reaches IPv6 sites, closed does not.
6. Hermes egress proxy (`hermes egress setup/start`): reachable from the sandbox in every
   state, other host ports not.
7. `sudo ./install.sh` again (upgrade) keeps leases open; `uninstall.sh` and `--purge`.
8. Distributions: Debian 13, Ubuntu 24.04, Fedora, Arch, openSUSE (install, add, open, close).

## Results

| Date | What | Where | Result |
|---|---|---|---|
| 2026-10-26 | unit tests, netns.sh (nft 1.1.3), shellcheck | Debian 13, Python 3.13 | pass |
| | live test, manual checks 1-8 | | **not done yet** |
