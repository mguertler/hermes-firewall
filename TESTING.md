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

### Other distributions (Docker on any test host)

```bash
sudo bash tests/distros.sh            # Debian 12/13, Ubuntu 24.04, Fedora 42, Arch, openSUSE Tumbleweed
sudo bash tests/distros.sh fedora:42  # or selected images
```

Per distribution in a container: required programs at the expected paths, Python
version, unit tests, the generated rules with its nft (`nft -c`), the sudoers file with
its visudo, and whether sudoers includes `/etc/sudoers.d`. Not covered: systemd, Docker
and the real packet path (live test).

### Test machines

Live tests need a disposable VM (root, Docker, Hermes, reboots allowed); helper hosts
can run the distribution containers and the fast tests. Such machines are not always
running: check first, keep the steps resumable, and run the local tests otherwise.

## Live test (root, Docker; opt-in)

Only on a host where nothing important runs, with an unused test profile:

```bash
hermes profile create fwtest                 # or any unused Hermes profile
hermes -p fwtest config set terminal.backend docker
sudo ./install.sh
sudo hermes-firewall add fwtest
sudo bash tests/integration.sh fwtest        # closed / open 30s / expiry / host blocked
sudo hermes-firewall remove fwtest
```

For a real Hermes session a local model is enough, e.g. Ollama (Hermes needs a context
window of at least 64K):

```bash
hermes config set model.provider ollama
hermes config set model.base_url http://OLLAMA_HOST:11434/v1
hermes config set model.default ministral-3:8b
hermes config set model.ollama_num_ctx 64000
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
| 2026-10-26 | independent code review (12 findings), fixes, re-run of all tests | Debian 13 | pass |
| 2026-10-26 | tests/distros.sh | Debian 12 (nft 1.0.6) and 13, Ubuntu 24.04 (nft 1.0.9), Fedora 42, Arch, openSUSE Tumbleweed | pass |
| 2026-10-26 | live: install, add (incl. backend check), integration.sh, LAN/Internet/host matrix against real LAN and Internet targets | test VM: Debian 13, Docker 26.1.5, Hermes 0.22.5 | pass |
| 2026-10-26 | manual 1 (boot closes leases, firewall before Docker, broken config keeps Docker down) | test VM | pass |
| 2026-10-26 | manual 2 (Hermes creates the sandbox in hermes-fw-default with our DNS; /firewall status/open/close in Hermes; curl closed/open/closed) | test VM, Ollama ministral-3:8b | pass |
| 2026-10-26 | manual 3 (old sandbox on bridge moved, host-network sandbox reported, add --yes resets) | test VM | pass |
| 2026-10-26 | manual 7 (upgrade keeps an open lease), sudoers with a restricted user (only open/close/status; options refused) | test VM | pass |
| | manual 4 (remove + new session), 5 (IPv6: needs Docker 27+), 6 (egress proxy), 7 (uninstall), 8 (live on other distributions) | | **not done yet** |
