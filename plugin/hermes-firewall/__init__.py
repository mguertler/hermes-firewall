"""/firewall for Hermes Agent: open, close and show the sandbox firewall of this profile.

Installed into a profile by 'sudo hermes-firewall add PROFILE'. It only calls
'sudo -n hermes-firewall open|close|status PROFILE ...', which that command
allows for this profile in /etc/sudoers.d/hermes-firewall. A slash command,
not a tool: only the user can run it, never the model.

Optional (plugins.entries.hermes-firewall.settings.agent_notice: true): when a
sandbox command fails with a network error while the firewall is closed, one
line is added to that command's output, so the model knows why and asks the
user. Nothing is added to any other output or to the prompt."""
import os
from pathlib import Path
import re
import subprocess

EXE = "/usr/local/bin/hermes-firewall"
USAGE = """/firewall open                 Internet for the default time (usually 1h)
/firewall open 30m             Internet for 30 minutes
/firewall open lan 2h          LAN for 2 hours (also: internet, all)
/firewall close                close everything (also: close lan, close internet)
/firewall status               what is open and for how long"""
# Typical messages of curl, wget, git, pip/requests, npm, apt and the C library for a blocked network.
NETWORK_ERROR = re.compile(
    r"Could not resolve host|Temporary failure in name resolution|Name or service not known|"
    r"Network is unreachable|No route to host|Connection timed out|Operation timed out|"
    r"Failed to establish a new connection|ConnectTimeout|Max retries exceeded|"
    r"ETIMEDOUT|EAI_AGAIN|ENETUNREACH|EHOSTUNREACH|Could not connect to|Unable to connect to|"
    r"unable to access '[^']*': Failed to connect", re.I)
CURL_NETWORK_EXIT = {6, 7, 28, 35, 56}  # resolve, connect, timeout, TLS connect, receive


def profile_name():
    """This gateway's Hermes profile: "default", a profile name, or None (custom HERMES_HOME)."""
    try:
        from hermes_cli.profiles import get_active_profile_name
        name = get_active_profile_name()
    except Exception:
        home = Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes").resolve()
        root = (Path.home() / ".hermes").resolve()
        name = "default" if home == root else home.name if home.parent == root / "profiles" else None
    return name if name and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", name) else None


def firewall(verb, profile, *words):
    # LC_ALL=C: sudo's own messages in English, so a missing rule is recognised in any locale.
    return subprocess.run(["sudo", "-n", EXE, verb, profile, *words], capture_output=True,
                          text=True, timeout=60, env={**os.environ, "LC_ALL": "C"})


def handle(raw_args=""):
    words = (raw_args or "").split()
    if not words or words[0] not in ("open", "close", "status") or (words[0] == "status" and len(words) > 1) \
            or any(not re.fullmatch(r"[a-z0-9]+", word) for word in words):
        return USAGE
    profile = profile_name()
    if profile is None:
        return "This Hermes profile is not in ~/.hermes, so /firewall cannot tell which firewall to use."
    try:
        result = firewall(words[0], profile, *words[1:])
    except FileNotFoundError:
        return "sudo is not installed on this host."
    except subprocess.TimeoutExpired:
        return "hermes-firewall did not answer within 60 seconds."
    output = (result.stdout + result.stderr).strip()
    if result.returncode and "password" in result.stderr:
        return (f"The firewall of {profile} is not set up for /firewall. "
                f"On the host, run once: sudo hermes-firewall add {profile}")
    return output.removeprefix("ERROR: ") or "hermes-firewall gave no answer."


def network_failure(command, output, returncode):
    if returncode in (None, 0):
        return False
    if returncode in CURL_NETWORK_EXIT and re.search(r"\bcurl\b", command or ""):
        return True
    return bool(NETWORK_ERROR.search(output or ""))


def lease_states(profile):
    """{"Internet": "closed" | "open ...", "LAN": ...} from 'status PROFILE', or None."""
    try:
        result = firewall("status", profile)
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"firewall active, Internet (.+?), LAN (.+)$", result.stdout, re.M)
    return {"Internet": match[1], "LAN": match[2].strip()} if result.returncode == 0 and match else None


def notice(states):
    return (f"[hermes-firewall] This sandbox is behind a firewall: Internet {states['Internet']}, "
            f"LAN {states['LAN']}. Only the user can open it (/firewall open [lan|all] [duration]); "
            "ask them if the task needs the network. Do not try to work around it.")


def make_output_hook(enabled):
    """transform_terminal_output: add one line to a sandbox command that failed on a closed network."""
    def hook(command="", output="", returncode=None, env_type="", **kwargs):
        if env_type != "docker" or not network_failure(command, output, returncode) or not enabled():
            return None
        profile = profile_name()
        states = lease_states(profile) if profile else None
        if not states or not any(state == "closed" for state in states.values()):
            return None  # firewall not involved (or unknown): leave the output as it is
        return f"{output.rstrip()}\n{notice(states)}"
    return hook


def register(ctx):
    ctx.register_command("firewall", handle, description="Open, close or show the sandbox firewall",
                         args_hint="open [internet|lan|all] [30m|2h] | close | status")
    def enabled():
        try:
            return ctx.get_config("agent_notice", False) is True
        except Exception:
            return False
    ctx.register_hook("transform_terminal_output", make_output_hook(enabled))
