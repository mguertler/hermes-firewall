"""/firewall for Hermes Agent: open, close and show the sandbox firewall of this profile.

Installed into a profile by 'sudo hermes-firewall add PROFILE'. It only calls
'sudo -n hermes-firewall open|close|status PROFILE ...', which that command
allows for this profile in /etc/sudoers.d/hermes-firewall. A slash command,
not a tool: only the user can run it, never the model."""
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


def handle(raw_args=""):
    words = (raw_args or "").split()
    if not words or words[0] not in ("open", "close", "status") or (words[0] == "status" and len(words) > 1) \
            or any(not re.fullmatch(r"[a-z0-9]+", word) for word in words):
        return USAGE
    profile = profile_name()
    if profile is None:
        return "This Hermes profile is not in ~/.hermes, so /firewall cannot tell which firewall to use."
    try:
        # LC_ALL=C: sudo's own messages in English, so a missing rule is recognised in any locale.
        result = subprocess.run(["sudo", "-n", EXE, words[0], profile, *words[1:]], capture_output=True,
                                text=True, timeout=60, env={**os.environ, "LC_ALL": "C"})
    except FileNotFoundError:
        return "sudo is not installed on this host."
    except subprocess.TimeoutExpired:
        return "hermes-firewall did not answer within 60 seconds."
    output = (result.stdout + result.stderr).strip()
    if result.returncode and "password" in result.stderr:
        return (f"The firewall of {profile} is not set up for /firewall. "
                f"On the host, run once: sudo hermes-firewall add {profile}")
    return output.removeprefix("ERROR: ") or "hermes-firewall gave no answer."


def register(ctx):
    ctx.register_command("firewall", handle, description="Open, close or show the sandbox firewall",
                         args_hint="open [internet|lan|all] [30m|2h] | close | status")
