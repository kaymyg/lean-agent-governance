"""Where the governance engine keeps its state database."""
import os


def state_db_path():
    """Per-user location for the engine's state database.

    It used to be the fixed path /tmp/agent_intel_state.db. /tmp is shared by
    every user on the machine, so another account could pre-create or replace
    that file (or point a symlink at it) and erase or forge the session history
    that quarantine decisions rely on. The default now lives under the user's
    own state directory with 0700 permissions. AGENT_GOVERNANCE_STATE_DIR
    overrides it (tests and CI use this).
    """
    base = os.environ.get("AGENT_GOVERNANCE_STATE_DIR")
    if not base:
        xdg = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
        base = os.path.join(xdg, "lean-agent-governance")
    os.makedirs(base, mode=0o700, exist_ok=True)
    try:
        os.chmod(base, 0o700)
    except OSError:
        pass
    path = os.path.join(base, "agent_intel_state.db")
    if os.path.islink(path):
        raise RuntimeError(f"refusing to use state database {path}: it is a symlink")
    return path
