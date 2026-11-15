"""Self-update of this plugin, offered by the hub at each connection (``subscribed.release``).

Two sources must agree before any new code lands: the release the deployed hub announces (version + commit of
the public repo) and the HEAD of the public repo's ``main`` (``git ls-remote``). Then ``hermes plugins update
briefling`` (Hermes' own scanned, atomic update) for THIS profile only, a check that the installed tree is that
commit and that its code imports and reports that version, then a graceful gateway restart, the same call as
``/restart``, only once the whole gateway runs no work. Any failure: nothing restarts, a broken tree is put back
on the previous commit, the commit is recorded as failed and never retried (a newer release is). Off with
``BRIEFLING_AUTO_UPDATE=0``. Never a downgrade, never a pinned (``--ref``) install.

The profile is the one this file is installed in (``<home>/plugins/briefling/selfupdate.py``), never
``get_hermes_home()``: the hub's frames are handled outside any turn, where a multiplexed gateway may resolve
another profile.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

NAME = "briefling"
VERSION_RE = re.compile(r"^(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
STATE_FILE = "briefling-update.json"
SETTLE_S = 90        # after our update, before the restart: other profiles of the same gateway update too
IDLE_POLL_S = 30     # how often the restart looks for an idle gateway
CMD_TIMEOUT_S = 300

# Run by the import check, with the gateway's sys.path: imports the installed tree, prints its VERSION.
_CHECK = ("import json, sys; sys.path[:0] = json.loads(sys.argv[1]); "
          "import briefling.adapter as a; print('VERSION=' + a.VERSION)")

Run = Callable[..., subprocess.CompletedProcess]


def parse_version(v: Any) -> Optional[tuple]:
    m = VERSION_RE.match(v) if isinstance(v, str) else None
    return tuple(int(x) for x in m.groups()) if m else None


def valid_release(release: Any) -> Optional[Dict[str, str]]:
    """The hub's ``subscribed.release`` when well formed ({version x.y.z, commit 40-hex}), else None."""
    if not isinstance(release, dict):
        return None
    version, commit = release.get("version"), release.get("commit")
    if parse_version(version) is None or not isinstance(commit, str) or not SHA_RE.match(commit):
        return None
    return {"version": version, "commit": commit}


def is_newer(release: str, current: str) -> bool:
    a, b = parse_version(release), parse_version(current)
    return a is not None and b is not None and a > b


def enabled(value: str) -> bool:
    return value.strip().lower() not in ("0", "false", "no", "off")


class Install:
    """Where this plugin is installed: profile home, plugin dir, Hermes' install record of it."""

    def __init__(self, plugin_dir: Path):
        self.plugin_dir = plugin_dir
        self.home = plugin_dir.parent.parent

    @classmethod
    def here(cls) -> "Install":
        return cls(Path(__file__).resolve().parent)

    def record(self) -> Dict[str, Any]:
        try:
            meta = json.loads((self.plugin_dir.parent / ".install-metadata.json").read_text())
        except (OSError, ValueError):
            return {}
        rec = meta.get(self.plugin_dir.name) if isinstance(meta, dict) else None
        return rec if isinstance(rec, dict) else {}

    def refusal(self) -> Optional[str]:
        """Why this install cannot follow releases, or None."""
        if self.plugin_dir.parent.name != "plugins" or self.plugin_dir.name != NAME:
            return f"not installed as <home>/plugins/{NAME}"
        if not (self.plugin_dir / ".git").is_dir():
            return "not a git checkout"
        rec = self.record()
        if not isinstance(rec.get("source"), str) or not rec["source"]:
            return "no install record (hermes plugins adopt briefling)"
        if rec["source"].startswith("-"):  # handed to git as an argument
            return "unexpected install source"
        if rec.get("pinned") is True:
            return "pinned install (--ref)"
        return None

    def state(self) -> Dict[str, Any]:
        try:
            s = json.loads((self.home / STATE_FILE).read_text())
            return s if isinstance(s, dict) else {}
        except (OSError, ValueError):
            return {}

    def save(self, **state: Any) -> None:
        path = self.home / STATE_FILE
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({**state, "at": int(time.time())}))
        os.replace(tmp, path)

    def clear(self) -> None:
        try:
            (self.home / STATE_FILE).unlink()
        except FileNotFoundError:
            pass


def hermes_argv() -> List[str]:
    """This very install of Hermes (as the gateway's /update does), never a ``hermes`` found first on PATH."""
    return [sys.executable, "-m", "hermes_cli.main"]


def _run(argv: Sequence[str], *, env: Optional[Dict[str, str]] = None, cwd: Optional[Path] = None,
         timeout: float = CMD_TIMEOUT_S) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), env=env, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          timeout=timeout)


def _tail(p: subprocess.CompletedProcess) -> str:
    return ((p.stderr or "") + (p.stdout or "")).strip()[-400:]


class Outcome:
    """Result of :func:`apply`: ``restart`` = the new code is installed and imports, a restart loads it."""

    def __init__(self, status: str, detail: str = ""):
        self.status, self.detail = status, detail

    @property
    def restart(self) -> bool:
        return self.status == "installed"

    def __repr__(self) -> str:
        return f"Outcome({self.status!r}, {self.detail!r})"


def apply(install: Install, release: Dict[str, str], current: str, *, run: Run = _run) -> Outcome:
    """Blocking (run it in an executor). Every refusal is logged once here; nothing restarts on its own."""
    version, commit = release["version"], release["commit"]
    if not is_newer(version, current):
        return Outcome("current")
    why = install.refusal()
    if why:
        logger.info("[briefling] update %s available, not applied automatically: %s", version, why)
        return Outcome("unsupported", why)
    state = install.state()
    if state.get("commit") == commit:  # failed, or restarted without loading it: never twice for one commit
        return Outcome("skipped", str(state.get("status") or ""))
    source = install.record()["source"]
    try:
        remote = run(["git", "ls-remote", source, "refs/heads/main"], timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("[briefling] update %s not applied: git ls-remote failed (%s)", version, exc)
        return Outcome("unverified", str(exc))
    head = (remote.stdout or "").split()[0] if remote.returncode == 0 and (remote.stdout or "").split() else ""
    if head != commit:
        logger.warning("[briefling] update %s NOT applied: the hub announces %s, public main is %s",
                       version, commit, head or "unreadable")
        return Outcome("mismatch", head)
    before = _head(install, run)
    env = {**os.environ, "HERMES_HOME": str(install.home)}
    try:
        up = run([*hermes_argv(), "plugins", "update", NAME], env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        up = subprocess.CompletedProcess([], 1, "", str(exc))
    after = _head(install, run)
    if up.returncode != 0:
        problem = f"plugins update failed: {_tail(up)}"  # it may have published before failing (a consent prompt)
    else:
        problem = None if after == commit else f"installed {after or 'unknown'} instead of {commit}"
    if problem is None:
        problem = _import_problem(install, version, env, run)
    if problem:
        rolled = _rollback(install, before, run) if after != before else True
        install.save(commit=commit, version=version, status="failed", detail=problem)
        logger.error("[briefling] update %s refused: %s; %s", version, problem,
                     f"back on {before}" if rolled else "ROLLBACK FAILED: fix the checkout before any restart")
        return Outcome("failed", problem)
    install.save(commit=commit, version=version, status="installed", previous=current)
    logger.info("[briefling] update %s installed (%s), restart once the gateway is idle", version, commit[:12])
    return Outcome("installed")


def _head(install: Install, run: Run) -> str:
    try:
        p = run(["git", "-C", str(install.plugin_dir), "rev-parse", "HEAD"], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return p.stdout.strip() if p.returncode == 0 and SHA_RE.match(p.stdout.strip()) else ""


def _import_problem(install: Install, version: str, env: Dict[str, str], run: Run) -> Optional[str]:
    path = [str(install.plugin_dir.parent)] + [p for p in sys.path if p]
    try:
        p = run([sys.executable, "-c", _CHECK, json.dumps(path)], env=env, cwd=install.home, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"import check did not run: {exc}"
    got = next((ln[8:] for ln in (p.stdout or "").splitlines() if ln.startswith("VERSION=")), "")
    if p.returncode != 0:
        return f"new code does not import: {_tail(p)}"
    return None if got == version else f"new code reports {got or 'no'} version, expected {version}"


def _rollback(install: Install, before: str, run: Run) -> bool:
    """Puts the checkout back on *before* (Hermes' record too), so a later restart loads the code running now."""
    if not before:
        return False
    try:
        p = run(["git", "-C", str(install.plugin_dir), "reset", "--hard", "--quiet", before], timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if p.returncode != 0:
        return False
    meta_path = install.plugin_dir.parent / ".install-metadata.json"
    try:
        meta = json.loads(meta_path.read_text())
        meta[install.plugin_dir.name]["revision"] = before
        tmp = meta_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(meta, indent=2))
        os.replace(tmp, meta_path)
    except (OSError, ValueError, KeyError, TypeError):
        logger.warning("[briefling] rollback: checkout back on %s but its install record was not rewritten", before)
    return True


def restarted_from(install: Install, current: str) -> Optional[str]:
    """At connect: the version this process replaced when it is the restart of an auto-update (reported once to the
    hub, which posts a notice), else None. A restart that did not load the new code marks the commit failed."""
    state = install.state()
    if state.get("status") != "installed":
        return None
    if state.get("version") == current and parse_version(state.get("previous")):
        install.save(**{**state, "status": "done"})
        return state["previous"]
    install.save(**{**state, "status": "failed", "detail": f"restarted on {current}, not {state.get('version')}"})
    logger.error("[briefling] update %s was installed but the gateway restarted on %s", state.get("version"), current)
    return None


def blocked(install: Install, on: bool, current: str) -> Optional[str]:
    """Why this plugin will not install new releases by itself, reported at subscribe (the hub shows the space's
    leads a banner while it is behind): ``off``, ``pinned``, ``manual`` (no git install) or ``failed``; None = it will."""
    if not on:
        return "off"
    why = install.refusal()
    if why:
        return "pinned" if why.startswith("pinned") else "manual"
    state = install.state()  # a failure of a release older than the running code (updated by hand since) is over
    return "failed" if state.get("status") == "failed" and is_newer(str(state.get("version")), current) else None


def idle(runner: Any) -> Optional[bool]:
    """Whether the gateway runs no work at all (every profile, cron, API runs); None = cannot tell."""
    count = getattr(runner, "_active_work_count", None) or getattr(runner, "_running_agent_count", None)
    if not callable(count):
        return None
    try:
        if getattr(runner, "_restart_requested", False) or getattr(runner, "_draining", False):
            return False
        return int(count()) == 0
    except Exception:
        return None


def request_restart(runner: Any) -> bool:
    """The gateway's own graceful restart, as its /restart command calls it (service manager or detached)."""
    req = getattr(runner, "request_restart", None)
    if not callable(req):
        return False
    try:
        from gateway.restart import is_container_restart_context, is_gateway_supervisor_process
        via_service = bool(is_gateway_supervisor_process() or is_container_restart_context())
    except Exception:
        via_service = False
    return bool(req(detached=not via_service, via_service=via_service))
