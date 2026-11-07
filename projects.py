"""Per-session project mount: the space of a briefling thread fixes the one host folder its sandbox sees.

Hermes' Docker backend in per-session isolation (``terminal.backend: docker``, ``container_persistent: false``,
``docker_mount_cwd_to_workspace: true``) mounts at ``/workspace`` only the ``cwd`` override registered for the
session (``cwd_source: "session"``), and nothing when there is none. This module computes that folder from a
map declared on the host (platform settings of the profile, never a tool or a message):

- ``projects_root`` / ``BRIEFLING_PROJECTS_ROOT``: absolute folder of the agent's own clones (one per project),
  e.g. ``~/agents/<agent>``; never the host's working copies.
- ``projects`` / ``BRIEFLING_PROJECTS``: ``space=org/project`` pairs, comma separated (or a mapping in
  ``config.yaml``).

Fail closed: a space without an entry, a malformed entry, a folder outside the root (``..``, symlink), a missing
folder, one under ``~/projects``, ``/root`` or ``/workspace`` gives ``None``, and the hook then registers nothing, so Hermes mounts nothing.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Mapping, Optional

logger = logging.getLogger(__name__)

_SEG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_SPACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def _seg_ok(s: str) -> bool:
    return bool(_SEG.match(s)) and ".." not in s


def parse_projects(raw: Any) -> Dict[str, str]:
    """``{space: "org/project"}`` from ``"a=org/x, b=org/y"`` or a mapping; malformed entries are dropped."""
    pairs: list = []
    if isinstance(raw, Mapping):
        pairs = [(str(k), str(v)) for k, v in raw.items()]
    elif isinstance(raw, str):
        for item in raw.split(","):
            if item.strip():
                k, sep, v = item.partition("=")
                pairs.append((k, v) if sep else (item, ""))
    out: Dict[str, str] = {}
    for space, path in pairs:
        space, path = space.strip(), path.strip()
        parts = path.split("/")
        if _SPACE.match(space) and len(parts) == 2 and all(_seg_ok(p) for p in parts):
            out[space] = path
        else:
            logger.warning("[briefling] projects: entry %r ignored (want space=org/project)", f"{space}={path}")
    return out


def _under(path: str, parent: str) -> bool:
    return path == parent or path.startswith(parent.rstrip("/") + "/")


def project_dir(root: str, projects: Mapping[str, str], space: str, home: Optional[str] = None) -> Optional[str]:
    """Host folder of ``space``'s project, or ``None`` (refused or unmapped). ``home`` overrides ``~`` (tests)."""
    rel = projects.get(space) if isinstance(space, str) else None
    if not rel or not isinstance(root, str) or not os.path.isabs(root):
        return None
    real_root = os.path.realpath(root)
    if real_root == "/":
        return None
    expected = os.path.join(real_root, *rel.split("/"))
    real = os.path.realpath(expected)
    if real != expected or not os.path.isdir(real):  # a symlink anywhere below the root, or not there
        return None
    if _under(real, "/root") or _under(real, "/workspace"):  # Hermes never mounts these: say so, don't pretend
        return None
    host_projects = os.path.realpath(os.path.join(home or os.path.expanduser("~"), "projects"))
    if _under(real, host_projects) or _under(host_projects, real):  # the host's working copies: never mounted
        return None
    return real


def bind_session_project(task_id: str, folder: str) -> bool:
    """Register ``folder`` as the session's mount (Hermes ``cwd_source: "session"`` override), once: re-registering
    an unchanged folder would reset the agent's ``cd`` at every turn. Other overrides of the task stay."""
    from tools.terminal_tool import _qualify_task_key, _task_env_overrides, register_task_env_overrides
    # The task's own entry only (resolve_task_overrides would fall back to a shared container's entry).
    current = dict(_task_env_overrides.get(_qualify_task_key(task_id)) or {})
    if current.get("cwd") == folder and current.get("cwd_source") == "session":
        return False
    register_task_env_overrides(task_id, {**current, "cwd": folder, "cwd_source": "session"})
    return True
