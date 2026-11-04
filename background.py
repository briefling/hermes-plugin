"""Background work per briefling thread (hub frame ``thread.background``, protocol/frames.ts ``Background``).

What the agent still runs once its turn is over: sub-agents (``delegate_task`` in the background, Hermes'
``tools.async_delegation`` records) and the processes it gets notified of (``terminal(background, notify)``,
``tools.process_registry``). Read by polling those registries (no hook covers both, and a poll also sees an end that a
hook would miss): a record belongs to a thread when its gateway session key is this adapter's key for it.

The hub gets the full list of a thread on every change, and again every BEAT_S while it is not empty: each frame
renews the deadline there (BG_LEASE_MS); silence past it = the work is lost (container restarted, gateway down) and
the thread becomes Your turn. Nothing here is sent but a short goal per task: the sub-agent's goal or the process
command, both redacted, one line, cut.
"""

from __future__ import annotations

import logging
import re
import threading
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

BEAT_S = 300            # BG_BEAT_MS in protocol/frames.ts
SCAN_S = 15.0           # how often the registries are read
MAX_TASKS = 10          # BG_MAX_TASKS
GOAL_MAX = 200          # BG_GOAL_MAX
ID_MAX = 64             # BG_ID_MAX
_LIVE = frozenset({"running", "stalling", "finalizing"})  # tools.async_delegation._LIVE_STATES
_THREAD_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")

Task = Dict[str, Any]


def key_prefix(owner_profile: Optional[str]) -> str:
    """Start of this adapter's session keys (gateway.session.build_session_key for a briefling DM = one thread)."""
    try:
        from gateway.session import _session_key_namespace
        ns = _session_key_namespace(owner_profile)
    except Exception:
        ns = "agent:main" if not owner_profile or owner_profile == "default" else f"agent:{owner_profile}"
    return f"{ns}:briefling:dm:"


def thread_of(session_key: Any, prefix: str) -> Optional[str]:
    if not isinstance(session_key, str) or not session_key.startswith(prefix):
        return None
    rest = session_key[len(prefix):]
    return rest if _THREAD_RE.fullmatch(rest) else None


def _redact(text: str) -> str:
    try:
        from agent.redact import redact_sensitive_text
        return redact_sensitive_text(text, force=True, redact_url_credentials=True)
    except Exception:
        logger.debug("briefling: background redaction unavailable", exc_info=True)
        return ""


def clean_goal(text: Any, fallback: str) -> str:
    """One redacted line, at most GOAL_MAX characters; ``fallback`` when nothing readable is left."""
    s = " ".join(_redact(str(text or "")).split())
    if not s:
        return fallback
    return s if len(s) <= GOAL_MAX else s[: GOAL_MAX - 1].rstrip() + "…"


def _ms(t: Any) -> int:
    try:
        v = int(float(t) * 1000)
    except (TypeError, ValueError):
        return 1
    return max(1, v)


def delegations() -> List[Dict[str, Any]]:
    try:
        from tools.async_delegation import list_async_delegations
        return list_async_delegations()
    except Exception:
        logger.debug("briefling: async delegations unreadable", exc_info=True)
        return []


def processes() -> List[Any]:
    """Running process sessions (the registry's live map: its public listing carries no session key)."""
    try:
        from tools.process_registry import process_registry as reg
        with reg._lock:
            return list(reg._running.values())
    except Exception:
        logger.debug("briefling: process registry unreadable", exc_info=True)
        return []


def collect(prefix: str, read_delegations: Callable[[], Iterable[Dict[str, Any]]] = delegations,
            read_processes: Callable[[], Iterable[Any]] = processes) -> Dict[str, List[Task]]:
    """Live background tasks per thread of this adapter (oldest first, at most MAX_TASKS each)."""
    out: Dict[str, List[Task]] = {}
    for r in read_delegations():
        if r.get("status") not in _LIVE:
            continue
        thread = thread_of(r.get("session_key"), prefix)
        if not thread:
            continue
        goals = r.get("goals") or []
        goal = r.get("goal") or (goals[0] if goals else "")
        if len(goals) > 1:
            goal = f"{goals[0]} (+{len(goals) - 1})"
        out.setdefault(thread, []).append({"id": str(r.get("delegation_id") or "")[:ID_MAX] or "delegation", "kind": "delegate",
                                           "goal": clean_goal(goal, "sub-agent"), "since": _ms(r.get("dispatched_at"))})
    for s in read_processes():
        if getattr(s, "exited", False) or not (getattr(s, "notify_on_complete", False) or getattr(s, "watch_patterns", None)):
            continue
        thread = thread_of(getattr(s, "session_key", ""), prefix)
        if not thread:
            continue
        out.setdefault(thread, []).append({"id": str(getattr(s, "id", "") or "")[:ID_MAX] or "process", "kind": "process",
                                           "goal": clean_goal(getattr(s, "command", ""), "process"), "since": _ms(getattr(s, "started_at", 0))})
    for thread, tasks in out.items():
        seen, uniq = set(), []
        for t in sorted(tasks, key=lambda t: t["since"]):
            if t["id"] not in seen:  # the hub refuses duplicate ids
                seen.add(t["id"])
                uniq.append(t)
        out[thread] = uniq[:MAX_TASKS]
    return out


def _sig(tasks: List[Task]) -> Tuple:
    return tuple((t["id"], t["kind"], t["goal"], t["since"]) for t in tasks)


class Tracker:
    """What the hub was last told per thread: decides which frames go now (change, beat, end)."""

    def __init__(self) -> None:
        self._sent: Dict[str, Tuple[Tuple, float]] = {}
        self._lock = threading.Lock()

    def due(self, current: Dict[str, List[Task]], known: Iterable[str], now: float) -> List[Tuple[str, List[Task]]]:
        known = set(known)
        out = []
        with self._lock:
            for thread in sorted(set(current) | set(self._sent)):
                if thread not in known:
                    continue
                tasks = current.get(thread, [])
                prev = self._sent.get(thread)
                if tasks:
                    if prev is None or prev[0] != _sig(tasks) or now - prev[1] >= BEAT_S:
                        out.append((thread, tasks))
                elif prev is not None:
                    out.append((thread, []))
        return out

    def sent(self, thread: str, tasks: List[Task], now: float) -> None:
        """Only after the hub got it: a failed send is tried again at the next scan."""
        with self._lock:
            if tasks:
                self._sent[thread] = (_sig(tasks), now)
            else:
                self._sent.pop(thread, None)
