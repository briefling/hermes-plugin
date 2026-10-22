"""Flow host: runs the board engine (``briefling.flow``) for this plugin's agent in board-driven spaces.

docs/design-flow.md § 4.3: a tick (timer every ``poll_min``, or right after a task turn) reads the board; an event
becomes a task the hub places in the issue thread (``flow.task``), the turn runs in that thread's session, and the
closed task goes back to the hub (``flow.done``). The board says what to do, the hub says where and whether now.

Settings: a JSON file (``BRIEFLING_FLOW`` / extra ``flow``), read at start::

    {"poll_min": 5, "spaces": [{"space": "sandbox", "agent": "kevin", "config": "/path/to/hq-clone",
      "identity": {"app_id": 123, "app_key": "/path/key.pem", "installation_id": 456}}]}

``config`` = a local folder holding the company config bundle (``config.yml``, ``culture.md``, ``agents/``,
``playbooks/``): the config editor of the hub comes in a later slice. ``identity`` = the agent's GitHub App (its key
stays on this machine); missing = this machine's ``gh`` login.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

from .flow.config import Company, Department, load_company
from .flow.backends.github import GitHubBoard
from .flow.identity import make_token
from .flow.model import AGENT_MARK
from .flow.poll import poll
from .flow.usage import USAGE_KEYS, usage_delta
from .flow.status import parse_status, status_body

logger = logging.getLogger(__name__)

DEFAULT_POLL_MIN = 5.0
MIN_POLL_MIN = 1.0
NOTHING_LEARNED = {"none", "nothing", "-"}
ZERO = {k: 0 for k in USAGE_KEYS}


class HubAnswer(Exception):
    """The hub refused a frame (its error code): retrying the same frame cannot help."""


class FlowError(Exception):
    """Refusal shown to the agent as the tool's error (bad ref, unknown state, assignment label...)."""


@dataclass
class FlowSpace:
    space: str
    agent: str
    config: Path
    identity: Dict[str, Any] = field(default_factory=dict)


def load_settings(path: str) -> tuple[float, List[FlowSpace]]:
    """(poll_min, spaces) from the settings file; an unreadable or malformed file = no flow (logged)."""
    if not path:
        return DEFAULT_POLL_MIN, []
    try:
        raw = json.loads(Path(os.path.expanduser(path)).read_text())
        poll_min = max(MIN_POLL_MIN, float(raw.get("poll_min") or DEFAULT_POLL_MIN))
        spaces = [FlowSpace(space=str(s["space"]), agent=str(s["agent"]), config=Path(os.path.expanduser(str(s["config"]))),
                            identity=dict(s.get("identity") or {})) for s in raw.get("spaces") or []]
        return poll_min, spaces
    except (OSError, ValueError, KeyError, TypeError) as e:
        logger.warning("briefling flow settings %s unreadable: %s", path, type(e).__name__)
        return DEFAULT_POLL_MIN, []


def bots(co: Company) -> set:
    """Logins trusted as machines: agent identities and `trusted_bots` (their words are never a human go)."""
    return {str(a.get("identity", "")).lower() for a in co.agents.values() if a.get("identity")} | set(co.trusted_bots)


def department_of(co: Company, agent: str, ref: str) -> Department:
    """The agent's department owning the repo of `ref` (`owner/repo#N`): the board tools act nowhere else."""
    repo, sep, num = ref.partition("#")
    if not sep or not num.isdigit():
        raise FlowError("ref must look like owner/repo#123")
    found = [d for d in co.departments_of(agent) if repo.lower() in (r.lower() for r in d.repos)]
    if len(found) != 1:
        raise FlowError("%s is not in one of your departments' repos" % repo if not found
                        else "%s belongs to several departments" % repo)
    return found[0]


def to_counters(u: Optional[Dict[str, Any]]) -> Dict[str, float]:
    """The plugin's per-turn usage (hub format) in the engine's counter keys."""
    u = u or {}
    return {"in": u.get("input", 0), "out": u.get("output", 0), "cache_read": u.get("cacheRead", 0),
            "cache_write": u.get("cacheWrite", 0), "reasoning": u.get("reasoning", 0), "cost": float(u.get("usd", 0) or 0)}


def add_counters(a: Dict[str, float], b: Dict[str, float]) -> Dict[str, float]:
    return {k: (a.get(k) or 0) + (b.get(k) or 0) for k in USAGE_KEYS}


class FlowHost:
    """One (space, agent): the engine state, the pending task, the task / discussion spend. Hub calls go through
    `request` (frame -> reply frame, raises on a hub error) and turns through `inject(thread, title, text)`."""

    def __init__(self, fs: FlowSpace, state_dir: Path, request: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]],
                 inject: Callable[[str, str, str], Awaitable[None]], make_board: Optional[Callable[..., Any]] = None,
                 clock: Callable[[], float] = time.time, company: Optional[Callable[[], Company]] = None):
        self.fs = fs
        self.path = state_dir / ("flow-%s-%s.json" % (fs.space, fs.agent))
        self.token_dir = state_dir
        self._request, self._inject, self._clock = request, inject, clock
        self._make_board = make_board or self._github_board
        self._company = company or (lambda: load_company(self.fs.config))
        self.state: Dict[str, Any] = self._load()
        self.lock = asyncio.Lock()
        self.task_turn = False            # a task turn of this host is running (no tick meanwhile)
        self.last_tick = 0.0
        self.poll_min: Optional[float] = None  # the agent's `limits.poll_min` in the config, read at each tick

    # -- state -----------------------------------------------------------------
    def _load(self) -> Dict[str, Any]:
        try:
            s = json.loads(self.path.read_text())
            return s if isinstance(s, dict) else {}
        except (OSError, ValueError):
            return {}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=1))
        os.replace(tmp, self.path)

    @property
    def engine(self) -> Dict[str, Any]:
        return self.state.setdefault("engine", {})

    @property
    def thread(self) -> Optional[str]:
        """The issue thread of the current task, once the hub placed it."""
        return self.state.get("thread")

    def usage(self) -> Dict[str, float]:
        """Cumulative spend in this space, task + discussion: every cost counts towards the quotas."""
        c = self.state.get("counters") or {}
        return add_counters(c.get("task") or ZERO, c.get("discussion") or ZERO)

    def add_usage(self, tag: str, turn_usage: Optional[Dict[str, Any]]) -> None:
        if not turn_usage:
            return
        c = self.state.setdefault("counters", {})
        c[tag] = add_counters(c.get(tag) or ZERO, to_counters(turn_usage))
        self.save()

    # -- GitHub ----------------------------------------------------------------
    def company(self) -> Company:
        return self._company()

    def _github_board(self, co: Company, dept: Department):
        token = make_token(self.fs.identity, dept.board["owner"], cache_dir=self.token_dir) if self.fs.identity else None
        return GitHubBoard(dept.board, dept.flow, bots(co), token=token)

    def boards(self, co: Company) -> Dict[str, Any]:
        return {d.name: self._make_board(co, d) for d in co.departments_of(self.fs.agent)}

    # -- tick ------------------------------------------------------------------
    def _poll(self, alive: Optional[int]) -> str:
        co = self.company()
        pm = co.limits_for(self.fs.agent).get("poll_min")
        self.poll_min = float(pm) if isinstance(pm, (int, float)) and pm > 0 else None
        return poll(self.fs.agent, co, self.boards(co), self.engine, now=int(self._clock()), usage=self.usage, alive=alive)

    async def tick(self, alive: Optional[int] = None) -> str:
        """One pass: a pending task first, else the engine. Returns what happened (logs, tests)."""
        if self.task_turn or self.lock.locked():
            return "busy"
        async with self.lock:
            self.last_tick = self._clock()
            await self._flush()
            if self.state.get("pending"):
                return await self._start()
            out = await asyncio.to_thread(self._poll, alive)
            finished = self.engine.pop("finished", None) or []
            self.save()
            for rec in finished:
                await self._done(rec)
            if not out:
                return "idle"
            cur = self.engine.get("current") or {}
            self.state["pending"] = {"key": cur.get("key"), "ref": cur.get("ref"), "trigger": cur.get("trigger"),
                                     "title": cur.get("title") or cur.get("ref"), "text": out}
            self.save()
            return await self._start()

    async def _start(self) -> str:
        p = self.state["pending"]
        cur = self.engine.get("current") or {}
        if cur.get("key") != p["key"]:          # the engine moved on (task closed meanwhile): drop it
            self.state.pop("pending", None)
            self.save()
            return "dropped"
        try:
            r = await self._request({"type": "flow.task", "space": self.fs.space, "agent": self.fs.agent, "ref": p["ref"],
                                     "key": p["key"], "trigger": p["trigger"], "title": (p["title"] or "")[:300]})
        except Exception as e:  # hub refusal or unreachable: the task stays pending, retried at the next tick
            logger.warning("briefling flow: task %s not placed: %s", p["ref"], e)
            return "refused"
        if r.get("status") != "started" or not r.get("thread"):
            return str(r.get("status") or "refused")
        if self.state.get("task_key") != p["key"]:  # a new task (not a retry/resume of the same one): its spend starts here
            self.state["task_key"], self.state["task_usage0"] = p["key"], (self.state.get("counters") or {}).get("task") or ZERO
        self.state["thread"] = r["thread"]
        cur["delivered"] = int(self._clock())   # the ack timer starts when the turn really starts
        self.state.pop("pending", None)
        self.task_turn = True
        self.save()
        try:
            await self._inject(r["thread"], p["title"] or p["ref"], p["text"])
        except Exception:
            self.task_turn = False
            raise
        return "started"

    def turn_ended(self) -> None:
        self.task_turn = False

    async def _done(self, rec: Dict[str, Any]) -> None:
        # The engine closes only its current task, the one placed last: its task-tagged spend since it was placed.
        task = (self.state.get("counters") or {}).get("task") or ZERO
        spent = usage_delta(self.state.get("task_usage0"), task) if self.state.get("task_key") else None
        record = {"outcome": rec.get("outcome") if rec.get("outcome") in ("done", "blocked", "gone", "lost") else "gone",
                  "kind": rec.get("kind"), "trigger": rec.get("trigger"), "start": int(rec.get("start") or 0),
                  "end": int(rec.get("end") or 0), "retries": int(rec.get("retries") or 0), "runs": int(rec.get("runs") or 0),
                  "reviews": int(rec.get("reviews") or 0), "cost": round(spent["cost"], 4) if spent else None}
        frame = {"type": "flow.done", "space": self.fs.space, "agent": self.fs.agent, "ref": rec.get("ref"),
                 "key": self.state.get("task_key") or str(rec.get("ref")), "record": record}
        for k in ("thread", "task_key", "task_usage0"):
            self.state.pop(k, None)
        self.state["outbox"] = (self.state.get("outbox") or [])[-49:] + [frame]
        self.save()
        await self._flush()

    async def _flush(self) -> None:
        """Closed tasks not acknowledged by the hub yet (unreachable): sent again, in order, until it answers.
        Why: the hub keeps the agent's hand on the thread until it gets them."""
        while self.state.get("outbox"):
            frame = self.state["outbox"][0]
            try:
                await self._request(frame)
            except HubAnswer as e:   # refused for good (bad frame, space changed): dropped, never retried forever
                logger.warning("briefling flow: record of %s refused by the hub: %s", frame.get("ref"), e)
            except Exception as e:
                logger.warning("briefling flow: record of %s not stored yet: %s", frame.get("ref"), type(e).__name__)
                return
            self.state["outbox"].pop(0)
            self.save()

    # -- board tools (agent's own identity, its departments' repos only) -----------
    def _target(self, ref: str):
        co = self.company()
        dept = department_of(co, self.fs.agent, ref)
        return co, dept, self._make_board(co, dept)

    def board_status(self, ref: str, state: str, todo: str = "", done: str = "", note: str = "", kind: str = "",
                     learned: str = "") -> str:
        if state not in ("working", "done", "blocked"):
            raise FlowError("state must be working, done or blocked")
        lesson = (learned or "").strip()
        if state == "done" and not lesson:
            raise FlowError('closing a task needs a lesson: learned="<rule> because <reason>" (or "none")')
        _, dept, board = self._target(ref)
        kinds = dept.flow.kinds
        if kind and kind not in kinds:
            raise FlowError("unknown kind %r (flow %s: %s)" % (kind, dept.flow.name, ", ".join(kinds) or "no kinds"))
        if state == "done" and kinds and not kind:
            raise FlowError("closing a task needs its kind: one of %s" % "|".join(kinds))
        it = board.item(ref)
        if it is None:
            raise FlowError("%s is closed or not on the board" % ref)
        prev = None
        for c in it.comments:
            prev = prev or (parse_status(c.body, self.fs.agent) if c.status else None)
        now = int(self._clock())
        since = prev["since"] if prev and (prev["state"] == "working" or state != "working") else now
        board.upsert_status(ref, self.fs.agent, status_body(self.fs.agent, state, since, now, done, todo, note, kind=kind))
        if state == "done" and lesson.lower() not in NOTHING_LEARNED:
            self.state.setdefault("learned", []).append({"ref": ref, "at": now, "lesson": lesson[:1000]})
            self.state["learned"] = self.state["learned"][-50:]
            self.save()
        return "%s status %s -> %s" % (ref, self.fs.agent, state)

    def board_comment(self, ref: str, body: str) -> str:
        if not (body or "").strip():
            raise FlowError("empty comment")
        _, _, board = self._target(ref)
        board.comment(ref, body.rstrip() + "\n\n" + AGENT_MARK % self.fs.agent)
        return "commented on %s" % ref

    def board_move(self, ref: str, state: str, force: bool = False) -> str:
        _, dept, board = self._target(ref)
        if not dept.flow.has_state(state):
            raise FlowError("unknown state %r (states: %s)" % (state, ", ".join(s.key for s in dept.flow.states)))
        it = board.item(ref)
        if it is None:
            raise FlowError("%s is closed or not on the board" % ref)
        if state in ("ready", "doing") and it.blocked_by and not force:
            raise FlowError("%s is blocked by %d open item(s); refusing (force only if a human said so)" % (ref, it.blocked_by))
        board.move(ref, dept.flow.column(state))
        return "%s -> %s (%s)" % (ref, state, dept.flow.column(state))

    def board_set(self, ref: str, field: str, value: str) -> str:
        """A single-select field of the board (Size, Priority...), like `uns set`."""
        if not field.strip() or not value.strip():
            raise FlowError("field and value are required")
        _, _, board = self._target(ref)
        board.set_field(ref, field.strip(), value.strip())
        return "%s %s = %s" % (ref, field.strip(), value.strip())

    def board_label(self, ref: str, add: List[str], remove: List[str]) -> str:
        _, dept, board = self._target(ref)
        for label in [*add, *remove]:
            if any(r.agent_of(label) or label in r.pool_labels() for r in dept.flow.roles.values()):
                raise FlowError("%s: assignment labels are set by humans" % label)
        board.labels(ref, add=add, remove=remove)
        return "%s labels +%s -%s" % (ref, ",".join(add) or "-", ",".join(remove) or "-")
