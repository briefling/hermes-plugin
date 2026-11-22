"""Command approvals set per agent in the space settings (protocol/approval.ts), plugin side.

The hub pushes, per space and per agent, the mode and the humans whose click answers a card (``subscribed.approvals``,
then ``allowed.approvals`` on every settings save). On each exec approval card the adapter asks ``decide``:
  agent       Hermes' smart judge (guardian LLM) decides; a command it is unsure of keeps the card for a human.
              A prompt the guardian already denied (``smart_denied``) is denied without a second LLM call.
  always      approved at once.
  trusted /
  contributor the card waits for a human of ``users``.
Hermes' hardline blocklist runs before any card, so no mode reaches those commands. The hub re-checks every auto
answer against its own copy of the setting (``ask.auto``) and every click against the approvers.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

MODES = ("agent", "always", "trusted", "contributor")
DEFAULT = "trusted"


def parse(x: Any) -> Dict[str, Dict[str, Any]]:
    """`{agent: {mode, by, users}}` from the hub; anything malformed is dropped (that agent falls back to the default)."""
    out: Dict[str, Dict[str, Any]] = {}
    if not isinstance(x, dict):
        return out
    for agent, v in list(x.items())[:20]:
        if not (isinstance(agent, str) and isinstance(v, dict) and v.get("mode") in MODES):
            continue
        users = v.get("users") if isinstance(v.get("users"), list) else []
        out[agent] = {"mode": v["mode"], "by": str(v.get("by") or "")[:60],
                      "users": frozenset(u for u in users[:200] if isinstance(u, str) and 0 < len(u) <= 128)}
    return out


def mode_of(table: Dict[str, Dict[str, Dict[str, Any]]], space: str, agent: str) -> str:
    return ((table.get(space) or {}).get(agent) or {}).get("mode", DEFAULT)


def approvers(table: Dict[str, Dict[str, Dict[str, Any]]], space: str, agent: str) -> Optional[frozenset]:
    """Who may click a card of `agent` in `space`; None when the hub sent nothing for it (older hub: the caller keeps
    its own allowlist)."""
    x = (table.get(space) or {}).get(agent)
    return x["users"] if x else None


async def decide(mode: str, command: str, description: str, smart_denied: bool) -> Optional[str]:
    """'once' / 'deny' answered without a human, or None = show the card."""
    if mode == "always":
        return "once"
    if mode != "agent":
        return None
    if smart_denied:
        return "deny"
    try:
        from tools.approval_smart import _smart_approve
        verdict = await asyncio.get_running_loop().run_in_executor(None, _smart_approve, command, description)
    except Exception as e:  # no judge available: a human decides
        logger.warning("[briefling] smart approval unavailable: %s", type(e).__name__)
        return None
    return {"approve": "once", "deny": "deny"}.get(verdict)
