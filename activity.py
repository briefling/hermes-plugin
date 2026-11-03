"""What an LLM call was for (turn.ended.usage.activity): one category per call, from the tool calls the model decided.

Runs locally on the hook payload: only the category leaves the instance, never a tool argument or a command.
Categories mirror ``ACTIVITIES`` in protocol/frames.ts. Priority when one call decides several tools: the most
specific action wins (a call that patches a file and runs the tests counts as a test run).
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable, List, Optional, Tuple

ACTIVITIES = ("answer", "read", "code", "test", "deploy", "git", "delegate", "compress", "other")

_PRIORITY = ("deploy", "test", "code", "git", "delegate", "read", "answer", "other")

_READ_TOOLS = frozenset({
    "read_file", "search_files", "web_search", "web_extract", "vision_analyze", "skill_view", "skills_list",
    "session_search", "chat_history_lookup", "memory_search", "memory_read", "tool_search", "tool_describe",
})
_CODE_TOOLS = frozenset({"patch", "write_file"})
_SHELL_TOOLS = frozenset({"terminal"})
_DELEGATE_TOOLS = frozenset({"delegate_task"})
# Talking to the humans of the thread (briefling tools): the call is part of the answer.
_ANSWER_TOOLS = frozenset({
    "turn_outcome", "propose_thread", "propose_issue", "propose_plan", "propose_space_about", "topic_title",
    "clarify", "send_message", "text_to_speech",
})

# Shell commands, matched on the whole command line (`cd x && npm test` is a test run). Deploy before test before git.
_DEPLOY = re.compile(r"\b(npm run (-s )?deploy|cdk (deploy|destroy)|publish-plugin|sam deploy|terraform apply|"
                     r"serverless deploy|sls deploy|eas (build|submit|update)|fastlane)\b")
_TEST = re.compile(r"\b(npm (run (-s )?)?test|npx (tsc|vitest|jest|playwright)|tsc --noEmit|pytest|vitest|jest|"
                   r"go test|cargo test|ui-render|e2e|unittest)\b")
_GIT = re.compile(r"(^|[;&|(]\s*|\s)(git|gh)\s")
_READ = re.compile(r"^\s*(cd \S+\s*&&\s*)?(cat|sed -n|head|tail|grep|rg|ls|find|wc|less|tree|git (show|log|diff|status|grep))\b")


def _tool_calls(message: Any) -> List[Tuple[str, Any]]:
    """(name, raw arguments) of each tool call of an assistant message (SDK object or dict)."""
    calls = message.get("tool_calls") if isinstance(message, dict) else getattr(message, "tool_calls", None)
    out = []
    for c in calls or []:
        fn = c.get("function") if isinstance(c, dict) else getattr(c, "function", None)
        if fn is None:
            continue
        name = fn.get("name") if isinstance(fn, dict) else getattr(fn, "name", None)
        args = fn.get("arguments") if isinstance(fn, dict) else getattr(fn, "arguments", None)
        if isinstance(name, str):
            out.append((name, args))
    return out


def _command(args: Any) -> str:
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            return ""
    cmd = args.get("command") if isinstance(args, dict) else None
    return cmd if isinstance(cmd, str) else ""


def shell_activity(command: str) -> str:
    if _DEPLOY.search(command):
        return "deploy"
    if _TEST.search(command):
        return "test"
    if _READ.search(command):
        return "read"  # `git log`, `git show` included: reading history, not git work
    if _GIT.search(command):
        return "git"
    return "other"


def tool_activity(name: str, args: Any = None) -> str:
    if name in _READ_TOOLS:
        return "read"
    if name in _CODE_TOOLS:
        return "code"
    if name in _DELEGATE_TOOLS:
        return "delegate"
    if name in _ANSWER_TOOLS:
        return "answer"
    if name in _SHELL_TOOLS:
        return shell_activity(_command(args))
    return "other"


def pick(categories: Iterable[str]) -> str:
    cats = set(categories)
    return next((c for c in _PRIORITY if c in cats), "other")


def call_activity(assistant_message: Any, platform: Optional[str] = None) -> str:
    """Category of one main-loop call (``post_api_request``). A sub-agent's calls all count as ``delegate``;
    a call that decides no tool writes the answer."""
    if platform == "subagent":
        return "delegate"
    calls = _tool_calls(assistant_message) if assistant_message is not None else []
    if not calls:
        return "answer"
    return pick(tool_activity(n, a) for n, a in calls)


def aux_activity(aux_task: Any) -> str:
    """Category of an auxiliary call (``post_auxiliary_call``): context compression has its own, the rest
    (titles, vision, approval...) is ``other``."""
    return "compress" if aux_task == "compression" else "other"
