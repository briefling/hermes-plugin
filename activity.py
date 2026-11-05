"""What an LLM call was for (turn.ended.usage.activity): one category per call, from the tool calls the model decided.

Runs locally on the hook payload: only the category leaves the instance, never a tool argument or a command.
Categories mirror ``ACTIVITIES`` in protocol/frames.ts. Priority when one call decides several tools: the most
specific action wins (a call that patches a file and runs the tests counts as a test run).
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable, List, Optional, Tuple

ACTIVITIES = ("answer", "read", "code", "test", "deploy", "git", "coordination", "review", "compress", "other")

_PRIORITY = ("deploy", "test", "code", "git", "read", "coordination", "answer", "other")

_READ_TOOLS = frozenset({
    "read_file", "search_files", "web_search", "web_extract", "vision_analyze", "skill_view", "skills_list",
    "session_search", "chat_history_lookup", "memory_search", "memory_read", "tool_search", "tool_describe",
    "space_threads", "thread_read", "space_metrics",
})
_CODE_TOOLS = frozenset({"patch", "write_file"})
_SHELL_TOOLS = frozenset({"terminal"})
# Keeping the work in step with the others and with itself: locks, board, project memory, background processes,
# task lists, schedules, skills (outside the background review, which has its own category), starting sub-agents.
_COORDINATION_TOOLS = frozenset({
    "delegate_task",
    "acquire_resource", "release_resource", "pushed_commits", "flow_switch",
    "board_comment", "board_label", "board_move", "board_set", "board_status",
    "memory_propose", "memory_review", "memory_compact", "memory_tag", "memory_tag_merge", "memory",
    "process_manage", "process", "todo_list", "todo", "cronjob_manage", "cronjob", "skill_manage",
})
# Deferred tools (Tool Search): the model calls ``tool_call`` with ``{calls: [{name, arguments}]}``.
_WRAPPER_TOOLS = frozenset({"tool_call"})
_SCRIPT_TOOLS = frozenset({"execute_code"})
# Talking to the humans of the thread (briefling tools): the call is part of the answer.
_ANSWER_TOOLS = frozenset({
    "turn_outcome", "propose_thread", "propose_issue", "propose_plan", "propose_space_about", "topic_title",
    "ask_choices", "request_elevation", "radar_signal", "radar_profile", "clarify", "send_message", "text_to_speech",
})

# Shell commands, matched on the whole command line (`cd x && npm test` is a test run). Deploy before test before git.
_DEPLOY = re.compile(r"\b(npm run (-s )?deploy|cdk (deploy|destroy)|publish-plugin|sam deploy|terraform apply|"
                     r"serverless deploy|sls deploy|eas (build|submit|update)|fastlane)\b")
_TEST = re.compile(r"\b(npm (run (-s )?)?test|node --test|npx (tsc|vitest|jest|playwright)|tsc --noEmit|pytest|vitest|jest|"
                   r"go test|cargo test|ui-render|e2e|unittest)\b")
_GIT = re.compile(r"(^|[;&|(]\s*|\s)(git|gh)\s")
_READ = re.compile(r"^\s*(cd \S+\s*&&\s*)?(cat|sed -n|head|tail|grep|rg|ls|find|wc|less|tree|git (show|log|diff|status|grep))\b")
# execute_code: the same shell rules on its code, where commands sit in string literals (``terminal("git push")``,
# ``subprocess.run(["git", "push"])``). Writing a file is code; the hermes_tools reads, or a quoted read command, are reads.
_CODE_WRITE = re.compile(r"\b(write_file|patch)\s*\(|\.write_text\s*\(|\.write_bytes\s*\(|"
                         r"\bopen\s*\([^)]*,\s*(mode\s*=\s*)?['\"][wax]")
_CODE_GIT_READ = re.compile(r"['\"\s](git|gh)['\"]?(\s*,\s*['\"]|\s+)(-C\s+\S+\s+)?(show|log|diff|status|grep)\b")
_CODE_GIT = re.compile(r"(^|[;&|(\s'\"])(git|gh)['\"]?(\s*,\s*['\"]|\s)")
_CODE_READ = re.compile(r"\b(read_file|search_files|web_search|web_extract)\s*\(|"
                        r"['\"](cd \S+\s*&&\s*)?(cat|sed -n|head|tail|grep|rg|ls|find|wc)\b")


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


def _args(args: Any) -> Any:
    if isinstance(args, str):
        try:
            return json.loads(args)
        except ValueError:
            return None
    return args


def _field(args: Any, key: str) -> str:
    args = _args(args)
    v = args.get(key) if isinstance(args, dict) else None
    return v if isinstance(v, str) else ""


def _command(args: Any) -> str:
    return _field(args, "command")


def _wrapped(args: Any) -> List[Tuple[str, Any]]:
    """(name, arguments) of the tools a ``tool_call`` invokes."""
    args = _args(args)
    calls = args.get("calls") if isinstance(args, dict) else None
    return [(c["name"], c.get("arguments")) for c in calls or [] if isinstance(c, dict) and isinstance(c.get("name"), str)]


def code_activity(code: str) -> str:
    """Category of an ``execute_code`` script, from its code: the shell rules, writing a file = code."""
    if _DEPLOY.search(code):
        return "deploy"
    if _TEST.search(code):
        return "test"
    if _CODE_WRITE.search(code):
        return "code"
    if _CODE_GIT_READ.search(code):
        return "read"
    if _CODE_GIT.search(code):
        return "git"
    if _CODE_READ.search(code):
        return "read"
    return "other"


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
    if name in _WRAPPER_TOOLS:
        inner = _wrapped(args)
        return pick(tool_activity(n, a) for n, a in inner) if inner else "other"
    if name in _READ_TOOLS:
        return "read"
    if name in _CODE_TOOLS:
        return "code"
    if name in _COORDINATION_TOOLS:
        return "coordination"
    if name in _ANSWER_TOOLS:
        return "answer"
    if name in _SHELL_TOOLS:
        return shell_activity(_command(args))
    if name in _SCRIPT_TOOLS:
        return code_activity(_field(args, "code"))
    return "other"


def pick(categories: Iterable[str]) -> str:
    cats = set(categories)
    return next((c for c in _PRIORITY if c in cats), "other")


def in_background_review() -> bool:
    """Whether the running call belongs to Hermes' background self-improvement review. The review fork shares the
    parent's session id and platform, so the hook kwargs cannot tell it apart; Hermes binds the skill write origin
    ``background_review`` (a ContextVar, ``tools/skill_provenance.py``) at the start of each of its turns, in the thread
    where ``post_api_request`` fires. An older Hermes without it: never a review."""
    try:
        from tools.skill_provenance import get_current_write_origin
    except Exception:
        return False
    try:
        return get_current_write_origin() == "background_review"
    except Exception:
        return False


def call_activity(assistant_message: Any, platform: Optional[str] = None, review: Optional[bool] = None) -> str:
    """Category of one main-loop call (``post_api_request``). Every call of the background review counts as
    ``review``; a sub-agent's call (``platform == "subagent"``) counts by what it does, like the parent's. A call that
    decides no tool writes the answer. ``platform`` is kept for the hook's signature."""
    if review if review is not None else in_background_review():
        return "review"
    calls = _tool_calls(assistant_message) if assistant_message is not None else []
    if not calls:
        return "answer"
    return pick(tool_activity(n, a) for n, a in calls)


def aux_activity(aux_task: Any) -> str:
    """Category of an auxiliary call (``post_auxiliary_call``): context compression has its own, the rest
    (titles, vision, approval...) is ``other``."""
    return "compress" if aux_task == "compression" else "other"