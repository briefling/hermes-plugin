"""Second source of the browser thumbnail: Playwright (Python) scripts the agent runs in its sandbox's terminal.

Hermes' own browser tool feeds browserthumb.py after each ``browser_*`` call. An agent that drives Chromium with its
own Playwright script instead (from ``terminal`` or ``execute_code``) never goes through that tool, so:

1. once per sandbox, the plugin copies ``pwthumb_sandbox.py`` next to the sandbox's Playwright package with a ``.pth``
   line importing it, so every later Python script that imports Playwright writes its page to ``SHOT`` after each
   action (no change to the agent's scripts, no port opened, stdlib only);
2. while a terminal-like tool call of a briefling turn runs, a poller reads ``SHOT`` from that same sandbox (the
   environment object resolved inside the turn, never looked up later) at most once per second, only if the file is
   newer than the tool call and the image changed, and hands it to the existing ``browser.frame`` path (same rate,
   watchers pause and end frame as browserthumb.py).

Sandboxed backends only: on the local backend the « sandbox » is the host, and the plugin never writes into the
host's Python. Best effort everywhere: a failure costs a debug line, never the agent's call.
"""
from __future__ import annotations

import base64
import logging
import shlex
import threading
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

TOOLS = frozenset({"terminal", "execute_code"})
DIR = "/tmp/briefling-thumb"          # pwthumb_sandbox.DIR
SHOT = f"{DIR}/frame.jpg"
MAX_BYTES = 2 * 1024 * 1024
POLL_S = 1.0
MODULE = Path(__file__).with_name("pwthumb_sandbox.py")
PTH = "briefling-pwthumb.pth"


def install_cmd() -> str:
    """Shell command that drops the module + .pth beside Playwright in the sandbox's python3 (no Playwright: no-op)."""
    src = base64.b64encode(MODULE.read_bytes()).decode("ascii")
    py = ("import base64,os,sys\n"
          "try:\n import playwright\nexcept Exception:\n sys.exit(0)\n"
          "d=os.path.dirname(os.path.dirname(playwright.__file__))\n"
          f"open(os.path.join(d,'briefling_pwthumb.py'),'wb').write(base64.b64decode('{src}'))\n"
          f"open(os.path.join(d,'{PTH}'),'w').write('import briefling_pwthumb\\n')\n")
    return f"python3 -c {shlex.quote(py)} >/dev/null 2>&1; true"


def read_cmd(since_ms: int) -> str:
    """Prints ``T<mtime ms>`` then the base64 JPEG when ``SHOT`` is newer than ``since_ms``; nothing otherwise."""
    return (f"f={SHOT}; t=$(date -r \"$f\" +%s%3N 2>/dev/null) || exit 0; "
            f"[ \"$t\" -gt {int(since_ms)} ] || exit 0; echo \"T$t\"; head -c {MAX_BYTES} \"$f\" | base64 -w0")


def parse(out: str) -> Optional[tuple]:
    """``read_cmd`` output -> (mtime ms, image bytes), or None."""
    if not isinstance(out, str):
        return None
    head, _, body = out.strip().partition("\n")
    head = head.strip()
    if not head.startswith("T") or not head[1:].isdigit() or not body.strip():
        return None
    try:
        return int(head[1:]), base64.b64decode(body.strip(), validate=True)
    except Exception:
        return None


def sandboxed(env: Any) -> bool:
    return env is not None and "local" not in type(env).__name__.lower()


class Poller:
    """One per running tool call: reads the sandbox's capture every ``POLL_S`` until ``stop``."""

    def __init__(self, env_of: Callable[[], Any], send: Callable[[bytes], None], since_ms: int,
                 installed: set, lock: threading.Lock, ready: Callable[[], bool] = lambda: True,
                 interval: float = POLL_S):
        self._env_of, self._send, self._since, self._ready = env_of, send, since_ms, ready
        self._installed, self._lock, self._interval = installed, lock, interval
        self._stop = threading.Event()
        self._env = None

    def env(self):
        if self._env is None:
            env = self._env_of()
            if sandboxed(env):
                self._env = env
                with self._lock:
                    fresh = id(env) not in self._installed
                    self._installed.add(id(env))
                if fresh:
                    env.execute(install_cmd(), timeout=20)
        return self._env

    def tick(self) -> None:
        env = self.env()
        if env is None or not self._ready():  # ready: rate and « nobody watches » pause, before any read
            return
        got = parse((env.execute(read_cmd(self._since), timeout=10) or {}).get("output", ""))
        if got:
            self._since = got[0]
            self._send(got[1])

    def run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self.tick()
            except Exception:
                logger.debug("[briefling] playwright thumbnail read failed", exc_info=True)
        try:
            self.tick()  # the last page of a short script
        except Exception:
            logger.debug("[briefling] playwright thumbnail read failed", exc_info=True)

    def stop(self) -> None:
        self._stop.set()
