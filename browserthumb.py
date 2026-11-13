"""Live thumbnail of the agent's browser (protocol/browser.ts).

After each ``browser_*`` tool call of a briefling turn, the plugin takes a screenshot of the page through Hermes' own
browser tool (same session, same sandbox: no CDP port opened, nothing the agent did not already have) and sends it to
the hub as a small JPEG, at most once per ``MIN_S`` per conversation and only when the image changed. The hub answers
how many tabs got it (``browser.watchers``); 0 = nobody looks, no capture for ``IDLE_S``. At the turn's end an ``end``
frame tells the tabs to drop it. Everything is best effort: a failure costs a log line, never the agent's tool call.

The capture uses Hermes internals (``tools.browser_tool_session``): if a Hermes update moves them, ``capture`` returns
None and the feature is simply off (tests/test_browserthumb.py pins the names it needs).
"""
from __future__ import annotations

import base64
import hashlib
import io
import logging
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, Dict, Optional

logger = logging.getLogger(__name__)

MIN_S = 1.0           # protocol/browser.ts BROWSER_MIN_MS
IDLE_S = 10.0         # protocol/browser.ts BROWSER_IDLE_MS
# API Gateway closes a WebSocket with 1009 on any frame over 32 KB (« WebSocket frame size » quota; only a message split
# into several frames may reach 128 KB, and aiohttp sends one frame per message). A 45 KB thumbnail of a busy page
# disconnected the agent from the hub, so the whole JSON frame stays under 32 KB: base64 <= 31 000 chars.
# protocol/browser.ts BROWSER_JPEG_MAX (90 000) stays the hub's own bound.
JPEG_MAX = 31_000
FRAME_MAX = 32_000    # bytes of the serialized browser.frame (adapter._send_frame drops a larger one)
WIDTH = 640           # thumbnail width: ~20 KB at quality 55 for a usual page
QUALITIES = (55, 40, 25)
SMALL = (480, 25)     # last try for a busy page: narrower, low quality
# Tools that only read the page or run in another context: no capture after them.
SKIP = frozenset({"browser_console", "browser_get_images", "browser_vault", "browser_dialog"})


def is_browser_tool(name: str) -> bool:
    return isinstance(name, str) and name.startswith("browser_") and name not in SKIP


def to_jpeg(png: bytes) -> Optional[tuple]:
    """PNG bytes -> (base64 JPEG, w, h) at most WIDTH wide and JPEG_MAX long, or None (no Pillow, bad image, too big)."""
    try:
        from PIL import Image
    except Exception:
        return None
    try:
        im = Image.open(io.BytesIO(png))
        im = im.convert("RGB")
        if im.width > WIDTH:
            im = im.resize((WIDTH, max(1, round(im.height * WIDTH / im.width))), Image.LANCZOS)
        im = im.crop((0, 0, im.width, min(im.height, round(im.width * 1.25))))  # the top of a long page only
        small = im.resize((SMALL[0], max(1, round(im.height * SMALL[0] / im.width))), Image.LANCZOS) if im.width > SMALL[0] else im
        for img, q in [(im, q) for q in QUALITIES] + [(small, SMALL[1])]:
            buf = io.BytesIO()
            img.save(buf, "JPEG", quality=q, optimize=True)
            b64 = base64.b64encode(buf.getvalue()).decode("ascii")
            if len(b64) <= JPEG_MAX:
                return b64, img.width, img.height
    except Exception:
        logger.debug("[briefling] browser thumbnail: bad image", exc_info=True)
    return None


def capture(task_id: str) -> Optional[bytes]:
    """PNG of the page the agent's browser session shows (viewport), or None."""
    try:
        from tools import browser_tool_session as s
    except Exception:
        return None
    with tempfile.TemporaryDirectory(prefix="briefling-thumb-") as d:
        dest = Path(d) / f"thumb-{int(time.time() * 1000)}.png"
        try:
            remote = s.sandbox_screenshot_path(dest)
            r = s._run_browser_command(task_id, "screenshot", [remote or str(dest)], timeout=10)
            if not r.get("success"):
                return None
            if remote:
                s.fetch_sandbox_file(str((r.get("data") or {}).get("path") or remote), dest, max_bytes=8 * 1024 * 1024)
            return dest.read_bytes() if dest.exists() else None
        except Exception:
            logger.debug("[briefling] browser thumbnail: capture failed", exc_info=True)
            return None


class Thumbs:
    """Per conversation: when the last capture went, the last image sent, the pause after « nobody watches »."""

    def __init__(self, now: Callable[[], float] = time.monotonic):
        self._now = now
        self._lock = threading.Lock()
        self._last: Dict[str, float] = {}
        self._hash: Dict[str, str] = {}
        self._paused: Dict[str, float] = {}

    def due(self, thread: str) -> bool:
        """A capture may be taken now (rate and pause); reserves the slot."""
        with self._lock:
            t = self._now()
            if t < self._paused.get(thread, 0) or t - self._last.get(thread, -1e9) < MIN_S:
                return False
            self._last[thread] = t
            return True

    def changed(self, thread: str, jpeg: str) -> bool:
        h = hashlib.sha256(jpeg.encode("ascii")).hexdigest()
        with self._lock:
            if self._hash.get(thread) == h:
                return False
            self._hash[thread] = h
            return True

    def watchers(self, thread: str, n: int) -> None:
        with self._lock:
            if n <= 0:
                self._paused[thread] = self._now() + IDLE_S
                self._hash.pop(thread, None)  # a viewer who comes back gets the image even if unchanged
            else:
                self._paused.pop(thread, None)

    def end(self, thread: str) -> bool:
        """Turn over: forget the conversation; True when a capture went out this turn (an end frame is owed)."""
        with self._lock:
            sent = self._hash.pop(thread, None) is not None
            self._last.pop(thread, None)
            self._paused.pop(thread, None)
            return sent


def frame(thread: str, jpeg: str, w: int, h: int) -> dict:
    return {"type": "browser.frame", "thread": thread, "at": int(time.time() * 1000), "jpeg": jpeg, "w": w, "h": h}


def end_frame(thread: str) -> dict:
    return {"type": "browser.frame", "thread": thread, "at": int(time.time() * 1000), "end": True}
