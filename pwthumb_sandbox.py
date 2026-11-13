"""Thumbnail source for Playwright (Python) scripts an agent runs in its own sandbox's terminal.

The briefling plugin copies this file into the sandbox next to the Playwright package, with a ``.pth`` line that
imports it at every Python start (pwthumb.py). Importing it costs one meta-path finder and nothing else: Playwright
itself is only patched when a script imports it. Then, after each page action (goto, click, fill, press...), the
page's viewport is written as a JPEG to ``DIR/frame.jpg`` (at most once per ``MIN_S``, atomic rename), and the plugin
reads that file while the agent's terminal call runs. No port, no network, no new dependency; any failure is silent
and never touches the script's own calls.

Self-contained on purpose (stdlib only): it runs inside the agent's sandbox, not in the gateway.
"""
import importlib.abc
import os
import sys
import time

DIR = "/tmp/briefling-thumb"
NAME = "frame.jpg"
MIN_S = 1.0
TARGET = "playwright._impl._connection"
# Protocol methods (Page / Frame / Keyboard / Mouse channels) after which the page may look different.
ACTIONS = frozenset({
    "goto", "reload", "goBack", "goForward", "setContent", "click", "dblclick", "tap", "fill", "press", "type",
    "check", "uncheck", "selectOption", "hover", "setInputFiles", "dragAndDrop", "waitForTimeout", "waitForLoadState",
    "waitForURL", "keyboardPress", "keyboardType", "keyboardInsertText", "mouseClick", "mouseWheel", "setViewportSize",
})
_last = [0.0]
_busy = [False]


def _page_of(owner):
    t = getattr(owner, "_type", "")
    if t == "Page":
        return owner
    if t == "Frame":
        return getattr(owner, "_page", None)
    return None


async def _shot(page) -> None:
    now = time.monotonic()
    if _busy[0] or now - _last[0] < MIN_S or page is None or page.is_closed():
        return
    _busy[0], _last[0] = True, now
    try:
        data = await page.screenshot(type="jpeg", quality=60, timeout=3000)
        os.makedirs(DIR, mode=0o700, exist_ok=True)
        tmp = os.path.join(DIR, f".{os.getpid()}.jpg")
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, os.path.join(DIR, NAME))
    except Exception:
        pass
    finally:
        _busy[0] = False


def patch(connection_module) -> bool:
    """Wrap ``Channel.send`` once: the call runs untouched, then a capture of its page when it was an action."""
    Channel = getattr(connection_module, "Channel", None)
    send = getattr(Channel, "send", None)
    if send is None or getattr(send, "_briefling", False):
        return False

    async def wrapped(self, method, *a, **k):
        r = await send(self, method, *a, **k)
        if method in ACTIONS:
            try:
                await _shot(_page_of(self._object))
            except Exception:
                pass
        return r

    wrapped._briefling = True
    Channel.send = wrapped
    return True


class _Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name != TARGET:
            return None
        sys.meta_path.remove(self)
        try:
            import importlib.util
            spec = importlib.util.find_spec(name)
        finally:
            sys.meta_path.insert(0, self)
        if spec is None or spec.loader is None:
            return spec
        run = spec.loader.exec_module

        def exec_module(module):
            run(module)
            try:
                patch(module)
            except Exception:
                pass
        spec.loader.exec_module = exec_module
        return spec


def install() -> None:
    if os.environ.get("BRIEFLING_THUMB") == "0" or any(isinstance(f, _Finder) for f in sys.meta_path):
        return
    if TARGET in sys.modules:
        patch(sys.modules[TARGET])
    else:
        sys.meta_path.insert(0, _Finder())


install()
