"""Agent web preview, plugin side (protocol/preview.ts): shares, and the agent peers that serve them.

The plugin runs in the Hermes gateway process on the HOST, while the agent's terminal and its dev server may run in a
Docker sandbox (terminal backend docker) whose 127.0.0.1 the host cannot reach. So everything that touches
127.0.0.1:<port> runs INSIDE the agent's terminal environment, the one Hermes keeps for the calling session's
``task_id`` (``tools.terminal_tool_lifecycle.get_active_env`` / ``ensure_task_env``): the probe of ``preview_share``
and the peer process (``preview_peer.py``, headless Chromium) of each viewer session.

Security gates enforced here and in preview_peer.py:
- the peer only fetches relative paths of 127.0.0.1:<port> (previewPathOk, in the peer's page script);
- the TURN credentials of an offer go to the peer on its stdin, never on a command line (``ps`` shows those);
- at most MAX_PEERS live peers per gateway, each killed after PEER_MAX_S, on the viewer's close, on preview_stop and
  at gateway stop.
"""
import json
import logging
import os
import re
import secrets
import shlex
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

PORT_MIN, PORT_MAX = 1024, 65535          # protocol/preview.ts PREVIEW_PORT_MIN / MAX
LABEL_MAX = 80                            # protocol/preview.ts PREVIEW_LABEL_MAX
SDP_MAX = 16_384                          # protocol/preview.ts PREVIEW_SDP_MAX
CANDIDATE_MAX = 1024                      # protocol/preview.ts PREVIEW_CANDIDATE_MAX
SESSION_RE = re.compile(r"[A-Za-z0-9_-]{22,64}")  # protocol/preview.ts PREVIEW_SESSION_RE (fullmatch)
PREVIEW_ERRORS = ("not_shared", "not_connected", "preview_off", "gone", "no_browser", "port_closed", "busy",
                  "peer_failed", "timeout")  # protocol/preview.ts PREVIEW_ERRORS
MAX_PEERS = 3
PEER_MAX_S = 30 * 60
PROBE_TIMEOUT_S = 15                      # docker exec + python start, the probe itself waits 1 s
LOG_LINE_MAX = 200
PEER_SOURCE = (Path(__file__).with_name("preview_peer.py")).read_text(encoding="utf-8")
PROBE_OK = "BRIEFLING_PROBE_OK"
# Any HTTP answer (404, 500 included) means something listens; refused/timeout means nothing does.
PROBE_PY = (
    "import sys, urllib.request, urllib.error\n"
    "try:\n"
    "    urllib.request.urlopen('http://127.0.0.1:%d/' % int(sys.argv[1]), timeout=1).close()\n"
    "except urllib.error.HTTPError:\n"
    "    pass\n"
    "except Exception:\n"
    "    sys.exit(1)\n"
    "print('" + PROBE_OK + "')\n"
)


class PreviewError(Exception):
    """A preview step failed; ``code`` is one of PREVIEW_ERRORS."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code


def port_ok(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and PORT_MIN <= x <= PORT_MAX


def clean_label(x: Any) -> str:
    """One line, trimmed, bounded (the hub cleans it again and fills `localhost:<port>` when empty)."""
    s = re.sub(r"[\x00-\x1f\x7f]+", " ", x if isinstance(x, str) else "").strip()
    return s[:LABEL_MAX]


def sdp_ok(x: Any) -> bool:
    return isinstance(x, str) and 0 < len(x) <= SDP_MAX and x.startswith("v=0")


def candidate_ok(c: Any, mid: Any) -> bool:
    return (isinstance(c, str) and len(c) <= CANDIDATE_MAX and (c == "" or c.startswith("candidate:"))
            and (mid is None or (isinstance(mid, str) and len(mid) <= 32)))


# -- the agent's terminal environment ------------------------------------------------------------------------------

class HostEnv:
    """Local terminal backend: the agent's terminal IS this host. Same spawn/kill surface as a Hermes environment."""

    def _run_bash(self, cmd_string: str, *, login: bool = False, timeout: int = 120,
                  stdin_data: Optional[str] = None) -> subprocess.Popen:
        proc = subprocess.Popen(["bash", "-c", cmd_string], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                                text=True, encoding="utf-8", errors="replace", start_new_session=True)
        if stdin_data is not None:
            def _write():
                try:
                    proc.stdin.write(stdin_data)
                except (BrokenPipeError, OSError):
                    pass
                finally:
                    try:
                        proc.stdin.close()
                    except OSError:
                        pass
            threading.Thread(target=_write, daemon=True).start()
        return proc

    def _kill_process(self, proc) -> None:
        try:
            os.killpg(proc.pid, 15)
        except OSError:
            try:
                proc.kill()
            except OSError:
                pass


def _backend_is_local() -> bool:
    try:
        from tools.terminal_tool import _get_env_config  # private Hermes API: fail closed (not local) when missing
        return _get_env_config().get("env_type") == "local"
    except Exception:
        return False


def task_env(task_id: Optional[str]):
    """The live terminal environment of the agent session ``task_id`` (Hermes ``BaseEnvironment``), brought up when
    needed; ``HostEnv()`` on the local backend. Raises PreviewError(peer_failed) when there is none: never falls back
    to the host for a sandboxed agent (the host's 127.0.0.1:<port> is another machine's port)."""
    key = task_id or "default"
    try:
        from tools.terminal_tool_lifecycle import ensure_task_env, get_active_env
    except ImportError:
        get_active_env = ensure_task_env = None  # type: ignore[assignment]
    env = None
    if get_active_env is not None:
        env = get_active_env(key)
        if env is None:
            env = ensure_task_env(key)
    if env is not None:
        return env
    if _backend_is_local():
        return HostEnv()
    raise PreviewError("peer_failed", "the agent's terminal environment is not available")


def spawn_in_env(env, cmd: str, stdin_data: Optional[str] = None, timeout: int = PEER_MAX_S):
    """Run ``bash -c cmd`` in the agent's environment; returns a Popen-like handle whose ``stdout`` streams the output
    (stderr merged, text). ``stdin_data`` is written once, then stdin is closed.

    PRIVATE Hermes API: ``BaseEnvironment._run_bash(cmd_string, login=, timeout=, stdin_data=)``
    (tools/environments/base.py, Hermes 8237c7f8ec; Docker = ``docker exec -i``, local = ``bash -c`` in its own
    process group). It is the only way to start a streaming process in a sandbox; if a Hermes update removes or
    changes it, previews fail with ``peer_failed`` instead of breaking the plugin."""
    run = getattr(env, "_run_bash", None)
    if not callable(run):
        raise PreviewError("peer_failed", f"{type(env).__name__} has no _run_bash (Hermes API changed)")
    try:
        proc = run(cmd, login=False, timeout=timeout, stdin_data=stdin_data)
    except TypeError as e:
        raise PreviewError("peer_failed", f"_run_bash signature changed: {e}")
    if getattr(proc, "stdout", None) is None:
        raise PreviewError("peer_failed", "_run_bash returned no stdout stream")
    return proc


def probe_port(env, port: int) -> bool:
    """True when something answers HTTP on 127.0.0.1:<port> of the agent's environment (1-second probe)."""
    proc = spawn_in_env(env, f"python3 -c {shlex.quote(PROBE_PY)} {int(port)}", timeout=PROBE_TIMEOUT_S)
    try:
        out = proc.stdout.read() if hasattr(proc.stdout, "read") else "".join(proc.stdout)
        proc.wait(timeout=PROBE_TIMEOUT_S)
    except Exception:
        _kill(env, proc)
        return False
    return PROBE_OK in (out or "")


def peer_command(tag: str) -> str:
    return f"python3 -c {shlex.quote(PEER_SOURCE)} {tag}"


def _kill(env, proc) -> None:
    killer = getattr(env, "_kill_process", None)
    try:
        killer(proc) if callable(killer) else proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def kill_peer(env, proc, tag: str) -> None:
    """Stop a peer and its Chromium. Killing a ``docker exec`` client does not stop the process inside the
    container, so first TERM the pid the peer wrote (it then closes its browser), then kill the handle (the local
    backend kills the whole process group)."""
    if proc.poll() is None:
        try:
            k = spawn_in_env(env, f'f=/tmp/briefling-preview-{tag}.pid; [ -f "$f" ] && kill -TERM "$(cat "$f")"',
                             timeout=10)
            k.wait(timeout=10)
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
    if proc.poll() is None:
        _kill(env, proc)


# -- shares and peers ------------------------------------------------------------------------------------------------

class Peer:
    def __init__(self, session: str, thread: str, port: int, msg: str, tag: str):
        self.session, self.thread, self.port, self.msg, self.tag = session, thread, port, msg, tag
        self.env: Any = None
        self.proc: Any = None
        self.answered = False
        self.failed = False
        self.closing = False
        self.started = time.monotonic()
        self.timer: Any = None


class Previews:
    """Shares of this gateway (in memory: a restart forgets them, offers then fail ``gone``) and their live peers.

    ``send(frame)`` is a coroutine function that sends a frame to the hub; ``loop`` the gateway loop it runs on.
    Peer stdout is read in one daemon thread per peer; its lines become frames on the loop."""

    def __init__(self, send: Callable[[Dict[str, Any]], Any]):
        self.send = send
        self.loop: Any = None
        self.shares: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self.peers: Dict[str, Peer] = {}
        self.lock = threading.Lock()
        self.task_env = task_env          # seams for the tests
        self.spawn = spawn_in_env
        self.kill = kill_peer

    # shares
    def share_of(self, thread: str, port: int) -> Optional[Dict[str, Any]]:
        return self.shares.get((thread, port))

    def remember(self, thread: str, port: int, task_id: Optional[str], msg: str, label: str) -> None:
        self.shares[(thread, port)] = {"task_id": task_id, "msg": msg, "label": label}

    def forget(self, thread: str, port: int) -> Optional[Dict[str, Any]]:
        share = self.shares.pop((thread, port), None)
        if share:
            for p in [p for p in list(self.peers.values()) if p.thread == thread and p.port == port]:
                self.close(p.session)
        return share

    # peers
    async def offer(self, frame: Dict[str, Any]) -> None:
        import asyncio
        self.loop = asyncio.get_running_loop()
        session, thread, msg, port = frame.get("session"), frame.get("thread"), frame.get("msg"), frame.get("port")
        if not (isinstance(session, str) and SESSION_RE.fullmatch(session)):
            return
        if session in self.peers:
            return  # a duplicate offer of a running session
        share = self.share_of(thread, port) if isinstance(thread, str) and port_ok(port) else None
        if share is None or share["msg"] != msg:
            return await self._failed(session, "gone")
        sdp, ice = frame.get("sdp"), frame.get("ice")
        if not sdp_ok(sdp) or not isinstance(ice, list):
            return await self._failed(session, "peer_failed")
        with self.lock:
            if len(self.peers) >= MAX_PEERS:
                busy = True
            else:
                busy = False
                peer = Peer(session, thread, port, msg, secrets.token_hex(8))
                self.peers[session] = peer
        if busy:
            return await self._failed(session, "busy")
        # The TURN credentials (ice) travel on stdin only; the command line carries the source and a random tag.
        stdin = json.dumps({"port": port, "sdp": sdp, "ice": [s for s in ice if isinstance(s, dict)],
                            "max_s": PEER_MAX_S}) + "\n"
        try:
            peer.env = await self.loop.run_in_executor(None, self.task_env, share["task_id"])
            peer.proc = await self.loop.run_in_executor(None, lambda: self.spawn(peer.env, peer_command(peer.tag), stdin))
        except PreviewError as e:
            logger.warning("[briefling] preview peer not started: %s", e)
            self.peers.pop(session, None)
            return await self._failed(session, e.code if e.code in PREVIEW_ERRORS else "peer_failed")
        except Exception as e:
            logger.warning("[briefling] preview peer not started: %s", type(e).__name__)
            self.peers.pop(session, None)
            return await self._failed(session, "peer_failed")
        if peer.closing:  # closed while it was starting
            self._kill_async(peer)
            return
        peer.timer = self.loop.call_later(PEER_MAX_S, self.close, session)
        threading.Thread(target=self._read, args=(peer,), daemon=True, name=f"preview-{peer.tag}").start()
        logger.info("[briefling] preview peer started for port %d (%d live)", port, len(self.peers))

    def _read(self, peer: Peer) -> None:
        """Peer stdout, in its own thread: JSON lines become frames, anything else is a log line (never forwarded)."""
        try:
            for line in peer.proc.stdout:
                line = line.rstrip("\r\n")
                try:
                    obj = json.loads(line) if line.startswith("{") else None
                except ValueError:
                    obj = None
                if not isinstance(obj, dict) or not isinstance(obj.get("t"), str):
                    if line.strip():
                        logger.debug("[briefling] preview peer: %s", line[:LOG_LINE_MAX])
                    continue
                self._call(self._on_line(peer, obj))
        except Exception as e:  # stream closed by a kill
            logger.debug("[briefling] preview peer stream: %s", type(e).__name__)
        finally:
            self._call(self._ended(peer))

    def _call(self, coro) -> None:
        import asyncio
        try:
            fut = asyncio.run_coroutine_threadsafe(coro, self.loop)
        except RuntimeError:  # loop closed: gateway gone
            coro.close()
            return
        try:
            fut.result(timeout=30)
        except Exception as e:
            logger.debug("[briefling] preview frame not sent: %s", type(e).__name__)

    async def _on_line(self, peer: Peer, obj: Dict[str, Any]) -> None:
        t = obj["t"]
        if peer.closing:
            return
        if t == "answer" and sdp_ok(obj.get("sdp")):
            peer.answered = True
            await self.send({"type": "preview.answer", "session": peer.session, "sdp": obj["sdp"]})
        elif t == "candidate" and candidate_ok(obj.get("candidate"), obj.get("mid")):
            await self.send({"type": "preview.candidate", "session": peer.session, "candidate": obj["candidate"],
                             "mid": obj.get("mid")})
        elif t == "error":
            code = obj.get("code") if obj.get("code") in PREVIEW_ERRORS else "peer_failed"
            await self._failed(peer.session, code)
            peer.failed = True
        elif t == "state":
            logger.info("[briefling] preview peer %s: %s", peer.tag, str(obj.get("state"))[:20])

    async def _ended(self, peer: Peer) -> None:
        if self.peers.get(peer.session) is peer:
            self.peers.pop(peer.session, None)
        if peer.timer:
            peer.timer.cancel()
        if not (peer.answered or peer.failed or peer.closing):
            await self._failed(peer.session, "peer_failed")
        logger.info("[briefling] preview peer %s ended (%d live)", peer.tag, len(self.peers))

    async def _failed(self, session: str, code: str) -> None:
        await self.send({"type": "preview.failed", "session": session, "code": code})

    def close(self, session: Any) -> None:
        """Viewer closed (hub ``preview.close``), share stopped or the hard cap: kill the peer (off the loop)."""
        peer = self.peers.pop(session, None) if isinstance(session, str) else None
        if peer is None:
            return
        peer.closing = True
        if peer.timer:
            peer.timer.cancel()
        if peer.proc is not None:
            self._kill_async(peer)

    def _kill_async(self, peer: Peer) -> None:
        threading.Thread(target=self.kill, args=(peer.env, peer.proc, peer.tag), daemon=True).start()

    def close_all(self, wait_s: float = 10) -> None:
        """Gateway stop: kill every peer, waiting up to ``wait_s`` for them."""
        peers = list(self.peers.values())
        self.peers.clear()
        threads: List[threading.Thread] = []
        for p in peers:
            p.closing = True
            if p.timer:
                p.timer.cancel()
            if p.proc is not None:
                th = threading.Thread(target=self.kill, args=(p.env, p.proc, p.tag), daemon=True)
                th.start()
                threads.append(th)
        end = time.monotonic() + wait_s
        for th in threads:
            th.join(max(0.0, end - time.monotonic()))
