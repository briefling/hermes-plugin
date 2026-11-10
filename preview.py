"""Agent web preview, plugin side (protocol/preview.ts): shares, and the agent peers that serve them.

The plugin runs in the Hermes gateway process on the HOST, while the agent's terminal and its dev server may run in a
Docker sandbox (terminal backend docker) whose 127.0.0.1 the host cannot reach. So everything that touches
127.0.0.1:<port> runs INSIDE the agent's terminal environment, the one Hermes keeps for the calling session's
``task_id`` (``tools.terminal_tool_lifecycle.get_active_env`` / ``ensure_task_env``): the probe of ``preview_share``
and the peer process (``preview_peer.py``, headless Chromium) of each viewer session. A screen share runs
``screen_peer.py`` instead, a voice channel ``voice_peer.py`` (a relay to the local voice daemon of the agent's
machine, voice/: the plugin only keeps the path of the daemon's url-file; the peer reads it in the sandbox, so the
daemon's URL and token never reach the gateway, the hub, a command line or a log).

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
                  "peer_failed", "timeout", "no_device", "no_scrcpy", "no_voice")  # protocol/preview.ts PREVIEW_ERRORS
DEVICE_RE = re.compile(r"[A-Za-z0-9._:-]{1,64}")  # protocol/preview.ts PREVIEW_DEVICE_RE (fullmatch)
MAX_PEERS = 3
PEER_MAX_S = 30 * 60


def peer_life(max_s: Any) -> int:
    """Seconds a peer may live: PEER_MAX_S, or less for a visitor link (`max_s` of preview.offer: the time left before
    its deadline, protocol/preview.ts « Visitor link »). Anything but a positive int is ignored."""
    if isinstance(max_s, int) and not isinstance(max_s, bool) and max_s > 0:
        return min(PEER_MAX_S, max_s)
    return PEER_MAX_S
PROBE_TIMEOUT_S = 15                      # docker exec + python start, the probe itself waits 1 s
LOG_LINE_MAX = 200
PEER_SOURCE = (Path(__file__).with_name("preview_peer.py")).read_text(encoding="utf-8")
SCREEN_PEER_SOURCE = (Path(__file__).with_name("screen_peer.py")).read_text(encoding="utf-8")
VOICE_PEER_SOURCE = (Path(__file__).with_name("voice_peer.py")).read_text(encoding="utf-8")
VOICE_FILE_MAX = 1024
# Peers need Playwright: an optional venv of the agent's machine wins over the plain python3 of the sandbox PATH
# (which may have none). Expanded by the sandbox's shell: $HOME is the sandbox user's.
PEER_VENV_PYTHON = "$HOME/.venvs/briefling-peer/bin/python"
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


class _Voice:
    """Share key of a voice channel (shares are keyed ``(thread, port | device | VOICE)``): not a str, so it is never
    mistaken for a device."""

    def __repr__(self):
        return "VOICE"


VOICE = _Voice()
# The daemon's url-file (voice/briefling_voice/daemon.py --url-file): exactly ws://127.0.0.1:<port>/<token>, one
# optional trailing newline. Same pattern in voice_peer.py and in PROBE_VOICE_PY.
VOICE_URL_RE = re.compile(r"ws://127\.0\.0\.1:(\d{1,5})/[A-Za-z0-9_-]{16,64}")
# TCP connect only: the daemon takes ONE WebSocket client, a probe that opened one would be seen as a ghost client.
# The path comes on stdin; the URL is never printed.
PROBE_VOICE_PY = (
    "import json, re, socket, sys\n"
    "def out(s):\n"
    "    print('" + PROBE_OK + " ' + s)\n"
    "    sys.exit(0)\n"
    "try:\n"
    "    path = json.loads(sys.stdin.readline())['path']\n"
    "    with open(path, 'r', encoding='ascii') as f:\n"
    "        raw = f.read(256)\n"
    "except Exception:\n"
    "    out('no file')\n"
    "raw = raw[:-1] if raw.endswith('\\n') else raw\n"
    "m = re.fullmatch(r'ws://127\\.0\\.0\\.1:(\\d{1,5})/[A-Za-z0-9_-]{16,64}', raw)\n"
    "if not m or not 1 <= int(m.group(1)) <= 65535:\n"
    "    out('bad url')\n"
    "try:\n"
    "    socket.create_connection(('127.0.0.1', int(m.group(1))), timeout=1).close()\n"
    "except OSError:\n"
    "    out('not listening')\n"
    "out('ok')\n"
)


class PreviewError(Exception):
    """A preview step failed; ``code`` is one of PREVIEW_ERRORS."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code


def port_ok(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and PORT_MIN <= x <= PORT_MAX


def device_ok(x: Any) -> bool:
    """An adb serial: no shell character (it is quoted anyway where a command line carries it)."""
    return isinstance(x, str) and DEVICE_RE.fullmatch(x) is not None


def target_ok(x: Any) -> bool:
    """What a share points at: a port (web page), an adb serial (screen) or VOICE (voice channel)."""
    return x is VOICE or port_ok(x) or device_ok(x)


def voice_file_ok(x: Any) -> bool:
    """A url-file path as the agent gives it: one bounded line, no control character. Not secret, and trusted for
    nothing but a read in the agent's own sandbox."""
    return (isinstance(x, str) and 0 < len(x) <= VOICE_FILE_MAX and not re.search(r"[\x00-\x1f\x7f]", x)
            and not re.match(r"wss?://", x, re.I))  # the URL itself, pasted instead of its file


def voice_url_ok(raw: Any) -> Optional[int]:
    """The daemon port when ``raw`` (the url-file's content) is exactly ws://127.0.0.1:<port>/<token> (one trailing
    newline allowed), else None."""
    if not isinstance(raw, str):
        return None
    m = VOICE_URL_RE.fullmatch(raw[:-1] if raw.endswith("\n") else raw)
    return int(m.group(1)) if m and 1 <= int(m.group(1)) <= 65535 else None


def target_what(x: Any) -> str:
    """A share's target, for the agent's messages and logs."""
    return "voice channel" if x is VOICE else f"device {x}" if isinstance(x, str) else f"port {x}"


def target_frame(x: Any) -> Dict[str, Any]:
    """The target fields of ``preview.share`` (protocol/frames.ts: exactly one of port, device, voice)."""
    return {"voice": True} if x is VOICE else {"device": x} if isinstance(x, str) else {"port": x}


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


# Voice on request (protocol/preview.ts « Voice on request »): BRIEFLING_VOICE names a directory of the agent's terminal
# holding `start` (an executable that runs the daemon with `--url-file <dir>/url`, in the foreground). The plugin starts
# it detached (own session: it outlives the command and the agent's turn), its output in `<dir>/daemon.log`; the
# directory rides on stdin, never in the command line.
VOICE_START_S = 90  # a cold start loads the STT and TTS models
VOICE_POLL_S = 1.0
START_VOICE_PY = (
    "import json, os, subprocess, sys\n"
    "def out(s):\n"
    "    print('" + PROBE_OK + " ' + s)\n"
    "    sys.exit(0)\n"
    "try:\n"
    "    d = json.loads(sys.stdin.readline())['dir']\n"
    "except Exception:\n"
    "    out('no dir')\n"
    "start = os.path.join(d, 'start')\n"
    "if not (os.path.isfile(start) and os.access(start, os.X_OK)):\n"
    "    out('no start')\n"
    "log = open(os.path.join(d, 'daemon.log'), 'ab')\n"
    "subprocess.Popen([start], cwd=d, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)\n"
    "out('started')\n"
)


def voice_url_file(voice_dir: str) -> str:
    """The url-file the daemon of a BRIEFLING_VOICE directory writes."""
    return voice_dir.rstrip("/") + "/url"


def start_voice(env, voice_dir: str) -> str:
    """Start the voice daemon of ``voice_dir`` in the agent's environment: 'started', 'no start' (no executable
    ``start`` there), 'no dir' or 'no answer'. Does not wait for it to listen (``probe_voice`` does)."""
    proc = spawn_in_env(env, python_command(START_VOICE_PY), stdin_data=json.dumps({"dir": voice_dir}) + "\n",
                        timeout=PROBE_TIMEOUT_S)
    try:
        out = proc.stdout.read() if hasattr(proc.stdout, "read") else "".join(proc.stdout)
        proc.wait(timeout=PROBE_TIMEOUT_S)
    except Exception:
        _kill(env, proc)
        return "no answer"
    m = re.search(PROBE_OK + r" (started|no start|no dir)\b", out or "")
    return m.group(1) if m else "no answer"


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


def in_turn_context(ctx, fn):
    """Run ``fn`` in a copy of the agent turn's context captured at ``preview_share`` (``contextvars``).

    Why: an offer arrives on the adapter's own task, outside any agent turn. A multiplexed gateway reads each
    profile's secrets only under that profile's secret scope (Hermes ``agent/secret_scope.py``, a ContextVar set
    for the turn); without it, starting the peer (``_run_bash`` forwards the profile's env passthrough) raises
    ``UnscopedSecretError``. Re-entering the turn's own context gives exactly that profile's scope and nothing more
    (never a wider allowlist). A copy per call: one Context cannot be entered by two threads at once."""
    return ctx.copy().run(fn) if ctx is not None else fn()


def session_env(shared_env):
    """The agent's environment for a preview session, at an offer: OUTSIDE any agent turn.

    Gate: outside a turn Hermes has no session/profile context, so looking the environment up by
    ``task_id`` (``get_active_env`` / ``ensure_task_env``) resolves another key (``default``) or answers « local »: a
    sandboxed agent whose container was reaped would then get its peer started on the HOST, as the gateway user, or in
    another profile's container. So the environment is resolved once, inside the agent's turn (``preview_share``), and
    here it must still be that very object among Hermes' live environments (identity, no key lookup, no creation);
    otherwise ``gone``. Only a share made on the local backend (``HostEnv``) runs on the host."""
    if isinstance(shared_env, HostEnv):
        return shared_env
    if shared_env is None:
        raise PreviewError("gone", "no terminal environment was recorded with the share")
    try:
        from tools.terminal_tool import _active_environments, _env_lock  # private Hermes API: fail closed when missing
    except ImportError:
        raise PreviewError("gone", "cannot check the agent's terminal environment (Hermes API changed)")
    with _env_lock:
        alive = any(e is shared_env for e in list(_active_environments.values()))
    if not alive:
        raise PreviewError("gone", "the agent's sandbox stopped since the share: share it again from a turn")
    return shared_env


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


def probe_voice(env, path: str) -> str:
    """'ok' when the url-file at ``path`` (in the agent's environment) holds a daemon URL whose port accepts a TCP
    connection, else 'no file' / 'bad url' / 'not listening' / 'no answer'. The path rides on stdin."""
    proc = spawn_in_env(env, python_command(PROBE_VOICE_PY), stdin_data=json.dumps({"path": path}) + "\n",
                        timeout=PROBE_TIMEOUT_S)
    try:
        out = proc.stdout.read() if hasattr(proc.stdout, "read") else "".join(proc.stdout)
        proc.wait(timeout=PROBE_TIMEOUT_S)
    except Exception:
        _kill(env, proc)
        return "no answer"
    m = re.search(PROBE_OK + r" (ok|no file|bad url|not listening)\b", out or "")
    return m.group(1) if m else "no answer"


def probe_device(env, device: str) -> str:
    """`adb -s <device> get-state` in the agent's environment: 'device' when online, else what adb said (one line,
    bounded) or 'no adb'."""
    cmd = f"command -v adb >/dev/null || {{ echo 'no adb'; exit 0; }}; adb -s {shlex.quote(device)} get-state 2>&1 | head -n 1"
    proc = spawn_in_env(env, cmd, timeout=PROBE_TIMEOUT_S)
    try:
        out = proc.stdout.read() if hasattr(proc.stdout, "read") else "".join(proc.stdout)
        proc.wait(timeout=PROBE_TIMEOUT_S)
    except Exception:
        _kill(env, proc)
        return "no answer"
    return re.sub(r"[\x00-\x1f]+", " ", out or "").strip()[:LOG_LINE_MAX] or "no answer"


def python_command(src: str, *args: str) -> str:
    """``<python> -c <src> <args>`` for the sandbox's bash, <python> = PEER_VENV_PYTHON when it is executable there,
    else ``python3``. ``args`` are quoted; nothing secret ever goes there (secrets ride on stdin)."""
    tail = "".join(" " + shlex.quote(a) for a in args)
    return (f'P=python3; [ -x "{PEER_VENV_PYTHON}" ] && P="{PEER_VENV_PYTHON}"; '
            f'"$P" -c {shlex.quote(src)}{tail}')


PEER_SOURCES = {"web": PEER_SOURCE, "screen": SCREEN_PEER_SOURCE, "voice": VOICE_PEER_SOURCE}


def peer_command(tag: str, kind: str = "web") -> str:
    """The peer of a share kind: ``web`` | ``screen`` | ``voice`` (see ``peer_kind``)."""
    return python_command(PEER_SOURCES[kind], tag)


def peer_kind(target: Any) -> str:
    return "voice" if target is VOICE else "screen" if isinstance(target, str) else "web"


# A daemon URL in a peer's log line (a Playwright error may quote it): the token is cut before any log.
_WS_TOKEN_RE = re.compile(r"(ws://[^/\s]+/)[A-Za-z0-9_-]+")


def redact(line: str) -> str:
    return _WS_TOKEN_RE.sub(r"\1***", line)


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
    ctx: Any = None  # the share's turn context (in_turn_context)

    def __init__(self, session: str, thread: str, port: Any, msg: str, tag: str):  # port: int, the device (str) of a screen, or VOICE
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
        self.shares: Dict[Tuple[str, Any], Dict[str, Any]] = {}  # (thread, port, device or VOICE)
        self.peers: Dict[str, Peer] = {}
        self.lock = threading.Lock()
        self.session_env = session_env    # seams for the tests
        self.spawn = spawn_in_env
        self.kill = kill_peer

    # shares
    def share_of(self, thread: str, port: Any) -> Optional[Dict[str, Any]]:
        return self.shares.get((thread, port))

    def remember(self, thread: str, port: Any, task_id: Optional[str], msg: str, label: str, env: Any = None, ctx: Any = None,
                 voice_file: Optional[str] = None) -> None:
        # env: the agent's terminal environment, resolved in its turn (see session_env); ctx: that turn's context
        # (see in_turn_context), under which every later step on that environment runs. voice_file: the daemon's
        # url-file path of a voice channel (memory only, handed to its peers on stdin).
        self.shares[(thread, port)] = {"task_id": task_id, "msg": msg, "label": label, "env": env, "ctx": ctx}
        if port is VOICE:
            self.shares[(thread, port)]["voice_file"] = voice_file

    def forget(self, thread: str, port: Any) -> Optional[Dict[str, Any]]:
        share = self.shares.pop((thread, port), None)
        if share:
            for p in [p for p in list(self.peers.values()) if p.thread == thread and p.port == port]:
                self.close(p.session)
        return share

    # peers
    async def offer(self, frame: Dict[str, Any]) -> None:
        import asyncio
        self.loop = asyncio.get_running_loop()
        session, thread, msg = frame.get("session"), frame.get("thread"), frame.get("msg")
        # A screen offer carries the device instead of the port, a voice offer `voice: true` (protocol/preview.ts); the
        # share is keyed by its target.
        port = VOICE if frame.get("voice") is True else frame.get("device") if "device" in frame else frame.get("port")
        kind = peer_kind(port)
        if not (isinstance(session, str) and SESSION_RE.fullmatch(session)):
            return
        if session in self.peers:
            return  # a duplicate offer of a running session
        share = self.share_of(thread, port) if isinstance(thread, str) and target_ok(port) else None
        if share is None or share["msg"] != msg:
            return await self._failed(session, "gone")
        sdp, ice = frame.get("sdp"), frame.get("ice")
        life = peer_life(frame.get("max_s"))
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
        # The TURN credentials (ice) and a voice url-file path travel on stdin only; the command line carries the
        # source and a random tag.
        what = {"voice_file": share.get("voice_file")} if kind == "voice" else {("device" if kind == "screen" else "port"): port}
        stdin = json.dumps({**what, "sdp": sdp, "ice": [s for s in ice if isinstance(s, dict)], "max_s": life}) + "\n"
        try:
            peer.ctx = ctx = share.get("ctx")
            peer.env = await self.loop.run_in_executor(None, lambda: in_turn_context(ctx, lambda: self.session_env(share.get("env"))))
            peer.proc = await self.loop.run_in_executor(None, lambda: in_turn_context(ctx, lambda: self.spawn(peer.env, peer_command(peer.tag, kind), stdin)))
        except PreviewError as e:
            logger.warning("[briefling] preview peer not started: %s", e)
            self.peers.pop(session, None)
            if e.code == "gone":
                # The hub turns the line off on `gone`: forget the share too, so that the next share (voice_open after
                # the app asks again) posts a new line instead of answering « already shared » with the dead one.
                self.shares.pop((thread, port), None)
            return await self._failed(session, e.code if e.code in PREVIEW_ERRORS else "peer_failed")
        except Exception as e:
            logger.warning("[briefling] preview peer not started: %s", type(e).__name__)
            self.peers.pop(session, None)
            return await self._failed(session, "peer_failed")
        if peer.closing:  # closed while it was starting
            self._kill_async(peer)
            return
        peer.timer = self.loop.call_later(life, self.close, session)
        threading.Thread(target=self._read, args=(peer,), daemon=True, name=f"preview-{peer.tag}").start()
        logger.info("[briefling] preview peer started for %s (%d live)", target_what(port), len(self.peers))

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
                        logger.debug("[briefling] preview peer: %s", redact(line)[:LOG_LINE_MAX])
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
        threading.Thread(target=lambda: in_turn_context(peer.ctx, lambda: self.kill(peer.env, peer.proc, peer.tag)), daemon=True).start()

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
                th = threading.Thread(target=lambda p=p: in_turn_context(p.ctx, lambda: self.kill(p.env, p.proc, p.tag)), daemon=True)
                th.start()
                threads.append(th)
        end = time.monotonic() + wait_s
        for th in threads:
            th.join(max(0.0, end - time.monotonic()))
