"""Agent side of a briefling VOICE channel: one WebRTC peer relaying one viewer to the local voice daemon.

Standalone script (stdlib + Playwright, Python >= 3.9), started by the plugin exactly like preview_peer.py (INSIDE the
agent's terminal environment, ``<python> -c <this source> <tag>``, ONE JSON line on stdin then closed):

    {"voice_file": "/path/of/the/url-file", "sdp": "v=0...", "ice": [...], "max_s": 1800}

and printing the same JSON lines on stdout (answer, candidate, state, error, closed; protocol in preview_peer.py), with
one more error code: ``no_voice`` (the url-file is missing or invalid, or the daemon refused or closed before ready).

The daemon (voice/briefling_voice/daemon.py) listens on ws://127.0.0.1:<port>/<token>, one client at a time; its
url-file holds that URL. This process reads the file itself, so the URL and its token never leave the sandbox: they are
not on any command line (``ps``), not on stdout, not in a log (``log`` cuts the token), and reach the page only as a
Playwright ``evaluate`` argument (CDP pipe).

How the bytes flow: a local HTTP server of this process (127.0.0.1, random port, random path token) serves the peer
page; a headless Chromium on that page answers the viewer's offer and, once the data channel (label ``voice``) opens,
opens ONE WebSocket to the daemon URL. Playwright routes gate the page: ``page.route`` lets only the page itself
load, ``page.route_web_socket`` lets only that one daemon URL connect, and every WebSocket message goes through this
process in both directions (``client_to_daemon`` / ``daemon_to_client``): checked and re-serialized (protocol/preview.ts
« Voice »), daemon audio cut into fragments of at most VOICE_CHUNK bytes, each with its 4-byte id prefix.

Exits like preview_peer.py: connection failed/closed, disconnected for more than 20 s, ``max_s``, SIGTERM, or the
daemon's socket closing.
"""
import asyncio
import http.server
import json
import os
import re
import secrets
import signal
import sys
import threading
import time

DISCONNECTED_MAX_S = 20
MAX_S = 1800
TAG_RE = re.compile(r"[a-f0-9]{8,32}")
URL_RE = re.compile(r"ws://127\.0\.0\.1:(\d{1,5})/[A-Za-z0-9_-]{16,64}")  # the daemon's url-file (fullmatch)
VOICE_FILE_MAX = 1024
VOICE_CHUNK = 16_384          # protocol/preview.ts VOICE_CHUNK: max binary message on the channel, both ways
VOICE_SAY_MAX = 1000          # protocol/preview.ts VOICE_SAY_MAX
VOICE_WORD_MAX = 200          # protocol/preview.ts VOICE_WORD_MAX
VOICE_TURN_MAX = 4000         # protocol/preview.ts VOICE_TURN_MAX
TTS_MAX = 4 * 1024 * 1024     # one daemon audio message (a sentence of PCM): bounded before it is cut
TEXT_MAX = 16_384             # one text message, either way, before JSON parsing
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SECRETS = []                 # cut from every log line


def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def log(msg):
    msg = str(msg)
    for s in _SECRETS:
        msg = msg.replace(s, "***")
    print(re.sub(r"(ws://[^/\s]+/)[A-Za-z0-9_-]+", r"\1***", f"log {msg}")[:300], flush=True)


# -- url-file ---------------------------------------------------------------------------------------------------------

def voice_file_ok(x):
    return (isinstance(x, str) and 0 < len(x) <= VOICE_FILE_MAX and not CONTROL_RE.search(x)
            and not re.match(r"wss?://", x, re.I))


def daemon_url(raw):
    """The daemon URL when ``raw`` is exactly ws://127.0.0.1:<port>/<token> (one trailing newline stripped), else None."""
    if not isinstance(raw, str):
        return None
    raw = raw[:-1] if raw.endswith("\n") else raw
    m = URL_RE.fullmatch(raw)
    return raw if m and 1 <= int(m.group(1)) <= 65535 else None


def read_url_file(path):
    try:
        with open(path, "r", encoding="ascii") as f:
            return daemon_url(f.read(256))
    except (OSError, ValueError):
        return None


# -- messages, both ways ------------------------------------------------------------------------------------------------

def _text(x, hi, lo=0):
    return isinstance(x, str) and lo <= len(x) <= hi


def _u32(x):
    return isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= 0xFFFFFFFF


def voice_client_message(o):
    """A viewer text message (protocol/preview.ts voiceClientMsg, checked again here), re-built, else None."""
    if not isinstance(o, dict):
        return None
    if o.get("type") == "say" and _text(o.get("text"), VOICE_SAY_MAX, 1) and not CONTROL_RE.search(o["text"]):
        return {"type": "say", "text": o["text"]}
    if o.get("type") == "stop":
        return {"type": "stop"}
    return None


def voice_daemon_message(o):
    """A daemon text message (protocol/preview.ts voiceDaemonMsg), re-built with its known fields only, else None."""
    if not isinstance(o, dict):
        return None
    t = o.get("type")
    if t == "ready":
        return {"type": "ready"}
    if t == "word" and _text(o.get("text"), VOICE_WORD_MAX):
        return {"type": "word", "text": o["text"]}
    if t == "turn" and _text(o.get("text"), VOICE_TURN_MAX):
        return {"type": "turn", "text": o["text"], "flush_ms": o["flush_ms"] if _u32(o.get("flush_ms")) else 0}
    if t == "tts_stop" and o.get("reason") in ("barge_in", "stop"):
        return {"type": "tts_stop", "reason": o["reason"]}
    if t == "tts_end" and _u32(o.get("id")):
        return {"type": "tts_end", "id": o["id"]}
    return None


def _json(msg):
    if not isinstance(msg, str) or len(msg) > TEXT_MAX:
        return None
    try:
        return json.loads(msg)
    except ValueError:
        return None


def client_to_daemon(msg):
    """One viewer message -> what goes to the daemon, or None (dropped). Binary: microphone PCM, int16, at most
    VOICE_CHUNK bytes. Text: say / stop, re-serialized."""
    if isinstance(msg, (bytes, bytearray)):
        return bytes(msg) if 0 < len(msg) <= VOICE_CHUNK and len(msg) % 2 == 0 else None
    m = voice_client_message(_json(msg))
    return json.dumps(m, ensure_ascii=False, separators=(",", ":")) if m else None


def daemon_to_client(msg):
    """One daemon message -> the list of messages for the viewer (empty = dropped). Text: re-serialized known types.
    Binary: [u32 id] + int16 PCM, cut into fragments of at most VOICE_CHUNK bytes, each with that id prefix."""
    if isinstance(msg, (bytes, bytearray)):
        if len(msg) < 4 or len(msg) > TTS_MAX or (len(msg) - 4) % 2:
            return []
        head, pcm, step = bytes(msg[:4]), bytes(msg[4:]), VOICE_CHUNK - 4
        return [head + pcm[i:i + step] for i in range(0, len(pcm), step)] or [head]
    m = voice_daemon_message(_json(msg))
    return [json.dumps(m, ensure_ascii=False, separators=(",", ":"))] if m else []


# -- the page ---------------------------------------------------------------------------------------------------------

PEER_JS = r"""
(() => {
  const CHUNK = %d, HIGH = 1 << 20;
  const emit = (o) => window.__emit(o);
  let warned = false;

  function relay(dc, url) {
    dc.binaryType = 'arraybuffer';
    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';
    // Every message is checked and re-serialized by the Python routes (client_to_daemon / daemon_to_client).
    ws.onmessage = (e) => {
      if (dc.readyState !== 'open') return;
      if (typeof e.data !== 'string' && e.data.byteLength > CHUNK) return;
      if (dc.bufferedAmount > HIGH && !warned) { warned = true; emit({ t: 'log', m: 'voice channel backlog over 1 MiB' }); }
      dc.send(e.data);
    };
    ws.onclose = () => { emit({ t: 'ws_closed' }); try { dc.close(); } catch (_) {} };
    dc.onmessage = (e) => {
      if (ws.readyState !== WebSocket.OPEN) return;  // before the daemon accepted: dropped
      if (typeof e.data === 'string' ? e.data.length > %d : e.data.byteLength > CHUNK) return;
      ws.send(e.data);
    };
    dc.onclose = () => { try { ws.close(); } catch (_) {} };
  }

  window.__start = async (sdp, ice, url) => {
    const pc = new RTCPeerConnection({ iceServers: ice });
    window.__pc = pc;
    let answered = false, taken = false;
    const queued = [];
    const cand = (c) => { if (answered) emit(c); else queued.push(c); };
    pc.onicecandidate = (e) => {
      if (!e.candidate) return cand({ t: 'candidate', candidate: '', mid: null });
      const c = e.candidate.candidate;
      if (c && c.startsWith('candidate:')) cand({ t: 'candidate', candidate: c, mid: e.candidate.sdpMid ?? null });
    };
    pc.onconnectionstatechange = () => emit({ t: 'state', state: pc.connectionState });
    pc.ondatachannel = ({ channel }) => {
      if (channel.label !== 'voice' || taken) return;
      taken = true;  // one daemon client: one channel
      if (channel.readyState === 'open') relay(channel, url); else channel.onopen = () => relay(channel, url);
    };
    await pc.setRemoteDescription({ type: 'offer', sdp });
    await pc.setLocalDescription(await pc.createAnswer());
    await emit({ t: 'answer', sdp: pc.localDescription.sdp });
    answered = true;
    for (const c of queued.splice(0)) await emit(c);
  };
})();
""" % (VOICE_CHUNK, TEXT_MAX)


def local_server(token):
    """127.0.0.1:<random> serving only /<token>/ (the peer page)."""
    page = f"<!doctype html><title>voice peer</title><script>{PEER_JS}</script>".encode()

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path != f"/{token}/":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(page)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def read_config(line=None):
    """The stdin config: ``voice_file`` (a path, never a URL) + sdp, ice, max_s; anything else is ignored, a missing or
    bad field refuses it (None)."""
    try:
        cfg = json.loads(sys.stdin.readline() if line is None else line)
    except (ValueError, OSError):
        return None
    if not isinstance(cfg, dict):
        return None
    path, sdp, ice = cfg.get("voice_file"), cfg.get("sdp"), cfg.get("ice")
    if not (voice_file_ok(path) and isinstance(sdp, str) and sdp.startswith("v=0")):
        return None
    max_s = cfg.get("max_s")
    max_s = max_s if isinstance(max_s, (int, float)) and not isinstance(max_s, bool) and 0 < max_s <= MAX_S else MAX_S
    return {"voice_file": path, "sdp": sdp, "ice": [s for s in ice if isinstance(s, dict)] if isinstance(ice, list) else [],
            "max_s": max_s}


class Relay:
    """The page's one WebSocket, routed through this process (Playwright ``route_web_socket``)."""

    def __init__(self, url, done):
        self.url, self.done = url, done
        self.ready = False
        self.connected = False

    async def route(self, ws):
        if ws.url != self.url or self.connected:
            log("websocket refused (not the daemon URL, or a second one)")
            await ws.close(code=1008)
            return
        self.connected = True
        server = ws.connect_to_server()

        def up(msg):
            out = client_to_daemon(msg)
            if out is not None:
                server.send(out)

        def down(msg):
            out = daemon_to_client(msg)
            if out == ['{"type":"ready"}']:
                self.ready = True
            for m in out:
                ws.send(m)

        ws.on_message(up)
        server.on_message(down)

    def closed(self):
        if not self.ready:
            log("daemon socket closed before ready")
            emit({"t": "error", "code": "no_voice"})
        self.done.set()


async def serve(cfg):
    url = read_url_file(cfg["voice_file"])
    if url is None:
        log("url-file missing or not a daemon URL")
        emit({"t": "error", "code": "no_voice"})
        return
    _SECRETS.append(url.rsplit("/", 1)[1])
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        emit({"t": "error", "code": "no_browser"})
        return
    loop = asyncio.get_running_loop()
    token = secrets.token_urlsafe(16)
    srv = local_server(token)
    page_url = f"http://127.0.0.1:{srv.server_address[1]}/{token}/"
    done = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, done.set)
        except (NotImplementedError, RuntimeError):
            pass
    disconnected_at = [None]
    relay = Relay(url, done)

    def on_emit(obj):
        if not isinstance(obj, dict):
            return
        t = obj.get("t")
        if t == "answer" and isinstance(obj.get("sdp"), str):
            emit({"t": "answer", "sdp": obj["sdp"]})
        elif t == "candidate" and isinstance(obj.get("candidate"), str):
            mid = obj.get("mid")
            emit({"t": "candidate", "candidate": obj["candidate"], "mid": mid if isinstance(mid, str) else None})
        elif t == "state" and isinstance(obj.get("state"), str):
            state = obj["state"]
            emit({"t": "state", "state": state})
            if state in ("failed", "closed"):
                done.set()
            disconnected_at[0] = time.monotonic() if state == "disconnected" else None
        elif t == "ws_closed":
            relay.closed()
        elif t == "log" and isinstance(obj.get("m"), str):
            log(obj["m"][:100])

    async def only_the_page(route):
        try:
            if route.request.url == page_url:
                await route.continue_()
            else:
                await route.abort()
        except Exception as e:
            log(f"route: {type(e).__name__}")

    async def only_the_daemon(ws):
        try:
            await relay.route(ws)
        except Exception as e:
            log(f"websocket route: {type(e).__name__}")
            done.set()

    try:
        async with async_playwright() as pw:
            try:
                browser = await pw.chromium.launch()
            except Exception as e:
                log(f"browser launch failed: {type(e).__name__}")
                emit({"t": "error", "code": "no_browser"})
                return
            try:
                page = await browser.new_page()
                page.on("crash", lambda _p: done.set())
                await page.route("**/*", only_the_page)
                await page.route_web_socket(re.compile(r".*"), only_the_daemon)
                await page.expose_function("__emit", on_emit)
                await page.goto(page_url)
                await page.evaluate("([s, i, u]) => window.__start(s, i, u)", [cfg["sdp"], cfg["ice"], url])
                end = time.monotonic() + cfg["max_s"]
                while not done.is_set() and time.monotonic() < end:
                    try:
                        await asyncio.wait_for(done.wait(), timeout=1)
                    except asyncio.TimeoutError:
                        pass
                    since = disconnected_at[0]
                    if since is not None and time.monotonic() - since > DISCONNECTED_MAX_S:
                        break
            except Exception as e:
                log(f"peer failed: {type(e).__name__}: {str(e)[:200]}")
                emit({"t": "error", "code": "peer_failed"})
            finally:
                try:
                    await browser.close()
                except Exception:
                    pass
    finally:
        srv.shutdown()


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 and TAG_RE.fullmatch(sys.argv[1]) else ""
    pidfile = f"/tmp/briefling-preview-{tag}.pid" if tag else ""
    try:
        if pidfile:
            with open(pidfile, "w") as f:
                f.write(str(os.getpid()))
        cfg = read_config()
        if cfg is None:
            emit({"t": "error", "code": "peer_failed"})
        else:
            asyncio.run(serve(cfg))
    finally:
        if pidfile:
            try:
                os.unlink(pidfile)
            except OSError:
                pass
        emit({"t": "closed"})


if __name__ == "__main__":
    main()
