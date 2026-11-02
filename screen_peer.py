"""Agent side of a briefling SCREEN share: one WebRTC peer streaming an Android device's screen to one viewer.

Standalone script (stdlib + Playwright, Python >= 3.9), started by the plugin exactly like preview_peer.py (INSIDE the
agent's terminal environment, ``python3 -c <this source> <tag>``, ONE JSON line on stdin then closed):

    {"device": "emulator-5554", "sdp": "v=0...", "ice": [...], "max_s": 1800}

and printing the same JSON lines on stdout (answer, candidate, state, error, closed; protocol in preview_peer.py), with
two more error codes: ``no_device`` (no adb, or the device is not online) and ``no_scrcpy`` (the scrcpy server could
not be fetched or did not match its checksum).

The screen: scrcpy-server (Genymobile, Apache-2.0, https://github.com/Genymobile/scrcpy), PINNED to SCRCPY_VERSION and
checked against SCRCPY_SHA256 before it is pushed to the device; fetched once from its GitHub release into
~/.cache/briefling/. It runs on the device (``app_process``) and gives, over an adb forward tunnel, one video socket
(H.264 packets, each with a 12-byte header: config/key flags and size) and one control socket (touch, keys, text).
Why not ``adb exec-out screenrecord``: its raw stream has no frame boundary (spike spikes/emulator-screen).

How the bytes flow: a local HTTP server of this process (127.0.0.1, random port, random path token) serves the peer
page and ``video``, the scrcpy packets as ``[size u32 BE][flags u8][packet]``; a headless Chromium on that page reads
it and sends each packet on the viewer's data channel (label ``screen``) as fragments ``[flags u8][<= 16383 bytes]``,
flag 0x80 on the last one (protocol/preview.ts « Screen »). When the channel backs up, delta packets are dropped up to
the next key frame, which is requested at once. The viewer's gestures (JSON text frames) reach this process through a
Playwright binding and are checked here (``gesture_message``): only typed, bounded gestures become fixed-size scrcpy
control messages; nothing the viewer sends ever reaches a shell or a command line.

Exits like preview_peer.py: connection failed/closed, disconnected for more than 20 s, ``max_s``, SIGTERM, or the
device's stream ending.
"""
import asyncio
import hashlib
import http.server
import json
import math
import os
import random
import re
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request

SCRCPY_VERSION = "5.0.1"
SCRCPY_SHA256 = "764eb6f79811d5211fe9df341120882ba9994c7a61b897d7bf3fb662e53bc536"
SCRCPY_URL = f"https://github.com/Genymobile/scrcpy/releases/download/v{SCRCPY_VERSION}/scrcpy-server-v{SCRCPY_VERSION}"
SCRCPY_REMOTE = f"/data/local/tmp/briefling-scrcpy-{SCRCPY_VERSION}.jar"
MAX_SIZE = 1280          # longest side of the picture: 576x1280 for a 1080x2400 phone, ~0.3-1.3 Mbit/s measured
BIT_RATE = 4_000_000
DISCONNECTED_MAX_S = 20
MAX_S = 1800
TAG_RE = re.compile(r"[a-f0-9]{8,32}")
DEVICE_RE = re.compile(r"[A-Za-z0-9._:-]{1,64}")  # protocol/preview.ts PREVIEW_DEVICE_RE
KEYS = {"back": 4, "home": 3, "recents": 187, "enter": 66, "del": 67}  # protocol/preview.ts SCREEN_KEYS -> Android keycodes
TEXT_MAX = 300           # protocol/preview.ts SCREEN_TEXT_MAX (characters); scrcpy takes <= 300 UTF-8 bytes per message
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def log(msg):
    print(f"log {msg}"[:300], flush=True)


# -- gestures ---------------------------------------------------------------------------------------------------------

def _unit(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and 0 <= v <= 1


def _utf8_pieces(s, limit):
    """``s`` cut into pieces of at most ``limit`` UTF-8 bytes, never inside a character."""
    out, cur, n = [], [], 0
    for ch in s:
        b = len(ch.encode("utf-8"))
        if n + b > limit:
            out.append("".join(cur))
            cur, n = [], 0
        cur.append(ch)
        n += b
    if cur:
        out.append("".join(cur))
    return out


def gesture_message(g, w, h):
    """A viewer gesture (protocol/preview.ts screenGesture, checked again here) -> list of scrcpy control messages, or
    None when refused. ``w``, ``h``: the video size (0 before the first session packet: touches refused)."""
    if not isinstance(g, dict):
        return None
    k = g.get("k")
    if k == "touch":
        a = {"down": 0, "up": 1, "move": 2}.get(g.get("a"))
        x, y = g.get("x"), g.get("y")
        if a is None or not (_unit(x) and _unit(y)) or not (w > 0 and h > 0):
            return None
        px, py = round(x * (w - 1)), round(y * (h - 1))
        # INJECT_TOUCH_EVENT (32 bytes): type 2, action, pointer id (a finger), x, y, screen w, h, pressure,
        # action button, buttons (scrcpy app/tests/test_control_msg_serialize.c, v5.0.1)
        return [struct.pack(">BBqiiHHHII", 2, a, 0, px, py, w, h, 0 if a == 1 else 0xFFFF, 0, 0)]
    if k == "key":
        code = KEYS.get(g.get("key")) if isinstance(g.get("key"), str) else None
        if code is None:
            return None
        # INJECT_KEYCODE (14 bytes): type 0, action down then up, keycode, repeat, metastate
        return [struct.pack(">BBIII", 0, a, code, 0, 0) for a in (0, 1)]
    if k == "text":
        s = g.get("s")
        if not isinstance(s, str) or not 0 < len(s) <= TEXT_MAX or CONTROL_RE.search(s):
            return None
        # INJECT_TEXT: type 1, length u32, UTF-8 bytes (<= 300)
        return [struct.pack(">BI", 1, len(b)) + b for b in (p.encode("utf-8") for p in _utf8_pieces(s, 300))]
    if k == "reset":
        return [b"\x11"]  # RESET_VIDEO: the encoder restarts on a key frame
    return None


# -- adb and the scrcpy server ----------------------------------------------------------------------------------------

class ScreenError(Exception):
    def __init__(self, code, detail=""):
        super().__init__(detail or code)
        self.code = code


def adb(device, *args, timeout=30):
    return subprocess.run(["adb", "-s", device, *args], capture_output=True, text=True, timeout=timeout)


def scrcpy_jar():
    """The pinned scrcpy server, from the cache or its GitHub release; its sha256 checked every time."""
    path = os.path.join(os.path.expanduser("~"), ".cache", "briefling", f"scrcpy-server-v{SCRCPY_VERSION}")
    ok = lambda data: hashlib.sha256(data).hexdigest() == SCRCPY_SHA256
    try:
        with open(path, "rb") as f:
            if ok(f.read()):
                return path
    except OSError:
        pass
    try:
        with urllib.request.urlopen(SCRCPY_URL, timeout=60) as r:
            data = r.read(4 * 1024 * 1024)
    except Exception as e:
        raise ScreenError("no_scrcpy", f"download failed: {type(e).__name__}")
    if not ok(data):
        raise ScreenError("no_scrcpy", "checksum mismatch")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.{os.getpid()}"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    return path


def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError
        b += c
    return b


class Scrcpy:
    """One scrcpy-server run on the device: a video socket and a control socket over an adb forward tunnel."""

    def __init__(self, device):
        if not shutil.which("adb"):
            raise ScreenError("no_device", "no adb in this environment")
        try:
            state = adb(device, "get-state", timeout=15).stdout.strip()
        except subprocess.TimeoutExpired:
            state = "timeout"
        if state != "device":
            raise ScreenError("no_device", f"device not online: {state[:60]}")
        jar = scrcpy_jar()
        # cleanup=true makes the server delete its jar once loaded: push it for every run (~0.7 MB).
        if adb(device, "push", jar, SCRCPY_REMOTE, timeout=60).returncode != 0:
            raise ScreenError("no_device", "adb push failed")
        self.device = device
        scid = random.randrange(1, 1 << 31)
        name = f"scrcpy_{scid:08x}"
        out = adb(device, "forward", "tcp:0", f"localabstract:{name}").stdout.strip()
        if not out.isdigit():
            raise ScreenError("no_device", "adb forward failed")
        self.port = int(out)
        self.proc = subprocess.Popen(
            ["adb", "-s", device, "shell", f"CLASSPATH={SCRCPY_REMOTE}", "app_process", "/", "com.genymobile.scrcpy.Server",
             SCRCPY_VERSION, f"scid={scid:08x}", "log_level=warn", "audio=false", "tunnel_forward=true",
             "video_codec=h264", f"max_size={MAX_SIZE}", f"video_bit_rate={BIT_RATE}", "max_fps=60", "cleanup=true"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.video = self.ctrl = None
        self.w = self.h = 0
        self.lock = threading.Lock()
        try:
            self._connect()
        except Exception:
            self.close()
            raise

    def _connect(self):
        end = time.monotonic() + 15
        while True:  # the forward accepts before the server listens: its dummy byte proves it is there
            try:
                s = socket.create_connection(("127.0.0.1", self.port), timeout=2)
                if s.recv(1) == b"\x00":
                    self.video = s
                    break
                s.close()
            except OSError:
                pass
            if time.monotonic() > end:
                raise ScreenError("no_device", "scrcpy server did not start")
            time.sleep(0.05)
        self.ctrl = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        self.ctrl.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.video.settimeout(None)
        self.ctrl.settimeout(5)
        recv_exact(self.video, 64)                       # device name
        codec, = struct.unpack(">I", recv_exact(self.video, 4))
        if codec != 0x68323634:                          # "h264"
            raise ScreenError("no_device", f"unexpected codec {codec:#x}")

    def packets(self):
        """Yields (flags, packet): flags 1 = config, 2 = key frame. Session packets update the video size."""
        while True:
            head = recv_exact(self.video, 12)
            if head[0] & 0x80:
                self.w, self.h = struct.unpack(">II", head[4:])
                continue
            pts, size = struct.unpack(">QI", head)
            flags = (1 if pts & (1 << 62) else 0) | (2 if pts & (1 << 61) else 0)
            yield flags, recv_exact(self.video, size)

    def control(self, msgs):
        with self.lock:
            for m in msgs:
                self.ctrl.sendall(m)

    def close(self):
        for s in (self.video, self.ctrl):
            try:
                s and s.close()
            except OSError:
                pass
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
        except (OSError, AttributeError):
            pass
        try:
            adb(self.device, "forward", "--remove", f"tcp:{self.port}", timeout=10)
        except Exception:
            pass


# -- the local page and the video -------------------------------------------------------------------------------------

PEER_JS = r"""
(() => {
  const FRAG = 16383, HIGH = 1 << 20;
  const emit = (o) => window.__emit(o);

  async function stream(dc) {
    let res;
    try { res = await fetch('video', { cache: 'no-store' }); } catch (_) { return emit({ t: 'ended' }); }
    if (!res.ok || !res.body) return emit({ t: 'ended' });
    const rd = res.body.getReader();
    let buf = new Uint8Array(0), skipping = false;
    const take = (n) => { const o = buf.subarray(0, n); buf = buf.subarray(n); return o; };
    for (;;) {
      const { done, value } = await rd.read();
      if (done) return emit({ t: 'ended' });
      const b = new Uint8Array(buf.length + value.length); b.set(buf); b.set(value, buf.length); buf = b;
      while (buf.length >= 5) {
        const n = new DataView(buf.buffer, buf.byteOffset).getUint32(0), flags = buf[4];
        if (buf.length < 5 + n) break;
        take(5); const pkt = take(n).slice();
        if (dc.readyState !== 'open') return;
        // Backed-up channel: drop deltas up to the next key frame, asked for at once. Config and key always go.
        if (!(flags & 3)) {
          if (skipping) continue;
          if (dc.bufferedAmount > HIGH) { skipping = true; window.__gesture({ k: 'reset' }); continue; }
        }
        if (flags & 2) skipping = false;
        for (let i = 0; i < pkt.length || i === 0; i += FRAG) {
          const part = pkt.subarray(i, i + FRAG), last = i + FRAG >= pkt.length;
          const f = new Uint8Array(1 + part.length); f[0] = (flags & 3) | (last ? 0x80 : 0); f.set(part, 1);
          dc.send(f);
        }
      }
    }
  }

  function serve(dc) {
    dc.binaryType = 'arraybuffer';
    dc.onmessage = (e) => {
      if (typeof e.data !== 'string' || e.data.length > 2048) return;
      let g; try { g = JSON.parse(e.data); } catch (_) { return; }
      window.__gesture(g);  // checked in Python (gesture_message)
    };
    if (dc.readyState === 'open') stream(dc); else dc.onopen = () => stream(dc);
  }

  window.__start = async (sdp, ice) => {
    const pc = new RTCPeerConnection({ iceServers: ice });
    window.__pc = pc;
    let answered = false;
    const queued = [];
    const cand = (c) => { if (answered) emit(c); else queued.push(c); };
    pc.onicecandidate = (e) => {
      if (!e.candidate) return cand({ t: 'candidate', candidate: '', mid: null });
      const c = e.candidate.candidate;
      if (c && c.startsWith('candidate:')) cand({ t: 'candidate', candidate: c, mid: e.candidate.sdpMid ?? null });
    };
    pc.onconnectionstatechange = () => emit({ t: 'state', state: pc.connectionState });
    pc.ondatachannel = ({ channel }) => { if (channel.label === 'screen') serve(channel); };
    await pc.setRemoteDescription({ type: 'offer', sdp });
    await pc.setLocalDescription(await pc.createAnswer());
    await emit({ t: 'answer', sdp: pc.localDescription.sdp });
    answered = true;
    for (const c of queued.splice(0)) await emit(c);
  };
})();
"""


def local_server(screen, token):
    """127.0.0.1:<random> serving /<token>/ (the peer page) and /<token>/video (the packets, once)."""
    page = f"<!doctype html><title>screen peer</title><script>{PEER_JS}</script>".encode()
    taken = threading.Lock()

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == f"/{token}/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)
                return
            if self.path != f"/{token}/video" or not taken.acquire(blocking=False):
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                for flags, pkt in screen.packets():
                    self.wfile.write(struct.pack(">IB", len(pkt), flags) + pkt)
                    self.wfile.flush()
            except (EOFError, OSError):
                pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def read_config():
    try:
        cfg = json.loads(sys.stdin.readline())
    except (ValueError, OSError):
        return None
    if not isinstance(cfg, dict):
        return None
    device, sdp, ice = cfg.get("device"), cfg.get("sdp"), cfg.get("ice")
    if not (isinstance(device, str) and DEVICE_RE.fullmatch(device) and isinstance(sdp, str) and sdp.startswith("v=0")):
        return None
    max_s = cfg.get("max_s")
    max_s = max_s if isinstance(max_s, (int, float)) and 0 < max_s <= MAX_S else MAX_S
    return {"device": device, "sdp": sdp, "ice": [s for s in ice if isinstance(s, dict)] if isinstance(ice, list) else [],
            "max_s": max_s}


async def serve(cfg):
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        emit({"t": "error", "code": "no_browser"})
        return
    loop = asyncio.get_running_loop()
    try:
        screen = await loop.run_in_executor(None, Scrcpy, cfg["device"])
    except ScreenError as e:
        log(f"screen not started: {e}")
        emit({"t": "error", "code": e.code})
        return
    except Exception as e:
        log(f"screen not started: {type(e).__name__}")
        emit({"t": "error", "code": "no_device"})
        return
    token = secrets.token_urlsafe(16)
    srv = local_server(screen, token)
    done = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, done.set)
        except (NotImplementedError, RuntimeError):
            pass
    disconnected_at = [None]

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
        elif t == "ended":  # the device's stream ended (emulator stopped, adb gone)
            log("screen stream ended")
            done.set()

    def on_gesture(g):
        msgs = gesture_message(g, screen.w, screen.h)
        if msgs:
            try:
                screen.control(msgs)
            except OSError:
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
                await page.expose_function("__emit", on_emit)
                await page.expose_function("__gesture", on_gesture)
                await page.goto(f"http://127.0.0.1:{srv.server_address[1]}/{token}/")
                await page.evaluate("([s, i]) => window.__start(s, i)", [cfg["sdp"], cfg["ice"]])
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
        screen.close()


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
