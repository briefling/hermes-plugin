"""Agent side of a briefling web preview: one WebRTC peer serving 127.0.0.1:<port> to one viewer.

Standalone script (stdlib + Playwright, Python >= 3.9). The plugin runs it INSIDE the agent's terminal environment (the
Docker sandbox when the terminal backend is docker: only there does 127.0.0.1:<port> reach the agent's dev server) as
``python3 -c <this source> <tag>``, and writes ONE JSON line on its stdin, then closes it:

    {"port": 5173, "sdp": "v=0...", "ice": [{"urls": [...], "username": "...", "credential": "..."}], "max_s": 1800}

(the TURN credentials travel on stdin only, never on the command line). It prints JSON lines on stdout, flushed one by
one, that the plugin relays to the hub:

    {"t": "answer", "sdp": "v=0..."}                     the answer, at once (candidates are trickled after it)
    {"t": "candidate", "candidate": "candidate:...", "mid": "0"}   one local candidate; candidate "" = end of candidates
    {"t": "state", "state": "connected"}                 RTCPeerConnection state (logged by the plugin only)
    {"t": "error", "code": "no_browser" | "port_closed" | "peer_failed"}
    {"t": "closed"}                                      last line, the process exits right after

Anything else on stdout (Playwright or Chromium noise) is a log line the plugin never forwards.

How the bytes flow: a headless Chromium opens a blank page routed ON http://127.0.0.1:<port>/__briefling_preview_peer__
(Playwright serves it, the dev server never sees that path), so the page's fetch() is same-origin with the dev server by
construction. The viewer's data channel (label ``http``, protocol/preview.ts) carries one JSON request per text frame;
the page answers with a JSON head then binary chunks ``[id u32 BE][last u8][payload <= 16 KiB]``.

Exits when the connection is failed/closed, disconnected for more than 20 s, after ``max_s`` (hard cap), or on SIGTERM
(the plugin's stop: it kills the pid written to /tmp/briefling-preview-<tag>.pid, since killing a ``docker exec`` client
does not stop the process inside the container).
"""
import asyncio
import json
import os
import re
import signal
import socket
import sys
import time

PEER_PATH = "/__briefling_preview_peer__"
DISCONNECTED_MAX_S = 20
MAX_S = 1800
TAG_RE = re.compile(r"[a-f0-9]{8,32}")

# The page script. Security gates enforced here (protocol/preview.ts previewPathOk; docs in preview-spec):
#  - only relative paths of this origin are fetched (`pathOk`, a copy of previewPathOk), nothing else, ever;
#  - a response whose final URL (after redirects) left http://127.0.0.1:<port> is refused, its body dropped.
PEER_JS = r"""
(() => {
  const CHUNK = 16384, HIGH = 1 << 20, BODY_MAX = 1 << 20;
  // Copy of previewPathOk (protocol/preview.ts): relative to the shared port only.
  const pathOk = (p) => typeof p === 'string' && p.length <= 8192 && p.startsWith('/') && !p.startsWith('//')
    && !p.includes('\\') && !/[\u0000-\u001f]/.test(p);
  const emit = (o) => window.__emit(o);

  function serve(dc) {
    dc.binaryType = 'arraybuffer';
    const room = async () => {
      while (dc.bufferedAmount > HIGH) {
        if (dc.readyState !== 'open') throw new Error('channel closed');
        await new Promise((ok) => setTimeout(ok, 5));
      }
    };
    const text = async (o) => { await room(); dc.send(JSON.stringify(o)); };
    const chunk = async (id, bytes, last) => {
      await room();
      const buf = new Uint8Array(5 + bytes.byteLength);
      new DataView(buf.buffer).setUint32(0, id); buf[4] = last ? 1 : 0; buf.set(bytes, 5);
      dc.send(buf);
    };
    dc.onmessage = async (e) => {
      if (typeof e.data !== 'string') return;
      let r;
      try { r = JSON.parse(e.data); } catch (_) { return; }
      if (!r || !Number.isInteger(r.id) || r.id < 0 || r.id > 0xffffffff) return;
      const id = r.id;
      let head = false;
      try {
        if (!pathOk(r.u)) return void await text({ id, err: 'refused' });  // gate: relative paths only
        const method = typeof r.m === 'string' && /^[A-Z]{1,12}$/.test(r.m) ? r.m : 'GET';
        const headers = new Headers();
        for (const [k, v] of Object.entries(r.h && typeof r.h === 'object' ? r.h : {})) {
          if (typeof v !== 'string' || k === 'host' || k === 'origin') continue;  // the browser sets its own
          try { headers.set(k, v); } catch (_) { /* invalid or forbidden header: dropped */ }
        }
        let body;
        if (typeof r.b === 'string' && method !== 'GET' && method !== 'HEAD') {
          body = Uint8Array.from(atob(r.b), (c) => c.charCodeAt(0));
          if (body.byteLength > BODY_MAX) return void await text({ id, err: 'refused' });
        }
        let res;
        try {
          res = await fetch(r.u, { method, headers, body, redirect: 'follow', cache: 'no-store' });
        } catch (_) {
          return void await text({ id, err: 'fetch' });  // nothing listening, or a cross-origin redirect (CORS)
        }
        if (res.url && new URL(res.url).origin !== location.origin) {  // gate: a redirect that left the origin
          try { await res.body?.cancel(); } catch (_) {}
          return void await text({ id, err: 'refused' });
        }
        const h = {};
        res.headers.forEach((v, k) => { if (k !== 'content-encoding' && k !== 'content-length') h[k] = v; });
        await text({ id, s: res.status, h });
        head = true;
        if (res.body) {
          const rd = res.body.getReader();
          for (;;) {
            const { done, value } = await rd.read();
            if (done) break;
            for (let i = 0; i < value.byteLength; i += CHUNK) await chunk(id, value.subarray(i, i + CHUNK), false);
          }
        }
        await chunk(id, new Uint8Array(0), true);
      } catch (_) {
        // Stream error or channel closing: end the response if the channel is still usable.
        try { if (dc.readyState === 'open') head ? await chunk(id, new Uint8Array(0), true) : await text({ id, err: 'fetch' }); } catch (_) {}
      }
    };
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
    pc.ondatachannel = ({ channel }) => { if (channel.label === 'http') serve(channel); };
    await pc.setRemoteDescription({ type: 'offer', sdp });
    await pc.setLocalDescription(await pc.createAnswer());
    await emit({ t: 'answer', sdp: pc.localDescription.sdp });  // at once: no wait for gathering
    answered = true;
    for (const c of queued.splice(0)) await emit(c);
  };
})();
"""


def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def read_config():
    try:
        cfg = json.loads(sys.stdin.readline())
    except (ValueError, OSError):
        return None
    if not isinstance(cfg, dict):
        return None
    port, sdp, ice = cfg.get("port"), cfg.get("sdp"), cfg.get("ice")
    if not (isinstance(port, int) and 1024 <= port <= 65535 and isinstance(sdp, str) and sdp.startswith("v=0")):
        return None
    if not isinstance(ice, list):
        ice = []
    max_s = cfg.get("max_s")
    max_s = max_s if isinstance(max_s, (int, float)) and 0 < max_s <= MAX_S else MAX_S
    return {"port": port, "sdp": sdp, "ice": [s for s in ice if isinstance(s, dict)], "max_s": max_s}


async def serve(cfg):
    port = cfg["port"]
    origin = f"http://127.0.0.1:{port}"
    if not port_open(port):
        emit({"t": "error", "code": "port_closed"})
        return
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        emit({"t": "error", "code": "no_browser"})
        return
    done = asyncio.Event()
    loop = asyncio.get_running_loop()
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

    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch()
        except Exception as e:  # Playwright installed without its Chromium
            print(f"log browser launch failed: {type(e).__name__}", flush=True)
            emit({"t": "error", "code": "no_browser"})
            return
        try:
            page = await browser.new_page()
            page.on("crash", lambda _p: done.set())
            await page.expose_function("__emit", on_emit)
            await page.route(origin + PEER_PATH, lambda r: r.fulfill(
                content_type="text/html", body=f"<!doctype html><title>peer</title><script>{PEER_JS}</script>"))
            await page.goto(origin + PEER_PATH)
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
            print(f"log peer failed: {type(e).__name__}: {str(e)[:200]}", flush=True)
            emit({"t": "error", "code": "peer_failed"})
        finally:
            try:
                await browser.close()
            except Exception:
                pass


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
