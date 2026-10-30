"""Secrets handed to an agent (« Secret » button of the composer, protocol/secret.ts in the briefling repo).

The adapter holds a P-256 key pair in memory only (new at every gateway start, never on disk) and reports its public
key at subscribe. A trusted human's browser encrypts the value for it; the hub relays ``secret.deliver`` and stores
nothing of it. Here: decrypt, then keep the value outside the conversation:
- password / api_key / private_key -> a 0600 file under the document cache (``briefling-secrets/<thread>/<NAME>``).
  Hermes' Docker terminal backend bind-mounts that cache read-only into the agent's container, so the agent's
  commands read it as ``$(cat <file>)`` without the value ever entering the model's context.
- totp -> the seed stays in this process' memory: the agent only ever gets codes (tool ``secret_totp``).
Safety net: every known value is masked in tool results (hook ``transform_tool_result``) and in frames sent to the
hub. Everything is dropped 24 h after receipt and at gateway connect/stop.

The registry is module-level: tools and hooks run outside the adapter (agent thread), keyed by thread.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import struct
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

logger = logging.getLogger(__name__)

INFO = "briefling-secret-v1"  # protocol/secret.ts SECRET_INFO
KINDS = ("password", "api_key", "private_key", "totp")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
EPK_RE = re.compile(r"^B[A-Za-z0-9_-]{86}$")      # SECRET_KEY_RE: uncompressed P-256 point
IV_RE = re.compile(r"^[A-Za-z0-9_-]{16}$")
CT_RE = re.compile(r"^[A-Za-z0-9_-]+$")
CT_MAX = -(-(8192 + 16) * 4 // 3)                 # SECRET_CT_MAX (value <= 8192 bytes + GCM tag)
ID_MAX = 64
TTL_S = 24 * 3600
SEEN_MAX = 512
MIN_WHOLE = 6    # shorter values would mask ordinary words in tool output
MIN_LINE = 16    # one line of a multi-line value (PEM body): long enough to be specific
TOTP_DIGITS = (6, 7, 8)
TOTP_ALGOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}

_lock = threading.Lock()
_registry: Dict[str, Dict[str, Dict[str, Any]]] = {}   # thread -> name -> {kind, path, agent_path, value, at}
_seen: set = set()
_seen_order: deque = deque()


class SecretError(Exception):
    """Refusal with a reason code: the only thing logged (never the value or the ciphertext)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


# -- crypto ----------------------------------------------------------------

def available() -> bool:
    try:
        import cryptography.hazmat.primitives.ciphers.aead  # noqa: F401
        return True
    except Exception:
        return False


def new_key():
    """In-memory agent key pair, or None when `cryptography` is missing (the feature is then off)."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        return ec.generate_private_key(ec.SECP256R1())
    except Exception:
        logger.warning("[briefling] cryptography unavailable: secrets are off")
        return None


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def public_raw(priv) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def public_key(priv) -> str:
    """Public key as reported at subscribe: base64url of the 65-byte uncompressed point."""
    return b64u(public_raw(priv))


def aad(space: str, thread: str, agent: str, name: str, kind: str) -> bytes:
    """protocol/secret.ts secretAad: binds the ciphertext to where it was sent (a relabel fails decryption)."""
    return "\n".join([INFO, space, thread, agent, name, kind]).encode()


def derive_key(shared: bytes, epk_raw: bytes, own_pub_raw: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=epk_raw + own_pub_raw, info=INFO.encode()).derive(shared)


def decrypt(priv, space: str, thread: str, agent: str, name: str, kind: str, epk: str, iv: str, ct: str) -> str:
    """ECDH(P-256) + HKDF-SHA256 + AES-256-GCM, as the browser encrypts it. Raises SecretError('decrypt')."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        epk_raw = unb64u(epk)
        shared = priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), epk_raw))
        key = derive_key(shared, epk_raw, public_raw(priv))
        return AESGCM(key).decrypt(unb64u(iv), unb64u(ct), aad(space, thread, agent, name, kind)).decode("utf-8")
    except Exception as e:  # bad point, tag mismatch, not UTF-8: one code, no detail that could echo data
        raise SecretError("decrypt") from e


# -- store -----------------------------------------------------------------

def root() -> Path:
    """Under the document cache: the Docker backend mounts it (read-only) in the agent's container."""
    from hermes_constants import get_hermes_dir
    return get_hermes_dir("cache/documents", "document_cache") / "briefling-secrets"


def agent_path(host_path: Path) -> str:
    """Where the agent's terminal sees the file (identity on the local backend)."""
    try:
        from tools.credential_files import to_agent_visible_cache_path
        return to_agent_visible_cache_path(str(host_path))
    except Exception:
        return str(host_path)


def purge_all() -> None:
    """Gateway connect (leftovers of a crash) and stop: no secret outlives the process that holds the key."""
    with _lock:
        _registry.clear()
    try:
        shutil.rmtree(root(), ignore_errors=True)
    except Exception:
        logger.warning("[briefling] secrets purge failed")


def has_any() -> bool:
    return bool(_registry)


def seen(secret_id: str) -> bool:
    """True when this delivery id was already handled (the hub sends to every live connection of the instance)."""
    with _lock:
        if secret_id in _seen:
            return True
        _seen.add(secret_id)
        _seen_order.append(secret_id)
        while len(_seen_order) > SEEN_MAX:
            _seen.discard(_seen_order.popleft())
        return False


def _drop(thread: str, name: str) -> None:
    entry = _registry.get(thread, {}).pop(name, None)
    if entry and entry.get("path"):
        try:
            os.unlink(entry["path"])
        except OSError:
            pass
    if thread in _registry and not _registry[thread]:
        del _registry[thread]


def expire(now: Optional[float] = None) -> None:
    """Drop (file + registry) every secret older than TTL_S. Lazy: called on each delivery, hint and tool call."""
    now = time.time() if now is None else now
    with _lock:
        for thread in list(_registry):
            for name, entry in list(_registry.get(thread, {}).items()):
                if now - entry["at"] > TTL_S:
                    _drop(thread, name)


def _mkdir_private(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)  # mkdir's mode goes through the umask, and an existing dir keeps its old mode


def store(thread: str, name: str, kind: str, value: str, now: Optional[float] = None) -> Dict[str, Any]:
    """Keep a decrypted secret: a 0600 file (same name = replaced), or in memory only for a TOTP seed."""
    if kind == "totp":
        parse_seed(value)  # an unusable seed is refused now, not at the agent's first code
        entry = {"kind": kind, "path": None, "agent_path": None, "value": value}
    else:
        path = root() / thread / name
        try:
            _mkdir_private(path.parent.parent)
            _mkdir_private(path.parent)
            fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            try:
                os.fchmod(fd, 0o600)  # an overwritten file keeps its old mode otherwise
                os.write(fd, value.encode("utf-8"))
            finally:
                os.close(fd)
        except OSError as e:
            raise SecretError("write") from e
        entry = {"kind": kind, "path": str(path), "agent_path": agent_path(path), "value": value}
    entry["at"] = time.time() if now is None else now
    with _lock:
        old = _registry.setdefault(thread, {}).get(name)
        if old and old.get("path") and old["path"] != entry["path"]:  # was a file, now a TOTP: remove the file
            try:
                os.unlink(old["path"])
            except OSError:
                pass
        _registry[thread][name] = entry
    return entry


def live(thread: str) -> Dict[str, Dict[str, Any]]:
    expire()
    with _lock:
        return dict(_registry.get(thread, {}))


def hint(thread: str) -> str:
    """Hidden one-line note on each message of a thread holding secrets: names and where to use them, never values."""
    items = live(thread)
    if not items:
        return ""
    parts = [f"{n} ({e['kind']}) call secret_totp" if e["kind"] == "totp" else f"{n} ({e['kind']}) file {e['agent_path']}"
             for n, e in sorted(items.items())]
    return ("[briefling: secrets shared with you in this thread, values never shown in the conversation: "
            + "; ".join(parts) + ". Use a file only as $(cat <file>) inside a command, never print, echo or cat it "
            "on its own; read-only, deleted when the gateway stops.]\n")


# -- redaction -------------------------------------------------------------

def _candidates() -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    with _lock:
        entries = [(n, e["value"]) for t in _registry.values() for n, e in t.items()]
    for name, value in entries:
        whole = value.strip()
        forms = {whole}
        escaped = json.dumps(whole, ensure_ascii=False)[1:-1]  # the value as it sits inside a JSON tool result
        forms.add(escaped)
        for f in forms:
            if len(f) >= MIN_WHOLE:
                out.append((f, name))
        if "\n" in whole:
            for line in whole.splitlines():
                line = line.strip()
                if len(line) >= MIN_LINE and not line.startswith("-----"):
                    out.append((line, name))
    out.sort(key=lambda c: -len(c[0]))  # longest first: the whole value before its own lines
    return out


def redact(text: str) -> str:
    if not _registry or not isinstance(text, str):
        return text
    for needle, name in _candidates():
        if needle in text:
            text = text.replace(needle, f"[secret {name}]")
    return text


def redact_obj(obj: Any) -> Any:
    """Every str inside a frame (nested dicts/lists), masked."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    return obj


def transform_tool_result(tool_name: Any = None, args: Any = None, result: Any = None, **_: Any) -> Optional[str]:
    """Hermes hook: a tool output that contains a secret (the agent ran `cat` on the file) reaches the model masked."""
    if not _registry or not isinstance(result, str):
        return None
    out = redact(result)
    return out if out != result else None


# -- TOTP (RFC 6238) -------------------------------------------------------

def _b32(seed: str) -> bytes:
    s = re.sub(r"[\s-]", "", seed).upper().rstrip("=")
    if not s or not re.fullmatch(r"[A-Z2-7]+", s):
        raise SecretError("bad_totp")
    try:
        return base64.b32decode(s + "=" * (-len(s) % 8))
    except Exception as e:
        raise SecretError("bad_totp") from e


def parse_seed(seed: str) -> Tuple[bytes, int, int, str]:
    """(key, digits, period, algorithm) from a base32 seed or an otpauth://totp/... URI."""
    seed = seed.strip()
    if not seed.lower().startswith("otpauth://"):
        return _b32(seed), 6, 30, "SHA1"
    u = urlparse(seed)
    if u.netloc.lower() != "totp":
        raise SecretError("bad_totp")
    q = {k.lower(): v[-1] for k, v in parse_qs(u.query).items()}
    try:
        digits, period = int(q.get("digits", 6)), int(q.get("period", 30))
    except ValueError as e:
        raise SecretError("bad_totp") from e
    algo = unquote(q.get("algorithm", "SHA1")).upper()
    if digits not in TOTP_DIGITS or not 1 <= period <= 3600 or algo not in TOTP_ALGOS:
        raise SecretError("bad_totp")
    return _b32(q.get("secret", "")), digits, period, algo


def totp(key: bytes, t: float, digits: int = 6, period: int = 30, algo: str = "SHA1") -> str:
    """RFC 6238 code at Unix time ``t`` (HOTP of the time step, dynamic truncation)."""
    mac = hmac.new(key, struct.pack(">Q", int(t) // period), TOTP_ALGOS[algo]).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_code(thread: str, name: str, now: Optional[float] = None) -> Dict[str, Any]:
    """{"code", "valid_for_s"} for a TOTP secret of the thread; SecretError('unknown') otherwise."""
    entry = live(thread).get(name)
    if not entry or entry["kind"] != "totp":
        raise SecretError("unknown")
    key, digits, period, algo = parse_seed(entry["value"])
    now = time.time() if now is None else now
    return {"code": totp(key, now, digits, period, algo), "valid_for_s": period - int(now) % period}


SECRET_TOTP_SCHEMA = {
    "name": "secret_totp",
    "description": (
        "Current one-time code (TOTP) of an MFA seed a human shared with you via briefling's Secret button, by its "
        "name. Returns only the code and how long it stays valid, never the seed."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Name of the shared TOTP secret (e.g. GITHUB_MFA)."},
        },
        "required": ["name"],
    },
}


def secret_totp_tool(args: Dict[str, Any], **_: Any) -> str:
    """Tool handler (agent thread): the code of a TOTP seed of this thread, never the seed."""
    from tools.registry import tool_error
    from .adapter import _session_thread
    thread, err = _session_thread("secret_totp")
    if err:
        return tool_error(err)
    name = str((args or {}).get("name") or "").strip()
    try:
        return json.dumps(totp_code(thread, name))
    except SecretError:
        names = sorted(n for n, e in live(thread).items() if e["kind"] == "totp")
        return tool_error(f"no TOTP secret named {name!r} in this thread. Available: {', '.join(names) or 'none'}.")
