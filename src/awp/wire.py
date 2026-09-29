"""The wire format: constants, encodings, keys, canonical JSON, ULIDs,
timestamps and signed grants (SPEC.md sections 5 to 10)."""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import hashlib
import json
import math
import os
import re as _re
import secrets
import time

from typing import TYPE_CHECKING

from ._ed25519 import ED25519_BACKEND, ed25519_public, ed25519_sign, ed25519_verify

if TYPE_CHECKING:
    from .store import Identity

PROTOCOL_VERSION = 0
AUTH_CONTEXT = b"awp-auth-v0"
MAX_LINE = 1 << 20                      # bytes, excluding the "\n"
CHUNK_SIZE = 256 * 1024                 # payload bytes per chunk, before base64
DEFAULT_BLOB_LIMIT = 50 * 1024 * 1024
DEFAULT_PING_INTERVAL = 30.0
BACKOFF_INITIAL = 0.5
BACKOFF_CAP = 60.0
BYE_TIMEOUT = 5.0
HANDSHAKE_TIMEOUT = 20.0
RESUME_TIMEOUT = 10.0
DEFAULT_GRANT_TTL = 3600
MY_CAPS = ["chat", "blob", "grant", "introduce"]
EXEC_MIME = "application/vnd.awp.exec+json"
REQUEST_MIMES = {
    "application/vnd.awp.exec+json": "exec",
    "application/vnd.awp.fs-read+json": "fs:read",
    "application/vnd.awp.fs-write+json": "fs:write",
    "application/vnd.awp.admin+json": "admin",
}
CLOSING_ERR_CODES = frozenset({"bad_frame", "version", "auth", "too_large"})
ACKED_TYPES = frozenset({"msg", "state"})
SEEN_TYPES = frozenset({"msg", "state", "chunk"})
PRE_AUTH_FORBIDDEN = frozenset({"msg", "state", "ack", "chunk", "resume", "grant", "introduce"})
READ_SIZE = 256 * 1024
TAILCAT_PORT = 1

FSYNC = os.environ.get("AWP_FSYNC", "1") != "0"


class AwpError(Exception):
    """The base of this package's errors."""


class CommandError(AwpError):
    """A request the peer cannot carry out: a bad key, an empty message, a missing file."""


class StartupError(AwpError):
    """The peer cannot start: the state directory is in use or unreadable, the address is bad."""


# ---------------------------------------------------------------- encodings

def b64url(data: bytes) -> str:
    """Unpadded base64url (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64std(data: bytes) -> str:
    """Standard padded base64 (RFC 4648 section 4)."""
    return base64.b64encode(data).decode("ascii")


_B64_TO_STD = str.maketrans("-_", "+/")


def b64decode_any(s) -> bytes:
    """Liberal base64 decoder: either alphabet, padded or not, whitespace ignored."""
    if not isinstance(s, str):
        raise ValueError("not a string")
    try:
        return base64.b64decode(s, validate=True)          # fast path: std + padding
    except (binascii.Error, ValueError):
        pass
    t = "".join(s.split()).translate(_B64_TO_STD).rstrip("=")
    if len(t) % 4 == 1:
        raise ValueError("invalid base64 length")
    t += "=" * (-len(t) % 4)
    try:
        return base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"invalid base64: {e}") from None


def parse_key(s) -> bytes:
    """'ed25519:<base64url of 32 bytes>' -> 32 raw bytes (the identity)."""
    if not isinstance(s, str):
        raise ValueError("key is not a string")
    prefix, sep, rest = s.partition(":")
    if not sep or prefix.lower() != "ed25519":
        raise ValueError("key must look like ed25519:<base64url>")
    raw = b64decode_any(rest)
    if len(raw) != 32:
        raise ValueError(f"ed25519 key must be 32 bytes, got {len(raw)}")
    return raw


def format_key(raw: bytes) -> str:
    return "ed25519:" + b64url(raw)


def key_fp(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()[:32]


def key_matches(s, raw) -> bool:
    if raw is None:
        return False
    try:
        return parse_key(s) == raw
    except ValueError:
        return False


def safe_name(s: str) -> str:
    """Make a sender-chosen string safe to use as a file name."""
    clean = _re.sub(r"[^A-Za-z0-9._-]", "_", s)[:120].lstrip(".")
    if clean != s or not clean:
        digest = hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()[:12]
        clean = f"{clean or 'x'}_{digest}"
    return clean


def dumps_line(obj) -> bytes:
    """One compact JSON line (no newline), UTF-8."""
    try:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except UnicodeEncodeError:          # lone surrogates: fall back to \u escapes
        return json.dumps(obj, ensure_ascii=True, separators=(",", ":"),
                          allow_nan=False).encode("ascii")


def canonical_json(obj) -> bytes:
    """Canonical JSON for grant signatures: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def canonical_json_variants(obj):
    """Byte strings a signer might reasonably have produced for `obj` (see I1)."""
    out = []
    try:
        base = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except ValueError:
        return out
    try:
        out.append(base.encode("utf-8"))
    except UnicodeEncodeError:
        pass
    asc = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if asc not in out:
        out.append(asc)
    go = (base.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
          .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))
    try:
        gob = go.encode("utf-8")
        if gob not in out:
            out.append(gob)
    except UnicodeEncodeError:
        pass
    return out


def blob_refs(obj) -> list:
    parts = obj.get("parts") if isinstance(obj, dict) else None
    if not isinstance(parts, list):
        return []
    return [p["ref"] for p in parts
            if isinstance(p, dict) and p.get("k") == "blob" and isinstance(p.get("ref"), str)]


# ---------------------------------------------------------------- time

def fmt_ts(t: float, millis: bool = True) -> str:
    d = _dt.datetime.fromtimestamp(t, _dt.timezone.utc)
    s = d.strftime("%Y-%m-%dT%H:%M:%S")
    if millis:
        s += ".%03d" % (d.microsecond // 1000)
    return s + "Z"


def now_ts() -> str:
    return fmt_ts(time.time())


_RFC3339 = _re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:?\d{2})$")


def parse_rfc3339(s) -> float:
    m = _RFC3339.match(s) if isinstance(s, str) else None
    if not m:
        raise ValueError(f"not an RFC 3339 timestamp: {s!r}")
    y, mo, d, hh, mi, ss = (int(m.group(i)) for i in range(1, 7))
    ss = min(ss, 59)                                        # leap second
    t = _dt.datetime(y, mo, d, hh, mi, ss, tzinfo=_dt.timezone.utc).timestamp()
    if m.group(7):
        t += float(m.group(7))
    tz = m.group(8)
    if tz not in ("Z", "z"):
        digits = tz[1:].replace(":", "")
        off = int(digits[:2]) * 3600 + int(digits[2:]) * 60
        t -= off if tz[0] == "+" else -off
    return t


# ---------------------------------------------------------------- ULID ids

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_INDEX = {c: i for i, c in enumerate(_CROCKFORD)}



_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_INDEX = {c: i for i, c in enumerate(_CROCKFORD)}


def ulid_encode(v: int) -> str:
    out = []
    for _ in range(26):
        out.append(_CROCKFORD[v & 31])
        v >>= 5
    return "".join(reversed(out))


def ulid_decode(s):
    if not isinstance(s, str) or len(s) != 26:
        return None
    v = 0
    for ch in s.upper():
        i = _CROCKFORD_INDEX.get(ch)
        if i is None:
            return None
        v = (v << 5) | i
    return v if v < (1 << 128) else None


class UlidGen:
    """Monotonic ULIDs: strictly increasing even within one millisecond."""

    def __init__(self):
        self.last_ms = 0
        self.last_rand = 0

    def observe(self, ulid) -> None:
        v = ulid_decode(ulid)
        if v is None:
            return
        ms, rnd = v >> 80, v & ((1 << 80) - 1)
        if (ms, rnd) > (self.last_ms, self.last_rand):
            self.last_ms, self.last_rand = ms, rnd

    def new(self) -> str:
        ms = time.time_ns() // 1_000_000
        if ms > self.last_ms:
            rnd = secrets.randbits(80)
        else:
            ms = self.last_ms
            rnd = self.last_rand + 1
            if rnd >> 80:
                ms += 1
                rnd = secrets.randbits(80)
        self.last_ms, self.last_rand = ms, rnd
        return ulid_encode((ms << 80) | rnd)


# ---------------------------------------------------------------- Ed25519
# Pure-Python fallback, after the RFC 8032 section 6 reference code.

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)




# ---------------------------------------------------------------- grants

def verify_grant(g):
    """Signature, shape and expiry check.  Returns (ok, reason)."""
    if not isinstance(g, dict):
        return False, "grant is not an object"
    try:
        iss = parse_key(g.get("iss"))
        parse_key(g.get("sub"))
        sig = b64decode_any(g.get("sig"))
    except ValueError as e:
        return False, f"malformed grant: {e}"
    caps = g.get("caps")
    if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
        return False, "caps must be a list of strings"
    body = {k: v for k, v in g.items() if k != "sig"}
    if not any(ed25519_verify(iss, sig, m) for m in canonical_json_variants(body)):
        return False, "bad signature"
    try:
        exp = parse_rfc3339(g.get("exp"))
    except ValueError as e:
        return False, f"bad exp: {e}"
    if exp <= time.time():
        return False, "expired"
    return True, "ok"


def mint_grant(identity: "Identity", sub: str, caps, ttl: float, aud: str | None = None) -> dict:
    """A grant from identity to sub for caps, valid ttl seconds. aud binds
    it to the one peer meant to honor it (an introduction's grant)."""
    g = {"iss": identity.key, "sub": sub, "caps": list(caps),
         "exp": fmt_ts(math.ceil(time.time() + ttl), millis=False),
         "nonce": b64url(os.urandom(32))}
    if aud:
        g["aud"] = aud
    g["sig"] = b64url(identity.sign(canonical_json(g)))
    return g


def grant_hash(g: dict) -> str:
    """How a grant is named: the SHA-256 of its canonical form, signature
    included, shortened; the same as the reference implementation's."""
    import hashlib
    return hashlib.sha256(canonical_json(g)).hexdigest()[:32]


# ---------------------------------------------------------------- persistence

