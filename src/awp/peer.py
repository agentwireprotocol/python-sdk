"""The Peer: listen, connect, send, and receive events (SPEC.md)."""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import mimetypes
import os
import random
import shutil
import socket
import stat
import tempfile
import traceback
from collections.abc import AsyncIterator, Callable, Iterable
from dataclasses import dataclass
from typing import Any

from . import events as ev
from ._log import debug, log
from .connection import Connection
from .store import (PENDING, GrantList, Identity, PeerState, _rec_bytes, atomic_write_json,
                    load_json)
from .transport import Tunnel, TunnelError, find_awp, remote_from_preamble
from .wire import (ACKED_TYPES, BACKOFF_CAP, BACKOFF_INITIAL, CHUNK_SIZE, DEFAULT_BLOB_LIMIT,
                   DEFAULT_GRANT_TTL, DEFAULT_PING_INTERVAL, FSYNC, MAX_LINE, MY_CAPS,
                   PROTOCOL_VERSION, REQUEST_MIMES, CommandError, StartupError, UlidGen,
                   b64decode_any, b64std, blob_refs, dumps_line, format_key, grant_hash,
                   is_address, key_fp, key_matches, mint_grant, now_ts, parse_key, safe_name,
                   verify_grant, x25519_public)


@dataclass(frozen=True)
class Sent:
    """A queued message or state."""

    id: str
    thread: str
    to: str
    new_thread: bool = False


@dataclass(frozen=True)
class PeerInfo:
    """What the Peer knows about another peer."""

    key: str
    name: str | None
    about: str | None
    caps: list[str]
    connected: bool
    last_connected: str | None


@dataclass(frozen=True)
class Thread:
    id: str
    peer: str
    subject: str | None
    my_state: str | None
    their_state: str | None
    closed: bool


class Peer:
    """An AWP peer.

    ::

        async with awp.Peer("~/.mybot", name="mybot@host") as peer:
            address = await peer.listen("tailcat")     # awp1...: share it
            key = await peer.connect("awp1...")        # an address shared with you
            peer.send(key, "Please run make test.", subject="Run the suite")
            async for event in peer.events():
                ...

    Everything durable lives under ``state_dir``: the identity, and per peer
    the outbox of unacked messages, the received ids, threads, grants and
    blobs. ``None`` uses a temporary directory with a fresh identity, removed
    on close. ``send`` never fails because the peer is away: the message is
    on disk and goes out on the next resume.

    Every connection is a WireGuard tunnel between the two peers' keys. The
    tunnel is ``awp tunnel``, the reference implementation's, run as a
    helper process: ``awp`` names the binary (default ``$AWP_BIN`` or
    ``awp`` on PATH).
    """

    def __init__(self, state_dir: str | os.PathLike[str] | None = None, *, name: str | None = None,
                 about: str | None = None, trust: Iterable[str] = (),
                 ping_interval: float = DEFAULT_PING_INTERVAL, blob_limit: int = DEFAULT_BLOB_LIMIT,
                 caps: Iterable[str] | None = None, awp: str | None = None) -> None:
        self._ephemeral = state_dir is None
        self.state_dir = (tempfile.mkdtemp(prefix="awp-") if state_dir is None
                          else os.path.abspath(os.path.expanduser(os.fspath(state_dir))))
        os.makedirs(self.state_dir, exist_ok=True)
        self._lock_fd = os.open(os.path.join(self.state_dir, "lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self._lock_fd)
            raise StartupError(f"state directory {self.state_dir} is in use by another process") from None
        self.outgoing_dir = os.path.join(self.state_dir, "outgoing")
        os.makedirs(self.outgoing_dir, exist_ok=True)
        os.makedirs(os.path.join(self.state_dir, "peers"), exist_ok=True)
        self.name = name or f"awp-py@{socket.gethostname()}"
        self.ping_interval = max(0.05, float(ping_interval)) if ping_interval > 0 else 0.0
        self.blob_limit = int(blob_limit)
        self.hello_caps = list(caps) if caps is not None else list(MY_CAPS)
        self.awp_bin = awp
        self.ids = UlidGen()
        self.identity = Identity.load_or_create(os.path.join(self.state_dir, "identity.json"))
        self.key = self.identity.key
        self.about = about or f"awp-python, key fingerprint sha256:{hashlib.sha256(self.identity.pub).hexdigest()[:16]}"
        self.trusted: set[bytes] = set()
        extra = load_json(os.path.join(self.state_dir, "trust.json"), [])
        for k in list(trust) + (extra if isinstance(extra, list) else []):
            try:
                self.trusted.add(parse_key(k))
            except ValueError as e:
                log(f"warning: ignoring bad trusted key {k!r}: {e}")
        self.issued = GrantList(os.path.join(self.state_dir, "grants_issued.json"))
        self.held = GrantList(os.path.join(self.state_dir, "grants_held.json"))
        self.peers: dict[str, PeerState] = {}
        peers_dir = os.path.join(self.state_dir, "peers")
        for fp in sorted(os.listdir(peers_dir)):
            if fp != PENDING and os.path.isdir(os.path.join(peers_dir, fp)):
                self.peers[fp] = PeerState(self, fp)
        self.pending = PeerState(self, PENDING)
        for ps in self._all_peer_states():
            if ps.outbox.max_id:
                self.ids.observe(ps.outbox.max_id)
        self._cleanup_outgoing()
        self.connections: dict[str, Connection] = {}
        self.all_conns: set[Connection] = set()
        self.conn_counter = 0
        self.default_fp: str | None = None
        dp = load_json(os.path.join(self.state_dir, "default_peer.json"), {})
        if isinstance(dp, dict) and dp.get("fp") in self.peers:
            self.default_fp = dp["fp"]
        self._parked: set[str] = set()
        self._tunnel: Tunnel | None = None
        self._tunnel_lock: asyncio.Lock | None = None
        self._dialers: dict[str, asyncio.Task[None]] = {}
        self._dial_waiters: dict[str, asyncio.Future[str]] = {}
        self._want_dial: set[str] = set()
        self._queue: asyncio.Queue[ev.Event] | None = None
        self._pending_events: list[ev.Event] = []
        self.wake: asyncio.Event | None = None
        self._closed = False
        #: Called with every received line as an object, for drivers that
        #: want the raw protocol (the CLI). None by default.
        self.raw_hook: Callable[[dict[str, Any]], None] | None = None
        self.announced: set[tuple[str, str]] = set()
        self.blob_parts: dict[tuple[str, str], dict[str, Any]] = {}

    # -- lifecycle ---------------------------------------------------------------

    async def start(self) -> Peer:
        """Bind to the running event loop. ``async with`` does this."""
        if self._queue is None:
            self._queue = asyncio.Queue()
            self.wake = asyncio.Event()
            for e in self._pending_events:
                self._queue.put_nowait(e)
            self._pending_events = []
            log(f"identity {self.key}, state {self.state_dir}")
            for ps in list(self.peers.values()):
                for ref in ps.inbox.to_finish:
                    self.finish_blob(ps, ref)
                ps.inbox.to_finish = []
        return self

    async def __aenter__(self) -> Peer:
        return await self.start()

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        """Stop listening and dialing, and drop every connection without a
        bye: the state is on disk and peers resume next time."""
        if self._closed:
            return
        self._closed = True
        for t in list(self._dialers.values()):
            t.cancel()
        for t in list(self._dialers.values()):
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        self._dialers.clear()
        for c in list(self.all_conns):
            c.close("closing")
        for c in list(self.all_conns):
            try:
                await asyncio.wait_for(c.done.wait(), 2)
            except asyncio.TimeoutError:
                pass
        if self._tunnel is not None:
            await self._tunnel.close()
            self._tunnel = None
        try:
            os.close(self._lock_fd)
        except OSError:
            pass
        if self._ephemeral:
            shutil.rmtree(self.state_dir, ignore_errors=True)

    # -- listening and connecting --------------------------------------------------

    async def _ensure_tunnel(self) -> Tunnel:
        """Start ``awp tunnel`` for this Peer, once."""
        await self.start()
        if self._tunnel_lock is None:
            self._tunnel_lock = asyncio.Lock()
        async with self._tunnel_lock:
            if self._tunnel is None:
                t = Tunnel(find_awp(self.awp_bin), os.path.join(self.state_dir, "identity.json"),
                           os.path.join(self.state_dir, "tunnel"))
                await t.start(self._accept)
                self._tunnel = t
                log(f"tunnel up (awp tunnel, pid {t.proc.pid if t.proc else '?'})")
        return self._tunnel

    @property
    def address(self) -> str | None:
        """The address to share (``awp1...``): this Peer's key, the
        pre-shared key that admits peers it has not met, and every carrier
        it listens on. None until it listens on something."""
        return self._tunnel.address if self._tunnel else None

    async def listen(self, carrier: str = "tailcat") -> str:
        """Accept connections on a carrier, and return the address to share,
        which lists every carrier this Peer listens on:

        ``tailcat``
            reachable from anywhere, through NAT, with no account
        ``udp:HOST:PORT``
            plain UDP: a LAN, Fly's 6PN, a public address
        ``ws:HOST:PORT`` or ``ws:HOST:PORT=URL``
            WebSockets, or behind a proxy or HTTP tunnel at URL
        ``cloudflare``
            WebSockets through a Cloudflare quick tunnel (needs cloudflared)
        ``unix:/path``
            peers on the same machine

        tailcat and cloudflare take a few seconds to come up."""
        t = await self._ensure_tunnel()
        try:
            address = await t.listen(carrier)
        except TunnelError as e:
            raise StartupError(f"cannot listen on {carrier}: {e}") from None
        log(f"listening on {carrier}")
        return address

    async def rotate_psk(self) -> str | None:
        """Replace the pre-shared key in this Peer's address. Copies of the
        address shared before stop admitting peers not met yet; peers
        already met keep working. Returns the new address."""
        t = await self._ensure_tunnel()
        return await t.rotate()

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """A stream a peer opened, forwarded by the tunnel helper."""
        try:
            pre = await asyncio.wait_for(reader.readline(), 10)
        except (asyncio.TimeoutError, OSError):
            writer.close()
            return
        remote = remote_from_preamble(pre)
        self.conn_counter += 1
        conn = Connection(self, reader, writer, f"conn#{self.conn_counter} in", remote=remote)
        conn.outbound = False  # type: ignore[attr-defined]
        try:
            await conn.run()
        except Exception as e:
            log(f"{conn.label}: crashed: {e}\n{traceback.format_exc()}")

    async def connect(self, addr: str, *, timeout: float | None = 30.0) -> str:
        """Dial an address shared out of band and return the key of the
        peer that answered, once the handshake is done. The Peer keeps
        dialing with backoff, capped at a minute, whenever there are unacked
        messages or open threads with that peer."""
        if not is_address(addr):
            raise StartupError(f"{addr!r} is not an address; addresses start with awp1")
        addr = addr.strip()
        await self._ensure_tunnel()
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[str] = loop.create_future()
        self._want_dial.add(addr)                   # dial now, work or not
        if addr in self._dialers and not self._dialers[addr].done():
            for ps in self.peers.values():
                if ps.meta.get("dialed") == addr:
                    if ps.fp in self.connections:
                        self._want_dial.discard(addr)
                        return ps.key_str or format_key(ps.key_raw)
                    self._parked.discard(ps.fp)     # an explicit connect lifts a bye
            fut = self._dial_waiters.setdefault(addr, fut)
            assert self.wake is not None
            self.wake.set()
        else:
            self._dial_waiters[addr] = fut
            self._dialers[addr] = asyncio.create_task(self._dial_loop(addr))
        try:
            return await asyncio.wait_for(asyncio.shield(fut), timeout)
        except asyncio.TimeoutError:
            t = self._dialers.pop(addr, None)
            if t is not None:
                t.cancel()
            self._dial_waiters.pop(addr, None)
            raise ConnectionError(f"no handshake with {addr} within {timeout}s") from None


    async def _dial_loop(self, addr: str) -> None:
        delay = BACKOFF_INITIAL
        ps: PeerState | None = None
        try:
            while not self._closed:
                idle = lambda: (addr not in self._want_dial and ps is not None and  # noqa: E731
                                (ps.fp in self._parked or not (ps.has_work() or self.pending.has_work())))
                if idle():
                    assert self.wake is not None
                    self.wake.clear()
                    if idle():
                        log(f"{addr}: idle; waiting for new work")
                        await self.wake.wait()
                    continue
                addrs = [addr]
                if ps is not None and is_address(ps.meta.get("addr")) and ps.meta["addr"] != addr:
                    addrs.append(ps.meta["addr"])       # where the peer said it is, in hello
                try:
                    assert self._tunnel is not None
                    reader, writer, rep = await self._tunnel.dial(addrs, timeout=60)
                except (OSError, asyncio.TimeoutError, ValueError, AssertionError) as e:
                    d = delay * random.uniform(0.9, 1.1)
                    log(f"connect {addr} failed: {e or type(e).__name__}; retrying in {d:.2f}s")
                    await asyncio.sleep(d)
                    delay = min(delay * 2, BACKOFF_CAP)
                    continue
                self.conn_counter += 1
                try:
                    remote = b64decode_any(rep.get("remote"))
                except ValueError:
                    remote = None
                conn = Connection(self, reader, writer, f"conn#{self.conn_counter} to {addr[:16]}…", remote=remote)
                conn.outbound = True  # type: ignore[attr-defined]
                conn.dialed = addr  # type: ignore[attr-defined]
                established = await conn.run()
                self._want_dial.discard(addr)
                if established:
                    ps = conn.ps
                    delay = BACKOFF_INITIAL
                    continue
                d = delay * random.uniform(0.9, 1.1)
                log(f"reconnecting to {addr} in {d:.2f}s")
                await asyncio.sleep(d)
                delay = min(delay * 2, BACKOFF_CAP)
        except asyncio.CancelledError:
            pass

    # -- what the connections call ---------------------------------------------------

    def make_hello(self, remote: bytes | None = None) -> dict[str, Any]:
        """Our hello: our address without its pre-shared key, so the peer can
        reconnect to us, and the grants we hold that concern the peer on the
        other end of the tunnel (ones it issued, and introductions meant for
        it)."""
        grants = []
        if remote is not None:
            for g in self.held.valid():
                if any(isinstance(g.get(f), str) and _tunnel_key(g[f]) == remote for f in ("iss", "aud")):
                    grants.append(g)
        public = self._tunnel.public if self._tunnel else None
        return self.envelope("hello", v=PROTOCOL_VERSION, key=self.key, name=self.name,
                             caps=list(self.hello_caps), about=self.about, addr=public,
                             grants=grants or None)

    def make_err(self, code: str, detail: str, re: str | None = None, ref: str | None = None) -> dict[str, Any]:
        return self.envelope("err", re=re, code=code, detail=detail, ref=ref)

    def envelope(self, t: str, **fields: Any) -> dict[str, Any]:
        obj: dict[str, Any] = {"t": t, "id": self.ids.new(), "ts": now_ts()}
        for k, v in fields.items():
            if v is not None:
                obj[k] = v
        return obj

    def entry_line(self, e: dict[str, Any]) -> bytes:
        obj = e["obj"]
        if obj.get("t") == "chunk" and "src" in e:
            with open(os.path.join(self.outgoing_dir, e["src"]), "rb") as f:
                f.seek(int(e["off"]))
                data = f.read(int(e["len"]))
            if len(data) != int(e["len"]):
                raise ValueError("outgoing blob copy is shorter than expected")
            obj = dict(obj)
            obj["data"] = b64std(data)
        return dumps_line(obj)

    def _emit(self, event: ev.Event) -> None:
        if self._queue is None:
            self._pending_events.append(event)
        else:
            self._queue.put_nowait(event)

    def emit(self, d: dict[str, Any]) -> None:
        """Events from the connection code, as dicts; translated here."""
        kind = d.get("event")
        if kind == "acked":
            self._emit(ev.Acked(peer=d.get("peer", ""), id=d["id"]))
        elif kind == "disconnected":
            self._emit(ev.Disconnected(peer=d.get("peer", ""), reason=d.get("reason", "closed")))
        elif kind == "error":
            self._emit(ev.Error(peer=d.get("peer", ""), detail=d["detail"]))

    def emit_error(self, detail: str) -> None:
        log(f"error: {detail}")
        self._emit(ev.Error(peer="", detail=detail))

    def on_connected(self, conn: Connection, name: str, caps: list[str], about: str) -> None:
        key = conn.peer_key_str
        if getattr(conn, "dialed", None):
            conn.ps.meta["dialed"] = conn.dialed  # type: ignore[attr-defined]
            atomic_write_json(conn.ps.meta_path, conn.ps.meta)
            fut = self._dial_waiters.pop(conn.dialed, None)  # type: ignore[attr-defined]
            if fut is not None and not fut.done():
                fut.set_result(key)
        self._parked.discard(conn.ps.fp)
        self._emit(ev.Connected(peer=key, name=name, caps=list(caps), about=about,
                                outbound=bool(getattr(conn, "outbound", False))))

    def emit_recv(self, conn: Connection, obj: dict[str, Any]) -> None:
        if self.raw_hook is not None:
            shown = obj
            if obj.get("t") == "chunk" and "data" in obj:
                shown = {k: v for k, v in obj.items() if k != "data"}
            self.raw_hook(shown)
        key = conn.peer_key_str or ""
        t = obj.get("t")
        sid = obj.get("id") if isinstance(obj.get("id"), str) else ""
        th = obj.get("th") if isinstance(obj.get("th"), str) else None
        if t == "msg" and th is not None:
            self._emit(ev.Message(peer=key, id=sid, thread=th,
                                  parts=[p for p in obj.get("parts", []) if isinstance(p, dict)],
                                  subject=obj.get("subject") if isinstance(obj.get("subject"), str) else None,
                                  reply_to=obj.get("re") if isinstance(obj.get("re"), str) else None,
                                  requests=self._requests(conn.ps, obj)))
        elif t == "state" and th is not None:
            self._emit(ev.State(peer=key, id=sid, thread=th, state=str(obj.get("state")),
                                note=obj.get("note") if isinstance(obj.get("note"), str) else None))
        elif t == "err":
            self._emit(ev.PeerError(peer=key, code=str(obj.get("code")),
                                    detail=obj.get("detail") if isinstance(obj.get("detail"), str) else None,
                                    reply_to=obj.get("re") if isinstance(obj.get("re"), str) else None,
                                    ref=obj.get("ref") if isinstance(obj.get("ref"), str) else None))
        elif t == "bye":
            self._emit(ev.Bye(peer=key, reason=obj.get("reason") if isinstance(obj.get("reason"), str) else None))

    def _requests(self, ps: PeerState, obj: dict[str, Any]) -> list[ev.Request]:
        out: list[ev.Request] = []
        parts = obj.get("parts")
        if not isinstance(parts, list):
            return out
        caps = None
        for i, p in enumerate(parts):
            if not isinstance(p, dict) or p.get("k") != "data":
                continue
            cap = REQUEST_MIMES.get(str(p.get("mime", "")).strip().lower())
            if cap is None:
                continue
            if caps is None:
                caps = self.honored_caps(ps)
            out.append(ev.Request(part=i, mime=str(p.get("mime")), cap=cap, allowed=cap in caps))
        return out

    # -- peers and connections ----------------------------------------------

    def peer_state_for(self, raw: bytes, key_str: str) -> PeerState:
        fp = key_fp(raw)
        ps = self.peers.get(fp)
        if ps is None:
            ps = self.peers[fp] = PeerState(self, fp, raw, key_str)
        return ps

    def bind_peer(self, raw: bytes, key_str: str, hello: dict[str, Any]) -> PeerState:
        ps = self.peer_state_for(raw, key_str)
        ps.save_meta(key_str, hello)
        if self.default_fp is None:
            ps.adopt(self.pending)          # what was queued before any peer was known
        if self.default_fp != ps.fp:
            self.default_fp = ps.fp
            atomic_write_json(os.path.join(self.state_dir, "default_peer.json"),
                              {"fp": ps.fp, "key": format_key(raw)}, durable=True)
        return ps

    def register_connection(self, conn: Connection) -> None:
        old = self.connections.get(conn.ps.fp)
        if old is not None and old is not conn:
            log(f"{old.label}: superseded by {conn.label} (same key)")
            old.close("superseded by a newer connection from the same key")
        self.connections[conn.ps.fp] = conn

    def on_conn_closed(self, conn: Connection) -> None:
        self.all_conns.discard(conn)
        if conn.ps is not None and self.connections.get(conn.ps.fp) is conn:
            del self.connections[conn.ps.fp]
        reason = conn.close_reason or "closed"
        log(f"{conn.label}: closed ({reason})")
        if conn.established:
            self._emit(ev.Disconnected(peer=conn.peer_key_str or "", reason=reason))

    def _ps(self, to: str | None) -> PeerState:
        """The state for a peer key. None means the default peer: the one
        that last connected, or, before any did, a pending queue that the
        first peer to connect adopts."""
        if to is None:
            if self.default_fp and self.default_fp in self.peers:
                return self.peers[self.default_fp]
            return self.pending
        try:
            raw = parse_key(to)
        except ValueError as e:
            raise CommandError(f"bad peer key: {e}") from None
        return self.peer_state_for(raw, to)

    def on_bye_exchange(self, conn: Connection) -> None:
        if conn.ps is not None:
            self._parked.add(conn.ps.fp)

    def _new_work(self, ps: PeerState) -> None:
        self._parked.discard(ps.fp)
        if self.wake is not None:
            self.wake.set()

    def _all_peer_states(self) -> list[PeerState]:
        return list(self.peers.values()) + [self.pending]

    def _cleanup_outgoing(self) -> None:
        used: set[str] = set()
        for ps in self._all_peer_states():
            used.update(ps.outbox.src_count.keys())
        for name in os.listdir(self.outgoing_dir):
            if name not in used:
                try:
                    os.remove(os.path.join(self.outgoing_dir, name))
                except OSError:
                    pass

    # -- outbox ---------------------------------------------------------------

    def _queue_outbox(self, ps: PeerState, entries: list[dict[str, Any]]) -> None:
        fresh = ps.outbox.add_many(entries)                 # durable before sending
        for e in fresh:
            obj = e["obj"]
            if obj["t"] in ACKED_TYPES and isinstance(obj.get("th"), str):
                ps.threads.touch(obj["th"], obj, outgoing=True)
        conn = self.connections.get(ps.fp)
        if conn is not None:
            for e in fresh:
                conn.queue_entry(e["obj"]["id"])
        self._new_work(ps)

    def prune(self, ps: PeerState, eid: str, via: str) -> None:
        e = ps.outbox.entries.get(eid)
        if e is None:
            return
        obj = e["obj"]
        t = obj.get("t")
        if t in ACKED_TYPES:            # emit first: a kill in between repeats, never loses
            debug(f"{t} {eid} acknowledged ({via})")
            self._emit(ev.Acked(peer=ps.key_str or "", id=eid))
        ps.outbox.remove(eid)
        if t == "msg":
            for ref in blob_refs(obj):
                for cid in list(ps.outbox.by_ref.get(ref, ())):
                    ps.outbox.remove(cid)

    def apply_seen(self, ps: PeerState, seen: dict[str, Any]) -> None:
        """Outbox entries covered by the peer's seen map count as acked."""
        from .wire import ulid_decode
        usable: dict[str, str] = {}
        for th, sid in seen.items():
            if ulid_decode(sid) is None:
                log(f"warning: peer's seen id {sid!r} for thread {th!r} is not one of our ids; "
                    "replaying the whole thread")
            else:
                usable[th] = sid.upper()
        if not usable:
            return
        for eid in list(ps.outbox.entries.keys()):
            e = ps.outbox.entries.get(eid)
            if e is None:
                continue
            th = e["obj"].get("th")
            if isinstance(th, str) and th in usable and eid <= usable[th]:
                self.prune(ps, eid, "resume seen")

    def stop_blob(self, ps: PeerState, ref: str) -> None:
        ids = list(ps.outbox.by_ref.get(ref, ()))
        for cid in ids:
            ps.outbox.remove(cid)
        log(f"peer refused blob {ref!r}; dropped {len(ids)} queued chunk(s)")

    def ref_for_entry(self, ps: PeerState, eid: Any) -> str | None:
        e = ps.outbox.entries.get(eid) if isinstance(eid, str) else None
        if e is None:
            return None
        if e["obj"].get("t") == "chunk":
            return e["obj"].get("ref")
        refs = blob_refs(e["obj"])
        return refs[0] if len(refs) == 1 else None

    # -- inbound --------------------------------------------------------------

    def on_msg_or_state(self, conn: Connection, obj: dict[str, Any], t: str) -> None:
        ps = conn.ps
        mid = obj.get("id") if isinstance(obj.get("id"), str) and obj.get("id") else None
        th = obj.get("th") if isinstance(obj.get("th"), str) and obj.get("th") else None
        if mid is not None and mid in ps.inbox.dedup:
            debug(f"{conn.label}: duplicate {t} {mid}; re-acking")
            if th is not None:
                conn.queue_ack(th, mid)
            return
        rec = {"id": mid, "t": t, "th": th}
        raw = _rec_bytes(rec)
        if mid is None:
            log(f"{conn.label}: warning: {t} without id cannot be acked or deduplicated")
        else:
            ps.inbox.record(rec, durable=True, raw=raw)      # persist, then report, then ack
        if th is not None:
            ps.threads.touch(th, obj, outgoing=False)
        elif mid is not None:
            log(f"{conn.label}: warning: {t} {mid} has no th; delivered but not acked")
        self.emit_recv(conn, obj)
        if t == "msg":
            self._inspect_parts(conn, obj, mid)
        if mid is not None and th is not None:
            conn.queue_ack(th, mid)

    def _inspect_parts(self, conn: Connection, obj: dict[str, Any], mid: str | None) -> None:
        ps = conn.ps
        parts = obj.get("parts")
        if not isinstance(parts, list):
            return
        needs: set[str] = set()
        for p in parts:
            if not isinstance(p, dict):
                continue
            k = p.get("k")
            if k == "blob":
                ref, size = p.get("ref"), p.get("size")
                if isinstance(ref, str) and isinstance(size, int) and not isinstance(size, bool):
                    ps.inbox.declared[ref] = size
                    self.blob_parts[(ps.fp, ref)] = {"name": p.get("name"), "mime": p.get("mime"),
                                                     "th": obj.get("th")}
                    if (size > self.blob_limit and ref not in ps.inbox.done
                            and ref not in ps.inbox.refused):
                        self.refuse_blob(conn, ps, ref, mid,
                                         f"declared blob size {size} exceeds the local limit of {self.blob_limit} bytes")
                    elif ref in ps.inbox.done:
                        self._announce_blob(ps, ref)        # the data came first
            elif k == "data":
                cap = REQUEST_MIMES.get(str(p.get("mime", "")).strip().lower())
                if cap is not None:
                    needs.add(cap)
        if needs:
            missing = sorted(needs - self.honored_caps(ps))
            if missing:
                conn.send_err("forbidden", f"request needs capability {', '.join(missing)} "
                                           "and this peer holds no honored grant for it", re=mid)

    def on_chunk(self, conn: Connection, obj: dict[str, Any]) -> None:
        ps = conn.ps
        inbox = ps.inbox
        cid = obj.get("id") if isinstance(obj.get("id"), str) and obj.get("id") else None
        th = obj.get("th") if isinstance(obj.get("th"), str) and obj.get("th") else None
        if cid is not None and cid in inbox.dedup:
            debug(f"{conn.label}: duplicate chunk {cid}")
            return
        self.emit_recv(conn, obj)
        ref = obj.get("ref")
        if not isinstance(ref, str) or not ref:
            log(f"{conn.label}: warning: chunk {cid} has no ref; ignored")
            return
        base = {"id": cid, "t": "chunk", "th": th, "ref": ref}
        if ref in inbox.refused or ref in inbox.done:
            if cid:
                inbox.record(dict(base, stored=False), durable=False)
            return
        st = inbox.partial.get(ref)
        expected = st["next"] if st else 0
        n = obj.get("n")
        if isinstance(n, bool) or not isinstance(n, int):
            n = expected
        if n < expected:
            if cid:
                inbox.record(dict(base, n=n, stored=False), durable=False)
            return
        if n > expected:
            conn.send_err("internal", f"blob {ref}: got chunk {n} but chunk {expected} was expected; "
                                      "chunk ignored", re=cid)
            return
        from .wire import b64decode_any
        try:
            data = b64decode_any(obj.get("data", ""))
        except ValueError as e:
            self.refuse_blob(conn, ps, ref, cid, f"chunk data is not valid base64: {e}")
            if cid:
                inbox.record(dict(base, n=n, stored=False), durable=False)
            return
        total = (st["size"] if st else 0) + len(data)
        if total > self.blob_limit:
            self.refuse_blob(conn, ps, ref, cid,
                             f"blob {ref} exceeds the local size limit of {self.blob_limit} bytes")
            if cid:
                inbox.record(dict(base, n=n, stored=False), durable=False)
            return
        last = obj.get("last") is True
        os.makedirs(inbox.partial_dir, exist_ok=True)
        with open(inbox.partial_path(ref), "ab" if st else "wb") as f:
            f.write(data)
            f.flush()
            if FSYNC:
                os.fsync(f.fileno())
        inbox.record(dict(base, n=n, len=len(data), last=last, stored=True), durable=False)
        if last:
            self.finish_blob(ps, ref)

    def refuse_blob(self, conn: Connection, ps: PeerState, ref: str, re_id: str | None, detail: str) -> None:
        inbox = ps.inbox
        if ref in inbox.refused:
            return
        conn.send_err("blob_refused", detail, re=re_id, ref=ref)
        inbox.record({"op": "blob_refused", "ref": ref}, durable=False)
        try:
            os.remove(inbox.partial_path(ref))
        except OSError:
            pass

    def finish_blob(self, ps: PeerState, ref: str) -> None:
        inbox = ps.inbox
        src, dst = inbox.partial_path(ref), inbox.final_path(ref)
        if os.path.exists(src):
            os.replace(src, dst)
        h = hashlib.sha256()
        size = 0
        with open(dst, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
                size += len(block)
        declared = inbox.declared.get(ref)
        if declared is not None and declared != size:
            log(f"warning: blob {ref!r} is {size} bytes but its blob part declared {declared}")
        digest = h.hexdigest()
        log(f"blob {ref!r} complete: {size} bytes -> {dst}")
        inbox.record({"op": "blob_done", "ref": ref, "path": dst, "size": size, "sha256": digest},
                     durable=True)
        if (ps.fp, ref) in self.blob_parts:
            self._announce_blob(ps, ref)

    def _announce_blob(self, ps: PeerState, ref: str) -> None:
        """A blob is reported once its data is complete and the msg naming
        it has arrived, whichever came last."""
        if (ps.fp, ref) in self.announced:
            return
        rec = ps.inbox.done.get(ref)
        if rec is None:
            return
        self.announced.add((ps.fp, ref))
        part = self.blob_parts.get((ps.fp, ref), {})
        self._emit(ev.Blob(peer=ps.key_str or "", ref=ref, path=rec["path"], size=int(rec["size"]),
                           sha256=rec["sha256"], thread=part.get("th"), name=part.get("name"),
                           mime=part.get("mime")))

    # -- grants -----------------------------------------------------------------

    def is_root(self, raw: bytes) -> bool:
        return raw == self.identity.pub or raw in self.trusted

    def supporting_grants(self, ps: PeerState) -> list[dict[str, Any]]:
        return list(ps.grants.items) + list(self.issued.items) + list(self.held.items)

    def grant_honored(self, g: dict[str, Any], ps: PeerState) -> bool:
        ok, _ = verify_grant(g)
        if not ok:
            return False
        aud = g.get("aud")
        if isinstance(aud, str) and not key_matches(aud, self.identity.pub):
            return False                    # meant for another peer to honor
        iss = parse_key(g["iss"])
        if self.is_root(iss):
            return True
        for s in self.supporting_grants(ps):                # one level of delegation
            if s is g or s.get("sig") == g.get("sig"):
                continue
            if not verify_grant(s)[0]:
                continue
            try:
                if (parse_key(s["sub"]) == iss and "introduce" in s["caps"]
                        and self.is_root(parse_key(s["iss"]))):
                    return True
            except (ValueError, KeyError, TypeError):
                continue
        return False

    def honored_caps(self, ps: PeerState) -> set[str]:
        caps: set[str] = set()
        cands = list(ps.grants.items) + [g for g in self.issued.items
                                         if key_matches(g.get("sub"), ps.key_raw)]
        for g in cands:
            if key_matches(g.get("sub"), ps.key_raw) and self.grant_honored(g, ps):
                caps.update(c for c in g.get("caps", []) if isinstance(c, str))
        return caps

    def receive_grant(self, conn: Connection, g: Any, source: str) -> None:
        ok, why = verify_grant(g)
        if not ok:
            log(f"{conn.label}: ignoring invalid grant ({source}): {why}")
            return
        sub = parse_key(g["sub"])
        conn.ps.grants.add(g)
        caps = [c for c in g.get("caps", []) if isinstance(c, str)]
        if sub == self.identity.pub:
            fresh = not any(x.get("sig") == g.get("sig") for x in self.held.items)
            self.held.add(g)
            log(f"{conn.label}: now holding grant {caps} from {g['iss']} ({source})")
            if fresh:
                self._emit(ev.GrantReceived(peer=conn.peer_key_str or "", issuer=g["iss"], caps=caps,
                                            expires=str(g.get("exp")), grant=dict(g)))
        elif sub == conn.peer_key_raw:
            verdict = "honored" if self.grant_honored(g, conn.ps) else "not honored (issuer not trusted)"
            log(f"{conn.label}: peer presented grant {caps} issued by {g['iss']} ({source}): {verdict}")
        else:
            log(f"{conn.label}: stored grant {caps} for third party {g['sub']} ({source})")

    def on_introduce(self, conn: Connection, obj: dict[str, Any]) -> None:
        g = obj.get("grant")
        if g is not None:
            self.receive_grant(conn, g, "introduce")
        peer = obj.get("peer") if isinstance(obj.get("peer"), dict) else {}
        key = peer.get("key")
        if not isinstance(key, str):
            return
        with open(os.path.join(self.state_dir, "introductions.jsonl"), "ab") as f:
            f.write(_rec_bytes({"from": conn.peer_key_str, "at": now_ts(), "th": obj.get("th"), "peer": peer}))
        log(f"{conn.label}: introduced to {key}")
        self._emit(ev.Introduced(peer=conn.peer_key_str or "", key=key,
                                 name=peer.get("name") if isinstance(peer.get("name"), str) else None,
                                 address=peer.get("address") if is_address(peer.get("address")) else None,
                                 thread=obj.get("th") if isinstance(obj.get("th"), str) else None,
                                 grant=dict(g) if isinstance(g, dict) else None))

    # -- the API ------------------------------------------------------------------

    def send(self, to: str | None, text: str | None = None, *, thread: str | None = None,
             subject: str | None = None, reply_to: str | None = None,
             parts: Iterable[dict[str, Any]] | None = None, files: Iterable[str | os.PathLike[str]] = ()) -> Sent:
        """Queue a msg to the peer ``to`` (its key). ``text`` becomes the
        first part; ``parts`` adds code or data parts; each of ``files``
        travels as a blob in chunks ahead of the message. A new thread
        starts when ``thread`` is None; ``subject`` titles it."""
        ps = self._ps(to)
        all_parts: list[dict[str, Any]] = []
        if text is not None:
            all_parts.append({"k": "text", "text": text})
        for p in parts or ():
            if not isinstance(p, dict) or not isinstance(p.get("k"), str):
                raise CommandError("parts must be objects with a k")
            if p["k"] == "blob":
                raise CommandError("blob parts are made from files")
            all_parts.append(dict(p))
        entries: list[dict[str, Any]] = []
        new_thread = thread is None or thread not in ps.threads.data
        th = thread or ("thr_" + self.ids.new().lower()[-10:])
        for path in files:
            part, chunk_entries = self._chunk_file(os.fspath(path), th)
            entries.extend(chunk_entries)
            all_parts.append(part)
        if not all_parts:
            raise CommandError("empty message: give text, parts or files")
        if new_thread and subject is None:
            subject = _derive_subject(all_parts)
        obj = self.envelope("msg", th=th, re=reply_to, subject=subject, parts=all_parts)
        if len(dumps_line(obj)) > MAX_LINE:
            raise CommandError("message would exceed the 1 MiB line limit; send it as a file")
        entries.append({"obj": obj})
        self._queue_outbox(ps, entries)
        return Sent(id=obj["id"], thread=th, to=ps.key_str or to or "", new_thread=new_thread)

    def _chunk_file(self, path: str, th: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        try:
            st = os.stat(path)
        except OSError as e:
            raise CommandError(f"cannot read {path}: {e}") from None
        if not stat.S_ISREG(st.st_mode):
            raise CommandError(f"{path} is not a regular file")
        if st.st_size > self.blob_limit:
            raise CommandError(f"{path} is {st.st_size} bytes; the blob limit is {self.blob_limit}")
        ref = "blob_" + self.ids.new().lower()
        src = safe_name(ref)
        dst = os.path.join(self.outgoing_dir, src)
        shutil.copyfile(path, dst)                          # immutable, durable copy
        with open(dst, "rb") as f:
            if FSYNC:
                os.fsync(f.fileno())
        size = os.path.getsize(dst)
        name = os.path.basename(path)
        mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
        nchunks = max(1, -(-size // CHUNK_SIZE))
        entries = []
        for n in range(nchunks):
            off = n * CHUNK_SIZE
            cobj = self.envelope("chunk", th=th, ref=ref, n=n, last=(n == nchunks - 1))
            entries.append({"obj": cobj, "src": src, "off": off, "len": min(CHUNK_SIZE, size - off)})
        return {"k": "blob", "ref": ref, "name": name, "mime": mime, "size": size}, entries

    def set_state(self, to: str | None, thread: str, state: str, note: str | None = None) -> Sent:
        """Send this side's state on a thread: open, working, waiting, done,
        failed, closed, or any word the two agents agree on."""
        if not state:
            raise CommandError("state is required")
        ps = self._ps(to)
        obj = self.envelope("state", th=thread, state=state, note=note)
        self._queue_outbox(ps, [{"obj": obj}])
        return Sent(id=obj["id"], thread=thread, to=ps.key_str or to or "")

    def grant(self, to: str, caps: Iterable[str], ttl: float = DEFAULT_GRANT_TTL) -> dict[str, Any]:
        """Mint a grant giving the peer the capabilities for ``ttl`` seconds,
        remember it, and send it (now, or when the peer is next connected)."""
        ps = self._ps(to)
        caps = list(caps)
        if not all(isinstance(c, str) for c in caps):
            raise CommandError("caps must be strings")
        if ttl <= 0:
            raise CommandError("ttl must be positive")
        g = mint_grant(self.identity, to, caps, ttl)
        self.issued.add(g)
        obj = self.envelope("grant", grant=g)
        ps.sendonce.add(obj)
        conn = self.connections.get(ps.fp)
        if conn is not None:
            conn.queue_once(obj["id"])
        self._new_work(ps)
        log(f"minted grant {caps} for {to}, expires {g['exp']}")
        return g

    def caps(self, to: str) -> set[str]:
        """The capabilities the peer holds on this Peer, from honored grants."""
        return self.honored_caps(self._ps(to))

    def grants(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """The grants this Peer issued and the ones it holds, valid now,
        each with a "hash" naming it for revoke()."""
        with_hash = lambda gs: [dict(g, hash=grant_hash(g)) for g in gs]
        return with_hash(self.issued.valid()), with_hash(self.held.valid())

    def revoke(self, hash: str) -> bool:
        """Stop honoring a grant this Peer issued, named by its hash. The
        peer's copy stays valid elsewhere until it expires."""
        for g in self.issued.items:
            if grant_hash(g) == hash:
                self.issued.remove(g.get("sig"))
                for ps in self.peers.values():
                    ps.grants.remove(g.get("sig"))
                return True
        return False

    def introduce(self, to: str, peer: str, caps: Iterable[str] = (), ttl: float = DEFAULT_GRANT_TTL,
                  thread: str | None = None) -> Sent:
        """Hand ``to`` the key and address of ``peer``, with a grant for
        ``caps`` that ``peer`` honors if it trusts this Peer with introduce.
        The grant is bound to ``peer`` (aud), so it confers nothing on anyone
        else. The address is the one ``peer`` announced or was dialed at."""
        if to == peer:
            raise CommandError("cannot introduce a peer to itself")
        target = self._ps(to)
        known = self.peers.get(key_fp(parse_key(peer)))
        if known is None or known.key_raw is None:
            raise CommandError(f"unknown peer {peer}")
        # The address we dialed carries the peer's pre-shared key; the one it
        # sent in hello does not.
        address = known.meta.get("dialed") or known.meta.get("addr")
        if not address:
            raise CommandError(f"no known address for {peer}")
        g = mint_grant(self.identity, to, list(caps), ttl, aud=peer)
        self.issued.add(g)
        intro = {"key": known.key_str or format_key(known.key_raw), "address": address}
        if known.meta.get("name"):
            intro["name"] = known.meta["name"]
        obj = self.envelope("introduce", th=thread, peer=intro, grant=g)
        target.sendonce.add(obj)
        conn = self.connections.get(target.fp)
        if conn is not None:
            conn.queue_once(obj["id"])
        self._new_work(target)
        return Sent(id=obj["id"], thread=thread or "", to=target.key_str or to)

    async def bye(self, to: str, reason: str = "done") -> None:
        """Close the connection to the peer gracefully and park it: no
        reconnection until something new is queued for it."""
        ps = self._ps(to)
        self._parked.add(ps.fp)
        conn = self.connections.get(ps.fp)
        if conn is None or not conn.established or conn.closing:
            raise ConnectionError("not connected (the peer is parked all the same)")
        conn.initiate_bye(reason)
        try:
            await asyncio.wait_for(conn.done.wait(), 6)
        except asyncio.TimeoutError:
            pass

    def connected(self, to: str) -> bool:
        ps = self.peers.get(key_fp(parse_key(to)))
        conn = self.connections.get(ps.fp) if ps else None
        return bool(conn and conn.established and not conn.closing)

    def list_peers(self) -> list[PeerInfo]:
        out = []
        for ps in self.peers.values():
            if ps.key_raw is None:
                continue
            key = ps.key_str or format_key(ps.key_raw)
            out.append(PeerInfo(key=key, name=ps.meta.get("name"), about=ps.meta.get("about"),
                                caps=list(ps.meta.get("caps") or []), connected=self.connected(key),
                                last_connected=ps.meta.get("last_connected")))
        return out

    def threads(self, to: str | None = None) -> list[Thread]:
        out = []
        for ps in self.peers.values():
            if ps.key_raw is None or (to is not None and not key_matches(to, ps.key_raw)):
                continue
            key = ps.key_str or format_key(ps.key_raw)
            for th, rec in ps.threads.data.items():
                if isinstance(rec, dict):
                    out.append(Thread(id=th, peer=key, subject=rec.get("subject"), my_state=rec.get("mine"),
                                      their_state=rec.get("theirs"), closed=bool(rec.get("closed"))))
        return out

    async def wait_ack(self, id: str, timeout: float | None = None) -> None:
        """Wait until the peer acks the message ``id``. Other events keep
        flowing to ``events()`` in the meantime? No: events are one queue;
        use this from a task of its own, or watch for Acked in events()."""
        deadline = None if timeout is None else asyncio.get_running_loop().time() + timeout
        for ps in self._all_peer_states():
            if id not in ps.outbox.entries:
                continue
            while id in ps.outbox.entries:
                left = None if deadline is None else max(0.0, deadline - asyncio.get_running_loop().time())
                if left == 0.0:
                    raise asyncio.TimeoutError(f"no ack for {id} within {timeout}s")
                await asyncio.sleep(min(0.05, left) if left is not None else 0.05)
            return
        return  # not in any outbox: already acked (or never sent)

    async def next_event(self, timeout: float | None = None) -> ev.Event:
        """The next event, or asyncio.TimeoutError."""
        await self.start()
        assert self._queue is not None
        if timeout is None:
            return await self._queue.get()
        return await asyncio.wait_for(self._queue.get(), timeout)

    async def events(self) -> AsyncIterator[ev.Event]:
        """Every event from now on, in order, until the Peer is closed."""
        await self.start()
        assert self._queue is not None
        while not self._closed:
            yield await self._queue.get()

    def __repr__(self) -> str:
        return f"<awp.Peer {self.name} {self.key}>"


def _tunnel_key(key: str) -> bytes | None:
    try:
        return x25519_public(parse_key(key))
    except ValueError:
        return None


def _derive_subject(parts: list[dict[str, Any]]) -> str | None:
    for p in parts:
        if p.get("k") == "text" and isinstance(p.get("text"), str) and p["text"].strip():
            s = p["text"].strip().split("\n", 1)[0]
            return s if len(s) <= 80 else s[:77] + "..."
    for p in parts:
        if p.get("k") == "blob" and isinstance(p.get("name"), str):
            return p["name"]
    return None
