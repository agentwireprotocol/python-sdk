"""One connection to a peer: the handshake, the reader, the FIFO writer and
the timers (SPEC.md sections 7 and 9)."""

from __future__ import annotations

import asyncio
import collections
import json
import traceback

from ._log import log, debug
from .wire import (ACKED_TYPES, AUTH_CONTEXT, BYE_TIMEOUT, CLOSING_ERR_CODES, HANDSHAKE_TIMEOUT,
                   MAX_LINE, PRE_AUTH_FORBIDDEN, PROTOCOL_VERSION, READ_SIZE, RESUME_TIMEOUT,
                   b64decode_any, b64url, dumps_line, parse_key)
from .wire import ed25519_verify

class Connection:
    """One transport connection: handshake, reader, FIFO writer, timers."""

    def __init__(self, node: "Node", reader, writer, label: str):
        self.node = node
        self.reader = reader
        self.writer = writer
        self.label = label
        self.loop = asyncio.get_running_loop()
        now = self.loop.time()
        self.started = now
        self.done = asyncio.Event()
        self.closing = False
        self.close_reason = None
        self.linger = False
        self.hello = node.make_hello()
        self.my_hello_line = dumps_line(self.hello)
        self.peer_hello_line = None
        self.peer_hello = None
        self.peer_key_raw = None
        self.peer_key_str = None
        self.established = False
        self.established_at = 0.0
        self.got_resume = False
        self.live = False
        self.ps = None
        self.queue = collections.deque()
        self.qevent = asyncio.Event()
        self.held = []
        self.bye_queued = False
        self.bye_sent = False
        self.bye_sent_at = 0.0
        self.last_inbound = now
        self.ping_id = None
        self.ping_at = 0.0
        self.missed = 0

    # -- lifecycle ---------------------------------------------------------

    async def run(self) -> bool:
        self.node.all_conns.add(self)
        tasks = []
        try:
            self._write(self.my_hello_line)
            tasks = [asyncio.create_task(self._read_loop()),
                     asyncio.create_task(self._pump()),
                     asyncio.create_task(self._timer())]
            await self.done.wait()
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self._shutdown()
            self.node.on_conn_closed(self)
        return self.established

    def close(self, reason: str) -> None:
        if self.closing:
            return
        self.closing = True
        self.close_reason = reason
        self.done.set()
        self.qevent.set()

    async def _shutdown(self) -> None:
        w = self.writer
        try:
            await asyncio.wait_for(w.drain(), 2.0)
        except Exception:
            pass
        if self.linger and not w.is_closing():
            # We sent a closing err: half-close and drain input briefly so the
            # kernel does not answer unread data with a RST that could destroy
            # the err line before the peer reads it.
            try:
                if w.can_write_eof():
                    w.write_eof()
                deadline = self.loop.time() + 1.0
                while True:
                    left = deadline - self.loop.time()
                    if left <= 0:
                        break
                    data = await asyncio.wait_for(self.reader.read(READ_SIZE), left)
                    if not data:
                        break
            except Exception:
                pass
        try:
            w.close()
            await asyncio.wait_for(w.wait_closed(), 2.0)
        except Exception:
            pass

    # -- writing -------------------------------------------------------------

    def _write(self, line: bytes) -> bool:
        if self.writer.is_closing():
            return False
        try:
            self.writer.write(line + b"\n")
            return True
        except Exception as e:
            self.close(f"write failed: {e}")
            return False

    def send_now(self, obj) -> bool:
        """Write a control message immediately (bypasses the FIFO)."""
        if self.bye_sent or self.closing:
            return False
        return self._write(dumps_line(obj))

    def send_err(self, code: str, detail: str, re=None, ref=None) -> None:
        log(f"{self.label}: sending err {code}: {detail}")
        self.send_now(self.node.make_err(code, detail, re=re, ref=ref))

    def fail(self, code: str, detail: str, re=None) -> None:
        """Send a closing err and close."""
        if self.closing:
            return
        if not self.bye_sent:
            self._write(dumps_line(self.node.make_err(code, detail, re=re)))
        self.node.emit_error(f"{self.label}: sent err {code}: {detail}")
        self.linger = True
        self.close(f"err {code}: {detail}")

    def queue_entry(self, eid: str) -> None:
        if self.live and not self.bye_queued and not self.closing:
            self.queue.append(("entry", eid))
            self.qevent.set()
        # otherwise the replay after the peer's resume picks it up

    def queue_once(self, oid: str) -> None:
        if self.live and not self.bye_queued and not self.closing:
            self.queue.append(("once", oid))
            self.qevent.set()

    def queue_ack(self, th: str, re_id: str) -> None:
        if self.bye_queued or self.closing:
            return
        item = ("line", dumps_line(self.node.envelope("ack", th=th, re=re_id)))
        if self.live:
            self.queue.append(item)
            self.qevent.set()
        else:
            self.held.append(item)      # see F2: never overtake our own replay

    def initiate_bye(self, reason: str):
        if self.bye_queued or self.bye_sent or self.closing:
            return None
        obj = self.node.envelope("bye", reason=reason)
        line = dumps_line(obj)
        self.bye_queued = True
        if self.live:
            self.queue.append(("bye", line))
            self.qevent.set()
        else:
            self._write(line)
            self.bye_sent = True
            self.bye_sent_at = self.loop.time()
        return obj["id"]

    def go_live(self, seen: dict) -> None:
        """Peer's resume arrived: replay, then flush held acks, then go FIFO."""
        if self.live or self.closing:
            return
        ps = self.ps
        self.node.apply_seen(ps, seen)
        replay = list(ps.outbox.entries.keys())
        for eid in replay:
            self.queue.append(("entry", eid))
        for oid in list(ps.sendonce.items.keys()):
            self.queue.append(("once", oid))
        self.queue.extend(self.held)
        self.held.clear()
        self.live = True
        if replay:
            log(f"{self.label}: replaying {len(replay)} outbox message(s)")
        self.qevent.set()

    async def _pump(self) -> None:
        try:
            while not self.closing:
                if not self.queue or self.bye_sent:
                    self.qevent.clear()
                    await self.qevent.wait()
                    continue
                kind, val = self.queue.popleft()
                if kind == "entry":
                    e = self.ps.outbox.entries.get(val)
                    if e is None:
                        continue                    # pruned while queued
                    try:
                        line = self.node.entry_line(e)
                    except (OSError, ValueError) as ex:
                        self.node.emit_error(f"cannot read outgoing blob data for {val}: {ex}; dropping it")
                        self.node.prune(self.ps, val, "unreadable")
                        continue
                elif kind == "once":
                    obj = self.ps.sendonce.items.get(val)
                    if obj is None:
                        continue
                    line = dumps_line(obj)
                else:
                    line = val
                if not self._write(line):
                    break
                if kind == "once":
                    self.ps.sendonce.remove(val)
                elif kind == "bye":
                    self.bye_sent = True
                    self.bye_sent_at = self.loop.time()
                    self.queue.clear()
                await self.writer.drain()
        except asyncio.CancelledError:
            raise
        except Exception as ex:
            self.close(f"write failed: {ex}")

    # -- timers --------------------------------------------------------------

    async def _timer(self) -> None:
        iv = self.node.ping_interval
        tick = 0.25 if iv <= 0 else max(0.02, min(0.5, iv / 5.0))
        while not self.closing:
            await asyncio.sleep(tick)
            if self.closing:
                return
            now = self.loop.time()
            if not self.established:
                if now - self.started > HANDSHAKE_TIMEOUT:
                    self.node.emit_error(f"{self.label}: handshake timed out")
                    self.close("handshake timeout")
                    return
                continue
            if not self.got_resume and now - self.established_at > RESUME_TIMEOUT:
                log(f"{self.label}: no resume from peer within {RESUME_TIMEOUT:.0f}s; replaying everything")
                self.got_resume = True
                self.go_live({})
            if self.bye_sent:
                if now - self.bye_sent_at >= BYE_TIMEOUT:
                    self.close("bye (peer did not answer within 5s)")
                    return
                continue
            if iv <= 0:
                continue
            if self.ping_id is None:
                if now - self.last_inbound >= iv:
                    self._send_ping(now)
            elif now - self.ping_at >= iv:
                self.missed += 1
                if self.missed >= 2:
                    self.close(f"dead connection: {self.missed} missed pongs")
                    return
                self._send_ping(now)

    def _send_ping(self, now: float) -> None:
        ping = self.node.envelope("ping")
        self.ping_id = ping["id"]
        self.ping_at = now
        self.send_now(ping)

    # -- reading -------------------------------------------------------------

    async def _read_loop(self) -> None:
        buf = bytearray()
        scan = 0
        try:
            while not self.closing:
                data = await self.reader.read(READ_SIZE)
                if not data:
                    self.close("connection closed by peer")
                    return
                buf += data
                while not self.closing:
                    i = buf.find(b"\n", scan)
                    if i < 0:
                        scan = len(buf)
                        if len(buf) > MAX_LINE:
                            self.fail("too_large", f"line exceeds {MAX_LINE} bytes")
                            return
                        break
                    line = bytes(buf[:i])
                    del buf[:i + 1]
                    scan = 0
                    if len(line) > MAX_LINE:
                        self.fail("too_large", f"line of {len(line)} bytes exceeds {MAX_LINE}")
                        return
                    self._handle_line(line)
        except asyncio.CancelledError:
            raise
        except (ConnectionError, OSError) as e:
            self.close(f"read failed: {e}")
        except Exception as e:
            log(f"{self.label}: internal error in reader: {e}\n{traceback.format_exc()}")
            self.close(f"internal error: {e}")

    def _handle_line(self, line: bytes) -> None:
        self.last_inbound = self.loop.time()
        self.ping_id = None
        self.missed = 0
        if not line.strip():
            return                                      # A3
        try:
            obj = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as e:
            self.fail("bad_frame", f"line is not valid UTF-8 JSON: {e}")
            return
        if not isinstance(obj, dict):
            self.fail("bad_frame", "line is not a JSON object")
            return
        t = obj.get("t")
        try:
            if not self.established:
                self._handshake(line, obj, t)
            else:
                self._dispatch(obj, t)
        except Exception as e:
            log(f"{self.label}: internal error handling {t!r}: {e}\n{traceback.format_exc()}")
            oid = obj.get("id")
            self.send_err("internal", f"internal error handling {t!r}: {e}",
                          re=oid if isinstance(oid, str) else None)

    # -- handshake -----------------------------------------------------------

    def _handshake(self, line: bytes, obj: dict, t) -> None:
        node = self.node
        oid = obj.get("id") if isinstance(obj.get("id"), str) else None
        if t == "hello":
            if self.peer_hello is not None:
                log(f"{self.label}: ignoring repeated hello")
                return
            node.emit_recv(self, obj)
            v = obj.get("v", 0)
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v != PROTOCOL_VERSION:
                self.fail("version", f"unsupported protocol version {v!r}; this peer speaks {PROTOCOL_VERSION}", re=oid)
                return
            try:
                raw = parse_key(obj.get("key"))
            except ValueError as e:
                self.fail("auth", f"invalid key in hello: {e}", re=oid)
                return
            if raw == node.identity.pub or line == self.my_hello_line:
                self.fail("auth", "hello carries our own key (reflected handshake)", re=oid)
                return
            self.peer_hello_line = line
            self.peer_hello = obj
            self.peer_key_raw = raw
            self.peer_key_str = obj.get("key")
            log(f"{self.label}: hello from {self.peer_key_str} name={obj.get('name')!r}")
            sig = node.identity.sign(AUTH_CONTEXT + b"\x00" + self.my_hello_line + b"\x00" + line)
            held = node.held.valid()
            auth = node.envelope("auth", sig=b64url(sig), grants=held if held else None)
            self._write(dumps_line(auth))
            return
        if t == "auth":
            if self.peer_hello is None:
                self.fail("auth", "auth received before hello", re=oid)
                return
            node.emit_recv(self, obj)
            try:
                sig = b64decode_any(obj.get("sig"))
            except ValueError:
                sig = b""
            transcript = AUTH_CONTEXT + b"\x00" + self.peer_hello_line + b"\x00" + self.my_hello_line
            if not ed25519_verify(self.peer_key_raw, sig, transcript):
                self.fail("auth", "auth signature does not verify", re=oid)
                return
            self._on_established(obj)
            return
        if t == "err":
            node.emit_recv(self, obj)
            code = obj.get("code")
            node.emit_error(f"{self.label}: peer sent err {code} during handshake: {obj.get('detail')}")
            if code in CLOSING_ERR_CODES:
                self.close(f"peer sent err {code}")
            return
        if t in ("ping", "pong"):
            return
        if t == "bye":
            node.emit_recv(self, obj)
            self.close("bye before handshake completed")
            return
        if t in PRE_AUTH_FORBIDDEN:
            self.fail("auth", f"{t!r} received before the handshake completed", re=oid)
            return
        node.emit_recv(self, obj)
        log(f"{self.label}: ignoring unknown message type {t!r} during handshake")

    def _on_established(self, auth: dict) -> None:
        node = self.node
        self.established = True
        self.established_at = self.loop.time()
        self.ps = node.bind_peer(self.peer_key_raw, self.peer_key_str, self.peer_hello)
        node.register_connection(self)
        grants = auth.get("grants")
        if isinstance(grants, list):
            for g in grants:
                node.receive_grant(self, g, "auth")
        h = self.peer_hello
        name = h.get("name") if isinstance(h.get("name"), str) else ""
        caps = h.get("caps") if isinstance(h.get("caps"), list) else []
        about = h.get("about") if isinstance(h.get("about"), str) else ""
        if "blob" not in caps:
            log(f"{self.label}: peer does not list the 'blob' capability")
        log(f"{self.label}: connected to {self.peer_key_str} ({name})")
        node.on_connected(self, name, caps, about)
        self.send_now(node.envelope("resume", seen=dict(self.ps.inbox.seen)))

    # -- established ---------------------------------------------------------

    def _dispatch(self, obj: dict, t) -> None:
        node = self.node
        ps = self.ps
        if t == "ping":
            pid = obj.get("id")
            self.send_now(node.envelope("pong", re=pid if isinstance(pid, str) else None))
            return
        if t == "pong":
            return
        if t in ACKED_TYPES:
            node.on_msg_or_state(self, obj, t)
            return
        if t == "chunk":
            node.on_chunk(self, obj)
            return
        node.emit_recv(self, obj)
        if t == "ack":
            rid = obj.get("re")
            if isinstance(rid, str):
                node.prune(ps, rid, "ack")
        elif t == "resume":
            if self.got_resume:
                log(f"{self.label}: ignoring repeated resume")
                return
            self.got_resume = True
            seen = obj.get("seen")
            clean = {}
            if isinstance(seen, dict):
                clean = {k: v for k, v in seen.items() if isinstance(k, str) and isinstance(v, str)}
            self.go_live(clean)
        elif t == "grant":
            node.receive_grant(self, obj.get("grant"), "grant message")
        elif t == "introduce":
            node.on_introduce(self, obj)
        elif t == "bye":
            self._on_bye(obj)
        elif t == "err":
            self._on_err(obj)
        elif t in ("hello", "auth"):
            log(f"{self.label}: ignoring {t} after the handshake")
        else:
            debug(f"{self.label}: ignoring unknown message type {t!r}")

    def _on_bye(self, obj: dict) -> None:
        self.node.on_bye_exchange(self)
        if not self.bye_sent:
            reason = obj.get("reason") if isinstance(obj.get("reason"), str) else "bye"
            self._write(dumps_line(self.node.envelope("bye", reason=reason)))
            self.bye_sent = True
            self.bye_sent_at = self.loop.time()
        self.close("bye")

    def _on_err(self, obj: dict) -> None:
        code = obj.get("code")
        detail = obj.get("detail")
        if code == "blob_refused":
            ref = obj.get("ref")
            if not isinstance(ref, str):
                ref = self.node.ref_for_entry(self.ps, obj.get("re"))
            if ref:
                self.node.stop_blob(self.ps, ref)
        if code in CLOSING_ERR_CODES:
            self.node.emit_error(f"{self.label}: peer sent err {code}: {detail}")
            self.close(f"peer sent err {code}: {detail}")
        else:
            log(f"{self.label}: peer sent err {code}: {detail}")


# ---------------------------------------------------------------- node

