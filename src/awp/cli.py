"""A peer driven over stdin and stdout, for tests and other languages.

::

    python -m awp --state DIR [--name NAME] listen tcp:127.0.0.1:7000
    python -m awp --state DIR [--name NAME] connect tc...

One JSON command per line on stdin, one JSON event per line on stdout:

    {"cmd":"send","th":"t1","subject":"optional","text":"hello","re":"optional id"}
        extension: "parts":[...] appends raw parts (code/data) after the text part
    {"cmd":"state","th":"t1","state":"working","note":"optional"}
    {"cmd":"blob","th":"t1","path":"/some/file","text":"optional"}   the file as chunks, then a msg
    {"cmd":"grant","sub":"ed25519:...","caps":["exec"],"ttl":3600}
    {"cmd":"bye","reason":"done"}
    {"cmd":"quit"}
    any command may add "peer":"ed25519:..." to pick the peer; the default is the last one connected

Events: identity, listening, connected, recv, blob, sent, acked, disconnected, error.
Logs go to stderr. Closing stdin does not stop the peer.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import threading
from dataclasses import asdict
from typing import Any

from . import events as ev
from .peer import Peer
from .wire import DEFAULT_BLOB_LIMIT, DEFAULT_GRANT_TTL, DEFAULT_PING_INTERVAL, AwpError, CommandError


def emit(d: dict[str, Any]) -> None:
    try:
        s = json.dumps(d, ensure_ascii=False, separators=(",", ":"))
    except ValueError:
        s = json.dumps(d, ensure_ascii=True, separators=(",", ":"), default=str)
    try:
        sys.stdout.write(s + "\n")
        sys.stdout.flush()
    except (BrokenPipeError, OSError, ValueError):
        pass


def to_dict(e: ev.Event) -> dict[str, Any] | None:
    if isinstance(e, ev.Connected):
        return {"event": "connected", "key": e.peer, "name": e.name, "caps": e.caps, "about": e.about}
    if isinstance(e, ev.Disconnected):
        return {"event": "disconnected", "reason": e.reason, "key": e.peer}
    if isinstance(e, ev.Acked):
        return {"event": "acked", "id": e.id}
    if isinstance(e, ev.Blob):
        return {"event": "blob", "ref": e.ref, "path": e.path, "size": e.size, "sha256": e.sha256}
    if isinstance(e, ev.Error):
        return {"event": "error", "detail": e.detail}
    if isinstance(e, ev.Introduced):
        return {"event": "introduced", **asdict(e)}
    return None  # messages, states, errs and byes are reported as raw "recv" lines


class Driver:
    def __init__(self, peer: Peer) -> None:
        self.peer = peer
        peer.raw_hook = lambda obj: emit({"event": "recv", "msg": obj})

    def target(self, c: dict[str, Any]) -> str | None:
        """The peer a command names, else None: the default peer, or the
        pending queue before any peer connected."""
        pk = c.get("peer")
        return pk if isinstance(pk, str) and pk else None

    def command(self, c: dict[str, Any]) -> None:
        cmd = c.get("cmd")
        if cmd == "send":
            parts = c.get("parts")
            text = c.get("text")
            s = self.peer.send(self.target(c), text if isinstance(text, str) or text is None else json.dumps(text),
                               thread=c.get("th"), subject=c.get("subject") or None, reply_to=c.get("re") or None,
                               parts=parts if isinstance(parts, list) else None)
            emit({"event": "sent", "id": s.id, "t": "msg", "th": s.thread})
        elif cmd == "state":
            s = self.peer.set_state(self.target(c), str(c.get("th")), str(c.get("state")), c.get("note") or None)
            emit({"event": "sent", "id": s.id, "t": "state"})
        elif cmd == "blob":
            text = c.get("text")
            s = self.peer.send(self.target(c), text if isinstance(text, str) or text is None else json.dumps(text),
                               thread=c.get("th"), subject=c.get("subject") or None, reply_to=c.get("re") or None,
                               files=[str(c.get("path"))])
            emit({"event": "sent", "id": s.id, "t": "msg", "th": s.thread})
        elif cmd == "grant":
            sub = c.get("sub") or self.target(c)
            if sub is None:
                fp = self.peer.default_fp
                ps = self.peer.peers.get(fp) if fp else None
                if ps is None or ps.key_raw is None:
                    raise CommandError("grant: 'sub' is required when no peer is known yet")
                from .wire import format_key
                sub = ps.key_str or format_key(ps.key_raw)
            ttl = c.get("ttl", DEFAULT_GRANT_TTL)
            if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
                raise CommandError("grant: ttl must be a number of seconds")
            self.peer.grant(sub, c.get("caps") or [], float(ttl))
            emit({"event": "sent", "t": "grant"})
        elif cmd == "bye":
            asyncio.create_task(self._bye(c))
        elif cmd == "quit":
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(0)
        else:
            raise CommandError(f"unknown command {cmd!r}")

    async def _bye(self, c: dict[str, Any]) -> None:
        reason = c.get("reason") or "done"
        targets = [c["peer"]] if isinstance(c.get("peer"), str) else [p.key for p in self.peer.list_peers() if p.connected]
        if not targets:
            emit({"event": "error", "detail": "bye: not connected"})
        for t in targets:
            try:
                emit({"event": "sent", "t": "bye"})
                await self.peer.bye(t, reason)
            except ConnectionError as e:
                emit({"event": "error", "detail": f"bye: {e}"})

    def line(self, raw: bytes) -> None:
        s = raw.strip()
        if not s:
            return
        try:
            c = json.loads(s.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as e:
            emit({"event": "error", "detail": f"bad command line (not JSON): {e}"})
            return
        if not isinstance(c, dict):
            emit({"event": "error", "detail": "bad command line: not a JSON object"})
            return
        try:
            self.command(c)
        except AwpError as e:
            emit({"event": "error", "detail": str(e)})
        except Exception as e:  # noqa: BLE001
            emit({"event": "error", "detail": f"command {c.get('cmd')!r} failed: {e}"})


def start_stdin_thread(loop: asyncio.AbstractEventLoop, driver: Driver) -> None:
    def reader() -> None:
        try:
            stream = sys.stdin.buffer if sys.stdin is not None else None
            if stream is not None:
                for raw in iter(stream.readline, b""):
                    loop.call_soon_threadsafe(driver.line, raw)
        except Exception:  # noqa: BLE001
            pass
        logging.getLogger("awp").info("stdin closed; running until killed")

    threading.Thread(target=reader, name="awp-stdin", daemon=True).start()


async def amain(args: argparse.Namespace) -> int:
    try:
        peer = Peer(args.state, name=args.name, about=args.about, trust=args.trust or (),
                    ping_interval=args.ping_interval, blob_limit=args.max_blob)
    except AwpError as e:
        emit({"event": "error", "detail": str(e)})
        return 1
    driver = Driver(peer)
    async with peer:
        emit({"event": "identity", "key": peer.key, "name": peer.name})
        start_stdin_thread(asyncio.get_running_loop(), driver)
        try:
            if args.mode == "listen":
                shown = await peer.listen(args.addr)
                emit({"event": "listening", "addr": shown, "key": peer.key})
            else:
                asyncio.get_running_loop().create_task(_connect_forever(peer, args.addr))
        except AwpError as e:
            emit({"event": "error", "detail": str(e)})
            return 1
        async for e in peer.events():
            d = to_dict(e)
            if d is not None:
                emit(d)

    return 0


async def _connect_forever(peer: Peer, addr: str) -> None:
    try:
        await peer.connect(addr, timeout=None)
    except Exception as e:  # noqa: BLE001
        emit({"event": "error", "detail": f"connect {addr}: {e}"})


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m awp",
                                 description="A peer for the Agent Wire Protocol, driven over stdin and stdout.")
    ap.add_argument("--state", default=os.path.join(os.path.expanduser("~"), ".awp-py"),
                    help="state directory (identity, outbox, seen map, blobs)")
    ap.add_argument("--name", default=None, help="name to announce in hello")
    ap.add_argument("--ping-interval", type=float, default=DEFAULT_PING_INTERVAL,
                    help="seconds of inbound silence before pinging (0 disables; default 30)")
    ap.add_argument("--max-blob", type=int, default=DEFAULT_BLOB_LIMIT,
                    help="largest blob accepted, in bytes (default 50 MiB)")
    ap.add_argument("--trust", action="append", default=[], help="trust grants issued by this key (repeatable)")
    ap.add_argument("--about", default=None, help="free text for hello.about")
    ap.add_argument("-v", "--verbose", action="store_true", help="debug logging on stderr")
    sub = ap.add_subparsers(dest="mode", required=True, metavar="{listen,connect}")
    for mode in ("listen", "connect"):
        sp = sub.add_parser(mode, help=f"{mode} on ADDR (tcp:HOST:PORT, unix:/path, or tailcat)")
        sp.add_argument("addr")
    args = ap.parse_args(argv)
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [awp] %(message)s", datefmt="%H:%M:%S")
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass
    try:
        return asyncio.run(amain(args))
    except KeyboardInterrupt:
        return 130
