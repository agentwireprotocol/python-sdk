"""Durable state on disk: the identity, and per peer an append-only outbox
log of unacked messages, an inbox log of received ids and blob progress,
the threads, grants and one-shot messages. Everything survives kill -9."""

from __future__ import annotations

import json
import os
import time

from ._ed25519 import ed25519_public, ed25519_sign
from ._log import log
from .wire import (FSYNC, SEEN_TYPES, b64decode_any, b64url, format_key, now_ts, parse_key,
                   parse_rfc3339, safe_name, StartupError)

PENDING = "_pending"


class Identity:
    def __init__(self, seed: bytes):
        self.seed = seed
        self.pub = ed25519_public(seed)
        self.key = format_key(self.pub)

    def sign(self, msg: bytes) -> bytes:
        return ed25519_sign(self.seed, msg)

    @classmethod
    def load_or_create(cls, path: str) -> "Identity":
        for _ in range(3):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    rec = json.load(f)
                seed = b64decode_any(rec["seed"])
                if len(seed) != 32:
                    raise ValueError("seed must be 32 bytes")
                return cls(seed)
            except FileNotFoundError:
                pass
            except (ValueError, KeyError, TypeError) as e:
                raise StartupError(f"identity file {path} is unreadable: {e}") from None
            seed = os.urandom(32)
            ident = cls(seed)
            rec = {"alg": "ed25519", "seed": b64url(seed), "key": ident.key, "created": now_ts()}
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                time.sleep(0.05)
                continue
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(rec, f)
                f.flush()
                os.fsync(f.fileno())
            return ident
        raise StartupError(f"could not create identity at {path}")


# ---------------------------------------------------------------- grants


def load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except (ValueError, OSError) as e:
        log(f"warning: cannot read {path}: {e}; starting from empty")
        return default


def atomic_write_json(path: str, obj, durable: bool = False) -> None:
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=True, separators=(",", ":"))
        f.flush()
        if durable and FSYNC:
            os.fsync(f.fileno())
    os.replace(tmp, path)


def read_jsonl(path: str) -> list:
    """Read an append-only JSONL log, dropping a torn final record."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return []
    end = data.rfind(b"\n") + 1
    if end < len(data):
        log(f"warning: {path} ends with a partial record (killed mid-write?); truncating it")
        with open(path, "r+b") as f:
            f.truncate(end)
    out = []
    for ln in data[:end].split(b"\n"):
        if not ln.strip():
            continue
        try:
            rec = json.loads(ln)
        except ValueError:
            log(f"warning: skipping a corrupt record in {path}")
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _rec_bytes(rec) -> bytes:
    return json.dumps(rec, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"


class AppendLog:
    def __init__(self, path: str):
        self.path = path
        self.f = open(path, "ab")

    def append(self, recs, durable: bool = True, raw: bytes = None) -> None:
        if isinstance(recs, dict):
            recs = [recs]
        self.f.write(raw if raw is not None else b"".join(_rec_bytes(r) for r in recs))
        self.f.flush()
        if durable and FSYNC:
            os.fsync(self.f.fileno())

    def close(self) -> None:
        try:
            self.f.close()
        except OSError:
            pass


class Outbox:
    """Unacked outbound msg/state/chunk entries, in original send order.

    entry = {"obj": wire object (chunks without "data")}
            + {"src": file in outgoing/, "off": int, "len": int} for chunks
    """

    def __init__(self, path: str, outgoing_dir: str):
        self.path = path
        self.outgoing_dir = outgoing_dir
        self.entries: dict = {}
        self.by_ref: dict = {}
        self.src_count: dict = {}
        self.max_id = None
        self.dels = 0
        for rec in read_jsonl(path):
            op = rec.get("op")
            if op == "add":
                e = rec.get("e")
                if self._valid(e) and e["obj"]["id"] not in self.entries:
                    self._mem_add(e)
            elif op == "del":
                if self._mem_del(rec.get("id")) is not None:
                    self.dels += 1
            elif op == "mark":
                self._note_id(rec.get("id"))
        self.log = AppendLog(path)
        if self.dels:
            self.compact()

    @staticmethod
    def _valid(e) -> bool:
        return (isinstance(e, dict) and isinstance(e.get("obj"), dict)
                and isinstance(e["obj"].get("id"), str) and isinstance(e["obj"].get("t"), str))

    def _note_id(self, i) -> None:
        if isinstance(i, str) and (self.max_id is None or i > self.max_id):
            self.max_id = i

    def _mem_add(self, e) -> None:
        obj = e["obj"]
        eid = obj["id"]
        self.entries[eid] = e
        self._note_id(eid)
        if obj["t"] == "chunk":
            self.by_ref.setdefault(obj.get("ref"), set()).add(eid)
            src = e.get("src")
            if src:
                self.src_count[src] = self.src_count.get(src, 0) + 1

    def _mem_del(self, eid):
        e = self.entries.pop(eid, None) if isinstance(eid, str) else None
        if e is None:
            return None
        obj = e["obj"]
        if obj["t"] == "chunk":
            ids = self.by_ref.get(obj.get("ref"))
            if ids is not None:
                ids.discard(eid)
                if not ids:
                    del self.by_ref[obj.get("ref")]
            src = e.get("src")
            if src:
                n = self.src_count.get(src, 0) - 1
                if n <= 0:
                    self.src_count.pop(src, None)
                else:
                    self.src_count[src] = n
        return e

    def add_many(self, entries) -> list:
        fresh = [e for e in entries if e["obj"]["id"] not in self.entries]
        if fresh:
            self.log.append([{"op": "add", "e": e} for e in fresh], durable=True)
            for e in fresh:
                self._mem_add(e)
        return fresh

    def remove(self, eid, delete_files: bool = True):
        e = self._mem_del(eid)
        if e is None:
            return None
        self.log.append({"op": "del", "id": eid}, durable=False)
        self.dels += 1
        src = e.get("src")
        if delete_files and src and src not in self.src_count:
            try:
                os.remove(os.path.join(self.outgoing_dir, src))
            except OSError:
                pass
        if self.dels > 512 and self.dels > 4 * len(self.entries):
            self.compact()
        return e

    def compact(self) -> None:
        tmp = self.path + ".compact"
        with open(tmp, "wb") as f:
            if self.max_id:
                f.write(_rec_bytes({"op": "mark", "id": self.max_id}))
            for e in self.entries.values():
                f.write(_rec_bytes({"op": "add", "e": e}))
            f.flush()
            if FSYNC:
                os.fsync(f.fileno())
        self.log.close()
        os.replace(tmp, self.path)
        self.log = AppendLog(self.path)
        self.dels = 0

    def reset(self) -> None:
        """Forget everything (after another outbox adopted our entries)."""
        self.entries.clear()
        self.by_ref.clear()
        self.src_count.clear()
        self.compact()


class Inbox:
    """What we have durably received from one peer: dedup set, per-thread seen,
    blob progress.  Everything is rebuilt from an append-only log at startup."""

    def __init__(self, path: str, blob_dir: str):
        self.path = path
        self.blob_dir = blob_dir
        self.partial_dir = os.path.join(blob_dir, ".partial")
        self.dedup: set = set()
        self.seen: dict = {}
        self.partial: dict = {}     # ref -> {"next": n, "size": bytes, "last": bool}
        self.done: dict = {}
        self.refused: set = set()
        self.declared: dict = {}    # ref -> size from a blob part (memory only)
        self.to_finish: list = []
        for rec in read_jsonl(path):
            self._apply(rec)
        self.log = AppendLog(path)
        self._reconcile()

    def partial_path(self, ref: str) -> str:
        return os.path.join(self.partial_dir, safe_name(ref))

    def final_path(self, ref: str) -> str:
        return os.path.join(self.blob_dir, safe_name(ref))

    def _apply(self, rec) -> None:
        op = rec.get("op")
        ref = rec.get("ref")
        if op == "blob_done":
            self.done[ref] = rec
            self.partial.pop(ref, None)
            return
        if op == "blob_refused":
            self.refused.add(ref)
            self.partial.pop(ref, None)
            return
        mid, t, th = rec.get("id"), rec.get("t"), rec.get("th")
        if isinstance(mid, str):
            self.dedup.add(mid)
            if isinstance(th, str) and t in SEEN_TYPES:
                self.seen[th] = mid
        if t == "chunk" and rec.get("stored"):
            st = self.partial.get(ref)
            if st is None:
                st = self.partial[ref] = {"next": 0, "size": 0, "last": False}
            st["next"] = int(rec.get("n", 0)) + 1
            st["size"] += int(rec.get("len", 0))
            st["last"] = bool(rec.get("last"))

    def record(self, rec, durable: bool = True, raw: bytes = None) -> None:
        self.log.append(rec, durable=durable, raw=raw)
        self._apply(rec)

    def _reconcile(self) -> None:
        for ref, st in list(self.partial.items()):
            p, final = self.partial_path(ref), self.final_path(ref)
            if not os.path.exists(p):
                if st["last"] and os.path.exists(final) and os.path.getsize(final) == st["size"]:
                    self.to_finish.append(ref)          # renamed but not yet logged
                else:
                    log(f"warning: data for partial blob {ref!r} is missing; it cannot complete")
                    del self.partial[ref]
                continue
            size = os.path.getsize(p)
            if size > st["size"]:
                with open(p, "r+b") as f:               # data written, record not: roll back
                    f.truncate(st["size"])
            elif size < st["size"]:
                log(f"warning: partial blob {ref!r} is shorter than its log; discarding it")
                del self.partial[ref]
                os.remove(p)
                continue
            if st["last"]:
                self.to_finish.append(ref)


class Threads:
    def __init__(self, path: str):
        self.path = path
        data = load_json(path, {})
        self.data = data if isinstance(data, dict) else {}

    def touch(self, th: str, obj: dict, outgoing: bool) -> None:
        rec = self.data.get(th)
        changed = False
        if not isinstance(rec, dict):
            rec = self.data[th] = {"closed": False}
            subj = obj.get("subject")
            if isinstance(subj, str):
                rec["subject"] = subj
            changed = True
        closed = False
        if obj.get("t") == "state":
            st = obj.get("state")
            closed = st == "closed"
            side = "mine" if outgoing else "theirs"
            if rec.get(side) != st:
                rec[side] = st
                changed = True
        if rec.get("closed") != closed:
            rec["closed"] = closed
            changed = True
        if changed:
            self.save()

    def any_open(self) -> bool:
        return any(isinstance(r, dict) and not r.get("closed") for r in self.data.values())

    def merge(self, other: "Threads") -> None:
        for th, rec in other.data.items():
            if th not in self.data:
                self.data[th] = rec
        self.save()

    def clear(self) -> None:
        self.data = {}
        self.save()

    def save(self) -> None:
        atomic_write_json(self.path, self.data)


class SendOnce:
    """Messages that are neither thread messages nor acked (grant): sent once."""

    def __init__(self, path: str):
        self.path = path
        lst = load_json(path, [])
        self.items = {o["id"]: o for o in lst if isinstance(o, dict) and isinstance(o.get("id"), str)} \
            if isinstance(lst, list) else {}

    def add(self, obj) -> None:
        self.items[obj["id"]] = obj
        self.save()

    def remove(self, oid) -> None:
        if self.items.pop(oid, None) is not None:
            self.save()

    def clear(self) -> None:
        self.items = {}
        self.save()

    def save(self) -> None:
        atomic_write_json(self.path, list(self.items.values()), durable=True)


class GrantList:
    def __init__(self, path: str):
        self.path = path
        lst = load_json(path, [])
        self.items = [g for g in lst if isinstance(g, dict)] if isinstance(lst, list) else []
        self.prune()

    def prune(self) -> None:
        keep = []
        for g in self.items:
            try:
                if parse_rfc3339(g.get("exp")) > time.time():
                    keep.append(g)
            except ValueError:
                pass
        if len(keep) != len(self.items):
            self.items = keep
            self.save()

    def add(self, g) -> None:
        if any(x.get("sig") == g.get("sig") for x in self.items):
            return
        self.items.append(g)
        self.save()

    def valid(self) -> list:
        self.prune()
        return list(self.items)

    def save(self) -> None:
        atomic_write_json(self.path, self.items)




class PeerState:
    """All durable state we keep about one remote key (or the pending queue)."""

    def __init__(self, node: "Node", fp: str, key_raw=None, key_str=None):
        self.node = node
        self.fp = fp
        self.dir = os.path.join(node.state_dir, "peers", fp)
        os.makedirs(self.dir, exist_ok=True)
        self.meta_path = os.path.join(self.dir, "peer.json")
        meta = load_json(self.meta_path, {})
        self.meta = meta if isinstance(meta, dict) else {}
        if key_raw is None and fp != PENDING:
            try:
                key_raw = parse_key(self.meta.get("key"))
                key_str = self.meta.get("key_as_sent") or self.meta.get("key")
            except ValueError:
                key_raw = None
        self.key_raw = key_raw
        self.key_str = key_str
        self.outbox = Outbox(os.path.join(self.dir, "outbox.log"), node.outgoing_dir)
        self.inbox = Inbox(os.path.join(self.dir, "inbox.log"),
                           os.path.join(node.state_dir, "blobs", fp))
        self.threads = Threads(os.path.join(self.dir, "threads.json"))
        self.sendonce = SendOnce(os.path.join(self.dir, "sendonce.json"))
        self.grants = GrantList(os.path.join(self.dir, "grants.json"))
        if key_raw is not None and not self.meta.get("key"):
            self.save_meta(key_str or format_key(key_raw), None)

    def save_meta(self, key_str: str, hello) -> None:
        self.key_str = key_str
        self.meta.update({"key": format_key(self.key_raw), "key_as_sent": key_str})
        if isinstance(hello, dict):
            for k in ("name", "about", "caps"):
                if k in hello:
                    self.meta[k] = hello[k]
            self.meta["last_connected"] = now_ts()
        atomic_write_json(self.meta_path, self.meta)

    def has_queued(self) -> bool:
        return bool(self.outbox.entries or self.sendonce.items or self.threads.data)

    def has_work(self) -> bool:
        return bool(self.outbox.entries or self.sendonce.items) or self.threads.any_open()

    def adopt(self, other: "PeerState") -> None:
        if not other.has_queued():
            return
        log(f"peer {self.key_str}: adopting {len(other.outbox.entries)} message(s) queued "
            "before any peer had connected")
        self.outbox.add_many(list(other.outbox.entries.values()))
        for obj in list(other.sendonce.items.values()):
            self.sendonce.add(obj)
        self.threads.merge(other.threads)
        other.outbox.reset()
        other.sendonce.clear()
        other.threads.clear()


# ---------------------------------------------------------------- addresses

