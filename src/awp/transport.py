"""The tunnel: `awp tunnel`, the reference implementation's WireGuard
tunnel as a helper process (SPEC.md section 18.2).

Python has no WireGuard of its own, so a Peer runs one helper for its
whole life. The helper holds the Peer's key, listens on the carriers it is
asked to (tailcat, udp, ws, cloudflare, unix), opens streams to other peers
on request, and forwards the streams they open to a Unix socket of the
Peer's. Everything on those streams is the protocol from section 8 on,
which the Peer speaks itself."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from typing import Any, Awaitable, Callable

from ._log import log
from .wire import MAX_LINE, StartupError, b64decode_any

INSTALL_HINT = "install it with: curl -fsSL https://agentwireprotocol.com/install.sh | sh"


def find_awp(awp: str | None) -> str:
    """The awp binary: the one given, $AWP_BIN, or awp on PATH."""
    cand = awp or os.environ.get("AWP_BIN") or "awp"
    path = cand if os.path.sep in cand and os.access(cand, os.X_OK) else shutil.which(cand)
    if not path:
        raise StartupError(f"{cand} not found: the tunnel runs as `awp tunnel`; {INSTALL_HINT}")
    return path


class TunnelError(ConnectionError):
    """The helper could not do what was asked: dial, listen or rotate."""


class Tunnel:
    """One `awp tunnel` process."""

    def __init__(self, awp: str, identity_file: str, state_dir: str) -> None:
        self.awp = awp
        self.identity_file = identity_file
        self.state_dir = state_dir
        self.address: str | None = None      # with the pre-shared key: the one to share
        self.public: str | None = None       # without: for hello.addr
        self.proc: asyncio.subprocess.Process | None = None
        self._dir: str | None = None
        self._server: asyncio.base_events.Server | None = None
        self._events: asyncio.Task[None] | None = None
        self._stderr: asyncio.Task[None] | None = None
        self.on_address: Callable[[], None] | None = None

    async def start(self, accept: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]) -> None:
        # Socket paths are limited to about 100 bytes: keep them short.
        self._dir = tempfile.mkdtemp(prefix="awp-", dir="/tmp" if os.path.isdir("/tmp") else None)
        ctl = os.path.join(self._dir, "ctl.sock")
        fwd = os.path.join(self._dir, "in.sock")
        self.ctl = ctl
        self._server = await asyncio.start_unix_server(accept, path=fwd, limit=2 * MAX_LINE)
        os.makedirs(self.state_dir, exist_ok=True)
        self.proc = await asyncio.create_subprocess_exec(
            self.awp, "tunnel", "--identity", self.identity_file, "--state", self.state_dir,
            "--socket", ctl, "--forward", fwd,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        assert self.proc.stdout is not None
        try:
            line = await asyncio.wait_for(self.proc.stdout.readline(), 30)
        except asyncio.TimeoutError:
            await self.close()
            raise StartupError("awp tunnel did not start within 30s") from None
        if not line:
            err = b""
            if self.proc.stderr is not None:
                err = await self.proc.stderr.read()
            await self.close()
            raise StartupError(f"awp tunnel exited: {err.decode('utf-8', 'replace').strip() or 'no output'}")
        self._apply(json.loads(line))
        self._events = asyncio.get_running_loop().create_task(self._read_events())
        self._stderr = asyncio.get_running_loop().create_task(self._drain_stderr())

    def _apply(self, ev: dict[str, Any]) -> None:
        if ev.get("address"):
            self.address, self.public = ev["address"], ev.get("public")
            if self.on_address is not None:
                self.on_address()

    async def _read_events(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        while True:
            line = await self.proc.stdout.readline()
            if not line:
                return
            try:
                self._apply(json.loads(line))
            except ValueError:
                pass

    async def _drain_stderr(self) -> None:
        assert self.proc is not None and self.proc.stderr is not None
        while True:
            line = await self.proc.stderr.readline()
            if not line:
                return
            log(f"awp tunnel: {line.decode('utf-8', 'replace').rstrip()}")

    async def _request(self, req: dict[str, Any], timeout: float | None):
        r, w = await asyncio.open_unix_connection(self.ctl, limit=2 * MAX_LINE)
        try:
            w.write(json.dumps(req).encode() + b"\n")
            await w.drain()
            line = await asyncio.wait_for(r.readline(), timeout)
        except BaseException:
            w.close()
            raise
        if not line:
            w.close()
            raise TunnelError("awp tunnel closed the request")
        rep = json.loads(line)
        if not rep.get("ok"):
            w.close()
            raise TunnelError(rep.get("error") or "awp tunnel refused the request")
        return rep, r, w

    async def dial(self, addresses: list[str], key: str | None = None, timeout: float | None = 60.0):
        """A stream to the peer the addresses (all of one key) describe:
        (reader, writer, reply), reply carrying "key" and "remote"."""
        req: dict[str, Any] = {"dial": addresses}
        if key:
            req["key"] = key
        rep, r, w = await self._request(req, timeout)
        return r, w, rep

    async def listen(self, carrier: str) -> str:
        rep, _, w = await self._request({"listen": carrier}, 120)
        w.close()
        self._apply(rep)
        return rep["address"]

    async def rotate(self) -> str | None:
        rep, _, w = await self._request({"rotate": True}, 30)
        w.close()
        self._apply(rep)
        return rep.get("address")

    async def close(self) -> None:
        if self.proc is not None and self.proc.returncode is None:
            try:
                assert self.proc.stdin is not None
                self.proc.stdin.close()             # the helper exits when stdin closes
                await asyncio.wait_for(self.proc.wait(), 5)
            except (asyncio.TimeoutError, OSError, AssertionError):
                try:
                    self.proc.kill()
                except ProcessLookupError:
                    pass
        for t in (self._events, self._stderr):
            if t is not None:
                t.cancel()
        if self._server is not None:
            self._server.close()
        if self._dir:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir = None


def remote_from_preamble(line: bytes) -> bytes | None:
    """The peer's tunnel key from the helper's first line on a forwarded
    stream: {"tunnel": {"remote": "..."}}."""
    try:
        obj = json.loads(line)
        return b64decode_any(obj["tunnel"]["remote"])
    except (ValueError, KeyError, TypeError):
        return None
