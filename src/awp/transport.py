"""Addresses and byte streams: tcp:HOST:PORT, unix:/path, and tailcat
addresses through the tailcat CLI."""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import stat

from ._log import log
from .wire import MAX_LINE, TAILCAT_PORT, StartupError

def looks_tailcat(s: str) -> bool:
    return len(s) >= 40 and s.startswith("tc") and all(c.isalnum() or c in "-_" for c in s)


def parse_addr(s: str):
    """tcp:HOST:PORT, unix:/path, tailcat:tc..., or a bare tailcat address."""
    s = s.strip()
    if s.startswith("tailcat:"):
        t = s[len("tailcat:"):].lstrip("/")
        if not looks_tailcat(t):
            raise StartupError(f"bad tailcat address {s!r}")
        return ("tailcat", t)
    if looks_tailcat(s):
        return ("tailcat", s)
    if s.startswith("tcp:"):
        host, sep, port = s[4:].lstrip("/").rpartition(":")
        if not sep or not port.isdigit():
            raise StartupError(f"bad tcp address {s!r}; expected tcp:HOST:PORT")
        return ("tcp", host.strip("[]"), int(port))
    if s.startswith("unix:"):
        path = s[5:]
        if path.startswith("//"):
            path = path[2:]
        if not path:
            raise StartupError(f"bad unix address {s!r}; expected unix:/path")
        return ("unix", path)
    if "/" in s:
        return ("unix", s)
    host, sep, port = s.rpartition(":")
    if sep and port.isdigit():
        return ("tcp", host.strip("[]"), int(port))
    raise StartupError(f"unrecognised address {s!r}; use tc..., tailcat:tc..., tcp:HOST:PORT or unix:/path")


def fmt_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def is_loopback(host: str) -> bool:
    return host in ("localhost", "::1") or host.startswith("127.")


async def open_stream(target, tailcat_bin: str = "tailcat"):
    """Open a byte stream to a parsed address: (reader, writer, process).
    The process is the tailcat client for tailcat addresses, else None."""
    if target[0] == "tcp":
        r, w = await asyncio.open_connection(target[1], target[2], limit=2 * MAX_LINE)
        return r, w, None
    if target[0] == "unix":
        r, w = await asyncio.open_unix_connection(target[1], limit=2 * MAX_LINE)
        return r, w, None
    binary = shutil.which(tailcat_bin)
    if binary is None:
        raise StartupError(f"{tailcat_bin} is not installed; tailcat addresses need the tailcat CLI "
                           "(https://github.com/tailscale/tailcat)")
    proc = await asyncio.create_subprocess_exec(
        binary, target[1], str(TAILCAT_PORT),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        limit=2 * MAX_LINE)
    assert proc.stdout is not None and proc.stdin is not None
    return proc.stdout, proc.stdin, proc


class TailcatListener:
    """`tailcat serve 1:127.0.0.1:PORT`: the tunnel's port 1, which awp peers
    dial, proxied to a local TCP listener."""

    def __init__(self, proc, address: str) -> None:
        self.proc = proc
        self.address = address

    @classmethod
    async def start(cls, tailcat_bin: str, port: int, timeout: float = 60.0) -> "TailcatListener":
        binary = shutil.which(tailcat_bin)
        if binary is None:
            raise StartupError(f"{tailcat_bin} is not installed; listening on tailcat needs the tailcat CLI "
                               "(https://github.com/tailscale/tailcat)")
        proc = await asyncio.create_subprocess_exec(
            binary, "serve", f"{TAILCAT_PORT}:127.0.0.1:{port}",
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        assert proc.stderr is not None

        async def find_address() -> str:
            while True:
                line = await proc.stderr.readline()
                if not line:
                    raise StartupError("tailcat exited before printing an address")
                text = line.decode("utf-8", "replace").strip()
                log(f"tailcat: {text}")
                for word in text.split():
                    if looks_tailcat(word):
                        return word

        try:
            address = await asyncio.wait_for(find_address(), timeout)
        except (asyncio.TimeoutError, StartupError):
            proc.kill()
            raise
        listener = cls(proc, address)
        asyncio.get_running_loop().create_task(listener._drain())
        return listener

    async def _drain(self) -> None:
        assert self.proc.stderr is not None
        while True:
            line = await self.proc.stderr.readline()
            if not line:
                return
            log(f"tailcat: {line.decode('utf-8', 'replace').rstrip()}")

    async def close(self) -> None:
        try:
            self.proc.kill()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(self.proc.wait(), 5)
        except asyncio.TimeoutError:
            pass


def make_tcp_listener(host: str, port: int) -> socket.socket:
    infos = socket.getaddrinfo(host or None, port, type=socket.SOCK_STREAM,
                               flags=socket.AI_PASSIVE)
    if not infos:
        raise StartupError(f"cannot resolve {host!r}")
    fam, typ, proto, _, sa = infos[0]
    s = socket.socket(fam, typ, proto)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(sa)
    except OSError as e:
        s.close()
        raise StartupError(f"cannot listen on tcp:{fmt_host(host)}:{port}: {e}") from None
    s.listen(128)
    s.setblocking(False)
    return s


def prepare_unix_path(path: str) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        return
    if not stat.S_ISSOCK(st.st_mode):
        raise StartupError(f"{path} exists and is not a socket")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(path)
    except OSError:
        os.unlink(path)                 # stale socket from a dead process
        return
    finally:
        probe.close()
    raise StartupError(f"{path}: another process is already listening there")


# ---------------------------------------------------------------- connection

