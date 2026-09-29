"""The Peer API: a conversation between two peers, delivery across a
restart, and the protocol's conformance suite when an awp binary is at
hand (AWP_BIN)."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

import awp

async def next_of(peer: awp.Peer, kind: type, timeout: float = 15.0):
    """The next event of a kind, skipping others."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        left = deadline - loop.time()
        if left <= 0:
            raise AssertionError(f"no {kind.__name__} within {timeout}s")
        e = await peer.next_event(left)
        if isinstance(e, kind):
            return e


@pytest.fixture
def tmp():
    d = tempfile.mkdtemp(prefix="awp-test-")
    yield d
    shutil.rmtree(d, ignore_errors=True)


async def test_conversation(tmp):
    async with awp.Peer(os.path.join(tmp, "a"), name="a@test", ping_interval=2) as a, \
            awp.Peer(os.path.join(tmp, "b"), name="b@test", ping_interval=2) as b:
        addr = await b.listen("unix:" + os.path.join(tmp, "b.sock"))
        assert b.address == addr and addr.startswith("awp1")
        key = await a.connect(addr, timeout=10)
        assert key == b.key
        c = await next_of(b, awp.Connected)
        assert c.peer == a.key and c.name == "a@test" and not c.outbound
        c = await next_of(a, awp.Connected)
        assert c.peer == b.key and c.outbound

        sent = a.send(key, "Please run make test.", subject="Run the suite",
                      parts=[{"k": "data", "mime": "application/json", "data": {"repo": "x"}}])
        assert sent.new_thread and sent.thread.startswith("thr_")
        m = await next_of(b, awp.Message)
        assert (m.peer, m.thread, m.subject, m.text) == (a.key, sent.thread, "Run the suite", "Please run make test.")
        assert m.parts[1]["data"] == {"repo": "x"} and not m.requests
        assert (await next_of(a, awp.Acked)).id == sent.id
        await a.wait_ack(sent.id, timeout=5)

        b.set_state(a.key, m.thread, "working", "running")
        s = await next_of(a, awp.State)
        assert (s.thread, s.state, s.note) == (m.thread, "working", "running")
        reply = b.send(a.key, "3 of 42 failing", thread=m.thread, reply_to=m.id)
        r = await next_of(a, awp.Message)
        assert (r.id, r.reply_to, r.text, r.subject) == (reply.id, m.id, "3 of 42 failing", None)
        th = [t for t in a.threads(key) if t.id == m.thread][0]
        assert (th.subject, th.their_state, th.closed) == ("Run the suite", "working", False)

        # A file goes as a blob, in several chunks, and arrives byte for byte.
        path = os.path.join(tmp, "log.txt")
        data = b"integration output\n" * 30000
        with open(path, "wb") as f:
            f.write(data)
        a.send(key, "log attached", thread=m.thread, files=[path])
        blob = await next_of(b, awp.Blob)
        assert (blob.name, blob.size, blob.thread, blob.mime) == ("log.txt", len(data), m.thread, "text/plain")
        with open(blob.path, "rb") as f:
            assert f.read() == data

        # A grant from a to b; b holds it, a honors it.
        g = a.grant(key, ["fs:read"], 3600)
        assert awp.verify_grant(g)[0]
        gr = await next_of(b, awp.GrantReceived)
        assert (gr.issuer, gr.caps) == (a.key, ["fs:read"])
        assert a.caps(key) == {"fs:read"}
        # A request b is not allowed to make is refused with err forbidden.
        b.send(a.key, thread=m.thread, parts=[{"k": "data", "mime": "application/vnd.awp.exec+json", "data": {"cmd": ["ls"]}}])
        req = await next_of(a, awp.Message)
        assert req.requests and req.requests[0].cap == "exec" and not req.requests[0].allowed
        err = await next_of(b, awp.PeerError)
        assert err.code == "forbidden" and err.reply_to == req.id

        peers = a.list_peers()
        assert len(peers) == 1 and peers[0].key == b.key and peers[0].connected and peers[0].name == "b@test"

        await b.bye(a.key, "done")
        assert (await next_of(a, awp.Bye)).reason == "done"
        await next_of(a, awp.Disconnected)
        assert not a.connected(key)


async def test_queued_while_away_and_restart(tmp):
    """Messages queued while the peer is down arrive after it is back, and
    a message queued before a restart survives it."""
    b_dir = os.path.join(tmp, "b")
    b_sock = "unix:" + os.path.join(tmp, "b.sock")
    async with awp.Peer(os.path.join(tmp, "a"), name="a@test", ping_interval=1) as a:
        b = await awp.Peer(b_dir, name="b@test").start()
        b_addr = await b.listen(b_sock)
        key = await a.connect(b_addr, timeout=10)
        await next_of(a, awp.Connected)
        await b.close()
        await next_of(a, awp.Disconnected)

        sent = [a.send(key, f"message {i}", thread="t1", subject="queued") for i in range(20)]
        assert not a.connected(key)

        b = await awp.Peer(b_dir, name="b@test").start()
        await b.listen(b_sock)
        try:
            got = [await next_of(b, awp.Message, 30) for _ in range(20)]
            assert [m.text for m in got] == [f"message {i}" for i in range(20)]
            assert [m.id for m in got] == [s.id for s in sent]
            for s in sent:
                await a.wait_ack(s.id, timeout=10)
        finally:
            await b.close()

    # a restarts with a message queued: it goes out when b is reachable.
    async with awp.Peer(os.path.join(tmp, "a"), name="a@test", ping_interval=1) as a:
        sent = a.send(key, "after the restart", thread="t1")
        b = await awp.Peer(b_dir, name="b@test").start()
        await b.listen(b_sock)
        try:
            await a.connect(b_addr, timeout=10)
            m = await next_of(b, awp.Message, 30)
            assert m.id == sent.id and m.text == "after the restart"
        finally:
            await b.close()


async def test_ephemeral_peer():
    p = awp.Peer(name="tmp@test")
    d = p.state_dir
    await p.start()
    assert p.key.startswith("ed25519:") and os.path.isdir(d)
    await p.close()
    assert not os.path.exists(d)


def awp_bin() -> str | None:
    b = os.environ.get("AWP_BIN") or shutil.which("awp")
    if not b:
        return None
    out = subprocess.run([b, "tunnel", "--help"], capture_output=True, text=True)
    return b if "identity" in out.stderr + out.stdout else None


# Every test needs `awp tunnel`: it is the transport.
pytestmark = [pytest.mark.asyncio,
              pytest.mark.skipif(awp_bin() is None, reason="needs an awp binary with `awp tunnel` (set AWP_BIN)")]



async def test_conformance_peer_listening(tmp):
    async with awp.Peer(os.path.join(tmp, "p"), name="py@test") as p:
        addr = await p.listen("udp:127.0.0.1:0")
        proc = await asyncio.create_subprocess_exec(awp_bin(), "conform", "--json", "--timeout", "10s", addr,
                                                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), 120)
        rep = json.loads(out)
        failed = [r for r in rep["results"] if r["status"] != "pass"]
        assert not failed, json.dumps(failed, indent=1)
        assert rep["passed"] == len(rep["results"])


async def test_conformance_peer_dialing(tmp):
    cmd = f"{sys.executable} -m awp --state {os.path.join(tmp, 'p')} --name py@test connect {{addr}}"
    env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"), AWP_BIN=awp_bin())
    proc = await asyncio.create_subprocess_exec(awp_bin(), "conform", "--json", "--timeout", "10s",
                                                "--listen", "udp:127.0.0.1:0", "--run", cmd,
                                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
    out, err = await asyncio.wait_for(proc.communicate(), 120)
    rep = json.loads(out)
    failed = [r for r in rep["results"] if r["status"] == "fail"]
    assert not failed, json.dumps(failed, indent=1)
    assert rep["passed"] >= 10


async def test_revoke_and_introduce(tmp):
    """a revokes a grant it issued; a introduces c to b with a grant bound to c."""
    async with awp.Peer(os.path.join(tmp, "a"), name="a@test", ping_interval=2) as a, \
            awp.Peer(os.path.join(tmp, "b"), name="b@test", ping_interval=2) as b, \
            awp.Peer(os.path.join(tmp, "c"), name="c@test", ping_interval=2, trust=[]) as c:
        b_addr = await b.listen("unix:" + os.path.join(tmp, "b.sock"))
        c_addr = await c.listen("unix:" + os.path.join(tmp, "c.sock"))
        await a.connect(b_addr, timeout=10)
        await a.connect(c_addr, timeout=10)
        await next_of(b, awp.Connected)
        await next_of(c, awp.Connected)

        g = a.grant(b.key, ["fs:read"], 3600)
        await next_of(b, awp.GrantReceived)
        issued, _ = a.grants()
        assert [x["sig"] for x in issued] == [g["sig"]] and "hash" in issued[0]
        assert a.caps(b.key) == {"fs:read"}
        assert a.revoke(issued[0]["hash"]) and not a.revoke(issued[0]["hash"])
        assert a.caps(b.key) == set() and a.grants()[0] == []

        sent = a.introduce(b.key, c.key, ["fs:read"], 3600)
        assert sent.to == b.key
        intro = await next_of(b, awp.Introduced)
        assert (intro.peer, intro.key, intro.address) == (a.key, c.key, c_addr)
        assert intro.grant and intro.grant["aud"] == c.key and intro.grant["sub"] == b.key
        # The grant is bound to c: a itself does not honor it for b.
        assert a.caps(b.key) == set()
        # b meets c through the address it was handed.
        assert await b.connect(intro.address, timeout=10) == c.key
        await next_of(c, awp.Connected)


async def test_rotation_and_presented_grants(tmp):
    """c trusts a with introduce; a introduces b to c with a grant bound to
    c, which b presents in its hello and c honors. Rotating c's pre-shared
    key keeps peers it met, and shuts out strangers with the old address."""
    async with awp.Peer(os.path.join(tmp, "a"), name="a@test") as a, \
            awp.Peer(os.path.join(tmp, "b"), name="b@test") as b, \
            awp.Peer(os.path.join(tmp, "c"), name="c@test", trust=[]) as c:
        c_addr = await c.listen("udp:127.0.0.1:0")
        c.trusted.add(awp.wire.parse_key(a.key))
        b_addr = await b.listen("unix:" + os.path.join(tmp, "b.sock"))
        await a.connect(b_addr, timeout=15)
        await a.connect(c_addr, timeout=15)
        await next_of(b, awp.Connected)
        a.introduce(b.key, c.key, ["fs:read"], 3600)
        intro = await next_of(b, awp.Introduced)
        assert intro.address == c_addr and intro.grant["aud"] == c.key
        assert await b.connect(intro.address, timeout=15) == c.key
        conn = await next_of(c, awp.Connected)
        while conn.peer != b.key:
            conn = await next_of(c, awp.Connected)
        assert c.caps(b.key) == {"fs:read"}          # presented in b's hello, honored by c

        new_addr = await c.rotate_psk()
        assert new_addr and new_addr != c_addr
        async with awp.Peer(name="stranger@test") as d:
            with pytest.raises(ConnectionError):
                await d.connect(c_addr, timeout=6)
            assert await d.connect(new_addr, timeout=15) == c.key
        await b.bye(c.key)
        await next_of(b, awp.Disconnected)
        assert await b.connect(intro.address, timeout=15) == c.key   # met before: still admitted
