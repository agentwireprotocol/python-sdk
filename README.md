# Agent Wire Protocol: Python SDK

The Python SDK for the [Agent Wire Protocol](https://agentwireprotocol.com) (AWP), the peer-to-peer messaging protocol for coding agents. A `Peer` listens and connects, sends messages in threads, and delivers what arrives as events, with everything the protocol asks for inside: resume with an outbox on disk, acks, dedup by id, blobs in chunks, grants and introductions, ping/pong, reconnection with backoff.

Python 3.11 or later, asyncio, no required dependencies. Ed25519 uses the [`cryptography`](https://pypi.org/project/cryptography/) package when it is installed and a pure-Python implementation otherwise.

```sh
pip install awp            # or: pip install "awp[crypto]"
```

## A peer in a few lines

```python
import asyncio
import awp

async def main():
    async with awp.Peer("~/.mybot", name="mybot@builder") as peer:
        address = await peer.listen("tailcat")          # or "tcp:127.0.0.1:7000", "unix:/tmp/awp.sock"
        print("share this:", address)

        key = await peer.connect("tc...")               # an address shared out of band
        sent = peer.send(key, "Please run make test at a1b2c3.", subject="Run the suite")

        async for event in peer.events():
            match event:
                case awp.Message():
                    print(f"{event.peer}: {event.text}")
                case awp.State():
                    print(f"{event.peer} is {event.state} in {event.thread}")
                case awp.Blob():
                    print(f"file {event.name} at {event.path}")

asyncio.run(main())
```

## What a Peer does

- **`Peer(state_dir, name=...)`** loads or creates the Ed25519 identity under `state_dir`, along with the outbox, received ids, threads, grants and blobs. `None` uses a temporary directory with a fresh identity, removed on close. Use it as an async context manager, or call `await peer.start()` and `await peer.close()`.
- **`listen(addr)`** accepts connections on `tcp:HOST:PORT`, `unix:/path`, or `tailcat`: a WireGuard tunnel through the [tailcat CLI](https://github.com/tailscale/tailcat) with an address any peer can reach, through NAT, with no account. It returns the address to share.
- **`connect(addr)`** dials an address and returns the peer's key once the handshake is done. The Peer keeps dialing with exponential backoff, capped at a minute, whenever there are unacked messages or open threads with that peer. Sleeping sandboxes wake on connect.
- **`send(to, text, thread=None, subject=None, reply_to=None, parts=None, files=())`** queues a message. It never fails because the peer is away: the message is on disk and goes out on the next resume. Files travel as blobs in 256 KiB chunks ahead of the message. **`wait_ack(id)`** waits for the peer's ack; `Acked` events carry it too.
- **`set_state(to, thread, state, note=None)`** sets this side's state on a thread: `working`, `waiting`, `done`, `failed`, `closed`, or any word the two agents agree on.
- **`events()`** and **`next_event(timeout)`**: `Connected`, `Disconnected`, `Message`, `State`, `Acked`, `Blob`, `GrantReceived`, `Introduced`, `PeerError`, `Bye`, `Error`. Messages are stored and acked before they are reported.
- **`grant(to, caps, ttl)`**, **`caps(to)`**: capabilities beyond the defaults (`exec`, `fs:read`, `fs:write`, `introduce`, `admin`, or your own strings) as signed grants. Grants issued by this Peer and by keys in `trust=` are honored, plus one level of delegation through `introduce`. A request in a message (a data part of a `vnd.awp` type) arrives in `Message.requests`, marked allowed or not; denied ones are answered with `err forbidden` already.
- **`bye(to)`** closes gracefully and parks the peer. **`list_peers()`**, **`threads()`**, **`connected(to)`**: what the Peer knows.

## A peer driven over stdin and stdout

`python -m awp --state DIR listen tcp:127.0.0.1:7000` runs a peer that reads JSON commands on stdin and writes JSON events on stdout, for tests and for other languages. The [reference implementation's interop tests](https://github.com/agentwireprotocol/awp/tree/main/python) drive it.

## Conformance

`pytest` runs a two-peer conversation with states, a reply, a multi-chunk blob, grants and bye; queued delivery across a `kill -9`; and, when `AWP_BIN` points at an `awp` binary, the protocol's conformance suite ([`awp conform`](https://docs.agentwireprotocol.com/reference/conformance)) against a `Peer`, both with the Peer listening and with the Peer dialing. CI does all of it.

## Status

v0.1. The API may change before v1; the wire protocol is v0 and stable.

## License

Apache-2.0.
