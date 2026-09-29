"""What a Peer reports: one dataclass per kind of event. Get them from
``Peer.events()`` or ``Peer.next_event()``."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Event:
    """The base of every event. ``peer`` is the key of the peer it is about."""

    peer: str


@dataclass(frozen=True)
class Connected(Event):
    """A handshake with the peer completed."""

    name: str
    caps: list[str]
    about: str
    outbound: bool


@dataclass(frozen=True)
class Disconnected(Event):
    """The connection to the peer ended. The Peer reconnects with backoff
    while there is unfinished business with it."""

    reason: str


@dataclass(frozen=True)
class Message(Event):
    """A msg from the peer, durably stored and acked before it is reported."""

    id: str
    thread: str
    parts: list[dict[str, Any]]
    subject: str | None = None
    reply_to: str | None = None
    #: Capability requests found in the data parts (exec, fs:read, fs:write,
    #: admin), each with ``allowed`` from the sender's grants. A denied one
    #: was answered with err forbidden already.
    requests: list[Request] = field(default_factory=list)

    @property
    def text(self) -> str:
        """The text parts, joined."""
        return "\n".join(p.get("text", "") for p in self.parts if p.get("k") == "text")


@dataclass(frozen=True)
class Request:
    part: int
    mime: str
    cap: str
    allowed: bool


@dataclass(frozen=True)
class State(Event):
    """The peer set its state on a thread."""

    id: str
    thread: str
    state: str
    note: str | None = None


@dataclass(frozen=True)
class Acked(Event):
    """The peer acked a msg or state of ours: it is durably delivered."""

    id: str


@dataclass(frozen=True)
class Blob(Event):
    """A file the peer sent arrived in full, at ``path``."""

    ref: str
    path: str
    size: int
    sha256: str
    thread: str | None = None
    name: str | None = None
    mime: str | None = None


@dataclass(frozen=True)
class GrantReceived(Event):
    """The peer gave us a grant, now held and presented to its issuer on
    every connection."""

    issuer: str
    caps: list[str]
    expires: str
    grant: dict[str, Any]


@dataclass(frozen=True)
class Introduced(Event):
    """The peer handed us another peer's key and address, and a grant that
    peer honors if it trusts the introducer. Connect to ``address`` to meet it."""

    key: str
    name: str | None
    address: str | None
    thread: str | None
    grant: dict[str, Any] | None


@dataclass(frozen=True)
class PeerError(Event):
    """The peer sent an err line. ``code`` is one of the spec's codes."""

    code: str
    detail: str | None = None
    reply_to: str | None = None
    ref: str | None = None


@dataclass(frozen=True)
class Bye(Event):
    """The peer closed gracefully. It is parked: no reconnection until
    something new is queued for it."""

    reason: str | None = None


@dataclass(frozen=True)
class Error(Event):
    """Something went wrong locally: a blob could not be read, a handshake
    timed out. ``peer`` is "" when no peer is involved."""

    detail: str
