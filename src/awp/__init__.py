"""The Python SDK for the Agent Wire Protocol (AWP).

::

    import awp

    async with awp.Peer("~/.mybot", name="mybot@host") as peer:
        address = await peer.listen("tailcat")
        key = await peer.connect("awp1...")
        peer.send(key, "Please run make test.", subject="Run the suite")
        async for event in peer.events():
            if isinstance(event, awp.Message):
                print(event.peer, event.text)
"""

from .events import (Acked, Blob, Bye, Connected, Disconnected, Error, Event, GrantReceived,
                     Introduced, Message, PeerError, Request, State)
from .peer import Peer, PeerInfo, Sent, Thread
from .wire import (AwpError, CommandError, StartupError, PROTOCOL_VERSION, mint_grant,
                   verify_grant)

__version__ = "0.2.0"

__all__ = [
    "Peer", "PeerInfo", "Sent", "Thread",
    "Event", "Connected", "Disconnected", "Message", "State", "Acked", "Blob", "GrantReceived",
    "Introduced", "PeerError", "Bye", "Error", "Request",
    "AwpError", "CommandError", "StartupError", "PROTOCOL_VERSION", "mint_grant", "verify_grant",
    "__version__",
]
