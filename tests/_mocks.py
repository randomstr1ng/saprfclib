# tests/_mocks.py
#
# Sans-I/O test doubles for the saprfclib transport seam (TRANS-08).
#
# MockTransport implements the same send_message/recv_message seam as the real
# socket Transport (src/saprfclib/transport.py) over a scripted byte queue, so the
# upper layers (Session/Connection/metadata, plans 03-02/03-03/03-04) test with
# zero network. send_message records every sent payload; recv_message pops a
# preset response FIFO and raises EOFError once the script is exhausted.
#
# AsyncMockTransport is the async counterpart for Phase 9 (09-01): it implements
# the async send_message/recv_message seam using coroutines over the same
# scripted byte queue design, enabling offline async tests without real sockets.

__all__ = ["MockTransport", "AsyncMockTransport"]


class MockTransport:
    """Non-socket Transport seam double driven by a scripted response queue.

    Construct with a list of server-response payloads (bytes). recv_message pops
    them FIFO; send_message appends to the public `sent` list. When the response
    script is exhausted, recv_message raises EOFError — mirroring a peer that has
    closed the stream. close() is a no-op that flips `closed` to True.
    """

    def __init__(self, responses: "list[bytes] | None" = None) -> None:
        self.sent: list[bytes] = []
        self._responses: list[bytes] = list(responses) if responses else []
        self.closed: bool = False

    def send_message(self, payload: bytes) -> None:
        """Record one sent payload (no framing — the seam is payload-level)."""
        self.sent.append(bytes(payload))

    def recv_message(self) -> bytes:
        """Pop the next scripted response; raise EOFError when exhausted."""
        if not self._responses:
            raise EOFError("mock transport script exhausted")
        return self._responses.pop(0)

    def close(self) -> None:
        """No-op close; marks the transport as closed."""
        self.closed = True


class AsyncMockTransport:
    """Async transport seam double driven by a scripted response queue (Phase 9).

    Mirrors MockTransport but with async send_message/recv_message coroutines,
    enabling offline async tests without real asyncio sockets. Designed for use
    with AsyncConnection, AsyncConnectionPool, and AsyncRfcServer test scaffolds.

    Construct with a list of server-response payloads (bytes). recv_message pops
    them FIFO; send_message appends to the public ``sent`` list. When the response
    script is exhausted, recv_message raises ``EOFError`` — mirroring a peer that
    has closed the stream. close() is a coroutine that sets ``closed`` to True.
    """

    def __init__(self, responses: "list[bytes] | None" = None) -> None:
        self.sent: list[bytes] = []
        self._responses: list[bytes] = list(responses) if responses else []
        self.closed: bool = False

    async def send_message(self, payload: bytes) -> None:
        """Record one sent payload (no framing — the seam is payload-level)."""
        self.sent.append(bytes(payload))

    async def recv_message(self) -> bytes:
        """Pop the next scripted response; raise EOFError when exhausted."""
        if not self._responses:
            raise EOFError("async mock transport script exhausted")
        return self._responses.pop(0)

    async def close(self) -> None:
        """Coroutine close; marks the transport as closed."""
        self.closed = True
