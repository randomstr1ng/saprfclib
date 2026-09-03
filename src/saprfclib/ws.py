# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — WebSocket RFC (wRFC) transport
#
# WsTransport implements the existing Transport duck-type seam
# (send_message/recv_message/close, TRANS-08 / D-17) over a WebSocket carried on
# TLS, so Connection is transparent to wRFC — no change to connection.py or any
# layer above transport. This is the D-16 connection sequence:
#
#     TCP connect  →  (optional HTTP CONNECT proxy tunnel, D-20)
#                  →  TLS handshake (stdlib ssl, verify ON by default)
#                  →  RFC 6455 upgrade (Sec-WebSocket-Accept validated)
#                  →  RFC payloads as masked binary frames (opcode 2)
#                  →  periodic ping/pong keepalive (D-18)
#
# The only bytes this module owns are the CONNECT request line and the
# Sec-WebSocket-Accept check; RFC 6455 framing / masking / control-frame
# interleaving is delegated to wsproto and TLS to stdlib ssl (no hand-rolled
# crypto, no hand-rolled frame codec — RESEARCH "Don't Hand-Roll").
#
# Security invariants (threat register 07-P04):
#   - T-07-TLS-VERIFY: ssl.create_default_context() (CERT_REQUIRED + hostname
#     check) with a TLSv1.2 floor and SNI; verify=False only via explicit opt-in
#     with a loud warnings.warn (ASVS V9).
#   - T-07-PROXY-CRED: ws_proxy_pass and the Proxy-Authorization value never
#     appear in logs or in any raised WebSocketError — failures report the HTTP
#     status code only.
#   - T-07-FRAME-DOS: recv_message caps the reassembled message at 128 MiB
#     (parity with transport.py _MAX_FRAME_BYTES) before growing the accumulator.
#   - T-07-WS-MASK: wsproto masks client→server frames (RFC 6455 §5.3); we never
#     hand-roll frame bytes.
from __future__ import annotations

import base64
import hashlib
import logging
import socket
import ssl
import threading
import warnings

from wsproto import ConnectionType, WSConnection
from wsproto.connection import Connection
from wsproto.events import (
    BytesMessage,
    CloseConnection,
    Ping,
    Pong,
    Request,
)

from saprfclib.exceptions import CommunicationError, WebSocketError
from saprfclib.transport import DEFAULT_READ_TIMEOUT

__all__ = ["WsTransport", "connect_ws"]

# RFC 6455 §1.3 magic GUID: Sec-WebSocket-Accept = base64(SHA1(key + GUID)).
_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# 128 MiB DoS cap (threat T-07-FRAME-DOS / T-03-DOS parity): reject a reassembled
# WebSocket message that grows past this before allocating further.
_MAX_FRAME_BYTES = 128 * 1024 * 1024

# Default wRFC endpoint path (D-19).  SAP ICM requires sap-apc-stateful=true
# query parameter to activate the stateful WebSocket RFC handler.
_DEFAULT_WS_PATH = "/sap/bc/rfc?sap-apc-stateful=true"


# --------------------------------------------------------------------------- #
# D-16 step 2: HTTP CONNECT proxy tunnel                                       #
# --------------------------------------------------------------------------- #
def _read_http_head(sock: socket.socket) -> bytes:
    """Read raw bytes from ``sock`` until the end of the HTTP head (blank line).

    Returns everything up to and including the terminating ``\\r\\n\\r\\n``.
    Raises :class:`WebSocketError` if the peer closes before the head completes.
    """
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise WebSocketError("connection closed before HTTP response completed")
        buf.extend(chunk)
        if len(buf) > _MAX_FRAME_BYTES:  # defensive: a runaway header stream
            raise WebSocketError("HTTP response head exceeded size cap")
    return bytes(buf)


def _status_code(head: bytes) -> int:
    """Parse the numeric status code from an HTTP status line (e.g. 200, 407)."""
    try:
        status_line = head.split(b"\r\n", 1)[0]
        return int(status_line.split(b" ", 2)[1])
    except (IndexError, ValueError) as exc:  # malformed status line
        raise WebSocketError("malformed HTTP status line in response") from exc


def _open_proxy_tunnel(
    sock: socket.socket,
    target_host: str,
    target_port: int,
    *,
    user: str | None = None,
    password: str | None = None,
) -> None:
    """Open an HTTP CONNECT tunnel through a forward proxy (D-16 step 2 / D-20).

    Sends ``CONNECT {target_host}:{target_port}`` with an optional
    ``Proxy-Authorization: Basic base64(user:pass)`` header (RFC 7617). A 2xx
    status opens the tunnel; anything else raises :class:`WebSocketError`.

    Security (T-07-PROXY-CRED): the credentials are used only to build the Basic
    token; they are NEVER echoed into the raised exception. On failure the
    exception reports the HTTP status code only.
    """
    lines = [
        f"CONNECT {target_host}:{target_port} HTTP/1.1",
        f"Host: {target_host}:{target_port}",
    ]
    if user is not None:
        # RFC 7617: base64 of the UTF-8 "user:password" octets.
        token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
        lines.append(f"Proxy-Authorization: Basic {token}")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    sock.sendall(request)

    head = _read_http_head(sock)
    code = _status_code(head)
    if not (200 <= code < 300):
        # NEVER include the credentials or the Proxy-Authorization value here.
        raise WebSocketError(f"HTTP CONNECT proxy refused the tunnel (status {code})")


# --------------------------------------------------------------------------- #
_logger = logging.getLogger(__name__)


# D-16 step 3: verifying TLS context                                           #
# --------------------------------------------------------------------------- #
def _make_ssl_context(
    *,
    ca_bundle: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    verify: bool = True,
) -> ssl.SSLContext:
    """Build a client TLS context for the wRFC leg (D-16 step 3, threat T-07-TLS-VERIFY).

    Defaults to ``ssl.create_default_context()`` (CERT_REQUIRED + hostname check)
    with a TLSv1.2 floor. Optional ``ca_bundle`` adds a corporate/BTP CA and
    ``client_cert``/``client_key`` enable mTLS (X.509-over-TLS).

    ``verify=False`` disables certificate and hostname verification — an insecure
    opt-in that emits a loud :func:`warnings.warn` (ASVS V9). It must never be the
    default.
    """
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_bundle:
        ctx.load_verify_locations(cafile=ca_bundle)
    if client_cert:
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
    if not verify:
        _message = (
            "saprfclib wRFC: TLS certificate verification is DISABLED (verify=False). "
            "The server identity is NOT authenticated; this is insecure and must "
            "only be used for local testing."
        )
        warnings.warn(_message, stacklevel=2)
        # Logged as well as warned, because the two channels fail differently. A
        # warning is shown once per call site and disappears entirely under
        # `python -W ignore` or a broad filterwarnings() -- both of which a
        # long-running service is likely to have set for unrelated reasons. The
        # log record survives that, so the one process where this matters most
        # still leaves a trace that its RFC traffic was unauthenticated.
        _logger.warning("%s", _message)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Lower OpenSSL security level so on-premise servers with weak RSA keys
        # (e.g. 1024-bit EE certs) don't fail at the TLS handshake layer even
        # with CERT_NONE — the user explicitly opted in via ws_tls_verify=False.
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


# --------------------------------------------------------------------------- #
# D-16 steps 4-5: RFC 6455 upgrade                                             #
# --------------------------------------------------------------------------- #
def _expected_accept(key: bytes) -> str:
    """Compute Sec-WebSocket-Accept = base64(SHA1(key + RFC 6455 GUID))."""
    # fmt: off
    return base64.b64encode(hashlib.sha1(key + _GUID).digest()).decode("ascii")  # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    # fmt: on


def _parse_headers(head: bytes) -> dict[str, str]:
    """Parse HTTP head bytes into a lowercased-key header dict (last value wins)."""
    headers: dict[str, str] = {}
    for raw in head.split(b"\r\n")[1:]:
        if not raw or b":" not in raw:
            continue
        name, _, value = raw.partition(b":")
        headers[name.strip().lower().decode("latin-1")] = value.strip().decode("latin-1")
    return headers


def _split_head_and_rest(sock: socket.socket) -> tuple[bytes, bytes]:
    """Read one HTTP response head; return (head_including_blank_line, leftover_body_bytes).

    Any bytes already read past the ``\\r\\n\\r\\n`` terminator (e.g. an early
    WebSocket frame glued to the 101 response) are returned as ``leftover`` so the
    frame layer does not lose them.
    """
    buf = bytearray()
    while True:
        idx = buf.find(b"\r\n\r\n")
        if idx != -1:
            end = idx + 4
            return bytes(buf[:end]), bytes(buf[end:])
        chunk = sock.recv(4096)
        if not chunk:
            raise WebSocketError("connection closed before WebSocket upgrade completed")
        buf.extend(chunk)
        if len(buf) > _MAX_FRAME_BYTES:
            raise WebSocketError("WebSocket upgrade response head exceeded size cap")


def _parse_location(location: str, default_host: str, default_path: str) -> tuple[str, str]:
    """Split a redirect Location into (host, path), tolerating ws(s):// or bare paths."""
    loc = location.strip()
    for scheme in ("wss://", "ws://", "https://", "http://"):
        if loc.lower().startswith(scheme):
            rest = loc[len(scheme) :]
            authority, slash, path = rest.partition("/")
            host = authority.split(":", 1)[0] or default_host
            return host, ("/" + path if slash else default_path)
    # Bare path redirect (same host).
    return default_host, (loc if loc.startswith("/") else default_path)


def _extract_sec_key(request_bytes: bytes) -> bytes:
    """Recover the Sec-WebSocket-Key wsproto put on the wire (to validate accept)."""
    for line in request_bytes.split(b"\r\n"):
        if line.lower().startswith(b"sec-websocket-key:"):
            return line.split(b":", 1)[1].strip()
    raise WebSocketError("internal: generated upgrade request lacks Sec-WebSocket-Key")


def _build_upgrade_request(
    host: str,
    port: int,
    ws_path: str,
    *,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> tuple[bytes, bytes]:
    """Build a client RFC 6455 upgrade GET; return (request_bytes, sec_key).

    We let wsproto generate the GET (RFC-correct key/headers), then recover the
    Sec-WebSocket-Key it placed on the wire so we can validate the server's
    Sec-WebSocket-Accept against it. (Injecting our own key would collide with
    wsproto's, so we read wsproto's key back out instead.)

    The SAP-required WebSocket subprotocol (Sec-WebSocket-Protocol: rfc.sap.com)
    is negotiated via wsproto's subprotocols parameter so it appears in the
    standard RFC 6455 position (verified: WebsocketDriver::rfcWSProtocolHeader
    = "Sec-WebSocket-Protocol", rfcWSProtocolValue = "rfc.sap.com").
    """
    client = WSConnection(ConnectionType.CLIENT)
    request_bytes = client.send(
        Request(
            host=f"{host}:{port}",
            target=ws_path,
            subprotocols=["rfc.sap.com"],
            extra_headers=extra_headers or [],
        )
    )
    return request_bytes, _extract_sec_key(request_bytes)


def _ws_upgrade(
    tls_sock: socket.socket,
    *,
    host: str,
    port: int,
    ws_path: str,
    user: str | None = None,
    passwd: str | None = None,
    sap_client: str | None = None,
    lang: str = "EN",
) -> bytes | None:
    """Perform the RFC 6455 upgrade over ``tls_sock`` (D-16 steps 4-5).

    Sends the GET Upgrade, validates the 101 status and ``Sec-WebSocket-Accept``,
    and follows a single 302/301 redirect (D-21). A second redirect, a non-101
    non-3xx status, or a wrong accept raises :class:`WebSocketError`.

    Returns any bytes already read past the 101 response so the caller can seed
    the frame layer's inbound buffer (returns ``b""`` when there are none).

    Security (T-07-CRED): ``passwd`` is used only to build the Basic auth token
    and is NEVER logged or embedded in a raised exception.
    """
    # SAP ICM headers required to activate the wRFC ICM handler (verified from
    # WebsocketDriver::addProprietaryHeaderFields in the reference client):
    #   rfcWSProtocolHeader/Value → Sec-WebSocket-Protocol: rfc.sap.com  (via subprotocols)
    #   rfcOptionsHeader/rfcOptionsDeltaOff → sap-rfc-options: rfc-delta=off
    #   sap-client, sap-language, sap-rfc-subtype: sync (always sent)
    extra_headers: list[tuple[bytes, bytes]] = [
        (b"sap-rfc-options", b"rfc-delta=off"),
        (b"sap-rfc-subtype", b"sync"),
        (b"sap-session-priority", b"high"),
        (b"sap-language", lang.upper().encode("ascii")),
    ]
    if sap_client is not None:
        extra_headers.append((b"sap-client", sap_client.encode("ascii")))
    if user is not None:
        # T-07-CRED: passwd never logged or embedded in exceptions.
        token = base64.b64encode(f"{user}:{passwd}".encode("latin-1")).decode("ascii")
        extra_headers.append((b"authorization", f"Basic {token}".encode("ascii")))

    current_host, current_path = host, ws_path
    redirected = False

    while True:
        # wsproto's Request always emits its own random Sec-WebSocket-Key too, but
        # we inject and track our own so we can validate the accept deterministically.
        # Build the GET manually via wsproto and recover our key.
        request_bytes, key = _build_upgrade_request(
            current_host, port, current_path, extra_headers=extra_headers
        )
        tls_sock.sendall(request_bytes)

        head, leftover = _split_head_and_rest(tls_sock)
        code = _status_code(head)

        if code == 101:
            headers = _parse_headers(head)
            accept = headers.get("sec-websocket-accept")
            if accept != _expected_accept(key):
                raise WebSocketError("WebSocket upgrade failed: bad Sec-WebSocket-Accept")
            return leftover

        if code in (301, 302, 307, 308):
            if redirected:
                raise WebSocketError("WebSocket upgrade failed: more than one redirect (D-21)")
            headers = _parse_headers(head)
            location = headers.get("location")
            if not location:
                raise WebSocketError(
                    f"WebSocket upgrade redirect (status {code}) missing Location header"
                )
            current_host, current_path = _parse_location(location, current_host, current_path)
            redirected = True
            continue

        raise WebSocketError(f"WebSocket upgrade failed with HTTP status {code}")


# --------------------------------------------------------------------------- #
# WsTransport + connect_ws — implemented in Task 2                             #
# --------------------------------------------------------------------------- #
class WsTransport:
    """WebSocket RFC transport implementing the Transport duck-type seam (D-17).

    Mirrors :class:`saprfclib.transport.Transport` (send_message / recv_message /
    close) so :class:`~saprfclib.connection.Connection` is transparent to wRFC. RFC
    payloads travel as masked binary frames (opcode 2); wsproto owns the framing,
    masking, fragmentation reassembly, and control-frame interleaving. No subclass
    of ``Transport`` (duck-type only, matching ``MockTransport``).

    An optional daemon ping thread (``ws_ping_interval`` > 0) sends idle
    keepalive pings (D-18); incoming pings are auto-ponged inline in
    :meth:`recv_message` (Pitfall 5) so the data-path recv is never starved.
    """

    def __init__(
        self,
        tls_sock: socket.socket,
        ws_conn: WSConnection | Connection,
        *,
        ws_ping_interval: float = 60.0,
        leftover: bytes = b"",
    ) -> None:
        self._sock = tls_sock
        self._ws = ws_conn
        # Per-instance cap (mirrors transport.py); tests may shrink it to trip the
        # DoS guard without allocating 128 MiB.
        self._MAX_FRAME_BYTES = _MAX_FRAME_BYTES
        self._send_lock = threading.Lock()
        self._stopped = False
        self._closed = False
        self._thread: threading.Thread | None = None

        # Seed the inbound decoder with any bytes read past the 101 response.
        if leftover:
            self._ws.receive_data(leftover)

        if ws_ping_interval and ws_ping_interval > 0:
            self._thread = threading.Thread(
                target=self._ping_loop,
                args=(ws_ping_interval,),
                name="saprfclib-ws-ping",
                daemon=True,
            )
            self._thread.start()

    # -- background keepalive (D-18) ------------------------------------------
    def _ping_loop(self, interval: float) -> None:  # pragma: no cover - timing thread
        """Emit an idle keepalive Ping every ``interval`` seconds until stopped.

        wsproto generates the frame bytes; we hold the send lock so a ping never
        interleaves with a partial application frame. The server auto-pongs; the
        pong is drained (and ignored) by :meth:`recv_message`.
        """
        while not self._stopped:
            # Wake up promptly on close() by polling the flag in small steps.
            waited = 0.0
            step = min(0.1, interval)
            while waited < interval:
                if self._stopped:
                    return
                threading.Event().wait(step)
                waited += step
            if self._stopped:
                return
            try:
                with self._send_lock:
                    if self._stopped:
                        return
                    self._sock.sendall(self._ws.send(Ping()))
            except OSError:
                return  # socket closed underneath us — exit quietly

    # -- Transport seam -------------------------------------------------------
    def send_message(self, payload: bytes) -> None:
        """Send ``payload`` as one masked binary WebSocket frame (opcode 2).

        wsproto masks client→server frames automatically (RFC 6455 §5.3 /
        T-07-WS-MASK) — we never hand-roll frame bytes. Transport/socket errors
        are wrapped as :class:`CommunicationError`; wsproto protocol errors as
        :class:`WebSocketError`.
        """
        try:
            data = self._ws.send(BytesMessage(data=payload))
        except Exception as exc:  # noqa: BLE001 - wsproto protocol/state error
            raise WebSocketError(f"WebSocket send failed: {type(exc).__name__}") from exc
        try:
            with self._send_lock:
                self._sock.sendall(data)
        except (OSError, EOFError) as exc:
            raise CommunicationError(
                "WebSocket transport send failed", original_exception=exc
            ) from exc

    def recv_message(self) -> bytes:
        """Receive and reassemble one full binary WebSocket message.

        Loops reading socket bytes and draining wsproto events: incoming Ping is
        answered inline with the wsproto-generated Pong (Pitfall 5); Pong is
        ignored (idle-keepalive reply); BytesMessage fragments accumulate until
        ``message_finished``. The accumulator is checked against the 128 MiB DoS
        cap BEFORE it grows (threat T-07-FRAME-DOS) — a ValueError is raised past
        the cap. A CloseConnection raises :class:`WebSocketError`.
        """
        # wsproto types BytesMessage.data as bytes | bytearray; accept both rather
        # than copying every chunk through bytes() just to satisfy the annotation.
        chunks: list[bytes | bytearray] = []
        size = 0
        while True:
            for event in self._ws.events():
                if isinstance(event, BytesMessage):
                    incoming = len(event.data)
                    if size + incoming > self._MAX_FRAME_BYTES:
                        raise ValueError(
                            f"WebSocket message exceeds cap {self._MAX_FRAME_BYTES} (DoS guard)"
                        )
                    chunks.append(event.data)
                    size += incoming
                    if event.message_finished:
                        return b"".join(chunks)
                elif isinstance(event, Ping):
                    # Auto-pong inline (never starve the data path — Pitfall 5).
                    with self._send_lock:
                        self._sock.sendall(self._ws.send(event.response()))
                elif isinstance(event, Pong):
                    continue  # keepalive reply — ignore
                elif isinstance(event, CloseConnection):
                    _reason = getattr(event, "message", "") or getattr(event, "reason", "")
                    _detail = f" reason={_reason!r}" if _reason else ""
                    raise WebSocketError(f"WebSocket closed by peer (code {event.code}){_detail}")

            try:
                data = self._sock.recv(65536)
            except (OSError, EOFError) as exc:
                raise CommunicationError(
                    "WebSocket transport recv failed", original_exception=exc
                ) from exc
            if not data:
                raise CommunicationError("WebSocket connection closed by peer")
            self._ws.receive_data(data)

    def drain_queued_close(self) -> WebSocketError | None:
        """Drain already-parsed wsproto events without blocking on the socket.

        Returns a :class:`WebSocketError` if a ``CloseConnection`` event is
        already queued (arrived in the same TCP segment as the previous frame),
        ``None`` otherwise.  Incoming ``Ping`` frames are auto-ponged inline.

        Use this immediately after :meth:`recv_message` to detect a WS CLOSE
        that the server sent back-to-back with the binary response.
        """
        for event in self._ws.events():
            if isinstance(event, CloseConnection):
                _reason = getattr(event, "message", "") or getattr(event, "reason", "")
                _detail = f" reason={_reason!r}" if _reason else ""
                return WebSocketError(f"WebSocket closed by peer (code {event.code}){_detail}")
            if isinstance(event, Ping):
                try:
                    with self._send_lock:
                        self._sock.sendall(self._ws.send(event.response()))
                except OSError:
                    pass
        return None

    def close(self) -> None:
        """Tear down: stop the ping thread, close the socket, join the thread.

        Sets ``_stopped`` FIRST (server.py teardown order) so the ping thread
        exits cleanly, then closes the socket, then joins with a timeout. Safe to
        call more than once.
        """
        if self._closed:
            return
        self._stopped = True
        self._closed = True
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5.0)
        self._thread = None


def connect_ws(
    wshost: str,
    wsport: int,
    *,
    ws_path: str = _DEFAULT_WS_PATH,
    ws_proxy_host: str | None = None,
    ws_proxy_port: int | None = None,
    ws_proxy_user: str | None = None,
    ws_proxy_pass: str | None = None,
    user: str | None = None,
    passwd: str | None = None,
    sap_client: str | None = None,
    lang: str = "EN",
    timeout: float | None = None,
    read_timeout: float | None = DEFAULT_READ_TIMEOUT,
    ws_ping_interval: float = 60.0,
    ca_bundle: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    verify: bool = True,
) -> WsTransport:
    """Open a wRFC transport and return a :class:`WsTransport` (full D-16 sequence).

    Steps: TCP connect (TCP_NODELAY) → optional HTTP CONNECT proxy tunnel (D-16
    step 2 / D-20) → verifying TLS with SNI (D-16 step 3) → RFC 6455 upgrade with
    SAP-specific headers (sap-client, sap-rfcpro-suppvers, etc.) + optional HTTP
    Basic auth, Sec-WebSocket-Accept validation and single-redirect handling (D-16
    steps 4-5) → a WsTransport over masked binary frames with ping/pong keepalive.

    ``timeout`` bounds the connect and the upgrade; ``read_timeout`` bounds every
    read afterwards and is applied once the handshake is done. They are separate
    because a slow connect and a slow RFC call want very different limits: the
    default read timeout is ``None``, matching the classic transport, because an
    RFC call may legitimately run for hours and a library that cut it off at sixty
    seconds would be unusable.

    Before this existed, ``connect(read_timeout=...)`` had no effect at all on a
    WebSocket connection -- the value was accepted and silently dropped, so a
    caller who asked for a bounded read got an unbounded one and a server that
    stopped answering blocked them forever.

    Security (T-07-PROXY-CRED / T-07-CRED): ``ws_proxy_pass`` and ``passwd`` are
    used only to build Basic auth tokens and are NEVER logged or embedded in
    exceptions.
    """
    if ws_proxy_host is not None:
        # Connect to the proxy first, then CONNECT-tunnel to the real endpoint.
        raw = socket.create_connection((ws_proxy_host, ws_proxy_port or wsport), timeout=timeout)
    else:
        raw = socket.create_connection((wshost, wsport), timeout=timeout)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    try:
        if ws_proxy_host is not None:
            _open_proxy_tunnel(
                raw,
                wshost,
                wsport,
                user=ws_proxy_user,
                password=ws_proxy_pass,
            )

        ctx = _make_ssl_context(
            ca_bundle=ca_bundle,
            client_cert=client_cert,
            client_key=client_key,
            verify=verify,
        )
        tls_sock = ctx.wrap_socket(raw, server_hostname=wshost)  # SNI required (BTP)
    except BaseException:
        try:
            raw.close()
        except OSError:
            pass
        raise

    try:
        leftover = _ws_upgrade(
            tls_sock,
            host=wshost,
            port=wsport,
            ws_path=ws_path,
            user=user,
            passwd=passwd,
            sap_client=sap_client,
            lang=lang,
        )
    except BaseException:
        try:
            tls_sock.close()
        except OSError:
            pass
        raise

    # The upgrade was performed manually, so hand the already-open connection to
    # wsproto's frame-layer Connection (ConnectionType.CLIENT starts in the OPEN
    # state and masks client→server frames). Any bytes read past the 101 response
    # are fed in as trailing_data so no frame is lost.
    ws_conn = Connection(ConnectionType.CLIENT, trailing_data=leftover or b"")

    # Switch from the connect budget to the read budget now the handshake is done.
    tls_sock.settimeout(read_timeout)
    return WsTransport(
        tls_sock,
        ws_conn,
        ws_ping_interval=ws_ping_interval,
        leftover=b"",  # already seeded via trailing_data above
    )
