# tests/test_phase05_server.py
#
# Offline tests for the sans-I/O RFC ServerSession (Plan 05-02, SERVER-02).
# This plan owns test_registration_frame_matches_capture: the registration frame
# the ServerSession builds must equal the captured golden fixture
# tests/golden/framing/server_registration_request.bin byte-for-byte (modulo the
# session-variable fields annotated in the .json sidecar).
#
# RE source of every reproduced byte: docs/protocol/framing.md (protocol analysis + capture).
# ZERO sockets — the registration frame is built by the pure state machine.
#
# Plan 03 also extends this file with the dispatch/serialize/auth tests; this plan
# adds only the registration golden round-trip + the state-machine guard tests.

import struct

import pytest

from saprfclib.connection import _scramble_password
from saprfclib.invoke import _extract_name_value_pairs, tlv_record
from saprfclib.metadata import FunctionDesc
from saprfclib.server import RfcServer
from saprfclib.server_session import ServerSession, ServerSessionState
from saprfclib.types import RFC_EXPORT, RFC_IMPORT, FieldDesc
from tests.conftest import GOLDEN_ROOT, compare_bytes, load_fixture

FRAMING_DIR = GOLDEN_ROOT / "framing"

# The PROGRAM_ID / gwserv the captured oracle registered with. The PROGRAM_ID is
# NOT present on the wire in the 0x0601 connect frame (see docs/protocol/framing.md); it is
# accepted via the follow-up SAP_CMACCPTP3 exchange (Wave 2). The builder still
# takes it so the public API matches RfcRegisterServer(program_id, gwhost, gwserv).
FIXTURE_PROGRAM_ID = "SAPRFC_TEST"
FIXTURE_GWSERV = "sapdp00"


def test_registration_frame_matches_capture() -> None:
    """ServerSession.build_registration_frame == captured golden fixture (SERVER-02).

    Byte-for-byte against server_registration_request.bin, skipping the
    session-variable fields (connection handle, local IP/host/service, OS user,
    time() blob) annotated `variable` in the .json sidecar.
    """
    fx = load_fixture(FRAMING_DIR, "server_registration_request")
    sess = ServerSession()
    frame = sess.build_registration_frame(program_id=FIXTURE_PROGRAM_ID, gwserv=FIXTURE_GWSERV)
    mismatches = compare_bytes(frame, fx.raw_bytes, fx.field_annotations)
    assert mismatches == [], "registration frame deviates from capture:\n" + "\n".join(mismatches)


def test_registration_state_machine_advances() -> None:
    """Fresh session is DISCONNECTED; build+ack drives REGISTERED then LISTENING."""
    sess = ServerSession()
    assert sess.state is ServerSessionState.DISCONNECTED

    sess.build_registration_frame(program_id=FIXTURE_PROGRAM_ID, gwserv=FIXTURE_GWSERV)
    assert sess.state is ServerSessionState.GW_CONNECTED

    # Feed the registration ACK (gateway accepted) -> REGISTERED, then listen.
    sess.feed(_load_ack())
    assert sess.state is ServerSessionState.REGISTERED

    sess.mark_listening()
    assert sess.state is ServerSessionState.LISTENING


def test_out_of_order_feed_rejected() -> None:
    """State guards reject a feed before registration was sent (mirrors session.py)."""
    sess = ServerSession()
    with pytest.raises(ValueError):
        sess.feed(b"\x00\x00\x00\x50")  # nothing built yet -> DISCONNECTED


def _load_ack() -> bytes:
    """Load the registration-ACK GW payload (strip 4-byte NI header).

    Transport.recv_message() strips the NI header before returning; feed()
    now accepts the raw GW payload that recv_message delivers.
    """
    raw = (FRAMING_DIR / "server_registration_ack.bin").read_bytes()
    return raw[4:]  # strip NI length header


# =========================================================================== #
# Plan 05-03: RfcServer core — registry, inbound deserialize, response          #
# serialize (SERVER-01/03/04), auth callback + exception isolation (05/06).     #
#                                                                               #
# All tests are OFFLINE: dispatch_inbound() is the sans-I/O seam (frame bytes   #
# in, response bytes out) so no socket is needed. Inbound frames are bare TLV   #
# (first byte != 0x06) so _strip_gw_header passes them through, mirroring the   #
# MockTransport idiom from test_connection.py.                                  #
# =========================================================================== #

# RFCTYPE constant (mirrors codec.py / test_invoke.py).
_RFCTYPE_CHAR = 0

# Response/request TLV tags (mirror invoke.py constants for assertions).
_TAG_FUNC_NAME = 0x0102
_TAG_PARAM_NAME = 0x0201
_TAG_PARAM_VALUE = 0x0203
_TAG_RESPONSE_START = 0x0500
_TAG_RETURN_CODE = 0x0420
_TAG_TERMINATOR = 0xFFFF


def _char_field(name: str, direction: int) -> FieldDesc:
    """A CHAR(255) FieldDesc mirroring test_invoke.py (STFC_CONNECTION shape)."""
    return FieldDesc(
        name=name,
        rfctype=_RFCTYPE_CHAR,
        nuc_length=255,
        nuc_offset=0,
        uc_length=510,
        uc_offset=0,
        decimals=0,
        unicode_mode=True,
        direction=direction,
    )


def _stfc_connection_desc() -> FunctionDesc:
    """FunctionDesc for STFC_CONNECTION (REQUTEXT in, ECHOTEXT/RESPTEXT out)."""
    return FunctionDesc(
        name="STFC_CONNECTION",
        parameters=[
            _char_field("ECHOTEXT", RFC_EXPORT),
            _char_field("RESPTEXT", RFC_EXPORT),
            _char_field("REQUTEXT", RFC_IMPORT),
        ],
    )


def _server() -> RfcServer:
    """A bare RfcServer with the discretion registration params."""
    return RfcServer(
        {"program_id": FIXTURE_PROGRAM_ID, "gwhost": "localhost", "gwserv": FIXTURE_GWSERV}
    )


def _inbound_call_frame(func_name: str, params: dict[str, str]) -> bytes:
    """Build a bare-TLV inbound call frame (no GW header — first byte != 0x06).

    Mirrors the client's request shape: 0x0102 func name + 0x0201/0x0203 pairs
    for the values the client sent (its IMPORTING params), then a 0xFFFF
    terminator. dispatch_inbound() reads exactly this via _extract_name_value_pairs.
    """
    parts = [tlv_record(_TAG_FUNC_NAME, func_name.encode("utf-16-le"))]
    for name, value in params.items():
        parts.append(tlv_record(_TAG_PARAM_NAME, name.encode("utf-16-le")))
        parts.append(tlv_record(_TAG_PARAM_VALUE, value.encode("utf-16-le")))
    parts.append(tlv_record(_TAG_TERMINATOR))
    return b"".join(parts)


def test_decorator_registers_handler() -> None:
    """@server.function registers a handler by FM name; generic fallback stored."""
    server = _server()
    desc = _stfc_connection_desc()

    @server.function("STFC_CONNECTION", desc)
    def _echo(request: dict) -> dict:  # noqa: ANN001
        return {"ECHOTEXT": request.get("REQUTEXT", "")}

    # The decorator returns the wrapped fn unchanged (D-07).
    assert _echo({"REQUTEXT": "x"}) == {"ECHOTEXT": "x"}
    assert "STFC_CONNECTION" in server._registry
    stored_desc, stored_fn = server._registry["STFC_CONNECTION"]
    assert stored_desc is desc
    assert stored_fn is _echo

    # A second registration for another FM coexists (case-insensitive key).
    other = FunctionDesc(name="RFC_PING", parameters=[])

    @server.function("rfc_ping", other)
    def _ping(request: dict) -> dict:  # noqa: ANN001
        return {}

    assert "RFC_PING" in server._registry
    assert "STFC_CONNECTION" in server._registry

    # set_generic_handler stores a fallback (D-09).
    def _generic(name: str):  # noqa: ANN001, ANN202
        return (FunctionDesc(name=name, parameters=[]), lambda req: {})

    server.set_generic_handler(_generic)
    assert server._generic is _generic


def test_inbound_deserializes_params() -> None:
    """A captured inbound call deserializes to a typed request dict (SERVER-03)."""
    server = _server()
    desc = _stfc_connection_desc()
    captured: dict = {}

    @server.function("STFC_CONNECTION", desc)
    def _echo(request: dict) -> dict:  # noqa: ANN001
        captured.update(request)
        return {"ECHOTEXT": request["REQUTEXT"], "RESPTEXT": "ok"}

    frame = _inbound_call_frame("STFC_CONNECTION", {"REQUTEXT": "hello sap"})
    server.dispatch_inbound(frame)

    # The handler received the client's IMPORTING value as a typed Python str.
    assert captured["REQUTEXT"] == "hello sap"


def test_response_serialization_roundtrip() -> None:
    """A handler's EXPORTING dict serializes to TLV that parses back (SERVER-04)."""
    server = _server()
    desc = _stfc_connection_desc()

    @server.function("STFC_CONNECTION", desc)
    def _echo(request: dict) -> dict:  # noqa: ANN001
        return {"ECHOTEXT": request["REQUTEXT"], "RESPTEXT": "done"}

    frame = _inbound_call_frame("STFC_CONNECTION", {"REQUTEXT": "ping"})
    resp = server.dispatch_inbound(frame)

    # Response starts the response section + return code 0.
    assert struct.pack(">H", _TAG_RESPONSE_START) in resp
    # Return code tag 0x0420 == 0 (4B BE).
    idx = resp.find(struct.pack(">H", _TAG_RETURN_CODE))
    assert idx != -1
    rc = struct.unpack_from(">I", resp, idx + 4)[0]
    assert rc == 0

    # The EXPORTING values round-trip through the invoke parser.
    pairs = dict(_extract_name_value_pairs(resp))
    assert pairs["ECHOTEXT"].decode("utf-16-le").rstrip(" ") == "ping"
    assert pairs["RESPTEXT"].decode("utf-16-le").rstrip(" ") == "done"


def test_response_matches_golden() -> None:
    """The accepted-response serializer emits the response-only tag set.

    The captured server_response.bin fixture is a logon-ERROR reply (annotated
    all-variable in its sidecar), so it is not byte-reproducible by a success
    handler. Instead we validate the response-only tag set the gateway expects on
    the success path (0x0500 response-start + 0x0420 return code), per the
    fixture sidecar's documented tag observations (OQ-3/A4).
    """
    server = _server()
    desc = _stfc_connection_desc()

    @server.function("STFC_CONNECTION", desc)
    def _echo(request: dict) -> dict:  # noqa: ANN001
        return {"ECHOTEXT": request["REQUTEXT"]}

    resp = server.dispatch_inbound(_inbound_call_frame("STFC_CONNECTION", {"REQUTEXT": "abc"}))

    # Response-only tags present (mirror the fixture sidecar's 0x0500 call-end note).
    assert struct.pack(">H", _TAG_RESPONSE_START) in resp
    assert struct.pack(">H", _TAG_RETURN_CODE) in resp
    # Stream is terminated with the tlv_record terminator (tag+len+close tag).
    assert resp.endswith(tlv_record(_TAG_TERMINATOR))


# --------------------------------------------------------------------------- #
# Task 2: auth callback (SERVER-05) + exception isolation (SERVER-06/D-03).     #
# --------------------------------------------------------------------------- #

_TAG_USER = 0x0111
_TAG_PASSWORD = 0x0117
_TAG_ERROR_MESSAGE = 0x0402


def _inbound_call_with_creds(
    func_name: str, params: dict[str, str], *, user: str, password: str
) -> bytes:
    """Inbound call frame carrying logon credentials (0x0111 user, 0x0117 passwd).

    The password is scrambled with the same _scramble_password the client uses
    (seed 4B LE + the password-scramble cipher), so the server's symmetric unscramble recovers it.
    """
    parts = [
        tlv_record(_TAG_FUNC_NAME, func_name.encode("utf-16-le")),
        tlv_record(_TAG_USER, user.encode("utf-16-le")),
        tlv_record(_TAG_PASSWORD, _scramble_password(password, seed=0x11223344)),
    ]
    for name, value in params.items():
        parts.append(tlv_record(_TAG_PARAM_NAME, name.encode("utf-16-le")))
        parts.append(tlv_record(_TAG_PARAM_VALUE, value.encode("utf-16-le")))
    parts.append(tlv_record(_TAG_TERMINATOR))
    return b"".join(parts)


def _error_message_from_response(resp: bytes) -> str:
    """Extract the 0x0402 error-message text (UTF-16LE) from a failure response."""
    from saprfclib.invoke import _parse_tlv_stream

    raw = _parse_tlv_stream(resp).get(_TAG_ERROR_MESSAGE)
    return raw.decode("utf-16-le") if raw else ""


def test_auth_callback_denies() -> None:
    """An auth callback returning False rejects the call; the handler never runs."""
    server = _server()
    desc = _stfc_connection_desc()
    handler_ran: list[bool] = []
    seen_creds: list[tuple] = []

    @server.function("STFC_CONNECTION", desc)
    def _echo(request: dict) -> dict:  # noqa: ANN001
        handler_ran.append(True)
        return {"ECHOTEXT": request["REQUTEXT"]}

    # Deny path: callback returns False -> auth-failure, handler skipped.
    def _deny(*, user, password):  # noqa: ANN001, ANN202
        seen_creds.append((user, password))
        return False

    server.set_authentication_check(_deny)
    frame = _inbound_call_with_creds(
        "STFC_CONNECTION", {"REQUTEXT": "x"}, user="DEVELOPER", password="s3cret"
    )
    resp = server.dispatch_inbound(frame)

    assert handler_ran == []  # handler NOT invoked on deny (T-05-C06)
    # The callback received the unscrambled credentials.
    assert seen_creds == [("DEVELOPER", "s3cret")]
    # Auth-failure is signalled (non-zero return code via the failure builder).
    idx = resp.find(struct.pack(">H", _TAG_RETURN_CODE))
    assert idx != -1 and struct.unpack_from(">I", resp, idx + 4)[0] != 0
    # The password is NEVER echoed in the failure message (T-05-C03).
    assert "s3cret" not in _error_message_from_response(resp)

    # Allow path: callback returns True -> handler runs normally.
    server.set_authentication_check(lambda *, user, password: True)
    server.dispatch_inbound(frame)
    assert handler_ran == [True]


def test_handler_exception_isolated() -> None:
    """A handler that raises -> SYSTEM_FAILURE; the loop survives (SERVER-06/D-03)."""
    server = _server()
    desc = _stfc_connection_desc()

    @server.function("BOOM", FunctionDesc(name="BOOM", parameters=[]))
    def _boom(request: dict) -> dict:  # noqa: ANN001
        raise RuntimeError("handler blew up\nsecret-trace-line")

    @server.function("STFC_CONNECTION", desc)
    def _ok(request: dict) -> dict:  # noqa: ANN001
        return {"ECHOTEXT": request["REQUTEXT"]}

    # The raising handler does not propagate; it becomes a SYSTEM_FAILURE.
    resp = server.dispatch_inbound(_inbound_call_frame("BOOM", {}))
    idx = resp.find(struct.pack(">H", _TAG_RETURN_CODE))
    assert idx != -1 and struct.unpack_from(">I", resp, idx + 4)[0] != 0
    msg = _error_message_from_response(resp)
    assert "handler blew up" in msg
    # No full traceback leaked — only the first line of str(exc) (T-05-C02).
    assert "secret-trace-line" not in msg

    # A subsequent call to a healthy handler still succeeds (loop survives).
    ok_resp = server.dispatch_inbound(_inbound_call_frame("STFC_CONNECTION", {"REQUTEXT": "alive"}))
    ok_idx = ok_resp.find(struct.pack(">H", _TAG_RETURN_CODE))
    assert struct.unpack_from(">I", ok_resp, ok_idx + 4)[0] == 0
    pairs = dict(_extract_name_value_pairs(ok_resp))
    assert pairs["ECHOTEXT"].decode("utf-16-le").rstrip(" ") == "alive"
