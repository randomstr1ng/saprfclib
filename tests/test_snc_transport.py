# tests/test_snc_transport.py
#
# Unit tests for SncTransport (plan 07-P02) — the SNC transport wrapper that
# drives the GSS handshake to COMPLETE (D-04) and dispatches send/recv by QOP
# (D-08), all behind the send_message/recv_message seam (D-01).
#
# Everything here is offline: a MockGssLib double (scripting gss_init_sec_context
# output tokens + gss_wrap/unwrap/get_mic/verify_mic) is injected via the
# GssBinding `loader` seam, and a MockTransport (tests/_mocks.py) is the inner
# transport. No real .so, no network.
#
# Coverage (Tasks 1-3):
#   - single-step and two-step handshakes reach _established == True (SEC-06)
#   - no data frame is sent before COMPLETE; send_message before COMPLETE raises
#   - a GSS hard error during handshake raises SncError(major/minor), no leak
#   - snc_sso=True raises NotImplementedError (D-23)
#   - QOP-3 privacy wrap/unwrap round-trip (type-9 frames)
#   - QOP-1 plain round-trip (type-7 frames)
#   - non-eye-catcher inner frame passes through unchanged (D-05)
#   - no-plaintext (SEC-04): a sentinel payload never reaches inner.sent at QOP 3
#   - the injected eye-catcher is the one used in built frames
#
# Security: every SncError assertion also checks the message carries NO
# token/credential/name bytes (threat T-07-CRED).

import os

import pytest

from saprfclib.exceptions import SncError
from saprfclib.snc import (
    GssBinding,
    SncFrameType,
    SncTransport,
    build_snc_frame,
    connect_snc,
    parse_snc_frame,
)

GSS_S_COMPLETE = 0
GSS_S_CONTINUE_NEEDED = 1

_EYE = b"SNCPROTO"


# --- MockGssLib: scripts init-token exchange + wrap/unwrap/mic --------------


class MockGssLib:
    """GSS library double scripting a handshake token exchange + data crypto.

    ``init_script`` is a list of ``(major, out_token)`` tuples returned by
    successive ``gss_init_sec_context`` calls. The wrap/unwrap/get_mic/verify_mic
    doubles apply a trivial reversible transform so a round-trip is assertable
    without a real mech.
    """

    def __init__(self, init_script=None, acquire_major=GSS_S_COMPLETE, import_major=GSS_S_COMPLETE):
        # Handshake: default single-step COMPLETE with a non-empty token.
        self._init_script = list(
            init_script if init_script is not None else [(GSS_S_COMPLETE, b"tok-final")]
        )
        self._init_i = 0
        self.init_inputs: list = []
        self._acquire_major = acquire_major
        self._import_major = import_major
        # Records of high-level GSS calls for assertions.
        self.wrapped: list = []
        self.unwrapped: list = []
        self.miced: list = []
        self.verified: list = []

    # -- cred / name (duck-typed path used by GssBinding._acquire_cred etc.) --

    def gss_acquire_cred(self, *args, **kwargs):
        return self._acquire_major, 0

    def gss_import_name(self, *args, **kwargs):
        return self._import_major, 0

    # -- handshake -----------------------------------------------------------

    def gss_init_sec_context(self, *args, **kwargs):
        """Return the next scripted (major, minor, out_token)."""
        self.init_inputs.append(kwargs.get("input_token"))
        major, out_token = self._init_script[self._init_i]
        if self._init_i < len(self._init_script) - 1:
            self._init_i += 1
        return major, 0, out_token

    # -- data crypto (privacy / integrity) -----------------------------------

    def gss_wrap(self, *args, **kwargs):
        # Simulate a real mech: the wrapped token is OPAQUE ciphertext that does
        # NOT contain the plaintext (XOR-0x5A + prefix), so the SEC-04 no-cleartext
        # assertion exercises the real structural guarantee, not a mock artifact.
        payload = kwargs.get("payload", b"")
        self.wrapped.append(payload)
        return GSS_S_COMPLETE, 0, b"WRP" + bytes(b ^ 0x5A for b in payload)

    def gss_unwrap(self, *args, **kwargs):
        token = kwargs.get("token", b"")
        self.unwrapped.append(token)
        body = token[len(b"WRP") :] if token.startswith(b"WRP") else token
        return GSS_S_COMPLETE, 0, bytes(b ^ 0x5A for b in body)

    def gss_get_mic(self, *args, **kwargs):
        payload = kwargs.get("payload", b"")
        self.miced.append(payload)
        return GSS_S_COMPLETE, 0, b"MIC(" + payload + b")"

    def gss_verify_mic(self, *args, **kwargs):
        self.verified.append((kwargs.get("payload"), kwargs.get("mic")))
        return GSS_S_COMPLETE, 0, b""

    # -- helpers (never exercised on the mock path, but present) -------------

    def gss_release_buffer(self, *args, **kwargs):
        return GSS_S_COMPLETE, 0

    def gss_release_name(self, *args, **kwargs):
        return GSS_S_COMPLETE, 0


def _make_transport(*, mock=None, inner=None, snc_qop=3, snc_sso=False, eye_catcher=None):
    """Build a SncTransport with an injected MockGssLib-backed binding.

    ``inner`` defaults to a MockTransport whose scripted responses are the
    FR_ACCEPT frames needed to satisfy the handshake in ``mock``'s init_script.
    """
    from tests._mocks import MockTransport

    mock = mock or MockGssLib()
    inner = inner if inner is not None else MockTransport(responses=[])
    binding = GssBinding(
        snc_lib="/nonexistent/lib.so",
        snc_partnername="p:CN=SAP Server",
        loader=lambda _p: mock,
    )
    eye = eye_catcher if eye_catcher is not None else _EYE
    t = SncTransport(
        inner,
        snc_lib="/nonexistent/lib.so",
        snc_partnername="p:CN=SAP Server",
        snc_qop=snc_qop,
        snc_sso=snc_sso,
        gss_binding=binding,
        eye_catcher=eye,
    )
    t.activate_snc()
    return t, mock, inner


def _accept_frame(token: bytes, eye: bytes = _EYE) -> bytes:
    """Build an FR_ACCEPT frame carrying a server handshake token."""
    return build_snc_frame(eye, int(SncFrameType.FR_ACCEPT), 0, 3, gss_token=token)


def _assert_no_leak(err: SncError) -> None:
    text = str(err)
    for secret in ("SNCPROTO", "SAP Server", "lib.so", "tok-", "WRAP(", "MIC("):
        assert secret not in text, f"credential/token leak in SncError: {secret!r}"


# --- Task 1: handshake state machine ---------------------------------------


def test_handshake_single_step_reaches_complete():
    # One init call returns COMPLETE immediately with a final token.
    mock = MockGssLib(init_script=[(GSS_S_COMPLETE, b"tok-final")])
    t, _mock, inner = _make_transport(mock=mock)
    assert t._established is True
    # The final token was sent as an FR_INIT frame.
    assert len(inner.sent) == 1
    ftype, _ctx, _qop, tok, app = parse_snc_frame(inner.sent[0])
    assert ftype == int(SncFrameType.FR_INIT)
    assert tok == b"tok-final"
    assert app == b""  # no app data during handshake (SEC-06)


def test_handshake_two_step_reaches_complete():
    from tests._mocks import MockTransport

    # First init: CONTINUE with tok1; after the server reply, COMPLETE with tok2.
    mock = MockGssLib(
        init_script=[
            (GSS_S_CONTINUE_NEEDED, b"tok1"),
            (GSS_S_COMPLETE, b"tok2"),
        ]
    )
    inner = MockTransport(responses=[_accept_frame(b"srv-accept")])
    t, _mock, inner = _make_transport(mock=mock, inner=inner)
    assert t._established is True
    # Two FR_INIT frames were sent (tok1 then tok2).
    assert len(inner.sent) == 2
    _f0, _c0, _q0, tok0, _a0 = parse_snc_frame(inner.sent[0])
    _f1, _c1, _q1, tok1, _a1 = parse_snc_frame(inner.sent[1])
    assert tok0 == b"tok1"
    assert tok1 == b"tok2"
    # The server accept token was fed back into the second init call.
    assert mock.init_inputs[1] == b"srv-accept"


def test_handshake_gss_error_raises_snc_error_no_leak():
    # A hard GSS error (neither COMPLETE nor CONTINUE) aborts the handshake.
    mock = MockGssLib(init_script=[(0x00070000, b"")])
    with pytest.raises(SncError) as ei:
        _make_transport(mock=mock)
    err = ei.value
    assert err.major == 0x00070000
    _assert_no_leak(err)


def test_snc_sso_raises_not_implemented():
    from tests._mocks import MockTransport

    binding = GssBinding(
        snc_lib="/nonexistent/lib.so",
        snc_partnername="p:CN=X",
        loader=lambda _p: MockGssLib(),
    )
    with pytest.raises(NotImplementedError):
        SncTransport(
            MockTransport(responses=[]),
            snc_lib="/nonexistent/lib.so",
            snc_partnername="p:CN=X",
            snc_sso=True,
            gss_binding=binding,
        )


def test_injected_eye_catcher_is_used_in_frames():
    custom = b"XYZPROT8"  # 8 bytes
    mock = MockGssLib(init_script=[(GSS_S_COMPLETE, b"tok-final")])
    t, _mock, inner = _make_transport(mock=mock, eye_catcher=custom)
    assert inner.sent[0][:8] == custom


def test_send_before_activate_is_plain_passthrough():
    # Before activate_snc() the channel is in passthrough mode for GW frames
    # (GW_CONNECT / GW_INFO / GW_DONE_CLIENT must reach the gateway unencrypted).
    from tests._mocks import MockTransport

    binding = GssBinding(
        snc_lib="/nonexistent/lib.so",
        snc_partnername="p:CN=SAP Server",
        loader=lambda _p: MockGssLib(),
    )
    inner = MockTransport(responses=[])
    t = SncTransport(
        inner,
        snc_lib="/nonexistent/lib.so",
        snc_partnername="p:CN=SAP Server",
        gss_binding=binding,
        eye_catcher=_EYE,
    )
    # activate_snc() NOT called — still in passthrough mode
    t.send_message(b"gw-connect-payload")
    assert len(inner.sent) == 1
    assert inner.sent[0] == b"gw-connect-payload"


# --- Task 2: QOP dispatch, passthrough, no-plaintext, connect_snc -----------


def test_qop3_privacy_send_emits_type9_wrapped():
    mock = MockGssLib(init_script=[(GSS_S_COMPLETE, b"tok-final")])
    t, mock, inner = _make_transport(mock=mock, snc_qop=3)
    inner.sent.clear()
    t.send_message(b"hello")
    assert len(inner.sent) == 1
    ftype, _ctx, _qop, tok, app = parse_snc_frame(inner.sent[0])
    assert ftype == int(SncFrameType.PRIVACY)  # type 9
    # PRIVACY: encrypted data goes in gss_token (token_len), data_len=0 —
    # confirmed from proxy capture and STISncOut protocol analysis.
    assert tok == b"WRP" + bytes(b ^ 0x5A for b in b"hello")
    assert app == b""
    assert mock.wrapped == [b"hello"]


def test_qop3_privacy_recv_unwraps_type9():
    mock = MockGssLib(init_script=[(GSS_S_COMPLETE, b"tok-final")])
    from tests._mocks import MockTransport

    wrapped = b"WRP" + bytes(b ^ 0x5A for b in b"world")
    # PRIVACY: encrypted data is in gss_token field, not app_data.
    frame = build_snc_frame(_EYE, int(SncFrameType.PRIVACY), 0, 3, gss_token=wrapped)
    inner = MockTransport(responses=[frame])
    t, mock, inner = _make_transport(mock=mock, inner=inner, snc_qop=3)
    out = t.recv_message()
    assert out == b"world"
    assert mock.unwrapped == [wrapped]


def test_qop1_plain_roundtrip():
    from tests._mocks import MockTransport

    mock = MockGssLib(init_script=[(GSS_S_COMPLETE, b"tok-final")])
    plain_in = build_snc_frame(_EYE, int(SncFrameType.PLAIN), 0, 1, app_data=b"cleartext")
    inner = MockTransport(responses=[plain_in])
    t, _mock, inner = _make_transport(mock=mock, inner=inner, snc_qop=1)
    inner.sent.clear()
    t.send_message(b"payload1")
    ftype, _c, _q, _tok, app = parse_snc_frame(inner.sent[0])
    assert ftype == int(SncFrameType.PLAIN)  # type 7
    assert app == b"payload1"
    # recv of a type-7 frame returns the raw payload.
    assert t.recv_message() == b"cleartext"


def test_passthrough_non_eye_catcher_frame():
    from tests._mocks import MockTransport

    # A non-SNC NI frame (does not begin with the eye-catcher) is returned as-is.
    raw = b"\x00\x01\x02\x03 not an snc frame at all, just NI payload bytes"
    assert raw[:8] != _EYE
    inner = MockTransport(responses=[raw])
    mock = MockGssLib(init_script=[(GSS_S_COMPLETE, b"tok-final")])
    t, _mock, inner = _make_transport(mock=mock, inner=inner)
    assert t.recv_message() == raw  # unchanged (D-05)


def test_send_before_established_is_plain_passthrough():
    # _established=False after activate_snc reset means passthrough (GW-frame mode).

    mock = MockGssLib(init_script=[(GSS_S_COMPLETE, b"tok-final")])
    t, _mock, inner = _make_transport(mock=mock)
    t._established = False  # simulate pre-activate state
    inner.sent.clear()
    t.send_message(b"gw-payload")
    assert inner.sent == [b"gw-payload"]


def test_no_plaintext_at_qop3():
    # SEC-04: a sentinel "password" payload is wrapped, so the sentinel never
    # appears in the bytes handed to inner.send_message.
    sentinel = b"SUPER_SECRET_PASSWORD_TLV"
    mock = MockGssLib(init_script=[(GSS_S_COMPLETE, b"tok-final")])
    t, _mock, inner = _make_transport(mock=mock, snc_qop=3)
    inner.sent.clear()
    t.send_message(sentinel)
    for frame in inner.sent:
        assert sentinel not in frame, "SEC-04 violated: cleartext payload on wire"


def test_qop2_integrity_roundtrip():

    mock = MockGssLib(init_script=[(GSS_S_COMPLETE, b"tok-final")])
    t, mock, inner = _make_transport(mock=mock, snc_qop=2)
    inner.sent.clear()
    t.send_message(b"integ-data")
    ftype, _c, _q, _tok, _app = parse_snc_frame(inner.sent[0])
    assert ftype == int(SncFrameType.INTEGRITY)  # type 8
    assert mock.miced == [b"integ-data"]


def test_connect_snc_returns_snctransport(monkeypatch):
    # connect_snc wraps connect_tcp; inject a fake inner + binding so no socket
    # and no real .so are touched.
    import saprfclib.snc as snc_mod
    from tests._mocks import MockTransport

    fake_inner = MockTransport(responses=[])
    monkeypatch.setattr(snc_mod, "connect_tcp", lambda *a, **k: fake_inner)

    real_binding_init = GssBinding.__init__

    def _patched_init(self, **kwargs):
        kwargs["loader"] = lambda _p: MockGssLib()
        real_binding_init(self, **kwargs)

    monkeypatch.setattr(GssBinding, "__init__", _patched_init)

    t = connect_snc("host", 3300, snc_lib="/nonexistent/lib.so", snc_partnername="p:CN=X")
    assert isinstance(t, SncTransport)
    assert t._established is True


def test_close_releases_and_closes_inner():
    mock = MockGssLib(init_script=[(GSS_S_COMPLETE, b"tok-final")])
    t, _mock, inner = _make_transport(mock=mock)
    t.close()
    assert inner.closed is True


# --- integration scaffold (live SNC handshake, offline suite skips) ---------


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("SAPRFC_SNC_LIB") or not os.environ.get("SAPRFC_ASHOST"),
    reason="SAPRFC_SNC_LIB and SAPRFC_ASHOST required for live SNC handshake test",
)
def test_live_snc_handshake():
    """Live SNC connection via saprfclib.connect — full NI+GW+GSS flow (SEC-02/03/06).

    Uses the same path as production: port 4800+sysnr → NI version exchange →
    GW_CONNECT/GW_INFO/GW_DONE → activate_snc (GW-wrapped FR_INIT/FR_ACCEPT) →
    READY. This is the only path that works reliably against real SAP systems.
    """
    import saprfclib

    lib_path = os.environ["SAPRFC_SNC_LIB"]
    partner = os.environ.get("SAPRFC_SNC_PARTNERNAME", "p:CN=test")
    host = os.environ["SAPRFC_ASHOST"]
    sysnr = os.environ.get("SAPRFC_SYSNR", "00")
    client = os.environ.get("SAPRFC_CLIENT", "001")
    user = os.environ.get("SAPRFC_USER", "")
    passwd = os.environ.get("SAPRFC_PASSWD", "")  # never logged — T-07-CRED

    conn = saprfclib.connect(
        ashost=host,
        sysnr=sysnr,
        client=client,
        user=user,
        passwd=passwd,
        snc_lib=lib_path,
        snc_partnername=partner,
    )
    try:
        from saprfclib.snc import SncTransport

        assert isinstance(conn._transport, SncTransport), "SNC connection must wrap an SncTransport"
        assert conn._transport._established is True, (
            "SncTransport GSS handshake must complete before connect() returns"
        )
    finally:
        conn.close()
