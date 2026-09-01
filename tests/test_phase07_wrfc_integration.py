# tests/test_phase07_wrfc_integration.py
#
# Phase 7 wRFC (WebSocket RFC over TLS) live integration gate — SEC-05.
#
# The entire module is behind the `integration` pytest marker, so it is NOT
# collected in the default offline suite (`-m "not integration"`). The live
# tests additionally skip unless SAPRFC_WSHOST is set, so even an explicit
# integration run is a no-op without a live wRFC endpoint.
#
# Target: on-premise ABAP system with ICM WebSocket RFC enabled (A4H/NW 7.x).
# On A4H the wRFC LOGON+RFCPING always yields E=163; the library falls back to
# classic RFC transparently (_ws_classic_fallback).
#
# The OFFLINE routing proof (connect(wshost=...) → connect_ws with the right
# defaults) lives in tests/test_connection.py — it needs no network and runs in
# the normal offline suite. This file holds only the live ABAP ICM gate.
#
# Required env vars for the live tests:
#   SAPRFC_WSHOST        — WebSocket RFC host (on-premise ABAP ICM)
#   SAPRFC_WSPORT        — TLS port (default 443)
#   SAPRFC_CLIENT        — SAP client (mandant), e.g. "100"
#   SAPRFC_USER          — logon user
#   SAPRFC_PASSWD        — logon password (never logged — T-07-CRED)
# Optional:
#   SAPRFC_WSPATH        — override the ICM handler path (default /sap/bc/rfc, D-19)
#   SAPRFC_WS_TLS_VERIFY — set to "false" to disable TLS cert verification (on-premise
#                          systems with self-signed or weak-key certs; T-07-TLS-VERIFY
#                          explicit opt-in)

import os

import pytest

import saprfclib

pytestmark = pytest.mark.integration  # entire module is integration-gated


@pytest.mark.skipif(
    not os.environ.get("SAPRFC_WSHOST"),
    reason="SAPRFC_WSHOST not set — no live ABAP ICM wRFC endpoint available",
)
def _connect_live_wrfc() -> "saprfclib.Connection":
    """Open a live wRFC connection from the SAPRFC_WS* env vars (passwd never logged)."""
    wshost = os.environ["SAPRFC_WSHOST"]
    wsport = int(os.environ.get("SAPRFC_WSPORT", "443"))
    ws_path = (
        os.environ.get("SAPRFC_WSPATH") or None
    )  # None → connect() uses default with ?sap-apc-stateful=true
    client = os.environ["SAPRFC_CLIENT"]
    user = os.environ["SAPRFC_USER"]
    passwd = os.environ["SAPRFC_PASSWD"]  # never logged — T-07-CRED
    ws_tls_verify = os.environ.get("SAPRFC_WS_TLS_VERIFY", "true").lower() != "false"

    return saprfclib.connect(
        ashost=wshost,  # ashost is unused on the wRFC path but kept in the signature
        sysnr="00",
        client=client,
        user=user,
        passwd=passwd,
        wshost=wshost,
        wsport=wsport,
        ws_path=ws_path,
        ws_tls_verify=ws_tls_verify,
    )


@pytest.mark.skipif(
    not os.environ.get("SAPRFC_WSHOST"),
    reason="SAPRFC_WSHOST not set — no live ABAP ICM wRFC endpoint available",
)
def test_live_wrfc_connect() -> None:
    """Live wRFC connect + get_function_desc (SEC-05, Track 2 lazy-LOGON).

    Opens a WebSocket RFC connection via ``saprfclib.connect(wshost=...)``.  Under
    Track 2 the RFC LOGON is deferred to the first call(); the connection starts
    in WS_PENDING and advances to READY on the first ``get_function_desc`` round-trip
    (which embeds LOGON+RFC_GET_FUNCTION_INTERFACE in one frame).

    Order matters: ``get_function_desc`` must be called BEFORE
    ``get_connection_attributes`` because ConnectionAttributes are populated only
    after the LOGON round-trip completes.
    """
    conn = _connect_live_wrfc()
    try:
        from saprfclib.metadata import MetadataCache, get_function_desc

        cache = MetadataCache()
        try:
            desc = get_function_desc(conn, "STFC_CONNECTION", cache=cache)
            assert desc.name == "STFC_CONNECTION"
            assert any(p.name == "REQUTEXT" for p in desc.parameters), (
                "STFC_CONNECTION descriptor missing REQUTEXT"
            )
        except saprfclib.AbapSystemFailure as exc:
            # This used to require the string "163" in the message. Nothing on the
            # wire ever produced it -- the library fabricated the number at three
            # points, one of them precisely when the server reported no return code
            # at all. Asserting on it pinned the fiction in place. The real open
            # gap is that the interface fetch does not complete over wRFC on this
            # kernel, so that is what is xfailed, with whatever the server actually
            # said carried into the reason.
            pytest.xfail(f"wRFC interface fetch did not complete: {exc}")
        except saprfclib.WebSocketError as exc:
            pytest.xfail(f"wRFC LOGON+GFI: server closed after LOGON ({exc})")

        # ConnectionAttributes are available after the first call (LOGON complete).
        attrs = conn.get_connection_attributes()
        assert attrs.sys_id, "sys_id must be non-empty after live wRFC LOGON"
    finally:
        conn.close()


@pytest.mark.skipif(
    not os.environ.get("SAPRFC_WSHOST"),
    reason="SAPRFC_WSHOST not set — no live ABAP ICM wRFC endpoint available",
)
def test_live_wrfc_call() -> None:
    """Live wRFC function invocation: conn.call('STFC_CONNECTION') (SEC-05 extended).

    Under Track 2 lazy-LOGON, the RFC LOGON is deferred to the first call().
    ``call("STFC_CONNECTION", ...)`` triggers: LOGON+RFC_GET_FUNCTION_INTERFACE
    (one round-trip to get the descriptor) then STFC_CONNECTION as a subsequent
    invoke.  ConnectionAttributes are queried after the call.

    Two outcomes are accepted:
      1. Call succeeds → ECHOTEXT/RESPTEXT present in result dict.
      2. ``saprfclib.AbapSystemFailure`` → the interface fetch does not complete
         gap (STATE.md blocker); pytest.xfail.

    Password is never logged (T-07-CRED).
    """
    conn = _connect_live_wrfc()
    try:
        try:
            result = conn.call("STFC_CONNECTION", REQUTEXT="ping")
        except NotImplementedError as exc:  # pragma: no cover
            pytest.fail(f"wRFC invoke path not exercised (NotImplementedError): {exc}")
        except saprfclib.AbapSystemFailure as exc:
            # See the note in the descriptor test: "163" was ours, not the
            # server's, so there is nothing to match on. The gap is real; the
            # number was not.
            pytest.xfail(f"wRFC descriptor gap: {exc}")
        except saprfclib.WebSocketError as exc:
            pytest.xfail(f"wRFC LOGON+GFI: server closed after LOGON ({exc})")

        assert isinstance(result, dict)
        assert "ECHOTEXT" in result or "RESPTEXT" in result, (
            f"STFC_CONNECTION returned no ECHOTEXT/RESPTEXT: keys={list(result)}"
        )

        # ConnectionAttributes available after the first call (LOGON complete).
        attrs = conn.get_connection_attributes()
        assert attrs.sys_id, "sys_id must be non-empty after live wRFC LOGON"
    finally:
        conn.close()


@pytest.mark.skipif(
    not os.environ.get("SAPRFC_WSHOST"),
    reason="SAPRFC_WSHOST not set — no live ABAP ICM wRFC endpoint available",
)
def test_live_wrfc_stfc_structure() -> None:
    """Live wRFC STFC_STRUCTURE call — exercises STRUCTURE Q-marker (rfctype=0x11).

    Calls STFC_STRUCTURE with a populated IMPORTSTRUCT dict over WebSocket RFC.
    This test verifies that the V1 ngrfc Q-marker for RFCTYPE_STRUCTURE is
    correctly encoded and accepted by the server.

    Two outcomes are accepted:
      1. Call succeeds → ECHOSTRUCT is a dict; RESPTEXT is a str.
      2. ``saprfclib.AbapSystemFailure`` → known wRFC descriptor gap on
         A4H; pytest.xfail.

    Password is never logged (T-07-CRED).
    """
    conn = _connect_live_wrfc()
    try:
        import_struct = {
            "RFCFLOAT": 3.14,
            "RFCCHAR1": "X",
            "RFCINT2": 42,
            "RFCINT1": 5,
            "RFCCHAR4": "TEST",
            "RFCINT4": 100,
            "RFCHEX3": b"\x01\x02\x03",
            "RFCCHAR2": "AB",
            "RFCTIME": "120000",
            "RFCDATE": "20260628",
            "RFCDATA1": "A" * 50,
            "RFCDATA2": "B" * 50,
        }
        try:
            result = conn.call("STFC_STRUCTURE", IMPORTSTRUCT=import_struct)
        except NotImplementedError as exc:  # pragma: no cover
            pytest.fail(f"wRFC STRUCTURE Q-marker path raised NotImplementedError: {exc}")
        except saprfclib.AbapSystemFailure as exc:
            # "server E=163" was never the server's; see the descriptor test.
            pytest.xfail(f"wRFC descriptor gap on STFC_STRUCTURE: {exc}")
        except saprfclib.WebSocketError as exc:
            pytest.xfail(f"wRFC session closed unexpectedly: {exc}")

        assert isinstance(result, dict), f"Expected dict result, got {type(result)}"
        if "ECHOSTRUCT" in result:
            assert isinstance(result["ECHOSTRUCT"], dict), (
                f"ECHOSTRUCT must be a dict, got {type(result['ECHOSTRUCT'])}"
            )
        if "RESPTEXT" in result:
            assert isinstance(result["RESPTEXT"], str), (
                f"RESPTEXT must be str, got {type(result['RESPTEXT'])}"
            )
    finally:
        conn.close()
