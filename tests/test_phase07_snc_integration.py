# tests/test_phase07_snc_integration.py
#
# Phase 7 SNC (Secure Network Communications) live integration gate —
# SEC-02 / SEC-03 / SEC-04 / SEC-06.
#
# The entire module is behind the `integration` pytest marker, so it is NOT
# collected in the default offline suite (`-m "not integration"`). The single
# live test additionally skips unless SAPRFC_SNC_LIB is set, so even an explicit
# integration run is a no-op without a real SNC-enabled SAP system and a GSS
# provider .so.
#
# The OFFLINE routing proof (connect(snc_lib=...) → SncTransport wrapping
# connect_tcp with the right defaults, and wshost winning over snc_lib) lives in
# tests/test_connection.py — it needs no network / .so and runs in the normal
# offline suite. This file holds only the live SNC gate.
#
# Required env vars for the live test:
#   SAPRFC_SNC_LIB          — path to the GSS provider .so on the test host, e.g.
#                             /usr/lib/libsapcrypto.so (X.509 / CommonCryptoLib) or
#                             libgssapi_krb5.so.2 (Kerberos)
#   SAPRFC_SNC_PARTNERNAME  — server GSS identity, e.g. p:CN=SAP Server,O=...
#   SAPRFC_ASHOST           — application server host
#   SAPRFC_SYSNR            — system number (default "00")
#   SAPRFC_CLIENT           — SAP client (mandant), e.g. "001"
#   SAPRFC_USER             — logon user
#   SAPRFC_PASSWD           — logon password (never logged — T-07-CRED)
# Optional:
#   SAPRFC_SNC_MYNAME       — client GSS identity (lib default if absent)
#   SAPRFC_SNC_QOP          — QOP level 1/2/3 (default 3, privacy)
#
# Credential discipline (T-07-CRED): SAPRFC_SNC_LIB, SAPRFC_SNC_PARTNERNAME and
# SAPRFC_SNC_MYNAME are never echoed into an assertion message or logged here.

import os

import pytest

import saprfclib

pytestmark = pytest.mark.integration  # entire module is integration-gated


@pytest.mark.skipif(
    not os.environ.get("SAPRFC_SNC_LIB"),
    reason="SAPRFC_SNC_LIB not set — no live SNC-enabled SAP system available",
)
def test_live_snc_handshake() -> None:
    """Live SNC connect (GSS handshake to COMPLETE), then STFC_CONNECTION.

    Opens a real SNC connection via ``saprfclib.connect(snc_lib=..., snc_partnername=...)``
    against an SNC-enabled SAP system, verifies the handshake lands on a READY
    connection with populated ConnectionAttributes (SEC-02/03/06), and attempts
    STFC_CONNECTION. The call is accepted whether it succeeds (Phase 4 invoke path
    available) or raises NotImplementedError (gap still open). Stays skipped in the
    offline suite.

    SEC-04 (no cleartext password) is additionally confirmed out-of-band at the
    P03 checkpoint via a packet capture (tcpdump/wireshark) — the logon payload
    must be GSS-wrapped, never cleartext. Record the real 8-byte eye-catcher
    (D-22) from that capture to update the docs/protocol/snc.md fallback.

    T-07-CRED: the snc_lib path and partner/my names are read from the env and
    passed straight to connect() — never echoed into an assertion message here.
    """
    snc_lib = os.environ["SAPRFC_SNC_LIB"]
    snc_partnername = os.environ["SAPRFC_SNC_PARTNERNAME"]
    snc_myname = os.environ.get("SAPRFC_SNC_MYNAME")
    snc_qop = int(os.environ.get("SAPRFC_SNC_QOP", "3"))
    ashost = os.environ["SAPRFC_ASHOST"]
    sysnr = os.environ.get("SAPRFC_SYSNR", "00")
    client = os.environ["SAPRFC_CLIENT"]
    user = os.environ["SAPRFC_USER"]
    passwd = os.environ["SAPRFC_PASSWD"]

    conn = saprfclib.connect(
        ashost=ashost,
        sysnr=sysnr,
        client=client,
        user=user,
        passwd=passwd,
        snc_lib=snc_lib,
        snc_partnername=snc_partnername,
        snc_myname=snc_myname,
        snc_qop=snc_qop,
    )
    try:
        attrs = conn.get_connection_attributes()
        # No credential material in the assertion message (T-07-CRED).
        assert attrs.sys_id, "sys_id must be non-empty after live SNC handshake"
        try:
            from saprfclib.metadata import MetadataCache, get_function_desc

            cache = MetadataCache()
            desc = get_function_desc(conn, "STFC_CONNECTION", cache=cache)
            assert desc.name == "STFC_CONNECTION"
        except NotImplementedError:
            pass  # Phase 4 invoke path not yet available — gap documented
    finally:
        conn.close()
