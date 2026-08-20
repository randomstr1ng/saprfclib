"""Connect to SAP using SNC (X.509 certificate authentication) and call STFC_CONNECTION."""

import os
import sys

import saprfclib


def main() -> None:
    # Required env vars:
    #   SAPRFC_ASHOST          SAP application server host
    #   SAPRFC_USER            SAP logon user (can be empty for certificate-only auth)
    #   SAPRFC_PASSWD          SAP logon password (can be empty for certificate-only auth)
    #   SAPRFC_SNC_LIB         Path to GSS-API provider library (e.g. libsapcrypto.so)
    #   SAPRFC_SNC_PARTNERNAME Server's SNC name (e.g. "p:CN=A4H, OU=SAP, O=SAP SE, C=DE")
    missing = [
        v for v in ("SAPRFC_ASHOST", "SAPRFC_SNC_LIB", "SAPRFC_SNC_PARTNERNAME")
        if not os.environ.get(v)
    ]
    if missing:
        print(f"ERROR: required environment variable(s) not set: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    snc_lib = os.environ["SAPRFC_SNC_LIB"]
    snc_partnername = os.environ["SAPRFC_SNC_PARTNERNAME"]
    snc_myname = os.environ.get("SAPRFC_SNC_MYNAME")   # optional: client SNC name

    # snc_qop controls the protection level:
    #   1 = authentication only (no encryption)
    #   2 = authentication + integrity check
    #   3 = authentication + integrity + encryption (privacy) — the default
    snc_qop = int(os.environ.get("SAPRFC_SNC_QOP", "3"))

    # user and passwd can be empty strings when SNC provides the identity via certificate.
    conn = saprfclib.connect(
        ashost=os.environ["SAPRFC_ASHOST"],
        sysnr=int(os.environ.get("SAPRFC_SYSNR", "0")),
        client=os.environ.get("SAPRFC_CLIENT", "100"),
        user=os.environ.get("SAPRFC_USER", ""),
        passwd=os.environ.get("SAPRFC_PASSWD", ""),
        snc_lib=snc_lib,
        snc_partnername=snc_partnername,
        snc_myname=snc_myname,      # None if not set — library uses its default identity
        snc_qop=snc_qop,
    )
    try:
        result = conn.call("STFC_CONNECTION", REQUTEXT="SNC-encrypted call via saprfclib")
        print(f"ECHOTEXT : {result['ECHOTEXT']!r}")
        print(f"RESPTEXT : {result['RESPTEXT']!r}")

        attrs = conn.get_connection_attributes()
        print(f"System ID: {attrs.sys_id}")
        print(f"Partner  : {attrs.partner_host}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
