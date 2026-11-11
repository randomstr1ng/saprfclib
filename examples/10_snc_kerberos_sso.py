"""Log on with Kerberos SNC single sign-on (Active Directory) and call STFC_CONNECTION.

No password is sent to SAP: the SAP user is the one whose SNC name (SU01) matches the
Kerberos principal, e.g. p:CN=ALICE@EXAMPLE.COM. No SAP library is needed.

Where the Kerberos ticket comes from:
  - Windows: the logon session of the signed-in domain user (nothing to configure).
  - Linux/macOS: the ticket cache from kinit or a domain login (KRB5CCNAME).
  - Or explicitly, with SAPRFC_KRB5_USER plus SAPRFC_KRB5_PASSWORD or SAPRFC_KRB5_KEYTAB
    (and SAPRFC_KRB5_KDC unless krb5.conf names the realm's KDC).
"""

import os
import sys

import saprfclib
from saprfclib.krb5 import KerberosLogin


def main() -> None:
    # Required env vars:
    #   SAPRFC_ASHOST                SAP application server host
    #   SAPRFC_SNC_KRB5_PARTNERNAME  SAP's Kerberos SNC name, as in SAP Logon,
    #                                e.g. "p:CN=A4H@EXAMPLE.COM" (SPN SAP/A4H)
    # Optional:
    #   SAPRFC_SYSNR, SAPRFC_CLIENT
    #   SAPRFC_KRB5_USER             e.g. "alice@EXAMPLE.COM"
    #   SAPRFC_KRB5_PASSWORD         password login instead of the logon session / cache
    #   SAPRFC_KRB5_KEYTAB           keytab login instead of the logon session / cache
    #   SAPRFC_KRB5_KDC              KDC host[:port] when a ticket must be requested
    missing = [v for v in ("SAPRFC_ASHOST", "SAPRFC_SNC_KRB5_PARTNERNAME") if not os.environ.get(v)]
    if missing:
        print(f"ERROR: required environment variable(s) not set: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    user = os.environ.get("SAPRFC_KRB5_USER")
    password = os.environ.get("SAPRFC_KRB5_PASSWORD")
    keytab = os.environ.get("SAPRFC_KRB5_KEYTAB")
    kdc = os.environ.get("SAPRFC_KRB5_KDC")
    if password or keytab or kdc or user:
        # Never log or print the password.
        kerberos: bool | KerberosLogin = KerberosLogin(
            principal=user, password=password, keytab=keytab, kdc=kdc
        )
    else:
        kerberos = True  # Windows logon session, else the ticket cache

    with saprfclib.connect(
        ashost=os.environ["SAPRFC_ASHOST"],
        sysnr=os.environ.get("SAPRFC_SYSNR", "00"),
        client=os.environ.get("SAPRFC_CLIENT", "100"),
        snc_partnername=os.environ["SAPRFC_SNC_KRB5_PARTNERNAME"],
        snc_kerberos=kerberos,
        snc_sso=True,  # log on as the user mapped to the Kerberos principal
    ) as conn:
        result = conn.call("STFC_CONNECTION", REQUTEXT="Kerberos SSO via saprfclib")
        print(f"ECHOTEXT : {result['ECHOTEXT']!r}")
        info = conn.call("RFC_SYSTEM_INFO")["RFCSI_EXPORT"]
        print(f"System   : {info['RFCSYSID']}  host {info['RFCHOST']}")


if __name__ == "__main__":
    main()
