"""Connect to an SAP system and call STFC_CONNECTION to verify the connection."""

import os
import sys

import saprfclib


def main() -> None:
    # Read required connection parameters from environment variables.
    # Set these before running:
    #   export SAPRFC_ASHOST=your-sap-host
    #   export SAPRFC_USER=RFC_USER
    #   export SAPRFC_PASSWD=your-password
    missing = [v for v in ("SAPRFC_ASHOST", "SAPRFC_USER", "SAPRFC_PASSWD") if not os.environ.get(v)]
    if missing:
        print(f"ERROR: required environment variable(s) not set: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    conn = saprfclib.connect(
        ashost=os.environ["SAPRFC_ASHOST"],
        sysnr=int(os.environ.get("SAPRFC_SYSNR", "0")),
        client=os.environ.get("SAPRFC_CLIENT", "100"),
        user=os.environ["SAPRFC_USER"],
        passwd=os.environ["SAPRFC_PASSWD"],
    )
    try:
        result = conn.call("STFC_CONNECTION", REQUTEXT="Hello from saprfclib!")
        print(f"ECHOTEXT : {result['ECHOTEXT']!r}")
        print(f"RESPTEXT : {result['RESPTEXT']!r}")

        # Print connection attributes returned by the SAP system.
        attrs = conn.get_connection_attributes()
        print(f"System ID: {attrs.sys_id}")
        print(f"Partner  : {attrs.partner_host}")
        print(f"Unicode  : {attrs.unicode_mode}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
