"""Connect to SAP BTP via WebSocket RFC (wRFC) and call STFC_CONNECTION over TLS."""

import os
import sys

import saprfclib


def main() -> None:
    # Required env vars:
    #   SAPRFC_WSHOST   WebSocket RFC host (e.g. your-system.abap.eu10.hana.ondemand.com)
    #   SAPRFC_USER     SAP logon user (often an email address for BTP)
    #   SAPRFC_PASSWD   SAP logon password
    #
    # Optional env vars:
    #   SAPRFC_WSPORT           WebSocket port (default: 443)
    #   SAPRFC_WS_PATH          ICF path (default: /sap/bc/rfc?sap-apc-stateful=true)
    #   SAPRFC_CLIENT           SAP client (default: 100)
    #   SAPRFC_WS_PROXY_HOST    HTTP CONNECT proxy host (omit if no proxy needed)
    #   SAPRFC_WS_PROXY_PORT    HTTP CONNECT proxy port (default: 3128)
    missing = [
        v for v in ("SAPRFC_WSHOST", "SAPRFC_USER", "SAPRFC_PASSWD")
        if not os.environ.get(v)
    ]
    if missing:
        print(f"ERROR: required environment variable(s) not set: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    wshost = os.environ["SAPRFC_WSHOST"]
    wsport = int(os.environ.get("SAPRFC_WSPORT", "443"))
    ws_path = os.environ.get("SAPRFC_WS_PATH", "/sap/bc/rfc?sap-apc-stateful=true")

    # Optional HTTP CONNECT proxy for environments that route HTTPS through a forward proxy.
    ws_proxy_host = os.environ.get("SAPRFC_WS_PROXY_HOST")
    ws_proxy_port = int(os.environ.get("SAPRFC_WS_PROXY_PORT", "3128")) if ws_proxy_host else None

    # ashost is required by connect() but is not used when wshost is set.
    conn = saprfclib.connect(
        ashost="dummy",
        sysnr=0,
        client=os.environ.get("SAPRFC_CLIENT", "100"),
        user=os.environ["SAPRFC_USER"],
        passwd=os.environ["SAPRFC_PASSWD"],
        wshost=wshost,
        wsport=wsport,
        ws_path=ws_path,
        ws_proxy_host=ws_proxy_host,    # None if not set (no proxy)
        ws_proxy_port=ws_proxy_port,    # None if not set
        ws_tls_verify=True,             # Set False only for dev/self-signed certs
    )
    try:
        result = conn.call("STFC_CONNECTION", REQUTEXT="Hello from saprfclib wRFC!")
        print(f"ECHOTEXT : {result['ECHOTEXT']!r}")
        print(f"RESPTEXT : {result['RESPTEXT']!r}")

        attrs = conn.get_connection_attributes()
        print(f"System ID: {attrs.sys_id}")
        print(f"Partner  : {attrs.partner_host}")
        print(f"Unicode  : {attrs.unicode_mode}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
