"""Start an RFC server that registers with the SAP gateway and handles STFC_CONNECTION calls."""

import os
import sys

import saprfclib
from saprfclib import FunctionDesc, FieldDesc, RFC_IMPORT, RFC_EXPORT


def main() -> None:
    # Required env vars:
    #   SAPRFC_GWHOST    SAP gateway host (defaults to SAPRFC_ASHOST if set)
    #   SAPRFC_GWSERV    Gateway service name/port (default: sapgw00)
    #   SAPRFC_PROGRAM_ID  Program ID registered in SM59 type-T destination
    gwhost = os.environ.get("SAPRFC_GWHOST") or os.environ.get("SAPRFC_ASHOST")
    if not gwhost:
        print(
            "ERROR: SAPRFC_GWHOST (or SAPRFC_ASHOST) not set — gateway host is required",
            file=sys.stderr,
        )
        sys.exit(1)

    program_id = os.environ.get("SAPRFC_PROGRAM_ID")
    if not program_id:
        print("ERROR: SAPRFC_PROGRAM_ID not set — must match the SM59 type-T destination", file=sys.stderr)
        sys.exit(1)

    gwserv = os.environ.get("SAPRFC_GWSERV", "sapgw00")

    # Build a FunctionDesc describing STFC_CONNECTION's parameter interface.
    # In production you can fetch this dynamically via RFC_GET_FUNCTION_INTERFACE.
    stfc_desc = FunctionDesc(
        name="STFC_CONNECTION",
        parameters=[
            FieldDesc(
                name="REQUTEXT",
                rfctype=0,          # RFCTYPE_CHAR
                nuc_length=255,
                nuc_offset=0,
                uc_length=510,      # uc_length = nuc_length * 2 for CHAR fields
                uc_offset=0,
                decimals=0,
                unicode_mode=True,
                direction=RFC_IMPORT,
            ),
            FieldDesc(
                name="ECHOTEXT",
                rfctype=0,
                nuc_length=255,
                nuc_offset=0,
                uc_length=510,
                uc_offset=0,
                decimals=0,
                unicode_mode=True,
                direction=RFC_EXPORT,
            ),
            FieldDesc(
                name="RESPTEXT",
                rfctype=0,
                nuc_length=255,
                nuc_offset=0,
                uc_length=510,
                uc_offset=0,
                decimals=0,
                unicode_mode=True,
                direction=RFC_EXPORT,
            ),
        ],
    )

    server = saprfclib.RfcServer({
        "program_id": program_id,
        "gwhost": gwhost,
        "gwserv": gwserv,
    })

    @server.function("STFC_CONNECTION", stfc_desc)
    def handle_stfc(request: dict) -> dict:
        """Echo the REQUTEXT back as ECHOTEXT and add a RESPTEXT."""
        req_text = request.get("REQUTEXT", "")
        print(f"  Handling STFC_CONNECTION: REQUTEXT={req_text!r}")
        return {
            "ECHOTEXT": req_text,
            "RESPTEXT": f"Handled by saprfclib Python server",
        }

    print(f"RFC server starting: program_id={program_id!r} gwhost={gwhost!r} gwserv={gwserv!r}")
    print("Press Ctrl+C to stop.")

    # serve_forever() blocks until the server stops or the process exits.
    # Call server.stop() from another thread to tear down cleanly.
    server.serve_forever()


if __name__ == "__main__":
    main()
