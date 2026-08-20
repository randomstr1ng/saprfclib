"""Read rows from an SAP table using RFC_READ_TABLE with TABLE input and output parameters."""

import os
import sys

import saprfclib


def main() -> None:
    # Required env vars: SAPRFC_ASHOST, SAPRFC_USER, SAPRFC_PASSWD
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
        # FIELDS is a TABLE input parameter: list of dicts with FIELDNAME key.
        # DATA is a TABLE output parameter: list of dicts where WA contains the row string.
        result = conn.call(
            "RFC_READ_TABLE",
            QUERY_TABLE="T001",        # Company codes table
            DELIMITER="|",             # Delimiter between field values in each WA row
            ROWCOUNT=10,               # Maximum rows to return
            FIELDS=[
                {"FIELDNAME": "MANDT"},
                {"FIELDNAME": "BUKRS"},
                {"FIELDNAME": "BUTXT"},
            ],
        )

        rows = result["DATA"]
        print(f"RFC_READ_TABLE returned {len(rows)} row(s) from T001:")
        for row in rows:
            print(f"  {row['WA']}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
