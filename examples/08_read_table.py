"""Read a table with RFC_READ_TABLE, using every TABLE parameter it exposes.

RFC_READ_TABLE is the densest TABLE-parameter workout in the standard SAP function
library: FIELDS and OPTIONS go in as tables, DATA and FIELDS come back as tables.
It is also the canonical case for partial row dicts — you set FIELDNAME on a FIELDS
row and leave OFFSET, LENGTH, TYPE and FIELDTEXT for the server to fill in.

Where 02_table_params.py shows the minimal call, this example uses the FIELDS
metadata the server returns to split each delimited DATA row back into named
columns, and adds a WHERE clause through the OPTIONS table.

Read-only — this example never writes to the SAP system.
"""

import os
import sys

import saprfclib
from saprfclib.connection import Connection

# RFC_READ_TABLE returns each row as one delimited string in the WA field. Pick a
# delimiter that will not occur inside the data itself.
DELIMITER = "|"


def connect_from_env() -> Connection:
    """Open a connection from SAPRFC_* environment variables."""
    missing = [v for v in ("SAPRFC_ASHOST", "SAPRFC_USER", "SAPRFC_PASSWD") if not os.environ.get(v)]
    if missing:
        print(f"ERROR: required environment variable(s) not set: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    return saprfclib.connect(
        ashost=os.environ["SAPRFC_ASHOST"],
        sysnr=int(os.environ.get("SAPRFC_SYSNR", "0")),
        client=os.environ.get("SAPRFC_CLIENT", "100"),
        user=os.environ["SAPRFC_USER"],
        passwd=os.environ["SAPRFC_PASSWD"],
        lang=os.environ.get("SAPRFC_LANG", "E"),
    )


def read_table(
    conn: Connection,
    table: str,
    fields: list[str],
    where: str = "",
    rowcount: int = 20,
) -> list[dict[str, str]]:
    """Return rows of `table` as dicts keyed by field name.

    `fields` are passed as partial FIELDS rows — only FIELDNAME is set, and the
    server fills in OFFSET / LENGTH / TYPE / FIELDTEXT on the way back. `where` is
    an ABAP WHERE clause fragment (without the WHERE keyword), split across OPTIONS
    rows because each row's TEXT field holds at most 72 characters.
    """
    params = {
        "QUERY_TABLE": table,
        "DELIMITER": DELIMITER,
        "ROWCOUNT": rowcount,
        # TABLE input: partial row dicts. Everything but FIELDNAME is left unset.
        "FIELDS": [{"FIELDNAME": name} for name in fields],
    }
    if where:
        # OPTIONS rows are RFC_DB_OPT, whose TEXT field is CHAR(72). Longer clauses
        # must be chunked; the server concatenates the rows back together.
        params["OPTIONS"] = [{"TEXT": where[i : i + 72]} for i in range(0, len(where), 72)]

    result = conn.call("RFC_READ_TABLE", **params)

    # FIELDS comes back describing the columns actually returned, in order. Use it
    # rather than the requested list so the mapping stays correct even if the
    # server reorders or rejects a column.
    columns = [row["FIELDNAME"].strip() for row in result["FIELDS"]]

    rows: list[dict[str, str]] = []
    for row in result["DATA"]:
        values = [v.strip() for v in row["WA"].split(DELIMITER)]
        rows.append(dict(zip(columns, values, strict=False)))
    return rows


def main() -> None:
    conn = connect_from_env()
    try:
        print(f"Connected to {conn.get_connection_attributes().sys_id}, ping={conn.ping()}\n")

        # --- 1. Plain read: clients ------------------------------------------ #
        # T000 is the client table — present on every SAP system, so it makes a
        # dependable first query. MANDT is the client number, MTEXT its name.
        print("T000 — clients")
        for row in read_table(conn, "T000", ["MANDT", "MTEXT", "ORT01", "MWAER"], rowcount=10):
            print(f"  {row['MANDT']:<6} {row['MTEXT']:<28} {row['ORT01']:<20} {row['MWAER']}")

        # --- 2. Filtered read via the OPTIONS table -------------------------- #
        # Reading USR02 needs table-display authorisation (S_TABU_DIS/S_TABU_NAM),
        # which the RFC account may not have. Report and carry on rather than
        # aborting the rest of the example.
        print("\nUSR02 — non-dialog users (WHERE clause through OPTIONS)")
        try:
            users = read_table(
                conn,
                "USR02",
                ["BNAME", "USTYP", "CLASS", "TRDAT"],
                where="USTYP <> 'A'",
                rowcount=15,
            )
            if users:
                for row in users:
                    print(f"  {row['BNAME']:<14} type={row['USTYP']:<2} group={row['CLASS']:<12} "
                          f"last logon={row['TRDAT'] or '-'}")
            else:
                print("  (no rows matched)")
        except saprfclib.SapRfcError as exc:
            print(f"  skipped: {exc}")

        # --- 3. Column metadata the server returned -------------------------- #
        print("\nColumn layout reported by the server for T000:")
        meta = conn.call(
            "RFC_READ_TABLE",
            QUERY_TABLE="T000",
            DELIMITER=DELIMITER,
            ROWCOUNT=1,
            FIELDS=[{"FIELDNAME": "MANDT"}, {"FIELDNAME": "MTEXT"}],
        )
        for col in meta["FIELDS"]:
            print(f"  {col['FIELDNAME']:<12} offset={col['OFFSET']:>4} "
                  f"len={col['LENGTH']:>4} type={col['TYPE']}  {col['FIELDTEXT']}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
