"""Create an SAP user with BAPI_USER_CREATE1, then read it back with BAPI_USER_GET_DETAIL.

This example exercises the two parameter shapes that a BAPI call leans on hardest:

  * STRUCTURE imports supplied as *partial* dicts — ADDRESS is BAPIADDR3 with some
    fifty fields, and this call sets two of them. Fields left out are sent at their
    ABAP initial value, which is what every SAP program expects.
  * TABLE exports — RETURN comes back as a list of BAPIRET2 rows, and
    BAPI_USER_GET_DETAIL returns PROFILES and ACTIVITYGROUPS the same way.

BAPI_USER_CREATE1 also shows the BAPI transaction model: the BAPI itself only stages
the change, and nothing is persisted until BAPI_TRANSACTION_COMMIT runs.

    WARNING: this example WRITES to the SAP system. It creates a real user account.
    It runs as a dry run by default and prints the payload without sending it; pass
    --commit to actually create the user. Use a test system.

Usage:

    export SAPRFC_ASHOST=... SAPRFC_USER=... SAPRFC_PASSWD=...
    export SAPRFC_NEW_USER_PASSWD='...'          # initial password for the new user

    python 09_bapi_user_create.py ZTESTUSER              # dry run — sends nothing
    python 09_bapi_user_create.py ZTESTUSER --commit     # creates the user
    python 09_bapi_user_create.py ZTESTUSER --show-only  # read an existing user

The calling account needs authorisation for user administration (S_USER_GRP). The new
user's password is read from SAPRFC_NEW_USER_PASSWD and is never printed or logged.
"""

import argparse
import os
import sys

import saprfclib
from saprfclib.connection import Connection

# BAPIRET2.TYPE values. 'E' error, 'A' abort, 'W' warning, 'S'/'I' informational.
ERROR_TYPES = frozenset({"E", "A"})


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


def as_return_rows(ret: object) -> list[dict]:
    """Normalise a BAPI RETURN parameter to a list of rows.

    RETURN is a BAPIRET2 *table* on most BAPIs but a single *structure* on some,
    BAPI_TRANSACTION_COMMIT among them — and which one you get also depends on the
    function interface the metadata reports. Code that checks only one shape does
    not fail when it meets the other; it silently finds no error rows and reports
    success. That is worth being strict about here, because the caller of this
    helper decides whether to tell the operator a user was created.
    """
    if ret is None:
        return []
    if isinstance(ret, dict):
        return [ret]
    if isinstance(ret, list):
        bad = [r for r in ret if not isinstance(r, dict)]
        if bad:
            raise TypeError(f"RETURN table contains a non-row entry: {bad[0]!r}")
        return ret
    raise TypeError(f"unexpected RETURN shape {type(ret).__name__}: {ret!r}")


def rows_failed(rows: list[dict]) -> bool:
    """True if any BAPIRET2 row is an error row."""
    return any(row.get("TYPE", "").strip() in ERROR_TYPES for row in rows)


def print_return_table(rows: list[dict], indent: str = "  ") -> bool:
    """Print a BAPIRET2 RETURN table. Returns True if it contains an error row.

    Every BAPI reports its outcome through this table rather than through an RFC
    exception, so a call that "succeeds" at the protocol level can still have failed
    at the application level. Always inspect it.
    """
    if not rows:
        print(f"{indent}(RETURN table is empty)")
        return False

    failed = False
    for row in rows:
        kind = row.get("TYPE", "").strip()
        message = row.get("MESSAGE", "").strip()
        msg_id = row.get("ID", "").strip()
        number = row.get("NUMBER", "").strip()
        marker = "!!" if kind in ERROR_TYPES else "  "
        print(f"{indent}{marker} [{kind}] {msg_id}{number}: {message}")
        failed = failed or kind in ERROR_TYPES
    return failed


def build_user_payload(username: str, password: str) -> dict:
    """Assemble the BAPI_USER_CREATE1 import parameters.

    Each of ADDRESS / LOGONDATA / PASSWORD is a STRUCTURE import passed as a partial
    dict: only the fields being set appear, and the rest are sent initial.
    """
    return {
        "USERNAME": username,
        # BAPIADDR3 — dozens of fields; two are set here.
        "ADDRESS": {
            "LASTNAME": "Test",
            "FIRSTNAME": "saprfclib",
        },
        # BAPILOGOND — 'S' is a service user, which needs no dialog logon.
        # Use 'A' for a normal dialog user.
        "LOGONDATA": {
            "USTYP": "S",
            "CLASS": "",
        },
        # BAPIPWD — the initial password. Never printed by this script.
        "PASSWORD": {
            "BAPIPWD": password,
        },
    }


def create_user(conn: Connection, username: str, password: str) -> bool:
    """Create the user and commit. Returns True on success."""
    payload = build_user_payload(username, password)

    print(f"Calling BAPI_USER_CREATE1 for {username!r} ...")
    result = conn.call("BAPI_USER_CREATE1", **payload)

    print("RETURN:")
    failed = print_return_table(as_return_rows(result.get("RETURN")))
    if failed:
        print("\nBAPI reported an error — not committing.")
        return False

    # BAPIs stage their work; nothing is persisted until the commit runs.
    print("\nCalling BAPI_TRANSACTION_COMMIT ...")
    commit = conn.call("BAPI_TRANSACTION_COMMIT", WAIT="X")
    # RETURN is a structure here on most systems and a table on others. The check
    # used to look only for a dict, so on a system that answers with a table a
    # failed commit fell straight through to the success message below and the
    # operator was told a user existed that did not.
    commit_rows = as_return_rows(commit.get("RETURN"))
    if rows_failed(commit_rows):
        for row in commit_rows:
            if row.get("TYPE", "").strip() in ERROR_TYPES:
                print(f"  commit failed: {row.get('MESSAGE', '').strip()}")
        return False

    print(f"  committed — user {username!r} created.")
    return True


def show_user(conn: Connection, username: str) -> None:
    """Read a user back with BAPI_USER_GET_DETAIL and print its TABLE exports."""
    print(f"\nCalling BAPI_USER_GET_DETAIL for {username!r} ...")
    detail = conn.call("BAPI_USER_GET_DETAIL", USERNAME=username)

    if print_return_table(as_return_rows(detail.get("RETURN"))):
        return

    address = detail.get("ADDRESS") or {}
    logondata = detail.get("LOGONDATA") or {}
    print("\nADDRESS (STRUCTURE export):")
    print(f"  name      : {address.get('FIRSTNAME', '').strip()} {address.get('LASTNAME', '').strip()}")
    print(f"  full name : {address.get('FULLNAME', '').strip()}")
    print("\nLOGONDATA (STRUCTURE export):")
    print(f"  user type : {logondata.get('USTYP', '').strip()}")
    print(f"  valid from: {logondata.get('GLTGV', '').strip() or '-'}")
    print(f"  valid to  : {logondata.get('GLTGB', '').strip() or '-'}")

    # TABLE exports — these come back as lists of row dicts.
    profiles = detail.get("PROFILES") or []
    print(f"\nPROFILES (TABLE export, {len(profiles)} row(s)):")
    for row in profiles:
        print(f"  {row.get('BAPIPROF', '').strip():<14} {row.get('BAPIPTEXT', '').strip()}")
    if not profiles:
        print("  (none)")

    roles = detail.get("ACTIVITYGROUPS") or []
    print(f"\nACTIVITYGROUPS (TABLE export, {len(roles)} row(s)):")
    for row in roles:
        print(f"  {row.get('AGR_NAME', '').strip():<32} {row.get('AGR_TEXT', '').strip()}")
    if not roles:
        print("  (none)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("username", help="user name to create (uppercase, max 12 chars)")
    parser.add_argument(
        "--commit",
        action="store_true",
        help="actually create the user; without this the script is a dry run",
    )
    parser.add_argument(
        "--show-only",
        action="store_true",
        help="skip creation and just read the user back with BAPI_USER_GET_DETAIL",
    )
    args = parser.parse_args()

    username = args.username.upper()
    if len(username) > 12:
        print("ERROR: SAP user names are at most 12 characters", file=sys.stderr)
        sys.exit(1)

    password = os.environ.get("SAPRFC_NEW_USER_PASSWD", "")
    if args.commit and not password:
        print("ERROR: set SAPRFC_NEW_USER_PASSWD to the initial password for the new user",
              file=sys.stderr)
        sys.exit(1)

    if not args.commit and not args.show_only:
        # Dry run: show what would be sent, with the password masked.
        payload = build_user_payload(username, password or "<unset>")
        payload["PASSWORD"] = {"BAPIPWD": "***"}
        print("DRY RUN — nothing will be sent. BAPI_USER_CREATE1 would be called with:\n")
        for key, value in payload.items():
            print(f"  {key} = {value!r}")
        print("\nRe-run with --commit to create the user, or --show-only to read an existing one.")
        return

    conn = connect_from_env()
    try:
        attrs = conn.get_connection_attributes()
        print(f"Connected to {attrs.sys_id} as {os.environ['SAPRFC_USER']}\n")

        if args.show_only:
            show_user(conn, username)
            return

        if create_user(conn, username, password):
            show_user(conn, username)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
