"""Submit a transactional RFC (tRFC) and a queued RFC (qRFC) with TID lifecycle management."""

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
        # --- tRFC example ---
        # Step 1: generate a unique 24-character TID.
        tid = conn.create_tid()
        print(f"tRFC TID: {tid}")

        try:
            # Step 2: submit the function module as a transactional call.
            conn.call_transactional(
                "STFC_CONNECTION",
                tid=tid,
                REQUTEXT="tRFC example from saprfclib",
            )
            # Step 3: confirm the TID only after the submit succeeded.
            # Confirmation removes the TID from SAP's dedup table (ARFCSSTATE).
            conn.confirm_tid(tid)
            print(f"tRFC TID {tid} submitted and confirmed.")
        except saprfclib.CommunicationError as exc:
            # Do NOT confirm if submit failed — keep the TID for a safe retry.
            print(f"tRFC submit failed; TID NOT confirmed (safe to retry): {exc}")

        # --- qRFC example ---
        # A qRFC uses the same API with an additional queue name.
        queue = os.environ.get("SAPRFC_QUEUE", "MY_QUEUE")
        qtid = conn.create_tid()
        print(f"qRFC TID: {qtid}  queue: {queue}")

        try:
            conn.call_transactional(
                "STFC_CONNECTION",
                tid=qtid,
                queue=queue,               # Non-None queue name → queued RFC (qRFC)
                REQUTEXT="qRFC example from saprfclib",
            )
            conn.confirm_tid(qtid)
            print(f"qRFC TID {qtid} submitted to queue {queue!r} and confirmed.")
        except saprfclib.CommunicationError as exc:
            print(f"qRFC submit failed; TID NOT confirmed (safe to retry): {exc}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
