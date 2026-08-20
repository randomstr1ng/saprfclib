"""Demonstrate concurrent SAP RFC calls using a ConnectionPool shared across threads."""

import os
import sys
import threading

import saprfclib


def main() -> None:
    # Required env vars: SAPRFC_ASHOST, SAPRFC_USER, SAPRFC_PASSWD
    missing = [v for v in ("SAPRFC_ASHOST", "SAPRFC_USER", "SAPRFC_PASSWD") if not os.environ.get(v)]
    if missing:
        print(f"ERROR: required environment variable(s) not set: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    params = {
        "ashost": os.environ["SAPRFC_ASHOST"],
        "sysnr": int(os.environ.get("SAPRFC_SYSNR", "0")),
        "client": os.environ.get("SAPRFC_CLIENT", "100"),
        "user": os.environ["SAPRFC_USER"],
        "passwd": os.environ["SAPRFC_PASSWD"],
    }

    # Pre-warm 2 connections; grow lazily up to 5 under load.
    pool = saprfclib.ConnectionPool(params, min_size=2, max_size=5)
    results: list[str] = []
    lock = threading.Lock()

    def worker(text: str) -> None:
        # pool.acquire() is a context manager — the connection is returned to the pool
        # automatically when the with block exits, even on exception.
        with pool.acquire(timeout=30.0) as conn:
            result = conn.call("STFC_CONNECTION", REQUTEXT=text)
            echo = result["ECHOTEXT"]
            with lock:
                results.append(echo)
                print(f"  Thread got ECHOTEXT={echo!r}")

    try:
        threads = [threading.Thread(target=worker, args=(f"message-{i}",)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        print(f"All {len(results)} calls completed successfully.")
    finally:
        pool.close()


if __name__ == "__main__":
    main()
