# tRFC / qRFC Submit

Use transactional RFC (tRFC) when you need exactly-once delivery of an RFC call — the SAP
system deduplicates calls by a transaction ID (TID) so that retries after a network failure
do not cause duplicate execution.  Queue RFC (qRFC) is the same mechanism with an additional
named queue that serialises execution order on the SAP side.

## tRFC lifecycle

```python
import saprfclib

conn = saprfclib.connect(
    ashost="sap-host",
    sysnr=0,
    client="100",
    user="RFC_USER",
    passwd="secret",
)

# Step 1: generate a unique 24-character TID.
tid = conn.create_tid()
print(f"TID: {tid}")           # e.g. "A3F1B2C4D5E6F7A8B9C0D1E2"

try:
    # Step 2: submit the call as tRFC.  The TID is embedded in the wire frame.
    conn.call_transactional(
        "STFC_CONNECTION",
        tid=tid,
        REQUTEXT="transactional call",
    )

    # Step 3: confirm the TID ONLY after verifying the submit succeeded.
    # Confirmation removes the TID from the SAP dedup table (ARFCSSTATE).
    conn.confirm_tid(tid)
    print(f"TID {tid} confirmed — exactly-once delivery guaranteed")

except saprfclib.CommunicationError as exc:
    # If the network fails during submit, do NOT confirm.
    # The TID remains valid for a retry; SAP dedup protects against duplicates.
    print(f"Submit failed — TID {tid} NOT confirmed; safe to retry: {exc}")

finally:
    conn.close()
```

## qRFC variant

Pass a `queue` keyword argument to submit to a named inbound queue.  SAP processes queued
calls in FIFO order within each queue name (transaction SMQ2).

```python
import saprfclib

conn = saprfclib.connect(
    ashost="sap-host",
    sysnr=0,
    client="100",
    user="RFC_USER",
    passwd="secret",
)

qtid = conn.create_tid()

try:
    # queue="MY_QUEUE" makes this a qRFC instead of a plain tRFC.
    conn.call_transactional(
        "STFC_CONNECTION",
        tid=qtid,
        queue="MY_QUEUE",          # Non-None queue name → queued RFC (qRFC)
        REQUTEXT="queued call",
    )
    conn.confirm_tid(qtid)
    print(f"qRFC submitted to queue MY_QUEUE, TID {qtid} confirmed")

except saprfclib.CommunicationError as exc:
    print(f"qRFC submit failed — do NOT confirm: {exc}")

finally:
    conn.close()
```

## Summary of the lifecycle

| Step | API call | When |
|------|----------|------|
| 1. Generate TID | `tid = conn.create_tid()` | Before every tRFC submit |
| 2. Submit | `conn.call_transactional(..., tid=tid)` | Once per TID |
| 3. Confirm | `conn.confirm_tid(tid)` | Only after successful submit |
| Retry | Re-use the same `tid` and call `call_transactional` again | On `CommunicationError` only |

Do **not** confirm the TID if `call_transactional` raises `CommunicationError` — the same
TID is safe to resubmit and SAP will deduplicate.
