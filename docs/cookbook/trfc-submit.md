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
    # Confirmation removes the TID from the SAP dedup table (ARFCRSTATE).
    conn.confirm_tid(tid)
    print(f"TID {tid} confirmed — exactly-once delivery guaranteed")

except (saprfclib.RetryExhausted, saprfclib.CommunicationError) as exc:
    # The network failed during the submit (after the library's own retries).
    # Do NOT confirm: the TID stays valid, and a resubmit with it does not run twice.
    print(f"Submit failed — TID {tid} NOT confirmed; safe to resubmit: {exc}")

finally:
    conn.close()
```

## qRFC variant

Pass a `queue` keyword argument to submit to a named inbound queue (1 to 24 characters).
The call lands in the system's inbound queue (transaction SMQ2) and runs in FIFO order within
that queue once the queue is processed; whether that happens automatically depends on the
queue registration (transaction SMQR).

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

except (saprfclib.RetryExhausted, saprfclib.CommunicationError) as exc:
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
| Retry | Re-use the same `tid` and call `call_transactional` again | After a transport failure only |

On a plain TCP connection `call_transactional` already retries a transport failure with the
same TID (`max_retries`, `retry_delay` on `connect()`), then parks the request in `tid_store`
if one is configured and raises `RetryExhausted`; `conn.retry_parked(tid)` sends the parked
request again later. Over SNC there is no automatic retry, and a transport failure raises
`CommunicationError`. In both cases: do **not** confirm the TID — it is safe to resubmit, and
the server does not run a call twice under one TID. An `AbapApplicationError` is never retried:
the server has refused the call.

The function module's parameters are passed as for `call()`: importing, changing and tables
parameters, checked against the server's metadata. Nothing comes back — a tRFC call has no
result — and success is the absence of an exception. The wire format is described in
[tRFC / qRFC / bgRFC](../protocol/trfc.md).
