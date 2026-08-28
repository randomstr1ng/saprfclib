# Error Handling

All exceptions raised by saprfclib inherit from `saprfclib.SapRfcError`, so you can
catch everything with a single `except saprfclib.SapRfcError` or handle specific
error types with the most-specific exception first.

## Exception hierarchy

```
SapRfcError
├── AbapApplicationError   — ABAP application exception from the function module
├── AbapSystemFailure      — ABAP short dump or system failure on the backend
├── CommunicationError     — network or protocol-level failure
├── TransactionalError     — tRFC / qRFC / bgRFC lifecycle error
├── SncError               — SNC GSS-API handshake or frame error
├── WebSocketError         — WebSocket upgrade, framing, or TLS error
└── PoolTimeoutError       — ConnectionPool.acquire() timed out
```

## Exception details

### SapRfcError

Base class for all saprfclib exceptions. Use as a catch-all when you want a single
handler for any RFC error.

### AbapApplicationError

Raised when the called ABAP function module raises an application exception.
Carries the ABAP exception metadata from the RFC protocol.

| Attribute | Type | Description |
|-----------|------|-------------|
| `key` | `str \| None` | Exception name (e.g. `"COMMUNICATION_FAILURE"`) |
| `message` | `str \| None` | Human-readable error text |
| `msg_class` | `str \| None` | ABAP message class |
| `msg_type` | `str \| None` | ABAP message type (E/W/I/S) |
| `msg_number` | `str \| None` | ABAP message number |
| `msg_v1`..`msg_v4` | `str \| None` | ABAP message variables |

### AbapSystemFailure

Raised when ABAP generates a short dump or a system-level failure occurs on
the backend (e.g. a program error, stack overflow, or system exception).

| Attribute | Type | Description |
|-----------|------|-------------|
| `message` | `str \| None` | System failure description |

### CommunicationError

Raised when a network or protocol-level failure prevents the call from
completing. Wraps the underlying transport error when available.

| Attribute | Type | Description |
|-----------|------|-------------|
| `message` | `str \| None` | Description of the failure |
| `original_exception` | `BaseException \| None` | Underlying `OSError` or protocol error |

### TransactionalError

Raised when a tRFC, qRFC, or bgRFC operation fails — for example, a duplicate
TID, a TID store failure, or a protocol invariant violation.

| Attribute | Type | Description |
|-----------|------|-------------|
| `message` | `str \| None` | Description of the transactional failure |

### SncError

Raised when the SNC GSS-API handshake or message protection fails. Carries the
OM_uint32 major and minor GSS status codes.

| Attribute | Type | Description |
|-----------|------|-------------|
| `message` | `str \| None` | Human-readable description |
| `major` | `int \| None` | GSS major status code |
| `minor` | `int \| None` | GSS minor status code |

### WebSocketError

Raised when the WebSocket upgrade fails (bad status, wrong
`Sec-WebSocket-Accept` header, refused proxy CONNECT), or when a WebSocket
framing or close error occurs.

| Attribute | Type | Description |
|-----------|------|-------------|
| `message` | `str \| None` | Description of the WebSocket error |

### PoolTimeoutError

Raised when `ConnectionPool.acquire()` cannot obtain a connection before the
timeout elapses. Carries diagnostic counters for debugging pool exhaustion.

| Attribute | Type | Description |
|-----------|------|-------------|
| `waited` | `float` | Seconds blocked before giving up |
| `discarded` | `int` | Dead connections replaced during the wait |
| `active` | `int` | Connections currently lent out |
| `idle` | `int` | Connections sitting idle |
| `max_size` | `int` | Pool's hard ceiling on total connections |

## Argument errors are not `SapRfcError`

Two failures happen **before** anything reaches the server, so they are plain
`ValueError` and are not caught by `except saprfclib.SapRfcError`:

- a keyword argument the function interface does not declare, when the connection
  was opened with `strict_params=True`
- an invalid `lang` code

```python
try:
    conn.call("SXPG_STEP_XPG_START", COMMANDNAME="LIST_DB2DUMP", MXROW=100)
except ValueError as exc:
    print(f"bad arguments, nothing was sent: {exc}")
```

!!! warning "By default this does not raise at all"
    `strict_params` defaults to `False`, so an undeclared argument is **dropped** and
    the call proceeds without it. The function then runs differently from what you
    asked — above, `SXPG_STEP_XPG_START` runs with no row limit — and the response
    contains nothing to indicate an argument went missing.

    Each drop is logged: `WARNING` the first time a given function drops a given set
    of names, `DEBUG` on repeats. If results ever look wrong, check the log for
    `dropping parameter(s)` before suspecting the server.

    Use `strict_params=True` when a dropped argument would change the result. See
    [Connection Options](connection-options.md#unknown-keyword-arguments).

## Empty or aborted responses

A response carrying no return code raises `CommunicationError`. This usually means
the gateway terminated the conversation, and **the connection is no longer usable** —
discard it rather than retrying on the same one. Later calls on a torn-down
conversation fail with `Conversation NNN not found`.

## Recommended pattern

Handle the most-specific exceptions first and use `SapRfcError` as the
final catch-all. Always close the connection in a `finally` block — `close()`
is safe to call in any state, including after an error.

```python
import saprfclib

conn = saprfclib.connect(
    ashost="your-sap-host",
    sysnr=0,
    client="100",
    user="RFC_USER",
    passwd="secret",
)

try:
    result = conn.call("STFC_CONNECTION", REQUTEXT="test")
    print(result["ECHOTEXT"])

except saprfclib.AbapApplicationError as exc:
    # ABAP raised an application exception (e.g. wrong input, missing auth)
    print(f"Application error: key={exc.key} message={exc.message}")

except saprfclib.AbapSystemFailure as exc:
    # ABAP short dump or backend system failure
    print(f"System failure: {exc.message}")

except saprfclib.CommunicationError as exc:
    # Network drop, protocol error, timeout
    print(f"Communication error: {exc.message}")
    if exc.original_exception:
        print(f"  Caused by: {exc.original_exception}")

except saprfclib.SapRfcError as exc:
    # Catch-all for TransactionalError, SncError, WebSocketError, PoolTimeoutError
    print(f"RFC error: {exc}")

finally:
    conn.close()
```

## Checking exception attributes safely

Any attribute on `AbapApplicationError` may be `None` if the wire error did not
include that field. Use `or ""` or `if exc.key:` guards:

```python
except saprfclib.AbapApplicationError as exc:
    key = exc.key or "(no key)"
    msg = exc.message or "(no message)"
    print(f"{key}: {msg}")
```
