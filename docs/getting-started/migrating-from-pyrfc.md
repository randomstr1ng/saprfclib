# Migrating from pyrfc

`pyrfc` wraps SAP's NetWeaver RFC SDK. `saprfclib` reimplements the protocol, so the
SDK, the C compiler and the `LD_LIBRARY_PATH` go away. That is the reason to migrate;
this page is the how.

Most of a port is mechanical. The traps are at the end — read those even if you skim
the tables.

## Connecting

```python
# pyrfc
from pyrfc import Connection
conn = Connection(ashost="10.0.0.1", sysnr="00", client="001",
                  user="DEVELOPER", passwd=secret)

# saprfclib
import saprfclib
conn = saprfclib.connect(ashost="10.0.0.1", sysnr="00", client="001",
                         user="DEVELOPER", passwd=secret)
```

The common connection parameters keep their names: `ashost`, `sysnr`, `client`, `user`,
`passwd`, `lang`, `saprouter`, `mshost`, `msserv`, `sysid`, `group`.

| pyrfc | saprfclib | Note |
|---|---|---|
| `Connection(...)` | `saprfclib.connect(...)` | a function, not a class |
| `conn.call("FM", **kw)` | `conn.call("FM", **kw)` | unchanged |
| `conn.ping()` | `conn.ping()` | a method in both — **call it**, see below |
| `conn.close()` | `conn.close()` | or use a `with` block |
| `conn.get_function_description(f)` | `saprfclib.get_function_desc(conn, f)` | different shape, see below |
| `snc_mode="1"` | *(removed)* | passing `snc_lib` is the switch |
| `snc_qop="3"` | `snc_qop=3` | `int`, not `str` |
| `snc_sso="1"` | `snc_sso=True` | `bool`, not `str` |
| `snc_lib=...` | `snc_lib=...` | unchanged |

`saprfclib.connect()` also takes `port`, which pyrfc had no equivalent for: when the
gateway is not reachable at `3300 + sysnr` — behind NAT, a port-forward or a jump host —
pass it explicitly. Leave it unset and the convention applies as before.

### Context manager

`Connection` supports `with`, so the `try/finally` goes away:

```python
with saprfclib.connect(...) as conn:
    result = conn.call("STFC_CONNECTION", REQUTEXT="hello")
```

## Exceptions

The class names differ in capitalisation, which makes a missed rename **silent** rather
than an `ImportError` — if `pyrfc` is still installed alongside, and during a migration
it usually is, the old name resolves against it and your `except` clause quietly stops
matching.

```python
from saprfclib.compat import ABAPApplicationError, ABAPRuntimeError, LogonError
```

`saprfclib.compat` exists for exactly this. Import it, get the port working, then
rewrite to the real names at your own pace. It is never re-exported from the package
root, so nothing acquires these spellings by accident.

| pyrfc | saprfclib | Exact? |
|---|---|---|
| `ABAPApplicationError` | `AbapApplicationError` | yes |
| `ABAPRuntimeError` | `AbapSystemFailure` | yes |
| `CommunicationError` | `CommunicationError` | same name |
| `ExternalRuntimeError` | `SapRfcError` | **widened** |
| `LogonError` | `CommunicationError` | **widened** |

The two widened rows matter. `ExternalRuntimeError` was pyrfc's wrapper for failures
inside the SDK — a category that cannot exist here, because there is no SDK. And
`LogonError` has no direct equivalent: depending on how far the handshake got, a
rejected logon surfaces as `CommunicationError` or `AbapSystemFailure`. If your handler
means "the logon did not work", catch `SapRfcError`.

## Return values

Both libraries decode to real Python types, and `saprfclib` keeps that: `datetime.date`
for DATS, `datetime.time` for TIMS, `decimal.Decimal` for BCD and DECFLOAT, `bytes` for
RAW and XSTRING.

If the result is going into something JSON-shaped, `saprfclib.jsonable()` normalises a
whole result in one pass — dates and times to ISO-8601, `Decimal` to `str`, `bytes` to
hex:

```python
import json
json.dumps(saprfclib.jsonable(conn.call("RFC_READ_TABLE", QUERY_TABLE="T000")))
```

`Decimal` becomes a string rather than a float deliberately: `float(Decimal("0.1"))` is
not `0.1`, and an amount that survived the wire intact should not lose precision leaving
the library.

## Function metadata

`pyrfc.Connection.get_function_description(name)` returns parameters carrying `name`,
`parameter_type`, `direction`, `optional`, `default_value` and `parameter_text` — the
six fields a dynamic UI needs.

`saprfclib` returns a `FunctionDesc` whose `FieldDesc` entries carry the same
information under different names, plus the byte-layout numbers the codec uses:

```python
import saprfclib

desc = saprfclib.get_function_desc(conn, "BAPI_USER_GET_DETAIL")
for field in desc.parameters:
    required = not field.optional
    label = field.param_text or field.name
    prefill = field.default_value
```

| pyrfc | saprfclib |
|---|---|
| `name` | `FieldDesc.name` |
| `parameter_type` | `FieldDesc.rfctype` (an `RFCTYPE_*` int) |
| `direction` | `FieldDesc.direction` (an `RFC_*` int) |
| `optional` | `FieldDesc.optional` |
| `default_value` | `FieldDesc.default_value` (`None` when unset) |
| `parameter_text` | `FieldDesc.param_text` (`None` when unset) |

`default_value` and `param_text` are `None` rather than `""` when the server sent
nothing, so "no default" is distinguishable from "the default is empty".

## Two traps

### `conn.ping` is a method in both libraries

```python
if conn.ping:        # ← always true. A bound method is truthy.
    ...
```

This is a health check that can never fail, and it reads as one that works. It was
equally wrong against pyrfc, so a migration will not surface it — but a migration is
when someone reads these call sites again, which makes it the moment to fix them:

```python
if conn.ping():      # ← actually pings
    ...
```

### Undeclared keyword arguments are dropped, not raised

`strict_params` is set on `connect()` and applies to every `call()` on that connection.
It defaults to `False`: a keyword the function's interface does not declare is dropped
with a warning rather than raising. This matches what pyrfc callers expect, and it is
what makes calling the same function module across releases with differing interfaces
survivable.

If you would rather find out immediately, pass `strict_params=True` on `connect()`.

## What has no equivalent yet

- **Server-side callbacks registered through pyrfc's `Server`** — `saprfclib` has its
  own `RfcServer`, with a different registration API rather than a drop-in one.
- **SNC without a GSS library.** Both libraries need one; `saprfclib` loads it through
  `snc_lib` exactly as pyrfc does.
