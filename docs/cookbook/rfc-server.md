# RFC Server

Use `RfcServer` to expose a Python function as an RFC-callable function module that SAP can
invoke.  The server registers with the SAP gateway using a program ID configured in SM59, then
dispatches inbound calls to decorated handler functions.

## Minimal RFC server for STFC_CONNECTION

```python
import saprfclib
from saprfclib import FunctionDesc, FieldDesc, RFC_IMPORT, RFC_EXPORT

# Build a FunctionDesc that describes the STFC_CONNECTION parameter interface.
# In production you can fetch this from a live system via RFC_GET_FUNCTION_INTERFACE.
stfc_desc = FunctionDesc(
    name="STFC_CONNECTION",
    parameters=[
        FieldDesc(
            name="REQUTEXT",
            rfctype=0,          # RFCTYPE_CHAR
            nuc_length=255,
            nuc_offset=0,
            uc_length=510,
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

# Create the server with gateway registration parameters.
# program_id must match the SM59 type-T destination configured in your SAP system.
server = saprfclib.RfcServer({
    "program_id": "MY_PYTHON_RFC",
    "gwhost": "sap-host",
    "gwserv": "sapgw00",
})

# Decorate a handler function to handle inbound calls to STFC_CONNECTION.
# The handler receives a dict keyed by IMPORT parameter names.
# It must return a dict keyed by EXPORT parameter names.
@server.function("STFC_CONNECTION", stfc_desc)
def handle_stfc(request: dict) -> dict:
    req_text = request.get("REQUTEXT", "")
    return {
        "ECHOTEXT": req_text,
        "RESPTEXT": f"Handled by saprfclib Python server (received: {req_text!r})",
    }

# Optional: register an authentication callback.
# Return True to allow the call, False to deny it.
# Inbound credentials are never logged by saprfclib.
def check_auth(user: str | None = None, password: str | None = None) -> bool:
    # user is None when the caller sent no credentials
    return (user or "").upper() == "RFC_USER"

server.set_authentication_check(check_auth)

# serve_forever() blocks in a daemon thread until server.stop() is called
# from another thread, or the process exits.
print("RFC server starting — press Ctrl+C to stop")
server.serve_forever()
```

## Notes

- `FunctionDesc` and `FieldDesc` are importable directly from `saprfclib` (top-level public API).
- `rfctype=0` is `RFCTYPE_CHAR`.  See [Serialization](../protocol/serialization.md) for the full type-code table, or the ABAP DDIC for a specific field.
- `nuc_length` is the character count in the non-Unicode encoding; `uc_length` is double
  that value for UTF-16 (2 bytes per code unit).
- The `RESPTEXT` export is sent back to the SAP caller automatically when the handler returns.
- Deep parameters (a structure with STRING, XSTRING or table components, or a table-typed
  IMPORTING/EXPORTING/CHANGING parameter) arrive as nested dicts and lists, and are returned
  the same way, provided the `FunctionDesc` carries their layout. The simplest way to get one
  is to fetch it from the system with a client connection.
- For tRFC/qRFC inbound calls the handler still needs a `FunctionDesc` to see its
  parameters: without one it is called with `{}`. Only a duplicate TID skips the handler
  before the request is decoded.

## Receiving bgRFC units

ABAP sends a bgRFC unit to a registered server when the unit's destination points at it.
`RfcServer` runs the unit's calls with the handlers registered for them, in order, and
records the unit in its unit store so a unit ABAP sends again is not run twice:

```python
from saprfclib.stores import UnitState

server.install_unit_handlers(
    check=lambda unit_id, unit_type: 16 if db.unit_done(unit_id) else 0,  # 16: already ran
    commit=lambda unit_id, unit_type: db.commit_unit(unit_id),      # all calls ran
    rollback=lambda unit_id, unit_type: db.rollback_unit(unit_id),  # a call raised
    confirm=lambda unit_id, unit_type: db.forget_unit(unit_id),     # ABAP confirmed it
)
```

`unit_type` is `'T'` or `'Q'`. Every call of the unit needs a handler with a `FunctionDesc`,
as for an ordinary inbound call. If a handler raises, the unit stops there, `rollback` runs,
and ABAP is told the unit failed: ABAP keeps it and sends it again later. `confirm` runs when
ABAP confirms the unit, in a separate call after the unit has run. Without callbacks, the unit
store (`set_unit_store`, in memory by default) does the bookkeeping.

On the ABAP side, the registered destination (SM59, type T) needs the bgRFC protocol
selected, must be registered for outbound bgRFC (SBGRFCCONF), and the system needs a bgRFC
supervisor destination. With the classic qRFC protocol ABAP reports the destination as not
registered for background RFC. The wire format is in
[tRFC / qRFC / bgRFC](../protocol/trfc.md#inbound-bgrfc).
