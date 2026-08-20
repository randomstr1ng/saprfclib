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
def check_auth(user: str = "", password: str = "") -> bool:
    return user.upper() == "RFC_USER"

server.set_authentication_check(check_auth)

# serve_forever() blocks in a daemon thread until server.stop() is called
# from another thread, or the process exits.
print("RFC server starting — press Ctrl+C to stop")
server.serve_forever()
```

## Notes

- `FunctionDesc` and `FieldDesc` are importable directly from `saprfclib` (top-level public API).
- `rfctype=0` is `RFCTYPE_CHAR`.  Consult `sapnwrfc.h` or the ABAP DDIC for other type codes.
- `nuc_length` is the character count in the non-Unicode encoding; `uc_length` is double
  that value for UTF-16 (2 bytes per code unit).
- The `RESPTEXT` export is sent back to the SAP caller automatically when the handler returns.
- For tRFC/qRFC inbound calls the `func_desc` argument to `@server.function` can be `None`
  because the server short-circuits before deserializing the request when it detects a
  duplicate TID.
