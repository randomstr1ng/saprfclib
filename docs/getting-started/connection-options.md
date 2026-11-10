# Connection Options

`saprfclib.connect()` supports five transport modes. All modes share the same
`conn.call()` / `conn.close()` interface once connected.

## Direct TCP (application server)

Connect directly to an SAP application server by hostname and system number.
The gateway port is calculated as `3300 + sysnr`.

```python
conn = saprfclib.connect(
    ashost="10.0.1.5",
    sysnr=0,          # Gateway port = 3300 + sysnr
    client="100",
    user="USER",
    passwd="pass",
    timeout=30.0,     # Socket timeout in seconds (optional)
)
```

## SAProuter hop

Route the connection through one or more SAProuters when the SAP system is not directly
reachable. `saprouter` lists the routers only (`/H/host/S/port[/P/password]` per router);
the destination is `ashost` and the gateway port. The connection is opened to the first
router.

```python
conn = saprfclib.connect(
    ashost="internal-sap-host",
    sysnr=0,
    client="100",
    user="USER",
    passwd="pass",
    saprouter="/H/saprouter.example.com/S/3299",
)
```

## Message server (load-balanced)

Connect to a logon group via the SAP message server. The message server returns
the least-loaded application server, and saprfclib connects to it directly.

```python
conn = saprfclib.connect(
    ashost="dummy",           # Required positionally; ignored when mshost is set
    sysnr=0,
    client="100",
    user="USER",
    passwd="pass",
    mshost="sapms.example.com",
    sysid="A4H",
    group="PUBLIC",
)
```

## SNC (X.509)

SAP Secure Network Communications encrypts the connection and authenticates both ends
with certificates. The X.509 mechanism is built in — point `snc_pse` at a PSE file
created with `sapgenpse`:

```python
conn = saprfclib.connect(
    ashost="sap-host",
    sysnr="00",
    client="100",
    user="USER",
    passwd="...",
    snc_partnername="p:CN=A4H, OU=IDEMOSYSTEM, OU=SAP Web AS, O=SAP Trust Community, C=DE",
    snc_pse="/secure/client.pse",
    snc_pse_pin="...",
)
```

For Kerberos SNC (single sign-on with Active Directory), pass `snc_kerberos=True` to use
the ticket cache, or `snc_kerberos=KerberosLogin(...)` for a password, keytab or specific
cache, with `snc_partnername="p:CN=<service>@<REALM>"` and usually `snc_sso=True`.

To use a native GSS-API library instead (e.g. CommonCryptoLib), pass `snc_lib` with its
absolute path and leave out `snc_pse`. See the [SNC cookbook](../cookbook/snc-connection.md)
for setup, partner-name rules and the protection levels (`snc_qop`).

## WebSocket RFC (BTP / Cloud)

Connect to SAP BTP ABAP Environment or other cloud systems via WebSocket RFC
(RFC over WebSocket over TLS). Use `wshost` instead of `ashost`.

```python
conn = saprfclib.connect(
    ashost="dummy",           # Not used for wRFC; required positionally
    sysnr=0,
    client="100",
    user="USER",
    passwd="pass",
    wshost="my-system.abap.eu10.hana.ondemand.com",
    wsport=443,               # default 443
    ws_path="/sap/bc/rfc?sap-apc-stateful=true",  # default
    ws_tls_verify=True,       # set False for self-signed certs (dev only)
)
```

To route the WebSocket connection through an HTTP CONNECT proxy:

```python
conn = saprfclib.connect(
    ashost="dummy",
    sysnr=0,
    client="100",
    user="USER",
    passwd="pass",
    wshost="my-system.abap.eu10.hana.ondemand.com",
    ws_proxy_host="proxy.internal.example.com",
    ws_proxy_port=3128,
)
```

## Logon language

The `lang` parameter sets the SAP logon language. It accepts either form, matching
the `LANG` option of the SAP NetWeaver RFC SDK:

```python
conn = saprfclib.connect(
    ashost="10.0.1.5",
    sysnr=0,
    client="100",
    user="USER",
    passwd="pass",
    lang="EN",        # two-character ISO code
)

conn = saprfclib.connect(..., lang="E")    # or the one-character SAP code
```

`lang` defaults to `"E"` (English). Input is case-insensitive.

The RFC logon frame itself only ever carries **one character** — the SAP language
code from the ABAP `SPRAS` domain. A two-character ISO code is converted before the
frame is built, exactly as the C SDK does it, so both spellings above produce
identical bytes on the wire.

!!! warning "The ISO code is not the first letter of the SAP code"
    `EN`→`E` and `DE`→`D` suggest a rule that does not hold. Spanish is `ES`→`S`,
    Danish is `DA`→`K`, Finnish is `FI`→`U`, Greek is `EL`→`G`, and Chinese is
    `ZH`→`1`. Do not truncate an ISO code by hand — pass it whole and let
    `saprfclib` convert it.

### Converting between the two forms

Two helpers are exported for callers migrating from `pyrfc`, which exposes the same
names:

```python
import saprfclib

saprfclib.language_iso_to_sap("EN")   # "E"
saprfclib.language_iso_to_sap("ES")   # "S"
saprfclib.language_sap_to_iso("1")    # "ZH"
```

An unknown code raises `ValueError`. This differs deliberately from the C SDK, whose
forward conversion returns an undefined character for an unrecognised ISO code rather
than reporting an error.

A **one-character** code is never looked up — it is taken at face value and sent as
given. Systems can have custom languages that appear in no standard table, and the
SDK does not validate one-character input either. The trade-off is that a typo in a
one-character code reaches the server rather than being caught locally.

## Unknown keyword arguments

`Connection.call()` matches keyword arguments against the function module's
interface. `strict_params` decides what happens to a name the interface does not
declare:

```python
conn = saprfclib.connect(...)                       # default: drop + warn
conn = saprfclib.connect(..., strict_params=True)   # raise ValueError
```

The default is **lenient**, so code ported from `pyrfc` that passes a superset of
kwargs across differing SAP releases keeps working:

```python
conn.call("SXPG_STEP_XPG_START", COMMANDNAME="LIST_DB2DUMP", MXROW=100)
# MXROW is not in the interface -> dropped, warning logged, call proceeds
```

Each dropped argument is logged. The first occurrence of a given
(function, argument-names) combination logs at `WARNING`; repeats fall to `DEBUG`,
so a long-running loop leaves a record without flooding its log.

!!! warning "A dropped argument changes what the call does"
    The function then runs *without* it and returns a result you did not ask for,
    and nothing in the response indicates an argument went missing. In the example
    above, `SXPG_STEP_XPG_START` runs with no row limit. Watch the warnings, and
    prefer `strict_params=True` wherever a dropped argument would change the result.

For reference, both `pyrfc` and the SAP NetWeaver RFC SDK **raise** here — the SDK's
`RfcGetParameterDescByName` returns `RFC_INVALID_PARAMETER` for a name it cannot
resolve, and `pyrfc` propagates that. `strict_params=True` matches them; the lenient
default is a deliberate convenience for migration.
