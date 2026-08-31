# Message Server — load-balanced logon

A load-balanced connection asks the message server which application server to
use, then connects to that server normally. `saprfclib` reaches the message
server over its **HTTP interface**, which is line-oriented and confirmed against
a live server. The binary protocol is also implemented but is **not** verified —
see the warning below.

---

## Ports are derived from the message server's instance, not the app server's

This is the first thing that goes wrong, and it fails by connecting to nothing.

| Interface | Port | Example (A4H) |
|-----------|------|---------------|
| Binary (`sapms<SID>`) | `36<nn>` | 3601 |
| HTTP | `81<nn>` | 8101 |

`<nn>` is the **message server's own instance number**. It is not the
application server's system number, and nothing lets you infer one from the
other.

On the A4H appliance the application server is system number 00 — gateway on
3300, confirmed — while the message server runs as instance 01. So the message
server is on 3601/8101 and **port 3600 refuses connections outright**. Any code
that computes the message-server port from `sysnr` reaches a closed port on a
completely ordinary system.

Live scan, 2026-08-31:

```
3200 open   dispatcher        (app server, sysnr 00)
3300 open   gateway           (app server, sysnr 00)
3600 CLOSED
3601 open   message server, binary
3901 open   message server, internal
8101 open   message server, HTTP
```

Pass `msserv` to override — a port (`msserv=3601`) or a service name
(`msserv="sapmsA4H"`, looked up in `/etc/services` as the SAP tools do). An
unknown service name raises rather than falling back to a default, because
falling back means silently connecting somewhere else.

---

## HTTP interface — CONFIRMED

Present only when the profile sets `ms/server_port_0`. When it is absent the
resolver says so explicitly rather than failing obscurely.

### `/msgserver/text/logon?version=1.2[&group=NAME]`

Tab-separated. Line 1 is the format version, line 2 the instance name, then one
row per service: `service`, `host`, `port`, extra.

```
version 1.2
sapdemo1_A4H_00
DIAG	sapdemo1	3200	LB=7
DIAGS	sapdemo1	3200	p:CN=A4H, OU=IDEMOSYSTEM, ...
RFC	sapdemo1	3300	
RFCS	sapdemo1	4800	p:CN=A4H, OU=IDEMOSYSTEM, ...
HTTP	sapdemo1	50000	
HTTPS	sapdemo1	50001	
```

`RFC` is the row to use. **`RFCS` is the SNC-protected endpoint on a different
port** (4800 here): selecting it by accident hands back a port that needs SNC
parameters the caller has not necessarily supplied, and the failure appears
later as a handshake error rather than as a wrong choice here.

Unparseable rows are skipped rather than failing the response. The service list
is open-ended, and a future release adding a row must not cost you the RFC row
you came for.

### `/msgserver/text/lglist`

The logon groups: `group`, `host`, `port`, release.

```
version 1.0
PUBLIC	192.0.2.1	3200	758
SPACE	192.0.2.1	3200	758
```

### `/msgserver/text/aslist`

The application servers, with both hostname and address.

Golden fixtures: `tests/golden/router/ms_http_*.txt`, sanitised (hostname and
address substituted). Unlike a binary frame these are line-oriented, so
substitution cannot invalidate an offset or a length.

---

## Hostname vs address

The logon endpoint reports the **hostname** SAP knows (`vhcala4hci`), not an
address. `lglist` and `aslist` report the address. If the client cannot resolve
the SAP-side hostname in DNS, a resolved connection fails at connect time even
though resolution succeeded — pass `ashost` directly in that case.

---

!!! warning "The binary message-server protocol is UNVERIFIED"

    `router.py` builds `**MESSAGE**` frames from a partial capture, and most of
    the `[ASSUMED]` labels in this project are in that code: the login frame
    body, the opcode pair believed to request a server list, the per-entry field
    layout, and how the entry count is derived.

    Tested against a live message server on 2026-08-31, it does not work. The
    server accepts the TCP connection on 3601 and then answers **nothing** — no
    login acknowledgement, no server list, no error. Both the login frame and
    the opcode pair are wrong.

    This is why the HTTP interface is the default. An unverified path deciding
    which application server a caller talks to is not a failure the caller can
    see. `ms_use_http=False` forces the binary path for anyone wanting to work
    on it.

    **To close this gap:** capture a real client performing a group logon
    (SAP GUI with a logon group, or `sapcontrol`) against the message server
    port and record both directions. The frames are small and the exchange is
    short.
