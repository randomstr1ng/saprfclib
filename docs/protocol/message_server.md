# Message Server — load-balanced logon

!!! note "SAProuter is documented in this file too"
    See **SAProuter route acknowledgement** near the end.


A load-balanced connection asks the message server which application server to
use, then connects to that server normally. `saprfclib` reaches the message
server over its **HTTP interface**, which is line-oriented and confirmed against
a live server. The binary protocol is also implemented but is **not** verified —
see the warning below.

---

## Ports — there is no formula for a modern system

**Source:** SAP, *TCP/IP Ports of All SAP Products* (SAP Help Portal, Security
guide). Cross-checked against a live scan of A4H on 2026-08-31.

The message server appears in that table **twice**, and the difference is the
whole story:

| Component | Service | Default | Range | Formula |
|-----------|---------|---------|-------|---------|
| Application Server ABAP | `sapmsSID` | 3600 | 3600–3699 | `36<NN>` |
| SAP Central Services (SCS/ASCS) | `sapms<SID>` | **9310** | **0–65535** | **None** |

The `36<NN>` row is annotated *"Relevant only for systems that have been
installed prior to SAP NetWeaver 7.0 with a central instance (CI)."* The SCS row
says *"Configure the message server port with profile parameter `rdisp/msserv`."*

So on any current system — an ASCS layout, which is every modern install — the
message server port is **whatever the profile says, anywhere in the port range,
with a documented default of 9310**. There is no formula to apply, and `36<NN>`
describes only legacy central-instance systems.

This is why `saprfclib` has no numeric default. Each candidate is wrong for a
different layout:

- 3600 — right only for a pre-7.0 central instance
- 9310 — the documented SCS default
- 3601 — what the A4H test system actually uses

`saprfclib` reads the instance from where SAP's own table points: the
`sapms<SID>` entry in `/etc/services`. That table notes *"You can reassign
service names to an arbitrary value after installation in `/etc/services`"*,
which makes that file the client-side record rather than a convention. When it is
absent, `msserv` must be supplied — a port, or the service name.

### The other ports, and what confirms them

| Port | Service | Formula | Status |
|------|---------|---------|--------|
| 3200 | Dispatcher | `sapdp<NN>` `32<NN>` | documented; observed on A4H |
| 3300 | **Gateway (RFC)** | `sapgw<NN>` `33<NN>` | documented; the A4H message server reports `RFC 3300` |
| 4800 | **Gateway secured (SNC)** | `sapgw<NN>s` `48<NN>` | documented; message server reports `RFCS 4800` |
| 3900–3999 | Message server internal | `39<NN>`, `rdisp/msserv_internal` | documented; 3901 observed |
| 8100–8199 | Message server HTTP | `81<NN>`, `ms/http_port_<n>` | documented **"Not active by default"**; 8101 observed |
| 44400–44499 | Message server HTTPS | `444<NN>`, `ms/https_port_<n>` | documented; not enabled on A4H |
| 3299 | SAProuter | fixed | documented |

`saprfclib`'s gateway derivation — `(4800 if snc else 3300) + sysnr` — is
confirmed by both the table and the message server's own service list. Note the
`<NN>` there is the **application server's** instance number, unlike the message
server's.

### Why the instance numbers differ on one host

`sapstartsrv` is `5<NN>13`. On A4H **both 50013 and 50113 answer**, so instances
00 and 01 both exist — and the table confirms the reason: *"On the SAP Central
Services (SCS and ASCS) instance the default instance is 01 making the default
port 50113."* The application server is instance 00 and the ASCS, which hosts
the message server, is instance 01. That is why the gateway is 3300 while the
message server is 3601.

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

## Binary protocol — CONFIRMED end to end

Captured from SAP GUI performing a group logon (`tcpdump` on port 3601), then
**reproduced against the live server by this library**, which answered
`errorno 0` and returned the real server list. Golden fixtures:
`tests/golden/router/sapms_*.bin`.

### The exchange

```
C->S  110B   attach    operation 0x08
S->C  110B   reply     errorno 0, fromname "MSG_SERVER"
C->S  162B   request   operation 0x01, toname "MSG_SERVER"  (110 header + 52 body)
S->C  275B   reply     server list as KEY=VALUE text
C->S  110B   detach    operation 0x04
```

### Header — 110 bytes

| Offset | Size | Field |
|--------|------|-------|
| `0x00` | 12 | `**MESSAGE**\0` |
| `0x0c` | 1 | version = 4 |
| `0x0d` | 1 | errorno, **signed** |
| `0x0e` | 40 | toname, space-padded |
| `0x36` | 1 | msgtype (0 in every captured frame) |
| `0x42` | 1 | speaker: `0x02` client, `0x03` server |
| `0x43` | 1 | **operation**: `0x08` attach, `0x01` request, `0x04` detach |
| `0x44` | 40 | fromname, space-padded |
| `0x6c` | 2 | service number, network order |

### Request body — 52 bytes

```
1e 00 01 01   opcode block (byte 3 is 01 outbound, 03 on the reply)
02 00 00 00 00 00 00 <sel>   ... then zeros to 52
```

`<sel>` at body offset 11 selects what is asked for:

| Selector | Returns |
|----------|---------|
| `0x1d` | application servers |
| `0x1f` | logon groups |

### Reply payload is text, not a binary table

```
ASNAME=host_A4H_00|HOSTNAME=host|PORT=3200|SAPSRV=DIA UPD BTC SPO UP2 ICM |SNC=p:CN=...
```

Newline-separated records, pipe-separated `KEY=VALUE`. The group list is the same
shape with `GROUP=` instead of `ASNAME=`.

**`PORT` is the dispatcher port (`32<NN>`), not the gateway.** The captured record
reads `PORT=3200` for a server whose gateway is 3300, so the system number comes
from the dispatcher formula and the caller adds 3300 — or 4800 for SNC.

### Return codes

`0x0d` is a **signed** byte; read unsigned, `0xec` is 236 rather than −20.

| Code | Meaning |
|------|---------|
| 0 | success |
| −12 | invalid client version |
| −20 | access denied |

### Corrections this capture forced

Three things recorded earlier in this file were wrong, and each was wrong in a way
that looked convincing:

- **"`0x43` must be 3."** It is the *operation* byte, and 3 is not one of its
  values. That conclusion came from a sweep that tried 0, 1, 2 and 4 — but not 8,
  which is what a real client sends. Every value in that sweep was tested against
  a `msgtype` the server would not accept anyway, so the whole sweep measured
  nothing.
- **"−20 means the server's ACL refused us."** There is no ACL configured on the
  test system. −20 was the server rejecting an invalid operation byte. Attributing
  it to `ms/acl_info` was a guess that happened to sound like a diagnosis.
- **The original `msg_type=0x02` / `direction=0x08` at `0x42`/`0x43` were right
  all along.** They were replaced with a wrong constant taken from a legacy code
  path. What was actually broken was the frame *length* (114 vs 110) and the name
  field layout — and the length alone is enough for the server to close the
  connection without a word.

### Two server-list opcodes, two payload formats

A fourth correction, this one to the paragraph above: **the binary parser was not
wrong either.** There is more than one server-list opcode, and they carry
different payloads:

| Opcode block | Payload | Capture |
|--------------|---------|---------|
| `1e 00 01 03` | `KEY=VALUE` text | SAP GUI group logon, 2026-08-31 |
| `05 00 04 03` | binary fixed-width entry table | 2026-06-27 |

Both are genuine replies with the identical 110-byte header; they differ only in
the opcode block and the shape of what follows. Byte 2 of that block is the
opcode *version*, and byte 3 is `0x01` outbound / `0x03` on the reply in both.

So `parse_sapms_server_list` handles opcode `0x05` and `parse_ms_list_reply`
handles `0x1e`. Neither supersedes the other, and a reply is dispatched on its
opcode rather than assumed — which is why `parse_ms_list_reply` names the other
parser when it meets a `0x05` payload instead of failing obscurely.

This was nearly a regression: the binary parser was about to be deleted as dead
code on the strength of one capture that happened to use the other opcode.



---

## SAProuter route acknowledgement — CONFIRMED

Confirmed against a live SAProuter (version 40.4) on 2026-08-31.

After the `NI_ROUTE` frame, the router answers **before** it begins forwarding:

| Outcome | Reply | Fixture |
|---------|-------|---------|
| Route accepted | `NI_PONG\0` (8 bytes) | `ni_pong_route_accepted.bin` |
| Route refused | `NI_RTERR` + `*ERR*` record | `ni_rterr_route_denied.bin` |

**That acknowledgement must be read.** Sending the route and going straight into
the RFC handshake leaves `NI_PONG` at the head of the stream, so the handshake's
first read returns it instead of the NI version response — and every frame after
that is one position out of step. `saprfclib` did exactly this until 2026-08-31,
which meant `connect(saprouter=...)` could not work at all.

### The refusal carries the router's own message

`NI_RTERR` is followed by a NUL-separated `*ERR*` record — the same shape the
gateway uses for its errors:

```
NI_RTERR\0 … *ERR*\0 1\0
saprouter: route permission denied (203.0.113.42 to 10.99.99.99, 3300)\0
-94\0 NI (network interface)\0 753\0 40\0 … SAProuter 40.4 on 'saprouter'\0 *ERR*\0
```

The message names the source address, the target and the port, which is what
someone debugging a denied route actually needs, so it is reported verbatim
rather than replaced with a generic explanation.

Observed while probing which targets the test router permits: `3300` and `3200`
were accepted for the configured host and `22` was refused, so the permission
table is per host **and** port.

### Hop passwords — CONFIRMED

A route entry is **three NUL-terminated fields**: host, service, password. An
entry with no password still ends with the empty password's NUL.

```
NI_ROUTE\0            9
talk_mode  0x02       1
0x28                  1
route_version 0x02    1
hop_count             4 BE
total_data_length     4 BE   (sum of entry data + destination data)
per hop:
    entry_length      4 BE
    host\0 service\0 password\0
destination (no length prefix):
    host\0 service\0 \0
```

Captured from `niping` sending a password-protected route, sanitised into
`tests/golden/router/ni_route_password_payload.bin`:

```
entry_length 37   b"router.example.com\0" b"3299\0" b"s3cr3tp4s\0"
destination       b"192.168.88.7\0" b"3300\0" b"\0"
```

`build_ni_route` reproduces both that frame and the unprotected
`ni_route_payload.bin` byte for byte.

#### The old implementation was right by coincidence

It padded the service into a fixed 6-byte NUL-filled field. For a four-character
port that is byte-identical to the correct form:

```
"3299" + NUL + NUL      ==      "3299\0"  +  "\0"
   fixed 6-byte field           service     empty password
```

So every numeric port produced a valid frame and the mistake stayed invisible.
It would have appeared the moment anyone used a service *name*: `sapgw00` is
seven characters, truncated to `sapgw0`, and the frame malformed. Five attempts
to append the password to that layout were all rejected by a live router with
`NiRRouteRepl: invalid route received` — the structure was wrong, not the
position.

The lesson worth keeping: a golden fixture proves the bytes match for the case it
captures. It does not prove the *reasoning* behind them is right, and a
coincidence at one input length can survive a byte-exact test indefinitely.
