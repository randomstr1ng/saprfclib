# Message Server — load-balanced logon

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

## Binary protocol — the frame layout is CONFIRMED

Validated 2026-08-31 against A4H (kernel 793) on port 3601 by sending candidate
frames and recording which drew a reply, which drew a specific error, and which
were dropped.

The attach frame is **110 bytes** of body behind the 4-byte NI length prefix.
The header runs to `0x6c` and ends with the service number, so the header *is*
the whole frame — nothing follows it.

| Offset | Size | Field | Evidence |
|--------|------|-------|----------|
| `0x00` | 12 | `**MESSAGE**\0` | magic |
| `0x0c` | 1 | version = **4** | version 5 is answered with −12 *"invalid client version"*; 1–3 are dropped without a reply |
| `0x0d` | 1 | errorno (signed) | 0 outbound; the server's return code inbound |
| `0x0e` | 40 | toname, space-padded | |
| `0x36` | 1 | msgtype | 0 draws no reply; 1–7 are each answered |
| `0x43` | 1 | must be **3** | 0, 1, 2 and 4 each get the connection dropped |
| `0x44` | 40 | fromname, space-padded | |
| `0x6c` | 2 | service number, network order | |

The server swaps the names in its reply: what you send as `fromname` comes back
in `toname`.

### Return codes

`0x0d` is a **signed** byte. Reading it unsigned turns an error into a plausible
number — `0xec` is −20, not 236.

| Code | Meaning |
|------|---------|
| 0 | success |
| −12 | invalid client version |
| −18 | message server shutdown |
| −20 | access denied |
| −25 | message server soft shutdown |

−20 and −12 were both reproduced live. Golden fixture:
`tests/golden/router/sapms_attach_access_denied.bin`.

### What the previous implementation sent

A 114-byte body, with `0x0e` read as a one-byte "sender type" and a 10-byte
"opcode name" placed at `0x44` — which is where the 40-byte `fromname` belongs.
**The message server closes the connection on that frame without replying.** The
mistake survived because both fields are space-padded, so the bytes looked
plausible beside a partial capture.

`MessageServerClient.resolve` was worse than wrong: it sent a 2-byte
length-prefixed group name — a shape invented to satisfy `MockTransport`, which
no message server can interpret. Its test passed because the stub and the test
agreed on a protocol that does not exist.

Both builders also carried their own NI length prefix while handing the result
to a transport seam that adds one, and looked for the magic at offset 4 of a
payload whose prefix had already been stripped. The two errors cancelled under
`MockTransport` and could never have worked on a socket.

---

!!! warning "What is still open: the server-list request"

    The attach frame is confirmed, but **which `msgtype` asks for a server list
    is not**. Every attach against a live server so far is refused with
    *access denied* before the request is reached, so no request has ever been
    answered with a list to compare against. `_build_sapms_server_list_request`
    uses `msgtype=4` as a **placeholder, not a finding**.

    Access is governed by the server's `ms/acl_info`. External binary attach is
    restricted by default on current kernels — which is why the HTTP interface
    remains the default path.

    **To close this:** either permit an external attach on a test system, or
    capture a real client performing a group logon (SAP GUI with a logon group,
    or `sapcontrol`) against the message-server port, both directions.


