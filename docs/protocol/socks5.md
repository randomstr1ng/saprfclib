# SOCKS5 Proxy Transport (SAP BTP Connectivity Proxy)

**Status:** CONFIRMED-on-doc — the 0x80 JWT frame and the method model are taken from
SAP's own published connectivity documentation (CC-BY 4.0) and SAP's reference sample.
Live confirmation against a Kyma Connectivity Proxy is still pending (issue #51); the
0x00 no-auth path and the CONNECT request/reply are plain RFC 1928.
**Confidence:** HIGH for the wire layout (two independent SAP sources agree). The
`[ASSUMED]` marker below records what a live capture would settle.

---

## Why this exists

In SAP BTP / Kyma, on-premise systems reached through SAP Cloud Connector are consumed by
Kubernetes workloads over a **SOCKS5** interface exposed by the SAP Connectivity Proxy
(default port `20004`). `proxy_type="socks5"` lets `saprfclib` open a raw RFC/TCP
connection through that proxy with no NW RFC SDK, no Transparent Proxy, and no local
`socat` bridge:

```
saprfclib → SOCKS5 proxy (:20004) → SAP Cloud Connector → virtual-host:3300 → SAP
```

SOCKS5 sits **below** the NI length prefix (see [framing.md](framing.md)). The handshake
produces an ordinary connected socket; everything above it — NI versioning, the GW
connect, the logon TLV, even SNC or an `saprouter` route — is unchanged. The seam is a
`socket_factory` in `transport.py` (D-39); `proxy_type="socks5"` is the built-in factory.

## Layering

```
RFC logon / RfcInvoke TLV
  → Session (NI version, GW connect, handshake)       — unchanged
    → Transport.send_message / recv_message            — NI 4-byte length prefix
      → socket                                         — returned by socks5_connect()
        → SOCKS5 greeting / auth / CONNECT             — this module (below the socket)
          → TCP to the proxy
```

## Authentication methods (D-40)

SAP uses **two** SOCKS5 authentication methods, and **not** the RFC 1929
username/password method (0x02). This was the specific correction that drove the design:
offering 0x02 is wrong.

| Method | Number | When | saprfclib trigger |
|--------|--------|------|-------------------|
| No authentication | `0x00` (RFC 1928 §3) | Connectivity Proxy **trusted mode** — `config.servers.proxy.socks5.enableProxyAuthorization = false`, the default for in-cluster Kyma workloads. The proxy derives the subaccount from the caller's in-cluster identity. | no JWT parameters set |
| SAP custom JWT | `0x80` | CF Connectivity service SOCKS5 (auth mandatory there) and the Connectivity Proxy in **untrusted mode** (`enableProxyAuthorization = true`). | `proxy_jwt`, or the `proxy_client_id`/`proxy_client_secret`/`proxy_token_url` triple |

### Method 0x00 — no authentication

Standard RFC 1928: greeting `05 01 00`, server selects `05 00`, then straight to CONNECT.

### Method 0x80 — SAP JWT sub-negotiation

Greeting `05 01 80`; the server confirms `05 80` (the method byte reads as `128`, or
`-128` in a signed-byte implementation — both are `0x80`). The authentication request
then carries a JWT access token and an optional Cloud Connector location id:

```
┌────────┬──────────────────────────────────────────────────────────────┐
│ 1 byte │ sub-negotiation version — currently 0x01                      │
│ 4 byte │ JWT length, uint32 big-endian                                 │
│ X byte │ the JWT in encoded (compact) form                            │
│ 1 byte │ Cloud Connector location id length (0 if unused)             │
│ Y byte │ location id, base64-encoded (omitted when the length is 0)   │
└────────┴──────────────────────────────────────────────────────────────┘
```

Reply: `01 <status>`, where `status == 0x00` is success. The JWT is an OAuth2
`client_credentials` token minted from the connectivity service binding's `client_id` /
`client_secret` against its `uaa` URL; `saprfclib` can fetch it (`proxy_token_url`) or
accept a pre-fetched `proxy_jwt`.

## CONNECT request / reply (RFC 1928 §4, §6)

Request: `05 01 00 <ATYP> <addr> <port:u16 BE>`. The address is sent as a packed IPv4/IPv6
literal when `dest_host` is one, otherwise as a **domain name** (`ATYP 0x03`) so the proxy
resolves it — a Cloud Connector virtual host is only resolvable behind the proxy.

Reply `REP` codes and the meanings `saprfclib` reports (matching SAP's own translation):

| REP | Meaning |
|-----|---------|
| 0 | succeeded |
| 1 | general SOCKS server failure |
| 2 | connection not allowed (forbidden) |
| 3 | network unreachable |
| 4 | host unreachable |
| 5 | connection refused |
| 6 | TTL expired |
| 7 | command not supported |
| 8 | address type not supported |

## Gateway host vs. tunnel host (`gwhost`)

The SOCKS5 tunnel and the SAP RFC handshake resolve the target host in **two
different places**, and through a proxy they are not the same name:

- The **SOCKS5 CONNECT** target (`ashost`) is resolved by the proxy / Cloud
  Connector. For a Connectivity Proxy this is the *virtual host* configured in the
  Cloud Connector (e.g. `s4-2025-raw`).
- The **GW handshake frames** (`0x0601` GW_CONNECT and `0x060f` GW_INFO) carry a
  gateway host that the **server-side gateway resolves locally** — byte `[80:192]`
  of the `0x060f` frame. The generic SOCKS5 tunnel forwards raw TCP, so the Cloud
  Connector does not rewrite this field (unlike its RFC-aware protocol handler); the
  virtual host reaches the gateway unchanged and cannot be resolved there.

A live capture (issue #51, `nohat-rfc.pcap`) showed the consequence: the NI version
exchange and GW_CONNECT succeed, then the gateway answers the `0x060f` frame with

```
*ERR* hostname 's4-2025-raw' unknown … NI (network interface) …
      SAP-Gateway on host vhcala4hci / sapgw00
```

and tears the conversation down, so the following RFC call fails with
`Conversation … not found`.

The fix is the `gwhost` parameter: `ashost` stays the virtual tunnel host, and
`gwhost` is set to the SAP system's own internal hostname — the name the gateway
resolves to itself (visible in the error above as `vhcala4hci`). `gwhost` defaults
to `ashost`, so a direct connection is unchanged.

```python
conn = saprfclib.connect(
    ashost="s4-2025-raw", sysnr="00", client="001", user="Developer", passwd="...",
    proxy_type="socks5", proxy_host="connectivity-proxy...", proxy_port=20004,
    gwhost="vhcala4hci",   # the internal host the gateway resolves locally
)
```

**[ASSUMED]** The exact value `gwhost` must take for a given landscape (the SAP
system's internal hostname, or whatever the gateway resolves to itself) is
confirmed only against the issue #51 capture, where `vhcala4hci` is the gateway's
own host. A capture from another landscape would confirm the general rule.

## Security (D-41, threat T-07-PROXY-CRED)

The JWT, the OAuth `client_secret`, and any proxy password are used only to build wire
bytes. They never enter a log record or a `ProxyError` message; a failure reports the
SOCKS5 reply code and its meaning only. `fetch_connectivity_token` refuses a non-`https`
`token_url` rather than send the secret in cleartext.

## Sources

- SAP-docs/btp-connectivity, `docs/1-connectivity-documentation/using-the-tcp-protocol-for-cloud-applications-cd15837.md`
  (the Markdown behind the help.sap.com page *Using the TCP Protocol for Cloud
  Applications*) — the 0x80 method number, the sub-negotiation frame table, and the
  reference sample `ConnectivitySocks5ProxySocket`. Licensed CC-BY 4.0; referenced here,
  not copied verbatim (legal boundary).
- SAP-docs/btp-connectivity, `connectivity-proxy-integration-f6cb5bc.md` — trusted vs.
  untrusted mode and `enableProxyAuthorization`.
- IETF RFC 1928 (SOCKS5), RFC 7519 (JWT).

## Known gaps / `[ASSUMED]`

- **[ASSUMED]** The 0x80 frame is confirmed against two SAP sources but not yet against a
  live capture from a Kyma Connectivity Proxy. A capture of a real 0x80 handshake (and of
  an untrusted-mode rejection) would promote this to tier-1 and is the outstanding item on
  issue #51. The reporter offered a Kyma + Connectivity Proxy + Cloud Connector test
  environment.
- The message-server resolve leg (`mshost`) still connects to the message server
  directly rather than through the proxy; only the resolved application-server
  connection is proxied. Message-server logon behind a Connectivity Proxy is untested.

## Reading the service binding

`connectivity_proxy_kwargs()` turns a Connectivity service binding into the `proxy_*`
keyword arguments for `connect()`, so the parameters need not be dug out by hand:

```python
import saprfclib

cfg = saprfclib.connectivity_proxy_kwargs()  # reads VCAP_SERVICES, else SERVICE_BINDING_ROOT
conn = saprfclib.connect(ashost="s4-2025", sysnr="00", client="001",
                         user="Developer", passwd="...", **cfg)
```

It accepts a raw credentials mapping, a service-instance mapping, a full
`VCAP_SERVICES` mapping, or a JSON string of any of those; with `None` it reads the
environment — `VCAP_SERVICES` (Cloud Foundry) first, then `SERVICE_BINDING_ROOT`
(Kyma / Kubernetes, one file per key or a single `credentials` JSON file). The binding
fields used are `onpremise_proxy_host`, `onpremise_socks5_proxy_port`, and — for the
SAP JWT method — `clientid`, `clientsecret` and `token_service_url` (or the deprecated
`url`), with the token endpoint formed as `<token_service_url>/oauth/token`. Pass
`with_auth=False` for a trusted-mode Connectivity Proxy (the in-cluster Kyma default),
which uses the no-authentication method and would reject a JWT.
