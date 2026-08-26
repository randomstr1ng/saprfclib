# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — RFC server core (sans-I/O dispatch + asyncio serve facade)
#
# RfcServer is "Phase 4's client run backwards": a Python process that registers a
# PROGRAM_ID with an SAP gateway (ServerSession, Plan 05-02) and answers the RFC
# calls the gateway pushes to it. Application code registers handlers by function
# module name; an inbound call frame is deserialized into a typed request dict and
# the handler's return dict is serialized back to the wire.
#
# Requirements (SERVER-01,03,04,05,06):
#   SERVER-01  handler registry + @server.function decorator + set_generic_handler
#   SERVER-03  inbound request deserialize into a typed dict (codec.decode per field)
#   SERVER-04  response serialize (0x0500 + 0x0420=0 + EXPORTING/CHANGING/TABLE pairs)
#   SERVER-05  authentication callback (allow/deny before handler dispatch)
#   SERVER-06  handler-exception isolation + asyncio dispatch + serve_forever facade
#
# Design (CLAUDE.md §"Async vs Sync"): the protocol is a sans-I/O core
# (``dispatch_inbound(frame) -> bytes``) so it is testable byte-for-byte with ZERO
# sockets against the Wave-1 golden fixtures. The asyncio serve loop and the
# ``serve_forever`` background-thread facade wrap that core; this is the repo's
# first asyncio surface (no in-repo analog — D-01/D-02).
#
# Wire reuse (RESEARCH "Don't Hand-Roll"; PATTERNS server.py section): the server
# reuses invoke.py's TLV machinery (``tlv_record`` writer, ``_extract_name_value_pairs``
# reader) and codec.py with directions flipped — it NEVER hand-rolls a second TLV
# parser/writer (Anti-Pattern). Direction inversion (Pitfall 4): the request carries
# the client's IMPORTING values (the server *reads* them); the handler *produces*
# the EXPORTING/CHANGING/TABLE values the server writes back.
#
# Security:
#   T-05-C01  every handler call is wrapped in try/except — one bad handler never
#             crashes the serve loop; the failure becomes a SYSTEM_FAILURE response.
#   T-05-C02  the SYSTEM_FAILURE message carries only str(exc) — never a full
#             traceback and never inbound credentials.
#   T-05-C03  inbound user/passwd are NEVER logged or echoed (T-04-CRED).
#   T-05-C04  all inbound TLV is parsed with the bounds-checked invoke walkers.
#   T-05-C06  the auth callback (if set) runs BEFORE handler dispatch; deny skips
#             the handler and returns an auth-failure SYSTEM_FAILURE.
from __future__ import annotations

import asyncio
import logging
import struct
import threading
from collections.abc import Callable
from typing import Any

from saprfclib.codec import RFCTYPE_TABLE, decode, encode
from saprfclib.connection import (
    _TAG_PASSWORD,
    _TAG_USER,
    _ab_scramble,
    _strip_gw_header,
)
from saprfclib.invoke import (
    _TID_ALPHABET,
    _TID_LN,
    _decode_utf16le,
    _extract_name_value_pairs,
    _parse_tlv_stream,
    tlv_record,
)
from saprfclib.metadata import FunctionDesc
from saprfclib.server_session import ServerSession
from saprfclib.stores import (
    InMemoryTidStore,
    InMemoryUnitStore,
    TidStore,
    UnitState,
    UnitStore,
)
from saprfclib.transport import AsyncTransport, Transport
from saprfclib.types import (
    RFC_CHANGING,
    RFC_EXPORT,
    RFC_TABLES,
    FieldDesc,
)

__all__ = ["RfcServer", "AsyncRfcServer"]

# --------------------------------------------------------------------------- #
# TLV tags — reuse invoke.py's confirmed constants (no second tag set).
# --------------------------------------------------------------------------- #
_TAG_FUNC_NAME = 0x0102  # function name UTF-16LE (invoke._TAG_FUNC_NAME)
_TAG_PARAM_NAME = 0x0201  # IN/CHANGING/TABLE param name (invoke._TAG_PARAM_NAME)
_TAG_PARAM_VALUE = 0x0203  # param value bytes (invoke._TAG_PARAM_VALUE)
# Server-direction TABLE records — same tags the client uses, with 0x0304 for rows
# (the tag a real SAP server uses in every captured response).
_TAG_TABLE_NAME = 0x0301
_TAG_TABLE_INFO = 0x0302
_TAG_TABLE_ROW = 0x0304
_TAG_DM_TABLE_ID = 0x0330
_TAG_TERMINATOR = 0xFFFF  # stream terminator (invoke._TAG_TERMINATOR)

# Response-only tags (invoke._TAG_RESPONSE_START / _TAG_RETURN_CODE; OQ-3/A4).
_TAG_RESPONSE_START = 0x0500  # empty: response-start marker
_TAG_RETURN_CODE = 0x0420  # 4B BE uint32 return code (0 = success)
_TAG_ERROR_MESSAGE = 0x0402  # error message text (server-direction; from fixture)

_logger = logging.getLogger(__name__)

# Return codes (SDK type definitions RFC_RC). 0 = OK; non-zero = failure on the response.
_RC_OK = 0
_RC_SYSTEM_FAILURE = 3  # RFC_SYS_EXCEPTION family (non-zero signals failure)
_RC_EXECUTED = 16  # RFC_EXECUTED — TID already executed

# System FM names that trigger transactional dispatch.
# ARFC_DEST_SHIP is the tRFC/qRFC call-type discriminator (function name IS the marker).
_ARFC_DEST_SHIP = "ARFC_DEST_SHIP"  # tRFC/qRFC inbound (Plan 06-01)
_ARFC_DEST_CONFIRM = "ARFC_DEST_CONFIRM"  # tRFC confirm
_BGRFC_DEST_SHIP = "BGRFC_DEST_SHIP"  # bgRFC submit
_BGRFC_DEST_CONFIRM = "BGRFC_DEST_CONFIRM"  # bgRFC confirm
_BGRFC_CHECK_UNIT_STATE_SERVER = "BGRFC_CHECK_UNIT_STATE_SERVER"  # bgRFC state query

# TID parameter name as carried in the ARFC_DEST_SHIP frame (invoke.py: ARFCTID).
_PARAM_ARFCTID = "ARFCTID"

# UnitID validation constants (T-06-U02).
_UNITID_LN = 32
_UNITID_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

# Directions whose values the SERVER produces on the response (Pitfall 4 mirror of
# invoke.parse_invoke_response: everything that is not pure IMPORTING comes back).
_RESPONSE_DIRECTIONS = frozenset({RFC_EXPORT, RFC_CHANGING, RFC_TABLES})


# --------------------------------------------------------------------------- #
# GW frame builders — sdk_listen.pcap ground truth (PKT4/PKT8/PKT9/PKT10/PKT11)
# --------------------------------------------------------------------------- #


def _build_reg_waiting() -> bytes:
    """Build 06d1 REG_WAITING (80B) — sent after 512B frame (sdk_listen.pcap PKT4).

    Signals GW "ready to accept CPI-C calls" → SMGW: "Waiting for CPI-C Call".
    GW responds with 06cf assigning a session handle.

    Layout (80B): [0:2]=06d1 [2:4]=0700 [4:6]=ffff [6:40]=zeros
    [32:40]=seq=1  [40:48]=local handle (\x00H000001)
    [48:52]=0x50 (frame size)  [52:76]=zeros  [76:80]=ffffffff
    """
    frame = bytearray(80)
    frame[0:2] = b"\x06\xd1"
    frame[2:4] = b"\x07\x00"
    frame[4:6] = b"\xff\xff"
    frame[32:40] = b"\x00\x00\x00\x00\x00\x00\x00\x01"
    frame[40:48] = b"\x00\x48\x30\x30\x30\x30\x30\x31"  # SDK local handle (\x00H000001)
    frame[48:52] = b"\x00\x00\x00\x50"  # = 80 (frame size)
    frame[76:80] = b"\xff\xff\xff\xff"
    return bytes(frame)


def _build_re_reg() -> bytes:
    """Build 06d0 RE-REG_WAITING (80B) — sent after replying to one call (PKT11).

    Identical to 06d1 except type byte is 06d0, signalling GW to queue next call.
    """
    frame = bytearray(_build_reg_waiting())
    frame[0:2] = b"\x06\xd0"
    return bytes(frame)


def _build_post_call_b(gw_handle: bytes) -> bytes:
    """Build 060b GW_MONITOR frame (80B) — sent after 0608 response (PKT9).

    [0:2]=060b [2:4]=0700 [4:6]=ffff [6:40]=zeros
    [40:48]=GW handle  [48:76]=zeros  [76:80]=ffff0001
    """
    frame = bytearray(80)
    frame[0:2] = b"\x06\x0b"
    frame[2:4] = b"\x07\x00"
    frame[4:6] = b"\xff\xff"
    frame[40:48] = gw_handle
    frame[76:78] = b"\xff\xff"
    frame[78:80] = b"\x00\x01"
    return bytes(frame)


def _build_post_call_d2(gw_handle: bytes) -> bytes:
    """Build 06d2 dispatch-done frame (80B) — sent after 060b (PKT10).

    [32:40]=seq=1  [40:48]=GW handle  [48:52]=0x50  [76:80]=ffff0001
    """
    frame = bytearray(80)
    frame[0:2] = b"\x06\xd2"
    frame[2:4] = b"\x07\x00"
    frame[4:6] = b"\xff\xff"
    frame[32:40] = b"\x00\x00\x00\x00\x00\x00\x00\x01"
    frame[40:48] = gw_handle
    frame[48:52] = b"\x00\x00\x00\x50"
    frame[76:78] = b"\xff\xff"
    frame[78:80] = b"\x00\x01"
    return bytes(frame)


def _wrap_in_0608(rfc_data: bytes, gw_handle: bytes) -> bytes:
    """Wrap RFC response TLV in 0608 GW frame header (sdk_listen.pcap PKT8).

    80B header: [0:2]=0608 [2:4]=0700 [4:6]=ffff [6:40]=zeros
    [40:48]=GW handle  [48:52]=len(rfc_data) BE  [52:76]=zeros  [76:80]=ffff0001
    Then rfc_data follows.
    """
    import struct as _struct

    frame = bytearray(80)
    frame[0:2] = b"\x06\x08"
    frame[2:4] = b"\x07\x00"
    frame[4:6] = b"\xff\xff"
    frame[40:48] = gw_handle
    _struct.pack_into(">I", frame, 48, len(rfc_data))
    frame[76:78] = b"\xff\xff"
    frame[78:80] = b"\x00\x01"
    return bytes(frame) + rfc_data


def _extract_5001_params(data: bytes) -> dict[str, str]:
    """Parse tag 0x5001 NgRfc compact param block → IMPORTING CHAR param values.

    verified format (the NgRfc receive stream + NgRfcDeserializer, 2026-07-02):
      [0:14]  NgRfc stream header: '$' magic (0x24) + 'H' (0x48) + 12 bytes flags
      [14..]  Entry stream from getNextParameter:
              0x54 [name_len 1B] [name_ascii] = type-spec (EXPORTING from server)
              0x51 [name_len 1B] [name_ascii] = IMPORTING param (value follows)
              0x44 = DDic type descriptor compMode (readMetadata/readColumnMetadata
                     consumes a variable-length DDic block from the stream — ~51B in
                     the STFC_CONNECTION capture; this is NOT a declaration entry)
              0x45 = end marker
      After 0x44 DDic block: value compMode 0x43 'C' for CHAR type:
              0x43 [len_lo 1B] [0x80] [len bytes ASCII value]
              LE int16 = (0x80<<8)|len_lo = 0x8000|len → high bit = compressed flag,
              N = LE int16 & 0x7FFF bytes of ASCII content.

    Only CHAR-type params are decoded (compMode 0x43 pattern); non-CHAR types
    (INT, FLOAT, DATE, STRING, TABLE etc.) are deferred to Phase 6 protocol analysis.
    See docs/protocol/framing.md §"Phase 5 protocol analysis" for full analysis.
    """
    params: dict[str, str] = {}
    pos = 14  # skip 14-byte header
    n = len(data)
    pending: list[str] = []

    while pos + 1 < n:
        entry_type = data[pos]
        if entry_type not in (0x54, 0x51):
            break
        if pos + 2 > n:
            break
        name_len = data[pos + 1]
        pos += 2
        if pos + name_len > n:
            break
        name = data[pos : pos + name_len].decode("ascii", "replace")
        pos += name_len
        if entry_type == 0x51:
            pending.append(name)

    # pos now past all declarations; scan for each pending param's value:
    # pattern: 0x43 [val_len_1B] 0x80 [val_bytes] 0x45
    for name in pending:
        i = pos
        while i + 3 < n:
            if data[i] == 0x43 and data[i + 2] == 0x80:
                val_len = data[i + 1]
                val_end = i + 3 + val_len
                if val_end < n and data[val_end] == 0x45:
                    params[name] = data[i + 3 : val_end].decode("ascii", "replace")
                    pos = val_end + 1
                    break
            i += 1

    return params


_5001_HEX = frozenset(b"0123456789ABCDEF")
_5001_FM = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def _scan_5001_char_values(data: bytes) -> list[tuple[int, int, bytes]]:
    """Scan all 0x43 [len] 0x80 [len bytes] CHAR encodings in a 5001 block.

    Returns [(offset, length, value_bytes), ...] in encounter order.
    Jumps past each match so nested false-positives are avoided.
    """
    results: list[tuple[int, int, bytes]] = []
    n = len(data)
    i = 0
    while i < n - 2:
        if data[i] == 0x43 and data[i + 2] == 0x80:
            vlen = data[i + 1]
            vend = i + 3 + vlen
            if vend <= n:
                results.append((i, vlen, data[i + 3 : vend]))
                i = vend
                continue
        i += 1
    return results


def _extract_trfc_params_from_5001(raw_5001: bytes) -> tuple[str, str]:
    """Extract (tid_24, arfcfnam) from an ARFC_DEST_SHIP 0x5001 block.

    confirmed ARFCSSTATE field order (getTidFields / getArfcDestShipFunctionDesc):
      ARFCIPID(8) + ARFCPID(4) + ARFCTIME(8) + ARFCTIDCNT(4) consecutive CHAR values
      → concatenated to form the 24-char TID (all uppercase hex from IP/PID/time/cnt).
    ARFCFNAM (the wrapped function module name): first CHAR value after the TID group
      that contains only uppercase ASCII + digits + underscore, with at least one '_'.

    Returns ("", "") when the block cannot be parsed (defensive, T-06-D02).
    """
    values = _scan_5001_char_values(raw_5001)

    # Find TID: 4 offset-consecutive CHAR values with exactly (8,4,8,4) hex bytes.
    tid = ""
    tid_end_idx = 0
    for j in range(len(values) - 3):
        o0, l0, v0 = values[j]
        o1, l1, v1 = values[j + 1]
        o2, l2, v2 = values[j + 2]
        o3, l3, v3 = values[j + 3]
        if (
            l0 == 8
            and l1 == 4
            and l2 == 8
            and l3 == 4
            and all(b in _5001_HEX for b in v0)
            and all(b in _5001_HEX for b in v1)
            and all(b in _5001_HEX for b in v2)
            and all(b in _5001_HEX for b in v3)
            and o1 == o0 + 3 + l0
            and o2 == o1 + 3 + l1
            and o3 == o2 + 3 + l2
        ):
            tid = (v0 + v1 + v2 + v3).decode("ascii")
            tid_end_idx = j + 4
            break

    # Find ARFCFNAM: first CHAR value after TID group that looks like a SAP FM name.
    # SAP function module names are uppercase+digits+underscore and always have '_'.
    arfcfnam = ""
    for _, vlen, val in values[tid_end_idx:]:
        if 1 <= vlen <= 30 and all(b in _5001_FM for b in val) and b"_" in val:
            arfcfnam = val.decode("ascii")
            break

    return tid, arfcfnam


def _gwserv_port(gwserv: str) -> int:
    """Resolve SAP gateway service name to TCP port.

    sapgwNN → 3300+NN; numeric string → int; else socket lookup.
    """
    s = gwserv.strip().lower()
    if s.startswith("sapgw"):
        try:
            return 3300 + int(s[5:])
        except ValueError:
            return 3300
    try:
        return int(s)
    except ValueError:
        import socket as _sock

        return _sock.getservbyname(s, "tcp")


def _dispatcher_svc_8(gwserv: str) -> bytes:
    """Derive the 8-byte SAP dispatcher service name from the gateway service.

    REGISTER_TP [64:72] uses the DISPATCHER service (e.g. "sapdp00 "), NOT the gateway
    service — even though the connection is made to the gateway port. The gateway requires
    the dispatcher service name here (pcap pkt8 confirmed: gwserv="sapgw00"/3300 but
    REGISTER_TP [64:72] = "sapdp00 "). Gateway port = 3300+sysnr; dispatcher = 3200+sysnr.
    """
    s = gwserv.strip().lower()
    if s.startswith("sapgw"):
        suffix = gwserv.strip()[5:]  # "00" from "sapgw00"
    else:
        try:
            port = int(s)
            sysnr = port - 3300  # 3300 = sapgw00, 3301 = sapgw01, ...
            suffix = f"{sysnr:02d}"
        except ValueError:
            suffix = "00"
    return f"sapdp{suffix}".ljust(8).encode("ascii")[:8]


class RfcServer:
    """Sans-I/O RFC server: handler registry + inbound dispatch + asyncio serve.

    Usage (sync facade, D-02)::

        server = RfcServer({"program_id": "MY_PROG", "gwhost": "gw", "gwserv": "sapgw00"})

        @server.function("STFC_CONNECTION", stfc_desc)
        def handle(request: dict) -> dict:
            return {"ECHOTEXT": request["REQUTEXT"], "RESPTEXT": "ok"}

        server.serve_forever()   # blocks; runs the asyncio loop in a daemon thread
        # ... server.stop() from another thread to tear down cleanly ...

    The offline-testable core is ``dispatch_inbound(frame) -> bytes`` (frame bytes
    in, response bytes out) — no sockets. ``serve``/``serve_forever`` drive it over
    a live gateway connection.
    """

    def __init__(self, params: dict[str, Any]) -> None:
        # Registration params (program_id/gwhost/gwserv). Shape is discretion; the
        # ServerSession enforces the registration constraints when serve() registers.
        self._params = dict(params)
        # FM_NAME.upper() -> (FunctionDesc | None, handler) — mirrors MetadataCache keying.
        # func_desc may be None for transactional handlers where dispatch short-circuits
        # before deserialization (no FunctionDesc needed at registration time).
        self._registry: dict[
            str, tuple[FunctionDesc | None, Callable[[dict[str, Any]], dict[str, Any]]]
        ] = {}
        # Generic fallback consulted on a registry miss (D-09); None by default.
        self._generic: (
            Callable[
                [str], tuple[FunctionDesc | None, Callable[[dict[str, Any]], dict[str, Any]]] | None
            ]
            | None
        ) = None
        # Auth callback (SERVER-05); None means "no auth check" (allow all).
        self._auth_check: Callable[..., bool] | None = None
        # TID store (TRFC-03 / D-03): default InMemoryTidStore so a bare server works.
        # Replace with a custom durable store via set_tid_store().
        self._tid_store: TidStore = InMemoryTidStore()
        # Transaction lifecycle callbacks (SDK type definitions-732 — RfcInstallTransactionHandlers).
        # When set, invoked at the corresponding check→commit/rollback→confirm sequence points.
        # Unset (None) means the store-only default behaviour applies (Task 1 dispatch).
        self._on_check_transaction: Callable[[str], int] | None = None
        self._on_commit_transaction: Callable[[str], None] | None = None
        self._on_rollback_transaction: Callable[[str], None] | None = None
        self._on_confirm_transaction: Callable[[str], None] | None = None
        # bgRFC Unit store (TRFC-07 / D-03): default InMemoryUnitStore so a bare server works.
        # Replace with a custom durable store via set_unit_store().
        self._unit_store: UnitStore = InMemoryUnitStore()
        # bgRFC unit lifecycle callbacks (SDK type definitions-741 — RfcInstallBgRfcHandlers).
        # Unset (None) means store-only default behaviour applies.
        self._on_check_unit: Callable[..., int] | None = None
        self._on_commit_unit: Callable[..., None] | None = None
        self._on_rollback_unit: Callable[..., None] | None = None
        self._on_confirm_unit: Callable[..., None] | None = None
        self._on_get_unit_state: Callable[..., UnitState] | None = None
        # serve-loop lifecycle (set up by serve_forever).
        self._thread: threading.Thread | None = None
        self._transport: Transport | None = None  # live Transport; set during _serve_blocking
        self._stopped: bool = False
        self._session = ServerSession()

    # --------------------------------------------------------------------- #
    # Registry + decorator (SERVER-01, D-07/D-08/D-09)
    # --------------------------------------------------------------------- #
    def function(
        self, name: str, func_desc: FunctionDesc | None = None
    ) -> Callable[
        [Callable[[dict[str, Any]], dict[str, Any]]], Callable[[dict[str, Any]], dict[str, Any]]
    ]:
        """Decorator registering ``(func_desc, fn)`` under ``name.upper()`` (D-07).

        ``func_desc`` is optional: for transactional handlers where the server
        dispatch short-circuits before deserialization (e.g. duplicate TID returns
        RFC_EXECUTED without deserializing the request), ``FunctionDesc`` is not
        needed at registration time. Pass ``None`` or omit it in that case.

        The wrapped handler is returned unchanged, so the decorated name stays a
        normal callable::

            @server.function("STFC_CONNECTION", desc)  # sync: desc required for deserialization
            def handle(request: dict) -> dict: ...

            @server.function("MY_TRFC_FM")             # transactional: no desc needed at register
            def trfc_handle(request: dict) -> dict: ...
        """
        key = name.upper()

        def _register(
            fn: Callable[[dict[str, Any]], dict[str, Any]],
        ) -> Callable[[dict[str, Any]], dict[str, Any]]:
            self._registry[key] = (func_desc, fn)
            return fn

        return _register

    def set_generic_handler(
        self,
        fn: Callable[[str], tuple[FunctionDesc, Callable[[dict[str, Any]], dict[str, Any]]] | None],
    ) -> None:
        """Register a fallback consulted on a registry miss (D-09).

        ``fn(func_name)`` returns ``(FunctionDesc, handler)`` to serve the call, or
        ``None`` to decline (→ SYSTEM_FAILURE). The default is no generic handler,
        so an unknown FM yields SYSTEM_FAILURE with no information leak about which
        FMs are registered (threat V4 / T-05-C05 — generic handler is explicit
        opt-in and must validate/whitelist).
        """
        self._generic = fn

    def set_authentication_check(self, fn: Callable[..., bool]) -> None:
        """Register an auth callback run before handler dispatch (SERVER-05).

        ``fn`` receives the inbound credentials and returns ``True`` to allow the
        call or ``False`` to deny it. On deny the handler is NOT invoked and an
        auth-failure SYSTEM_FAILURE is returned (T-05-C06). The callback signature
        is invoked as ``fn(user=..., password=...)`` (keyword args); a single
        unhandled credential field is passed as ``None``. Inbound credentials are
        NEVER logged (T-04-CRED / T-05-C03).
        """
        self._auth_check = fn

    def set_tid_store(self, store: TidStore) -> None:
        """Replace the default InMemoryTidStore with a custom durable store (TRFC-08).

        The custom store is used by ``dispatch_inbound`` for the transactional
        dispatch branch: duplicate-TID detection (``is_executed``), crash-safe
        persistence (``mark_received`` before handler), and lifecycle management
        (``mark_executed`` / ``mark_rolled_back`` / ``confirm``).

        ``store`` must satisfy the :class:`~saprfclib.stores.TidStore` Protocol
        (structural typing, D-01). Optionally validated with isinstance when
        TidStore is @runtime_checkable.

        Example::

            db_store = MyPostgreSQLTidStore(conn)
            server.set_tid_store(db_store)
        """
        if not isinstance(store, TidStore):
            raise TypeError(
                f"store must implement the TidStore Protocol, got {type(store).__name__!r}"
            )
        self._tid_store = store

    def install_transaction_handlers(
        self,
        *,
        on_check: Callable[[str], int] | None = None,
        on_commit: Callable[[str], None] | None = None,
        on_rollback: Callable[[str], None] | None = None,
        on_confirm: Callable[[str], None] | None = None,
    ) -> None:
        """Register the four tRFC transaction lifecycle callbacks (TRFC-03).

        Maps the ``RfcInstallTransactionHandlers`` API (SDK type definitions-732):

        - ``on_check(tid) -> int``: called first; return 0 (RFC_OK) for a new TID
          or 16 (RFC_EXECUTED) if already executed. When set, this callback REPLACES
          the default store-based check (``TidStore.is_executed``).
        - ``on_commit(tid) -> None``: called after the handler succeeds; maps to
          ``TidStore.mark_executed``.
        - ``on_rollback(tid) -> None``: called when the handler raises an exception;
          maps to ``TidStore.mark_rolled_back``.
        - ``on_confirm(tid) -> None``: called as cleanup after commit/rollback;
          maps to ``TidStore.confirm``.

        When unset (None), the corresponding store method is used directly. Setting
        the callbacks enables the full ``RFC_ON_CHECK/COMMIT/ROLLBACK/CONFIRM_TRANSACTION``
        contract from SDK type definitions.

        Example::

            server.install_transaction_handlers(
                on_check=lambda tid: 16 if my_db.has(tid) else 0,
                on_commit=lambda tid: my_db.commit(tid),
                on_rollback=lambda tid: my_db.rollback(tid),
                on_confirm=lambda tid: my_db.remove(tid),
            )
        """
        self._on_check_transaction = on_check
        self._on_commit_transaction = on_commit
        self._on_rollback_transaction = on_rollback
        self._on_confirm_transaction = on_confirm

    def set_unit_store(self, store: UnitStore) -> None:
        """Replace the default InMemoryUnitStore with a custom durable store (TRFC-08).

        The custom store is used by ``dispatch_inbound`` for the bgRFC unit dispatch
        branch: unit state tracking (``get_unit_state``), persistence (``persist``),
        and lifecycle management (``confirm``).

        ``store`` must satisfy the :class:`~saprfclib.stores.UnitStore` Protocol
        (structural typing, D-02). Optionally validated with isinstance when
        UnitStore is @runtime_checkable.

        Example::

            db_store = MyPostgreSQLUnitStore(conn)
            server.set_unit_store(db_store)
        """
        if not isinstance(store, UnitStore):
            raise TypeError(
                f"store must implement the UnitStore Protocol, got {type(store).__name__!r}"
            )
        self._unit_store = store

    def install_unit_handlers(
        self,
        *,
        check: Callable[..., int] | None = None,
        commit: Callable[..., None] | None = None,
        rollback: Callable[..., None] | None = None,
        confirm: Callable[..., None] | None = None,
        get_state: Callable[..., UnitState] | None = None,
    ) -> None:
        """Register the five bgRFC unit lifecycle callbacks (TRFC-07).

        Maps ``RfcInstallBgRfcHandlers`` (SDK type definitions-741):

        - ``check(unit_id, unit_type) -> int``: called first; return 0 (RFC_OK) for a
          new unit or 16 (RFC_EXECUTED) if already known.
        - ``commit(unit_id, unit_type) -> None``: called after handler executes
          successfully; maps to ``UnitStore.persist`` → ``UnitStore.confirm``.
        - ``rollback(unit_id, unit_type) -> None``: called when a handler raises;
          maps to ``UnitState.ROLLED_BACK`` state.
        - ``confirm(unit_id, unit_type) -> None``: called after commit as cleanup;
          maps to ``UnitStore.confirm``.
        - ``get_state(unit_id, unit_type) -> UnitState``: called on inbound state
          query; maps to ``UnitStore.get_unit_state``.

        When unset (None), the corresponding store method is used directly.

        Example::

            server.install_unit_handlers(
                check=lambda uid, ut: 16 if db.has_unit(uid) else 0,
                commit=lambda uid, ut: db.commit_unit(uid, ut),
                rollback=lambda uid, ut: db.rollback_unit(uid, ut),
                confirm=lambda uid, ut: db.confirm_unit(uid, ut),
                get_state=lambda uid, ut: db.get_unit_state(uid, ut),
            )
        """
        self._on_check_unit = check
        self._on_commit_unit = commit
        self._on_rollback_unit = rollback
        self._on_confirm_unit = confirm
        self._on_get_unit_state = get_state

    # --------------------------------------------------------------------- #
    # Sans-I/O dispatch core (SERVER-03/04/05/06) — frame bytes in, bytes out
    # --------------------------------------------------------------------- #
    def dispatch_inbound(self, frame: bytes) -> bytes:
        """Deserialize one inbound call, run the handler, serialize the response.

        Pure function of ``frame`` (no I/O) — the offline-testable seam. Steps:

        1. Strip the live GW header if present (``_strip_gw_header``; bare TLV from
           MockTransport passes through — first byte != 0x06).
        2. Read the function name (tag 0x0102, UTF-16LE).

        Phase-6 Pitfall 6 seam: the call-type IS the function name.
        Branch on name BEFORE normal handler lookup (TRFC-03):
          - ``ARFC_DEST_SHIP``    → transactional tRFC/qRFC dispatch (this phase)
          - ``ARFC_DEST_CONFIRM`` → tRFC confirm (Plan 06-05; placeholder SYSTEM_FAILURE)
          - any other name       → synchronous dispatch (existing path, unchanged)

        Synchronous path (unchanged — Pitfall 2 regression guard):
        3. Look up the handler, fall back to generic, then SYSTEM_FAILURE if unknown.
        4. Auth check (SERVER-05) before handler.
        5. Deserialize request (SERVER-03, Pitfall 4).
        6. Handler dispatch, exception-isolated (SERVER-06).
        7. Serialize response (SERVER-04).
        """
        tlv = _strip_gw_header(frame)

        # Phase-6 Pitfall 6 seam: function name IS the call-type discriminator
        # (protocol analysis — no separate byte needed).
        fname = self._read_func_name(tlv)

        if fname == _ARFC_DEST_SHIP:
            # Transactional tRFC/qRFC inbound dispatch (TRFC-03).
            return self._dispatch_transactional(tlv, fname)

        # ARFC_DEST_CONFIRM is handled by the gateway-side SAP infra; if it somehow
        # reaches our registered server, respond with SYSTEM_FAILURE until a full
        # confirm path is implemented (placeholder; does not regress sync tests).
        if fname == _ARFC_DEST_CONFIRM:
            return self._build_rfc_ok_response()

        # bgRFC unit submit (TRFC-07): BGRFC_DEST_SHIP → _dispatch_bgrfc_unit
        if fname == _BGRFC_DEST_SHIP:
            return self._dispatch_bgrfc_unit(tlv)

        # bgRFC confirm: BGRFC_DEST_CONFIRM → confirm the unit in the store
        if fname == _BGRFC_DEST_CONFIRM:
            return self._dispatch_bgrfc_confirm(tlv)

        # bgRFC state query: BGRFC_CHECK_UNIT_STATE_SERVER → return UnitState
        if fname == _BGRFC_CHECK_UNIT_STATE_SERVER:
            return self._dispatch_bgrfc_state_query(tlv)

        # ----- SYNCHRONOUS DISPATCH (unchanged — Pitfall 2 regression guard) -----
        entry = self._registry.get(fname.upper())
        if entry is None and self._generic is not None:
            entry = self._generic(fname)
        if entry is None:
            # No info leak about the registered set (V4 / T-05-C05).
            return self._build_system_failure(f"function {fname} not registered")
        func_desc, handler = entry

        # --- authentication (SERVER-05 / T-05-C06) — BEFORE handler dispatch ---
        if self._auth_check is not None and not self._check_auth(tlv):
            return self._build_system_failure("authentication failed")

        # --- deserialize request → typed dict (SERVER-03, Pitfall 4) ---
        request = self._deserialize_request(tlv, func_desc)

        # --- handler dispatch, exception-isolated (SERVER-06 / D-03 / T-05-C01) ---
        try:
            result = handler(request)
        except Exception as exc:  # noqa: BLE001 — isolate ALL handler errors
            # str(exc) only — never a full traceback, never credentials (T-05-C02).
            return self._build_system_failure(str(exc))

        if result is None:
            result = {}
        return self._build_response(func_desc, result)

    def _dispatch_transactional(self, tlv: bytes, fname: str) -> bytes:
        """Transactional (tRFC/qRFC) inbound dispatch — TRFC-03 exactly-once gate.

        Implements the server-side dedup state machine from RESEARCH Pattern 2
        (docs/protocol/trfc.md §"Server-Side Dispatch") and SDK type definitions-732:

          1. Extract TID from the ARFCTID param; validate (V5 — reject non-24-char
             TIDs before any store call, T-06-D02).
          2. check_transaction(tid): if is_executed → return RFC_EXECUTED (no handler).
          3. mark_received(tid) BEFORE handler execute (crash-safety, T-06-D01).
          4. Run the application handler inside the standard exception-isolation block
             (reuse of lines 413-418 verbatim, T-06-D03 / T-05-C01).
             a. Success → mark_executed(tid) + confirm(tid).
             b. Exception → mark_rolled_back(tid) + SYSTEM_FAILURE(str(exc)) first-line only.

        When ``install_transaction_handlers`` callbacks are set, they are invoked at
        the corresponding points (step 2 → on_check; step 4a → on_commit + on_confirm;
        step 4b → on_rollback). Store calls serve as fallback when callbacks are unset.

        The synchronous dispatch path (other function names) is NOT touched.
        """
        # --- TID extraction + validation (V5 / T-06-D02) ---
        tid = self._extract_tid_from_frame(tlv)
        if not tid:
            return self._build_system_failure(
                "ARFC_DEST_SHIP: missing ARFCTID param in inbound frame"
            )
        if len(tid) != _TID_LN:
            return self._build_system_failure(
                f"ARFC_DEST_SHIP: invalid TID length {len(tid)} (expected {_TID_LN})"
            )
        if any(c not in _TID_ALPHABET for c in tid):
            return self._build_system_failure(
                "ARFC_DEST_SHIP: TID contains characters outside RFC alphabet"
            )

        # --- check_transaction: is_executed? (TRFC-03 dedup short-circuit) ---
        store = self._tid_store
        if self._on_check_transaction is not None:
            rc = self._on_check_transaction(tid)
            already_done = rc == _RC_EXECUTED
        else:
            already_done = store.is_executed(tid)

        if already_done:
            # Known TID — return RFC_EXECUTED; DO NOT call the application handler.
            return self._build_rfc_executed_response()

        # --- persist BEFORE execute (crash-safety — Pattern 2, T-06-D01) ---
        store.mark_received(tid)

        # --- resolve handler from registry (wrapped FM name is in ARFCFNAM param) ---
        wrapped_fn = self._extract_param_from_frame(tlv, "ARFCFNAM")
        entry = None
        if wrapped_fn:
            entry = self._registry.get(wrapped_fn.upper())
        if entry is None and self._generic is not None and wrapped_fn:
            entry = self._generic(wrapped_fn)
        # If no handler, run a no-op (consistent with exactly-once: we still mark TID).
        # The handler must be present for a meaningful execution; if absent, the TID
        # is persisted but SYSTEM_FAILURE is returned (deferred-handler path).
        if entry is None:
            store.mark_rolled_back(tid)
            if self._on_rollback_transaction is not None:
                self._on_rollback_transaction(tid)
            return self._build_system_failure(
                f"ARFC_DEST_SHIP: no handler registered for {wrapped_fn!r}"
            )
        func_desc, handler = entry

        # --- deserialize request (Pitfall 4 direction flip — same as sync path) ---
        request = self._deserialize_request(tlv, func_desc) if func_desc is not None else {}

        # --- handler dispatch, exception-isolated (T-06-D03 / T-05-C01) ---
        try:
            result = handler(request)
        except Exception as exc:  # noqa: BLE001 — isolate ALL handler errors
            store.mark_rolled_back(tid)
            if self._on_rollback_transaction is not None:
                self._on_rollback_transaction(tid)
            # str(exc) only — no traceback, no credential leak (T-06-D03 / T-05-C02).
            return self._build_system_failure(str(exc))

        # --- commit (on_commit) — mark TID executed; keep in store for dedup ---
        # NOTE: confirm() / on_confirm are NOT called here. The TID must remain
        # in the store as "executed" so that retry deliveries see it as a dup
        # and return RFC_EXECUTED (exactly-once guarantee). Confirmation (cleanup)
        # happens only when the client sends ARFC_DEST_CONFIRM (a separate call),
        # which maps to the on_confirm callback. Removing the TID here (calling
        # store.confirm()) would break dedup on retry — Pitfall 3.
        store.mark_executed(tid)
        if self._on_commit_transaction is not None:
            self._on_commit_transaction(tid)

        if result is None:
            result = {}
        # tRFC has no EXPORTING params by design (CONTEXT Claude's discretion).
        # Return a minimal success response (RFC_OK) without deserializing the desc.
        return self._build_rfc_ok_response()

    # --------------------------------------------------------------------- #
    # bgRFC unit dispatch (TRFC-07) — Plan 06-05
    # --------------------------------------------------------------------- #

    def _dispatch_bgrfc_unit(self, tlv: bytes) -> bytes:
        """bgRFC unit inbound dispatch — TRFC-07 unit callback state machine.

        Implements the server-side unit processing sequence from
        docs/protocol/trfc.md §"Server-Side Dispatch" and SDK type definitions-2500:

          1. Extract + validate UnitID (exactly 32 uppercase hex chars, V5 / T-06-U02).
          2. Extract unit_type ('T' or 'Q') from frame params.
          3. check_unit(uid, unit_type): if already executed → return RFC_EXECUTED.
          4. persist(uid, unit_type) BEFORE handler execute (crash-safety, T-06-U01).
          5. Execute each buffered call from the frame (exception-isolated, T-06-U03).
          6. Success → on_commit(uid, unit_type) + store state = COMMITTED.
          7. on_confirm(uid, unit_type) + store.confirm(uid, unit_type).
          8. Exception → on_rollback(uid, unit_type) + store state = ROLLED_BACK.

        Threat mitigations:
          T-06-U01: persist before execute; confirm is a separate step.
          T-06-U02: reject non-32-char or non-hex UnitID before store lookup.
          T-06-U03: handler exception isolation — SYSTEM_FAILURE(str(exc)) only.
          T-06-U04: NOT_FOUND after confirm is success; never resend (N/A server side).
        """
        # --- UnitID extraction + validation (V5 / T-06-U02) ---
        unit_id = self._extract_param_from_frame(tlv, "BGRFC_UNIT_ID")
        if not unit_id:
            return self._build_system_failure(
                "BGRFC_DEST_SHIP: missing BGRFC_UNIT_ID param in inbound frame"
            )
        if len(unit_id) != _UNITID_LN:
            return self._build_system_failure(
                f"BGRFC_DEST_SHIP: invalid UnitID length {len(unit_id)} (expected {_UNITID_LN})"
            )
        if any(c not in _UNITID_CHARSET for c in unit_id):
            return self._build_system_failure(
                "BGRFC_DEST_SHIP: UnitID contains characters outside uppercase hex charset "
                "(allowed: 0-9A-F)"
            )

        # --- unit_type extraction ---
        unit_type = self._extract_param_from_frame(tlv, "BGRFC_UNIT_TYPE") or "T"
        if unit_type not in ("T", "Q"):
            unit_type = "T"  # defensive default; invalid type treated as 'T'

        unit_store = self._unit_store

        # --- check_unit: already executed? ---
        if self._on_check_unit is not None:
            rc = self._on_check_unit(unit_id, unit_type)
            already_done = rc == _RC_EXECUTED
        else:
            state = unit_store.get_unit_state(unit_id, unit_type)
            already_done = state in (UnitState.COMMITTED, UnitState.CONFIRMED)

        if already_done:
            return self._build_rfc_executed_response()

        # --- persist BEFORE execute (crash-safety, T-06-U01) ---
        unit_store.persist(unit_id, unit_type)

        # --- execute buffered calls (exception-isolated, T-06-U03) ---
        # Each buffered call in the frame was embedded by build_bgrfc_request as
        # raw bytes under BGRFC_CALL_N params.  For each call, extract and attempt
        # to dispatch through the standard handler registry (existing isolation block).
        # If the call bytes cannot be parsed or the handler is missing, treat as
        # a handler error but continue (isolation: one bad call does not abort the unit).
        call_error: str | None = None
        call_count_str = self._extract_param_from_frame(tlv, "BGRFC_CALL_COUNT")
        call_count = 0
        if call_count_str:
            try:
                call_count = int(call_count_str)
            except ValueError:
                call_count = 0

        for i in range(call_count):
            call_bytes = self._extract_raw_param_from_frame(tlv, f"BGRFC_CALL_{i}")
            if call_bytes is None:
                continue
            # Try to decode the embedded call (func_name from UTF-16LE until NUL NUL).
            try:
                call_error = self._execute_buffered_call(call_bytes)
            except Exception as exc:  # noqa: BLE001 — isolate ALL errors (T-06-U03)
                call_error = str(exc).splitlines()[0][:512]

        if call_error is not None:
            # Exception in a unit call → rollback path (T-06-U03)
            if self._on_rollback_unit is not None:
                try:
                    self._on_rollback_unit(unit_id, unit_type)
                except Exception:  # noqa: BLE001
                    pass
            return self._build_system_failure(call_error)

        # --- success path → on_commit + store committed + on_confirm ---
        if self._on_commit_unit is not None:
            try:
                self._on_commit_unit(unit_id, unit_type)
            except Exception:  # noqa: BLE001 — isolate callback errors
                # Commit callback error: still confirm store (persist-then-commit separation)
                pass

        unit_store.confirm(unit_id, unit_type)

        if self._on_confirm_unit is not None:
            try:
                self._on_confirm_unit(unit_id, unit_type)
            except Exception:  # noqa: BLE001
                pass

        return self._build_rfc_ok_response()

    def _dispatch_bgrfc_confirm(self, tlv: bytes) -> bytes:
        """Handle BGRFC_DEST_CONFIRM: confirm unit in the store."""
        unit_id = self._extract_param_from_frame(tlv, "BGRFC_UNIT_ID")
        unit_type = self._extract_param_from_frame(tlv, "BGRFC_UNIT_TYPE") or "T"
        if not unit_id or len(unit_id) != _UNITID_LN:
            return self._build_system_failure(
                "BGRFC_DEST_CONFIRM: invalid or missing BGRFC_UNIT_ID"
            )
        # T-06-U04: NOT_FOUND after confirm = success; do not error.
        self._unit_store.confirm(unit_id, unit_type)
        if self._on_confirm_unit is not None:
            try:
                self._on_confirm_unit(unit_id, unit_type)
            except Exception:  # noqa: BLE001
                pass
        return self._build_rfc_ok_response()

    def _dispatch_bgrfc_state_query(self, tlv: bytes) -> bytes:
        """Handle BGRFC_CHECK_UNIT_STATE_SERVER: return unit state."""
        unit_id = self._extract_param_from_frame(tlv, "BGRFC_UNIT_ID")
        unit_type = self._extract_param_from_frame(tlv, "BGRFC_UNIT_TYPE") or "T"
        if not unit_id or len(unit_id) != _UNITID_LN:
            return self._build_system_failure(
                "BGRFC_CHECK_UNIT_STATE_SERVER: invalid or missing BGRFC_UNIT_ID"
            )
        if self._on_get_unit_state is not None:
            try:
                state = self._on_get_unit_state(unit_id, unit_type)
            except Exception:  # noqa: BLE001
                state = UnitState.NOT_FOUND
        else:
            state = self._unit_store.get_unit_state(unit_id, unit_type)
        # Encode state name as a CHAR param in the response TLV.
        return b"".join(
            [
                tlv_record(_TAG_RESPONSE_START),
                tlv_record(_TAG_RETURN_CODE, struct.pack(">I", _RC_OK)),
                tlv_record(_TAG_PARAM_NAME, "BGRFC_STATE".encode("utf-16-le")),
                tlv_record(_TAG_PARAM_VALUE, state.name.encode("utf-16-le")),
                tlv_record(_TAG_TERMINATOR),
            ]
        )

    def _execute_buffered_call(self, call_bytes: bytes) -> str | None:
        """Execute one buffered call from a bgRFC unit payload.

        Decodes the func_name from the call_bytes (UTF-16LE until NUL NUL separator),
        looks up the handler, and dispatches it.  Returns None on success or an error
        string (str(exc) first line) on failure.

        This method is exception-isolated: the caller wraps it in try/except to
        satisfy T-06-U03 (no traceback leak, no credential leak).
        """
        if not call_bytes:
            return None

        # Decode func_name: the first UTF-16LE string up to NUL NUL (b"\x00\x00" separator)
        try:
            nul_pos = call_bytes.find(b"\x00\x00")
            if nul_pos < 0 or nul_pos % 2 != 0:
                # No NUL NUL separator found — entire payload is the func_name
                func_name = call_bytes.decode("utf-16-le").rstrip("\x00 ")
            else:
                func_name = call_bytes[:nul_pos].decode("utf-16-le").rstrip("\x00 ")
        except Exception:
            return None  # Cannot decode func_name — skip this call

        if not func_name:
            return None

        entry = self._registry.get(func_name.upper())
        if entry is None and self._generic is not None:
            entry = self._generic(func_name)
        if entry is None:
            # No handler registered — return error (does not crash the unit)
            return f"bgRFC: no handler registered for {func_name!r}"

        func_desc, handler = entry
        # For bgRFC buffered calls, params are not yet deserialized (OG-06-02).
        # Pass an empty request dict until live-capture confirms the encoding.
        try:
            handler({})
        except Exception as exc:  # noqa: BLE001 — isolate (T-06-U03)
            return str(exc).splitlines()[0][:512]
        return None

    @staticmethod
    def _extract_raw_param_from_frame(tlv: bytes, param_name: str) -> bytes | None:
        """Extract a raw (bytes) named param value from a TLV frame.

        Returns the raw bytes value of the first param whose name matches
        ``param_name`` (case-insensitive).  Returns None if not found.
        Used for BGRFC_CALL_N entries (binary payload, not UTF-16LE strings).
        """
        key = param_name.upper()
        pos = 0
        n = len(tlv)
        current_name: str | None = None

        while pos + 4 <= n:
            tag = struct.unpack_from(">H", tlv, pos)[0]
            length = struct.unpack_from(">H", tlv, pos + 2)[0]
            pos += 4
            if tag == _TAG_TERMINATOR:
                break
            if length == 0xFFFF:
                if pos + 4 > n:
                    break
                ext_len = struct.unpack_from(">I", tlv, pos)[0]
                pos += 4
                end = pos + ext_len
                if end > n:
                    break
                value = tlv[pos:end]
                pos = end
            else:
                end = pos + length
                if end > n:
                    break
                value = tlv[pos:end]
                pos = end
            # Skip close tag
            if pos + 2 <= n and struct.unpack_from(">H", tlv, pos)[0] == tag:
                pos += 2
            if tag == _TAG_PARAM_NAME:
                current_name = _decode_utf16le(value)
            elif tag == _TAG_PARAM_VALUE and current_name is not None:
                if current_name.upper() == key:
                    return value
                current_name = None
        return None

    # --------------------------------------------------------------------- #
    # Request deserialize (SERVER-03)
    # --------------------------------------------------------------------- #
    @staticmethod
    def _read_func_name(tlv: bytes) -> str:
        """Read the function-module name from tag 0x0102 (UTF-16LE).

        Uses the bounds-checked invoke walker (T-05-C04); returns "" if absent.
        """
        tags = _parse_tlv_stream(tlv)
        raw = tags.get(_TAG_FUNC_NAME)
        if raw is None:
            return ""
        return _decode_utf16le(raw)

    @staticmethod
    def _deserialize_request(tlv: bytes, func_desc: FunctionDesc | None) -> dict[str, Any]:
        """Walk 0x0201/0x0203 pairs and decode each into a typed Python value.

        The request carries the client's IMPORTING values as-is (Pitfall 4); each
        is decoded via ``codec.decode(field.rfctype, raw, field)`` per the
        registered FunctionDesc. Unknown param names are ignored defensively.

        When ``func_desc`` is ``None`` (transactional handler registered without a
        descriptor, or dedup short-circuit caller), returns an empty dict — no
        deserialization is attempted.

        Registered-server inbound path: SAP encodes params in a 0x5001 compact
        block (no 0x0201/0x0203 pairs). When the primary walk finds nothing, fall
        back to ``_extract_5001_params`` which decodes the compact ASCII format.
        """
        if func_desc is None:
            return {}
        name_to_field: dict[str, FieldDesc] = {f.name.upper(): f for f in func_desc.parameters}
        request: dict[str, object] = {}
        for name, raw in _extract_name_value_pairs(tlv):
            field = name_to_field.get(name.upper())
            if field is None:
                continue
            request[field.name] = decode(field.rfctype, raw, field)

        # Registered-server inbound: 0x5001 compact param block (no 0x0201/0x0203)
        if not request:
            tags = _parse_tlv_stream(tlv)
            raw_5001 = tags.get(0x5001)
            if raw_5001 is not None:
                for name, value_str in _extract_5001_params(raw_5001).items():
                    field = name_to_field.get(name.upper())
                    if field is not None:
                        request[field.name] = value_str

        return request

    # --------------------------------------------------------------------- #
    # Transactional dispatch helpers (TRFC-03)
    # --------------------------------------------------------------------- #

    @staticmethod
    def _extract_tid_from_frame(tlv: bytes) -> str:
        """Extract the ARFCTID parameter value from an ARFC_DEST_SHIP frame.

        Tries 0x0201/0x0203 pairs first (offline fixtures / Python-built frames),
        then falls back to the 0x5001 compact block (live SAP inbound tRFC frames
        use NgRfc format — same encoding as Phase 5 registered-server inbound).

        Returns the TID string (stripped of padding), or ``""`` if absent.
        """
        for name, val in _extract_name_value_pairs(tlv):
            if name.upper() == _PARAM_ARFCTID:
                return _decode_utf16le(val)
        # Fallback: live SAP sends params in 0x5001 compact block (ARFC_DEST_SHIP)
        raw_5001 = _parse_tlv_stream(tlv).get(0x5001)
        if raw_5001 is not None:
            tid, _ = _extract_trfc_params_from_5001(raw_5001)
            return tid
        return ""

    @staticmethod
    def _extract_param_from_frame(tlv: bytes, param_name: str) -> str:
        """Extract any named UTF-16LE CHAR param value from a TLV frame.

        Tries 0x0201/0x0203 pairs first (offline fixtures / Python-built frames),
        then falls back to the 0x5001 compact block (live SAP inbound tRFC frames).

        Used for ARFCFNAM (the wrapped function module name) and other metadata
        params in the ARFC_DEST_SHIP frame.  Returns ``""`` if absent.
        """
        key = param_name.upper()
        for name, val in _extract_name_value_pairs(tlv):
            if name.upper() == key:
                return _decode_utf16le(val)
        # Fallback: live SAP sends params in 0x5001 compact block (ARFC_DEST_SHIP)
        raw_5001 = _parse_tlv_stream(tlv).get(0x5001)
        if raw_5001 is not None:
            tid, arfcfnam = _extract_trfc_params_from_5001(raw_5001)
            if key == "ARFCFNAM":
                return arfcfnam
            if key == _PARAM_ARFCTID:
                return tid
        return ""

    def _build_rfc_executed_response(self) -> bytes:
        """Build the RFC_EXECUTED wire response (SDK type definitions, value 0x10 = 16).

        The response return code is _RC_EXECUTED (16).  SAP's client interprets
        this as "TID already executed" and does NOT raise an error; it is a
        normal flow indicator for exactly-once dedup (TRFC-03).

        Format mirrors _build_system_failure but uses _RC_EXECUTED instead of
        _RC_SYSTEM_FAILURE.  No error-message TLV is emitted (not an error path).
        """
        return b"".join(
            [
                tlv_record(_TAG_RESPONSE_START),
                tlv_record(_TAG_RETURN_CODE, struct.pack(">I", _RC_EXECUTED)),
                tlv_record(_TAG_TERMINATOR),
            ]
        )

    def _build_rfc_ok_response(self) -> bytes:
        """Build a minimal RFC_OK (return-code 0) response with no output params.

        Used for tRFC success: ARFC_DEST_SHIP has no EXPORTING params (tRFC design).
        Format: 0x0500 empty + 0x0420 = 0 + 0xFFFF.
        """
        return b"".join(
            [
                tlv_record(_TAG_RESPONSE_START),
                tlv_record(_TAG_RETURN_CODE, struct.pack(">I", _RC_OK)),
                tlv_record(_TAG_TERMINATOR),
            ]
        )

    # --------------------------------------------------------------------- #
    # Response serialize (SERVER-04) — mirror build_invoke_request, flipped
    # --------------------------------------------------------------------- #
    def _build_response(self, func_desc: FunctionDesc | None, result: dict[str, Any]) -> bytes:
        """Serialize a handler return dict to the response TLV stream (SERVER-04).

        Mirror of ``invoke.build_invoke_request`` with directions flipped: emit the
        0x0500 response-start marker, the 0x0420 return code (0 = success), then one
        record group per EXPORTING/CHANGING/TABLE param the handler returned, then
        the 0xFFFF terminator. Reuses ``tlv_record`` + ``codec.encode`` — NO second
        TLV writer (RESEARCH Anti-Pattern).

        Scalars and structures use the 0x0201(name)/0x0203(value) pair. A TABLE
        parameter must NOT: it needs the table protocol, exactly as the client side
        does. Emitting a table as a scalar 0x0203 value is the server-direction twin
        of the mistyping that made client calls fail with
        CALL_FUNCTION_ILLEGAL_P_TYPE.

        Server-direction table shape, from the golden captures of a real SAP server
        (tests/golden/framing/rfc_read_table_response.bin, and the compressed
        metadata response): 0x0301(name) 0x0330(dm id) 0x0302(row_size,row_count)
        then one 0x0304 per row. No 0x0306 end tag — in that capture each table runs
        straight into the next 0x0301.

        When ``func_desc`` is ``None`` (handler registered without a descriptor),
        only the success header and terminator are emitted — no output params.
        """
        result_upper = {k.upper(): v for k, v in result.items()}
        dm_ids: list[str] = []  # DM table ids run from 1 in emission order
        parts: list[bytes] = [
            tlv_record(_TAG_RESPONSE_START),
            tlv_record(_TAG_RETURN_CODE, struct.pack(">I", _RC_OK)),
        ]
        if func_desc is not None:
            for field in func_desc.parameters:
                if field.direction not in _RESPONSE_DIRECTIONS:
                    continue  # pure IMPORTING — client sent it, server does not echo
                name_upper = field.name.upper()
                if name_upper not in result_upper:
                    continue  # handler did not supply this output — skip (optional)
                value = result_upper[name_upper]
                if field.rfctype == RFCTYPE_TABLE:
                    parts.extend(self._build_table_records(field, value, len(dm_ids) + 1))
                    dm_ids.append(field.name)
                    continue
                encoded = encode(field.rfctype, value, field)
                parts.append(tlv_record(_TAG_PARAM_NAME, field.name.encode("utf-16-le")))
                parts.append(tlv_record(_TAG_PARAM_VALUE, encoded))
        parts.append(tlv_record(_TAG_TERMINATOR))
        return b"".join(parts)

    @staticmethod
    def _build_table_records(field: FieldDesc, rows: Any, dm_id: int) -> list[bytes]:
        """Serialize one TABLE output parameter using the table protocol.

        An empty table is declared by name only, matching the client side where an
        empty table needs no data block.
        """
        if field.type_desc is None:
            raise ValueError(
                f"cannot encode TABLE parameter {field.name!r}: its row layout is "
                f"missing (type_desc is None)"
            )
        row_list = list(rows) if rows else []
        parts = [tlv_record(_TAG_TABLE_NAME, field.name.encode("utf-16-le"))]
        if not row_list:
            return parts
        row_size = field.type_desc.uc_size if field.unicode_mode else field.type_desc.nuc_size
        all_rows = encode(RFCTYPE_TABLE, row_list, field)
        parts.append(tlv_record(_TAG_DM_TABLE_ID, struct.pack(">I", dm_id)))
        parts.append(tlv_record(_TAG_TABLE_INFO, struct.pack(">II", row_size, len(row_list))))
        for i in range(len(row_list)):
            parts.append(tlv_record(_TAG_TABLE_ROW, all_rows[i * row_size : (i + 1) * row_size]))
        return parts

    def _build_system_failure(self, message: str) -> bytes:
        """Serialize an RFC SYSTEM_FAILURE response (D-03 / T-05-C02).

        Non-zero return code (0x0420) + an error-message TLV (0x0402, UTF-16LE).
        ``message`` is sanitized: it is the caller-supplied ``str(exc)`` only — no
        full traceback and no inbound credentials are ever placed here.
        """
        safe = self._sanitize_message(message)
        return b"".join(
            [
                tlv_record(_TAG_RESPONSE_START),
                tlv_record(_TAG_RETURN_CODE, struct.pack(">I", _RC_SYSTEM_FAILURE)),
                tlv_record(_TAG_ERROR_MESSAGE, safe.encode("utf-16-le")),
                tlv_record(_TAG_TERMINATOR),
            ]
        )

    @staticmethod
    def _sanitize_message(message: str) -> str:
        """Collapse a failure message to a single line (no traceback leakage).

        Only the first line is kept and length-bounded, so a handler that raises
        with an embedded traceback or a multi-line dump cannot leak it onto the
        wire (T-05-C02). Credentials never reach this path (they live only in the
        auth TLV, never in str(exc)).
        """
        if not message:
            return ""
        first_line = message.splitlines()[0]
        return first_line[:512]

    # --------------------------------------------------------------------- #
    # Authentication (SERVER-05) — placeholder until Task 2 wires the callback
    # --------------------------------------------------------------------- #
    def _check_auth(self, tlv: bytes) -> bool:
        """Extract inbound credentials and consult the auth callback (SERVER-05).

        The user (tag 0x0111) and password (tag 0x0117) are read from the inbound
        credential TLV; the secret is unscrambled with the symmetric
        ``_ab_scramble`` (its own inverse). The callback is invoked as
        ``fn(user=..., password=...)``. Neither value is ever written to a log or
        echoed (T-04-CRED / T-05-C03). Returns True when no callback is set
        (allow-all) or the callback returns truthy.
        """
        if self._auth_check is None:
            return True
        user, password = self._extract_credentials(tlv)
        try:
            return bool(self._auth_check(user=user, password=password))
        except TypeError:
            # Tolerate a positional single-arg callback: fn(user).
            return bool(self._auth_check(user))

    @staticmethod
    def _extract_credentials(tlv: bytes) -> tuple[str | None, str | None]:
        """Read user (0x0111) + unscrambled password (0x0117) from inbound TLV.

        Returns ``(user, password)``; either may be ``None`` if the field is
        absent (registration-mode inbound calls may pre-authenticate — A3). The
        password 0x0117 value is ``seed(4B LE) + scramble(passwd, seed)``;
        ``_ab_scramble`` is symmetric so the same routine recovers the plaintext.
        The plaintext is returned to the callback ONLY — never logged (T-05-C03).
        """
        tags = _parse_tlv_stream(tlv)
        user_raw = tags.get(_TAG_USER)
        user = _decode_utf16le(user_raw) if user_raw else None

        pwd_raw = tags.get(_TAG_PASSWORD)
        password: str | None = None
        if pwd_raw and len(pwd_raw) >= 4:
            seed = struct.unpack_from("<I", pwd_raw, 0)[0]
            body = bytearray(pwd_raw[4:])
            _ab_scramble(body, seed)
            password = bytes(body).decode("latin-1", "replace")
        return user, password

    # --------------------------------------------------------------------- #
    # Blocking serve loop + sync facade (SERVER-06, D-01/D-02) — Task 2
    # --------------------------------------------------------------------- #
    def _serve_blocking(self) -> None:  # pragma: no cover - live path
        """Blocking serve loop: register with GW, signal ready, dispatch inbound calls.

        SDK-verified protocol (sdk_reg.pcap + sdk_listen.pcap ground truth):
          1. NI init (64B, type=0x020b) → recv NI response (discard)
          2. 512B hostname+TPNAME frame → SMGW: "Registered Server"
          3. 06d1 REG_WAITING (80B) → SMGW: "Waiting for CPI-C Call"
          4. recv 06cf (125B) — GW assigns session handle at [40:48]
          5. recv loop: 0603 = inbound call → dispatch → 0608 response + cleanup
                        06cf = GW re-handle (after re-register) → update handle
        """
        import socket as _socket

        from saprfclib.transport import connect_tcp

        program_id = self._params["program_id"]
        gwhost = self._params.get("gwhost", "localhost")
        gwserv = self._params["gwserv"]

        transport = connect_tcp(gwhost, _gwserv_port(gwserv))
        self._transport = transport
        try:
            local_ip_str = transport.local_address[0]
            local_ip_bytes = _socket.inet_aton(local_ip_str)

            try:
                local_host = _socket.gethostname()
            except Exception:
                local_host = "saprfclib"

            prog_id_enc = program_id.encode("ascii")

            # --- NI init (64B, SDK-verified from sdk_reg.pcap PKT3) ---
            _pid9 = prog_id_enc[:9]
            proc_name_10 = _pid9 + b"\x00" + b"\x20" * (9 - len(_pid9))
            local_host_8 = local_host[:8].encode("ascii", "replace").ljust(8, b"\x20")
            prog_id_16 = prog_id_enc[:8].ljust(16, b"\x20")
            ni_init = (
                b"\x02\x0b"
                + local_ip_bytes
                + b"\x00\x00\x00\x00"
                + proc_name_10
                + b"1100"
                + b"\x00\x00\x00\x00"
                + b"\x00\x06"
                + local_host_8
                + prog_id_16
                + b"\x06\xcb\xff\xff"
                + b"\x00" * 6
            )
            assert len(ni_init) == 64
            transport.send_message(ni_init)
            transport.recv_message()  # NI response (sdk_reg.pcap PKT5) — discard

            # --- 512B hostname+TPNAME frame (sdk_reg.pcap PKT7) ---
            frame_512 = bytearray(b"\x20" * 512)
            _lh = local_host.encode("ascii", "replace")[:127]
            frame_512[: len(_lh)] = _lh
            frame_512[len(_lh)] = 0
            _pid = prog_id_enc[:63]
            frame_512[128 : 128 + len(_pid)] = _pid
            frame_512[128 + len(_pid)] = 0
            transport.send_message(bytes(frame_512))

            # --- 06d1 REG_WAITING (sdk_listen.pcap PKT4) ---
            # RfcListenAndDispatch sends this to signal CMACCP "I'm ready to accept".
            # GW transitions our entry to "Waiting for CPI-C Call" in SMGW.
            transport.send_message(_build_reg_waiting())

            # --- recv 06cf/06ce — GW assigns session handle ---
            # sdk_listen.pcap PKT5: type 0x06CF when a call arrives immediately.
            # Empirically observed: type 0x06CE is also sent by GW (queued-call path).
            # Both carry the GW session handle at bytes [40:48].
            cf_resp = transport.recv_message()
            cf_ft = int.from_bytes(cf_resp[0:2], "big") if len(cf_resp) >= 2 else 0
            gw_handle: bytes = cf_resp[40:48] if len(cf_resp) >= 48 else b"        "
            _logger.debug(
                "[saprfclib-server] LISTENING — program_id=%r gw_frame=0x%04x gw_handle=%r",
                program_id,
                cf_ft,
                gw_handle,
            )

            while not self._stopped:
                try:
                    frame = transport.recv_message()
                except (EOFError, OSError) as _e:
                    _logger.debug("[saprfclib-server] loop exit: %s: %s", type(_e).__name__, _e)
                    break
                if len(frame) < 2:
                    continue
                ft = int.from_bytes(frame[0:2], "big")
                _logger.debug("[saprfclib-server] frame type=0x%04x len=%d", ft, len(frame))
                if ft in (0x06CF, 0x06CE):
                    # GW (re-)assigned session handle — 06CF after 06d0 re-register,
                    # 06CE for queued-call dispatch.
                    gw_handle = frame[40:48] if len(frame) >= 48 else gw_handle
                    _logger.debug("[saprfclib-server] gw handle=%r", gw_handle)
                elif ft == 0x0603:
                    self._dispatch_and_reply_sync(transport, frame, gw_handle)
                else:
                    _logger.debug("[saprfclib-server] unhandled frame 0x%04x, skip", ft)

            _logger.debug("[saprfclib-server] serve loop exited")
        finally:
            self._transport = None
            transport.close()

    def _dispatch_and_reply_sync(  # pragma: no cover
        self, transport: Transport, frame: bytes, gw_handle: bytes
    ) -> None:
        """Dispatch one 0603 inbound call and send the 0608 response + cleanup frames.

        sdk_listen.pcap PKT8 (0608 response): 80B GW header with GW handle at [40:48]
        + RFC TLV from dispatch_inbound. Post-call: PKT9 (060b) + PKT10 (06d2) +
        PKT11 (06d0) to signal GW we processed the call and are ready for the next.
        """
        try:
            response_tlv = self.dispatch_inbound(frame)
            full_response = _wrap_in_0608(response_tlv, gw_handle)
            transport.send_message(full_response)
            _logger.debug(
                "[saprfclib-server] dispatch OK — %dB TLV wrapped in 0608 (%dB)",
                len(response_tlv),
                len(full_response),
            )
            # Post-call cleanup (sdk_listen.pcap PKT9/PKT10/PKT11)
            transport.send_message(_build_post_call_b(gw_handle))  # 060b
            transport.send_message(_build_post_call_d2(gw_handle))  # 06d2
            transport.send_message(_build_re_reg())  # 06d0 re-register
        except Exception as e:  # noqa: BLE001
            _logger.error("[saprfclib-server] dispatch ERROR: %s: %s", type(e).__name__, e)

    def serve_forever(self) -> None:  # pragma: no cover - live path, exercised in Plan 04
        """Blocking facade: run the serve loop in a daemon thread (D-02).

        The caller needs no asyncio knowledge. Call stop()/close() from another
        thread to tear down cleanly (Pitfall 5).
        """
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("server already running")

        self._stopped = False
        _exc: list[BaseException] = []

        def _run() -> None:
            try:
                self._serve_blocking()
            except Exception as e:  # noqa: BLE001
                _logger.error("[saprfclib-server] FATAL: %s: %s", type(e).__name__, e)
                _exc.append(e)

        self._thread = threading.Thread(target=_run, name="saprfclib-server", daemon=True)
        self._thread.start()
        self._thread.join()
        if _exc:
            raise _exc[0]

    def stop(self) -> None:  # pragma: no cover - live path
        """Signal the serve loop to stop: set the stopped flag and close the socket.

        Closing the socket unblocks the blocking recv_message() call in the serve
        loop so it exits cleanly. Safe to call from any thread (Pitfall 5).
        """
        self._stopped = True
        transport = getattr(self, "_transport", None)
        if transport is not None:
            try:
                transport.close()
            except Exception:  # noqa: BLE001
                pass

    def close(self) -> None:  # pragma: no cover - live path
        """Tear the server down: stop the loop and join the background thread."""
        self.stop()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5.0)
        self._thread = None


# --------------------------------------------------------------------------- #
# AsyncRfcServer — asyncio.start_server over the sans-I/O dispatch core (D-08)
# --------------------------------------------------------------------------- #


class AsyncRfcServer(RfcServer):
    """Asyncio-native RFC server: awaits async handlers over asyncio.start_server.

    Subclasses :class:`RfcServer` to inherit the full handler registry surface
    (``@server.function`` decorator, ``set_generic_handler``,
    ``set_authentication_check``, ``set_tid_store``, ``set_unit_store``,
    ``install_transaction_handlers``, ``install_unit_handlers``) and the
    sans-I/O ``dispatch_inbound(frame) -> bytes`` core — which is **not**
    reimplemented here.

    Handlers may be ``async def handler(request: dict) -> dict`` (awaited) or
    plain ``def handler(request: dict) -> dict`` (called directly).  The
    dispatch path checks ``asyncio.iscoroutinefunction`` before calling and
    awaits the result if it returns a coroutine.

    Server I/O lifecycle::

        server = AsyncRfcServer(params)

        @server.function("STFC_CONNECTION", stfc_desc)
        async def handle(request: dict) -> dict:
            return {"ECHOTEXT": request["REQUTEXT"], "RESPTEXT": "ok"}

        await server.serve(host="0.0.0.0", port=3300)  # blocks until stop()

    Security (T-09-05-CANCEL / Pitfall 7):
        ``asyncio.CancelledError`` is **never** caught by a broad ``except
        Exception`` in the dispatch or I/O paths; it propagates so that
        ``asyncio.wait_for`` / ``asyncio.Task.cancel`` work correctly.

    Security (T-09-05-LEAK):
        Handler exceptions are isolated to a SYSTEM_FAILURE response carrying
        only the first line of ``str(exc)`` — reuses ``RfcServer._build_system_failure``
        which itself calls ``_sanitize_message`` (first-line, 512-char cap).
    """

    def __init__(self, params: dict[str, Any]) -> None:
        super().__init__(params)
        # asyncio server handle — set by serve(), cleared by stop_async().
        self._async_server: asyncio.AbstractServer | None = None

    # --------------------------------------------------------------------- #
    # Async dispatch — awaits async handlers, isolates exceptions
    # --------------------------------------------------------------------- #

    async def _async_dispatch(self, frame: bytes) -> bytes:
        """Async dispatch: reuse the sans-I/O core and await async handlers.

        For transactional/bgRFC function names the synchronous
        ``dispatch_inbound`` handles everything (TID/Unit store calls are
        synchronous; async store support is documented as a future enhancement
        when ``AsyncTidStore``/``AsyncUnitStore`` are wired).

        For the synchronous-RFC dispatch path:
        1. Parse function name and look up handler.
        2. Auth check (``_check_auth``).
        3. Deserialize the request (``_deserialize_request``).
        4. If handler is ``async def``, **await** it; if plain ``def``, call it.
        5. Isolate exceptions → ``_build_system_failure`` (T-09-05-LEAK).

        ``asyncio.CancelledError`` is ``BaseException`` — not caught by any
        ``except Exception`` block here (Pitfall 7 / T-09-05-CANCEL).
        """
        tlv = _strip_gw_header(frame)
        fname = self._read_func_name(tlv)

        # Transactional and bgRFC branches are fully synchronous: delegate
        # entirely to the inherited dispatch_inbound (sans-I/O core).
        if fname in (
            _ARFC_DEST_SHIP,
            _ARFC_DEST_CONFIRM,
            _BGRFC_DEST_SHIP,
            _BGRFC_DEST_CONFIRM,
            _BGRFC_CHECK_UNIT_STATE_SERVER,
        ):
            return self.dispatch_inbound(frame)

        # ----- Synchronous RFC path with async handler support ---- #
        entry = self._registry.get(fname.upper())
        if entry is None and self._generic is not None:
            entry = self._generic(fname)
        if entry is None:
            return self._build_system_failure(f"function {fname} not registered")
        func_desc, handler = entry

        # Auth check before handler dispatch (SERVER-05 / T-05-C06).
        if self._auth_check is not None and not self._check_auth(tlv):
            return self._build_system_failure("authentication failed")

        # Deserialize request (Pitfall 4 direction inversion — same as sync).
        request = self._deserialize_request(tlv, func_desc)

        # Dispatch: await async handlers; call sync handlers directly.
        # CancelledError (BaseException) propagates — not caught (Pitfall 7).
        try:
            if asyncio.iscoroutinefunction(handler):
                result = await handler(request)
            else:
                result = handler(request)
        except Exception as exc:  # noqa: BLE001 — isolate ALL handler errors
            # str(exc) first-line only — no traceback, no credentials (T-09-05-LEAK).
            return self._build_system_failure(str(exc))

        if result is None:
            result = {}
        return self._build_response(func_desc, result)

    # --------------------------------------------------------------------- #
    # asyncio.start_server serve loop
    # --------------------------------------------------------------------- #

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle one inbound TCP connection from a SAP gateway or peer.

        Wraps the (reader, writer) pair in an ``AsyncTransport`` and enters a
        receive loop.  Each inbound 0x0603 call frame is dispatched as a
        separate ``asyncio.Task`` (one Task per inbound call — unbounded by
        default, per plan discretion; add a ``Semaphore(max_concurrent)`` here
        if a bounded deployment is needed later).

        ``asyncio.CancelledError`` exits the loop cleanly (T-09-05-CANCEL).
        """
        transport = AsyncTransport(reader, writer)
        peer = writer.get_extra_info("peername", default=("?", 0))
        _logger.debug("[saprfclib-async-server] client connected from %s:%s", *peer)

        tasks: list[asyncio.Task[None]] = []
        try:
            while True:
                try:
                    frame = await transport.recv_message()
                except asyncio.CancelledError:
                    raise  # Pitfall 7 — propagate cancellation
                except (EOFError, OSError) as _e:
                    _logger.debug(
                        "[saprfclib-async-server] client disconnected (%s: %s)",
                        type(_e).__name__,
                        _e,
                    )
                    break

                if len(frame) < 2:
                    continue
                ft = int.from_bytes(frame[0:2], "big")
                _logger.debug("[saprfclib-async-server] frame type=0x%04x len=%d", ft, len(frame))

                if ft == 0x0603:
                    # Inbound RFC call: dispatch as its own Task so the recv
                    # loop is not blocked while the handler runs (D-08 design).
                    task = asyncio.create_task(
                        self._dispatch_and_reply_async(transport, frame),
                        name=f"saprfclib-dispatch-{ft:#06x}",
                    )
                    tasks.append(task)
                else:
                    _logger.debug("[saprfclib-async-server] unhandled frame 0x%04x, skip", ft)
        except asyncio.CancelledError:
            raise
        finally:
            # Cancel any outstanding dispatch tasks on disconnect.
            for t in tasks:
                if not t.done():
                    t.cancel()
            # Close the async transport (best-effort; swallow OSError).
            try:
                await transport.close()
            except Exception:  # noqa: BLE001
                pass

    async def _dispatch_and_reply_async(
        self,
        transport: AsyncTransport,
        frame: bytes,
    ) -> None:
        """Dispatch one inbound call frame and send the response asynchronously.

        Isolates both the dispatch and the send so that a handler failure or
        a send error does not crash the whole accept loop (T-09-05-LEAK).
        ``asyncio.CancelledError`` propagates (Pitfall 7 / T-09-05-CANCEL).
        """
        try:
            resp = await self._async_dispatch(frame)
            await transport.send_message(resp)
        except asyncio.CancelledError:
            raise  # Pitfall 7 — never swallow
        except Exception as exc:  # noqa: BLE001 — log, never crash the loop
            _logger.error(
                "[saprfclib-async-server] dispatch ERROR: %s: %s", type(exc).__name__, exc
            )

    async def serve(
        self,
        host: str = "0.0.0.0",
        port: int = 0,
    ) -> None:
        """Start the async server and block until ``stop_async()`` is called.

        Uses ``asyncio.start_server`` to accept TCP connections on ``(host,
        port)`` and spawns ``_handle_client`` for each.  The server runs until
        ``stop_async()`` closes the underlying server handle.

        Example::

            server = AsyncRfcServer(params)

            @server.function("MY_FM", desc)
            async def handler(request):
                return {"OUT_PARAM": request["IN_PARAM"]}

            # In an async context:
            await server.serve(host="0.0.0.0", port=3300)
        """
        self._async_server = await asyncio.start_server(self._handle_client, host, port)
        async with self._async_server:
            await self._async_server.serve_forever()

    async def stop_async(self) -> None:
        """Signal the async serve loop to stop (close the server socket)."""
        srv = self._async_server
        if srv is not None:
            srv.close()
            try:
                await srv.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self._async_server = None
