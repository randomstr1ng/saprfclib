# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — DDIC metadata fetch & cache
#
# Turns a live connection into typed function metadata (META-01..05): the input
# Phase 4's call() marshals against.
#
#   MetadataCache               -- in-process {sys_id: {name: FunctionDesc}} cache (META-03)
#   BOOTSTRAP_GET_FUNCTION_INTERFACE
#                               -- hard-coded FunctionDesc for the DDIC lookup FM
#                                  itself, breaking the chicken-and-egg (META-05)
#   _parse_params_row           -- one RFC_GET_FUNCTION_INTERFACE PARAMS row -> FieldDesc (META-01)
#   _build_type_desc            -- recursive STRUCTURE/TABLE -> nested TypeDesc (META-02)
#   get_function_desc           -- cache-hit short-circuit; uncached live fetch deferred to Phase 4
#
# META-01 CONFIRMED (live capture 2026-06-27): RFC_GET_FUNCTION_INTERFACE PARAMS table
# columns: PARAMCLASS, PARAMETER, TABNAME, FIELDNAME, EXID, POSITION, OFFSET,
# INTLENGTH, DECIMALS, DEFAULT, PARAMTEXT, OPTIONAL.
# EXID is a single-char string code ('C'=CHAR, 'I'=INT4, etc.), not an integer.
# OFFSET is the unicode byte offset; INTLENGTH is the unicode byte length.
# No separate NUC/UC columns — nuc values are derived (char types: // 2, binary: same).
# The uncached live-fetch path is deferred to Phase 4 (invoke path not yet available).
from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from saprfclib.types import (
    RFC_CHANGING,
    RFC_EXPORT,
    RFC_IMPORT,
    RFC_TABLES,
    FieldDesc,
    FunctionDesc,
    TypeDesc,
)

__all__ = ["MetadataCache", "BOOTSTRAP_GET_FUNCTION_INTERFACE", "get_function_desc", "FunctionDesc"]


# --------------------------------------------------------------------------- #
# RFCTYPE constants (mirror src/saprfclib/codec.py lines 40-68 — keep values in
# sync; only the few used by the metadata layer are mirrored here).
# --------------------------------------------------------------------------- #
RFCTYPE_CHAR = 0
RFCTYPE_DATE = 1
RFCTYPE_BCD = 2
RFCTYPE_TIME = 3
RFCTYPE_BYTE = 4
RFCTYPE_TABLE = 5
RFCTYPE_NUM = 6
RFCTYPE_FLOAT = 7
RFCTYPE_INT = 8
RFCTYPE_INT2 = 9
RFCTYPE_INT1 = 10
RFCTYPE_STRUCTURE = 17
RFCTYPE_DECF16 = 23
RFCTYPE_DECF34 = 24
RFCTYPE_STRING = 29
RFCTYPE_XSTRING = 30
RFCTYPE_INT8 = 31

# Tampering guard (threat T-03-META): cap result-table size and recursion depth
# so a malicious peer cannot exhaust memory / blow the stack via crafted metadata.
_MAX_RECURSION_DEPTH = 32
_MAX_ROWS = 10_000


# --------------------------------------------------------------------------- #
# In-process cache (META-03)
# --------------------------------------------------------------------------- #
class MetadataCache:
    """In-process FunctionDesc cache, keyed by (sys_id, func_name) (META-03).

    Func names are normalised to upper-case so lookups are case-insensitive
    (ABAP function-module names are upper-case canonical).

    Safe to share between threads, and meant to be: one cache per pool rather
    than one per connection. A descriptor is a property of the *system*, not of
    the socket it arrived on, so a pool of N connections calling M function
    modules otherwise pays N*M RFC_GET_FUNCTION_INTERFACE round-trips to learn
    the same M answers. Sharing makes that M.

    The lock is held only around the dict operations, never across the fetch —
    two threads racing for the same uncached descriptor will both fetch it and
    the second simply overwrites with an equal value. Holding the lock across a
    network round-trip would serialise every first call in the pool behind one
    connection, which is a worse trade than a rare duplicate fetch.
    """

    def __init__(self) -> None:
        # {sys_id: {func_name_upper: FunctionDesc}}
        self._cache: dict[str, dict[str, FunctionDesc]] = {}
        self._lock = threading.Lock()

    def get(self, sys_id: str, name: str) -> FunctionDesc | None:
        """Return the cached descriptor or None on miss (never raises KeyError)."""
        with self._lock:
            return self._cache.get(sys_id, {}).get(name.upper())

    def put(self, sys_id: str, desc: FunctionDesc) -> None:
        """Cache a descriptor under (sys_id, desc.name.upper())."""
        with self._lock:
            self._cache.setdefault(sys_id, {})[desc.name.upper()] = desc

    def get_or_fetch(
        self, sys_id: str, name: str, fetch: Callable[[str], FunctionDesc]
    ) -> FunctionDesc:
        """Return the cached descriptor, or call fetch(name) once and cache it.

        fetch is invoked at most once per (sys_id, name) in the common case: a
        subsequent call for the same key is served from the cache with no second
        round-trip (META-03). See the class docstring on why the lock is not held
        across ``fetch``.
        """
        hit = self.get(sys_id, name)
        if hit is not None:
            return hit
        desc = fetch(name)
        self.put(sys_id, desc)
        return desc


# --------------------------------------------------------------------------- #
# Bootstrap descriptor (META-05 chicken-and-egg)
# --------------------------------------------------------------------------- #
# The metadata of the metadata FM cannot be fetched from the metadata FM, so the
# signature of the DDIC lookup FM itself is hard-coded. RFC_GET_FUNCTION_INTERFACE
# is the MVP bootstrap FM (RESEARCH OQ-5): small, stable signature, simpler PARAMS
# rows than RFC_METADATA_GET.
#
# [ASSUMED — parameter/table shapes pending live metadata capture; RESEARCH A3 /
# META-01.] Only the FUNCNAME import parameter is needed for MVP; the PARAMS
# result table shape is confirmed by the live capture gated in Task 3. FUNCNAME is
# a CHAR(30) field: nuc_length 30 bytes / uc_length 60 bytes (UTF-16, 2 bytes per
# char — RESEARCH Pitfall 2: code-unit lengths, never len(str)).
BOOTSTRAP_GET_FUNCTION_INTERFACE: FunctionDesc = FunctionDesc(
    name="RFC_GET_FUNCTION_INTERFACE",
    parameters=[
        FieldDesc(
            name="FUNCNAME",
            rfctype=RFCTYPE_CHAR,
            nuc_length=30,
            nuc_offset=0,
            uc_length=60,
            uc_offset=0,
            decimals=0,
            unicode_mode=True,
        ),
    ],
)


# --------------------------------------------------------------------------- #
# Result-table parse (META-01) + recursive TypeDesc (META-02)
# --------------------------------------------------------------------------- #
# META-01 CONFIRMED (live capture 2026-06-27): 12-column PARAMS table.
# EXID is a single-char string code — map to RFCTYPE int via _EXID_TO_RFCTYPE.
# OFFSET = unicode byte offset; INTLENGTH = unicode byte length.
# nuc values derived: char-like types halve (UTF-16 = 2x); binary types same.
_COL_PARAMETER = "PARAMETER"  # parameter name
_COL_PARAMCLASS = "PARAMCLASS"  # direction class: 'I'=IMPORT, 'E'=EXPORT, 'C'=CHANGING, 'T'=TABLES
_COL_EXID = "EXID"  # type code string: 'C'=CHAR, 'I'=INT4, etc.
_COL_INTLENGTH = "INTLENGTH"  # unicode byte length (confirmed from live capture)
_COL_OFFSET = "OFFSET"  # unicode byte offset (confirmed from live capture)
_COL_DECIMALS = "DECIMALS"  # BCD decimal places
_COL_TABNAME = "TABNAME"  # structure/table type name

# PARAMCLASS single-char code → RFC_DIRECTION integer (caller perspective, confirmed
# from captures/phase03_metadata_STFC_CONNECTION.json: REQUTEXT='I', ECHOTEXT='E').
_PARAMCLASS_TO_DIRECTION: dict[str, int] = {
    "I": RFC_IMPORT,
    "E": RFC_EXPORT,
    "C": RFC_CHANGING,
    "T": RFC_TABLES,
}

# PARAMCLASS 'X' rows describe the function's EXCEPTIONS, not its parameters: they
# carry the exception name in PARAMETER and leave EXID blank. They belong in no
# FunctionDesc.parameters list and must be recognised deliberately — they used to be
# discarded only as a side effect of the blank EXID raising, which meant a genuinely
# unparseable *parameter* was thrown away just as quietly.
# Confirmed live (kernel 793): RFC_READ_TABLE returns 6 such rows —
# DATA_BUFFER_EXCEEDED, FIELD_NOT_VALID, NOT_AUTHORIZED, OPTION_NOT_VALID,
# TABLE_NOT_AVAILABLE, TABLE_WITHOUT_DATA.
_PARAMCLASS_EXCEPTION = "X"


def is_exception_row(row: dict[str, Any]) -> bool:
    """True if this PARAMS row describes an exception rather than a parameter."""
    return str(row.get(_COL_PARAMCLASS, "")).strip().upper() == _PARAMCLASS_EXCEPTION


# EXID single-char code → RFCTYPE integer (SDK type definitions / confirmed by live capture).
_EXID_TO_RFCTYPE: dict[str, int] = {
    "C": RFCTYPE_CHAR,
    "D": RFCTYPE_DATE,
    "P": RFCTYPE_BCD,
    "T": RFCTYPE_TIME,
    "X": RFCTYPE_BYTE,
    "h": RFCTYPE_TABLE,
    "N": RFCTYPE_NUM,
    "F": RFCTYPE_FLOAT,
    "I": RFCTYPE_INT,
    "s": RFCTYPE_INT2,
    "b": RFCTYPE_INT1,
    "u": RFCTYPE_STRUCTURE,
    # DECFLOAT16 arrives as 'a'. Confirmed by live capture on 2026-08-31: a custom
    # remote-enabled function module on A4H (kernel 793) with seven DECFLOAT16
    # parameters returned EXID 'a' for every one of them, while its DECFLOAT34
    # parameters returned 'e' as this table already had. Before this entry existed
    # every DECFLOAT16 parameter failed _parse_params_row and was dropped from the
    # descriptor, so the function interface silently lost them -- the call then went
    # out missing those parameters rather than failing.
    "a": RFCTYPE_DECF16,
    # [ASSUMED] 'v' for DECFLOAT16 predates that capture and has never been observed.
    # Kept because removing an untested entry is no better evidenced than keeping it,
    # and a stray 'v' would otherwise drop the row. If a capture shows 'v' is
    # something else, replace it rather than relabelling.
    "v": RFCTYPE_DECF16,
    "e": RFCTYPE_DECF34,  # confirmed by the same 2026-08-31 capture
    "g": RFCTYPE_STRING,
    "y": RFCTYPE_XSTRING,
    "8": RFCTYPE_INT8,
}

# RFCTYPE values for char-like types where unicode doubles the byte width.
_CHAR_LIKE_TYPES = frozenset(
    {RFCTYPE_CHAR, RFCTYPE_DATE, RFCTYPE_TIME, RFCTYPE_NUM, RFCTYPE_STRING}
)


def _coerce_int(row: dict[str, Any], column: str) -> int:
    """int() a result-table column, raising ValueError on a malformed value.

    Untrusted metadata rows from the SAP peer (trust boundary; threat T-03-META):
    validate before conversion rather than letting a bare int() crash or coerce
    silently.
    """
    try:
        return int(row[column])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            f"malformed PARAMS row: column {column!r} is not an integer ({row.get(column)!r})"
        ) from exc


def _parse_params_row(row: dict[str, Any]) -> FieldDesc:
    """Map one RFC_GET_FUNCTION_INTERFACE PARAMS row to a FieldDesc (META-01).

    Column layout confirmed from live capture 2026-06-27. EXID is a string type
    code; OFFSET/INTLENGTH are unicode byte values. nuc values are derived:
    char-like types (CHAR/DATE/TIME/NUM/STRING) halve the unicode width; binary
    types keep the same size. type_desc is left None; _build_type_desc attaches
    nested layout for STRUCTURE/TABLE fields.

    TABLES-direction promotion: GFI declares a TABLES parameter with the EXID of
    its *row structure* (``EXID='u'`` → STRUCTURE) and ``PARAMCLASS='T'``.  EXID
    alone therefore mistypes every TABLES param as a bare structure, which routes
    it through the scalar 0x0201/0x0203 TLV pair instead of the table protocol and
    makes the server reject the call with CALL_FUNCTION_ILLEGAL_P_TYPE.  The
    direction is what decides: PARAMCLASS 'T' means the wire carries a table.

    Source: golden fixture tests/golden/framing/rfc_read_table_response.bin —
    RFC_READ_TABLE's DATA / FIELDS / OPTIONS params (all PARAMCLASS 'T') are
    transported as 0x0301(name) 0x0330(dm_id) 0x0302(row_size,row_count)
    0x0304(rows)…, i.e. the TABLE tag sequence, never as a 0x0203 scalar value.

    PARAMCLASS alone decides. The GFI PARAMS table is flat — it lists the function's
    parameters and its exceptions, never the fields inside a parameter's row
    structure (that layout is fetched separately via RFC_GET_STRUCTURE_DEFINITION).
    Confirmed live on kernel 793: RFC_READ_TABLE returned exactly 11 parameter rows
    for its 11 parameters, plus 6 PARAMCLASS='X' exception rows, and no field rows.

    In particular, do NOT gate this on FIELDNAME being blank. FIELDNAME names the
    DDIC field a parameter's type is derived from, not a nesting level: the live
    rows show DELIMITER with FIELDNAME='FLAG' and QUERY_TABLE with
    FIELDNAME='TABNAME', both plain top-level parameters.
    """
    name = row.get(_COL_PARAMETER)
    if not isinstance(name, str) or not name:
        raise ValueError(f"malformed PARAMS row: missing/blank {_COL_PARAMETER!r}")
    exid = row.get(_COL_EXID, "")
    rfctype = _EXID_TO_RFCTYPE.get(str(exid))
    if rfctype is None:
        raise ValueError(f"malformed PARAMS row: unknown EXID code {exid!r}")
    paramclass = row.get(_COL_PARAMCLASS, "")
    direction = _PARAMCLASS_TO_DIRECTION.get(str(paramclass))
    if direction is None:
        raise ValueError(f"malformed PARAMS row: unknown PARAMCLASS code {paramclass!r}")
    # A TABLES-direction param is a table on the wire regardless of the EXID naming
    # its row structure (see docstring — golden rfc_read_table_response.bin).
    if direction == RFC_TABLES:
        rfctype = RFCTYPE_TABLE
    intlength = _coerce_int(row, _COL_INTLENGTH)
    offset = _coerce_int(row, _COL_OFFSET)
    decimals = _coerce_int(row, _COL_DECIMALS)
    if rfctype in _CHAR_LIKE_TYPES:
        nuc_length = intlength // 2
        nuc_offset = offset // 2
    else:
        nuc_length = intlength
        nuc_offset = offset
    return FieldDesc(
        name=name,
        rfctype=rfctype,
        nuc_length=nuc_length,
        nuc_offset=nuc_offset,
        uc_length=intlength,
        uc_offset=offset,
        decimals=decimals,
        direction=direction,
    )


def _build_type_desc(name: str, nodes: list[dict[str, Any]], *, _depth: int = 0) -> TypeDesc:
    """Build a TypeDesc from nested PARAMS nodes, recursing on STRUCTURE/TABLE (META-02).

    Each node is a dict ``{"row": <PARAMS row>, "fields": [<child node>, ...]}``.
    A node whose row rfctype is RFCTYPE_STRUCTURE or RFCTYPE_TABLE recurses into a
    nested TypeDesc set on the FieldDesc.type_desc; scalar nodes leave it None.
    Recursion depth and row count are bounded (threat T-03-META) so crafted
    metadata cannot exhaust the stack or memory.
    """
    if _depth > _MAX_RECURSION_DEPTH:
        raise ValueError(f"metadata nesting depth exceeds cap {_MAX_RECURSION_DEPTH} (DoS guard)")
    if len(nodes) > _MAX_ROWS:
        raise ValueError(f"metadata row count {len(nodes)} exceeds cap {_MAX_ROWS} (DoS guard)")

    fields: list[FieldDesc] = []
    for node in nodes:
        field_desc = _parse_params_row(node["row"])
        if field_desc.rfctype in (RFCTYPE_STRUCTURE, RFCTYPE_TABLE):
            children = node.get("fields", [])
            field_desc.type_desc = _build_type_desc(field_desc.name, children, _depth=_depth + 1)
        fields.append(field_desc)

    nuc_size = sum(f.nuc_length for f in fields)
    uc_size = sum(f.uc_length for f in fields)
    return TypeDesc(name=name, fields=fields, nuc_size=nuc_size, uc_size=uc_size)


# --------------------------------------------------------------------------- #
# Live fetch (META-01) — Phase 4 bootstrap-invoke path
# --------------------------------------------------------------------------- #
# Column layout confirmed 2026-06-27. The live path invokes RFC_GET_FUNCTION_INTERFACE
# via the bootstrap descriptor to retrieve function metadata. The connection must
# implement _call_bootstrap(name) -> FunctionDesc (Connection task 3).
#
# Cache strategy (META-03): a cache miss triggers the bootstrap invoke; the result
# is stored and subsequent calls for the same (sys_id, name) never round-trip.


def get_function_desc(
    connection: object,
    name: str,
    *,
    cache: MetadataCache | None = None,
) -> FunctionDesc:
    """Return the FunctionDesc for ``name`` on ``connection``'s system (META-01).

    Cache hit path: if cache is supplied and (sys_id, name) is present, return
    immediately (no round-trip, META-03).

    Live path: invoke RFC_GET_FUNCTION_INTERFACE via the connection's bootstrap
    call interface (connection._call_bootstrap(name)), cache the result, and
    return. The PARAMS rows are parsed by _parse_params_row (direction-preserving
    from Task 1). DoS guards (_MAX_ROWS, _MAX_RECURSION_DEPTH) are retained.

    Connection requirements (D-21/META-01):
      - connection._metadata_cache_key: str | None — the cache key, falling back
        to connection.sys_id for connection-likes that do not define it
      - connection._call_bootstrap(name: str) -> FunctionDesc — bootstrap invoke
    """
    cache_key = getattr(connection, "_metadata_cache_key", None)
    if cache_key is None:
        cache_key = getattr(connection, "sys_id", None)
    # An empty system ID is not a key. Some releases send no system ID in the logon
    # response (observed on 7.52), and filing every one of them under "" would serve
    # one system's descriptors to another. Connection substitutes a per-connection
    # token for that case; anything else duck-typed here simply goes uncached.
    if not cache_key:
        cache_key = None

    # Cache hit (META-03): return immediately with no round-trip.
    if cache is not None and cache_key is not None:
        hit = cache.get(cache_key, name)
        if hit is not None:
            return hit

    # Live path: delegate to the connection's bootstrap invoke method.
    # _call_bootstrap is implemented by Connection (task 3) to build and send
    # the RFC_GET_FUNCTION_INTERFACE invoke without going through call() (which
    # would be circular) — it sends the TLV directly via the transport seam.
    bootstrap_fn = getattr(connection, "_call_bootstrap", None)
    if bootstrap_fn is None:
        raise AttributeError(
            "connection does not implement _call_bootstrap — "
            "use a Connection instance (Phase 4) or pre-populate the MetadataCache"
        )
    desc: FunctionDesc = bootstrap_fn(name)

    # Cache the result (META-03): subsequent calls for (cache_key, name) are served
    # from the cache with no second round-trip.
    if cache is not None and cache_key is not None:
        cache.put(cache_key, desc)

    return desc
