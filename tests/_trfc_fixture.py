# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Shared tRFC test data: the golden capture and the metadata a submit needs.

The ARFC_DEST_SHIP row layouts are built from the server's DDIF_FIELDINFO_GET replies
stored in tests/golden/trfc/trfc_reference.json, the same path the library takes.
"""

from __future__ import annotations

import json
import pathlib

from saprfclib.connection import (
    _build_type_desc_from_ddif,
    _join_response_frames,
    _parse_ddif_dfies_rows,
)
from saprfclib.invoke import tlv_record
from saprfclib.types import RFC_IMPORT, RFC_TABLES, FieldDesc, FunctionDesc, TypeDesc

FX = json.loads(
    (pathlib.Path(__file__).parent / "golden" / "trfc" / "trfc_reference.json").read_text(
        encoding="utf-8"
    )
)


def type_desc(name: str) -> TypeDesc:
    frames = iter(bytes.fromhex(h) for h in FX["ddif"][name]["reply"])
    reply = _join_response_frames(lambda: next(frames), "DDIF_FIELDINFO_GET")
    return _build_type_desc_from_ddif(name, _parse_ddif_dfies_rows(reply))


def _table(name: str, row_type: str) -> FieldDesc:
    return FieldDesc(
        name=name,
        rfctype=5,
        nuc_length=0,
        nuc_offset=0,
        uc_length=0,
        uc_offset=0,
        decimals=0,
        type_desc=type_desc(row_type),
        direction=RFC_TABLES,
    )


SHIP = FunctionDesc(
    name="ARFC_DEST_SHIP",
    parameters=[_table("DATA", "ARFCRDATA"), _table("STATE", "ARFCRSTATE")],
)
STFC_CONNECTION = FunctionDesc(
    name="STFC_CONNECTION",
    parameters=[
        FieldDesc(
            name="REQUTEXT",
            rfctype=0,
            nuc_length=255,
            nuc_offset=0,
            uc_length=510,
            uc_offset=0,
            decimals=0,
            direction=RFC_IMPORT,
        )
    ],
)
DESCS = {"ARFC_DEST_SHIP": SHIP, "STFC_CONNECTION": STFC_CONNECTION}


def use_fixture_metadata(monkeypatch, conn=None) -> None:
    """Serve SHIP / STFC_CONNECTION instead of fetching metadata from a server."""
    from saprfclib import connection as connmod

    monkeypatch.setattr(connmod, "get_function_desc", lambda c, n, cache=None: DESCS[n.upper()])
    if conn is not None:

        async def _desc_for(name: str) -> FunctionDesc:
            return DESCS[name.upper()]

        monkeypatch.setattr(conn, "_desc_for", _desc_for)


def forged_inbound_trfc(tid: str, func_name: str) -> bytes:
    """An inbound ARFC_DEST_SHIP frame in the shape the RFC server's handler reads.

    The server reads the TID from a parameter named ARFCTID ([ASSUMED] in
    server.py: no capture of a SAP system sending tRFC to a registered server
    exists). This is not what a client sends -- see build_trfc_request -- and is
    used only to drive the server's inbound path.
    """
    u = lambda s: s.encode("utf-16-le")  # noqa: E731
    return b"".join(
        [
            tlv_record(0x0502),
            tlv_record(0x000B, u("754")),
            tlv_record(0x0102, u("ARFC_DEST_SHIP")),
            tlv_record(0x0512),
            tlv_record(0x0201, u("ARFCTID")),
            tlv_record(0x0203, u(tid)),
            tlv_record(0x0201, u("ARFCFNAM")),
            tlv_record(0x0203, u(func_name)),
            tlv_record(0xFFFF),
        ]
    )
