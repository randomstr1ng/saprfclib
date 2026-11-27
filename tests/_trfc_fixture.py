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


def forged_inbound_trfc(tid: str, func_name: str, *more: str) -> bytes:
    """An ARFC_DEST_SHIP LUW of calls with no values, in STATE / DATA rows.

    The rows ABAP sends to a registered server have the layout a client submits
    (tests/golden/trfc/trfc_inbound.json), so the client's own builder makes them.
    """
    from saprfclib.invoke import TrfcOrigin, build_trfc_call, build_trfc_request

    origin = TrfcOrigin(session_token=bytes(16), **FX["origin"])
    calls = [
        (name, build_trfc_call(name, FunctionDesc(name, []), {}, origin))
        for name in (func_name, *more)
    ]
    return build_trfc_request(tid, calls, SHIP, origin)


def _inbound() -> dict:
    return json.loads(
        (pathlib.Path(__file__).parent / "golden" / "trfc" / "trfc_inbound.json").read_text(
            encoding="utf-8"
        )
    )


def confirm_desc() -> FunctionDesc:
    """ARFC_DEST_CONFIRM's CALLID, laid out from the captured DDIF_FIELDINFO_GET reply."""
    frames = iter(bytes.fromhex(h) for h in _inbound()["ddif_arfccallid"])
    reply = _join_response_frames(lambda: next(frames), "DDIF_FIELDINFO_GET")
    callid = _build_type_desc_from_ddif("ARFCCALLID", _parse_ddif_dfies_rows(reply))
    return FunctionDesc(
        name="ARFC_DEST_CONFIRM",
        parameters=[
            # CALLID is a structure (RFCTYPE 17) of 64 characters in the system's
            # interface for ARFC_DEST_CONFIRM, read live 2026-11-27.
            FieldDesc("CALLID", 17, 64, 0, 128, 0, 0, type_desc=callid, direction=RFC_IMPORT)
        ],
    )


def trfc_descriptors() -> tuple[FunctionDesc, FunctionDesc]:
    """What RfcServer.set_trfc_descriptors() takes: ARFC_DEST_SHIP, ARFC_DEST_CONFIRM."""
    return SHIP, confirm_desc()
