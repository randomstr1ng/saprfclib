# SPDX-License-Identifier: MPL-2.0
"""A TABLE's row width comes from the server, not from the descriptor.

The same DDIC row type reaches the client at two different widths. The
uncompressed 0x0303 path packs rows to the sum of their field widths; the
compressed 0x0305 path pads each row to a 4-byte boundary. ``RFC_FUNINT`` is 402
packed and 404 padded, because it carries INT4 members.

``_decode_table`` used to take the width from ``TypeDesc.uc_size``, which is that
sum — right for one path and wrong for the other. Splitting a padded 17776-byte
buffer by 402 does not raise: it yields 44 row-shaped slices that drift one
character further left each time, so the names decay through ``'EADMINDATA'`` and
``'\\x00EALIAS'`` to ``'TADDS'``, ``'TADD'``, ``'TAD'``, ``'TA'`` as the walk runs
off the end. PARAMCLASS and EXID read empty; DEFAULT fills with binary.

The server states the real width in the 0x0302 record, which the parser
discarded as "already available from row data length" — true only when the
buffer happens to divide exactly.

Source: tests/golden/framing/gfi_compressed_params_response.bin —
BAPI_USER_GET_DETAIL's interface, whose 0x0302 reads row_size=404 row_count=44.
"""

from __future__ import annotations

import pathlib
import struct

import pytest

from saprfclib.codec import _decode_table
from saprfclib.connection import _strip_gw_header
from saprfclib.types import RFC_TABLES, FieldDesc, FunctionDesc, TypeDesc

GOLDEN = pathlib.Path(__file__).parent / "golden" / "framing"
COMPRESSED = GOLDEN / "gfi_compressed_params_response.bin"

# The 12 columns of RFC_FUNINT, in wire order. Sum = 402; the compressed path
# sends 404.
_COLUMNS: list[tuple[str, int, int]] = [
    ("PARAMCLASS", 0, 2),
    ("PARAMETER", 2, 60),
    ("TABNAME", 62, 60),
    ("FIELDNAME", 122, 60),
    ("EXID", 182, 2),
    ("POSITION", 184, 4),
    ("OFFSET", 188, 4),
    ("INTLENGTH", 192, 4),
    ("DECIMALS", 196, 4),
    ("DEFAULT", 200, 42),
    ("PARAMTEXT", 242, 158),
    ("OPTIONAL", 400, 2),
]
_INT_COLUMNS = {"POSITION", "OFFSET", "INTLENGTH", "DECIMALS"}

RFCTYPE_CHAR = 0
RFCTYPE_INT = 8
RFCTYPE_TABLE = 5


def _funint_type_desc() -> TypeDesc:
    fields = [
        FieldDesc(
            name=name,
            rfctype=RFCTYPE_INT if name in _INT_COLUMNS else RFCTYPE_CHAR,
            nuc_length=width // 2,
            nuc_offset=offset // 2,
            uc_length=width,
            uc_offset=offset,
            decimals=0,
        )
        for name, offset, width in _COLUMNS
    ]
    return TypeDesc(name="RFC_FUNINT", fields=fields, nuc_size=201, uc_size=402)


def _params_field() -> FieldDesc:
    return FieldDesc(
        name="PARAMS",
        rfctype=RFCTYPE_TABLE,
        nuc_length=0,
        nuc_offset=0,
        uc_length=0,
        uc_offset=0,
        decimals=0,
        direction=RFC_TABLES,
        type_desc=_funint_type_desc(),
    )


def _capture_records() -> tuple[int, int, bytes]:
    """Return (row_size, row_count, decompressed rows) from the golden capture."""
    from saprfclib.invoke import decompress_table_stream

    raw = _strip_gw_header(COMPRESSED.read_bytes())
    pos, n = 0, len(raw)
    row_size = row_count = 0
    chunks: list[bytes] = []
    while pos + 4 <= n:
        tag, length = struct.unpack_from(">HH", raw, pos)
        pos += 4
        if tag == 0xFFFF:
            break
        if length == 0xFFFF:
            length = struct.unpack_from(">I", raw, pos)[0]
            pos += 4
        value = raw[pos : pos + length]
        pos += length
        if pos + 2 <= n and struct.unpack_from(">H", raw, pos)[0] == tag:
            pos += 2
        if tag == 0x0302:
            row_size, row_count = struct.unpack_from(">II", value, 0)
        elif tag == 0x0305:
            chunks.append(value)
    return row_size, row_count, decompress_table_stream(chunks, "PARAMS")


def test_the_server_declares_a_width_the_descriptor_cannot_derive() -> None:
    """0x0302 says 404; the sum of the field widths says 402. Both are real."""
    row_size, row_count, rows = _capture_records()
    assert (row_size, row_count) == (404, 44)
    assert len(rows) == 17776 == row_size * row_count
    assert _funint_type_desc().uc_size == 402
    # The buffer does not divide by the descriptor's width, which is exactly why
    # "already available from row data length" was not enough.
    assert len(rows) % 402 == 88


def test_rows_decode_cleanly_at_the_declared_width() -> None:
    """44 rows, every one intact — the fix.

    Before, this produced 44 slices whose PARAMCLASS was empty from row 1 on.
    """
    row_size, _count, rows = _capture_records()
    decoded = _decode_table(rows, _params_field(), row_size)

    assert len(decoded) == 44
    assert all(r["PARAMCLASS"].strip() for r in decoded), "a row lost its PARAMCLASS"
    assert all(r["PARAMETER"].strip() for r in decoded), "a row lost its name"
    assert all(r["PARAMCLASS"].strip() in {"I", "E", "C", "T", "X"} for r in decoded)

    names = [r["PARAMETER"].strip() for r in decoded]
    assert names[0] == "ADDRESS"
    assert "ADMINDATA" in names
    # The corruption signature: names eaten from the left as the walk drifts.
    assert not any(n.startswith("\x00") for n in names)
    assert not any(n in {"TADDS", "TADD", "TAD", "TA"} for n in names)


def test_the_descriptor_width_is_what_corrupted_them() -> None:
    """Pin the old behaviour, so the fix cannot be quietly reverted.

    Decoding the same buffer at the descriptor's 402 does not raise — it returns
    the right number of rows, wrong. That silence is the reason this reached a
    downstream integration rather than a test.
    """
    _row_size, _count, rows = _capture_records()
    wrong = _decode_table(rows, _params_field())  # no override: falls back to 402

    assert len(wrong) == 44, "the row count is right even when the rows are not"
    assert not all(r["PARAMCLASS"].strip() for r in wrong), (
        "decoding at the descriptor width should corrupt these rows; if it no "
        "longer does, this test is asserting nothing"
    )
    assert wrong[0]["PARAMETER"].strip() == "ADDRESS", "row 0 is aligned either way"
    assert wrong[1]["PARAMETER"].strip() != "ADMINDATA", "row 1 is where the drift starts"


def test_a_narrower_declared_width_is_refused() -> None:
    """A width from the peer becomes a slice length — same trust boundary as T-02-06.

    A row narrower than the layout cannot be decoded: every field past the cut
    reads from the next row. Refuse rather than return plausible rows built from
    misaligned bytes.
    """
    _row_size, _count, rows = _capture_records()
    with pytest.raises(ValueError, match="narrower than"):
        _decode_table(rows, _params_field(), 200)


def test_a_non_positive_declared_width_is_refused() -> None:
    _row_size, _count, rows = _capture_records()
    with pytest.raises(ValueError):
        _decode_table(rows, _params_field(), 0)


def test_the_packed_path_still_decodes_at_the_descriptor_width() -> None:
    """Rounding uc_size up to the alignment would have broken this case.

    RFC_READ_TABLE's interface arrives uncompressed and packed: 402 exactly, no
    remainder. A fix that padded the descriptor to 404 would corrupt it in the
    mirror image of the bug it set out to fix.
    """
    packed = b"\x00" * (402 * 3)
    decoded = _decode_table(packed, _params_field(), 402)
    assert len(decoded) == 3
    # And with no server width at all, the descriptor is still the right answer.
    assert len(_decode_table(packed, _params_field())) == 3


def test_parse_invoke_response_uses_the_declared_width_end_to_end() -> None:
    """The whole path, not just the codec: capture in, clean rows out."""
    from saprfclib.invoke import parse_invoke_response

    desc = FunctionDesc(name="RFC_GET_FUNCTION_INTERFACE", parameters=[_params_field()])
    result = parse_invoke_response(_strip_gw_header(COMPRESSED.read_bytes()), desc)

    params = result["PARAMS"]
    assert isinstance(params, list)
    assert len(params) == 44
    assert all(r["PARAMCLASS"].strip() for r in params)
    assert params[0]["PARAMETER"].strip() == "ADDRESS"
