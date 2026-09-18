# SPDX-License-Identifier: MPL-2.0
"""A TABLE's row width is measured, not declared.

The same DDIC row type reaches the client at two widths. The uncompressed 0x0303
path packs rows to the sum of their field widths; the compressed 0x0305 path pads
each row to a 4-byte boundary. ``RFC_FUNINT`` is 402 packed and 404 padded,
because it carries INT4 members.

Both obvious sources are wrong on one path:

* ``TypeDesc.uc_size`` is that sum -- 402. Right packed, wrong padded.
* ``0x0302``'s ``row_size`` reports 404 on **both** paths. It carries the DDIC
  layout width and does not track how the rows were serialized. Right padded,
  wrong packed.

Picking either moves the bug rather than fixing it, and it moves silently:
splitting a 404-wide buffer by 402, or a 402-wide buffer by 404, returns the
right *number* of row-shaped slices, each drifting further out of alignment.

``row_count`` is a tally of what the server actually sent, so it cannot disagree
with the serializer. The width falls out of the buffer: ``len(buf) // row_count``.

This file covers both directions deliberately. An earlier version reached the
packed path only through the no-count fallback, never the production shape where
a 0x0302 declares 404 over 402-byte rows -- and that gap is why trusting
``row_size`` shipped. Every table fixture in this tree is one where the two
widths coincide, so the corpus cannot discriminate on its own.

Sources: tests/golden/framing/gfi_compressed_params_response.bin (padded, real);
the packed cases are synthetic, pinning the rule rather than a captured sequence,
because no uncompressed-GFI capture exists in this tree.
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


def test_rows_decode_cleanly_from_the_declared_count() -> None:
    """44 rows, every one intact.

    The width is 17776 // 44 = 404, measured rather than declared.
    """
    _row_size, count, rows = _capture_records()
    decoded = _decode_table(rows, _params_field(), count)

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
    wrong = _decode_table(rows, _params_field())  # no count: falls back to 402

    assert len(wrong) == 44, "the row count is right even when the rows are not"
    assert not all(r["PARAMCLASS"].strip() for r in wrong), (
        "decoding at the descriptor width should corrupt these rows; if it no "
        "longer does, this test is asserting nothing"
    )
    assert wrong[0]["PARAMETER"].strip() == "ADDRESS", "row 0 is aligned either way"
    assert wrong[1]["PARAMETER"].strip() != "ADMINDATA", "row 1 is where the drift starts"


def test_a_row_narrower_than_the_layout_is_refused() -> None:
    """The derived width becomes a slice length — same trust boundary as T-02-06.

    A row narrower than the layout cannot be decoded: every field past the cut
    reads from the next row. Refuse rather than return plausible rows built from
    misaligned bytes.
    """
    _row_size, _count, rows = _capture_records()
    with pytest.raises(ValueError, match="narrower than"):
        # 17776 / 88 = 202, which divides exactly and is still narrower than the
        # 402-byte layout, so this reaches the trust-boundary guard rather than
        # the divisibility one.
        _decode_table(rows, _params_field(), 88)


def test_a_buffer_that_does_not_divide_by_the_count_is_refused() -> None:
    """Every row is the same width, so a remainder means a number is lying.

    Rounding it away would decode rows that are quietly misaligned, which is the
    failure mode this whole area keeps producing.
    """
    _row_size, _count, rows = _capture_records()
    with pytest.raises(ValueError, match="does not divide"):
        _decode_table(rows, _params_field(), 43)


def test_an_empty_table_is_not_an_error() -> None:
    assert _decode_table(b"", _params_field(), 0) == []
    assert _decode_table(b"", _params_field(), None) == []


def test_the_packed_path_decodes_when_0x0302_declares_the_padded_width() -> None:
    """The production shape of the uncompressed path, and the case 485907f broke.

    RFC_READ_TABLE's own interface arrives uncompressed: 17 rows of 402 bytes,
    6834 in total — while its 0x0302 declares row_size 404, the padded DDIC
    width, exactly as the compressed capture does. Trusting that number splits a
    402-wide buffer by 404 and yields drifting rows.

    The earlier version of this test reached the packed path through the
    *fallback*, with no 0x0302 at all, so it never exercised this. That gap is
    why the regression shipped: every fixture in the tree is a table where the
    two widths coincide.

    Synthetic buffer, deliberately: it pins the rule rather than a captured byte
    sequence, and no uncompressed-GFI capture exists in this tree to pin.
    """
    packed = bytes(17 * 402)
    decoded = _decode_table(packed, _params_field(), 17)
    assert len(decoded) == 17, "17 packed rows must decode as 17"

    # The mirror, so neither direction can regress again.
    padded = bytes(44 * 404)
    assert len(_decode_table(padded, _params_field(), 44)) == 44


def test_the_descriptor_is_still_the_fallback_without_a_count() -> None:
    """Hand-built descriptors and the encode path have no 0x0302 to read."""
    packed = bytes(402 * 3)
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
