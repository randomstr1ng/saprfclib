# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — descriptor dataclasses
#
# Field/type/function descriptors carrying the metadata the codec needs to
# encode/decode ABAP values. Phase 2 builds these by hand in tests; Phase 3
# fills them from live DDIC metadata.
#
# Sizing note: nuc_size/uc_size are the total non-Unicode / Unicode byte
# lengths of a structure layout (map to RfcSetTypeLength(nucByteLength,
# ucByteLength) in the C SDK). The unicode_mode flag on FieldDesc selects the
# nuc_* vs uc_* offsets/lengths at decode time (D-09); Phase 2 wire mode is
# UTF-16-LE, so unicode_mode defaults to True.
from __future__ import annotations

from dataclasses import dataclass, field

__all__ = [
    "FieldDesc",
    "TypeDesc",
    "FunctionDesc",
    "RFC_IMPORT",
    "RFC_EXPORT",
    "RFC_CHANGING",
    "RFC_TABLES",
]

# RFC_DIRECTION constants (SDK type definitions lines 644-650).
# These reflect the **caller's perspective**: RFC_IMPORT means the caller sends the
# value (ABAP IMPORTING param); RFC_EXPORT means the caller receives it back.
RFC_IMPORT: int = 0x01  # caller sends  (ABAP IMPORTING, PARAMCLASS 'I')
RFC_EXPORT: int = 0x02  # caller reads  (ABAP EXPORTING, PARAMCLASS 'E')
RFC_CHANGING: int = 0x03  # bidirectional (ABAP CHANGING,  PARAMCLASS 'C')
RFC_TABLES: int = 0x07  # tables        (ABAP TABLES,    PARAMCLASS 'T')


@dataclass
class FieldDesc:
    """A single field descriptor (D-02).

    The sole context object the codec consumes per field. ``unicode_mode``
    drives nuc_* vs uc_* offset/length selection. ``type_desc`` is set only for
    RFCTYPE_STRUCTURE / RFCTYPE_TABLE fields (points at the nested layout); it is
    ``None`` for all scalar types.
    """

    name: str
    rfctype: int
    nuc_length: int
    nuc_offset: int
    uc_length: int
    uc_offset: int
    decimals: int
    unicode_mode: bool = True
    type_desc: TypeDesc | None = None
    direction: int = RFC_IMPORT  # RFC_DIRECTION from PARAMCLASS (default: caller sends)


@dataclass
class TypeDesc:
    """A structure/table layout descriptor (D-07).

    Holds its ordered field list and the total byte size of the layout in both
    the non-Unicode (``nuc_size``) and Unicode (``uc_size``) representations.
    """

    name: str
    fields: list[FieldDesc]
    nuc_size: int
    uc_size: int


@dataclass
class FunctionDesc:
    """A function-module descriptor (stub).

    Phase 3 fills the parameter list from live DDIC metadata; Phase 2 only
    needs the name and an (empty) parameter list to satisfy descriptor wiring.
    """

    name: str
    parameters: list[FieldDesc] = field(default_factory=list)
