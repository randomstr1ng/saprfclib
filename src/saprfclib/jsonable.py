# SPDX-License-Identifier: MPL-2.0
"""Convert a decoded RFC result into JSON-serialisable values.

:func:`saprfclib.Connection.call` returns real Python types — ``datetime.date``
for DATS, ``datetime.time`` for TIMS, ``decimal.Decimal`` for BCD and DECFLOAT,
``bytes`` for RAW and XSTRING. That is the right decode: a string would lose
information, and a float would lose precision that matters in financial data.

It is also not what ``json.dumps`` accepts, so every integration writing results
into a JSON-shaped system — a SOAR playbook, an HTTP API, a message queue —
writes the same recursive normaliser. This is that function, once.

Deliberately a separate call rather than a ``call(..., json_safe=True)`` flag:
the protocol path should not carry a presentation concern, and a caller that
wants both the exact value and a serialisable one should not have to choose at
call time.
"""

from __future__ import annotations

import datetime as _dt
from decimal import Decimal
from typing import Any

__all__ = ["jsonable"]


def jsonable(value: Any) -> Any:
    """Return ``value`` with RFC-decoded types replaced by JSON-safe ones.

    Recurses through dicts, lists and tuples, so a whole ``call()`` result can be
    passed in one go. Anything already serialisable is returned unchanged.

    Conversions:

    ==================  ==========================  ===============================
    From                To                          Note
    ==================  ==========================  ===============================
    ``datetime``        ISO-8601 ``str``            ``isoformat()``
    ``date``            ISO-8601 ``str``            e.g. ``"2026-09-17"``
    ``time``            ISO-8601 ``str``            e.g. ``"14:30:00"``
    ``Decimal``         ``str``                     **never float** — see below
    ``bytes``           hex ``str``                 lowercase, no prefix
    ==================  ==========================  ===============================

    ``Decimal`` becomes a string, not a float, for the same reason the codec
    refuses float in the first place: ``float(Decimal("0.1"))`` is not 0.1, and a
    currency amount that survives the wire intact should not lose precision on the
    way out of the library. A consumer that wants a number can parse the string
    with full control over rounding; one that gets a float cannot get the digits
    back.

    ``bytes`` becomes hex rather than base64 because RFC binary fields are
    routinely inspected by hand — a RAW key or a unit id is read as hex
    everywhere else in this library and in SAP's own tools.

    Dict keys are left alone. RFC parameter names are always strings, and coercing
    a key would hide a caller passing something else.

    >>> jsonable({"AMOUNT": Decimal("12.50"), "WHEN": _dt.date(2026, 9, 17)})
    {'AMOUNT': '12.50', 'WHEN': '2026-09-17'}
    """
    # datetime before date: datetime is a subclass of date, so the order decides
    # whether a timestamp keeps its time component.
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    if isinstance(value, _dt.date):
        return value.isoformat()
    if isinstance(value, _dt.time):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    # bool before int would matter if ints were converted; they are not, and bool
    # is JSON-native anyway. bytearray and memoryview reach the wire as bytes do.
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).hex()
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    # str is a Sequence; check it before the list/tuple branch or every string
    # would be walked character by character into a list.
    if isinstance(value, list | tuple):
        return [jsonable(v) for v in value]
    return value
