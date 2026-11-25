# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""The public API, compared with its committed snapshot (#90).

``tests/api/public_api.json`` lists every name in ``saprfclib.__all__`` with its kind,
its signature, the public methods of a class, and a stability label. A rename, a
removal, a new export or a changed signature fails this test with a readable diff.
That is the point: such a change alters the public contract, so it is made on purpose,
recorded in CHANGELOG.md, and the snapshot is regenerated with

    python -m tests.test_public_api --update

Regeneration keeps the stability labels and reasons already in the file. A new
export arrives without one and fails the test until it is labelled, so nothing
becomes public without someone deciding what it promises.
"""

from __future__ import annotations

import inspect
import json
import pathlib
import sys
from typing import Any

import saprfclib

SNAPSHOT = pathlib.Path(__file__).parent / "api" / "public_api.json"


def _signature(obj: Any) -> str | None:
    try:
        return str(inspect.signature(obj))
    except (TypeError, ValueError):
        return None


def _entry(name: str) -> dict[str, Any]:
    obj = getattr(saprfclib, name)
    if inspect.isclass(obj):
        members = {}
        for attr, raw in sorted(vars(obj).items()):
            if attr.startswith("_"):
                continue
            if isinstance(raw, property):
                members[attr] = "property"
            elif callable(getattr(obj, attr, None)):
                members[attr] = _signature(getattr(obj, attr)) or "callable"
        kind = "exception" if issubclass(obj, BaseException) else "class"
        signature = None if kind == "exception" else _signature(obj)
        return {"kind": kind, "signature": signature, "members": members}
    if callable(obj):
        return {"kind": "function", "signature": _signature(obj), "members": {}}
    return {"kind": "constant", "signature": None, "members": {}, "type": type(obj).__name__}


def live_api() -> dict[str, dict[str, Any]]:
    return {name: _entry(name) for name in saprfclib.__all__ if name != "__version__"}


def load_snapshot() -> dict[str, Any]:
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))


def _shape(entry: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in entry.items() if k not in ("stability", "reason")}


def test_the_public_api_matches_the_snapshot() -> None:
    snap = load_snapshot()["exports"]
    live = live_api()
    problems = []
    for name in sorted(set(snap) - set(live)):
        problems.append(f"removed from __all__: {name}")
    for name in sorted(set(live) - set(snap)):
        problems.append(f"new in __all__, not in the snapshot: {name}")
    for name in sorted(set(live) & set(snap)):
        want, got = _shape(snap[name]), live[name]
        if want != got:
            for key in sorted(set(want) | set(got)):
                if want.get(key) != got.get(key):
                    problems.append(
                        f"{name}.{key}:\n    snapshot: {want.get(key)!r}\n    live:     {got.get(key)!r}"
                    )
    assert not problems, (
        "The public API differs from tests/api/public_api.json. If the change is "
        "intended, record it in CHANGELOG.md and run `python -m tests.test_public_api "
        "--update`.\n" + "\n".join(problems)
    )


def test_every_export_has_a_known_stability_label() -> None:
    data = load_snapshot()
    levels = data["stability_levels"]
    for name, entry in data["exports"].items():
        assert entry.get("stability") in levels, f"{name}: stability {entry.get('stability')!r}"
        assert entry.get("reason"), f"{name}: no reason given for its stability label"


def test_dunder_version_stays_exported() -> None:
    assert "__version__" in saprfclib.__all__


def update() -> None:
    old = load_snapshot() if SNAPSHOT.exists() else {"exports": {}}
    exports = {}
    for name, entry in live_api().items():
        prev = old["exports"].get(name, {})
        entry["stability"] = prev.get("stability", "UNLABELLED")
        entry["reason"] = prev.get("reason", "")
        exports[name] = entry
    old["exports"] = exports
    SNAPSHOT.write_text(json.dumps(old, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    unlabelled = [n for n, e in exports.items() if e["stability"] == "UNLABELLED"]
    sys.stdout.write(f"wrote {SNAPSHOT} ({len(exports)} exports)\n")
    if unlabelled:
        sys.stdout.write(f"label these before committing: {', '.join(unlabelled)}\n")


if __name__ == "__main__":
    if sys.argv[1:] == ["--update"]:
        update()
    else:
        sys.stdout.write(f"{__doc__}\n")
