# tests/test_packaging.py
#
# Dependency-contract guard for the D-26/D-27 packaging decisions.
#
# Phase 7 (SNC + wRFC) locks two dependency facts:
#   - D-27: wsproto and h11 are CORE dependencies — `pip install saprfclib`
#     pulls them with no extra, because the wRFC transport imports them
#     unconditionally.
#   - D-26: SNC needs NO install-time dependency — the user supplies the GSS
#     `.so` at runtime via `snc_lib`; ctypes is stdlib. D-07 additionally
#     forbids minikerberos (it cannot do gss_wrap/gss_unwrap).
#
# These tests parse the real repo pyproject.toml (not a fixture copy) so a
# future edit cannot silently reintroduce the [ws]/[snc]/all extras or
# minikerberos without turning this file red.

import pathlib
import tomllib

_PYPROJECT = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"


def _load():
    with _PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)


def _raw():
    return _PYPROJECT.read_text(encoding="utf-8")


def test_wsproto_h11_are_core_deps():
    deps = _load()["project"]["dependencies"]
    assert any(d.startswith("wsproto") for d in deps), f"wsproto not a core dep: {deps}"
    assert any(d.startswith("h11") for d in deps), f"h11 not a core dep: {deps}"


def test_no_ws_or_snc_extras():
    opt = _load()["project"].get("optional-dependencies", {})
    assert "ws" not in opt, "stale [ws] extra reintroduced"
    assert "snc" not in opt, "stale [snc] extra reintroduced"
    assert "all" not in opt, "stale [all] extra reintroduced"
    assert "dev" in opt, "dev extra should remain"


def test_minikerberos_absent():
    assert "minikerberos" not in _raw(), "minikerberos must not appear (D-07)"


def test_h11_pin_is_at_least_016():
    deps = _load()["project"]["dependencies"]
    h11 = next(d for d in deps if d.startswith("h11"))
    assert ">=0.16" in h11, f"h11 pin must be >=0.16, got: {h11!r}"


def test_version_is_pep440():
    import re

    import saprfclib

    v = saprfclib.__version__
    assert isinstance(v, str) and v, f"__version__ must be a non-empty str, got: {v!r}"
    assert re.match(r"^\d+\.\d+", v), (
        f"__version__ must match PEP 440 (e.g. '0.1.0' or '0.1.0.dev3+gabcdef'), got: {v!r}"
    )
