# tests/test_packaging.py
#
# Dependency-contract guard for the D-26/D-27 packaging decisions.
#
# Phase 7 (SNC + wRFC) locks two dependency facts:
#   - D-27: wsproto and h11 are CORE dependencies — `pip install saprfclib`
#     pulls them with no extra, because the wRFC transport imports them
#     unconditionally.
#   - D-26 (revised for v0.2.0): the built-in SNC mechanism needs asn1crypto,
#     ecdsa and tlslite-ng — all pure Python, all core. The native-library path
#     (`snc_lib`) still needs nothing at install time; ctypes is stdlib.
#     minikerberos stays forbidden: it pulls pycryptodomex (a C extension).
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


# The complete set of runtime dependencies. Each one must be pure Python: a
# py3-none-any wheel, no build step. Adding a dependency means adding it here
# deliberately, after checking that.
_ALLOWED_CORE = {"wsproto", "h11", "asn1crypto", "ecdsa", "tlslite-ng"}


def _dist_name(req: str) -> str:
    import re

    return re.split(r"[<>=!~;\[ ]", req, maxsplit=1)[0].strip().lower()


def test_core_deps_are_exactly_the_allowlist():
    deps = {_dist_name(d) for d in _load()["project"]["dependencies"]}
    assert deps == _ALLOWED_CORE, f"core dependency set changed: {sorted(deps)}"


def test_snc_crypto_deps_are_core():
    deps = {_dist_name(d) for d in _load()["project"]["dependencies"]}
    assert {"asn1crypto", "ecdsa", "tlslite-ng"} <= deps


def test_no_native_crypto_dependency():
    raw = _raw().lower()
    for banned in ("cryptography", "pycryptodome", "pyopenssl", "unicrypto", "gssapi"):
        assert f'"{banned}' not in raw, f"{banned} must not be a dependency"


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
