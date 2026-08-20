# tests/test_snc_gss_binding.py
#
# Unit tests for GssBinding — the ctypes GSS-API layer that mirrors SAP's
# dlopen(SNC_LIB) + resolve-6-function-pointers pattern (D-06).
#
# All tests are offline: a MockGssLib double is injected via the `loader` seam
# so no real .so is required. MockGssLib is analogous to tests/_mocks.MockTransport
# — it records the arguments passed to each GSS function and returns scripted
# (major, minor) results and output buffers.
#
# Coverage:
#   - GssBinding resolves all 6 required GSS symbols + the 4 helpers.
#   - acquire_cred is called with cred_usage == GSS_C_INITIATE (client).
#   - import_name receives the quote-stripped partner name (D-14).
#   - a routine-error GSS major surfaces as SncError(.major/.minor) with no
#     credential/token text (threat T-07-CRED).
#
# A live symbol-resolution test against a real libgssapi_krb5.so.2 is gated
# behind SAPRFC_SNC_LIB + the integration marker (offline suite never needs it).

import os

import pytest

from saprfclib.exceptions import SncError
from saprfclib.snc import GssBinding

# The 6 required GSS functions (D-06) + 4 helpers GssBinding must resolve.
_REQUIRED_GSS_FNS = (
    "gss_init_sec_context",
    "gss_accept_sec_context",
    "gss_wrap",
    "gss_unwrap",
    "gss_get_mic",
    "gss_verify_mic",
)
_HELPER_GSS_FNS = (
    "gss_import_name",
    "gss_acquire_cred",
    "gss_release_buffer",
    "gss_release_name",
)

GSS_S_COMPLETE = 0
GSS_C_INITIATE = 1


class _MockGssFn:
    """A single scripted GSS function: records call args, returns a preset major.

    GssBinding drives GSS through small wrapper methods that pass Python-level
    arguments (the imported name string, the cred usage int, etc.) to these mock
    callables. The mock does NOT need to be ctypes-compatible — the `loader`
    seam returns a MockGssLib instead of a real CDLL, so no ctypes marshalling
    occurs in the offline suite.
    """

    def __init__(self, name: str, major: int = GSS_S_COMPLETE, minor: int = 0):
        self.name = name
        self.major = major
        self.minor = minor
        self.calls: list = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.major, self.minor


class MockGssLib:
    """Scripted GSS library double injected via the GssBinding `loader` seam.

    Exposes the 10 GSS function names as :class:`_MockGssFn` attributes. Records
    the high-level arguments GssBinding passes (imported name, cred usage) so
    tests can assert on quote-stripping (D-14) and GSS_C_INITIATE.
    """

    def __init__(
        self,
        *,
        acquire_major=GSS_S_COMPLETE,
        import_major=GSS_S_COMPLETE,
        acquire_minor=0,
        import_minor=0,
    ):
        for fn in _REQUIRED_GSS_FNS + _HELPER_GSS_FNS:
            setattr(self, fn, _MockGssFn(fn))
        self.gss_acquire_cred = _MockGssFn(
            "gss_acquire_cred", major=acquire_major, minor=acquire_minor
        )
        self.gss_import_name = _MockGssFn("gss_import_name", major=import_major, minor=import_minor)


def _make_binding(mock: MockGssLib | None = None, **kwargs) -> GssBinding:
    mock = mock or MockGssLib()
    params = {
        "snc_lib": "/nonexistent/libgssapi_krb5.so.2",
        "snc_partnername": "p:CN=SAP Server",
        "loader": lambda _path: mock,
    }
    params.update(kwargs)
    return GssBinding(**params)


def test_resolves_all_six_gss_symbols() -> None:
    mock = MockGssLib()
    binding = _make_binding(mock)
    for fn in _REQUIRED_GSS_FNS:
        assert hasattr(binding._lib, fn), f"missing required GSS symbol {fn}"
    for fn in _HELPER_GSS_FNS:
        assert hasattr(binding._lib, fn), f"missing GSS helper {fn}"


def test_acquire_cred_uses_initiate() -> None:
    mock = MockGssLib()
    _make_binding(mock)
    assert mock.gss_acquire_cred.calls, "acquire_cred was never called"
    args, kwargs = mock.gss_acquire_cred.calls[0]
    # The cred usage GSS_C_INITIATE must be passed (positional or kwarg).
    assert GSS_C_INITIATE in args or kwargs.get("cred_usage") == GSS_C_INITIATE


def test_import_name_strips_enclosing_quotes() -> None:
    # D-14: SAP env may quote SNC_PARTNERNAME; strip enclosing " and the SAP
    # SNC type prefix ("p:") before gss_import_name (BN RE of STISncInit).
    mock = MockGssLib()
    _make_binding(mock, snc_partnername='"p:CN=X"')
    assert mock.gss_import_name.calls, "import_name was never called"
    args, kwargs = mock.gss_import_name.calls[0]
    imported = kwargs.get("name")
    if imported is None:
        imported = next((a for a in args if isinstance(a, str)), None)
    assert imported == "CN=X"  # both quotes and "p:" prefix stripped


def test_import_name_strips_myname_quotes() -> None:
    mock = MockGssLib()
    b = _make_binding(mock, snc_myname='"p:CN=Client"')
    assert b._myname == "CN=Client"  # both quotes and "p:" prefix stripped


def test_gss_error_raises_snc_error_no_leak() -> None:
    # A routine-error major on acquire_cred must surface as SncError(major/minor)
    # with no credential/token text (T-07-CRED).
    mock = MockGssLib(acquire_major=0x00070000, acquire_minor=0x2A)
    with pytest.raises(SncError) as ei:
        _make_binding(mock, snc_partnername='"p:CN=SecretPartner"')
    err = ei.value
    assert err.major == 0x00070000
    assert err.minor == 0x2A
    text = str(err)
    assert "SecretPartner" not in text
    assert "libgssapi" not in text
    assert "krb5" not in text


def test_close_is_idempotent() -> None:
    binding = _make_binding()
    binding.close()
    binding.close()  # double-close must not raise (guard against double-free)


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("SAPRFC_SNC_LIB"),
    reason="SAPRFC_SNC_LIB env var required for live GSS symbol-resolution test",
)
def test_live_gss_symbol_resolution() -> None:
    # Live path home: resolve the 6 GSS symbols against a real .so.
    lib_path = os.environ["SAPRFC_SNC_LIB"]
    binding = GssBinding(
        snc_lib=lib_path,
        snc_partnername=os.environ.get("SAPRFC_SNC_PARTNERNAME", "p:CN=test"),
    )
    for fn in _REQUIRED_GSS_FNS:
        assert hasattr(binding._lib, fn)
    binding.close()
