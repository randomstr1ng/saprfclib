# SPDX-License-Identifier: MPL-2.0
"""TLS verification defaults for the WebSocket transport.

The default is to verify, in all three places a caller can reach it. That is the
kind of default nothing notices when it is right and nobody notices when it
silently flips, so it is asserted rather than assumed.

Disabling it warns *and* logs. The two channels fail differently: a warning is
shown once per call site and vanishes entirely under ``python -W ignore`` or a
broad ``filterwarnings()`` — both of which a long-running service is likely to
have set for unrelated reasons. The log record survives that, so the process
where this matters most still leaves a trace that its RFC traffic was
unauthenticated.
"""

from __future__ import annotations

import inspect
import logging
import ssl
import warnings

import pytest

from saprfclib import connect
from saprfclib.ws import _make_ssl_context, connect_ws


def test_verification_is_on_by_default_everywhere_a_caller_reaches_it() -> None:
    assert inspect.signature(connect).parameters["ws_tls_verify"].default is True
    assert inspect.signature(connect_ws).parameters["verify"].default is True
    assert inspect.signature(_make_ssl_context).parameters["verify"].default is True


def test_the_default_context_actually_verifies() -> None:
    """The signature default is only half of it; the context must honour it."""
    ctx = _make_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_disabling_verification_warns_and_logs(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="saprfclib.ws"):
        with pytest.warns(UserWarning, match="DISABLED"):
            ctx = _make_ssl_context(verify=False)

    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False
    records = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert records, "a suppressed warning must not be the only signal"
    assert "NOT authenticated" in records[0].getMessage()


def test_the_log_record_survives_warnings_being_silenced() -> None:
    """The whole point of carrying both channels."""
    logger = logging.getLogger("saprfclib.ws")
    seen: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record.getMessage())

    handler = _Capture()
    logger.addHandler(handler)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # what -W ignore does
            _make_ssl_context(verify=False)
    finally:
        logger.removeHandler(handler)

    assert seen, "warnings were silenced and nothing was left to say verification was off"
