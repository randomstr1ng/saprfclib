# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib-native typed exceptions (D-14..D-19).
#
# These are the public error types raised by the synchronous RFC client. They use
# saprfclib-native names — deliberately NOT aliased to pyrfc's upper-cased "ABAP*"
# error names (D-14; pyrfc-compatible aliases are a Phase 8 Deferred Idea). A
# single SapRfcError
# base lets callers `except saprfclib.SapRfcError` to catch every RFC error (D-18).
#
# The AbapApplicationError field set mirrors RFC_ERROR_INFO from SDK type definitions
# (key, message, abapMsgClass, abapMsgType, abapMsgNumber, abapMsgV1..V4) for full
# pyrfc field parity (D-15). Any field may be absent in the error TLV, so every
# field defaults to None.
#
# Security (threat T-04-CRED): these classes carry only server-supplied error text
# and caller-passed values. They are never populated from credential tags — that
# invariant is enforced at the 04-05 wire-to-exception classification boundary.
#
# RetryExhausted (T-09-04-CRED lineage): carries only tid/unit_id/unit_type and the
# last CommunicationError cause. It MUST NOT accept or store credentials, payload
# bytes, or params (T-09-04-CRED security contract).

__all__ = [
    "SapRfcError",
    "AbapApplicationError",
    "AbapSystemFailure",
    "CommunicationError",
    "PoolTimeoutError",
    "RetryExhausted",
    "SncError",
    "TransactionalError",
    "WebSocketError",
]


class SapRfcError(Exception):
    """Common base for all saprfclib RFC errors (D-18).

    Catching ``SapRfcError`` catches every error type the client raises:
    ``AbapApplicationError``, ``AbapSystemFailure`` and ``CommunicationError``.
    """


class AbapApplicationError(SapRfcError):
    """An ABAP-level application error returned by the called function module (D-15).

    Mirrors the ``RFC_ERROR_INFO`` ABAP message fields for full pyrfc parity. Every
    field may be absent in the wire error and therefore defaults to ``None``.
    """

    def __init__(
        self,
        *,
        key: str | None = None,
        msg_class: str | None = None,
        msg_type: str | None = None,
        msg_number: str | None = None,
        msg_v1: str | None = None,
        msg_v2: str | None = None,
        msg_v3: str | None = None,
        msg_v4: str | None = None,
        message: str | None = None,
    ) -> None:
        self.key = key
        self.msg_class = msg_class
        self.msg_type = msg_type
        self.msg_number = msg_number
        self.msg_v1 = msg_v1
        self.msg_v2 = msg_v2
        self.msg_v3 = msg_v3
        self.msg_v4 = msg_v4
        self.message = message
        # Build a useful diagnostic string, omitting absent parts.
        diagnostic = ": ".join(part for part in (key, message) if part is not None)
        super().__init__(diagnostic)


class AbapSystemFailure(SapRfcError):
    """An ABAP system failure / short dump on the backend (D-16).

    Mirrors the ``RFC_ERROR_INFO`` ABAP message fields (same set as
    :class:`AbapApplicationError`, minus ``key`` which is absent for system
    failures). Every field may be absent in the wire error and defaults to
    ``None``.
    """

    def __init__(
        self,
        *,
        msg_class: str | None = None,
        msg_type: str | None = None,
        msg_number: str | None = None,
        msg_v1: str | None = None,
        msg_v2: str | None = None,
        msg_v3: str | None = None,
        msg_v4: str | None = None,
        message: str | None = None,
    ) -> None:
        self.msg_class = msg_class
        self.msg_type = msg_type
        self.msg_number = msg_number
        self.msg_v1 = msg_v1
        self.msg_v2 = msg_v2
        self.msg_v3 = msg_v3
        self.msg_v4 = msg_v4
        self.message = message
        super().__init__(message if message is not None else "")


class CommunicationError(SapRfcError):
    """A transport/network-level communication failure (D-17).

    ``original_exception`` carries the underlying transport error (e.g. an
    ``OSError``) when the failure originated below the RFC protocol layer.
    """

    def __init__(
        self,
        message: str | None = None,
        *,
        original_exception: BaseException | None = None,
    ) -> None:
        self.message = message
        self.original_exception = original_exception
        super().__init__(message if message is not None else "")


class TransactionalError(SapRfcError):
    """A transactional RFC (tRFC/qRFC/bgRFC) error (D-18 / TRFC-08).

    Raised when a TID-store operation fails, a duplicate TID is detected,
    or any tRFC/qRFC/bgRFC protocol invariant is violated. Subclasses
    :class:`SapRfcError` so ``except saprfclib.SapRfcError`` still catches it.
    """

    def __init__(self, message: str | None = None) -> None:
        self.message = message
        super().__init__(message if message is not None else "")


class RetryExhausted(TransactionalError):
    """All retry attempts for a tRFC/qRFC/bgRFC submit failed; payload is parked (D-01/D-03).

    Raised by :meth:`~saprfclib.AsyncConnection._submit_with_retry` after
    ``max_retries + 1`` consecutive :class:`CommunicationError` failures.
    The pending call's request bytes are persisted to the durable store before
    this exception is raised; the caller can re-drive via
    :meth:`~saprfclib.AsyncConnection.retry_parked`.

    Carries only the transactional identifier (``tid`` or ``unit_id``/``unit_type``)
    and the last ``CommunicationError`` as ``cause``.  It subclasses
    :class:`TransactionalError` (and thus :class:`SapRfcError`) so
    ``except saprfclib.SapRfcError`` catches it uniformly (D-18).

    Security (T-09-04-CRED)
    -----------------------
    This class MUST NOT accept or store credentials, payload bytes, or parameter
    dicts.  The ``tid``/``unit_id`` are short identifiers (24-char / 32-char hex),
    not user-controlled content beyond the alphabet check.  ``cause`` carries only
    the :class:`CommunicationError` message, never the connection ``passwd``,
    ``ws_proxy_pass``, ``snc_*`` fields, or raw request bytes.  The diagnostic
    string built in ``__init__`` contains only the id and a short cause summary.
    """

    def __init__(
        self,
        *,
        tid: str | None = None,
        unit_id: str | None = None,
        unit_type: str | None = None,
        cause: "CommunicationError | None" = None,
    ) -> None:
        self.tid = tid
        self.unit_id = unit_id
        self.unit_type = unit_type
        self.cause = cause

        # Build a credential-safe diagnostic string (T-09-04-CRED):
        # only the id and a short cause summary, nothing credential-bearing.
        if tid is not None:
            id_part = f"tRFC {tid}"
        elif unit_id is not None:
            type_tag = f" ({unit_type})" if unit_type is not None else ""
            id_part = f"bgRFC unit {unit_id}{type_tag}"
        else:
            id_part = "transactional call"

        cause_part = f": {cause}" if cause is not None else ""
        super().__init__(f"{id_part} exhausted{cause_part}")


class SncError(SapRfcError):
    """GSS-API / SNC handshake or frame error (Phase 7 SNC transport).

    ``major`` and ``minor`` carry the OM_uint32 GSS status codes returned by the
    underlying SNC library. Subclasses :class:`SapRfcError` so callers can
    ``except saprfclib.SapRfcError`` uniformly (D-18).

    Security (threat T-07-CRED): this class is NEVER populated from credential
    material. The ``snc_lib`` path, ``snc_myname``, ``snc_partnername``, GSS
    tokens, and any name/credential bytes must never enter the message, the
    ``major``/``minor`` fields, or the ``repr``. Only the two GSS status codes
    (and, optionally, a caller-supplied non-credential message) are carried.
    """

    def __init__(
        self,
        message: str | None = None,
        *,
        major: int | None = None,
        minor: int | None = None,
    ) -> None:
        self.message = message
        self.major = major
        self.minor = minor
        diagnostic = message or (f"GSS error major=0x{(major or 0):08x} minor=0x{(minor or 0):08x}")
        super().__init__(diagnostic)


class WebSocketError(SapRfcError):
    """WebSocket upgrade, framing, TLS, or HTTP-CONNECT-proxy error (Phase 7 wRFC).

    Raised by :mod:`saprfclib.ws` when the RFC 6455 upgrade fails (bad status,
    wrong ``Sec-WebSocket-Accept``, or a second redirect), when the HTTP CONNECT
    proxy tunnel is refused, or when a WebSocket protocol/close error occurs.
    Subclasses :class:`SapRfcError` so callers can ``except saprfclib.SapRfcError``
    uniformly (D-18).

    Security (threat T-07-PROXY-CRED): this class is NEVER populated from
    credential material. ``ws_proxy_pass`` and the ``Proxy-Authorization`` value
    must never enter the message or the ``repr``. Proxy failures report only the
    HTTP status code — never the credential string.
    """

    def __init__(self, message: str | None = None) -> None:
        self.message = message
        super().__init__(message if message is not None else "")


class PoolTimeoutError(SapRfcError):
    """A :class:`~saprfclib.pool.ConnectionPool` could not lend a connection in time.

    Raised by ``ConnectionPool.acquire()`` when every connection is in use and the
    acquire deadline elapses before one is released (POOL-04). Subclasses
    ``SapRfcError`` so callers can ``except saprfclib.SapRfcError`` uniformly (D-18).

    The structured diagnostic fields aid debugging an exhausted pool:

    - ``waited`` — seconds the caller blocked before giving up.
    - ``discarded`` — connections found dead-on-ping and replaced during the wait.
    - ``active`` — connections currently lent out (``len(in_use)``).
    - ``idle`` — connections sitting idle (``len(idle)``).
    - ``max_size`` — the pool's hard ceiling on total connections.

    Security (threat T-05-P03): the diagnostic message carries only these counts
    and never echoes the connection ``params`` (which hold credentials, T-04-CRED).
    """

    def __init__(
        self,
        *,
        waited: float,
        discarded: int,
        active: int,
        idle: int,
        max_size: int,
        message: str | None = None,
    ) -> None:
        self.waited = waited
        self.discarded = discarded
        self.active = active
        self.idle = idle
        self.max_size = max_size
        diagnostic = message or (
            f"no pooled connection after {waited:.3f}s; discarded={discarded}; "
            f"active={active} idle={idle} max={max_size}"
        )
        self.message = diagnostic
        super().__init__(diagnostic)
