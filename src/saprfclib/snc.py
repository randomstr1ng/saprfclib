# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — SNC (Secure Network Communications) frame codec + GSS-API binding
#
# Phase 7 Track A, lowest two layers (plan 07-P01):
#   1. The SNC 0x18-byte fixed-header frame codec (build_snc_frame /
#      parse_snc_frame) — the only bytes SNC actually owns (D-02).
#   2. GssBinding: the ctypes layer that mirrors SAP's dlopen(SNC_LIB) +
#      resolve-6-function-pointers pattern (D-06). GSS crypto is delegated to
#      the user-supplied .so — no reimplementation.
#
# This module does NOT wire into the Transport seam (that is plan 07-P02). It is
# a standalone, fully offline-testable unit: the GssBinding takes an injectable
# `loader` so tests drive it with a MockGssLib double, no real .so required.
#
# Frame layout (D-02, confirmed):
#     offset  size  field
#     0x00    8B    eye-catcher = "SNCFRAME" (D-22 resolved — protocol analysis 2026-07-21)
#     0x08    1B    frame_type: 2=FR_INIT, 4=FR_ACCEPT, 7=plain, 8=integrity, 9=privacy
#     0x09    1B    protocol version = 6
#     0x0a    2B    BE uint16: total header length (0x18 + extension header size)
#     0x0c    4B    BE uint32: GSS token length
#     0x10    4B    BE uint32: application data length
#     0x14    2B    BE uint16: context/adapter ID
#     0x16    2B    BE uint16: QOP flags
#     [0x18]        GSS token bytes, then application data bytes
#
# hdrlen > 0x18 means extension headers follow the fixed header. The outbound
# mechanism extension header (first FR_INIT only) is built by
# _build_snc_ext_header; on inbound frames parse_snc_frame seeks to hdrlen, so
# an extension header is skipped rather than rejected.
#
# DoS guard (T-07-FRAME-DOS, T-03-DOS parity): parse rejects a declared
# token_len+data_len above _MAX_FRAME_BYTES (128 MiB) BEFORE slicing.
#
# Security (threat T-07-CRED): no credential material — the snc_lib path,
# snc_myname, snc_partnername, GSS tokens, or name/credential bytes — ever enters
# a log, a repr, or an exception message. SncError carries GSS major/minor only.
from __future__ import annotations

import ctypes
import os
import struct
from enum import IntEnum
from typing import Any, Protocol, cast

from saprfclib.exceptions import CommunicationError, SncError
from saprfclib.transport import Transport, connect_tcp

__all__ = [
    "build_snc_frame",
    "parse_snc_frame",
    "SncFrameType",
    "SncQop",
    "validate_snc_qop",
    "GssBinding",
    "SncTransport",
    "connect_snc",
]


# --- SNC frame header (D-02) -------------------------------------------------
# eye(8s) type(1B) ver(1B) hdrlen(2B) toklen(4B) datalen(4B) ctxid(2B) qop(2B)
_SNC_HDR = struct.Struct(">8sBBHIIHH")
_SNC_HEADER_SIZE = 0x18
_SNC_VERSION = 6
# Same 128 MiB DoS cap as transport.py (threat T-03-DOS / T-07-FRAME-DOS).
_MAX_FRAME_BYTES = 128 * 1024 * 1024

assert _SNC_HDR.size == _SNC_HEADER_SIZE  # header struct must be exactly 0x18 bytes

# Context ID used in SNC frames (confirmed from live pyrfc capture 2026-07-XX: D-24).
_SNC_CTX_ID = 3
# --- QOP field of handshake frames (header offset 0x16, BE16) ----------------
# bits 1-2 = minimum, bits 3-4 = maximum, bits 5-6 = level in use. Only handshake
# frames (FR_INIT / FR_ACCEPT) carry it; data frames carry 0. Source: golden fixture
# snc/snc_frame_headers.json — a reference client sends 0x3a/0x7a for snc_qop=1,
# 0x5c/0x7c for 2 and 0x7e/0x7e for 3, 8 and 9; the server answered 0x7e.
_QOP_MAX_AVAILABLE = 3  # privacy: both mechanisms provide confidentiality


def _qop_field(qmin: int, qmax: int, quse: int) -> int:
    return (qmin << 1) | (qmax << 3) | (quse << 5)


def _qop_unpack(field: int) -> tuple[int, int, int]:
    return (field >> 1) & 3, (field >> 3) & 3, (field >> 5) & 3


# Kept for callers that imported it: the field for snc_qop 3/8/9.
_SNC_HANDSHAKE_QOP = _qop_field(3, 3, 3)
assert _SNC_HANDSHAKE_QOP == 0x7E

# --- SNC extension header (first FR_INIT only) -----------------------------
# Layout: BE32 slot bitmask, then for every set bit a BE16 length and the slot's
# bytes. Only slot 0 is sent: BE16 mechanism id (3), then the target name as a GSS
# exported-name token (RFC 2743 section 3.2): 04 01 | BE16 OID length | mechanism
# OID | BE32 name length | DN DER. Source: golden fixture snc/snc_frame_headers.json
# (first client frame of every capture).
_SAP_SNC_OID = b"\x06\x06\x2b\x24\x03\x01\x25\x01"
_SNC_EXT_SLOT0 = b"\x00\x00\x00\x01"
_GSS_EXPORT_NAME_TOKEN_ID = b"\x04\x01"
# Back-compat aliases for the previous names of the two constants above.
_SNC_EXT_MAGIC = _SNC_EXT_SLOT0
_SNC_EXT_FLAGS = _GSS_EXPORT_NAME_TOKEN_ID

# RDN attribute types → (DER-encoded OID, string tag override). The reference
# library encodes values as PrintableString when possible and as T61String
# otherwise; DC is an IA5String; SN means serialNumber. Observed in its exported
# names for probe partner names (2026-11-08).
_RDN_OID: dict[str, bytes] = {
    "CN": b"\x06\x03\x55\x04\x03",
    "SN": b"\x06\x03\x55\x04\x05",
    "SERIALNUMBER": b"\x06\x03\x55\x04\x05",
    "C": b"\x06\x03\x55\x04\x06",
    "L": b"\x06\x03\x55\x04\x07",
    "ST": b"\x06\x03\x55\x04\x08",
    "SP": b"\x06\x03\x55\x04\x08",
    "O": b"\x06\x03\x55\x04\x0a",
    "OU": b"\x06\x03\x55\x04\x0b",
    "DC": b"\x06\x0a\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19",
}
_PRINTABLE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?")


def _der_tlv(tag: int, content: bytes) -> bytes:
    """Minimal DER length-encoding (definite short/long form for ≤64 KiB)."""
    n = len(content)
    if n < 128:
        length = bytes([n])
    elif n < 256:
        length = bytes([0x81, n])
    else:
        length = bytes([0x82, n >> 8, n & 0xFF])
    return bytes([tag]) + length + content


def _dn_value(attr: str, value: str) -> bytes:
    if not value.isascii():
        # The reference library writes non-ASCII as T.61 sequences; whether a server
        # accepts such a target name is untested, so refuse rather than guess.
        raise ValueError("non-ASCII characters in the SNC partner name are not supported")
    if attr == "DC":
        return _der_tlv(0x16, value.encode("ascii"))  # IA5String
    if attr == "C":
        value = value.upper()
    tag = 0x13 if set(value) <= _PRINTABLE else 0x14  # PrintableString / T61String
    return _der_tlv(tag, value.encode("ascii"))


def _build_dn_der(dn_str: str) -> bytes:
    """Encode a SAP SNC DN string to X.509 ASN.1 DER (RFC 5280: C first, CN last)."""
    rdns = [r.strip() for r in dn_str.replace(";", ",").split(",")]
    rdns.reverse()  # RFC 5280 order: outermost (C) first in DER
    parts = bytearray()
    for rdn in rdns:
        attr, _, value = rdn.partition("=")
        attr = attr.strip().upper()
        value = value.strip()
        oid_bytes = _RDN_OID.get(attr)
        if oid_bytes is None:
            raise ValueError(f"Unknown RDN attribute in SNC partner name: {attr!r}")
        atv = oid_bytes + _dn_value(attr, value)
        parts += _der_tlv(0x31, _der_tlv(0x30, atv))  # SET{SEQUENCE{ATV}}
    return _der_tlv(0x30, bytes(parts))  # outer SEQUENCE


def _build_snc_ext_header(partner_dn_str: str) -> bytes:
    """Build the extension header of the first FR_INIT frame (target-name slot 0)."""
    dn_der = _build_dn_der(partner_dn_str)
    export_token = (
        _GSS_EXPORT_NAME_TOKEN_ID
        + struct.pack(">H", len(_SAP_SNC_OID))
        + _SAP_SNC_OID
        + struct.pack(">I", len(dn_der))
        + dn_der
    )
    slot0 = struct.pack(">H", _SNC_CTX_ID) + export_token
    return _SNC_EXT_SLOT0 + struct.pack(">H", len(slot0)) + slot0


def _get_snc_adapter_info(lib: ctypes.CDLL) -> bytes:
    """Return the SNC adapter info string sent as app_data in FR_INIT frames.

    The string identifies the SNC adapter. Confirmed from live pyrfc SNC capture
    (D-24): CommonCryptoLib sends "Internal SNC-Adapter (Rev 1.1) to CommonCryptoLib".
    sapcr_sncinfo is the sncinfo CLI entry point and crashes when called without
    arguments — do not call it.
    """
    return b"Internal SNC-Adapter (Rev 1.1) to CommonCryptoLib"


class SncFrameType(IntEnum):
    """SNC frame type byte at offset 0x08 (D-02)."""

    FR_INIT = 2  # client → server handshake init token (proxy capture confirmed)
    FR_ACCEPT = 4  # server → client handshake accept token (proxy capture confirmed)
    # server → client, no token and no data: the acceptor completed on the
    # initiator's last token without producing one of its own. Source: live capture
    # 2026-11-10, Kerberos SNC handshake (client's final FR_INIT answered by type 5).
    FR_ACCEPT_ACK = 5
    PLAIN = 7  # data frame, QOP 1 (authentication only, no protection)
    INTEGRITY = 8  # data frame, QOP 2 (gss_get_mic / gss_verify_mic)
    PRIVACY = 9  # data frame, QOP 3 (gss_wrap / gss_unwrap)


class SncQop(IntEnum):
    """SNC quality-of-protection level (D-08).

    1-3 select a protection level directly. 8 and 9 are the two indirect values
    SAP defines: 9 asks for the maximum the connection supports, 8 for whatever
    the system's own default protection is.

    ``DEFAULT`` (8) selects the client's default levels. A client without an SAP
    profile, which is what this library is, defaults to privacy: a reference
    client sends exactly the same handshake QOP field for 8 as for 3 (golden
    fixture snc/snc_frame_headers.json). 9 selects the maximum available, which
    is privacy for both mechanisms.

    The level is a starting point: a server whose minimum is higher raises it
    during the handshake (see :class:`SncTransport`).
    """

    AUTH_ONLY = 1
    INTEGRITY = 2
    PRIVACY = 3
    DEFAULT = 8  # client default = privacy; see the class docstring
    MAXIMUM = 9


#: Which frame protection each accepted QOP selects.
#:
#: Explicit rather than a ``>=`` comparison. The dispatch used to read
#: ``qop >= PRIVACY`` / ``== INTEGRITY`` / else PLAIN, which meant any value the
#: library did not recognise fell through to the ``else``: a negative number sent
#: payloads unprotected, silently, on a connection the caller had asked to
#: protect. A table cannot fall through.
_QOP_PROTECTION: dict[int, SncFrameType] = {
    SncQop.AUTH_ONLY: SncFrameType.PLAIN,
    SncQop.INTEGRITY: SncFrameType.INTEGRITY,
    SncQop.PRIVACY: SncFrameType.PRIVACY,
    SncQop.DEFAULT: SncFrameType.PRIVACY,
    SncQop.MAXIMUM: SncFrameType.PRIVACY,
}


_PROTECTION_LEVEL: dict[SncFrameType, int] = {
    SncFrameType.PLAIN: 1,
    SncFrameType.INTEGRITY: 2,
    SncFrameType.PRIVACY: 3,
}
_LEVEL_PROTECTION: dict[int, SncFrameType] = {v: k for k, v in _PROTECTION_LEVEL.items()}
_FRAME_LEVEL: dict[int, int] = {int(k): v for k, v in _PROTECTION_LEVEL.items()}


def validate_snc_qop(value: int) -> int:
    """Return ``value`` if it is a QOP level this library implements, else raise.

    A setting that decides whether payloads are encrypted must not accept a value
    it does not recognise. Every plausible typo used to land on privacy, which is
    the safe side and is why this went unnoticed -- but a negative number landed
    on PLAIN, and nothing said so.

    Raises:
        ValueError: if ``value`` is not one of 1, 2, 3, 8 or 9.
    """
    try:
        level = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"snc_qop must be an integer, got {value!r}") from None
    if level not in _QOP_PROTECTION:
        accepted = ", ".join(str(int(q)) for q in sorted(_QOP_PROTECTION))
        raise ValueError(
            f"snc_qop={level} is not a protection level this library implements "
            f"(accepted: {accepted}). 1=authentication only, 2=integrity, "
            f"3=privacy, 8=system default, 9=maximum. Refusing rather than "
            f"guessing: the value decides whether payloads are encrypted."
        )
    return level


def build_snc_frame(
    eye: bytes,
    frame_type: int,
    ctx_id: int,
    qop: int,
    gss_token: bytes = b"",
    app_data: bytes = b"",
    *,
    ext_header: bytes = b"",
) -> bytes:
    """Pack an SNC frame: fixed 0x18 header + optional extension header + GSS token + app data.

    ``eye`` is the 8-byte eye-catcher (``b"SNCFRAME"`` — D-22 resolved).
    ``ext_header`` is the pre-built extension header bytes for the first FR_INIT (D-24);
    empty for all other frame types. ``hdrlen`` in the fixed header reflects its presence.
    """
    hdrlen = _SNC_HEADER_SIZE + len(ext_header)
    header = _SNC_HDR.pack(
        eye,
        frame_type,
        _SNC_VERSION,
        hdrlen,
        len(gss_token),
        len(app_data),
        ctx_id,
        qop,
    )
    return header + ext_header + gss_token + app_data


def parse_snc_frame(buf: bytes) -> tuple[int, int, int, bytes, bytes]:
    """Split an SNC frame into (frame_type, ctx_id, qop, gss_token, app_data).

    Extension headers (hdrlen > 0x18) are skipped: the GSS token starts at
    ``hdrlen`` bytes from the start of the frame, not at 0x18 (D-24).

    Rejects a declared ``token_len + data_len`` above the 128 MiB cap with
    ``ValueError`` BEFORE slicing (DoS guard, threat T-07-FRAME-DOS).
    """
    (_eye, frame_type, _version, hdrlen, token_len, data_len, ctx_id, qop) = _SNC_HDR.unpack_from(
        buf
    )
    # DoS guard: validate declared lengths BEFORE slicing/allocating.
    if token_len + data_len > _MAX_FRAME_BYTES:
        raise ValueError(
            f"SNC frame payload {token_len + data_len} exceeds cap {_MAX_FRAME_BYTES} (DoS guard)"
        )
    # hdrlen counts from the start of the frame, the 8-byte eye-catcher included: 0x18
    # for the plain header, larger when an extension header follows (the reference
    # client's first INIT frame carries the partner-name extension; golden fixture
    # snc/snc_frame_headers.json). The GSS token starts at hdrlen.
    token_start = hdrlen if hdrlen >= _SNC_HEADER_SIZE else _SNC_HEADER_SIZE
    data_start = token_start + token_len
    gss_token = buf[token_start:data_start]
    app_data = buf[data_start : data_start + data_len]
    return frame_type, ctx_id, qop, gss_token, app_data


# --- GSS-API ctypes binding (D-06) -------------------------------------------
# Mirrors SAP's dlopen(SNC_LIB) + resolve-exactly-6-function-pointers pattern.
# GSS crypto is delegated wholesale to the user-supplied .so — no reimplementation.
#
# ctypes types (RFC 2744 C bindings, verified against libgssapi_krb5.so.2):
OM_uint32 = ctypes.c_uint32  # RFC 2744: OM_uint32 is 32-bit
gss_ctx_id_t = ctypes.c_void_p  # opaque context handle (pointer)
gss_cred_id_t = ctypes.c_void_p
gss_name_t = ctypes.c_void_p


class gss_buffer_desc(ctypes.Structure):
    # RFC 2744 §3.2: { size_t length; void *value; }
    _fields_ = [("length", ctypes.c_size_t), ("value", ctypes.c_void_p)]


gss_buffer_t = ctypes.POINTER(gss_buffer_desc)


class gss_OID_desc(ctypes.Structure):
    # RFC 2744 §3.1: { OM_uint32 length; void *elements; }
    _fields_ = [("length", OM_uint32), ("elements", ctypes.c_void_p)]


gss_OID = ctypes.POINTER(gss_OID_desc)

# GSS status / flag constants (RFC 2744).
GSS_S_COMPLETE = 0
GSS_S_CONTINUE_NEEDED = 1  # supplementary bit: "call me again"
GSS_C_INITIATE = 1  # cred usage: initiator (client)
GSS_C_MUTUAL_FLAG = 2
GSS_C_INTEG_FLAG = 0x20
GSS_C_CONF_FLAG = 0x10

# The 6 required GSS functions (D-06) + the 4 helpers GssBinding resolves.
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


def _load_snc_lib(path: str) -> ctypes.CDLL:
    """Load the SNC .so and set argtypes/restype for the 6 GSS fns + 4 helpers.

    Mirrors SAP's ``dlopen(SNC_LIB)`` then resolve-function-pointers (D-06). The
    resulting :class:`ctypes.CDLL` is provider-agnostic (D-07): CommonCryptoLib
    (X.509), libgssapi_krb5.so (Kerberos), or any GSSAPI-compliant library.
    """
    lib = ctypes.CDLL(path)  # mirrors SAP dlopen(SNC_LIB) — D-06

    lib.gss_import_name.restype = OM_uint32
    lib.gss_import_name.argtypes = [
        ctypes.POINTER(OM_uint32),  # minor_status
        gss_buffer_t,  # input_name_buffer (the partnername)
        gss_OID,  # input_name_type
        ctypes.POINTER(gss_name_t),  # output_name
    ]
    lib.gss_acquire_cred.restype = OM_uint32
    lib.gss_acquire_cred.argtypes = [
        ctypes.POINTER(OM_uint32),  # minor_status
        gss_name_t,  # desired_name (or GSS_C_NO_NAME)
        OM_uint32,  # time_req
        gss_OID,  # desired_mechs
        OM_uint32,  # cred_usage = GSS_C_INITIATE
        ctypes.POINTER(gss_cred_id_t),  # output_cred
        ctypes.c_void_p,  # actual_mechs (NULL ok)
        ctypes.POINTER(OM_uint32),  # time_rec (NULL ok)
    ]
    lib.gss_init_sec_context.restype = OM_uint32
    lib.gss_init_sec_context.argtypes = [
        ctypes.POINTER(OM_uint32),  # minor_status
        gss_cred_id_t,  # claimant_cred
        ctypes.POINTER(gss_ctx_id_t),  # context_handle (in/out)
        gss_name_t,  # target_name (partner)
        gss_OID,  # mech_type
        OM_uint32,  # req_flags
        OM_uint32,  # time_req
        ctypes.c_void_p,  # input_chan_bindings (NULL)
        gss_buffer_t,  # input_token
        ctypes.POINTER(gss_OID),  # actual_mech_type (out)
        gss_buffer_t,  # output_token
        ctypes.POINTER(OM_uint32),  # ret_flags
        ctypes.POINTER(OM_uint32),  # time_rec
    ]
    lib.gss_accept_sec_context.restype = OM_uint32
    lib.gss_accept_sec_context.argtypes = [
        ctypes.POINTER(OM_uint32),  # minor_status
        ctypes.POINTER(gss_ctx_id_t),  # context_handle (in/out)
        gss_cred_id_t,  # acceptor_cred
        gss_buffer_t,  # input_token
        ctypes.c_void_p,  # input_chan_bindings (NULL)
        ctypes.POINTER(gss_name_t),  # src_name (out)
        ctypes.POINTER(gss_OID),  # mech_type (out)
        gss_buffer_t,  # output_token
        ctypes.POINTER(OM_uint32),  # ret_flags
        ctypes.POINTER(OM_uint32),  # time_rec
        ctypes.POINTER(gss_cred_id_t),  # delegated_cred (out)
    ]
    lib.gss_wrap.restype = OM_uint32
    lib.gss_wrap.argtypes = [
        ctypes.POINTER(OM_uint32),  # minor_status
        gss_ctx_id_t,  # context_handle
        ctypes.c_int,  # conf_req_flag (1 = privacy)
        OM_uint32,  # qop_req
        gss_buffer_t,  # input_message
        ctypes.POINTER(ctypes.c_int),  # conf_state (out)
        gss_buffer_t,  # output_message (must release)
    ]
    lib.gss_unwrap.restype = OM_uint32
    lib.gss_unwrap.argtypes = [
        ctypes.POINTER(OM_uint32),  # minor_status
        gss_ctx_id_t,  # context_handle
        gss_buffer_t,  # input_message
        gss_buffer_t,  # output_message (must release)
        ctypes.POINTER(ctypes.c_int),  # conf_state (out)
        ctypes.POINTER(OM_uint32),  # qop_state (out)
    ]
    lib.gss_get_mic.restype = OM_uint32
    lib.gss_get_mic.argtypes = [
        ctypes.POINTER(OM_uint32),  # minor_status
        gss_ctx_id_t,  # context_handle
        OM_uint32,  # qop_req
        gss_buffer_t,  # message
        gss_buffer_t,  # msg_token (out, must release)
    ]
    lib.gss_verify_mic.restype = OM_uint32
    lib.gss_verify_mic.argtypes = [
        ctypes.POINTER(OM_uint32),  # minor_status
        gss_ctx_id_t,  # context_handle
        gss_buffer_t,  # message
        gss_buffer_t,  # msg_token
        ctypes.POINTER(OM_uint32),  # qop_state (out)
    ]
    lib.gss_release_buffer.restype = OM_uint32
    lib.gss_release_buffer.argtypes = [ctypes.POINTER(OM_uint32), gss_buffer_t]
    lib.gss_release_name.restype = OM_uint32
    lib.gss_release_name.argtypes = [ctypes.POINTER(OM_uint32), ctypes.POINTER(gss_name_t)]
    return lib


class GssBinding:
    """Per-connection GSS-API binding over a user-supplied SNC library (D-06).

    Loads the .so via the injectable ``loader`` (default :func:`_load_snc_lib`,
    which calls ``ctypes.CDLL``), resolves the 6 required GSS functions plus the
    4 helpers, acquires an initiator credential, and imports the (quote-stripped,
    D-14) partner name. The GSS security context itself is established later,
    during the handshake in plan 07-P02; here ``self._ctx`` is initialised to None.

    The ``loader`` seam lets tests inject a MockGssLib double so the offline suite
    needs no real .so. When the loaded lib is a real :class:`ctypes.CDLL`, GSS
    calls use the ctypes calling convention (out-params via pointers); when it is
    a duck-typed double, calls pass Python-level arguments and read a
    ``(major, minor)`` tuple return.

    Security (threat T-07-CRED): the ``snc_lib`` path, ``snc_myname``,
    ``snc_partnername``, GSS tokens, and name/credential bytes NEVER enter a log,
    a repr, or an exception. Failures raise :class:`SncError` with GSS
    major/minor status codes only.
    """

    def __init__(
        self,
        *,
        snc_lib: str,
        snc_partnername: str,
        snc_myname: str | None = None,
        snc_qop: int = 3,
        loader: Any = _load_snc_lib,
    ) -> None:
        # D-09: use snc_lib; fall back to the SNC_LIB env var if the arg is
        # falsy. NO multi-lib probing — the user provides an explicit path.
        resolved_path = snc_lib or os.environ.get("SNC_LIB")
        if not resolved_path:
            # Note: do NOT echo any path here (T-07-CRED).
            raise SncError("no SNC library path configured")

        # D-14: strip enclosing double-quotes SAP env may add, then strip the
        # SAP SNC type prefix ("p:", "u:", "s:"): the GSS library is given the bare
        # X.500 DN; the prefix is a SAP-level convention only (behavioural:
        # CommonCryptoLib accepted the bare DN in every live snc_lib logon).
        self._partnername = _strip_snc_prefix(_strip_quotes(snc_partnername))
        self._myname = (
            _strip_snc_prefix(_strip_quotes(snc_myname)) if snc_myname is not None else None
        )
        self._qop = validate_snc_qop(snc_qop)

        # Load the lib (D-06). Kept in a local first so a failing load never
        # leaves a half-initialised binding.
        lib = loader(resolved_path)
        self._lib = lib
        self._real = isinstance(lib, ctypes.CDLL)
        self._ctx: Any = None  # context handle — filled during P02 handshake
        self._cred = None
        self._target_name = None

        # D-10 order: acquire initiator credential, then import partner name.
        self._cred = self._acquire_cred()
        self._target_name = self._import_name(self._partnername)

    # -- GSS call wrappers ---------------------------------------------------

    def _acquire_cred(self) -> Any:
        """Acquire an initiator (client) credential — GSS_C_INITIATE (D-10)."""
        if self._real:
            minor = OM_uint32(0)
            cred = gss_cred_id_t()
            major = self._lib.gss_acquire_cred(
                ctypes.byref(minor),
                None,  # desired_name = GSS_C_NO_NAME
                0,  # time_req
                None,  # desired_mechs = GSS_C_NO_OID_SET
                GSS_C_INITIATE,  # cred_usage (client)
                ctypes.byref(cred),
                None,  # actual_mechs
                None,  # time_rec
            )
            self._check(major, minor.value)
            return cred
        # Duck-typed mock path: pass cred_usage; read (major, minor) tuple.
        major, minor = self._lib.gss_acquire_cred(GSS_C_INITIATE)
        self._check(major, minor)
        return object()  # opaque credential placeholder for the mock path

    def _import_name(self, name: str) -> Any:
        """Import the (quote-stripped) partner name into a gss_name_t (D-14)."""
        if self._real:
            minor = OM_uint32(0)
            name_bytes = name.encode("utf-8")
            buf = gss_buffer_desc()
            buf.length = len(name_bytes)
            buf.value = ctypes.cast(
                ctypes.create_string_buffer(name_bytes, len(name_bytes)),
                ctypes.c_void_p,
            )
            out_name = gss_name_t()
            major = self._lib.gss_import_name(
                ctypes.byref(minor),
                ctypes.byref(buf),
                None,  # input_name_type
                ctypes.byref(out_name),
            )
            self._check(major, minor.value)
            return out_name
        # Duck-typed mock path: pass the Python string; read (major, minor).
        major, minor = self._lib.gss_import_name(name=name)
        self._check(major, minor)
        return object()  # opaque name placeholder for the mock path

    # -- GSS handshake + data-protection wrappers ----------------------------
    #
    # Each wrapper returns a value the P02 SncTransport consumes. On the real
    # ctypes path they marshal out-params via pointers and copy+release every
    # mech-allocated output buffer (Pitfall 6 / threat T-07-BUFFER-LEAK); on the
    # duck-typed mock path they pass Python-level kwargs and read a
    # ``(major, minor, out_bytes)`` (or ``(major, minor)``) tuple return.

    def init_sec_context(self, input_token: bytes) -> tuple[int, bytes]:
        """One GSS init step. Returns ``(major, output_token)``.

        ``input_token`` is the server's previous FR_ACCEPT token (empty on the
        first call → GSS_C_NO_BUFFER). The context handle in ``self._ctx`` is
        carried across calls (in/out), per RFC 2744.
        """
        if self._real:
            minor = OM_uint32(0)
            if self._ctx is None:
                self._ctx = gss_ctx_id_t()
            in_buf = gss_buffer_desc()
            if input_token:
                in_buf.length = len(input_token)
                in_buf.value = ctypes.cast(
                    ctypes.create_string_buffer(input_token, len(input_token)),
                    ctypes.c_void_p,
                )
            out_buf = gss_buffer_desc()
            req_flags = GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG
            major = self._lib.gss_init_sec_context(
                ctypes.byref(minor),
                self._cred,
                ctypes.byref(self._ctx),
                self._target_name,
                None,  # mech_type = default
                req_flags,
                0,  # time_req
                None,  # input_chan_bindings
                ctypes.byref(in_buf) if input_token else None,
                None,  # actual_mech_type
                ctypes.byref(out_buf),
                None,  # ret_flags
                None,  # time_rec
            )
            out_token = self._release(out_buf)
            self._check(major, minor.value)
            return major, out_token
        # Duck-typed mock path: (major, minor, out_token).
        major, minor, out_token = self._lib.gss_init_sec_context(input_token=input_token)
        self._check(major, minor)
        return major, out_token

    def wrap(self, payload: bytes) -> bytes:
        """gss_wrap for privacy (QOP 3). Returns the wrapped token bytes."""
        if self._real:
            minor = OM_uint32(0)
            in_buf = gss_buffer_desc()
            in_buf.length = len(payload)
            in_buf.value = ctypes.cast(
                ctypes.create_string_buffer(payload, len(payload)), ctypes.c_void_p
            )
            out_buf = gss_buffer_desc()
            conf_state = ctypes.c_int(0)
            major = self._lib.gss_wrap(
                ctypes.byref(minor),
                self._ctx,
                1,  # conf_req_flag = 1 (privacy)
                0,  # qop_req = default
                ctypes.byref(in_buf),
                ctypes.byref(conf_state),
                ctypes.byref(out_buf),
            )
            wrapped = self._release(out_buf)
            self._check(major, minor.value)
            return wrapped
        major, minor, wrapped = self._lib.gss_wrap(payload=payload)
        self._check(major, minor)
        return cast(bytes, wrapped)

    def unwrap(self, token: bytes) -> bytes:
        """gss_unwrap for privacy (QOP 3). Returns the recovered payload bytes."""
        if self._real:
            minor = OM_uint32(0)
            in_buf = gss_buffer_desc()
            in_buf.length = len(token)
            in_buf.value = ctypes.cast(
                ctypes.create_string_buffer(token, len(token)), ctypes.c_void_p
            )
            out_buf = gss_buffer_desc()
            conf_state = ctypes.c_int(0)
            qop_state = OM_uint32(0)
            major = self._lib.gss_unwrap(
                ctypes.byref(minor),
                self._ctx,
                ctypes.byref(in_buf),
                ctypes.byref(out_buf),
                ctypes.byref(conf_state),
                ctypes.byref(qop_state),
            )
            recovered = self._release(out_buf)
            self._check(major, minor.value)
            return recovered
        major, minor, recovered = self._lib.gss_unwrap(token=token)
        self._check(major, minor)
        return cast(bytes, recovered)

    def get_mic(self, payload: bytes) -> bytes:
        """gss_get_mic for integrity (QOP 2). Returns the MIC token bytes."""
        if self._real:
            minor = OM_uint32(0)
            in_buf = gss_buffer_desc()
            in_buf.length = len(payload)
            in_buf.value = ctypes.cast(
                ctypes.create_string_buffer(payload, len(payload)), ctypes.c_void_p
            )
            out_buf = gss_buffer_desc()
            major = self._lib.gss_get_mic(
                ctypes.byref(minor),
                self._ctx,
                0,  # qop_req = default
                ctypes.byref(in_buf),
                ctypes.byref(out_buf),
            )
            mic = self._release(out_buf)
            self._check(major, minor.value)
            return mic
        major, minor, mic = self._lib.gss_get_mic(payload=payload)
        self._check(major, minor)
        return cast(bytes, mic)

    def verify_mic(self, payload: bytes, mic: bytes) -> None:
        """gss_verify_mic for integrity (QOP 2). Raises SncError on mismatch."""
        if self._real:
            minor = OM_uint32(0)
            msg_buf = gss_buffer_desc()
            msg_buf.length = len(payload)
            msg_buf.value = ctypes.cast(
                ctypes.create_string_buffer(payload, len(payload)), ctypes.c_void_p
            )
            tok_buf = gss_buffer_desc()
            tok_buf.length = len(mic)
            tok_buf.value = ctypes.cast(ctypes.create_string_buffer(mic, len(mic)), ctypes.c_void_p)
            qop_state = OM_uint32(0)
            major = self._lib.gss_verify_mic(
                ctypes.byref(minor),
                self._ctx,
                ctypes.byref(msg_buf),
                ctypes.byref(tok_buf),
                ctypes.byref(qop_state),
            )
            self._check(major, minor.value)
            return
        major, minor, _ = self._lib.gss_verify_mic(payload=payload, mic=mic)
        self._check(major, minor)

    # -- helpers -------------------------------------------------------------

    def _release(self, buf: gss_buffer_desc) -> bytes:
        """Copy a GSS output buffer to Python bytes, then release it (Pitfall 6).

        Every mech-allocated output buffer leaks if not freed via
        ``gss_release_buffer`` (threat T-07-BUFFER-LEAK). The copy-then-free is
        done in try/finally so the buffer is released even if the copy raises.
        """
        try:
            if not buf.value or buf.length == 0:
                return b""
            return ctypes.string_at(buf.value, buf.length)
        finally:
            minor = OM_uint32(0)
            self._lib.gss_release_buffer(ctypes.byref(minor), ctypes.byref(buf))

    def _check(self, major: int, minor: int) -> None:
        """Raise SncError unless major is COMPLETE or the CONTINUE bit is set.

        Carries GSS major/minor status codes ONLY — never token or credential
        material (threat T-07-CRED).
        """
        if major == GSS_S_COMPLETE or (major & GSS_S_CONTINUE_NEEDED):
            return
        raise SncError(major=major, minor=minor)

    def close(self) -> None:
        """Release the imported name and credential (guards against double-free)."""
        if self._real:
            if self._target_name is not None:
                minor = OM_uint32(0)
                try:
                    self._lib.gss_release_name(ctypes.byref(minor), ctypes.byref(self._target_name))
                except Exception:
                    pass
        # Whether real or mock: clear handles so a second close() is a no-op.
        self._target_name = None
        self._cred = None
        self._ctx = None


def _strip_quotes(value: str) -> str:
    """Strip a single pair of enclosing double-quotes SAP env may add (D-14)."""
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _strip_snc_prefix(value: str) -> str:
    """Strip SAP SNC type prefix before passing to gss_import_name.

    CommonCryptoLib's DName_decode expects a raw X.500 DN string (e.g.
    "CN=A4H, OU=...").  The "p:" / "u:" / "s:" prefixes are SAP-level
    conventions (profile params, STRUST, sapgenpse -n) that are stripped
    before the GSS call in SAP's own RFC code.  Passing "p:CN=..." causes
    DName_decode to fail with GSS_S_BAD_NAME (0x00020000) because "p" is
    not a valid DN attribute type.
    """
    if len(value) >= 2 and value[1] == ":" and value[0].isalpha():
        return value[2:]
    return value


# --- SNC transport wrapper (D-01 / D-04 / D-08) ------------------------------
# SncTransport sits on top of an inner Transport, drives the GSS handshake to
# GSS_S_COMPLETE (D-04), then wraps/unwraps every payload per the negotiated QOP
# (D-08). It duck-types the send_message/recv_message/close seam (it is NOT a
# Transport subclass), exactly like MockTransport — so Connection is transparent.
#
# SEC-06 (T-07-GSS-BEFORE-COMPLETE): no application data is wrapped or sent until
# the handshake reaches COMPLETE. The `_established` gate is set only inside
# _handshake and re-asserted at the top of send_message (belt-and-suspenders).
#
# SEC-04 (T-07-SEC04): at QOP 3 every payload — including the logon TLV carrying
# the scrambled password — is passed through gss_wrap, so the raw payload bytes
# never reach the socket in cleartext. No plain (type 7) frame is emitted at
# QOP >= 3.
#
# D-05 (T-07-EYE-CATCH): a frame from the inner transport whose leading bytes are
# NOT the eye-catcher is passed through unchanged — non-SNC NI traffic must not
# be corrupted.
#
# Security (T-07-CRED): the eye-catcher, GSS tokens, and names are NEVER logged
# or placed in exceptions. SncError carries GSS major/minor only.


class GssMechanism(Protocol):
    """What :class:`SncTransport` needs from a GSS mechanism.

    Implemented by :class:`GssBinding` (a native GSS library over ctypes) and by
    :class:`saprfclib.secgss.SecGssInitiator` (the built-in X.509 mechanism).
    """

    _real: bool
    _lib: Any

    def init_sec_context(self, input_token: bytes) -> tuple[int, bytes]: ...
    def wrap(self, payload: bytes) -> bytes: ...
    def unwrap(self, token: bytes) -> bytes: ...
    def get_mic(self, payload: bytes) -> bytes: ...
    def verify_mic(self, payload: bytes, mic: bytes) -> None: ...
    def close(self) -> None: ...


class SncTransport:
    """SNC transport: drive the GSS handshake, then QOP-dispatch send/recv.

    Wraps an ``inner`` Transport (duck-typed seam). ``__init__`` builds a
    :class:`GssBinding` (or takes an injected one — the test seam) and runs the
    FR_INIT/FR_ACCEPT handshake to COMPLETE before returning; only then is
    ``_established`` set True and data frames unlocked (SEC-06).
    """

    # Same 128 MiB DoS cap as transport.py / parse_snc_frame (T-07-FRAME-DOS).
    _MAX_FRAME_BYTES = _MAX_FRAME_BYTES

    def __init__(
        self,
        inner: Transport,
        *,
        snc_lib: str | None = None,
        snc_partnername: str,
        snc_myname: str | None = None,
        snc_qop: int = 3,
        snc_sso: bool = False,
        gss_binding: GssMechanism | None = None,
        eye_catcher: bytes | None = None,
    ) -> None:
        # snc_sso (log on with the SNC identity) changes only the logon records,
        # which Connection builds; the SNC frames are identical either way (golden
        # fixture snc/snc_logon_tlvs.json). Accepted here for API compatibility.
        del snc_sso
        self._inner = inner
        self._qop = validate_snc_qop(snc_qop)
        self._established = False  # SEC-06 gate; set by _handshake()
        # D-24 (live pyrfc capture): ctx_id=3 in all SNC frames.
        self._ctx_id = _SNC_CTX_ID
        # D-22 RESOLVED: every SNC frame starts with the eye-catcher "SNCFRAME"
        # (golden fixture snc/snc_frame_headers.json). Injectable so tests can override.
        self._eye = eye_catcher or b"SNCFRAME"
        if gss_binding is None:
            if snc_lib is None:
                raise SncError("no SNC mechanism: pass snc_lib or a gss_binding")
            gss_binding = GssBinding(
                snc_lib=snc_lib,
                snc_partnername=snc_partnername,
                snc_myname=snc_myname,
                snc_qop=snc_qop,
            )
        self._gss: GssMechanism = gss_binding
        # Handshake QOP triple (minimum, maximum, in use). snc_qop q in 1..3 asks for
        # min = use = q and max = the maximum available; 8 and 9 both yield 3/3/3.
        # Source: golden fixture snc/snc_frame_headers.json.
        level = _PROTECTION_LEVEL[_QOP_PROTECTION[self._qop]]
        if self._qop in (SncQop.AUTH_ONLY, SncQop.INTEGRITY, SncQop.PRIVACY):
            self._qmin, self._qmax, self._quse = level, _QOP_MAX_AVAILABLE, level
        else:
            self._qmin = self._qmax = self._quse = _QOP_MAX_AVAILABLE
        # D-24: build the 126-byte SNC extension header for the first FR_INIT.
        # _build_snc_ext_header is pure Python — no lib needed.
        _partner_dn = _strip_snc_prefix(_strip_quotes(snc_partnername))
        self._ext_header: bytes = _build_snc_ext_header(_partner_dn)
        # D-24: adapter info string goes as app_data in every FR_INIT frame when a
        # native library is loaded. Empty otherwise: a live server completed the
        # handshake with empty app_data from the built-in mechanism (2026-11-08,
        # tests/golden/snc/secgss_live_handshake.json).
        self._adapter_info: bytes = (
            _get_snc_adapter_info(self._gss._lib) if self._gss._real else b""
        )
        # GW-envelope mode: RFC connections use GW-wrapped SNC frames on port 4800.
        # Set by activate_snc(gw_handle=...) when the GW connection handle is known.
        self._gw_handle: bytes = b"        "
        self._use_gw: bool = False
        # Gateway-assigned connection index echoed at GW header [78:80]. None =
        # not known (connect_snc / tests); the previously hard-coded 9 is used then.
        self._conn_idx: int | None = None
        # Handshake is NOT called here. For RFC connections the GW_CONNECT /
        # GW_INFO / GW_DONE_CLIENT exchange must complete on the plain channel
        # BEFORE the GSS frames go on the wire. Connection._handshake() calls
        # activate_snc() after GW_DONE. connect_snc() callers activate manually.

    # -- handshake (D-04, SEC-06) --------------------------------------------

    def activate_snc(self, gw_handle: bytes | None = None, conn_idx: int | None = None) -> None:
        """Run the GSS handshake; called by Connection after GW_DONE.

        ``gw_handle`` is the 8-byte ASCII handle from GW_CONNECT_RESPONSE
        (payload[40:48]). When provided, SNC frames are wrapped in the
        GW-type-0x06CB envelope (port-4800 / sapgw00s flow). When None,
        frames are sent as raw SNC (direct / test flow).

        Must be called exactly once before any data frames are sent or received.
        """
        if gw_handle is not None:
            self._gw_handle = gw_handle
            self._use_gw = True
        self._conn_idx = conn_idx
        self._handshake()

    # -- GW envelope builder/stripper (port-4800 flow) -----------------------

    def _build_gw_snc_frame(self, snc_frame: bytes, *, handshake: bool = False) -> bytes:
        """Wrap an SNC frame in the 80-byte GW type-0x06CB envelope.

        Source: golden fixture snc/snc_frame_headers.json (reference client):
          [0:2]   06 CB    GW frame type
          [2]     02       version
          [4:6]   FF FF
          [10]    28 on handshake frames, 08 on data frames
          [26:28] 00 08
          [30:32] 05 0C
          [40:48] handle   8-byte ASCII GW conversation id
          [48:52] 00 00 85 00 on handshake frames, zero on data frames
          [76:78] FF FF
          [78:80] BE16 connection index assigned by the gateway's CONNECT reply
          [80:]   SNC frame
          [-8:]   trailer = BE32 len(SNC frame) || 00 00 85 00
        """
        snc_size = len(snc_frame)
        hdr = bytearray(80)
        hdr[0] = 0x06
        hdr[1] = 0xCB
        hdr[2] = 0x02  # version
        struct.pack_into(">H", hdr, 4, 0xFFFF)
        hdr[10] = 0x28 if handshake else 0x08
        struct.pack_into(">H", hdr, 26, 0x0008)
        struct.pack_into(">H", hdr, 30, 0x050C)
        hdr[40:48] = self._gw_handle
        if handshake:
            hdr[48:52] = b"\x00\x00\x85\x00"
        struct.pack_into(">H", hdr, 76, 0xFFFF)
        # Unknown index: keep the value earlier releases sent (accepted by gateways).
        struct.pack_into(">H", hdr, 78, 9 if self._conn_idx is None else self._conn_idx)
        trailer = struct.pack(">I", snc_size) + b"\x00\x00\x85\x00"
        return bytes(hdr) + snc_frame + trailer

    def _strip_gw_snc_frame(self, raw: bytes) -> bytes:
        """Strip the 80-byte GW header; return the SNC frame bytes.

        Server frames carry GW_HDR(80B) + SNC_FRAME without a trailing size tag
        (D-24: confirmed from live capture — server does not append the 8-byte
        trailer that the client adds in _build_gw_snc_frame). parse_snc_frame
        reads exactly hdrlen+toklen+datalen bytes and ignores any suffix, so
        returning raw[80:] is safe for both cases.
        """
        if len(raw) < 80 + _SNC_HEADER_SIZE:
            raise CommunicationError(f"GW-wrapped SNC frame too short: {len(raw)} bytes")
        return raw[80:]

    def _handshake(self) -> None:
        """Drive FR_INIT/FR_ACCEPT until GSS_S_COMPLETE (RESEARCH Pattern 2).

        D-24: first FR_INIT carries the extension header + adapter info.
        Subsequent FR_INIT rounds omit the extension header but keep adapter info.
        Every FR_INIT carries the current (min, max, use) QOP triple. When the
        server's FR_ACCEPT announces a minimum above the level in use, the level is
        raised to it — a server configured for privacy only therefore gets privacy
        even from a client that asked for less (golden fixture
        snc/snc_frame_headers.json, snc_qop 1 and 2).

        A GSS output token is sent whenever its length > 0, even on the final
        COMPLETE step. Data frames stay locked until ``_established`` is set.
        """
        input_token = b""  # first call: GSS_C_NO_BUFFER
        first_round = True
        while True:
            major, out_token = self._gss.init_sec_context(input_token)
            if out_token:
                self._send_snc_frame(
                    SncFrameType.FR_INIT,
                    gss_token=out_token,
                    app_data=self._adapter_info,
                    ext_header=self._ext_header if first_round else b"",
                    qop=_qop_field(self._qmin, self._qmax, self._quse),
                    handshake=True,
                )
                first_round = False
            if major == GSS_S_COMPLETE:
                if out_token:
                    # The acceptor still has to consume our last token; it confirms
                    # with an empty ACCEPT_ACK frame, and the gateway refuses data
                    # sent before that frame was read ("SEND_DATA in state
                    # RECEIVE_WAIT_FOR_DATA"). Source: live capture 2026-11-10.
                    ft, _ctx, _qop, token, app = self._recv_snc_frame()
                    if ft != int(SncFrameType.FR_ACCEPT_ACK) or token or app:
                        raise SncError("SNC partner did not acknowledge the handshake")
                self._established = True  # SEC-06: only now may data be wrapped
                break
            if not (major & GSS_S_CONTINUE_NEEDED):
                # Hard GSS error — carry status codes only (T-07-CRED).
                raise SncError(major=major)
            ft, _ctx, qop, token, _app = self._recv_snc_frame()
            if ft != int(SncFrameType.FR_ACCEPT):
                raise SncError("SNC partner did not accept the handshake")
            self._apply_partner_qop(qop)
            input_token = token

    def _apply_partner_qop(self, field: int) -> None:
        pmin, pmax, puse = _qop_unpack(field)
        if not 1 <= pmin <= puse <= pmax:
            raise SncError("SNC partner sent an invalid protection level")
        if pmin > self._quse:
            self._quse = pmin
            self._qmax = max(self._qmax, pmin)

    # -- frame I/O over the inner transport ----------------------------------

    def _send_snc_frame(
        self,
        frame_type: SncFrameType,
        *,
        gss_token: bytes = b"",
        app_data: bytes = b"",
        ext_header: bytes = b"",
        qop: int = 0,
        handshake: bool = False,
    ) -> None:
        # Data frames carry 0 in the QOP field; only handshake frames carry levels.
        frame = build_snc_frame(
            self._eye,
            int(frame_type),
            self._ctx_id,
            qop,
            gss_token,
            app_data,
            ext_header=ext_header,
        )
        wire = self._build_gw_snc_frame(frame, handshake=handshake) if self._use_gw else frame
        try:
            self._inner.send_message(wire)
        except (OSError, EOFError) as exc:
            raise CommunicationError(str(exc), original_exception=exc) from exc

    def _recv_snc_frame(self) -> tuple[int, int, int, bytes, bytes]:
        try:
            raw = self._inner.recv_message()
        except (OSError, EOFError) as exc:
            raise CommunicationError(str(exc), original_exception=exc) from exc
        snc_raw = self._strip_gw_snc_frame(raw) if self._use_gw else raw
        return parse_snc_frame(snc_raw)

    # -- data path (D-08 QOP dispatch, D-05 passthrough) ---------------------

    def send_message(self, payload: bytes) -> None:
        """Wrap ``payload`` per the negotiated QOP and send one SNC frame.

        Before activate_snc() is called the channel is in passthrough mode so
        that GW_CONNECT / GW_INFO / GW_DONE_CLIENT frames reach the gateway
        unmodified (SEC-06: encryption begins only after GSS COMPLETE).
        """
        if not self._established:
            self._inner.send_message(payload)
            return
        # Table lookup, not a comparison chain: an unrecognised value must not be
        # able to reach the unprotected branch. The level in use is 1, 2 or 3 —
        # set in the constructor and only ever raised by the handshake.
        protection = _LEVEL_PROTECTION[self._quse]
        if protection is SncFrameType.PRIVACY:
            # gss_wrap → PRIVACY (type 9). Encrypted token goes in the gss_token
            # field (token_len), not app_data — confirmed from proxy capture
            # (PRIVACY frame has token_len=320, data_len=0). SEC-04.
            wrapped = self._gss.wrap(payload)
            self._send_snc_frame(SncFrameType.PRIVACY, gss_token=wrapped)
        elif protection is SncFrameType.INTEGRITY:
            # gss_get_mic → INTEGRITY (type 8), payload followed by MIC.
            mic = self._gss.get_mic(payload)
            self._send_snc_frame(SncFrameType.INTEGRITY, gss_token=mic, app_data=payload)
        else:
            # QOP 1 only: PLAIN (type 7), no data protection.
            self._send_snc_frame(SncFrameType.PLAIN, app_data=payload)

    def send_chunked(self, payload: bytes, chunk_size: int) -> None:
        """Send a large request as several protected chunks (GW-envelope mode).

        The reference client splits a request whose TLV stream exceeds the
        gateway's frame limit into ``chunk_size`` pieces, protects each piece as its
        own SNC data frame and sends it in a GW frame of type 0x0608 — [24:32] zero,
        [48:52] the SNC frame's length, no trailer — then an 80-byte header-only
        frame of type 0x0609 with byte 10 = 0, [28:32] = 0x00000100 and
        [48:52] = 00 00 85 00. Source: golden fixture framing/multiframe_request_snc.
        """
        if not self._established or not self._use_gw:
            raise SncError("chunked send requires an established GW-envelope SNC channel")
        for i in range(0, len(payload), chunk_size):
            frame = self._protect(payload[i : i + chunk_size])
            hdr = bytearray(self._build_gw_snc_frame(frame)[:80])
            struct.pack_into(">H", hdr, 0, 0x0608)
            hdr[24:32] = bytes(8)
            struct.pack_into(">I", hdr, 48, len(frame))
            self._send_raw(bytes(hdr) + frame)
        end = bytearray(self._build_gw_snc_frame(b"")[:80])
        struct.pack_into(">H", end, 0, 0x0609)
        end[10] = 0
        end[24:28] = bytes(4)
        struct.pack_into(">I", end, 28, 0x100)
        end[48:52] = b"\x00\x00\x85\x00"
        self._send_raw(bytes(end))

    def _protect(self, payload: bytes) -> bytes:
        """Protect ``payload`` at the level in use; return the SNC frame (no envelope)."""
        protection = _LEVEL_PROTECTION[self._quse]
        if protection is SncFrameType.PRIVACY:
            return build_snc_frame(
                self._eye, int(protection), self._ctx_id, 0, self._gss.wrap(payload)
            )
        if protection is SncFrameType.INTEGRITY:
            return build_snc_frame(
                self._eye, int(protection), self._ctx_id, 0, self._gss.get_mic(payload), payload
            )
        return build_snc_frame(self._eye, int(protection), self._ctx_id, 0, b"", payload)

    def _send_raw(self, wire: bytes) -> None:
        try:
            self._inner.send_message(wire)
        except (OSError, EOFError) as exc:
            raise CommunicationError(str(exc), original_exception=exc) from exc

    def recv_message(self) -> bytes:
        """Receive one frame; passthrough non-SNC frames, else QOP-dispatch."""
        try:
            raw = self._inner.recv_message()
        except (OSError, EOFError) as exc:
            raise CommunicationError(str(exc), original_exception=exc) from exc
        if not self._established:
            return raw
        if self._use_gw:
            # GW-envelope mode: all established-path frames are GW-wrapped SNC.
            snc_raw = self._strip_gw_snc_frame(raw)
        else:
            # D-05: direct SNC — a frame not starting with the eye-catcher is
            # non-SNC NI traffic; return it unchanged (must not be corrupted).
            if raw[: len(self._eye)] != self._eye:
                return raw
            snc_raw = raw
        # parse_snc_frame enforces the 128 MiB DoS cap.
        frame_type, _ctx, _qop, gss_token, app_data = parse_snc_frame(snc_raw)
        level = _FRAME_LEVEL.get(frame_type)
        if level is None:
            raise SncError(f"unexpected SNC frame type {frame_type} on an established channel")
        if level < self._qmin:
            # Never accept less protection than this side's own minimum: a frame
            # type is chosen by the sender, so this is where a downgrade is refused.
            raise SncError("SNC frame protected below the required minimum")
        if frame_type == int(SncFrameType.PRIVACY):
            # PRIVACY: encrypted data is in gss_token (token_len field),
            # data_len=0 — confirmed by proxy capture and the SNC output path protocol analysis.
            return self._gss.unwrap(gss_token)
        if frame_type == int(SncFrameType.INTEGRITY):
            self._gss.verify_mic(app_data, gss_token)
            return app_data
        return app_data  # PLAIN (type 7)

    def close(self) -> None:
        """Best-effort release the GSS context, then close the inner transport."""
        try:
            self._gss.close()
        except Exception:
            pass
        self._inner.close()


def connect_snc(
    host: str,
    port: int,
    *,
    snc_lib: str,
    snc_partnername: str,
    snc_myname: str | None = None,
    snc_qop: int = 3,
    snc_sso: bool = False,
    timeout: float = 30,
) -> SncTransport:
    """Open a TCP transport and wrap it in a handshaken :class:`SncTransport`.

    Mirrors :func:`saprfclib.transport.connect_tcp` for the SNC channel: the inner
    TCP transport is established first, then the SNC handshake runs to COMPLETE
    inside :class:`SncTransport.__init__` before this returns (SEC-06).
    """
    inner = connect_tcp(host, port, timeout=timeout)
    t = SncTransport(
        inner,
        snc_lib=snc_lib,
        snc_partnername=snc_partnername,
        snc_myname=snc_myname,
        snc_qop=snc_qop,
        snc_sso=snc_sso,
    )
    t.activate_snc()
    return t
