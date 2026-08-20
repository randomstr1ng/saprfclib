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
# Only the fixed 0x18 header is implemented. A hdrlen field != 0x18 (extension
# headers, e.g. SSO2) is not reverse-engineered (D-23) and is rejected.
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
from typing import Any, cast

from saprfclib.exceptions import CommunicationError, SncError
from saprfclib.transport import Transport, connect_tcp

__all__ = [
    "build_snc_frame",
    "parse_snc_frame",
    "SncFrameType",
    "SncQop",
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
# QOP bitmask sent in FR_INIT / FR_ACCEPT header during the GSS handshake
# (0x7E = bits 1-6 set = advertise all protection capabilities).
# Data frames (PRIVACY/INTEGRITY/PLAIN) use the user-configured snc_qop instead.
_SNC_HANDSHAKE_QOP = 0x7E

# --- SNC extension header (D-24) — first FR_INIT only ----------------------
# SAP SNC OID 1.3.36.3.1.37.1 in DER tag-length-value form.
_SAP_SNC_OID = b"\x06\x06\x2b\x24\x03\x01\x25\x01"
_SNC_EXT_MAGIC = b"\x00\x00\x00\x01"
_SNC_EXT_FLAGS = b"\x04\x01"

# Known RDN attribute OIDs in DER form (06 03 55 04 XX).
_RDN_OID: dict[str, bytes] = {
    "CN": b"\x06\x03\x55\x04\x03",
    "OU": b"\x06\x03\x55\x04\x0b",
    "O": b"\x06\x03\x55\x04\x0a",
    "C": b"\x06\x03\x55\x04\x06",
    "L": b"\x06\x03\x55\x04\x07",
    "ST": b"\x06\x03\x55\x04\x08",
}


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


def _build_dn_der(dn_str: str) -> bytes:
    """Encode a SAP SNC DN string to X.509 ASN.1 DER (RFC 5280: C first, CN last)."""
    rdns = [r.strip() for r in dn_str.split(",")]
    rdns.reverse()  # RFC 5280 order: outermost (C) first in DER
    parts = bytearray()
    for rdn in rdns:
        attr, _, value = rdn.partition("=")
        attr = attr.strip().upper()
        value = value.strip()
        oid_bytes = _RDN_OID.get(attr)
        if oid_bytes is None:
            raise ValueError(f"Unknown RDN attribute in SNC partner name: {attr!r}")
        atv = oid_bytes + _der_tlv(0x13, value.encode("ascii"))  # PrintableString
        parts += _der_tlv(0x31, _der_tlv(0x30, atv))  # SET{SEQUENCE{ATV}}
    return _der_tlv(0x30, bytes(parts))  # outer SEQUENCE


def _build_snc_ext_header(partner_dn_str: str) -> bytes:
    """Build the SNC extension header for the first FR_INIT frame.

    Format confirmed from live pyrfc SNC capture (D-24):
      [0:4]   magic 00 00 00 01
      [4:6]   remaining length (BE uint16) from byte 6 onward
      [6:8]   ctx_id = 3 (BE uint16)
      [8:10]  flags = 04 01
      [10:12] OID length (BE uint16)
      [12:20] SAP SNC OID (1.3.36.3.1.37.1 in DER tag-length-value)
      [20:24] partner DN DER length (BE uint32)
      [24:]   partner DN in X.509 ASN.1 DER format
    """
    dn_der = _build_dn_der(partner_dn_str)
    remaining = 2 + 2 + 2 + len(_SAP_SNC_OID) + 4 + len(dn_der)
    return (
        _SNC_EXT_MAGIC
        + struct.pack(">H", remaining)
        + struct.pack(">H", _SNC_CTX_ID)
        + _SNC_EXT_FLAGS
        + struct.pack(">H", len(_SAP_SNC_OID))
        + _SAP_SNC_OID
        + struct.pack(">I", len(dn_der))
        + dn_der
    )


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
    PLAIN = 7  # data frame, QOP 1 (authentication only, no protection)
    INTEGRITY = 8  # data frame, QOP 2 (gss_get_mic / gss_verify_mic)
    PRIVACY = 9  # data frame, QOP 3 (gss_wrap / gss_unwrap)


class SncQop(IntEnum):
    """SNC quality-of-protection level (D-08)."""

    AUTH_ONLY = 1
    INTEGRITY = 2
    PRIVACY = 3


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
    # hdrlen=0 means no extension headers; otherwise token starts at hdrlen bytes
    # from the start of the frame (hdrlen includes the 8-byte eye — confirmed by
    # protocol analysis of the SNC frame builder). Standard hdrlen=0x18; extended (SSO2) hdrlen>0x18.
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
        # SAP SNC type prefix ("p:", "u:", "s:") — CommonCryptoLib's DName_decode
        # expects a raw X.500 DN; the prefix is a SAP-level convention only
        # (confirmed protocol analysis of sec1_gss_import_name at).
        self._partnername = _strip_snc_prefix(_strip_quotes(snc_partnername))
        self._myname = (
            _strip_snc_prefix(_strip_quotes(snc_myname)) if snc_myname is not None else None
        )
        self._qop = snc_qop

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
        snc_lib: str,
        snc_partnername: str,
        snc_myname: str | None = None,
        snc_qop: int = 3,
        snc_sso: bool = False,
        gss_binding: GssBinding | None = None,
        eye_catcher: bytes | None = None,
    ) -> None:
        if snc_sso:
            # D-23: SNC SSO2 rides in an extension header (hdrlen > 0x18) whose
            # format is not reverse-engineered. Gate until a live capture.
            raise NotImplementedError(
                "SNC SSO2 extension headers are not reverse-engineered (D-23)"
            )
        self._inner = inner
        self._qop = snc_qop
        self._established = False  # SEC-06 gate; set by _handshake()
        # D-24 (live pyrfc capture): ctx_id=3 in all SNC frames.
        self._ctx_id = _SNC_CTX_ID
        # D-22 RESOLVED (protocol analysis 2026-07-21): snc_eyecatcher global at
        # points to "SNCFRAME\0" at. Injectable so tests can override.
        self._eye = eye_catcher or b"SNCFRAME"
        self._gss = gss_binding or GssBinding(
            snc_lib=snc_lib,
            snc_partnername=snc_partnername,
            snc_myname=snc_myname,
            snc_qop=snc_qop,
        )
        # D-24: build the 126-byte SNC extension header for the first FR_INIT.
        # _build_snc_ext_header is pure Python — no lib needed.
        _partner_dn = _strip_snc_prefix(_strip_quotes(snc_partnername))
        self._ext_header: bytes = _build_snc_ext_header(_partner_dn)
        # D-24: adapter info string goes as app_data in every FR_INIT frame.
        # Empty for mock/test bindings (_real == False) to keep test assertions stable.
        self._adapter_info: bytes = (
            _get_snc_adapter_info(self._gss._lib) if self._gss._real else b""
        )
        # GW-envelope mode: RFC connections use GW-wrapped SNC frames on port 4800.
        # Set by activate_snc(gw_handle=...) when the GW connection handle is known.
        self._gw_handle: bytes = b"        "
        self._use_gw: bool = False
        # Handshake is NOT called here. For RFC connections the GW_CONNECT /
        # GW_INFO / GW_DONE_CLIENT exchange must complete on the plain channel
        # BEFORE the GSS frames go on the wire. Connection._handshake() calls
        # activate_snc() after GW_DONE. connect_snc() callers activate manually.

    # -- handshake (D-04, SEC-06) --------------------------------------------

    def activate_snc(self, gw_handle: bytes | None = None) -> None:
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
        self._handshake()

    # -- GW envelope builder/stripper (port-4800 flow) -----------------------

    def _build_gw_snc_frame(self, snc_frame: bytes) -> bytes:
        """Wrap an SNC frame in the GW type-0x06CB envelope (the SNC output path protocol analysis).

        Layout (all confirmed from proxy capture + protocol analysis of the SNC output path):
          [0:2]   0x06CB   GW frame type
          [2]     0x02     version (from CONV_PROTO+0x17, always 2 in practice)
          [4:6]   0xFFFF   flags high bytes
          [10]    0x28     SNC + encrypted flag bits
          [26:28] LE 0x0800 (from CONV_PROTO; zero-init → 0x0008 in BE view)
          [30:32] LE 0x0C05 (from CONV_PROTO; zero-init → 0x050C in BE view)
          [40:48] handle   8-byte ASCII GW connection handle
          [48:52] LE 0x00850000 → wire bytes 00 00 85 00
          [76:80] FF FF 00 09   RFC_MARKER (hardcoded by the SNC output path)
          [80:]   SNC frame content
          [-8:]   trailer = BE(snc_size) + 00 00 85 00
        """
        snc_size = len(snc_frame)
        hdr = bytearray(80)
        hdr[0] = 0x06
        hdr[1] = 0xCB
        hdr[2] = 0x02  # version
        struct.pack_into(">H", hdr, 4, 0xFFFF)  # flags[4:6]
        hdr[10] = 0x28  # SNC+encrypted
        struct.pack_into("<H", hdr, 26, 0x0800)  # LE 0x0800
        struct.pack_into("<H", hdr, 30, 0x0C05)  # LE 0x0C05
        hdr[40:48] = self._gw_handle  # GW handle
        struct.pack_into("<I", hdr, 48, 0x00850000)  # 00 00 85 00
        # RFC_MARKER [76:80] = FF FF 00 09
        hdr[76] = 0xFF
        hdr[77] = 0xFF
        hdr[78] = 0x00
        hdr[79] = 0x09
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

        D-24: first FR_INIT carries the 126-byte extension header + adapter info.
        Subsequent FR_INIT rounds omit the extension header but keep adapter info.
        All handshake frames use QOP = _SNC_HANDSHAKE_QOP (0x7E capabilities mask),
        not the user-configured data-protection QOP.

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
                    qop=_SNC_HANDSHAKE_QOP,
                )
                first_round = False
            if major == GSS_S_COMPLETE:
                self._established = True  # SEC-06: only now may data be wrapped
                break
            if not (major & GSS_S_CONTINUE_NEEDED):
                # Hard GSS error — carry status codes only (T-07-CRED).
                raise SncError(major=major)
            _ft, _ctx, _qop, token, _app = self._recv_snc_frame()  # FR_ACCEPT
            input_token = token

    # -- frame I/O over the inner transport ----------------------------------

    def _send_snc_frame(
        self,
        frame_type: SncFrameType,
        *,
        gss_token: bytes = b"",
        app_data: bytes = b"",
        ext_header: bytes = b"",
        qop: int | None = None,
    ) -> None:
        effective_qop = qop if qop is not None else self._qop
        frame = build_snc_frame(
            self._eye,
            int(frame_type),
            self._ctx_id,
            effective_qop,
            gss_token,
            app_data,
            ext_header=ext_header,
        )
        wire = self._build_gw_snc_frame(frame) if self._use_gw else frame
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
        if self._qop >= int(SncQop.PRIVACY):
            # QOP 3: gss_wrap → PRIVACY (type 9). Encrypted token goes in the
            # gss_token field (token_len), not app_data — confirmed from proxy
            # capture (PRIVACY frame has token_len=320, data_len=0). SEC-04.
            wrapped = self._gss.wrap(payload)
            self._send_snc_frame(SncFrameType.PRIVACY, gss_token=wrapped)
        elif self._qop == int(SncQop.INTEGRITY):
            # QOP 2: gss_get_mic → INTEGRITY (type 8), payload followed by MIC.
            mic = self._gss.get_mic(payload)
            self._send_snc_frame(SncFrameType.INTEGRITY, gss_token=mic, app_data=payload)
        else:
            # QOP 1: PLAIN (type 7), no data protection.
            self._send_snc_frame(SncFrameType.PLAIN, app_data=payload)

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
        if frame_type == int(SncFrameType.PRIVACY):
            # PRIVACY: encrypted data is in gss_token (token_len field),
            # data_len=0 — confirmed by proxy capture and the SNC output path protocol analysis.
            return self._gss.unwrap(gss_token)
        if frame_type == int(SncFrameType.INTEGRITY):
            self._gss.verify_mic(app_data, gss_token)
            return app_data
        # PLAIN (type 7) or handshake frame leaking through: return app data.
        return app_data

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
