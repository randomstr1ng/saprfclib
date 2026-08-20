# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — pure-Python SAPCOMPRESS (LZH + LZC) decompressor + SAP LZ4 frame handler.
#
# SAPCOMPRESS is SAP's proprietary row-based compression for the classic RFC TCP path
# (port 3300).  Compression is signalled at the RFCID level in the TLV stream:
#   RFCID 0x0305 (TableContLZ) — table rows compressed with SAPCOMPRESS.
#
# Wire header (8 bytes, prepended by the compressor / the decompressor):
#   [0-3]  LE uint32  uncompressed length
#   [4]    algo byte  bits[3:0]=algo_id (1=LZC, 2=LZH), bits[7:4]=version
#   [5-6]  magic bytes 0x1f 0x9d
#   [7]    config byte (LZC: bit7=block_mode, bits[4:0]=code_len_limit)
#
# LZ4 SAP frame (NgRFC / wRFC WebSocket path, marker byte 0x34 '4'):
#   [0]    0x34 marker
#   [1-4]  LE uint32 uncompressed length
#   [5-8]  LE uint32 compressed length
#   [9..]  LZ4 block data
#
# The LZH/LZC decompressors are ported from pysap (OWASP / Martin Gallo) —
# pure stdlib (struct only). The LZ4 frame handling was derived from observed
# wire behaviour; see docs/protocol/framing.md.
from __future__ import annotations

import struct
from typing import Any

__all__ = [
    "DecompressError",
    "sapcompress_decompress",
    "lz4_block_decompress",
    "sap_lz4_frame_decompress",
]

# ---------------------------------------------------------------------------
# Shared exception
# ---------------------------------------------------------------------------


class DecompressError(Exception):
    """Raised on any decompression failure."""


# ---------------------------------------------------------------------------
# SAPCOMPRESS constants
# ---------------------------------------------------------------------------

_HDR_SIZE = 8
_HDR_MAGIC = b"\x1f\x9d"
_HDR_ALG_LZC = 1
_HDR_ALG_LZH = 2

# LZC
_LZC_MIN_CODE_LEN = 9
_LZC_MAX_CODE_LEN = 16
_LZC_LITERAL_COUNT = 256
_LZC_CODE_END_BLOCK = 256
_LZC_SINGLE_BLOCK = 0
_LZC_MULTI_BLOCK = 1
_LZC_DEFAULT_CODE_LEN_LIMIT = 13

# LZH
_LZH_WINDOW_SIZE = 0x4000
_LZH_MIN_MATCH = 3
_LZH_MAX_MATCH = 258
_LZH_END_BLOCK = 256
_LZH_LIT_LAST = 255
_LZH_LENGTH_FIRST = 257
_LZH_LITLEN_COUNT = 286
_LZH_DIST_COUNT = 30
_LZH_BITLEN_COUNT = 19
_LZH_TREETYPE_STATIC = 1
_LZH_TREETYPE_DYNAMIC = 2

_LZH_LEN_EXTRA = [
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    1,
    1,
    1,
    2,
    2,
    2,
    2,
    3,
    3,
    3,
    3,
    4,
    4,
    4,
    4,
    5,
    5,
    5,
    5,
    0,
    99,
    99,
]
_LZH_DIST_EXTRA = [
    0,
    0,
    0,
    0,
    1,
    1,
    2,
    2,
    3,
    3,
    4,
    4,
    5,
    5,
    6,
    6,
    7,
    7,
    8,
    8,
    9,
    9,
    10,
    10,
    11,
    11,
    12,
    12,
    13,
    13,
]
_LZH_BITLEN_RANKING = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
_LZH_BITLEN_REPEAT_NZ = 16
_LZH_BITLEN_REPEAT_Z3 = 17
_LZH_BITLEN_REPEAT_Z11 = 18

# ---------------------------------------------------------------------------
# I/O primitives
# ---------------------------------------------------------------------------


class _Reader:
    """Byte + LSB-first bit reader."""

    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)
        self._pos = 0
        self._bits = 0
        self._bits_count = 0

    @property
    def bytes_left(self) -> int:
        return len(self._data) - self._pos

    @property
    def bits_left(self) -> int:
        return self.bytes_left * 8 + self._bits_count

    def _read_byte_raw(self) -> int:
        if self._pos >= len(self._data):
            raise DecompressError("unexpected end of compressed data")
        b = self._data[self._pos]
        self._pos += 1
        return b

    def read_byte(self) -> int:
        if self._bits_count != 0:
            raise RuntimeError("pending bit read")
        return self._read_byte_raw()

    def read(self, n: int) -> bytes:
        if self._bits_count != 0:
            raise RuntimeError("pending bit read")
        if self._pos + n > len(self._data):
            raise DecompressError("unexpected end of compressed data")
        chunk = self._data[self._pos : self._pos + n]
        self._pos += n
        return chunk

    def peek_bits(self, n: int) -> int:
        while self._bits_count < n:
            b = self._read_byte_raw()
            self._bits |= b << self._bits_count
            self._bits_count += 8
        return self._bits & ((1 << n) - 1)

    def read_bits(self, n: int) -> int:
        val = self.peek_bits(n)
        self._bits >>= n
        self._bits_count -= n
        return val

    def skip_bits(self, n: int) -> None:
        self.read_bits(n)


class _Writer:
    """Output byte accumulator."""

    def __init__(self) -> None:
        self._buf: bytearray = bytearray()

    @property
    def data(self) -> bytes:
        return bytes(self._buf)

    def write(self, data: bytes | bytearray) -> None:
        self._buf.extend(data)

    def write_byte(self, b: int) -> None:
        self._buf.append(b & 0xFF)


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------


def _parse_header(data: bytes) -> tuple[int, int, int, int]:
    """Return (uncomp_len, algo_id, version, config) from 8-byte SAPCOMPRESS header."""
    if len(data) < _HDR_SIZE:
        raise DecompressError("header truncated")
    uncomp_len = struct.unpack_from("<I", data, 0)[0]
    algo_byte = data[4]
    algo_id = algo_byte & 0x0F
    version = (algo_byte >> 4) & 0x0F
    if bytes(data[5:7]) != _HDR_MAGIC:
        raise DecompressError(f"bad SAPCOMPRESS magic: {data[5:7].hex()}")
    config = data[7]
    return uncomp_len, algo_id, version, config


# ---------------------------------------------------------------------------
# LZC decompressor
# ---------------------------------------------------------------------------


class _LZCDecompress:
    """UNIX-compress-style variable-width LZC decompressor."""

    def __init__(self, data: bytes, compat_mode: bool = False) -> None:
        self._reader = _Reader(data)
        self._writer = _Writer()
        self._compat_mode = compat_mode
        self._block_mode = _LZC_MULTI_BLOCK
        self._code_len_limit = _LZC_DEFAULT_CODE_LEN_LIMIT
        self._code_limit = 1 << _LZC_DEFAULT_CODE_LEN_LIMIT
        self._code_len = _LZC_MIN_CODE_LEN
        self._max_code = (1 << _LZC_MIN_CODE_LEN) - 1
        self._next_free = -1
        self._chunk: _Reader | None = None

    @property
    def _first_seq_code(self) -> int:
        return (
            _LZC_LITERAL_COUNT if self._block_mode == _LZC_SINGLE_BLOCK else _LZC_LITERAL_COUNT + 1
        )

    def _set_code_len(self, n: int) -> None:
        self._code_len = n
        self._max_code = self._code_limit if n == self._code_len_limit else (1 << n) - 1

    def _read_header(self) -> int:
        uncomp_len, algo_id, _, config = _parse_header(self._reader.read(_HDR_SIZE))
        if algo_id != _HDR_ALG_LZC:
            raise DecompressError(f"expected LZC algo (1), got {algo_id}")
        self._block_mode = config >> 7
        limit = config & 0x1F
        if not (_LZC_MIN_CODE_LEN <= limit <= _LZC_MAX_CODE_LEN):
            raise DecompressError(f"code_len_limit {limit} out of range")
        self._code_len_limit = limit
        self._code_limit = 1 << limit
        return uncomp_len

    def _start_chunk(self) -> None:
        n = min(self._code_len, self._reader.bytes_left)
        self._chunk = _Reader(self._reader.read(n)) if n else None

    def _start_block(self) -> None:
        self._next_free = self._first_seq_code
        self._set_code_len(_LZC_MIN_CODE_LEN)
        self._start_chunk()

    def _read_code(self) -> int | None:
        need_chunk = (
            self._chunk is None
            or self._chunk.bits_left < self._code_len
            or self._next_free > self._max_code
        )
        if need_chunk:
            if self._next_free > self._max_code:
                self._set_code_len(self._code_len + 1)
            self._start_chunk()
        if self._chunk is None or self._chunk.bits_left < self._code_len:
            return None
        return self._chunk.read_bits(self._code_len)

    def decompress(self) -> bytes:
        decomp_left = self._read_header()
        self._next_free = self._first_seq_code

        # codes[code] = {base, next, chain_index}
        #   base        = parent code
        #   next        = first char of this code's sequence
        #   chain_index = depth from the terminal literal (1-based)
        codes: dict[int, dict[str, Any]] = {}
        # chain_buf[i] = i-th character of the current sequence (0=terminal literal)
        chain_buf = bytearray(1 << self._code_len_limit)

        prev_code: int | None = None
        prev_cdef: dict[str, Any] | None = None

        self._start_chunk()

        while decomp_left > 0:
            code = self._read_code()
            if self._block_mode == _LZC_MULTI_BLOCK and code == _LZC_CODE_END_BLOCK:
                self._start_block()
                prev_code = None
                prev_cdef = None
                continue
            if code is None:
                if self._compat_mode:
                    break
                raise DecompressError("unexpected end of compressed data")
            if code >= self._code_limit:
                raise DecompressError(f"code {code} >= limit {self._code_limit}")

            chain_len = 0
            if code == prev_code:
                # Same code twice: reuse chain_buf from previous iteration.
                chain_len = (prev_cdef["chain_index"] if prev_cdef else 0) + 1
            elif code < self._next_free:
                # Known code: walk the chain back to the terminal literal.
                resolve = code
                while resolve >= _LZC_LITERAL_COUNT:
                    if resolve >= self._next_free:
                        raise DecompressError(f"unresolvable code {resolve}")
                    cdef = codes.get(resolve)
                    if cdef is None:
                        raise DecompressError(f"missing code entry {resolve}")
                    chain_buf[cdef["chain_index"]] = cdef["next"]
                    chain_len += 1
                    resolve = cdef["base"]
                chain_buf[0] = resolve
                chain_len += 1
            elif code == self._next_free and prev_code is not None:
                # KwKwKw: code equals the next free entry that hasn't been stored yet.
                prev_ci = prev_cdef["chain_index"] if prev_cdef else 0
                chain_buf[prev_ci + 1] = chain_buf[0]
                chain_len = prev_ci + 2
            else:
                raise DecompressError(f"code {code} out of range (next_free={self._next_free})")

            self._writer.write(chain_buf[:chain_len])
            decomp_left -= chain_len

            if prev_code is not None and self._next_free < self._code_limit:
                prev_ci = prev_cdef["chain_index"] if prev_cdef else 0
                codes[self._next_free] = {
                    "base": prev_code,
                    "next": chain_buf[0],
                    "chain_index": prev_ci + 1,
                }
                self._next_free += 1

            prev_code = code
            prev_cdef = codes.get(code)

        return self._writer.data

    @staticmethod
    def decompress_data(data: bytes, compat_mode: bool = False) -> bytes:
        return _LZCDecompress(data, compat_mode).decompress()


# ---------------------------------------------------------------------------
# LZH decompressor (DEFLATE-compatible blocks with SAP header)
# ---------------------------------------------------------------------------


def _reverse_int(value: int, length: int) -> int:
    """Reverse the low `length` bits of value."""
    rev = 0
    for _ in range(length):
        rev = (rev << 1) | (value & 1)
        value >>= 1
    return rev


class _HuffTree:
    """Canonical Huffman decoder (LSB-first bit order)."""

    def __init__(self, nodes: list[dict[str, Any]]) -> None:
        self.nodes = nodes
        self._lookup: tuple[list[int], list[dict[str, Any] | None]] | None = None
        self._max_bits: int | None = None

    def _get_max_bits(self) -> int:
        if self._max_bits is None:
            self._max_bits = max((n["code_length"] for n in self.nodes), default=0)
        return self._max_bits

    def _build_lookup(self) -> None:
        max_bits = self._get_max_bits()
        length_lut: list[int] = [0] * (1 << max_bits)
        node_lut: list[dict[str, Any] | None] = [None] * (1 << max_bits)
        for nd in self.nodes:
            cl = nd["code_length"]
            if cl <= 0:
                continue
            code = nd["code"]
            ext_count = 1 << (max_bits - cl)
            for i in range(ext_count):
                idx = code | (i << cl)
                length_lut[idx] = cl
                node_lut[idx] = nd
        self._lookup = (length_lut, node_lut)

    def read_code(self, reader: _Reader) -> dict[str, Any]:
        if self._lookup is None:
            self._build_lookup()
        max_bits = self._get_max_bits()
        raw = reader.peek_bits(max_bits)
        length_lut, node_lut = self._lookup  # type: ignore[misc]
        nd = node_lut[raw]
        if nd is None:
            raise DecompressError(f"no Huffman node for bit pattern 0x{raw:x}")
        reader.skip_bits(nd["code_length"])
        return nd

    def read_code_two_staged(self, reader: _Reader, first_len: int) -> dict[str, Any]:
        """Peek first_len bits; if unambiguous, use that length; else use full max_bits."""
        if self._lookup is None:
            self._build_lookup()
        max_bits = self._get_max_bits()
        if first_len >= max_bits:
            return self.read_code(reader)
        length_lut, node_lut = self._lookup  # type: ignore[misc]
        raw_short = reader.peek_bits(first_len)
        if length_lut[raw_short] == first_len and node_lut[raw_short] is not None:
            nd = node_lut[raw_short]
        else:
            raw = reader.peek_bits(max_bits)
            nd = node_lut[raw]
        if nd is None:
            raise DecompressError("no Huffman node")
        reader.skip_bits(nd["code_length"])
        return nd

    @staticmethod
    def _assign_codes(nodes: list[dict[str, Any]]) -> None:
        """Assign canonical codes to nodes (modifies in-place)."""
        # Build distribution: dist[length] = count of codes with that length.
        max_len = max((n["code_length"] for n in nodes), default=0)
        dist = [0] * (max_len + 1)
        for n in nodes:
            cl = n["code_length"]
            if cl > 0:
                dist[cl] += 1

        # Compute starting codes per length.
        next_codes = [0] * (max_len + 2)
        code = 0
        for cl in range(1, max_len + 1):
            code = (code + dist[cl - 1]) << 1
            next_codes[cl] = code

        for nd in nodes:
            cl = nd["code_length"]
            if cl > 0:
                nd["code"] = _reverse_int(next_codes[cl], cl)
                next_codes[cl] += 1

    @classmethod
    def from_distribution(cls, dist: list[int]) -> _HuffTree:
        """Build decoder from code-length list (index=symbol, value=code_length)."""
        nodes = [{"value": i, "code": -1, "code_length": cl} for i, cl in enumerate(dist)]
        cls._assign_codes(nodes)
        return cls(nodes)


class _LZHBase:
    """Shared static-tree cache for LZH."""

    _static_litlen: _HuffTree | None = None
    _static_dist: _HuffTree | None = None
    _len_code_map: tuple[bytearray, list[int]] | None = None
    _dist_code_map: tuple[bytearray, list[int]] | None = None

    @classmethod
    def get_static_litlen(cls) -> _HuffTree:
        if cls._static_litlen is None:
            nodes = []
            for c in range(144):
                nodes.append({"value": c, "code": -1, "code_length": 8})
            for c in range(144, 256):
                nodes.append({"value": c, "code": -1, "code_length": 9})
            for c in range(256, 280):
                nodes.append({"value": c, "code": -1, "code_length": 7})
            for c in range(280, 288):
                nodes.append({"value": c, "code": -1, "code_length": 8})
            _HuffTree._assign_codes(nodes)
            cls._static_litlen = _HuffTree(nodes)
        return cls._static_litlen

    @classmethod
    def get_static_dist(cls) -> _HuffTree:
        if cls._static_dist is None:
            nodes = [{"value": c, "code_length": 5, "code": _reverse_int(c, 5)} for c in range(30)]
            cls._static_dist = _HuffTree(nodes)
        return cls._static_dist

    @classmethod
    def get_len_map(cls) -> tuple[bytearray, list[int]]:
        if cls._len_code_map is None:
            lookup = bytearray(259)
            starts = [0] * 29
            length = _LZH_MIN_MATCH
            for code in range(28):
                starts[code] = length
                count = 1 << _LZH_LEN_EXTRA[code]
                for _ in range(count):
                    lookup[length] = code
                    length += 1
            lookup[_LZH_MAX_MATCH] = 28
            starts[28] = _LZH_MAX_MATCH
            cls._len_code_map = (lookup, starts)
        return cls._len_code_map

    @classmethod
    def get_dist_map(cls) -> tuple[bytearray, list[int]]:
        if cls._dist_code_map is None:
            lookup = bytearray(32769)
            starts = [0] * 30
            dist = 1
            for code in range(30):
                starts[code] = dist
                count = 1 << _LZH_DIST_EXTRA[code]
                for _ in range(count):
                    lookup[dist] = code
                    dist += 1
            cls._dist_code_map = (lookup, starts)
        return cls._dist_code_map


class _LZHDecompress(_LZHBase):
    """DEFLATE-style LZH decompressor with SAP 8-byte header + 2-bit noise."""

    def __init__(self, data: bytes) -> None:
        self._reader = _Reader(data)
        self._writer = _Writer()
        self._window = bytearray(_LZH_WINDOW_SIZE)
        self._wpos = 0

    def decompress(self) -> bytes:
        self._read_head()
        while True:
            last = self._reader.read_bits(1)
            btype = self._reader.read_bits(2)
            if btype == _LZH_TREETYPE_STATIC:
                self._read_block(self.get_static_litlen(), self.get_static_dist())
            elif btype == _LZH_TREETYPE_DYNAMIC:
                litlen_tree, dist_tree = self._read_dynamic_trees()
                self._read_block(litlen_tree, dist_tree)
            else:
                raise DecompressError(f"unknown LZH block type {btype}")
            if last:
                break
        return self._writer.data

    def _read_head(self) -> None:
        hdr = self._reader.read(_HDR_SIZE)
        _, algo_id, _, _ = _parse_header(hdr)
        if algo_id != _HDR_ALG_LZH:
            raise DecompressError(f"expected LZH algo (2), got {algo_id}")
        noise = self._reader.read_bits(2)
        if noise:
            self._reader.skip_bits(noise)

    def _read_dynamic_trees(self) -> tuple[_HuffTree, _HuffTree]:
        r = self._reader
        litlen_count = 257 + r.read_bits(5)
        dist_count = 1 + r.read_bits(5)
        bitlen_count = 4 + r.read_bits(4)

        if litlen_count > _LZH_LITLEN_COUNT:
            raise DecompressError(f"litlen_count {litlen_count} > {_LZH_LITLEN_COUNT}")
        if dist_count > _LZH_DIST_COUNT:
            raise DecompressError(f"dist_count {dist_count} > {_LZH_DIST_COUNT}")

        bl_dist = [0] * _LZH_BITLEN_COUNT
        for i in range(bitlen_count):
            bl_dist[_LZH_BITLEN_RANKING[i]] = r.read_bits(3)
        bl_tree = _HuffTree.from_distribution(bl_dist)

        litlen_cl = self._read_encoded_lengths(r, bl_tree, litlen_count)
        dist_cl = self._read_encoded_lengths(r, bl_tree, dist_count)

        return _HuffTree.from_distribution(litlen_cl), _HuffTree.from_distribution(dist_cl)

    @staticmethod
    def _read_encoded_lengths(r: _Reader, bl_tree: _HuffTree, count: int) -> list[int]:
        codes: list[int] = []
        lastlen = 0
        while len(codes) < count:
            nd = bl_tree.read_code(r)
            bl_code = nd["value"]
            if bl_code < 16:
                codes.append(bl_code)
                lastlen = bl_code
            elif bl_code == _LZH_BITLEN_REPEAT_NZ:
                rep = 3 + r.read_bits(2)
                if rep > count - len(codes):
                    raise DecompressError("repeat overflow")
                codes.extend([lastlen] * rep)
            elif bl_code == _LZH_BITLEN_REPEAT_Z3:
                rep = 3 + r.read_bits(3)
                if rep > count - len(codes):
                    raise DecompressError("repeat overflow")
                codes.extend([0] * rep)
                lastlen = 0
            elif bl_code == _LZH_BITLEN_REPEAT_Z11:
                rep = 11 + r.read_bits(7)
                if rep > count - len(codes):
                    raise DecompressError("repeat overflow")
                codes.extend([0] * rep)
                lastlen = 0
            else:
                raise DecompressError(f"unknown bitlen code {bl_code}")
        return codes

    def _read_block(self, litlen_tree: _HuffTree, dist_tree: _HuffTree) -> None:
        r = self._reader
        w = self._writer
        window = self._window
        _, len_starts = self.get_len_map()
        _, dist_starts = self.get_dist_map()

        # Determine end-of-block code length for two-staged read.
        eob_nodes = [
            n for n in litlen_tree.nodes if n["value"] == _LZH_END_BLOCK and n["code_length"] > 0
        ]
        eob_len = eob_nodes[0]["code_length"] if eob_nodes else litlen_tree._get_max_bits()

        while True:
            nd = litlen_tree.read_code_two_staged(r, eob_len)
            val = nd["value"]
            if val <= _LZH_LIT_LAST:
                window[self._wpos] = val
                w.write_byte(val)
                self._wpos = (self._wpos + 1) % _LZH_WINDOW_SIZE
                continue
            if val == _LZH_END_BLOCK:
                break

            # Match: decode length then distance.
            lc = val - _LZH_LENGTH_FIRST
            length = len_starts[lc] + r.read_bits(_LZH_LEN_EXTRA[lc])
            if length > _LZH_MAX_MATCH:
                raise DecompressError(f"match length {length} > {_LZH_MAX_MATCH}")

            dnd = dist_tree.read_code(r)
            dc = dnd["value"]
            distance = dist_starts[dc] + r.read_bits(_LZH_DIST_EXTRA[dc])
            if distance > _LZH_WINDOW_SIZE:
                raise DecompressError(f"distance {distance} > window {_LZH_WINDOW_SIZE}")

            copy_left = length
            src = (self._wpos - distance + _LZH_WINDOW_SIZE) % _LZH_WINDOW_SIZE
            while copy_left > 0:
                # Copy in slices that don't wrap mid-copy.
                wpos = self._wpos
                chunk = min(
                    _LZH_WINDOW_SIZE - max(src, wpos),
                    copy_left,
                )
                for i in range(chunk):
                    window[wpos + i] = window[src + i]
                w.write(window[wpos : wpos + chunk])
                self._wpos = (wpos + chunk) % _LZH_WINDOW_SIZE
                src = (src + chunk) % _LZH_WINDOW_SIZE
                copy_left -= chunk

    @staticmethod
    def decompress_data(data: bytes) -> bytes:
        return _LZHDecompress(data).decompress()


# ---------------------------------------------------------------------------
# Public SAPCOMPRESS API
# ---------------------------------------------------------------------------


def sapcompress_decompress(data: bytes, out_length: int) -> bytes:
    """Decompress SAPCOMPRESS data.

    `data`       — compressed bytes (8-byte header + algorithm payload).
    `out_length` — expected uncompressed length (from RFCID 0x0302 table info
                   or from the header itself at data[0:4]).

    Raises DecompressError on any format or algorithm error.
    """
    if len(data) < _HDR_SIZE:
        raise DecompressError(f"SAPCOMPRESS data too short: {len(data)} bytes")
    try:
        hdr_uncomp, algo_id, _, _ = _parse_header(data)
    except DecompressError:
        raise
    except Exception as exc:
        raise DecompressError(f"header parse error: {exc}") from exc

    if hdr_uncomp != out_length:
        raise DecompressError(f"SAPCOMPRESS header length {hdr_uncomp} != expected {out_length}")

    try:
        if algo_id == _HDR_ALG_LZC:
            result = _LZCDecompress.decompress_data(data, compat_mode=True)
        elif algo_id == _HDR_ALG_LZH:
            result = _LZHDecompress.decompress_data(data)
        else:
            raise DecompressError(f"unknown SAPCOMPRESS algo_id {algo_id}")
    except DecompressError:
        raise
    except Exception as exc:
        raise DecompressError(f"decompression error: {exc}") from exc

    if len(result) != out_length:
        raise DecompressError(f"decompressed {len(result)} bytes, expected {out_length}")
    return result


# ---------------------------------------------------------------------------
# LZ4 block decompressor (pure Python, no frame format)
# ---------------------------------------------------------------------------


def lz4_block_decompress(src: bytes, max_output: int = 0) -> bytes:
    """Decompress an LZ4 block (no frame header/checksum — raw block only).

    `max_output` is advisory only; pass 0 to disable the cap.

    Raises DecompressError on malformed input.
    """
    out = bytearray()
    pos = 0
    n = len(src)

    try:
        while pos < n:
            token = src[pos]
            pos += 1

            # --- Literal length ---
            lit_len = (token >> 4) & 0xF
            if lit_len == 15:
                while pos < n:
                    extra = src[pos]
                    pos += 1
                    lit_len += extra
                    if extra != 255:
                        break

            # --- Literals ---
            if pos + lit_len > n:
                raise DecompressError(f"literal overrun at pos={pos} lit_len={lit_len}")
            out.extend(src[pos : pos + lit_len])
            pos += lit_len

            # --- Last sequence has no match ---
            if pos >= n:
                break

            # --- Match offset (2 bytes LE) ---
            if pos + 2 > n:
                raise DecompressError(f"offset bytes truncated at pos={pos}")
            offset = src[pos] | (src[pos + 1] << 8)
            pos += 2
            if offset == 0:
                raise DecompressError("LZ4 block: match offset 0 is invalid")

            # --- Match length ---
            match_len = (token & 0xF) + 4
            if (token & 0xF) == 15:
                while pos < n:
                    extra = src[pos]
                    pos += 1
                    match_len += extra
                    if extra != 255:
                        break

            # --- Copy match ---
            copy_from = len(out) - offset
            if copy_from < 0:
                raise DecompressError(
                    f"LZ4 block: offset {offset} exceeds output length {len(out)}"
                )
            for i in range(match_len):
                out.append(out[copy_from + i])

    except DecompressError:
        raise
    except Exception as exc:
        raise DecompressError(f"LZ4 block decompression error: {exc}") from exc

    return bytes(out)


# ---------------------------------------------------------------------------
# SAP LZ4 frame decompressor (wRFC / NgRFC WebSocket path)
# ---------------------------------------------------------------------------

_SAP_LZ4_MARKER = 0x34  # ASCII '4' — confirmed by the LZ4 decompressor


def sap_lz4_frame_decompress(data: bytes) -> bytes:
    """Decompress a SAP wRFC LZ4 frame.

    Frame layout (confirmed from NgRfcLZ4Compressor / the LZ4 decompressor):
      [0]    0x34 '4' marker byte
      [1-4]  LE uint32 uncompressed length
      [5-8]  LE uint32 compressed length
      [9..]  LZ4 block data (compressed length bytes)

    Raises DecompressError on any format or decompression error.
    """
    if not data:
        raise DecompressError("empty SAP LZ4 frame")
    if data[0] != _SAP_LZ4_MARKER:
        raise DecompressError(f"SAP LZ4 frame: expected marker 0x34, got 0x{data[0]:02x}")
    if len(data) < 9:
        raise DecompressError(f"SAP LZ4 frame too short: {len(data)} bytes")
    uncomp_len = struct.unpack_from("<I", data, 1)[0]
    comp_len = struct.unpack_from("<I", data, 5)[0]
    if len(data) < 9 + comp_len:
        raise DecompressError(
            f"SAP LZ4 frame truncated: need {9 + comp_len} bytes, have {len(data)}"
        )
    block = data[9 : 9 + comp_len]
    result = lz4_block_decompress(block, max_output=uncomp_len)
    if len(result) != uncomp_len:
        raise DecompressError(f"SAP LZ4 decompressed {len(result)} bytes, expected {uncomp_len}")
    return result
