# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Cached metadata can be invalidated (#80).

Descriptors live for the life of the process. A function module or a DDIC type
changed and activated in the system afterwards is still encoded with the old
layout, so the caller needs a way to make the next call fetch it again -- for one
function, for a system, and through a pool whose connections other threads hold.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from saprfclib.connection import Connection, _drop_stale_layouts
from saprfclib.metadata import MetadataCache, get_function_desc
from saprfclib.pool import ConnectionPool
from saprfclib.types import FunctionDesc, TypeDesc

from .test_connection import MockTransport, _handshake_responses

GFI_REPLY = Path(__file__).parent / "golden" / "framing" / "gfi_compressed_params_response.bin"


def _desc(name: str) -> FunctionDesc:
    return FunctionDesc(name=name, parameters=[])


# --------------------------------------------------------------------------- #
# MetadataCache
# --------------------------------------------------------------------------- #


def test_invalidate_one_function_leaves_the_others() -> None:
    cache = MetadataCache()
    cache.put("A4H", _desc("Z_A"))
    cache.put("A4H", _desc("Z_B"))
    assert cache.invalidate("z_a") == 1  # case-insensitive, like get()
    assert cache.get("A4H", "Z_A") is None
    assert cache.get("A4H", "Z_B") is not None


def test_invalidate_one_system_leaves_the_others() -> None:
    cache = MetadataCache()
    cache.put("A4H", _desc("Z_A"))
    cache.put("NPL", _desc("Z_A"))
    assert cache.invalidate(sys_id="A4H") == 1
    assert cache.get("A4H", "Z_A") is None
    assert cache.get("NPL", "Z_A") is not None
    assert cache.invalidate("Z_A", sys_id="NPL") == 1
    assert cache.get("NPL", "Z_A") is None


def test_invalidate_everything() -> None:
    cache = MetadataCache()
    cache.put("A4H", _desc("Z_A"))
    cache.put("NPL", _desc("Z_B"))
    assert cache.invalidate() == 2
    assert cache.invalidate() == 0


def test_every_invalidate_moves_the_generation_even_when_nothing_was_cached() -> None:
    cache = MetadataCache()
    before = cache.generation
    cache.invalidate("Z_NOTHING_CACHED", sys_id="A4H")
    # Layout caches on connections depend on it moving, cached function or not.
    assert cache.generation != before


def test_a_fetch_that_overlaps_an_invalidate_is_not_stored() -> None:
    cache = MetadataCache()

    def fetch(name: str) -> FunctionDesc:
        # The function was changed while its old interface was on the wire.
        cache.invalidate(name)
        return _desc(name)

    cache.get_or_fetch("A4H", "Z_A", fetch)
    assert cache.get("A4H", "Z_A") is None


def test_get_function_desc_does_not_store_a_descriptor_fetched_across_an_invalidate() -> None:
    cache = MetadataCache()

    class _Conn:
        sys_id = "A4H"

        def _call_bootstrap(self, name: str) -> FunctionDesc:
            cache.invalidate(name, sys_id="A4H")
            return _desc(name)

    get_function_desc(_Conn(), "Z_A", cache=cache)
    assert cache.get("A4H", "Z_A") is None


# --------------------------------------------------------------------------- #
# Connection
# --------------------------------------------------------------------------- #


def _ready_conn(*responses: bytes, cache: MetadataCache | None = None) -> Connection:
    conn = Connection(MockTransport(_handshake_responses() + list(responses)), metadata_cache=cache)
    conn._handshake(client="001", user="DEVELOPER", passwd="secret")
    return conn


def test_connection_invalidates_only_its_own_system() -> None:
    cache = MetadataCache()
    conn = _ready_conn(cache=cache)
    key = conn._metadata_cache_key
    assert key
    cache.put(key, _desc("Z_A"))
    cache.put("\x00other-system", _desc("Z_A"))

    assert conn.invalidate_metadata("Z_A") == 1
    assert cache.get(key, "Z_A") is None
    assert cache.get("\x00other-system", "Z_A") is not None


def test_a_connection_that_is_not_logged_on_invalidates_nothing_else() -> None:
    cache = MetadataCache()
    cache.put("A4H", _desc("Z_A"))
    conn = Connection(MockTransport([]), metadata_cache=cache)
    assert conn.invalidate_metadata() == 0
    assert cache.get("A4H", "Z_A") is not None


def test_layouts_are_fetched_again_after_an_invalidate() -> None:
    """The per-connection DDIC layout cache follows the shared cache's generation."""
    conn = _ready_conn(GFI_REPLY.read_bytes(), GFI_REPLY.read_bytes(), GFI_REPLY.read_bytes())
    looked_up: list[str] = []

    def struct_bootstrap(tabname: str) -> TypeDesc:
        looked_up.append(tabname)
        return TypeDesc(name=tabname, fields=[], nuc_size=0, uc_size=0)

    conn._call_struct_bootstrap = struct_bootstrap  # type: ignore[method-assign]

    conn._call_bootstrap("BAPI_USER_GET_DETAIL")
    first = len(looked_up)
    assert first, "the captured interface has STRUCTURE parameters"

    conn._call_bootstrap("BAPI_USER_GET_DETAIL")
    assert len(looked_up) == first, "cached layouts are reused"

    conn.invalidate_metadata("BAPI_USER_GET_DETAIL")
    conn._call_bootstrap("BAPI_USER_GET_DETAIL")
    assert len(looked_up) == 2 * first, "after invalidate, every layout is fetched again"


def test_a_shared_cache_reaches_the_layouts_of_every_connection() -> None:
    cache = MetadataCache()
    holder: Any = Connection(MockTransport([]), metadata_cache=cache)
    holder._struct_desc_cache["ZSTRUCT"] = TypeDesc("ZSTRUCT", [], 0, 0)
    other = Connection(MockTransport([]), metadata_cache=cache)
    other.invalidate_metadata()
    _drop_stale_layouts(holder)
    assert holder._struct_desc_cache == {}


# --------------------------------------------------------------------------- #
# Pools
# --------------------------------------------------------------------------- #


def test_pool_invalidate_clears_the_shared_cache() -> None:
    pool = ConnectionPool({}, min_size=0)
    pool._metadata_cache.put("A4H", _desc("Z_A"))
    pool._metadata_cache.put("A4H", _desc("Z_B"))
    assert pool.invalidate_metadata("Z_A") == 1
    assert pool.invalidate_metadata() == 1
    assert pool._metadata_cache.get("A4H", "Z_B") is None


def test_async_pool_invalidate_clears_the_shared_cache() -> None:
    from saprfclib.pool import AsyncConnectionPool

    pool = AsyncConnectionPool({}, min_size=0)
    pool._metadata_cache.put("A4H", _desc("Z_A"))
    assert pool.invalidate_metadata() == 1


# --------------------------------------------------------------------------- #
# The server keeps the version it loaded: pools reset after an invalidate
# --------------------------------------------------------------------------- #
# Live probe (ABAP Platform 2025, docs/protocol/framing.md): after a function
# module's interface was changed and activated, a connection whose session had
# already called it kept running the old version -- a 30-character value was read
# as 20 -- until reset_server_context(); a new connection ran the new one.


class _Conn:
    def __init__(self) -> None:
        self.pings = 0
        self.resets = 0
        self.reset_error: Exception | None = None
        self.closed = False

    def ping(self) -> bool:
        self.pings += 1
        return True

    def reset_server_context(self) -> None:
        self.resets += 1
        if self.reset_error is not None:
            raise self.reset_error

    def close(self) -> None:
        self.closed = True


class _Pool(ConnectionPool):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__({}, min_size=0, max_size=2, **kwargs)

    def _open(self) -> Any:
        return _Conn()


def test_a_pool_resets_each_connection_once_after_an_invalidate() -> None:
    pool = _Pool()
    with pool.acquire() as conn:
        pass
    with pool.acquire() as again:
        assert again is conn
    assert (conn.pings, conn.resets) == (1, 0)

    pool.invalidate_metadata()
    with pool.acquire() as again:
        assert again is conn
    # The reset takes the place of the health check, once.
    assert (conn.pings, conn.resets) == (1, 1)
    with pool.acquire():
        pass
    assert (conn.pings, conn.resets) == (2, 1)


def test_a_connection_opened_after_the_invalidate_is_not_reset() -> None:
    pool = _Pool()
    pool.invalidate_metadata()
    with pool.acquire() as conn:
        pass
    with pool.acquire():
        pass
    assert conn.resets == 0


def test_a_connection_whose_reset_fails_is_discarded_not_lent() -> None:
    pool = _Pool()
    with pool.acquire() as conn:
        pass
    pool.invalidate_metadata("Z_A")
    conn.reset_error = OSError("gone")
    with pool.acquire() as fresh:
        assert fresh is not conn
    assert conn.closed
    assert pool.metrics.discards == 1


def test_an_async_pool_resets_after_an_invalidate() -> None:
    import asyncio

    from saprfclib.pool import AsyncConnectionPool

    class _AConn:
        def __init__(self) -> None:
            self.pings = 0
            self.resets = 0

        async def ping(self) -> bool:
            self.pings += 1
            return True

        async def reset_server_context(self) -> None:
            self.resets += 1

        async def close(self) -> None:
            return None

    class _APool(AsyncConnectionPool):
        async def _open(self) -> Any:
            return _AConn()

    async def main() -> None:
        pool = _APool({}, min_size=0, max_size=1)
        async with pool.acquire() as conn:
            pass
        pool.invalidate_metadata()
        async with pool.acquire():
            pass
        async with pool.acquire():
            pass
        assert (conn.pings, conn.resets) == (1, 1)

    asyncio.run(main())
