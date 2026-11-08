# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""connect_async() for SNC and WebSocket RFC (issue #17), offline.

Those paths run the synchronous connection on one dedicated worker thread. These
tests pin the contract: every operation runs on that one thread, the event loop
stays free while it runs, and close() releases the worker.
"""

import asyncio
import threading
import time

import pytest

import saprfclib
import saprfclib.connection as connmod
from saprfclib.connection import AsyncConnection


class _FakeSync:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.threads: set[int] = {threading.get_ident()}
        self.metrics = object()
        self.sys_id = "A4H"
        self.closed = False

    def _mark(self):
        self.threads.add(threading.get_ident())

    def call(self, name, **params):
        self._mark()
        time.sleep(0.05)
        return {"name": name, **params}

    def ping(self):
        self._mark()
        return True

    def close(self):
        self._mark()
        self.closed = True

    def get_connection_attributes(self):
        return "attrs"

    def call_transactional(self, func_name, *, tid, queue=None, **params):
        self._mark()
        self.tx = (func_name, tid, queue, params)

    def confirm_tid(self, tid):
        self._mark()


@pytest.fixture
def fake(monkeypatch):
    made = []

    def _connect(**kwargs):
        made.append(_FakeSync(**kwargs))
        return made[-1]

    monkeypatch.setattr(connmod, "connect", _connect)
    return made


@pytest.mark.parametrize(
    "kw",
    [
        {"snc_partnername": "p:CN=X", "snc_pse": "x.pse", "snc_pse_pin": "pin"},
        {"snc_partnername": "p:CN=X", "snc_lib": "/x.so"},
        {"wshost": "ws.example", "wsport": 443},
    ],
)
async def test_snc_and_ws_paths_are_served_on_one_worker_thread(fake, kw):
    conn = await saprfclib.connect_async(
        ashost="h", sysnr="00", client="001", user="U", passwd="P", **kw
    )
    assert isinstance(conn, AsyncConnection)
    sync = fake[0]
    for k, v in kw.items():
        assert sync.kwargs[k] == v  # parameters reach the synchronous connect()

    # The loop keeps running while a call is in flight on the worker.
    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.005)

    t = asyncio.create_task(ticker())
    assert await conn.call("STFC", X=1) == {"name": "STFC", "X": 1}
    t.cancel()
    assert ticks > 2

    assert await conn.ping() is True
    await conn.call_transactional("F", tid="T1", queue="Q", A=1)
    assert sync.tx == ("F", "T1", "Q", {"A": 1})
    assert conn.sys_id == "A4H"
    assert conn.get_connection_attributes() == "attrs"
    assert conn.metrics is sync.metrics

    await conn.close()
    assert sync.closed
    # connect, call, ping, call_transactional and close all ran on one thread,
    # which is not the event loop's.
    assert len(sync.threads) == 1
    assert threading.get_ident() not in sync.threads
    with pytest.raises(ValueError, match="closed"):
        await conn.ping()


async def test_async_context_manager_closes(fake):
    async with await saprfclib.connect_async(
        ashost="h", sysnr="00", client="001", snc_partnername="p:CN=X", snc_lib="/x.so"
    ):
        pass
    assert fake[0].closed


async def test_connect_failure_propagates(monkeypatch):
    def _boom(**kwargs):
        raise saprfclib.SncError("handshake failed")

    monkeypatch.setattr(connmod, "connect", _boom)
    with pytest.raises(saprfclib.SncError, match="handshake failed"):
        await saprfclib.connect_async(
            ashost="h", sysnr="00", client="001", snc_partnername="p:CN=X", snc_lib="/x.so"
        )
