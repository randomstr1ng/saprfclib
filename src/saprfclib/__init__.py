# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Pure Python SAP RFC protocol implementation — zero native dependencies.

Call any SAP function module from Python with no SAP SDK installed. Supports
direct TCP, SAProuter, message server (load-balanced), SNC (X.509/Kerberos),
and WebSocket RFC (BTP/cloud) connections. Full ABAP type codec, connection
pooling, RFC server, transactional RFC (tRFC/qRFC/bgRFC), async-native API,
and durable sqlite TID/Unit stores included.

Quick start:

    import saprfclib
    conn = saprfclib.connect(ashost="myhost", sysnr="00", client="100",
                          user="USER", passwd="PASS")
    result = conn.call("STFC_CONNECTION", REQUTEXT="Hello SAP")
    conn.close()

Async quick start:

    import saprfclib
    async with await saprfclib.connect_async(ashost="myhost", sysnr="00",
                                          client="100", user="U", passwd="P") as conn:
        result = await conn.call("STFC_CONNECTION", REQUTEXT="Hello")
"""

try:
    from saprfclib._version import __version__
except (
    ImportError
):  # pragma: no cover — _version.py is hatch-vcs generated; may be absent in dev worktrees
    __version__ = "0.0.0.dev0"

from saprfclib.codec import decode, encode
from saprfclib.connection import (
    AsyncConnection,
    CallStats,
    ConnectionMetrics,
    connect,
    connect_async,
)
from saprfclib.exceptions import (
    AbapApplicationError,
    AbapSystemFailure,
    CommunicationError,
    IncompleteDescriptorError,
    PoolTimeoutError,
    RetryExhausted,
    SapRfcError,
    SncError,
    TransactionalError,
    WebSocketError,
)
from saprfclib.language import language_iso_to_sap, language_sap_to_iso
from saprfclib.pool import AsyncConnectionPool, ConnectionPool, PoolMetrics
from saprfclib.server import AsyncRfcServer, RfcServer
from saprfclib.stores import (
    AsyncTidStore,
    AsyncUnitStore,
    InMemoryTidStore,
    InMemoryUnitStore,
    SqliteTidStore,
    SqliteUnitStore,
    TidStore,
    UnitState,
    UnitStore,
)
from saprfclib.trace import RfcTrace
from saprfclib.types import (
    RFC_CHANGING,
    RFC_EXPORT,
    RFC_IMPORT,
    RFC_TABLES,
    FieldDesc,
    FunctionDesc,
    TypeDesc,
)

__all__ = [
    "__version__",
    "encode",
    "decode",
    # Logon language helpers (SDK parity: RfcLanguageIsoToSap / RfcLanguageSapToIso)
    "language_iso_to_sap",
    "language_sap_to_iso",
    # Sync connection
    "connect",
    "ConnectionPool",
    # Async connection + pool + server (Phase 9 / D-08)
    "connect_async",
    "AsyncConnection",
    "CallStats",
    "ConnectionMetrics",
    "RfcTrace",
    "RfcTrace",
    "PoolMetrics",
    "AsyncConnectionPool",
    "AsyncRfcServer",
    # Sync server
    "RfcServer",
    # Exceptions
    "SapRfcError",
    "AbapApplicationError",
    "AbapSystemFailure",
    "CommunicationError",
    "IncompleteDescriptorError",
    "PoolTimeoutError",
    "RetryExhausted",
    "SncError",
    "TransactionalError",
    "WebSocketError",
    # TID / Unit stores — sync protocols + in-memory impls
    "TidStore",
    "UnitStore",
    "UnitState",
    "InMemoryTidStore",
    "InMemoryUnitStore",
    # TID / Unit stores — durable sqlite impls (D-04)
    "SqliteTidStore",
    "SqliteUnitStore",
    # TID / Unit stores — async protocols (D-08)
    "AsyncTidStore",
    "AsyncUnitStore",
    # Types
    "FieldDesc",
    "FunctionDesc",
    "TypeDesc",
    "RFC_IMPORT",
    "RFC_EXPORT",
    "RFC_CHANGING",
    "RFC_TABLES",
]
