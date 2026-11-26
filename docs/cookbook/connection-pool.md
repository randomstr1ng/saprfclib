# Connection Pool

Use `ConnectionPool` when multiple threads need to share a set of SAP connections.  The pool
pre-warms a minimum number of connections at startup, grows lazily to the configured maximum
under load, and health-checks connections (via `ping()`) before lending them.

## Multi-threaded pool usage

```python
import threading
import saprfclib

# Connection parameters as a dict — same keys as saprfclib.connect().
params = {
    "ashost": "sap-host",
    "sysnr": 0,
    "client": "100",
    "user": "RFC_USER",
    "passwd": "secret",
}

# Create the pool.  min_size connections are opened eagerly at construction;
# the pool grows lazily up to max_size under concurrent demand.
pool = saprfclib.ConnectionPool(params, min_size=2, max_size=10)

def worker(text: str) -> None:
    """Each worker acquires a connection, makes one call, and releases it."""
    # pool.acquire() is a context manager.  The connection is returned to the
    # pool automatically when the with block exits, even on exception.
    with pool.acquire(timeout=30.0) as conn:
        result = conn.call("STFC_CONNECTION", REQUTEXT=text)
        print(f"[{text}] ECHOTEXT={result['ECHOTEXT']!r}")

# Run 5 concurrent threads — the pool serialises access when all connections are busy.
threads = [
    threading.Thread(target=worker, args=(f"msg-{i}",))
    for i in range(5)
]
for t in threads:
    t.start()
for t in threads:
    t.join()

# Close the pool when done: idle connections close now, checked-out ones when released.
pool.close()
```

## Tips

- `timeout` in `pool.acquire(timeout=...)` is the maximum seconds to wait for a free
  connection.  If the pool is exhausted and no connection is returned within the timeout,
  `PoolTimeoutError` is raised.
- `min_size=0` creates a lazy pool: no connections are opened until the first `acquire()`.
- The pool is thread-safe: multiple threads may call `acquire()` concurrently.
- Do not share a single acquired connection across threads — each `with pool.acquire()` block
  owns exactly one connection for its duration.
- Pass `reset_on_release=True` to reset each connection's ABAP session state when it is
  returned, so the next borrower does not inherit function-group globals, buffers or an
  uncommitted LUW from the previous one. It costs one round trip per release; a connection
  whose reset fails is closed instead of lent again. Without it, state carries over between
  borrowers, which is what a stateful sequence across several `acquire()` blocks would need.
- Callers that have to wait are served in the order they arrived. A caller that comes in
  while others are waiting joins the back of the queue; it never takes a released connection
  ahead of them.
- `max_waiters=N` limits that queue. When no connection is free and `N` callers already
  wait, `acquire()` raises `PoolOverloadedError` at once instead of blocking, so overload is
  shed early rather than ending in a `PoolTimeoutError` for everyone queued. `max_waiters=0`
  means never wait. `pool.waiting` and `stats()["waiting"]` show the queue length, and
  `stats()["overloads"]` counts the refusals. Without `max_waiters` the queue is unbounded.
- `pool.close()` does not wait: it closes the idle connections at once, and each
  checked-out connection is closed when it is released. Call it once at application shutdown.

## After a function module changes

Function interfaces are cached for the life of the pool. When a function module, or a
structure or table type it uses, is changed and activated in SAP, call:

```python
pool.invalidate_metadata("Z_MY_FUNCTION")   # or invalidate_metadata() for everything
```

The next call on any of the pool's connections fetches the interface again. The pool also
resets each connection's ABAP session (`reset_server_context()`) before lending it again,
because a session that already called the old version keeps running it: a live probe showed a
widened character parameter still cut to its old length on such a connection, with no error.
That reset drops whatever session state the connections held. A connection that is lent at the
moment finishes on the old version and is reset when it is next lent.

A call made with an outdated interface usually succeeds and returns the old shape of the
data (`docs/protocol/framing.md`, "Metadata and the server's loaded version"), so the pool can
ask the server instead:

```python
pool = ConnectionPool(params, metadata_check_interval=300)   # at most every 5 minutes
```

When the interval has passed, the next connection lent first asks `RFC_METADATA_GET` whether a
cached interface or a type it uses changed, one round trip per cached function. A changed one
is invalidated and the connections reset as above. Off by default; the interval is yours to
pick. A change made before a function's first check is not seen.

