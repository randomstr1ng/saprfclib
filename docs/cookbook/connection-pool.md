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

# Close the pool when done — this closes all idle and checked-out connections.
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
- `pool.close()` waits for checked-out connections to be returned, then closes all of them.
  Call it once at application shutdown.
