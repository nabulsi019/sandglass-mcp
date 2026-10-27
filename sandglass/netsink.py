"""The local network sink: a fake HTTP(S) proxy that never connects anywhere.

Started by the launcher inside the sandbox, as its own process:
`python -I -S -c <this source>` (-I: no cwd on sys.path, so starting it
lists no folder; -S: no site-packages, it only needs the stdlib).

The server's HTTP_PROXY / HTTPS_PROXY point here. For every request the sink
records the method, host and port, then answers locally (200 for plain HTTP,
403 for HTTPS CONNECT). It records through the trace itself: it stat()s a path
like /sandglass-netsink/GET/example.com/80 that doesn't exist; strace logs
the call and compare.py turns it into a domain event. So the sink needs no
log file or channel of its own that the server could attack.

Imported on the host too (compare.py uses the constants), so the actual work
only happens under `if __name__ == "__main__"`.
"""

import os

SINK_HOST = "127.0.0.1"
SINK_PORT = 18080
SINK_URL = f"http://{SINK_HOST}:{SINK_PORT}"
# The sink stat()s paths under this folder. It doesn't exist; the stat is
# only there so the event lands in the trace.
SINK_MARKER_DIR = "/sandglass-netsink"
SINK_READY = f"{SINK_MARKER_DIR}/ready"
# A public address the sink tries to reach once at startup. The connect must
# fail with "network unreachable", which shows the sandbox has no route out.
ISOLATION_CHECK = ("1.1.1.1", 443)
ISOLATION_TIMEOUT = 2  # seconds
# The sink reports the check's outcome itself (#100), after the connect has
# finished, by stat()ing <this>/<isolated|not-isolated>/<outcome>, before it
# marks itself ready. compare.py reads only that, never the connect's errno.
ISOLATION_MARKER_DIR = "/sandglass-isolation"
# (#141) The nameservers in the container's /etc/resolv.conf, reported the
# same way, also before "ready": <this>/nameserver/<address> for each, then
# <this>/done (or <this>/unreadable if the file can't be read). compare.py
# uses them to tell the system resolver's lookups from DNS sent elsewhere.
RESOLVER_FILE = "/etc/resolv.conf"
RESOLVER_MARKER_DIR = "/sandglass-resolver"
# The launcher hands the sink this fd; the sink writes one byte when listening.
READY_FD = 3

# Hosts, methods and ports must look like this, or they're recorded as
# "_invalid_", so a crafted request can't put ".." or "/" into the marker path.
# "_" is allowed: real DNS names use it (_dmarc.example.com, some internal hosts).
_HOST_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
# What's recorded when no method or host can be read (#136: compare.py calls
# such a record an "unidentified connection to the sink").
INVALID = "_invalid_"


def clean_host(host: str) -> str:
    """Return the host if every label is letters/digits/hyphens/underscores, else INVALID."""
    labels = host.lower().split(".")
    if len(host) > 253 or not all(labels) or any(c not in _HOST_CHARS for c in "".join(labels)):
        return INVALID
    return host.lower()


def parse_request(data: bytes) -> tuple[str, str, int]:
    """(method, host, port) from the start of a proxy request.

    Handles "CONNECT host:443 HTTP/1.1" (HTTPS through a proxy) and
    "GET http://host[:port]/path HTTP/1.1" (plain HTTP through a proxy).
    """
    first = data.split(b"\r\n", 1)[0].decode("latin-1")
    parts = first.split(" ")
    if len(parts) != 3 or not parts[0].isalpha() or not parts[0].isupper() or len(parts[0]) > 10:
        return INVALID, INVALID, 0
    method, target = parts[0], parts[1]
    default_port = 443 if method == "CONNECT" else 80
    if target.startswith("http://"):
        target = target[len("http://"):].split("/", 1)[0]
    host, _, port = target.partition(":")
    port = int(port) if port.isdigit() and len(port) <= 5 else default_port
    return method, clean_host(host), port


def _record(path: str) -> None:
    """Leave an event in the trace: stat() a path that doesn't exist."""
    try:
        os.stat(path)
    except OSError:
        pass


def nameservers(text: str) -> list[str]:
    """The addresses on resolv.conf's "nameserver" lines, valid IPs only
    (a zone like %eth0 is dropped), so nothing else gets into a marker path."""
    import ipaddress

    found = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            try:
                found.append(str(ipaddress.ip_address(parts[1].split("%")[0])))
            except ValueError:
                pass
    return found


def report_resolvers() -> None:
    """Record the container's nameservers in the trace (#141), or that the
    file couldn't be read. Runs before "ready", so before any server code."""
    try:
        with open(RESOLVER_FILE, encoding="utf-8", errors="replace") as f:
            text = f.read(65536)
    except OSError:
        _record(f"{RESOLVER_MARKER_DIR}/unreadable")
        return
    for address in nameservers(text):
        _record(f"{RESOLVER_MARKER_DIR}/nameserver/{address}")
    _record(f"{RESOLVER_MARKER_DIR}/done")


def isolation_result(connect=None) -> tuple[str, str]:
    """("isolated" or "not-isolated", outcome) of a connect to ISOLATION_CHECK.

    Decided after the connect has FINISHED. With a timeout, the connect
    doesn't block, so its first errno (EINPROGRESS) says nothing; the
    exception (or the lack of one) at the end does. Only ENETUNREACH (no route
    at all, what --network none gives) counts as isolated. Success, a timeout,
    a refusal or any other error means packets may have left the container.
    `connect` is replaceable for tests.
    """
    import errno
    import socket

    if connect is None:
        connect = lambda: socket.create_connection(ISOLATION_CHECK, timeout=ISOLATION_TIMEOUT).close()
    try:
        connect()
    except TimeoutError:  # socket.timeout is TimeoutError
        return "not-isolated", "timeout"
    except OSError as exc:
        outcome = errno.errorcode.get(exc.errno, "unknown-error")
        return ("isolated" if exc.errno == errno.ENETUNREACH else "not-isolated"), outcome
    return "not-isolated", "connected"


# (#136) How long the sink waits for one connection's request, from the
# moment it accepts it: a deadline, not a per-read timeout, so a client that
# trickles a byte at a time can't hold the sink. And after the server has
# exited, how long it keeps reading the connections still open or queued.
REQUEST_DEADLINE = 2.0   # seconds
DRAIN_DEADLINE = 1.0     # seconds
MAX_REQUEST_BYTES = 8192


def _reply(method: str) -> bytes:
    """403 for HTTPS CONNECT, a short 200 for plain HTTP."""
    if method == "CONNECT":
        return b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    body = b"sandglass sink: request recorded, nothing was sent anywhere\n"
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


def _finish(conn, data: bytes) -> None:
    """Record one connection's request (exactly one record per connection,
    "_invalid_" if it can't be parsed), answer it, close it."""
    method, host, port = parse_request(data)
    _record(f"{SINK_MARKER_DIR}/{method}/{host}/{port}")
    try:
        conn.setblocking(True)
        conn.settimeout(0.5)
        conn.sendall(_reply(method))
    except OSError:
        pass
    conn.close()


def serve() -> None:
    """Answer proxy requests locally and record each one, until the server exits.

    (#136) Connections are read side by side, in this one thread (selectors),
    so one unfinished request can't keep the next one waiting, and every
    record is made by this process's main thread (compare.py finds them by
    its pid). When the server has exited, every connection still open AND
    every one still queued in the listen backlog is read and recorded before
    the sink stops: a request can't hide behind a stalled one.
    """
    import selectors
    import socket
    import time

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((SINK_HOST, SINK_PORT))
    server.listen(64)

    # Isolation check (#100): decided once the connect has finished, and
    # reported in the trace before "ready", so before any server code runs.
    result, outcome = isolation_result()
    _record(f"{ISOLATION_MARKER_DIR}/{result}/{outcome}")
    report_resolvers()  # (#141) also before "ready"

    _record(SINK_READY)
    os.write(READY_FD, b"1")  # tell the launcher the sink is listening
    os.close(READY_FD)

    server.setblocking(False)
    selector = selectors.DefaultSelector()
    selector.register(server, selectors.EVENT_READ)
    pending = {}  # connection -> [bytes read so far, deadline]

    def accept_all(deadline: float) -> None:
        """Accept every connection waiting in the backlog."""
        while True:
            try:
                conn, _ = server.accept()
            except (BlockingIOError, InterruptedError):
                return
            conn.setblocking(False)
            pending[conn] = [b"", deadline]
            selector.register(conn, selectors.EVENT_READ)

    def read(conn) -> None:
        """Read what's there; finish the request once it's complete or closed."""
        data = pending[conn][0]
        try:
            chunk = conn.recv(4096)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            chunk = b""
        data += chunk
        pending[conn][0] = data
        if not chunk or b"\r\n\r\n" in data or len(data) >= MAX_REQUEST_BYTES:
            selector.unregister(conn)
            del pending[conn]
            _finish(conn, data)

    def expire(now: float) -> None:
        """Finish every connection past its deadline with what it sent."""
        for conn in [c for c, (_, deadline) in pending.items() if deadline <= now]:
            selector.unregister(conn)
            _finish(conn, pending.pop(conn)[0])

    parent = os.getppid()
    while os.getppid() == parent:  # until the server has exited
        for key, _ in selector.select(timeout=0.2):
            if key.fileobj is server:
                accept_all(time.monotonic() + REQUEST_DEADLINE)
            else:
                read(key.fileobj)
        expire(time.monotonic())

    # The server has exited: drain. Everything still queued is accepted, and
    # everything open is read until it's complete, closed or out of time.
    end = time.monotonic() + DRAIN_DEADLINE
    accept_all(end)
    for item in pending.values():
        item[1] = min(item[1], end)
    while pending:
        for key, _ in selector.select(timeout=0.1):
            if key.fileobj is server:
                accept_all(end)
            else:
                read(key.fileobj)
        expire(time.monotonic())
    server.close()


if __name__ == "__main__":
    serve()
