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
# fail, which shows the sandbox has no route to the internet.
ISOLATION_CHECK = ("1.1.1.1", 443)
# The launcher hands the sink this fd; the sink writes one byte when listening.
READY_FD = 3

# Hosts, methods and ports must look like this, or they're recorded as
# "_invalid_", so a crafted request can't put ".." or "/" into the marker path.
_HOST_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"


def clean_host(host: str) -> str:
    """Return the host if every label is letters/digits/hyphens, else "_invalid_"."""
    labels = host.lower().split(".")
    if len(host) > 253 or not all(labels) or any(c not in _HOST_CHARS for c in "".join(labels)):
        return "_invalid_"
    return host.lower()


def parse_request(data: bytes) -> tuple[str, str, int]:
    """(method, host, port) from the start of a proxy request.

    Handles "CONNECT host:443 HTTP/1.1" (HTTPS through a proxy) and
    "GET http://host[:port]/path HTTP/1.1" (plain HTTP through a proxy).
    """
    first = data.split(b"\r\n", 1)[0].decode("latin-1")
    parts = first.split(" ")
    if len(parts) != 3 or not parts[0].isalpha() or not parts[0].isupper() or len(parts[0]) > 10:
        return "_invalid_", "_invalid_", 0
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


def serve() -> None:
    """Answer proxy requests locally and record each one, until the server exits."""
    import socket

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((SINK_HOST, SINK_PORT))
    server.listen(16)
    server.settimeout(0.5)

    # Isolation check: this must fail under --network none.
    try:
        socket.create_connection(ISOLATION_CHECK, timeout=2).close()
    except OSError:
        pass

    _record(SINK_READY)
    os.write(READY_FD, b"1")  # tell the launcher the sink is listening
    os.close(READY_FD)

    parent = os.getppid()
    while os.getppid() == parent:  # stop once the server has exited
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        with conn:
            conn.settimeout(2)
            data = b""
            try:
                while b"\r\n\r\n" not in data and len(data) < 8192:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            method, host, port = parse_request(data)
            _record(f"{SINK_MARKER_DIR}/{method}/{host}/{port}")
            if method == "CONNECT":
                reply = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            else:
                body = b"sandglass sink: request recorded, nothing was sent anywhere\n"
                reply = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                         b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            try:
                conn.sendall(reply)
            except OSError:
                pass


if __name__ == "__main__":
    serve()
