"""The DNS recorder: a resolver that records every name looked up and answers NXDOMAIN (#147).

Started by the launcher inside the sandbox, as its own process, before the
network sink and any server code: `python -I -S /usr/local/lib/mcp-runtime/dns.py`,
where the Dockerfile copies this file (a neutral path, #159), with an empty
environment. The server's container gets `--dns 127.0.0.1 --dns-search .`,
so /etc/resolv.conf points glibc's resolver (Node's fetch, Python's
socket.getaddrinfo, curl, ...) here. Without it, a lookup went to Docker's
resolver address, which `--network none` can't reach, and the trace showed
that a lookup happened but never which name.

It listens on 127.0.0.1:53, UDP and TCP (a client may use TCP DNS). For every
query it records the type and the name the way the network sink records a
request: it stat()s /sandglass-dns/<type>/<name>, a path that doesn't exist,
so strace logs it and compare.py reads it. It never returns an address: it
answers NXDOMAIN ("no such name"), so nothing is ever contacted because of an
answer from here. (NXDOMAIN, not REFUSED: glibc stops at NXDOMAIN, while
REFUSED makes it try other servers and search domains.)

It stops once the server has exited (its parent is gone), after reading what
is still queued. Like the sink, it runs as the server's user; compare.py
trusts only the markers of the first process to stat the "ready" marker.

Imported on the host too (compare.py uses the constants, tests the parser),
so the actual work only happens under `if __name__ == "__main__"`.
"""

import os

DNS_HOST = "127.0.0.1"
DNS_PORT = 53
# The recorder stat()s paths under this folder. It doesn't exist; the stat is
# only there so the event lands in the trace.
DNS_MARKER_DIR = "/sandglass-dns"
DNS_READY = f"{DNS_MARKER_DIR}/ready"
# The launcher hands the recorder this fd; it writes one byte when listening.
READY_FD = 3
# What's recorded for a query that can't be read (too short, bad name).
INVALID = "_invalid_"
# The query types worth naming; any other is recorded as TYPE<number>.
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
          28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
MAX_NAME = 253
# Characters a name keeps as they are; any other byte becomes %XX, so a
# crafted name can't put "/" or ".." into the marker path.
_NAME_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-_")

# How long a TCP connection may take to send its query, and after the server
# has exited, how long the recorder keeps reading what's still queued.
TCP_DEADLINE = 2.0   # seconds
DRAIN_DEADLINE = 0.5  # seconds


def _label(raw: bytes) -> str:
    """One label, lower-cased, with anything outside [a-z0-9-_] escaped as %XX."""
    return "".join(chr(b) if chr(b) in _NAME_CHARS else f"%{b:02X}" for b in raw.lower())


def parse_query(packet: bytes) -> tuple[str, str, int] | None:
    """(type, name, end of the question) from a DNS query, or None if unreadable.

    The header is 12 bytes; the question's name is a list of length-prefixed
    labels ending with 0 (a query never uses compression pointers), then 2
    bytes of type and 2 of class. The name comes back lower-case and escaped,
    "." for the root.
    """
    if len(packet) < 12 or int.from_bytes(packet[4:6], "big") < 1:
        return None
    labels, i = [], 12
    while True:
        if i >= len(packet):
            return None
        length = packet[i]
        if length == 0:
            i += 1
            break
        if length > 63 or i + 1 + length > len(packet):  # a pointer or a cut-off label
            return None
        labels.append(_label(packet[i + 1:i + 1 + length]))
        i += 1 + length
    if i + 4 > len(packet):
        return None
    qtype = int.from_bytes(packet[i:i + 2], "big")
    name = ".".join(labels) or "."
    if len(name) > MAX_NAME:
        return None
    return QTYPES.get(qtype, f"TYPE{qtype}"), name, i + 4


def nxdomain(packet: bytes, end: int) -> bytes:
    """The NXDOMAIN answer to a query: the same ID and question, QR set,
    opcode and RD copied, RA set, RCODE 3, no answer, authority or extra records."""
    flags = 0x8000 | (packet[2] & 0x79) << 8 | 0x80 | 3  # QR | opcode, RD | RA | NXDOMAIN
    return packet[:2] + flags.to_bytes(2, "big") + b"\x00\x01\x00\x00\x00\x00\x00\x00" + packet[12:end]


def marker(packet: bytes) -> tuple[str, bytes | None]:
    """(the marker path to stat, the reply or None) for one query."""
    parsed = parse_query(packet)
    if parsed is None:
        return f"{DNS_MARKER_DIR}/{INVALID}/{INVALID}", None
    qtype, name, end = parsed
    return f"{DNS_MARKER_DIR}/{qtype}/{name}", nxdomain(packet, end)


def _record(path: str) -> None:
    """Leave an event in the trace: stat() a path that doesn't exist."""
    try:
        os.stat(path)
    except OSError:
        pass


def serve(port: int = DNS_PORT, ready_fd: int = READY_FD) -> None:
    """Answer every query with NXDOMAIN and record it, until the server exits.

    One thread (selectors), like the network sink, so every record is made by
    this process's main thread and compare.py finds them by its pid.
    `port` and `ready_fd` are only changed by tests (a free port on the host).
    """
    import selectors
    import socket
    import time

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((DNS_HOST, port))
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((DNS_HOST, port))
    tcp.listen(16)

    _record(DNS_READY)
    os.write(ready_fd, b"1")  # tell the launcher the recorder is listening
    os.close(ready_fd)

    for sock in (udp, tcp):
        sock.setblocking(False)
    selector = selectors.DefaultSelector()
    selector.register(udp, selectors.EVENT_READ)
    selector.register(tcp, selectors.EVENT_READ)
    pending = {}  # TCP connection -> [bytes read so far, deadline]

    def answer_udp() -> None:
        while True:
            try:
                packet, client = udp.recvfrom(4096)
            except (BlockingIOError, InterruptedError):
                return
            path, reply = marker(packet)
            _record(path)
            if reply is not None:
                try:
                    udp.sendto(reply, client)
                except OSError:
                    pass

    def finish_tcp(conn, data: bytes) -> None:
        """One query per connection (2-byte length, then the packet); recorded
        even if it never arrived whole, as an invalid query."""
        selector.unregister(conn)
        del pending[conn]
        size = int.from_bytes(data[:2], "big") if len(data) >= 2 else -1
        path, reply = marker(data[2:2 + size] if size >= 0 else b"")
        _record(path)
        try:
            if reply is not None:
                conn.setblocking(True)
                conn.settimeout(0.5)
                conn.sendall(len(reply).to_bytes(2, "big") + reply)
        except OSError:
            pass
        conn.close()

    def read_tcp(conn) -> None:
        data = pending[conn][0]
        try:
            chunk = conn.recv(4096)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            chunk = b""
        data += chunk
        pending[conn][0] = data
        if not chunk or (len(data) >= 2 and len(data) >= 2 + int.from_bytes(data[:2], "big")):
            finish_tcp(conn, data)

    def accept_all(deadline: float) -> None:
        while True:
            try:
                conn, _ = tcp.accept()
            except (BlockingIOError, InterruptedError):
                return
            conn.setblocking(False)
            pending[conn] = [b"", deadline]
            selector.register(conn, selectors.EVENT_READ)

    def step(timeout: float, deadline: float) -> None:
        for key, _ in selector.select(timeout=timeout):
            if key.fileobj is udp:
                answer_udp()
            elif key.fileobj is tcp:
                accept_all(deadline)
            else:
                read_tcp(key.fileobj)
        now = time.monotonic()
        for conn in [c for c, (_, end) in pending.items() if end <= now]:
            finish_tcp(conn, pending[conn][0])

    parent = os.getppid()
    while os.getppid() == parent:  # until the server has exited
        step(0.2, time.monotonic() + TCP_DEADLINE)

    # The server has exited: answer and record what's still queued.
    end = time.monotonic() + DRAIN_DEADLINE
    for item in pending.values():
        item[1] = min(item[1], end)
    while time.monotonic() < end or pending:
        step(0.05, end)
    udp.close()
    tcp.close()


if __name__ == "__main__":
    serve()
