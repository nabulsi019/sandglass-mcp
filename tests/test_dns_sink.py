"""The DNS recorder (sandglass/dnssink.py, #147): parsing, NXDOMAIN, a real run.

No Docker. The real run starts the recorder on the host on a free port and
sends it A, AAAA, TCP and malformed queries; its markers (stat calls) only
show under strace, so here only its answers are checked. compare.py's rules
for it are in tests/test_dns_rules.py.
"""

import os
import socket
import struct
import subprocess
import sys
import time

from sandglass import PROJECT_ROOT, dnssink


def query(name: str, qtype: int = 1, qid: int = 0x1234) -> bytes:
    """A standard query with recursion desired, as glibc sends it."""
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p)
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", qtype, 1)


def test_parse_query_names_and_types():
    assert dnssink.parse_query(query("Hidden-Node.Example"))[:2] == ("A", "hidden-node.example")
    assert dnssink.parse_query(query("hidden-node.example", 28))[:2] == ("AAAA", "hidden-node.example")
    assert dnssink.parse_query(query("x.example", 99))[:2] == ("TYPE99", "x.example")
    assert dnssink.parse_query(query("", 2))[:2] == ("NS", ".")


def test_a_crafted_name_cant_escape_the_marker_folder():
    # "/" and ".." inside a label are escaped, so the marker stays one path component per label.
    packet = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x05../.x\x00" + struct.pack(">HH", 1, 1)
    path, _ = dnssink.marker(packet)
    assert path == "/sandglass-dns/A/%2E%2E%2F%2Ex"


def test_malformed_queries_are_recorded_as_invalid_without_a_reply():
    for packet in (b"", b"\x00" * 11, query("x.example")[:-3],
                   struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"):
        assert dnssink.marker(packet) == ("/sandglass-dns/_invalid_/_invalid_", None)


def test_the_answer_is_nxdomain_with_the_same_id_and_question():
    packet = query("hidden-node.example", 28, qid=0xBEEF)
    _, reply = dnssink.marker(packet)
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", reply[:12])
    assert qid == 0xBEEF and (qd, an, ns, ar) == (1, 0, 0, 0)
    assert flags & 0x8000 and flags & 0x0100 and flags & 0x0080  # QR, RD copied, RA
    assert flags & 0x000F == 3  # NXDOMAIN
    assert reply[12:] == packet[12:]  # the question, unchanged


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_a_real_recorder_answers_udp_and_tcp():
    port = _free_port()
    ready_r, ready_w = os.pipe()
    code = f"from sandglass import dnssink; dnssink.serve({port}, {ready_w})"
    proc = subprocess.Popen([sys.executable, "-c", code], cwd=PROJECT_ROOT, pass_fds=(ready_w,))
    os.close(ready_w)
    try:
        assert os.read(ready_r, 1) == b"1"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(5)
            for qtype in (1, 28):
                udp.sendto(query("hidden-node.example", qtype), ("127.0.0.1", port))
                reply, _ = udp.recvfrom(512)
                assert struct.unpack(">H", reply[2:4])[0] & 0xF == 3
            udp.sendto(b"\x01\x02", ("127.0.0.1", port))  # malformed: recorded, no answer
            udp.sendto(query("after.example"), ("127.0.0.1", port))
            assert dnssink.parse_query(udp.recvfrom(512)[0])[1] == "after.example"
        with socket.create_connection(("127.0.0.1", port), timeout=5) as tcp:
            packet = query("tcp.example")
            tcp.sendall(len(packet).to_bytes(2, "big") + packet)
            size = int.from_bytes(tcp.recv(2), "big")
            reply = b""
            while len(reply) < size:
                reply += tcp.recv(size - len(reply))
            assert struct.unpack(">H", reply[2:4])[0] & 0xF == 3
    finally:
        proc.kill()
        proc.wait(timeout=10)
        os.close(ready_r)


def test_the_recorder_stops_when_its_parent_is_gone():
    # Started from a short-lived parent: once that exits, the recorder ends on its own.
    port = _free_port()
    code = (f"import os, subprocess, sys; r, w = os.pipe(); "
            f"p = subprocess.Popen([sys.executable, '-c', 'from sandglass import dnssink; dnssink.serve({port}, %d)' % w], "
            f"pass_fds=(w,)); os.read(r, 1); print(p.pid, flush=True)")
    out = subprocess.run([sys.executable, "-c", code], cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30)
    pid = int(out.stdout.split()[0])
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    os.kill(pid, 9)
    raise AssertionError("the recorder kept running after its parent exited")
