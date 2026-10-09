"""Scanner behaviour against a fake server (no openssl needed)."""

import socket
import threading

import pytest

from cifr.scanner import resolve, scan


@pytest.fixture
def hello_rejecting_server():
    """A server that answers every ClientHello with a close_notify alert, as CloudFront does for a bad hello."""
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            with conn:
                conn.settimeout(1)
                try:
                    conn.recv(4096)
                    conn.sendall(bytes([21, 3, 3, 0, 2, 1, 0]))  # alert record: warning, close_notify
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield listener.getsockname()[1]
    stop.set()
    thread.join()
    listener.close()


def test_rejected_client_hello_is_reported_as_inconclusive(hello_rejecting_server):
    result = scan(resolve("127.0.0.1", hello_rejecting_server, None, 2.0), timeout=2.0)
    assert not result.supported
    for proto in result.protocols:
        assert proto.inconclusive and "close_notify" in proto.inconclusive
