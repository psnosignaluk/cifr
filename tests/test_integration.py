"""End-to-end scans against a local `openssl s_server` (skipped if openssl is unavailable)."""

import shutil
import socket
import subprocess
import time

import pytest

from cifr import tls
from cifr.scanner import resolve, scan

OPENSSL = shutil.which("openssl")
pytestmark = pytest.mark.skipif(OPENSSL is None, reason="openssl not installed")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("tls")
    key, cert = tmp / "key.pem", tmp / "cert.pem"
    subprocess.run(
        [OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
         "-days", "1", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )  # fmt: skip
    port = _free_port()
    ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA:AES128-SHA"
    proc = subprocess.Popen(
        [OPENSSL, "s_server", "-accept", str(port), "-cert", cert, "-key", key, "-www", "-quiet",
         "-serverpref", "-cipher", ciphers, "-ciphersuites", "TLS_AES_256_GCM_SHA384",
         "-min_protocol", "TLSv1.2"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield port
    proc.terminate()
    proc.wait()


def test_scan_local_server(server):
    result = scan(resolve("127.0.0.1", server, None, 2.0), timeout=2.0)
    by_version = {p.version: p for p in result.protocols}

    assert not by_version[tls.SSL3].supported
    assert not by_version[tls.TLS10].supported
    assert not by_version[tls.TLS11].supported

    tls12 = by_version[tls.TLS12]
    assert [c.suite.name for c in tls12.ciphers] == [
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
    ]
    assert tls12.preference == "server"
    assert str(tls12.ciphers[2].kex) == "rsa 2048"
    assert tls12.certificate.key_type == "rsa"

    tls13 = by_version[tls.TLS13]
    assert [c.suite.name for c in tls13.ciphers] == ["TLS_AES_256_GCM_SHA384"]
    assert tls13.ciphers[0].score.grade == "A"
