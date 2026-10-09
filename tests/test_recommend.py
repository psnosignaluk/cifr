import shutil
import subprocess

import pytest
from conftest import MLKEM, RSA2048, X25519, make_result

from cifr import tls
from cifr.kex import CertificateInfo
from cifr.recommend import recommend, snippets

ECDHE_RSA_GCM = [("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", X25519), ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", X25519)]
TLS13 = [("TLS_AES_128_GCM_SHA256", MLKEM), ("TLS_AES_256_GCM_SHA384", MLKEM), ("TLS_CHACHA20_POLY1305_SHA256", MLKEM)]
LEGACY = [("TLS_RSA_WITH_AES_128_CBC_SHA", RSA2048), ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", RSA2048)]


def test_compliant_server_needs_no_changes():
    rec = recommend(make_result({tls.TLS12: ECDHE_RSA_GCM, tls.TLS13: TLS13}))
    assert not rec.needed
    assert any("ECDSA" in s for s in rec.suggestions)  # optional, so it doesn't make changes "needed"


def test_weak_server_gets_tailored_recommendation():
    result = make_result({tls.TLS10: LEGACY[:1], tls.TLS12: [*ECDHE_RSA_GCM, *LEGACY]})
    rec = recommend(result)
    assert rec.needed
    assert rec.disable_protocols == ["TLSv1.0"]
    assert rec.enable_protocols == ["TLSv1.3"]
    assert {c.suite.name for c in rec.remove} == {name for name, _ in LEGACY}
    # RSA certificate only: no ECDHE-ECDSA suites in the target set.
    names = [s.suite.name for s in rec.suites]
    assert "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" in names
    assert not any("ECDSA" in n for n in names)
    assert [s.priority for s in rec.suites] == sorted(s.priority for s in rec.suites)
    offered = {s.suite.name for s in rec.suites if s.offered}
    assert offered == {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}
    # Projection keeps only the target suites the server already offers; TLS 1.3 is still missing.
    assert rec.projected.grade == "A-"
    assert rec.projected_tiers == {"Secure": 2}
    assert rec.removal_reasons()["no forward secrecy"] == 2


def test_modern_profile_requires_tls13_only_and_ecdsa():
    rec = recommend(make_result({tls.TLS12: ECDHE_RSA_GCM, tls.TLS13: TLS13}), "modern")
    assert rec.protocols == ["TLSv1.3"]
    assert rec.disable_protocols == ["TLSv1.2"]
    assert all(s.suite.tls13 for s in rec.suites)
    assert any("ECDSA certificate" in a for a in rec.actions)
    assert rec.projected.grade == "A"


def test_certificate_problems_are_required_actions():
    weak_cert = CertificateInfo("rsa", 1024, "sha1")
    rec = recommend(make_result({tls.TLS12: ECDHE_RSA_GCM, tls.TLS13: TLS13}, cert=weak_cert))
    assert rec.needed
    assert len(rec.actions) == 2


def test_post_quantum_suggested_when_not_negotiated():
    classic = [(name, X25519) for name, _ in TLS13]
    rec = recommend(make_result({tls.TLS12: ECDHE_RSA_GCM, tls.TLS13: classic}))
    assert any("X25519MLKEM768" in s for s in rec.suggestions)


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError, match="unknown profile"):
        recommend(make_result({tls.TLS13: TLS13}), "old")


def test_snippets_cover_each_server_type():
    rec = recommend(make_result({tls.TLS12: [*ECDHE_RSA_GCM, *LEGACY]}))
    configs = snippets(rec)
    assert set(configs) == {"nginx", "apache", "haproxy", "openssl"}
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in configs["nginx"]
    assert "SSLProtocol -all +TLSv1.2 +TLSv1.3" in configs["apache"]
    assert "ssl-min-ver TLSv1.2" in configs["haproxy"]
    assert "CBC" not in "".join(configs.values())


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_openssl_accepts_generated_cipher_strings():
    rec = recommend(make_result({tls.TLS12: ECDHE_RSA_GCM, tls.TLS13: TLS13}))
    tls12 = subprocess.run(
        ["openssl", "ciphers", "-s", "-tls1_2", rec.openssl_ciphers()], capture_output=True, text=True, check=True
    )
    assert tls12.stdout.strip().split(":") == [s.openssl_name for s in rec.tls12_suites]
    tls13 = subprocess.run(
        ["openssl", "ciphers", "-s", "-tls1_3", "-ciphersuites", rec.openssl_ciphersuites()],
        capture_output=True, text=True, check=True,
    )  # fmt: skip
    assert set(rec.openssl_ciphersuites().split(":")) <= set(tls13.stdout.strip().split(":"))
