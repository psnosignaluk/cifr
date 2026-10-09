"""Builders for synthetic scan results, shared by the rating and recommendation tests."""

from cifr import tls
from cifr.kex import CertificateInfo, KeyExchange
from cifr.rating import rate_suite
from cifr.scanner import AcceptedCipher, ProtocolResult, ScanResult, Target
from cifr.scoring import score_cipher
from cifr.suites import by_name
from cifr.tlsref import rank

X25519 = KeyExchange("ecdh", 256, "x25519")
MLKEM = KeyExchange("ecdh", 256, "X25519MLKEM768")
RSA2048 = KeyExchange("rsa", 2048)
RSA_CERT = CertificateInfo("rsa", 2048, "sha256")


def accepted(name, kex, version=tls.TLS12):
    s = by_name(name)
    return AcceptedCipher(s, kex, score_cipher(s, kex, version), rate_suite(s, kex), rank(s))


def make_result(protocols, cert=RSA_CERT):
    """protocols: {version: [(suite name, KeyExchange), ...]}"""
    target = Target("example.test", 443, ("192.0.2.1", 443), "example.test")
    results = []
    for version, ciphers in protocols.items():
        p = ProtocolResult(version, [accepted(n, k, version) for n, k in ciphers])
        p.certificate = cert if version != tls.TLS13 else None
        results.append(p)
    return ScanResult(target, results)
