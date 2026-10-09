"""Whole-server grade following the Qualys SSL Labs SSL Server Rating Guide (2009r).

Score = 30% protocol support + 30% key exchange + 40% cipher strength, mapped to
A-F, then capped by the guide's rules. Only the rules cifr can measure from a
handshake scan are applied; certificate trust, HSTS and vulnerability tests
(Heartbleed, ROBOT, renegotiation and so on) are not assessed, so A+ is never
awarded. This approximates SSL Labs; it is not an official SSL Labs result.

Guide: https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cifr import tls
from cifr.kex import ec_to_rsa_bits
from cifr.scanner import ScanResult

GRADE_ORDER = ["A+", "A", "A-", "B", "C", "D", "E", "F"]
THRESHOLDS = [(80, "A"), (65, "B"), (50, "C"), (35, "D"), (20, "E")]
PROTOCOL_SCORES = {tls.SSL3: 80, tls.TLS10: 90, tls.TLS11: 95, tls.TLS12: 100, tls.TLS13: 100}
NOT_ASSESSED = [
    "certificate trust, hostname and expiry",
    "HSTS (so no A+)",
    "SSLv2",
    "vulnerability tests (Heartbleed, ROBOT, POODLE-TLS, renegotiation, compression)",
]
# Tools that cover the checks above, for users who need a complete assessment.
FURTHER_TESTING = {
    "Qualys SSL Labs": "https://www.ssllabs.com/ssltest/",
    "testssl.sh": "https://testssl.sh/",
}


@dataclass
class ServerGrade:
    grade: str
    score: int
    protocol_score: float
    kex_score: float
    cipher_score: float
    caps: list[str] = field(default_factory=list)

    @property
    def not_assessed(self) -> list[str]:
        return NOT_ASSESSED


def kex_score(strength: int) -> int:
    if strength <= 0:
        return 0
    for limit, score in ((512, 20), (1024, 40), (2048, 80), (4096, 90)):
        if strength < limit:
            return score
    return 100


def cipher_score(bits: int) -> int:
    if bits <= 0:
        return 0
    if bits < 128:
        return 20
    if bits < 256:
        return 80
    return 100


def _cert_strength(cert) -> int | None:
    if cert is None:
        return None
    if cert.key_type in ("ec", "ed25519", "ed448"):
        return ec_to_rsa_bits(cert.key_bits)
    return cert.key_bits


def grade_server(result: ScanResult) -> ServerGrade | None:
    protocols = result.supported
    if not protocols:
        return None
    versions = [p.version for p in protocols]
    ciphers = [(p.version, c) for p in protocols for c in p.ciphers]
    certs = [p.certificate for p in protocols if p.certificate]

    protocol = (PROTOCOL_SCORES[max(versions)] + PROTOCOL_SCORES[min(versions)]) / 2

    # Handshake strength: the key exchange, capped by the certificate key (as the guide does for DHE/ECDHE).
    cert_strengths = [s for c in certs if (s := _cert_strength(c))]
    cert_min = min(cert_strengths, default=None)
    kex_scores = []
    for _, c in ciphers:
        if c.suite.anonymous:
            kex_scores.append(0)
            continue
        strengths = [s for s in (c.kex.strength if c.kex else None, cert_min) if s]
        if strengths:
            score = kex_score(min(strengths))
            kex_scores.append(min(score, 40) if c.suite.export else score)
    kex = min(kex_scores) if kex_scores else 100

    bits = [c.suite.bits for _, c in ciphers]
    cipher = (cipher_score(max(bits)) + cipher_score(min(bits))) / 2

    total = 0 if 0 in (protocol, kex, cipher) else round(0.3 * protocol + 0.3 * kex + 0.4 * cipher)
    grade = next((g for limit, g in THRESHOLDS if total >= limit), "F")
    caps: list[str] = []

    def cap(limit: str, reason: str) -> None:
        nonlocal grade
        caps.append(f"{reason} → max {limit}")
        if GRADE_ORDER.index(limit) > GRADE_ORDER.index(grade):
            grade = limit

    if total == 0:
        caps.append("a category scored zero (anonymous key exchange) → F")
    if max(versions) == tls.SSL3:
        cap("F", "SSLv3 is the best protocol supported")
    elif tls.SSL3 in versions:
        cap("B", "SSLv3 supported")
    if tls.TLS10 in versions or tls.TLS11 in versions:
        cap("B", "TLS 1.0/1.1 supported")
    if max(versions) < tls.TLS12:
        cap("C", "no TLS 1.2 or 1.3")

    rc4 = [(v, c) for v, c in ciphers if c.suite.family == "RC4"]
    if rc4 and len(rc4) == len(ciphers):
        cap("F", "only RC4 suites")
    elif any(v >= tls.TLS11 for v, _ in rc4):
        cap("C", "RC4 with TLS 1.1+")
    elif rc4:
        cap("B", "RC4 supported")
    if any(v >= tls.TLS11 and c.suite.block64 for v, c in ciphers):
        cap("C", "64-bit block cipher (3DES etc.) with TLS 1.1+")
    if any(c.suite.export for _, c in ciphers):
        cap("F", "export suites supported")

    dh = [c.kex.bits for _, c in ciphers if c.kex and c.kex.kind == "dh"]
    if dh and min(dh) < 1024:
        cap("F", f"DH parameters of {min(dh)} bits")
    elif dh and min(dh) < 2048:
        cap("B", f"DH parameters of {min(dh)} bits")
    if cert_min and cert_min < 1024:
        cap("F", "certificate key under 1024 bits")
    elif cert_min and cert_min < 2048:
        cap("B", "certificate key under 2048 bits")
    if any(c.signature_hash == "md5" for c in certs):
        cap("F", "MD5 certificate signature")

    if not any(c.suite.forward_secret for _, c in ciphers):
        cap("B", "no forward secrecy")
    if not any(c.suite.aead for _, c in ciphers):
        cap("B", "no AEAD suites")
    if tls.TLS13 not in versions:
        cap("A-", "no TLS 1.3")
    if any(c.signature_hash == "sha1" for c in certs):
        cap("A-", "SHA-1 certificate signature, which SSL Labs grades T (untrusted)")

    return ServerGrade(grade, total, protocol, kex, cipher, caps)
