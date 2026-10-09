"""nmap ssl-enum-ciphers style cipher scoring.

Mirrors the algorithm in nmap's ssl-enum-ciphers.lua (itself modelled on the
SSL Labs rating guide): the key exchange and the bulk cipher are each scored
on a 0-1 scale, combined 43/57, and mapped to a letter grade. Specific
weaknesses then cap the grade.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cifr.kex import CertificateInfo, KeyExchange
from cifr.suites import CipherSuite
from cifr.tls import SSL3

GRADES = "ABCDEF"
GRADE_THRESHOLDS = [(0.80, "A"), (0.65, "B"), (0.50, "C"), (0.35, "D"), (0.20, "E")]


@dataclass
class CipherScore:
    score: float | None
    grade: str
    warnings: list[str] = field(default_factory=list)


def kex_score(strength: int) -> float:
    if strength <= 0:
        return 0.0
    if strength < 512:
        return 0.2
    if strength < 1024:
        return 0.4
    if strength < 2048:
        return 0.8
    if strength < 4096:
        return 0.9
    return 1.0


def cipher_score(bits: int) -> float:
    if bits <= 0:
        return 0.0
    if bits < 128:
        return 0.2
    if bits < 256:
        return 0.8
    return 1.0


def letter_grade(score: float) -> str:
    return next((grade for threshold, grade in GRADE_THRESHOLDS if score >= threshold), "F")


def worst_grade(grades: list[str]) -> str | None:
    known = [g for g in grades if g in GRADES]
    return max(known, key=GRADES.index) if known else None


def _cap(grade: str, cap: str) -> str:
    return worst_grade([grade, cap]) or cap


def score_cipher(
    suite: CipherSuite, kex: KeyExchange | None, version: int, cert: CertificateInfo | None = None
) -> CipherScore:
    warnings: list[str] = []
    caps: list[str] = []

    if suite.anonymous:
        warnings.append("Anonymous key exchange, score capped at F")
        caps.append("F")
    if suite.family == "NULL":
        warnings.append("Null cipher, score capped at F")
        caps.append("F")
    if suite.export:
        warnings.append("Export-grade cipher suite, score capped at F")
        caps.append("F")
    if suite.family == "RC4":
        warnings.append("Broken cipher RC4 is deprecated by RFC 7465, score capped at C")
        caps.append("C")
    if suite.block64:
        warnings.append(f"64-bit block cipher {suite.family} vulnerable to SWEET32 attack, score capped at C")
        caps.append("C")
    if suite.mac == "MD5":
        warnings.append("Ciphersuite uses MD5 for message integrity")
    if version == SSL3 and suite.cbc:
        warnings.append("CBC-mode cipher in SSLv3 (CVE-2014-3566)")
    if cert and cert.signature_hash == "md5":
        warnings.append("Insecure certificate signature (MD5), score capped at F")
        caps.append("F")
    elif cert and cert.signature_hash == "sha1":
        warnings.append("Weak certificate signature: SHA1")
    if kex and cert and kex.kind == "dh" and cert.key_type == "rsa" and kex.bits < cert.key_bits:
        warnings.append(f"Key exchange ({kex}) of lower strength than certificate key")

    if kex is None:
        if caps:
            return CipherScore(None, worst_grade(caps), warnings)
        return CipherScore(None, "unknown", warnings)

    score = 0.43 * kex_score(kex.strength) + 0.57 * cipher_score(suite.bits)
    grade = letter_grade(score)
    for cap in caps:
        grade = _cap(grade, cap)
    return CipherScore(round(score, 3), grade, warnings)
