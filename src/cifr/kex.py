"""Derive key exchange strength from the server's handshake messages."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa

from cifr.suites import CipherSuite
from cifr.tls import GROUP_NAMES, ServerHello, group_bits

# NIST SP 800-57 comparable strengths: EC field size -> RSA modulus size.
EC_RSA_EQUIVALENT = [(512, 15360), (384, 7680), (256, 3072), (224, 2048), (160, 1024)]


def ec_to_rsa_bits(bits: int) -> int:
    for ec_bits, rsa_bits in EC_RSA_EQUIVALENT:
        if bits >= ec_bits:
            return rsa_bits
    return 512 if bits else 0


@dataclass
class KeyExchange:
    kind: str  # "rsa", "dh" or "ecdh"
    bits: int
    group: str | None = None

    @property
    def strength(self) -> int:
        """RSA-equivalent strength in bits, the basis for nmap-style scoring."""
        return ec_to_rsa_bits(self.bits) if self.kind == "ecdh" else self.bits

    def __str__(self) -> str:
        return self.group or f"{self.kind} {self.bits}"


@dataclass
class CertificateInfo:
    key_type: str
    key_bits: int
    signature_hash: str | None
    curve: str | None = None

    def __str__(self) -> str:
        key = f"{self.key_type} {self.curve or self.key_bits}"
        return f"{key}, {self.signature_hash or 'unknown'} signature"


def parse_certificate(der: bytes) -> CertificateInfo | None:
    try:
        cert = x509.load_der_x509_certificate(der)
        key = cert.public_key()
    except (ValueError, UnsupportedAlgorithm):
        return None
    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except UnsupportedAlgorithm:
        sig_hash = None
    match key:
        case rsa.RSAPublicKey():
            return CertificateInfo("rsa", key.key_size, sig_hash)
        case ec.EllipticCurvePublicKey():
            return CertificateInfo("ec", key.key_size, sig_hash, key.curve.name)
        case dsa.DSAPublicKey():
            return CertificateInfo("dsa", key.key_size, sig_hash)
        case dh.DHPublicKey():
            return CertificateInfo("dh", key.key_size, sig_hash)
        case ed25519.Ed25519PublicKey():
            return CertificateInfo("ed25519", 256, sig_hash)
        case ed448.Ed448PublicKey():
            return CertificateInfo("ed448", 448, sig_hash)
    return None


def _vec16(data: bytes, pos: int) -> tuple[bytes, int]:
    length = struct.unpack_from("!H", data, pos)[0]
    return data[pos + 2 : pos + 2 + length], pos + 2 + length


def _named_group(group: int) -> KeyExchange:
    name = GROUP_NAMES.get(group, f"group 0x{group:04X}")
    if 256 <= group <= 260:
        return KeyExchange("dh", group_bits(group), name)
    return KeyExchange("ecdh", group_bits(group), name)


def analyse(
    suite: CipherSuite, hello: ServerHello, ske: bytes | None, cert: CertificateInfo | None
) -> KeyExchange | None:
    """Return the KeyExchange for a negotiated suite, or None if it can't be determined."""
    if suite.tls13:
        return _named_group(hello.group) if hello.group is not None else None
    try:
        pos = 0
        if ske is not None and suite.auth == "PSK" and suite.kex in {"DHE", "ECDHE"}:
            _, pos = _vec16(ske, 0)  # skip psk_identity_hint
        if suite.kex in {"DHE", "SRP"} or (suite.kex == "DH" and suite.auth == "anon"):
            if ske is None:
                return None
            prime, _ = _vec16(ske, pos)
            return KeyExchange("dh", int.from_bytes(prime).bit_length())
        if suite.kex == "ECDHE" or (suite.kex == "ECDH" and suite.auth == "anon"):
            if ske is None or ske[pos] != 3:  # only named_curve is meaningful
                return None
            return _named_group(struct.unpack_from("!H", ske, pos + 1)[0])
        if suite.kex == "RSA":
            if suite.export and ske is not None:
                modulus, _ = _vec16(ske, 0)
                return KeyExchange("rsa", int.from_bytes(modulus).bit_length())
            return KeyExchange("rsa", cert.key_bits) if cert and cert.key_type == "rsa" else None
        if suite.kex == "DH" and cert and cert.key_type == "dh":
            return KeyExchange("dh", cert.key_bits)
        if suite.kex == "ECDH" and cert and cert.key_type == "ec":
            return KeyExchange("ecdh", cert.key_bits, cert.curve)
    except (struct.error, IndexError):
        return None
    return None
