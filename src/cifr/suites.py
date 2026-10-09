"""TLS cipher suite registry, derived from the IANA TLS parameters registry.

Every attribute (key exchange, authentication, bulk cipher, strength, MAC) is
parsed out of the IANA suite name, so the bundled data only needs code -> name.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cache
from importlib.resources import files

MAC_TOKENS = {"MD5", "SHA", "SHA256", "SHA384", "SHA512", "NULL", "IMIT", "OMAC", "SM3", "ASCONHASH256"}
AEAD_TOKENS = {"GCM", "CCM", "POLY1305", "MGM"}
AEAD_FAMILIES = {"ASCONAEAD128", "AEGIS"}
BLOCK64_FAMILIES = {"3DES", "DES", "DES40", "IDEA", "RC2", "MAGMA", "GOST28147"}
# Effective strength for families whose name carries no key size. 3DES is
# rated at 112 bits, as nmap does.
FAMILY_BITS = {
    "3DES": 112,
    "DES": 56,
    "DES40": 40,
    "IDEA": 128,
    "SEED": 128,
    "CHACHA20": 256,
    "GOST28147": 256,
    "KUZNYECHIK": 256,
    "MAGMA": 256,
    "SM4": 128,
    "ASCONAEAD128": 128,
}


@dataclass(frozen=True)
class CipherSuite:
    code: int
    name: str
    iana_recommended: str
    tls13: bool
    kex: str
    auth: str
    export: bool
    cipher: str
    family: str
    bits: int
    aead: bool
    mac: str

    @property
    def hex(self) -> str:
        return f"0x{self.code:04X}"

    @property
    def forward_secret(self) -> bool:
        return self.tls13 or self.kex in {"DHE", "ECDHE"}

    @property
    def anonymous(self) -> bool:
        return self.auth in {"anon", "NULL"}

    @property
    def block64(self) -> bool:
        return self.family in BLOCK64_FAMILIES

    @property
    def cbc(self) -> bool:
        return "_CBC" in f"_{self.cipher}"

    @property
    def tls12_only(self) -> bool:
        """Suites that cannot be negotiated before TLS 1.2 (AEAD or SHA-2 MAC)."""
        return not self.tls13 and (self.aead or self.mac in {"SHA256", "SHA384"})


def _parse_kex(part: str) -> tuple[str, str, bool]:
    tokens = part.split("_")
    export = "EXPORT" in tokens
    tokens = [t for t in tokens if t != "EXPORT"]
    match tokens:
        case ["NULL"]:
            return "NULL", "NULL", export
        case ["RSA"]:
            return "RSA", "RSA", export
        case ["PSK"]:
            return "PSK", "PSK", export
        case ["PSK", "DHE"]:
            return "DHE", "PSK", export
        case ["RSA", "PSK"]:
            return "RSA", "PSK", export
        case [("DH" | "DHE" | "ECDH" | "ECDHE") as kex, auth]:
            return kex, auth, export
        case ["SRP", "SHA"]:
            return "SRP", "SRP", export
        case ["SRP", "SHA", auth]:
            return "SRP", auth, export
        case ["KRB5"]:
            return "KRB5", "KRB5", export
        case ["GOSTR341112", "256"]:
            return "GOST", "GOST", export
        case _:
            return tokens[0], tokens[0], export


def _parse_cipher(part: str) -> tuple[str, str, int, bool, str]:
    """Split '<cipher>_<mac>' into (cipher, family, bits, aead, mac)."""
    tokens = part.split("_")
    mac = ""
    if len(tokens) > 1 and tokens[-1] in MAC_TOKENS:
        mac = tokens.pop()
    cipher = "_".join(tokens)
    family = tokens[0]
    if family == "28147":
        family = "GOST28147"
    if family in {"NULL", "SHA256", "SHA384"}:
        # NULL_* suites and the TLS 1.3 integrity-only suites (RFC 9150).
        return "NULL", "NULL", 0, False, mac or family
    aead = family in AEAD_FAMILIES or any(t in AEAD_TOKENS for t in tokens)
    numeric = [t.rstrip("L") for t in tokens[1:] if t.rstrip("L").isdigit()]
    bits = int(numeric[0]) if numeric else FAMILY_BITS.get(family, 0)
    return cipher, family, bits, aead, ("AEAD" if aead else mac)


def parse_suite(code: int, name: str, recommended: str = "") -> CipherSuite:
    body = name.removeprefix("TLS_")
    if "_WITH_" in body:
        kex_part, cipher_part = body.split("_WITH_", 1)
        kex, auth, export = _parse_kex(kex_part)
        tls13 = False
    else:
        # TLS 1.3 suites only name the AEAD and the handshake hash.
        cipher_part, kex, auth, export, tls13 = body, "TLS13", "TLS13", False, True
    cipher, family, bits, aead, mac = _parse_cipher(cipher_part)
    if export and bits > 56:
        bits = 40
    return CipherSuite(code, name, recommended, tls13, kex, auth, export, cipher, family, bits, aead, mac)


@cache
def registry() -> dict[int, CipherSuite]:
    raw = json.loads(files("cifr").joinpath("data", "iana_ciphers.json").read_text())
    return {int(code, 16): parse_suite(int(code, 16), v["name"], v["recommended"]) for code, v in raw.items()}


def by_name(name: str) -> CipherSuite | None:
    return next((s for s in registry().values() if s.name == name), None)
