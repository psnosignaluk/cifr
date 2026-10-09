"""Recommend a replacement TLS configuration when a scan finds weaknesses.

The target is a TLSRef Server-Side TLS profile (Intermediate by default, or
Modern), tailored to what the scan observed: suites are limited to the
certificate types the server actually uses, and the projected grade is
recomputed from the suites the server already supports.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field, replace

from cifr import tls, tlsref
from cifr.rating import Tier
from cifr.scanner import AcceptedCipher, ScanResult
from cifr.servergrade import ServerGrade, grade_server
from cifr.suites import CipherSuite, by_name

PROFILES = ("intermediate", "modern")
VERSION_BY_NAME = {name: version for version, name in tls.VERSION_NAMES.items()}
PQ_GROUPS = {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"}


@dataclass
class TargetSuite:
    suite: CipherSuite
    openssl_name: str
    priority: int
    offered: bool  # already accepted by the server


@dataclass
class Recommendation:
    profile: str
    protocols: list[str]
    disable_protocols: list[str]
    enable_protocols: list[str]
    suites: list[TargetSuite]
    remove: list[AcceptedCipher]
    curves: list[str]
    actions: list[str] = field(default_factory=list)  # required changes beyond the suite list
    suggestions: list[str] = field(default_factory=list)  # optional improvements
    projected: ServerGrade | None = None
    projected_tiers: dict[str, int] = field(default_factory=dict)

    @property
    def needed(self) -> bool:
        """True when the configuration must change to meet the profile; suggestions alone don't count."""
        return bool(self.remove or self.disable_protocols or self.enable_protocols or self.actions)

    @property
    def tls12_suites(self) -> list[TargetSuite]:
        return [s for s in self.suites if not s.suite.tls13]

    @property
    def tls13_suites(self) -> list[TargetSuite]:
        return [s for s in self.suites if s.suite.tls13]

    def openssl_ciphers(self) -> str:
        return ":".join(s.openssl_name for s in self.tls12_suites)

    def openssl_ciphersuites(self) -> str:
        return ":".join(s.openssl_name for s in self.tls13_suites)

    def removal_reasons(self) -> Counter:
        """How often each technical weakness (cifr's own findings) occurs among the suites to drop."""
        return Counter(
            f.reason for c in self.remove for f in c.rating.findings if f.tier >= Tier.WEAK and f.source == "cifr"
        )


def _profile_suites(profile: str) -> list[tuple[CipherSuite, str]]:
    """(suite, OpenSSL name) pairs for a profile, in TLSRef priority order."""
    config = tlsref.guidelines()["configurations"][profile]
    pairs = [(name, name) for name in config["ciphersuites"]]
    pairs += zip(config["ciphers"]["iana"], config["ciphers"]["openssl"], strict=True)
    return [(suite, openssl) for name, openssl in pairs if (suite := by_name(name))]


def _server_auth_types(result: ScanResult) -> set[str]:
    """Certificate types in use, from the suites accepted and the certificate seen for TLS <= 1.2."""
    auths = {c.suite.auth for p in result.supported for c in p.ciphers if c.suite.auth in ("RSA", "ECDSA")}
    for p in result.supported:
        if p.certificate and p.certificate.key_type == "rsa":
            auths.add("RSA")
        elif p.certificate and p.certificate.key_type == "ec":
            auths.add("ECDSA")
    return auths or {"RSA", "ECDSA"}


def _certificate_advice(result: ScanResult, profile: str, auths: set[str]) -> tuple[list[str], list[str]]:
    """(required actions, optional suggestions) about the certificate."""
    actions, suggestions = [], []
    certs = [p.certificate for p in result.supported if p.certificate]
    if profile == "modern" and "ECDSA" not in auths:
        actions.append("TLSRef Modern expects an ECDSA certificate (P-256 or P-384); the server presents RSA.")
    elif profile == "intermediate" and auths == {"RSA"}:
        suggestions.append(
            "With only an RSA certificate, the best TLS 1.2 suites rate Secure. Adding an ECDSA P-256 "
            "certificate alongside it lets TLS 1.2 clients use ECDHE-ECDSA suites, which rate Recommended."
        )
    if any(c.key_type == "rsa" and c.key_bits < 2048 for c in certs):
        actions.append("Replace the certificate: its RSA key is under 2048 bits.")
    if any(c.signature_hash in ("md5", "sha1") for c in certs):
        actions.append("Reissue the certificate with a SHA-256 (or stronger) signature.")
    return actions, suggestions


def recommend(result: ScanResult, profile: str = "intermediate") -> Recommendation | None:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; choose from {', '.join(PROFILES)}")
    if not result.supported:
        return None
    config = tlsref.guidelines()["configurations"][profile]
    target_versions = [VERSION_BY_NAME[v] for v in config["tls_versions"]]
    supported = {p.version for p in result.supported}
    accepted = {c.suite.code for p in result.supported for c in p.ciphers}

    auths = _server_auth_types(result)
    suites = [
        TargetSuite(suite, openssl, priority, suite.code in accepted)
        for priority, (suite, openssl) in enumerate(_profile_suites(profile), start=1)
        if suite.tls13 or suite.auth in auths
    ]
    target_codes = {s.suite.code for s in suites}
    # One entry per suite, even if it is accepted on several protocol versions.
    remove = list(
        {c.suite.code: c for p in result.supported for c in p.ciphers if c.suite.code not in target_codes}.values()
    )

    rec = Recommendation(
        profile=profile,
        protocols=config["tls_versions"],
        disable_protocols=[tls.VERSION_NAMES[v] for v in sorted(supported - set(target_versions))],
        enable_protocols=[tls.VERSION_NAMES[v] for v in target_versions if v not in supported],
        suites=suites,
        remove=sorted(remove, key=lambda c: (-c.rating.tier, c.suite.name)),
        curves=config["tls_curves"],
    )
    rec.actions, rec.suggestions = _certificate_advice(result, profile, auths)

    tls13_groups = {str(c.kex) for p in result.supported if p.version == tls.TLS13 for c in p.ciphers if c.kex}
    if tls.TLS13 in supported and not tls13_groups & PQ_GROUPS:
        rec.suggestions.append("Enable X25519MLKEM768 for post-quantum key exchange (needs OpenSSL 3.5+).")

    # Project the outcome from the suites the server already supports.
    kept = [
        replace(p, ciphers=[c for c in p.ciphers if c.suite.code in target_codes])
        for p in result.protocols
        if p.version in target_versions
    ]
    projected = replace(result, protocols=kept)
    if projected.supported:
        rec.projected = grade_server(projected)
        tiers = Counter(c.rating.tier for p in projected.supported for c in p.ciphers)
        rec.projected_tiers = {tier.label: tiers[tier] for tier in Tier if tiers[tier]}
    return rec


def snippets(rec: Recommendation) -> dict[str, str]:
    """Server configuration for the recommendation, keyed by server type."""
    curves = ":".join(rec.curves)
    pq_comment = "drop X25519MLKEM768 if built against OpenSSL < 3.5, or the server will fail to start"
    ciphers, suites13 = rec.openssl_ciphers(), rec.openssl_ciphersuites()
    tls12 = "TLSv1.2" in rec.protocols

    nginx = [f"ssl_protocols {' '.join(rec.protocols)};", f"# {pq_comment}", f"ssl_ecdh_curve {curves};"]
    if tls12:
        nginx.append(f"ssl_ciphers {ciphers};")
    nginx += [f"ssl_conf_command Ciphersuites {suites13};  # nginx 1.19.4+", "ssl_prefer_server_ciphers off;"]

    apache = [
        "SSLProtocol -all " + " ".join(f"+{p}" for p in rec.protocols),
        f"# {pq_comment}",
        f"SSLOpenSSLConfCmd Curves {curves}",
    ]
    if tls12:
        apache.append(f"SSLCipherSuite {ciphers}")
    apache += [f"SSLCipherSuite TLSv1.3 {suites13}", "SSLHonorCipherOrder off"]

    haproxy = ["global", f"    # {pq_comment}", f"    ssl-default-bind-curves {curves}"]
    if tls12:
        haproxy.append(f"    ssl-default-bind-ciphers {ciphers}")
    haproxy += [
        f"    ssl-default-bind-ciphersuites {suites13}",
        f"    ssl-default-bind-options prefer-client-ciphers ssl-min-ver {rec.protocols[0]}",
    ]

    openssl = [
        "[system_default_sect]",
        f"MinProtocol = {rec.protocols[0]}",
        f"# {pq_comment}",
        f"Groups = {curves}",
    ]
    if tls12:
        openssl.append(f"CipherString = {ciphers}")
    openssl.append(f"Ciphersuites = {suites13}")

    return {name: "\n".join(lines) for name, lines in
            {"nginx": nginx, "apache": apache, "haproxy": haproxy, "openssl": openssl}.items()}  # fmt: skip
