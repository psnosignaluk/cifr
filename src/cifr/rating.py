"""cifr's primary per-suite rating: Recommended, Secure, Weak or Insecure.

A suite's tier is the worst verdict from three independent sources:

* cifr's own rules, which also use the key exchange strength measured on the wire;
* the IANA registry's "Recommended" column (Y / N / D, where RFC 10015 marks
  RSA, DHE and static (EC)DH key exchange as D, "discouraged");
* ciphersuite.info's per-suite rating (bundled snapshot, MIT licence).

Every downgrade is recorded as a Finding, so the verdict is explainable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import IntEnum
from functools import cache
from importlib.resources import files

from cifr.kex import KeyExchange
from cifr.suites import CipherSuite


class Tier(IntEnum):
    RECOMMENDED = 0
    SECURE = 1
    WEAK = 2
    INSECURE = 3

    @property
    def label(self) -> str:
        return self.name.title()


@dataclass(frozen=True)
class Finding:
    tier: Tier
    reason: str
    source: str  # "cifr", "IANA" or "ciphersuite.info"


@dataclass
class SuiteRating:
    tier: Tier
    findings: list[Finding] = field(default_factory=list)
    ciphersuite_info: str | None = None
    iana: str | None = None

    @property
    def reasons(self) -> list[str]:
        """Findings that are not Recommended, worst first."""
        return [f.reason for f in sorted(self.findings, key=lambda f: -f.tier)]


@cache
def ciphersuite_info() -> dict:
    return json.loads(files("cifr").joinpath("data", "ciphersuite_info.json").read_text())


CSINFO_TIERS = {"recommended": Tier.RECOMMENDED, "secure": Tier.SECURE, "weak": Tier.WEAK, "insecure": Tier.INSECURE}
IANA_FINDINGS = {
    "D": Finding(Tier.WEAK, "IANA: discouraged", "IANA"),
    "N": Finding(Tier.SECURE, "IANA: not recommended", "IANA"),
}


def _rule_findings(suite: CipherSuite, kex: KeyExchange | None) -> list[Finding]:
    found: list[tuple[Tier, str]] = []
    if suite.family == "NULL":
        found.append((Tier.INSECURE, "no encryption"))
    if suite.anonymous:
        found.append((Tier.INSECURE, "unauthenticated"))
    if suite.export:
        found.append((Tier.INSECURE, "export-grade"))
    if suite.family == "RC4":
        found.append((Tier.INSECURE, "RC4"))
    if 0 < suite.bits < 112:
        found.append((Tier.INSECURE, f"{suite.bits}-bit cipher"))
    if suite.mac == "MD5":
        found.append((Tier.INSECURE, "MD5 MAC"))
    if kex and 0 < kex.strength < 1024:
        found.append((Tier.INSECURE, f"{kex} key exchange"))
    elif kex and 0 < kex.strength < 2048:
        found.append((Tier.WEAK, f"{kex} key exchange"))
    if suite.block64 and suite.bits >= 112:
        found.append((Tier.WEAK, "64-bit block (SWEET32)"))
    if not suite.forward_secret and not suite.anonymous:
        found.append((Tier.WEAK, "no forward secrecy"))
    if suite.cbc:
        found.append((Tier.WEAK, "CBC mode"))
    if suite.mac == "SHA":
        found.append((Tier.WEAK, "SHA-1 MAC"))
    if suite.cipher.endswith("CCM_8"):
        found.append((Tier.SECURE, "truncated 64-bit tag"))
    return [Finding(tier, reason, "cifr") for tier, reason in found]


def rate_suite(suite: CipherSuite, kex: KeyExchange | None = None) -> SuiteRating:
    findings = _rule_findings(suite, kex)
    if iana := IANA_FINDINGS.get(suite.iana_recommended):
        findings.append(iana)
    tier = max((f.tier for f in findings), default=Tier.RECOMMENDED)

    csinfo = ciphersuite_info()["ratings"].get(suite.name)
    if csinfo in CSINFO_TIERS and CSINFO_TIERS[csinfo] > tier:
        # Only surfaced when ciphersuite.info is stricter, since then it explains the tier.
        tier = CSINFO_TIERS[csinfo]
        findings.append(Finding(tier, f"ciphersuite.info: {csinfo}", "ciphersuite.info"))
    return SuiteRating(tier, findings, csinfo, suite.iana_recommended or None)
