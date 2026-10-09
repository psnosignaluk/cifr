"""Cipher suite ranking from the TLSRef Server-Side TLS guidelines.

TLSRef (https://docs.tlsref.org/cipher-suites.html) ranks suites into two
compatibility levels, Modern (priority 1-3) and Intermediate (priority 4-9).
Every other suite is unlisted; cifr's own rating (rating.py) covers those.

The guidelines are bundled from https://data.tlsref.org/guidelines/latest.json.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from functools import cache
from importlib.resources import files

from cifr.suites import CipherSuite
from cifr.tls import VERSION_NAMES


class Level(Enum):
    MODERN = "Modern"
    INTERMEDIATE = "Intermediate"


@dataclass(frozen=True)
class Ranking:
    level: Level
    priority: int | None


@cache
def guidelines() -> dict:
    return json.loads(files("cifr").joinpath("data", "tlsref_guidelines.json").read_text())


def _level_suites(level: str) -> list[str]:
    config = guidelines()["configurations"][level]
    return config["ciphersuites"] + config["ciphers"]["iana"]


@cache
def _priorities() -> dict[str, Ranking]:
    modern = set(_level_suites("modern"))
    return {
        name: Ranking(Level.MODERN if name in modern else Level.INTERMEDIATE, priority)
        for priority, name in enumerate(_level_suites("intermediate"), start=1)
    }


def rank(suite: CipherSuite) -> Ranking | None:
    """TLSRef level and priority, or None if TLSRef doesn't list the suite."""
    return _priorities().get(suite.name)


def version_label() -> str:
    return f"TLSRef guidelines v{guidelines()['version']}"


@dataclass
class Compliance:
    level: str
    protocols: list[str]
    suites: list[str]
    dh_bits: int | None

    @property
    def compliant(self) -> bool:
        return not (self.protocols or self.suites or self.dh_bits)

    def summary(self) -> list[str]:
        issues = [f"{p} enabled" for p in self.protocols]
        if self.suites:
            issues.append(f"{len(self.suites)} cipher suite(s) outside {self.level.title()}")
        if self.dh_bits:
            issues.append(f"{self.dh_bits}-bit DH parameters")
        return issues


def compliance(level: str, protocols: dict[int, list[CipherSuite]], dh_bits: list[int]) -> Compliance:
    """Compare an observed configuration with a TLSRef level.

    `protocols` maps each supported protocol version to its accepted suites.
    """
    config = guidelines()["configurations"][level]
    allowed = set(_level_suites(level))
    bad_protocols = [VERSION_NAMES[v] for v in sorted(protocols) if VERSION_NAMES[v] not in config["tls_versions"]]
    bad_suites = sorted({s.name for suites in protocols.values() for s in suites} - allowed)
    weak_dh = min(dh_bits) if dh_bits and config["dh_param_size"] and min(dh_bits) < config["dh_param_size"] else None
    return Compliance(level, bad_protocols, bad_suites, weak_dh)
