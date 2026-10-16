"""Cipher suite enumeration, in the style of nmap's ssl-enum-ciphers.

For each protocol version the candidate suites are offered in chunks. Each
time the server picks a suite it is removed from the offer and the handshake
is repeated, until the server refuses. The accepted suites are then offered
together repeatedly to discover the server's preference order.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from cifr import tls
from cifr.kex import CertificateInfo, KeyExchange, analyse, parse_certificate
from cifr.rating import SuiteRating, rate_suite
from cifr.scoring import CipherScore, score_cipher
from cifr.suites import CipherSuite, registry
from cifr.tlsref import Ranking, rank

CHUNK_SIZE = 64
RETRIES = 2
# Alerts that point at the ClientHello's format or extensions rather than at the offered suites.
MALFORMED_HELLO_ALERTS = {
    "close_notify", "unexpected_message", "decode_error", "illegal_parameter", "internal_error", "missing_extension",
}  # fmt: skip
PROTOCOLS = [tls.SSL3, tls.TLS10, tls.TLS11, tls.TLS12, tls.TLS13]

Progress = Callable[[str], None]


class TargetError(ValueError):
    pass


@dataclass
class Target:
    host: str
    port: int
    address: tuple
    sni: str | None

    @property
    def ip(self) -> str:
        return self.address[0]


@dataclass
class AcceptedCipher:
    suite: CipherSuite
    kex: KeyExchange | None
    score: CipherScore
    rating: SuiteRating
    ranking: Ranking | None


@dataclass
class ProtocolResult:
    version: int
    ciphers: list[AcceptedCipher] = field(default_factory=list)
    preference: str = "indeterminate"
    certificate: CertificateInfo | None = None
    warnings: list[str] = field(default_factory=list)
    # Set when the server rejected cifr's ClientHello itself rather than the offered suites,
    # so "not supported" may be wrong.
    inconclusive: str | None = None

    @property
    def name(self) -> str:
        return tls.VERSION_NAMES[self.version]

    @property
    def supported(self) -> bool:
        return bool(self.ciphers)


@dataclass
class ScanResult:
    target: Target
    protocols: list[ProtocolResult]

    @property
    def supported(self) -> list[ProtocolResult]:
        return [p for p in self.protocols if p.supported]


_HOST_PORT = re.compile(r"^\[(?P<v6>[^\]]+)\](?::(?P<v6port>\d+))?$|^(?P<host>[^:]+)(?::(?P<port>\d+))?$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$", re.IGNORECASE
)


def parse_target(raw: str, port: int | None = None) -> tuple[str, int]:
    """Accept 'host', 'host:port', '[v6]:port', a bare IP or a URL."""
    raw = raw.strip()
    if "://" in raw:
        raw = urlsplit(raw).netloc
    raw = raw.rsplit("@", 1)[-1].split("/", 1)[0]
    if tls.is_ip(raw):  # bare IPv4/IPv6 address
        return raw, port or 443
    m = _HOST_PORT.match(raw)
    if not m:
        raise TargetError(f"invalid target: {raw!r}")
    host = m["v6"] or m["host"]
    embedded = m["v6port"] or m["port"]
    if not (tls.is_ip(host) or _HOSTNAME.match(host)):
        raise TargetError(f"invalid hostname or IP address: {host!r}")
    resolved_port = port or (int(embedded) if embedded else 443)
    if not 0 < resolved_port < 65536:
        raise TargetError(f"invalid port: {resolved_port}")
    return host.rstrip("."), resolved_port


def parse_sni(raw: str | None) -> str | None:
    """Check an explicit --sni value. None means the default; an empty string sends no SNI."""
    if not raw or tls.is_ip(raw):
        return raw
    try:
        name = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetError(f"invalid SNI name: {raw!r}") from exc
    if not _HOSTNAME.match(name):
        raise TargetError(f"invalid SNI name: {raw!r}")
    return raw.rstrip(".")


def resolve(host: str, port: int, sni: str | None, timeout: float) -> Target:
    try:
        info = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetError(f"could not resolve {host}: {exc.strerror}") from exc
    address = info[0][4][:2]
    try:
        socket.create_connection(address, timeout=timeout).close()
    except OSError as exc:
        raise TargetError(f"could not connect to {address[0]} port {port}: {exc.strerror or exc}") from exc
    return Target(host, port, address, sni if sni is not None else (None if tls.is_ip(host) else host))


# Offer the most widely deployed suites first, so the first chunk doubles as a
# probe for whether the protocol version is supported at all.
KEX_POPULARITY = {"TLS13": 0, "ECDHE": 0, "DHE": 1, "RSA": 2, "ECDH": 3, "DH": 4}


def candidate_suites(version: int) -> list[CipherSuite]:
    suites = registry().values()
    if version == tls.TLS13:
        suites = [s for s in suites if s.tls13]
    else:
        suites = [s for s in suites if not s.tls13 and (version == tls.TLS12 or not s.tls12_only)]
    return sorted(suites, key=lambda s: (s.auth == "PSK", KEX_POPULARITY.get(s.kex, 5), not s.aead))


class _ProtocolScanner:
    def __init__(self, target: Target, version: int, timeout: float, limiter: threading.Semaphore):
        self.target, self.version, self.timeout, self.limiter = target, version, timeout, limiter

    def handshake(self, codes: list[int], retry_timeouts: bool = True) -> tls.HandshakeResult:
        """Run one handshake, retrying transient failures (resets, throttling) with backoff."""
        hello = tls.build_client_hello(self.version, codes, self.target.sni)
        for attempt in range(RETRIES + 1):
            with self.limiter:
                result = tls.handshake(self.target.address, hello, self.timeout)
            if result.server_hello or result.alert or not result.error:
                break
            if result.timed_out and not retry_timeouts:
                break
            time.sleep(0.5 * (attempt + 1))
        return result

    def offer(self, codes: list[int]) -> tls.HandshakeResult | None:
        """Offer `codes`; return the result if the server picked one of them."""
        result = self.handshake(codes)
        sh = result.server_hello
        if sh is None or sh.version != self.version or sh.cipher not in codes:
            return None
        return result

    def probe(self, codes: list[int]) -> tuple[bool, str | None]:
        """Cheap first check: rule the version out on a version alert, downgrade or silence.

        Also returns the alert the server sent, if any.
        """
        result = self.handshake(codes, retry_timeouts=False)
        if result.server_hello:
            return result.server_hello.version == self.version, None
        return result.alert not in (None, "protocol_version"), result.alert

    def enumerate_chunk(self, codes: list[int]) -> dict[int, tls.HandshakeResult]:
        accepted, remaining = {}, list(codes)
        while remaining and (result := self.offer(remaining)):
            accepted[result.server_hello.cipher] = result
            remaining.remove(result.server_hello.cipher)
        return accepted

    def preference_order(self, codes: list[int]) -> tuple[list[int], str]:
        if len(codes) < 2:
            return codes, "indeterminate"
        order, remaining = [], list(codes)
        while remaining and (result := self.offer(remaining)):
            order.append(result.server_hello.cipher)
            remaining.remove(result.server_hello.cipher)
        order += [c for c in codes if c not in order]
        reverse = self.offer(list(reversed(order)))
        if reverse is None:
            return order, "indeterminate"
        return order, "server" if reverse.server_hello.cipher == order[0] else "client"


def scan_protocol(
    target: Target,
    version: int,
    timeout: float,
    limiter: threading.Semaphore,
    progress: Progress | None = None,
) -> ProtocolResult:
    scanner = _ProtocolScanner(target, version, timeout, limiter)
    candidates = [s.code for s in candidate_suites(version)]
    chunks = [candidates[i : i + CHUNK_SIZE] for i in range(0, len(candidates), CHUNK_SIZE)]
    result = ProtocolResult(version)
    plausible, alert = scanner.probe(chunks[0])
    if not plausible:
        return result

    with ThreadPoolExecutor(max_workers=len(chunks)) as pool:
        accepted: dict[int, tls.HandshakeResult] = {}
        for found in pool.map(scanner.enumerate_chunk, chunks):
            accepted.update(found)
    if not accepted:
        if alert in MALFORMED_HELLO_ALERTS:
            result.inconclusive = (
                f"every {result.name} ClientHello was refused with a {alert} alert rather than "
                "handshake_failure; the server may be rejecting cifr's ClientHello, not the cipher suites"
            )
        return result
    if progress:
        progress(f"{result.name}: {len(accepted)} cipher suites accepted, checking preference order")

    order, result.preference = scanner.preference_order(list(accepted))
    certs = [parse_certificate(r.certificates[0]) for r in accepted.values() if r.certificates]
    result.certificate = next((c for c in certs if c), None)

    for code in order:
        hs = accepted[code]
        suite = registry()[code]
        cert = parse_certificate(hs.certificates[0]) if hs.certificates else None
        kex = analyse(suite, hs.server_hello, hs.server_key_exchange, cert)
        score = score_cipher(suite, kex, version, cert)
        result.ciphers.append(AcceptedCipher(suite, kex, score, rate_suite(suite, kex), rank(suite)))

    if result.preference == "client":
        result.warnings.append("Server does not enforce a cipher preference order (client order used)")
        result.ciphers.sort(key=lambda c: (c.rating.tier, -(c.score.score or 0)))
    if version == tls.SSL3:
        result.warnings.append("SSLv3 is insecure and prohibited by RFC 7568 (POODLE)")
    elif version in (tls.TLS10, tls.TLS11):
        result.warnings.append(f"{result.name} is deprecated by RFC 8996")
    if version != tls.TLS13 and not any(c.suite.forward_secret for c in result.ciphers):
        result.warnings.append("Forward secrecy not supported by any cipher")
    return result


def scan(target: Target, timeout: float = 5.0, concurrency: int = 8, progress: Progress | None = None) -> ScanResult:
    """Scan every protocol version, with at most `concurrency` connections open at once."""
    limiter = threading.Semaphore(concurrency)

    def run(version: int) -> ProtocolResult:
        res = scan_protocol(target, version, timeout, limiter, progress)
        if progress:
            progress(f"{res.name}: {'supported' if res.supported else 'not supported'}")
        return res

    with ThreadPoolExecutor(max_workers=len(PROTOCOLS)) as pool:
        protocols = list(pool.map(run, PROTOCOLS))
    return ScanResult(target, protocols)
