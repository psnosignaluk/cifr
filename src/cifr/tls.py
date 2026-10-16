"""Minimal raw TLS handshake client.

cifr crafts its own ClientHello messages rather than using the ssl module so it
can offer any cipher suite on any protocol version (including SSLv3, export and
NULL suites that a modern OpenSSL refuses to send). Only the server's plaintext
first flight is read: ServerHello, and for TLS <= 1.2 the Certificate and
ServerKeyExchange, which reveal the key exchange strength.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import struct
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SSL3, TLS10, TLS11, TLS12, TLS13 = 0x0300, 0x0301, 0x0302, 0x0303, 0x0304
VERSION_NAMES = {SSL3: "SSLv3", TLS10: "TLSv1.0", TLS11: "TLSv1.1", TLS12: "TLSv1.2", TLS13: "TLSv1.3"}

CONTENT_ALERT, CONTENT_HANDSHAKE = 21, 22
HS_CLIENT_HELLO, HS_SERVER_HELLO, HS_CERTIFICATE, HS_SERVER_KEY_EXCHANGE, HS_SERVER_HELLO_DONE = 1, 2, 11, 12, 14

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_PADDING = 21
EXT_EXTENDED_MASTER_SECRET = 23
EXT_SESSION_TICKET = 35
EXT_SUPPORTED_VERSIONS = 43
EXT_PSK_KEY_EXCHANGE_MODES = 45
EXT_KEY_SHARE = 51
EXT_RENEGOTIATION_INFO = 0xFF01

HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
    42: "bad_certificate", 47: "illegal_parameter", 50: "decode_error", 51: "decrypt_error",
    70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
    86: "inappropriate_fallback", 90: "user_canceled", 109: "missing_extension",
    112: "unrecognized_name", 120: "no_application_protocol",
}  # fmt: skip

GROUP_NAMES = {
    1: "sect163k1", 2: "sect163r1", 3: "sect163r2", 4: "sect193r1", 5: "sect193r2", 6: "sect233k1",
    7: "sect233r1", 8: "sect239k1", 9: "sect283k1", 10: "sect283r1", 11: "sect409k1", 12: "sect409r1",
    13: "sect571k1", 14: "sect571r1", 15: "secp160k1", 16: "secp160r1", 17: "secp160r2", 18: "secp192k1",
    19: "secp192r1", 20: "secp224k1", 21: "secp224r1", 22: "secp256k1", 23: "secp256r1", 24: "secp384r1",
    25: "secp521r1", 26: "brainpoolP256r1", 27: "brainpoolP384r1", 28: "brainpoolP512r1", 29: "x25519",
    30: "x448", 256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096", 259: "ffdhe6144", 260: "ffdhe8192",
    0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
}  # fmt: skip
# Hybrid post-quantum groups are rated by their classical component.
HYBRID_CLASSICAL = {0x11EB: 23, 0x11EC: 29, 0x11ED: 24}
GROUP_ORDER = [0x11EC, 29, 23, 24, 25, 30, 26, 27, 28, 256, 257, 258, 259, 260, 22, 21, 20, 19, 18, 15, 16, 17,
               *range(1, 15)]  # fmt: skip

SIGNATURE_ALGORITHMS = [
    0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806, 0x0809, 0x080A, 0x080B,
    0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602, 0x0203, 0x0201, 0x0202,
]  # fmt: skip

MAX_READ = 256 * 1024


def group_bits(group: int) -> int:
    """Field size in bits of a named group, before any RSA-equivalence mapping."""
    group = HYBRID_CLASSICAL.get(group, group)
    name = GROUP_NAMES.get(group, "")
    if name == "x25519":
        return 256
    if m := re.search(r"(\d{3,4})", name):
        return int(m.group(1))
    return 0


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _u8(n: int) -> bytes:
    return struct.pack("!B", n)


def _u16(n: int) -> bytes:
    return struct.pack("!H", n)


def _u24(n: int) -> bytes:
    return struct.pack("!I", n)[1:]


def _vec16(data: bytes) -> bytes:
    return _u16(len(data)) + data


def _ext(ext_type: int, data: bytes) -> bytes:
    return _u16(ext_type) + _vec16(data)


def offered_groups(version: int) -> list[int]:
    """Groups to advertise for `version`.

    Hybrid ML-KEM groups are TLS 1.3-only and must not be offered for TLS 1.2
    (strict servers such as CloudFront abort the handshake if they are), and
    FFDHE groups are only advertised from TLS 1.2.
    """
    if version >= TLS13:
        return GROUP_ORDER
    if version == TLS12:
        return [g for g in GROUP_ORDER if g not in HYBRID_CLASSICAL]
    return [g for g in GROUP_ORDER if g < 256]


def build_client_hello(version: int, ciphers: list[int], sni: str | None = None) -> bytes:
    """Build a complete ClientHello record offering `ciphers` for `version`."""
    tls13 = version == TLS13
    legacy_version = min(version, TLS12)
    session_id = os.urandom(32) if tls13 else b""

    body = _u16(legacy_version) + os.urandom(32) + _u8(len(session_id)) + session_id
    body += _vec16(b"".join(_u16(c) for c in ciphers))
    body += _u8(1) + _u8(0)  # compression: null only

    if version >= TLS10:
        exts = []
        if sni and not is_ip(sni):
            name = sni.encode("idna")
            exts.append(_ext(EXT_SERVER_NAME, _vec16(_u8(0) + _vec16(name))))
        groups = offered_groups(version)
        exts.append(_ext(EXT_SUPPORTED_GROUPS, _vec16(b"".join(_u16(g) for g in groups))))
        exts.append(_ext(EXT_EC_POINT_FORMATS, b"\x03\x00\x01\x02"))
        if version >= TLS12:
            exts.append(_ext(EXT_SIGNATURE_ALGORITHMS, _vec16(b"".join(_u16(s) for s in SIGNATURE_ALGORITHMS))))
        exts.append(_ext(EXT_RENEGOTIATION_INFO, b"\x00"))
        exts.append(_ext(EXT_EXTENDED_MASTER_SECRET, b""))
        exts.append(_ext(EXT_SESSION_TICKET, b""))
        if tls13:
            exts.append(_ext(EXT_SUPPORTED_VERSIONS, b"\x02" + _u16(TLS13)))
            exts.append(_ext(EXT_PSK_KEY_EXCHANGE_MODES, b"\x01\x01"))
            pub = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            exts.append(_ext(EXT_KEY_SHARE, _vec16(_u16(29) + _vec16(pub))))
        ext_bytes = b"".join(exts)
        # Some middleboxes hang on ClientHellos of 256-511 bytes (RFC 7685).
        hello_len = 4 + len(body) + 2 + len(ext_bytes)
        if 256 <= hello_len < 512:
            ext_bytes += _ext(EXT_PADDING, b"\x00" * max(0, 512 - hello_len - 4))
        body += _vec16(ext_bytes)

    handshake = _u8(HS_CLIENT_HELLO) + _u24(len(body)) + body
    record_version = SSL3 if version == SSL3 else TLS10
    return _u8(CONTENT_HANDSHAKE) + _u16(record_version) + _u16(len(handshake)) + handshake


@dataclass
class ServerHello:
    version: int
    cipher: int
    compression: int
    hello_retry: bool = False
    group: int | None = None


@dataclass
class HandshakeResult:
    server_hello: ServerHello | None = None
    alert: str | None = None
    certificates: list[bytes] = field(default_factory=list)
    server_key_exchange: bytes | None = None
    error: str | None = None
    timed_out: bool = False


def parse_server_hello(data: bytes) -> ServerHello:
    version = struct.unpack_from("!H", data, 0)[0]
    random = data[2:34]
    sid_len = data[34]
    pos = 35 + sid_len
    cipher, compression = struct.unpack_from("!HB", data, pos)
    pos += 3
    hello = ServerHello(version, cipher, compression, hello_retry=random == HRR_RANDOM)
    if pos + 2 <= len(data):
        end = pos + 2 + struct.unpack_from("!H", data, pos)[0]
        pos += 2
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack_from("!HH", data, pos)
            ext = data[pos + 4 : pos + 4 + ext_len]
            if ext_type == EXT_SUPPORTED_VERSIONS and len(ext) >= 2:
                hello.version = struct.unpack_from("!H", ext)[0]
            elif ext_type == EXT_KEY_SHARE and len(ext) >= 2:
                hello.group = struct.unpack_from("!H", ext)[0]
            pos += 4 + ext_len
    return hello


def parse_certificates(data: bytes) -> list[bytes]:
    # Bound the walk by the bytes actually received: a server can declare a list
    # length of up to 16 MB, and zero-length entries would otherwise loop millions of times.
    end = min(3 + int.from_bytes(data[0:3]), len(data))
    pos, certs = 3, []
    while pos + 3 <= end:
        length = int.from_bytes(data[pos : pos + 3])
        if length == 0 or pos + 3 + length > end:
            break
        certs.append(data[pos + 3 : pos + 3 + length])
        pos += 3 + length
    return certs


class _RecordReader:
    def __init__(self, sock: socket.socket, deadline: float):
        self.sock, self.deadline, self.buf, self.total = sock, deadline, b"", 0

    def _fill(self, n: int) -> bool:
        while len(self.buf) < n:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or self.total > MAX_READ:
                raise TimeoutError("timed out reading server response")
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(16384)
            if not chunk:
                return False
            self.buf += chunk
            self.total += len(chunk)
        return True

    def record(self) -> tuple[int, int, bytes] | None:
        if not self._fill(5):
            return None
        ctype, version, length = struct.unpack_from("!BHH", self.buf)
        if ctype not in (20, 21, 22, 23) or length > 18432:
            raise ValueError("response is not TLS")
        if not self._fill(5 + length):
            return None
        payload, self.buf = self.buf[5 : 5 + length], self.buf[5 + length :]
        return ctype, version, payload


def handshake(address: tuple, hello: bytes, timeout: float, full_flight: bool = True) -> HandshakeResult:
    """Send a ClientHello and collect the server's plaintext response.

    With `full_flight`, keep reading after a TLS <= 1.2 ServerHello until
    ServerHelloDone so the certificate and key exchange can be inspected.
    """
    result = HandshakeResult()
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection(address, timeout=timeout) as sock:
            sock.sendall(hello)
            reader = _RecordReader(sock, deadline)
            hs_buf = b""
            while (rec := reader.record()) is not None:
                ctype, _, payload = rec
                if ctype == CONTENT_ALERT:
                    if len(payload) >= 2:
                        result.alert = ALERTS.get(payload[1], f"alert {payload[1]}")
                    return result
                if ctype != CONTENT_HANDSHAKE:
                    return result
                hs_buf += payload
                while len(hs_buf) >= 4:
                    msg_type, length = hs_buf[0], int.from_bytes(hs_buf[1:4])
                    if len(hs_buf) < 4 + length:
                        break
                    msg, hs_buf = hs_buf[4 : 4 + length], hs_buf[4 + length :]
                    if msg_type == HS_SERVER_HELLO:
                        result.server_hello = parse_server_hello(msg)
                        sh = result.server_hello
                        if not full_flight or sh.version >= TLS13 or sh.hello_retry:
                            return result
                    elif msg_type == HS_CERTIFICATE:
                        result.certificates = parse_certificates(msg)
                    elif msg_type == HS_SERVER_KEY_EXCHANGE:
                        result.server_key_exchange = msg
                    elif msg_type == HS_SERVER_HELLO_DONE:
                        return result
    except TimeoutError:
        result.error, result.timed_out = "timed out", True
    except (OSError, ValueError, struct.error, IndexError) as exc:
        result.error = str(exc) or exc.__class__.__name__
    return result
