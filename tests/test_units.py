import struct

import pytest

from cifr import tls
from cifr.kex import KeyExchange, analyse, ec_to_rsa_bits
from cifr.scanner import TargetError, candidate_suites, parse_target
from cifr.scoring import letter_grade, score_cipher, worst_grade
from cifr.suites import by_name, registry
from cifr.tlsref import Level, compliance, rank


def suite(name):
    s = by_name(name)
    assert s is not None, name
    return s


# --- cipher suite parsing -------------------------------------------------


def test_registry_has_tls13_and_legacy_suites():
    reg = registry()
    assert reg[0x1301].name == "TLS_AES_128_GCM_SHA256"
    assert reg[0xC02F].name == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert 0x00FF not in reg  # SCSV is not a real suite


@pytest.mark.parametrize(
    ("name", "kex", "auth", "family", "bits", "aead", "mac"),
    [
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA", "AES", 128, True, "AEAD"),
        ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", "3DES", 112, False, "SHA"),
        ("TLS_RSA_EXPORT_WITH_RC4_40_MD5", "RSA", "RSA", "RC4", 40, False, "MD5"),
        ("TLS_DH_anon_WITH_AES_256_CBC_SHA", "DH", "anon", "AES", 256, False, "SHA"),
        ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "ECDSA", "CHACHA20", 256, True, "AEAD"),
        ("TLS_RSA_WITH_NULL_SHA256", "RSA", "RSA", "NULL", 0, False, "SHA256"),
        ("TLS_PSK_DHE_WITH_AES_128_CCM_8", "DHE", "PSK", "AES", 128, True, "AEAD"),
        ("TLS_AES_256_GCM_SHA384", "TLS13", "TLS13", "AES", 256, True, "AEAD"),
        ("TLS_SHA256_SHA256", "TLS13", "TLS13", "NULL", 0, False, "SHA256"),
    ],
)
def test_parse_suite(name, kex, auth, family, bits, aead, mac):
    s = suite(name)
    assert (s.kex, s.auth, s.family, s.bits, s.aead, s.mac) == (kex, auth, family, bits, aead, mac)


def test_candidates_exclude_tls12_only_suites_from_older_versions():
    tls10 = {s.name for s in candidate_suites(tls.TLS10)}
    assert "TLS_RSA_WITH_AES_128_CBC_SHA" in tls10
    assert "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" not in tls10
    assert all(s.tls13 for s in candidate_suites(tls.TLS13))


# --- nmap-style scoring ---------------------------------------------------


@pytest.mark.parametrize(
    ("name", "kex", "grade"),
    [
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", KeyExchange("ecdh", 256, "x25519"), "A"),
        ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", KeyExchange("ecdh", 256, "secp256r1"), "A"),
        ("TLS_RSA_WITH_AES_128_CBC_SHA", KeyExchange("rsa", 2048), "A"),
        ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", KeyExchange("rsa", 2048), "C"),
        ("TLS_RSA_WITH_RC4_128_SHA", KeyExchange("rsa", 2048), "C"),
        ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", KeyExchange("dh", 512), "C"),
        ("TLS_DH_anon_WITH_AES_256_CBC_SHA", KeyExchange("dh", 2048), "F"),
        ("TLS_RSA_WITH_NULL_SHA", KeyExchange("rsa", 2048), "F"),
        ("TLS_RSA_EXPORT_WITH_RC4_40_MD5", KeyExchange("rsa", 512), "F"),
    ],
)
def test_score_cipher(name, kex, grade):
    assert score_cipher(suite(name), kex, tls.TLS12).grade == grade


def test_score_formula_matches_nmap():
    # 0.43 * kex(3072 rsa-equivalent -> 0.9) + 0.57 * cipher(128 -> 0.8)
    score = score_cipher(suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"), KeyExchange("ecdh", 256), tls.TLS12)
    assert score.score == pytest.approx(0.843)
    assert [letter_grade(x) for x in (0.8, 0.65, 0.5, 0.35, 0.2, 0.1)] == list("ABCDEF")


def test_unknown_kex_is_unknown_unless_capped():
    assert score_cipher(suite("TLS_PSK_WITH_AES_128_GCM_SHA256"), None, tls.TLS12).grade == "unknown"
    assert score_cipher(suite("TLS_PSK_WITH_NULL_SHA"), None, tls.TLS12).grade == "F"


def test_worst_grade():
    assert worst_grade(["A", "C", "unknown", "B"]) == "C"
    assert worst_grade(["unknown"]) is None


def test_ec_rsa_equivalence():
    assert ec_to_rsa_bits(256) == 3072
    assert ec_to_rsa_bits(384) == 7680
    assert ec_to_rsa_bits(521) == 15360


# --- TLSRef ranking -------------------------------------------------------


def test_tlsref_rank():
    assert rank(suite("TLS_AES_128_GCM_SHA256")).level is Level.MODERN
    assert rank(suite("TLS_AES_128_GCM_SHA256")).priority == 1
    assert rank(suite("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")).priority == 9
    assert rank(suite("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")) is None


def test_tlsref_compliance():
    good = {tls.TLS13: [suite("TLS_AES_128_GCM_SHA256")]}
    assert compliance("modern", good, []).compliant
    mixed = {**good, tls.TLS12: [suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")]}
    assert not compliance("modern", mixed, []).compliant
    assert compliance("intermediate", mixed, []).compliant
    weak_dh = compliance("intermediate", mixed, [1024])
    assert weak_dh.dh_bits == 1024 and not weak_dh.compliant


# --- wire format ----------------------------------------------------------


def test_client_hello_structure():
    record = tls.build_client_hello(tls.TLS12, [0xC02F, 0x002F], "example.com")
    ctype, rec_version, rec_len = struct.unpack_from("!BHH", record)
    assert (ctype, rec_version, rec_len) == (22, tls.TLS10, len(record) - 5)
    assert record[5] == tls.HS_CLIENT_HELLO
    assert int.from_bytes(record[6:9]) == len(record) - 9
    assert struct.unpack_from("!H", record, 9)[0] == tls.TLS12
    assert b"example.com" in record


@pytest.mark.parametrize("count", [1, 20, 60, 120])
def test_client_hello_avoids_256_to_511_byte_handshakes(count):
    record = tls.build_client_hello(tls.TLS12, list(range(1, count + 1)), "example.com")
    assert not 256 <= len(record) - 5 < 512


def test_client_hello_omits_sni_for_ip_and_extensions_for_sslv3():
    assert b"\x00\x00\x00" not in tls.build_client_hello(tls.TLS12, [0x2F], "192.0.2.1")[43:50]
    sslv3 = tls.build_client_hello(tls.SSL3, [0x2F], "example.com")
    assert b"example.com" not in sslv3
    assert struct.unpack_from("!H", sslv3, 1)[0] == tls.SSL3


def _offered_groups(record: bytes) -> list[int]:
    """Pull the supported_groups extension out of a ClientHello record."""
    pos = 5 + 4 + 2 + 32
    pos += 1 + record[pos]  # session id
    pos += 2 + struct.unpack_from("!H", record, pos)[0]  # cipher suites
    pos += 1 + record[pos]  # compression methods
    end = pos + 2 + struct.unpack_from("!H", record, pos)[0]
    pos += 2
    while pos < end:
        ext_type, ext_len = struct.unpack_from("!HH", record, pos)
        if ext_type == tls.EXT_SUPPORTED_GROUPS:
            data = record[pos + 6 : pos + 4 + ext_len]
            return [struct.unpack_from("!H", data, i)[0] for i in range(0, len(data), 2)]
        pos += 4 + ext_len
    return []


def test_hybrid_pq_groups_only_offered_for_tls13():
    tls13 = _offered_groups(tls.build_client_hello(tls.TLS13, [0x1301], "example.com"))
    tls12 = _offered_groups(tls.build_client_hello(tls.TLS12, [0xC02F], "example.com"))
    tls10 = _offered_groups(tls.build_client_hello(tls.TLS10, [0xC013], "example.com"))
    assert 0x11EC in tls13
    assert 29 in tls12 and not set(tls12) & set(tls.HYBRID_CLASSICAL)
    assert 256 in tls12 and not [g for g in tls10 if g >= 256]


def _server_hello(version, cipher, random=b"\x11" * 32, exts=b""):
    body = struct.pack("!H", version) + random + b"\x00" + struct.pack("!HB", cipher, 0)
    return body + (struct.pack("!H", len(exts)) + exts if exts else b"")


def test_parse_server_hello_tls13_and_hrr():
    exts = struct.pack("!HHH", 43, 2, tls.TLS13) + struct.pack("!HHH", 51, 2, 0x11EC)
    sh = tls.parse_server_hello(_server_hello(tls.TLS12, 0x1301, tls.HRR_RANDOM, exts))
    assert (sh.version, sh.cipher, sh.group, sh.hello_retry) == (tls.TLS13, 0x1301, 0x11EC, True)
    sh12 = tls.parse_server_hello(_server_hello(tls.TLS12, 0xC02F))
    assert (sh12.version, sh12.cipher, sh12.hello_retry) == (tls.TLS12, 0xC02F, False)


def test_analyse_server_key_exchange():
    hello = tls.ServerHello(tls.TLS12, 0, 0)
    ecdhe = b"\x03" + struct.pack("!H", 23) + b"\x41" + b"\x04" * 65
    assert str(analyse(suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"), hello, ecdhe, None)) == "secp256r1"
    prime = (1 << 1023 | 1).to_bytes(128)
    dhe = struct.pack("!H", len(prime)) + prime + b"\x00\x01\x02"
    kx = analyse(suite("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"), hello, dhe, None)
    assert (kx.kind, kx.bits) == ("dh", 1024)
    psk = b"\x00\x02hi" + dhe
    assert analyse(suite("TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"), hello, psk, None).bits == 1024
    tls13 = tls.ServerHello(tls.TLS13, 0x1301, 0, group=29)
    assert analyse(suite("TLS_AES_128_GCM_SHA256"), tls13, None, None).strength == 3072


# --- target parsing -------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "port", "expected"),
    [
        ("example.com", None, ("example.com", 443)),
        ("example.com:8443", None, ("example.com", 8443)),
        ("https://example.com/path", None, ("example.com", 443)),
        ("https://example.com:9443/", None, ("example.com", 9443)),
        ("192.0.2.10", 8443, ("192.0.2.10", 8443)),
        ("192.0.2.10:993", None, ("192.0.2.10", 993)),
        ("2001:db8::1", None, ("2001:db8::1", 443)),
        ("[2001:db8::1]:8443", None, ("2001:db8::1", 8443)),
        ("example.com:8443", 443, ("example.com", 443)),
    ],
)
def test_parse_target(raw, port, expected):
    assert parse_target(raw, port) == expected


@pytest.mark.parametrize("raw", ["bad_host!", "example.com:99999", "-leading.example"])
def test_parse_target_rejects_invalid(raw):
    with pytest.raises(TargetError):
        parse_target(raw)
