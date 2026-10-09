import pytest
from conftest import RSA2048, X25519, make_result

from cifr import tls
from cifr.kex import CertificateInfo, KeyExchange
from cifr.rating import Tier, rate_suite
from cifr.servergrade import grade_server
from cifr.suites import by_name

# --- per-suite rating -----------------------------------------------------


@pytest.mark.parametrize(
    ("name", "kex", "tier"),
    [
        ("TLS_AES_128_GCM_SHA256", X25519, Tier.RECOMMENDED),
        ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", X25519, Tier.RECOMMENDED),
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", X25519, Tier.SECURE),  # ciphersuite.info: secure
        ("TLS_AES_128_CCM_8_SHA256", X25519, Tier.SECURE),
        ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", X25519, Tier.WEAK),
        ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", KeyExchange("dh", 2048), Tier.WEAK),
        ("TLS_RSA_WITH_AES_256_GCM_SHA384", RSA2048, Tier.WEAK),
        ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", RSA2048, Tier.WEAK),
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", KeyExchange("ecdh", 160, "secp160r1"), Tier.WEAK),
        ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", KeyExchange("dh", 512), Tier.INSECURE),
        ("TLS_RSA_WITH_RC4_128_SHA", RSA2048, Tier.INSECURE),
        ("TLS_DH_anon_WITH_AES_256_GCM_SHA384", KeyExchange("dh", 2048), Tier.INSECURE),
        ("TLS_RSA_WITH_NULL_SHA256", RSA2048, Tier.INSECURE),
        ("TLS_RSA_WITH_DES_CBC_SHA", RSA2048, Tier.INSECURE),
        ("TLS_SM4_GCM_SM3", X25519, Tier.INSECURE),  # only ciphersuite.info objects
    ],
)
def test_rate_suite(name, kex, tier):
    assert rate_suite(by_name(name), kex).tier is tier


def test_rating_explains_itself():
    rating = rate_suite(by_name("TLS_RSA_WITH_AES_128_CBC_SHA"), RSA2048)
    assert {"no forward secrecy", "CBC mode", "SHA-1 MAC", "IANA: discouraged"} <= set(rating.reasons)
    assert rating.ciphersuite_info == "weak"
    sm4 = rate_suite(by_name("TLS_SM4_GCM_SM3"), X25519)
    assert [f.source for f in sm4.findings if f.tier is Tier.INSECURE] == ["ciphersuite.info"]


def test_suites_missing_from_ciphersuite_info_use_rules_only():
    rating = rate_suite(by_name("TLS_AEGIS_256_SHA512"), X25519)
    assert rating.ciphersuite_info is None
    assert rating.tier is Tier.SECURE  # IANA "N"


# --- SSL Labs-style server grade ------------------------------------------


MODERN_12 = [("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", X25519), ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", X25519)]
MODERN_13 = [("TLS_AES_128_GCM_SHA256", X25519), ("TLS_AES_256_GCM_SHA384", X25519)]


def test_modern_server_grades_a():
    grade = grade_server(make_result({tls.TLS12: MODERN_12, tls.TLS13: MODERN_13}))
    assert grade.grade == "A"
    assert grade.score == 93  # 0.3*100 + 0.3*90 (2048-bit cert) + 0.4*90


def test_no_tls13_caps_at_a_minus():
    assert grade_server(make_result({tls.TLS12: MODERN_12})).grade == "A-"


def test_tls10_caps_at_b():
    grade = grade_server(
        make_result({tls.TLS10: [("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", X25519)], tls.TLS12: MODERN_12})
    )
    assert grade.grade == "B"
    assert any("TLS 1.0/1.1" in rule for rule in grade.caps)


def test_3des_with_tls11_plus_caps_at_c():
    ciphers = [*MODERN_12, ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", RSA2048)]
    assert grade_server(make_result({tls.TLS12: ciphers})).grade == "C"


def test_weak_dh_caps_at_b_and_tiny_dh_fails():
    weak = [*MODERN_12, ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", KeyExchange("dh", 1024))]
    assert grade_server(make_result({tls.TLS12: weak, tls.TLS13: MODERN_13})).grade == "B"
    tiny = [*MODERN_12, ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", KeyExchange("dh", 768))]
    assert grade_server(make_result({tls.TLS12: tiny, tls.TLS13: MODERN_13})).grade == "F"


def test_no_forward_secrecy_or_aead_caps_at_b():
    rsa_cbc = [("TLS_RSA_WITH_AES_128_CBC_SHA", RSA2048)]
    grade = grade_server(make_result({tls.TLS12: rsa_cbc}))
    assert grade.grade == "B"
    assert {"no forward secrecy → max B", "no AEAD suites → max B"} <= set(grade.caps)


def test_anonymous_or_null_scores_zero():
    anon = [*MODERN_12, ("TLS_DH_anon_WITH_AES_128_GCM_SHA256", KeyExchange("dh", 2048))]
    assert grade_server(make_result({tls.TLS12: anon})).grade == "F"


def test_weak_certificate_key_caps():
    assert grade_server(make_result({tls.TLS12: MODERN_12, tls.TLS13: MODERN_13},
                                CertificateInfo("rsa", 1024, "sha256"))).grade == "B"  # fmt: skip
