# cifr

Enumerate the TLS cipher suites a domain or IP address exposes. Each suite gets a rating drawn from cifr's
own rules, the IANA registry and [ciphersuite.info](https://ciphersuite.info), and the server as a whole gets an
SSL Labs-style grade. nmap-compatible grades and [TLSRef](https://docs.tlsref.org/cipher-suites.html) levels are
shown alongside, and output is colourised with [Rich](https://github.com/Textualize/rich).

```console
$ uv run cifr enum example.com
$ uv run cifr enum 192.0.2.10 -p 8443
$ uv run cifr enum https://example.com:9443 --json > report.json
```

## Install

```console
$ uv sync            # development
$ uv tool install .  # puts `cifr` on your PATH
```

## Usage

```
cifr enum TARGET [--port/-p PORT] [--sni NAME] [--timeout/-t SECONDS] [--concurrency/-c N]
                 [--profile intermediate|modern] [--config nginx|apache|haproxy|openssl|none] [--json]
```

`TARGET` can be a domain, an IPv4/IPv6 address, `host:port`, `[v6]:port` or a URL. SNI defaults to the
domain name, and isn't sent for IP targets unless you pass `--sni`. The exit code is 0 on success, 1 if no
SSL/TLS version could be negotiated, and 2 for target errors.

## How it works

cifr writes its own ClientHello messages instead of using Python's `ssl` module. That means it can offer
any IANA-registered suite (export, NULL, anonymous, RC4, GOST and the rest) over SSLv3 to TLS 1.3,
however the local OpenSSL was built. For each protocol version it:

1. Offers candidate suites in chunks of 64. Each suite the server picks is removed and the offer is
   repeated until the server refuses (the same method nmap uses).
2. Offers the accepted suites again to find the server's preference order, then offers them reversed to
   find out whether the server or the client order wins.
3. For TLS ≤ 1.2, reads the Certificate and ServerKeyExchange to measure key exchange strength (RSA
   modulus, DH prime, ECDH curve). For TLS 1.3 it uses the group chosen in the ServerHello or
   HelloRetryRequest, including hybrid post-quantum groups such as `X25519MLKEM768`.

## Ranking

cifr looks at a scan through four lenses. They answer different questions, so they're shown side by side.

### 1. Rating (primary, per suite): Recommended / Secure / Weak / Insecure

Each suite gets the **worst** verdict from three independent sources, and every downgrade is listed in the
**Why** column (on wide terminals) and in the JSON output.

| Source | What it contributes |
|---|---|
| **cifr rules** | **Insecure:** NULL encryption, anonymous, export, RC4, cipher under 112 bits, MD5 MAC, key exchange under 1024-bit RSA-equivalent. **Weak:** no forward secrecy, CBC mode, SHA-1 MAC, 64-bit block (SWEET32), key exchange under 2048-bit. **Secure:** truncated CCM_8 tag. The key exchange checks use the strength **measured on the wire**. |
| **IANA registry** | "D" (discouraged; RFC 10015 covers all RSA, DHE and static (EC)DH key exchange) → at most Weak. "N" (not recommended) → at most Secure. |
| **[ciphersuite.info](https://ciphersuite.info)** | Its per-suite rating. It only appears in **Why** when it's stricter than the rules. For example, it rates ECDHE_RSA suites "secure" (its "recommended" TLS 1.2 suites are almost all ECDSA- or PSK-authenticated), and it rates GOST and SM4 suites "insecure". |

### 2. Server grade (whole server, SSL Labs method)

This follows the [Qualys SSL Labs Rating Guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)
(2009r): 30% protocol support + 30% key exchange + 40% cipher strength, then the caps cifr can measure:

- **F:** SSLv3 as the best protocol, only RC4, export suites, DH under 1024 bits, certificate key under 1024
  bits, MD5 certificate signature, or anonymous key exchange.
- **C:** no TLS 1.2/1.3, RC4 or 64-bit block ciphers with TLS 1.1+.
- **B:** SSLv3 or TLS 1.0/1.1 enabled, any RC4, DH under 2048 bits, certificate key under 2048 bits, no forward
  secrecy, or no AEAD suites.
- **A-:** no TLS 1.3, or a SHA-1 certificate signature (SSL Labs grades that T).

This is an approximation, not an official SSL Labs result. cifr doesn't check certificate trust, hostname or
expiry, HSTS (so it never awards A+), SSLv2, or vulnerabilities such as Heartbleed and ROBOT.
For those, use [Qualys SSL Labs](https://www.ssllabs.com/ssltest/) or [testssl.sh](https://testssl.sh/);
the summary and the JSON output (`server_grade.further_testing`) point to both.

The two views often disagree on purpose. A server offering modern suites alongside many CBC/RSA fallbacks
can grade **A** overall while most of its individual suites rate **Weak**.

### 3. nmap grade (A–F, per suite)

This is kept for comparison with `nmap --script ssl-enum-ciphers`. It uses the same formula:

```
score = 0.43 × kex_score(RSA-equivalent key exchange bits) + 0.57 × cipher_score(cipher bits)
A ≥ 0.80 > B ≥ 0.65 > C ≥ 0.50 > D ≥ 0.35 > E ≥ 0.20 > F
```

It's capped at F for anonymous, NULL and export suites and MD5-signed certificates, and at C for RC4 and 64-bit
block ciphers. Its known blind spots are why it's no longer the primary rating: RSA-1024 still grades A, and it
ignores forward secrecy, CBC versus AEAD, and protocol version.

### 4. TLSRef level

TLSRef's **Modern** (#1–3) and **Intermediate** (#4–9) suites, plus a check of the whole configuration
(protocols, suites and DH size) against each profile. Suites TLSRef doesn't list show as `–`.

## Recommendations

After the summary, cifr compares the server with a TLSRef profile: `--profile intermediate` (default:
TLS 1.2 + 1.3) or `--profile modern` (TLS 1.3 only). If the server doesn't meet it, cifr recommends a
replacement configuration:

- **Protocols** to disable or enable.
- **Suites to drop**, counted by rating, with the most common weaknesses among them.
- **The target suite set** in TLSRef priority order, tailored to the server. With only an RSA certificate,
  ECDHE-ECDSA suites are left out. Each suite is marked *offered* if the server already supports it, or
  *enable* if it doesn't.
- **Required actions**, such as replacing an RSA certificate key under 2048 bits or a SHA-1-signed certificate,
  and **optional suggestions**, such as adding an ECDSA certificate or post-quantum `X25519MLKEM768` key exchange.
- **A projection**: the server grade and suite ratings the server would get if it kept only the target suites
  it already offers.
- **A ready-to-paste config snippet** for nginx (default), Apache, HAProxy or `openssl.cnf` (`--config`).
  `--config none` hides it. The group list includes `X25519MLKEM768`, which needs OpenSSL 3.5 or later, so
  remove it on older builds or the server won't start.

If TLS terminates at a CDN or load balancer, pick the managed security policy that is closest to the
recommended set. The JSON output includes the full recommendation and all four snippets under `recommendation`.

## Data

All datasets are bundled so scans work offline:

- `src/cifr/data/iana_ciphers.json`: the IANA TLS cipher suite registry. To regenerate it:
  ```console
  $ curl -sSfLO https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv
  $ uv run python scripts/gen_iana_ciphers.py tls-parameters-4.csv
  ```
- `src/cifr/data/ciphersuite_info.json`: ratings from the ciphersuite.info API (MIT licence,
  © Hans Christian Rudolph). To refresh it: `uv run python scripts/gen_ciphersuite_info.py`
- `src/cifr/data/tlsref_guidelines.json`: a copy of https://data.tlsref.org/guidelines/latest.json (v6.0).

## Development

```console
$ uv run pytest      # integration tests need `openssl` on PATH (they're skipped otherwise)
$ uvx ruff check . && uvx ruff format .
```

Only scan systems you own or have permission to test.
