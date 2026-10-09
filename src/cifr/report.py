"""Rich terminal and JSON rendering of scan results."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cifr import tls, tlsref
from cifr.rating import Tier, ciphersuite_info, rate_suite
from cifr.recommend import Recommendation, recommend, snippets
from cifr.scanner import AcceptedCipher, ProtocolResult, ScanResult
from cifr.scoring import worst_grade
from cifr.servergrade import FURTHER_TESTING, ServerGrade, grade_server
from cifr.tlsref import Level

GRADE_STYLES = {
    "A+": "bold green",
    "A": "bold green",
    "A-": "green",
    "B": "green",
    "C": "yellow",
    "D": "dark_orange",
    "E": "red",
    "F": "bold white on red",
}
TIER_STYLES = {
    Tier.RECOMMENDED: "bold green",
    Tier.SECURE: "green",
    Tier.WEAK: "yellow",
    Tier.INSECURE: "bold red",
}
LEVEL_STYLES = {Level.MODERN: "bold green", Level.INTERMEDIATE: "cyan"}
PROTOCOL_STYLES = {
    tls.SSL3: "bold white on red",
    tls.TLS10: "red",
    tls.TLS11: "dark_orange",
    tls.TLS12: "green",
    tls.TLS13: "bold green",
}
WEAK_TOKENS = ["EXPORT", "anon", "NULL", "RC4", "RC2", "DES40", "DES_CBC", "3DES", "IDEA", "MD5"]


def grade_text(grade: str | None) -> Text:
    grade = grade or "unknown"
    return Text(f" {grade} " if grade in GRADE_STYLES else grade, style=GRADE_STYLES.get(grade, "dim"))


def tier_text(tier: Tier) -> Text:
    return Text(tier.label, style=TIER_STYLES[tier])


def _suite_text(c: AcceptedCipher, width: int) -> Text:
    """Colour the weak components of a suite name."""
    name = c.suite.name.removeprefix("TLS_") if width < 100 else c.suite.name
    text = Text(name)
    text.highlight_words(WEAK_TOKENS, style="bold red")
    text.highlight_words(["_CBC_"], style="yellow")
    return text


def _kex_text(c: AcceptedCipher) -> Text:
    if not c.kex:
        return Text("unknown", style="dim")
    return Text(str(c.kex), style="red" if 0 < c.kex.strength < 2048 else "")


def _tlsref_text(c: AcceptedCipher) -> Text:
    if c.ranking is None:
        return Text("–", style="dim")
    return Text.assemble((c.ranking.level.value, LEVEL_STYLES[c.ranking.level]), (f" #{c.ranking.priority}", "dim"))


def _why_text(c: AcceptedCipher) -> Text:
    text = Text()
    for i, finding in enumerate(sorted(c.rating.findings, key=lambda f: -f.tier)):
        if i:
            text.append(", ", style="dim")
        text.append(finding.reason, style=TIER_STYLES[finding.tier] if finding.tier >= Tier.WEAK else "dim")
    return text


@dataclass
class Column:
    header: str
    min_width: int  # console width at which the column appears
    cell: Callable[[AcceptedCipher, int, int], object]  # (cipher, row number, console width)
    options: dict


# Suite, rating, nmap grade and TLSRef level always show; the rest appear as the terminal widens.
COLUMNS = [
    Column("#", 115, lambda c, i, w: str(i), {"justify": "right", "style": "dim"}),
    Column("Cipher suite", 0, lambda c, i, w: _suite_text(c, w), {"no_wrap": True}),
    Column("Code", 160, lambda c, i, w: c.suite.hex, {"style": "dim"}),
    Column("Key exchange", 100, lambda c, i, w: _kex_text(c), {"no_wrap": True}),
    Column("Bits", 115, lambda c, i, w: Text(str(c.suite.bits), style="red" if c.suite.bits < 128 else ""),
           {"justify": "right"}),
    Column("PFS", 115, lambda c, i, w: Text("✔", "green") if c.suite.forward_secret else Text("✘", "red"),
           {"justify": "center"}),
    Column("Rating", 0, lambda c, i, w: tier_text(c.rating.tier), {"no_wrap": True}),
    Column("nmap", 0, lambda c, i, w: grade_text(c.score.grade), {"justify": "center", "no_wrap": True}),
    Column("TLSRef", 0, lambda c, i, w: _tlsref_text(c), {"no_wrap": True}),
    Column("Why", 140, lambda c, i, w: _why_text(c), {"ratio": 1}),
]  # fmt: skip


def _protocol_table(proto: ProtocolResult, width: int) -> Table:
    columns = [col for col in COLUMNS if width >= col.min_width]
    table = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False, padding=(0, 1), expand=False)
    for col in columns:
        table.add_column(col.header, **col.options)
    for i, c in enumerate(proto.ciphers, start=1):
        table.add_row(*[col.cell(c, i, width) for col in columns])
    return table


def _render_protocol(proto: ProtocolResult, console: Console) -> None:
    console.rule(Text(f" {proto.name} ", style=PROTOCOL_STYLES[proto.version]), align="left", style="bright_black")
    meta = Text()
    meta.append("cipher preference: ", style="dim")
    meta.append(proto.preference, style={"server": "green", "client": "yellow"}.get(proto.preference, "dim"))
    meta.append("   worst rating: ", style="dim")
    meta.append_text(tier_text(max(c.rating.tier for c in proto.ciphers)))
    meta.append("   nmap least strength: ", style="dim")
    meta.append_text(grade_text(worst_grade([c.score.grade for c in proto.ciphers])))
    if proto.certificate:
        meta.append("\ncertificate: ", style="dim")
        meta.append(str(proto.certificate))
    console.print(meta)
    console.print(_protocol_table(proto, console.width))

    warnings = list(proto.warnings)
    for c in proto.ciphers:
        warnings += [f"nmap: {w}" for w in c.score.warnings if f"nmap: {w}" not in warnings]
    for w in warnings:
        console.print(Text.assemble(("  ⚠ ", "yellow"), w))
    console.print()


def _dh_bits(result: ScanResult) -> list[int]:
    return [c.kex.bits for p in result.supported for c in p.ciphers if c.kex and c.kex.kind == "dh"]


def _accepted_by_version(result: ScanResult) -> dict:
    return {p.version: [c.suite for c in p.ciphers] for p in result.supported}


def _grade_cell(grade: ServerGrade) -> Text:
    text = grade_text(grade.grade)
    text.append(f"  score {grade.score}/100", style="dim")
    text.append(
        f"  (protocol {grade.protocol_score:g}, key exchange {grade.kex_score:g}, cipher {grade.cipher_score:g})",
        style="dim",
    )
    for rule in grade.caps:
        text.append("\n• ", style="yellow")
        text.append(rule)
    text.append(f"\nnot assessed: {'; '.join(grade.not_assessed)}", style="dim italic")
    tools = " or ".join(f"{name} ({url})" for name, url in FURTHER_TESTING.items())
    text.append(f"\nfor these checks, use {tools}", style="dim italic")
    return text


def _summary(result: ScanResult) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column()

    if grade := grade_server(result):
        grid.add_row("Server grade\n(SSL Labs method)", _grade_cell(grade))

    tiers = [c.rating.tier for p in result.supported for c in p.ciphers]
    counts = Text()
    for tier in Tier:
        if n := tiers.count(tier):
            counts.append(f"{tier.label}: {n}  ", style=TIER_STYLES[tier])
    grid.add_row("Suite ratings", counts)

    protocols = Text()
    for p in result.protocols:
        protocols.append(p.name, style=PROTOCOL_STYLES[p.version] if p.supported else "dim strike")
        protocols.append("  ")
    grid.add_row("Protocols", protocols)
    for p in result.protocols:
        if p.inconclusive:
            grid.add_row("", Text(f"⚠ {p.name} inconclusive: {p.inconclusive}", style="yellow"))

    grades = [c.score.grade for p in result.supported for c in p.ciphers]
    grid.add_row("nmap least strength", grade_text(worst_grade(grades)))

    accepted, dh_bits = _accepted_by_version(result), _dh_bits(result)
    for level in ("modern", "intermediate"):
        check = tlsref.compliance(level, accepted, dh_bits)
        label = f"TLSRef {level.title()}"
        if check.compliant:
            grid.add_row(label, Text("✔ compliant", style="bold green"))
        else:
            grid.add_row(label, Text("✘ " + "; ".join(check.summary()), style="red"))
    return Panel(grid, title=Text(" Summary ", style="bold"), title_align="left", border_style="cyan")


def _sources() -> str:
    return (
        f"rating: cifr rules + IANA registry + ciphersuite.info ({ciphersuite_info()['retrieved']}) · "
        f"server grade: SSL Labs guide 2009r · nmap ssl-enum-ciphers · {tlsref.version_label()}"
    )


def _recommendation_table(rec: Recommendation) -> Table:
    table = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False, padding=(0, 1))
    for header, opts in [
        ("#", {"justify": "right", "style": "dim"}),
        ("Cipher suite", {"no_wrap": True}),
        ("OpenSSL name", {"style": "dim"}),
        ("Status", {"no_wrap": True}),
        ("Rating", {}),
    ]:
        table.add_column(header, **opts)  # fmt: skip
    for s in rec.suites:
        status = Text("✔ offered", style="green") if s.offered else Text("＋ enable", style="cyan")
        table.add_row(str(s.priority), s.suite.name, s.openssl_name, status, tier_text(rate_suite(s.suite).tier))
    return table


def render_recommendation(rec: Recommendation, console: Console, config_format: str | None) -> None:
    title = f" Recommendation: TLSRef {rec.profile.title()} "
    console.rule(Text(title, style="bold cyan"), align="left", style="cyan")
    if not rec.needed:
        console.print(Text(f"✔ No changes required to meet TLSRef {rec.profile.title()}.", style="bold green"))
    else:
        protocols = Text("protocols: ", style="dim")
        protocols.append(" ".join(rec.protocols), style="bold")
        if rec.disable_protocols:
            protocols.append(f"   disable {', '.join(rec.disable_protocols)}", style="red")
        if rec.enable_protocols:
            protocols.append(f"   enable {', '.join(rec.enable_protocols)}", style="cyan")
        console.print(protocols)

        if rec.remove:
            tiers = [c.rating.tier for c in rec.remove]
            drop = Text(f"drop {len(rec.remove)} suite(s): ", style="dim")
            for tier in reversed(Tier):
                if n := tiers.count(tier):
                    drop.append(f"{n} {tier.label}  ", style=TIER_STYLES[tier])
            reasons = rec.removal_reasons().most_common(5)
            if reasons:
                drop.append("\nmost common issues: ", style="dim")
                drop.append(", ".join(f"{reason} ({n})" for reason, n in reasons))
            console.print(drop)
        console.print(_recommendation_table(rec))
        for action in rec.actions:
            console.print(Text.assemble(("  ✘ ", "red"), action))

    for suggestion in rec.suggestions:
        console.print(Text.assemble(("  → ", "cyan"), (suggestion, "dim")))
    if rec.needed and not rec.projected:
        console.print(Text("no projection: the server doesn't offer any of these suites yet", style="dim"))
    if rec.needed and rec.projected:
        projected = Text("projected, using suites the server already offers: ", style="dim")
        projected.append("server grade ")
        projected.append_text(grade_text(rec.projected.grade))
        projected.append("  ratings: ")
        for label, n in rec.projected_tiers.items():
            projected.append(f"{label}: {n}  ", style=TIER_STYLES[Tier[label.upper()]])
        remaining = [rule for rule in rec.projected.caps if "zero" not in rule]
        if remaining:
            projected.append(f"\nremaining grade rules: {'; '.join(remaining)}", style="dim")
        console.print(projected)

    if rec.needed and config_format:
        console.print(Text(f"\n{config_format} configuration:", style="bold"))
        # Printed raw (no Rich wrapping) so it can be copied straight from the terminal.
        console.out(snippets(rec)[config_format], highlight=False)
        console.print(
            Text(
                "If TLS terminates at a CDN or load balancer, choose its security policy closest to this set. "
                "Full server configs: https://configurator.tlsref.org/",
                style="dim italic",
            )
        )
    console.print()


def render(
    result: ScanResult, console: Console, profile: str = "intermediate", config_format: str | None = "nginx"
) -> None:
    t = result.target
    header = Text()
    header.append("cifr", style="bold magenta")
    header.append(f"  {t.host}", style="bold")
    header.append(f":{t.port}")
    if t.ip != t.host:
        header.append(f"  ({t.ip})", style="dim")
    header.append(f"   SNI: {t.sni or 'none'}", style="dim")
    header.append(f"\n{_sources()}", style="dim")
    console.print(Panel(header, border_style="magenta"))

    if not result.supported:
        console.print("[bold red]No SSL/TLS protocol versions were negotiated.[/]")
        return
    for proto in result.supported:
        _render_protocol(proto, console)
    console.print(_summary(result))
    if rec := recommend(result, profile):
        render_recommendation(rec, console, config_format)


def _compliance_dict(check: tlsref.Compliance) -> dict:
    return {
        "compliant": check.compliant,
        "protocols_not_allowed": check.protocols,
        "suites_not_allowed": check.suites,
        "weak_dh_bits": check.dh_bits,
    }


def _cipher_dict(c: AcceptedCipher) -> dict:
    return {
        "name": c.suite.name,
        "code": c.suite.hex,
        "kex": str(c.kex) if c.kex else None,
        "bits": c.suite.bits,
        "forward_secrecy": c.suite.forward_secret,
        "rating": {
            "tier": c.rating.tier.label,
            "reasons": c.rating.reasons,
            "findings": [{"tier": f.tier.label, "reason": f.reason, "source": f.source} for f in c.rating.findings],
            "iana_recommended": c.rating.iana,
            "ciphersuite_info": c.rating.ciphersuite_info,
        },
        "nmap": {"score": c.score.score, "grade": c.score.grade, "warnings": c.score.warnings},
        "tlsref": {"level": c.ranking.level.value, "priority": c.ranking.priority} if c.ranking else None,
    }


def _recommendation_dict(rec: Recommendation | None) -> dict | None:
    if rec is None:
        return None
    return {
        "profile": rec.profile,
        "changes_required": rec.needed,
        "protocols": rec.protocols,
        "disable_protocols": rec.disable_protocols,
        "enable_protocols": rec.enable_protocols,
        "suites": [
            {"name": s.suite.name, "openssl_name": s.openssl_name, "priority": s.priority, "offered": s.offered}
            for s in rec.suites
        ],
        "remove": [
            {"name": c.suite.name, "tier": c.rating.tier.label, "reasons": c.rating.reasons} for c in rec.remove
        ],
        "curves": rec.curves,
        "actions": rec.actions,
        "suggestions": rec.suggestions,
        "projected_server_grade": rec.projected.grade if rec.projected else None,
        "projected_ratings": rec.projected_tiers,
        "config": snippets(rec),
    }


def to_dict(result: ScanResult, profile: str = "intermediate") -> dict:
    t = result.target
    grades = [c.score.grade for p in result.supported for c in p.ciphers]
    accepted, dh_bits = _accepted_by_version(result), _dh_bits(result)
    grade = grade_server(result)
    return {
        "target": {"host": t.host, "ip": t.ip, "port": t.port, "sni": t.sni},
        "sources": _sources(),
        "server_grade": {
            "grade": grade.grade,
            "score": grade.score,
            "protocol_score": grade.protocol_score,
            "kex_score": grade.kex_score,
            "cipher_score": grade.cipher_score,
            "rules": grade.caps,
            "not_assessed": grade.not_assessed,
            "further_testing": FURTHER_TESTING,
        }
        if grade
        else None,
        "nmap_least_strength": worst_grade(grades),
        "tlsref": {
            "guidelines": tlsref.version_label(),
            "modern": _compliance_dict(tlsref.compliance("modern", accepted, dh_bits)),
            "intermediate": _compliance_dict(tlsref.compliance("intermediate", accepted, dh_bits)),
        },
        "recommendation": _recommendation_dict(recommend(result, profile)),
        "protocols": [
            {
                "name": p.name,
                "supported": p.supported,
                "inconclusive": p.inconclusive,
                "cipher_preference": p.preference if p.supported else None,
                "certificate": str(p.certificate) if p.certificate else None,
                "warnings": p.warnings,
                "ciphers": [_cipher_dict(c) for c in p.ciphers],
            }
            for p in result.protocols
        ],
    }
