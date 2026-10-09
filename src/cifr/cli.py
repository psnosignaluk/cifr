from __future__ import annotations

import json
from enum import StrEnum
from typing import Annotated

import typer
from rich.console import Console

from cifr import report
from cifr.scanner import TargetError, parse_target, resolve, scan


class Profile(StrEnum):
    intermediate = "intermediate"
    modern = "modern"


class ConfigFormat(StrEnum):
    nginx = "nginx"
    apache = "apache"
    haproxy = "haproxy"
    openssl = "openssl"
    none = "none"


app = typer.Typer(
    help="Enumerate and rank the TLS cipher suites exposed by a host.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def main() -> None:
    """cifr - TLS cipher suite enumeration and ranking."""


@app.command("enum")
def enum_ciphers(
    target: Annotated[str, typer.Argument(help="Domain or IP address, optionally with :port or as a URL.")],
    port: Annotated[int | None, typer.Option("--port", "-p", help="Port to scan (default 443).")] = None,
    sni: Annotated[str | None, typer.Option(help="Server Name Indication to send (defaults to the domain).")] = None,
    timeout: Annotated[float, typer.Option("--timeout", "-t", help="Per-handshake timeout in seconds.")] = 5.0,
    concurrency: Annotated[
        int, typer.Option("--concurrency", "-c", min=1, max=64, help="Maximum simultaneous connections.")
    ] = 8,
    profile: Annotated[
        Profile, typer.Option("--profile", help="TLSRef profile to recommend a configuration for.")
    ] = Profile.intermediate,
    config: Annotated[
        ConfigFormat, typer.Option("--config", help="Server type for the recommended configuration snippet.")
    ] = ConfigFormat.nginx,
    as_json: Annotated[bool, typer.Option("--json", help="Emit machine-readable JSON instead of tables.")] = False,
) -> None:
    """Enumerate the cipher suites offered by TARGET and rank each one."""
    console = Console(stderr=as_json)
    try:
        host, resolved_port = parse_target(target, port)
        with console.status(f"Connecting to {host}:{resolved_port}…"):
            tgt = resolve(host, resolved_port, sni, timeout)
        with console.status(f"Enumerating cipher suites on {tgt.ip}:{tgt.port}…") as status:
            result = scan(
                tgt, timeout, concurrency, progress=lambda msg: console.log(msg) if not as_json else status.update(msg)
            )
    except TargetError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(2) from exc

    if as_json:
        print(json.dumps(report.to_dict(result, profile.value), indent=2))
    else:
        report.render(result, console, profile.value, None if config is ConfigFormat.none else config.value)
    if not result.supported:
        raise typer.Exit(1)
