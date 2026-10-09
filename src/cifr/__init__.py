"""cifr - enumerate and rank the TLS cipher suites exposed by a host."""

__version__ = "0.1.0"


def main() -> None:
    from cifr.cli import app

    app()
