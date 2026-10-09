"""Regenerate src/cifr/data/iana_ciphers.json from the IANA TLS cipher suite registry.

Usage:
    curl -sSfLO https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv
    uv run python scripts/gen_iana_ciphers.py tls-parameters-4.csv
"""

import csv
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "src" / "cifr" / "data" / "iana_ciphers.json"
SKIP = {"TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "TLS_FALLBACK_SCSV"}


def main(csv_path: str) -> None:
    suites = {}
    with open(csv_path, newline="") as fh:
        for row in csv.DictReader(fh):
            value, name = row["Value"], row["Description"].strip()
            if "-" in value or "*" in value or not name.startswith("TLS_") or name in SKIP:
                continue
            hi, lo = (int(part, 16) for part in value.split(","))
            suites[f"0x{hi:02X}{lo:02X}"] = {"name": name, "recommended": row["Recommended"].strip()}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(suites, indent=1) + "\n")
    print(f"wrote {len(suites)} cipher suites to {OUT}")


if __name__ == "__main__":
    main(sys.argv[1])
