"""Regenerate src/cifr/data/ciphersuite_info.json from the ciphersuite.info API.

ciphersuite.info (https://ciphersuite.info, MIT licence, (c) Hans Christian
Rudolph) rates each IANA suite as recommended, secure, weak or insecure.
Only the IANA name and that rating are kept.

Usage:
    uv run python scripts/gen_ciphersuite_info.py            # fetch the live API
    uv run python scripts/gen_ciphersuite_info.py cs.json    # or use a saved response
"""

import datetime
import json
import sys
import urllib.request
from pathlib import Path

API = "https://ciphersuite.info/api/cs/"
OUT = Path(__file__).resolve().parent.parent / "src" / "cifr" / "data" / "ciphersuite_info.json"


def main(path: str | None = None) -> None:
    if path:
        raw = json.loads(Path(path).read_text())
    else:
        with urllib.request.urlopen(API, timeout=30) as resp:
            raw = json.load(resp)
    ratings = {name: info["security"] for entry in raw["ciphersuites"] for name, info in entry.items()}
    data = {
        "source": API,
        "license": "MIT, (c) 2017 Hans Christian Rudolph",
        "retrieved": datetime.datetime.now(datetime.UTC).date().isoformat(),
        "ratings": dict(sorted(ratings.items())),
    }
    OUT.write_text(json.dumps(data, indent=1) + "\n")
    print(f"wrote {len(ratings)} ratings to {OUT}")


if __name__ == "__main__":
    main(*sys.argv[1:2])
