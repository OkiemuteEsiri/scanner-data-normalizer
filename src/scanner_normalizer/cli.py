import argparse
import json
from pathlib import Path

from .adapters import ADAPTERS


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize synthetic vulnerability scanner records")
    parser.add_argument("--scanner", choices=sorted(ADAPTERS), required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    records = json.loads(Path(args.input).read_text(encoding="utf-8"))
    adapter = ADAPTERS[args.scanner]
    normalized = [adapter(record).to_dict() for record in records]
    with Path(args.output).open("w", encoding="utf-8") as handle:
        for finding in normalized:
            handle.write(json.dumps(finding, sort_keys=True) + "\n")
    print(f"normalized={len(normalized)} scanner={args.scanner} output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
