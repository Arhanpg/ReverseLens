from __future__ import annotations

import json
import sys
from pathlib import Path

from .specialist_adapters import run_mobsf


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: mobsf_adapter.py INPUT_APK OUTPUT_DIR", file=sys.stderr)
        return 2
    apk, output = Path(sys.argv[1]), Path(sys.argv[2])
    try:
        result = run_mobsf(apk, output)
        (output / "adapter-result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
        )
        return 0
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
