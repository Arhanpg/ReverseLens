from __future__ import annotations
import json
import sys
import zipfile
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: androguard_adapter.py INPUT_APK OUTPUT_DIR", file=sys.stderr)
        return 2
    apk_path, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    from androguard.core.apk import APK

    apk = APK(str(apk_path))
    result = {
        "engine": "androguard",
        "package": apk.get_package(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "permissions": sorted(apk.get_permissions() or []),
        "activities": sorted(apk.get_activities() or []),
        "services": sorted(apk.get_services() or []),
        "receivers": sorted(apk.get_receivers() or []),
        "providers": sorted(apk.get_providers() or []),
        "dex_entries": [],
        "limitations": ["Metadata and DEX inventory only; this adapter does not claim full Java source reconstruction."]
    }
    with zipfile.ZipFile(apk_path) as zf:
        result["dex_entries"] = [
            {"name": item.filename, "size_bytes": item.file_size}
            for item in zf.infolist()
            if item.filename == "classes.dex" or (item.filename.startswith("classes") and item.filename.endswith(".dex"))
        ]
    (out_dir / "androguard-summary.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
