from __future__ import annotations

import hashlib
import json
import re
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit, urlunsplit
from pathlib import Path

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
MAX_OBSERVATIONS = 20000


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def _canonical(kind: str, value: str) -> str:
    return f"{kind}:{' '.join(value.strip().lower().split())}"


def _observation(engine: str, capability: str, item_type: str, title: str, value: str,
                 path: Path, output_root: Path, confidence: str = "medium",
                 attributes: dict | None = None) -> dict:
    relative = path.relative_to(output_root).as_posix()
    return {
        "observation_id": str(uuid.uuid4()),
        "capability_class": capability,
        "item_type": item_type,
        "title": title[:300],
        "observed_value": value[:8000],
        "canonical_key": _canonical(item_type, value),
        "evidence_path": relative,
        "evidence_sha256": _digest(path),
        "confidence": confidence,
        "attributes": {"engine_id": engine, **(attributes or {})},
    }


def _add(rows: list[dict], *args, **kwargs) -> None:
    if len(rows) < MAX_OBSERVATIONS:
        rows.append(_observation(*args, **kwargs))


def _manifest_observations(engine: str, path: Path, root: Path, rows: list[dict],
                           capability: str = "manifest") -> None:
    try:
        tree = ET.parse(path)
        manifest = tree.getroot()
    except (ET.ParseError, OSError):
        return
    for node in manifest:
        tag = node.tag.rsplit("}", 1)[-1]
        if tag.startswith("uses-permission") or tag == "permission":
            name = node.attrib.get(ANDROID_NS + "name")
            if name:
                _add(rows, engine, capability, "permission", "Android permission", name, path, root, "high")
    app = manifest.find("application")
    if app is None:
        return
    for component_tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for node in app.findall(component_tag):
            name = node.attrib.get(ANDROID_NS + "name")
            if name:
                value = f"{component_tag}:{name}"
                _add(rows, engine, capability, "manifest_component", "Manifest component", value, path, root, "high")


def _androguard(root: Path, rows: list[dict]) -> None:
    path = root / "raw/analysis/androguard-summary.json"
    if not path.is_file():
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    package = data.get("package")
    if package:
        _add(rows, "androguard", "apk_parsing", "package_metadata", "Package name", str(package), path, root, "high")
    for permission in data.get("permissions", []) or []:
        _add(rows, "androguard", "apk_parsing", "permission", "Android permission", str(permission), path, root, "high")
    for key, kind in (("activities", "activity"), ("services", "service"),
                      ("receivers", "receiver"), ("providers", "provider")):
        for value in data.get(key, []) or []:
            _add(rows, "androguard", "apk_parsing", "manifest_component",
                 "Android component", f"{kind}:{value}", path, root, "high")
    for entry in data.get("dex_entries", []) or []:
        name = entry.get("name")
        if name:
            _add(rows, "androguard", "dex_analysis", "dex_entry", "DEX entry", str(name), path, root, "high")


def _apktool(root: Path, rows: list[dict]) -> None:
    base = root / "raw/decoded"
    manifest = base / "AndroidManifest.xml"
    if manifest.is_file():
        _manifest_observations("apktool", manifest, root, rows, "manifest")
    pattern_class = re.compile(r"^\.class\s+.*?\s+(L[^;]+;)", re.MULTILINE)
    pattern_method = re.compile(r"^\.method\s+.*?\s+([A-Za-z0-9_$<>-]+)\(([^)]*)\)", re.MULTILINE)
    for path in base.rglob("*.smali"):
        if len(rows) >= MAX_OBSERVATIONS:
            break
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = pattern_class.search(content)
        if match:
            name = match.group(1).strip("L;").replace("/", ".")
            _add(rows, "apktool", "smali", "class", "Smali class", name, path, root, "medium")
        for method in pattern_method.findall(content):
            _add(rows, "apktool", "smali", "method", "Smali method", f"{path.stem}#{method[0]}", path, root, "low")


def _jadx(root: Path, rows: list[dict]) -> None:
    base = root / "raw/decompiled"
    class_pattern = re.compile(r"\b(?:public\s+|protected\s+|private\s+|abstract\s+|final\s+)*(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)")
    package_pattern = re.compile(r"^\s*package\s+([A-Za-z0-9_.]+)\s*;", re.MULTILINE)
    method_pattern = re.compile(r"^\s*(?:public|protected|private)\s+(?:static\s+|final\s+|abstract\s+|synchronized\s+)*(?:[A-Za-z_$][\w$<>., ?\[\]]*)\s+([A-Za-z_$][\w$]*)\s*\(", re.MULTILINE)
    for path in base.rglob("*.java"):
        if len(rows) >= MAX_OBSERVATIONS:
            break
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        package = package_pattern.search(content)
        classes = class_pattern.findall(content)
        for class_name in classes:
            fqcn = f"{package.group(1)}.{class_name}" if package else class_name
            _add(rows, "jadx", "dex_to_source", "class", "Reconstructed Java class", fqcn, path, root, "medium")
        for method in method_pattern.findall(content):
            _add(rows, "jadx", "dex_to_source", "method", "Reconstructed Java method", f"{path.stem}#{method}", path, root, "low")


def _safe_endpoint(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        host = parsed.hostname.lower()
        port = parsed.port
        netloc = host if port is None else f"{host}:{port}"
        path = parsed.path or "/"
        # Query, fragment and user-info are intentionally removed to avoid copying tokens.
        return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))
    except ValueError:
        return None


def _source_strings(root: Path, rows: list[dict]) -> None:
    base = root / "raw/decompiled"
    if not base.exists():
        return
    url_pattern = re.compile(r"https?://[^\s\"'<>]{4,1024}", re.IGNORECASE)
    literal_pattern = re.compile(r'"((?:[^"\\]|\\.){4,256})"')
    secret_pattern = re.compile(r"(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|cookie)", re.IGNORECASE)
    for path in base.rglob("*.java"):
        if len(rows) >= MAX_OBSERVATIONS:
            break
        try:
            if path.stat().st_size > 5 * 1024 * 1024:
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        seen_endpoints: set[str] = set()
        for match in url_pattern.findall(content):
            safe = _safe_endpoint(match.rstrip(").,;"))
            if safe and safe not in seen_endpoints:
                seen_endpoints.add(safe)
                _add(rows, "jadx", "dex_to_source", "endpoint", "Client-visible URL string", safe, path, root, "medium")
        seen_strings: set[str] = set()
        for match in literal_pattern.finditer(content):
            value = match.group(1).strip()
            line_start = content.rfind("\n", 0, match.start()) + 1
            context = content[line_start:match.start()]
            if len(value) < 4 or value in seen_strings or secret_pattern.search(context) or secret_pattern.search(value):
                continue
            if "://" in value or re.fullmatch(r"[A-Za-z0-9+/=_-]{40,}", value):
                continue
            seen_strings.add(value)
            _add(rows, "jadx", "dex_to_source", "string_literal", "Reconstructed string literal", value, path, root, "low")


def _apkid(root: Path, rows: list[dict]) -> None:
    candidates = list((root / "raw/matches").rglob("*.json"))
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    normalized = key.lower()
                    capability = next((c for word, c in (("compiler", "compiler_detection"),
                        ("packer", "packer_detection"), ("protector", "protector_detection")) if word in normalized), None)
                    if capability and isinstance(value, (str, int, float)):
                        _add(rows, "apkid", capability, "fingerprint", key.replace("_", " ").title(),
                             str(value), path, root, "medium")
                    else:
                        walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)
        walk(data)
    if not candidates:
        # APKiD may emit a JSON file at the direct output path on future releases; keep raw output as evidence only.
        return


def _bundletool(root: Path, rows: list[dict]) -> None:
    manifest = root / "raw/manifest.xml"
    if manifest.is_file():
        _manifest_observations("bundletool", manifest, root, rows, "aab_processing")
    inventory = root / "raw/split-inventory.json"
    if inventory.is_file():
        try:
            data = json.loads(inventory.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        for split in data.get("splits", []) or []:
            name = split.get("name")
            if name:
                _add(rows, "bundletool", "split_apk_processing", "apk_split", "APK split",
                     str(name), inventory, root, "high", {"size_bytes": split.get("size_bytes")})



_SECRET_VALUE = re.compile(
    r"(?i)(?:AKIA[0-9A-Z]{16}|(?:gh[pousr]_[A-Za-z0-9_]{20,})|"
    r"(?:sk-[A-Za-z0-9_-]{20,})|(?:Bearer\s+[A-Za-z0-9._~-]{12,})|"
    r"(?:eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}))"
)


def _redact(value: object) -> str:
    return _SECRET_VALUE.sub("[REDACTED_CANDIDATE]", str(value)[:8000])


def _load_json(path: Path):
    try:
        if not path.is_file() or path.stat().st_size > 30 * 1024 * 1024:
            return None
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def _specialist(engine: str, root: Path, rows: list[dict]) -> None:
    if engine == "apkeditor":
        manifest = root / "raw/apkeditor/decoded/AndroidManifest.xml"
        if manifest.is_file():
            _manifest_observations(engine, manifest, root, rows, "manifest")

    elif engine == "hermes-dec":
        for path in (root / "raw/hermes/bundle.pseudo.js", root / "raw/hermes/bundle.hasm"):
            if not path.is_file():
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            line_count = content.count("\n") + (1 if content else 0)
            _add(rows, engine, "hermes_bytecode", "reconstruction_summary",
                 "Hermes reconstructed artifact", f"{path.name}: {line_count} lines",
                 path, root, "medium", {"line_count": line_count,
                 "note": "Reconstructed output is approximate and is not source-equivalence proof."})

    elif engine == "blutter":
        for name in ("pp.txt", "objs.txt"):
            path = root / "raw/blutter" / name
            if not path.is_file():
                continue
            try:
                line_count = sum(1 for _ in path.open("r", encoding="utf-8", errors="replace"))
            except OSError:
                continue
            _add(rows, engine, "dart_object_pool", "object_pool_summary",
                 "Blutter object pool", f"{name}: {line_count} lines",
                 path, root, "medium", {"line_count": line_count})

    elif engine == "ghidra":
        functions, edges = [], []
        base = root / "raw/ghidra-export"
        for path in sorted(base.glob("*.json")):
            data = _load_json(path)
            if not isinstance(data, dict) or not isinstance(data.get("functions"), list):
                continue
            for item in data.get("functions", [])[:MAX_OBSERVATIONS]:
                if not isinstance(item, dict) or not item.get("entry"):
                    continue
                name, entry = str(item.get("name") or "FUN_"), str(item["entry"])
                functions.append({"id": entry, "name": name, "binary": data.get("binary_name")})
                _add(rows, engine, "native_pseudocode", "native_function",
                     "Ghidra native function", f"{name}@{entry}", path, root, "medium",
                     {"binary": data.get("binary_name"), "language_id": data.get("language_id")})
            for edge in data.get("call_edges", [])[:50000]:
                if isinstance(edge, dict) and edge.get("caller") and edge.get("callee"):
                    edges.append({
                        "from": str(edge["caller"]), "to": str(edge["callee"]),
                        "caller_name": str(edge.get("caller_name", "")),
                        "callee_name": str(edge.get("callee_name", "")),
                        "evidence_path": path.relative_to(root).as_posix(),
                        "evidence_sha256": _digest(path),
                        "validation_status": "static_reference",
                    })
        if functions or edges:
            graph_dir = root / "graphs"
            graph_dir.mkdir(exist_ok=True)
            graph_path = graph_dir / "call-graph.json"
            graph_path.write_text(json.dumps({
                "schema_version": "1.0.0", "graph_type": "native_call_graph",
                "nodes": functions, "edges": edges,
                "limitations": [
                    "Static disassembler references are not proof of runtime execution.",
                    "Only functions and edges emitted by configured Ghidra runs are shown.",
                ],
            }, indent=2, sort_keys=True), encoding="utf-8")
            _add(rows, engine, "native_call_graph", "call_graph_summary",
                 "Native static call graph", f"{len(functions)} functions, {len(edges)} call edges",
                 graph_path, root, "medium",
                 {"function_count": len(functions), "edge_count": len(edges)})

    elif engine == "apkleaks":
        path = root / "raw/apkleaks/results.json"
        data = _load_json(path)
        candidates = data if isinstance(data, list) else (
            data.get("results", data.get("findings", [])) if isinstance(data, dict) else []
        )
        if isinstance(candidates, list):
            for item in candidates[:MAX_OBSERVATIONS]:
                value = _redact(item if isinstance(item, str) else json.dumps(item, sort_keys=True))
                _add(rows, engine, "uri_extraction", "apk_candidate",
                     "APKLeaks URI/string candidate", value, path, root, "low",
                     {"validation_status": "unverified_candidate"})
        else:
            path = root / "logs/command-1.stdout.txt"
            if path.is_file():
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:1000]:
                    _add(rows, engine, "uri_extraction", "apk_candidate",
                         "APKLeaks output candidate", _redact(line), path, root, "low",
                         {"validation_status": "unverified_candidate"})

    elif engine == "exodus-standalone":
        path = root / "raw/exodus/report.json"
        data = _load_json(path)
        trackers = data.get("trackers", []) if isinstance(data, dict) else []
        for tracker in trackers[:MAX_OBSERVATIONS] if isinstance(trackers, list) else []:
            if isinstance(tracker, dict) and tracker.get("name"):
                _add(rows, engine, "tracker_signature_matching", "tracker",
                     "Exodus tracker signature", str(tracker["name"]), path, root, "medium",
                     {"tracker_id": tracker.get("id"),
                      "validation_status": "signature_match_not_runtime_confirmation"})

    elif engine == "mobsf":
        path = root / "raw/mobsf/mobsf-report.json"
        data = _load_json(path)
        if isinstance(data, dict):
            summary = {
                "manifest_analysis_sections": len(data.get("manifest_analysis", {}))
                if isinstance(data.get("manifest_analysis"), dict) else 0,
                "code_analysis_sections": len(data.get("code_analysis", {}))
                if isinstance(data.get("code_analysis"), dict) else 0,
                "file_analysis_sections": len(data.get("file_analysis", {}))
                if isinstance(data.get("file_analysis"), dict) else 0,
            }
            _add(rows, engine, "mobile_static_analysis", "mobsf_summary",
                 "MobSF static-analysis report", json.dumps(summary, sort_keys=True),
                 path, root, "medium",
                 {"validation_status": "tool_report_requires_analyst_review"})

def normalize_engine(engine_id: str, output_root: Path) -> list[dict]:
    rows: list[dict] = []
    if engine_id == "androguard":
        _androguard(output_root, rows)
    elif engine_id == "apktool":
        _apktool(output_root, rows)
    elif engine_id == "jadx":
        _jadx(output_root, rows)
        _source_strings(output_root, rows)
    elif engine_id == "apkid":
        _apkid(output_root, rows)
    elif engine_id == "bundletool":
        _bundletool(output_root, rows)
    elif engine_id in {"apkeditor", "hermes-dec", "blutter", "ghidra",
                       "apkleaks", "exodus-standalone", "mobsf"}:
        _specialist(engine_id, output_root, rows)
    return rows
