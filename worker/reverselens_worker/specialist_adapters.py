from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from .android_runtime import HERMES_MAGIC, AndroidRuntimeProfile

MAX_BUNDLE_BYTES = 150 * 1024 * 1024
MAX_NATIVE_BYTES = 600 * 1024 * 1024
MAX_NATIVE_FILES = 1000


def _copy_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, destination: Path,
                 limit: int) -> Path:
    if info.file_size < 0 or info.file_size > limit:
        raise ValueError(f"Archive member is outside the extraction size limit: {info.filename}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with archive.open(info) as source, destination.open("wb") as target:
        while chunk := source.read(1024 * 1024):
            written += len(chunk)
            if written > limit or written > info.file_size:
                raise ValueError(f"Archive member exceeded its declared/configured size: {info.filename}")
            target.write(chunk)
    if written != info.file_size:
        raise ValueError(f"Archive member size mismatch: {info.filename}")
    return destination


def extract_hermes_bundle(apk_path: Path, destination: Path, profile: AndroidRuntimeProfile) -> Path:
    if not profile.hermes_bundle_path:
        raise ValueError("The APK does not contain a verified Hermes HBC bundle.")
    with zipfile.ZipFile(apk_path) as archive:
        info = archive.getinfo(profile.hermes_bundle_path)
        output = _copy_member(archive, info, destination / "index.android.bundle", MAX_BUNDLE_BYTES)
    with output.open("rb") as handle:
        if handle.read(8) != HERMES_MAGIC:
            output.unlink(missing_ok=True)
            raise ValueError("Extracted bundle failed its Hermes HBC magic check.")
    return output


def extract_native_libraries(apk_path: Path, destination: Path,
                             abi_filter: set[str] | None = None) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    results: list[Path] = []
    total = 0
    with zipfile.ZipFile(apk_path) as archive:
        infos = [i for i in archive.infolist() if not i.is_dir() and i.filename.endswith(".so")]
        if len(infos) > MAX_NATIVE_FILES:
            raise ValueError("APK contains too many native libraries.")
        for info in infos:
            name = info.filename
            if "\\" in name or "\x00" in name:
                continue
            parts = PurePosixPath(name).parts
            if len(parts) != 3 or parts[0] != "lib" or parts[1] in {"", ".", ".."}:
                continue
            if not re.fullmatch(r"[A-Za-z0-9_-]+", parts[1]):
                continue
            if abi_filter and parts[1] not in abi_filter:
                continue
            if not re.fullmatch(r"lib[A-Za-z0-9_.+-]+\.so", parts[2]):
                continue
            with archive.open(info) as probe:
                if probe.read(4) != b"\x7fELF":
                    continue
            total += info.file_size
            if total > MAX_NATIVE_BYTES:
                raise ValueError("Native library extraction exceeded the aggregate size limit.")
            results.append(_copy_member(archive, info, destination / parts[1] / parts[2], MAX_NATIVE_BYTES))
    return results


def _required_executable(name: str) -> str:
    value = shutil.which(name)
    if not value:
        raise RuntimeError(f"Required executable '{name}' is not installed in the specialist worker.")
    return value


def specialist_commands(engine_id: str, apk_path: Path, raw_dir: Path,
                        profile: AndroidRuntimeProfile | None = None) -> list[list[str]]:
    """Return argument-vector-only commands for configured Android specialist tools."""
    if engine_id == "apkeditor":
        jar = Path(os.getenv("APKEDITOR_JAR", "/opt/APKEditor.jar"))
        if not jar.is_file():
            raise RuntimeError("APKEditor JAR is not installed; configure APKEDITOR_JAR.")
        output = raw_dir / "apkeditor" / "decoded"
        output.parent.mkdir(parents=True, exist_ok=True)
        return [["java", "-jar", str(jar), "d", "-t", "xml", "-i", str(apk_path), "-o", str(output)]]

    if engine_id == "apkleaks":
        output = raw_dir / "apkleaks" / "results.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        return [[_required_executable("apkleaks"), "-f", str(apk_path), "-o", str(output), "--json"]]

    if engine_id == "hermes-dec":
        if profile is None:
            raise ValueError("Runtime profile is required for Hermes compatibility routing.")
        bundle = extract_hermes_bundle(apk_path, raw_dir / "hermes", profile)
        output = raw_dir / "hermes"
        return [
            [_required_executable("hbc-disassembler"), str(bundle), str(output / "bundle.hasm")],
            [_required_executable("hbc-decompiler"), str(bundle), str(output / "bundle.pseudo.js")],
        ]

    if engine_id == "blutter":
        home = Path(os.getenv("BLUTTER_HOME", "/opt/blutter")).resolve()
        script = home / "blutter.py"
        if not script.is_file():
            raise RuntimeError("Blutter is not installed; set BLUTTER_HOME to a reviewed checkout.")
        abi_dir = raw_dir / "native-libs" / "arm64-v8a"
        libs = extract_native_libraries(apk_path, raw_dir / "native-libs", {"arm64-v8a"})
        if not any(path.name == "libapp.so" for path in libs):
            raise RuntimeError("Blutter requires an extracted arm64-v8a/libapp.so.")
        if not (home / "bin").is_dir():
            raise RuntimeError("Blutter runtime binaries are not pre-provisioned; dynamic downloads are disabled.")
        output = raw_dir / "blutter"
        output.mkdir(parents=True, exist_ok=True)
        return [[_required_executable("python3"), str(script), str(abi_dir), str(output)]]

    if engine_id == "ghidra":
        home = Path(os.getenv("GHIDRA_HOME", "")).expanduser()
        analyze = home / "support" / "analyzeHeadless"
        if not analyze.is_file():
            raise RuntimeError("Ghidra is optional; set GHIDRA_HOME to a pre-installed distribution.")
        script_dir = Path(__file__).with_name("ghidra_scripts")
        script = script_dir / "ExportProgramAnalysis.java"
        if not script.is_file():
            raise RuntimeError("ReverseLens Ghidra export script is missing.")
        libs = extract_native_libraries(apk_path, raw_dir / "native-libs")
        if not libs:
            raise RuntimeError("No native ELF libraries were available for Ghidra.")
        project = raw_dir / "ghidra-project"
        output = raw_dir / "ghidra-export"
        output.mkdir(parents=True, exist_ok=True)
        return [[str(analyze), str(project), "ReverseLens", "-import", str(raw_dir / "native-libs"),
                 "-recursive", "-scriptPath", str(script_dir), "-postScript", script.name,
                 str(output), "-analysisTimeoutPerFile", "180", "-max-cpu", "1", "-deleteProject"]]

    if engine_id == "mobsf":
        output = raw_dir / "mobsf"
        output.mkdir(parents=True, exist_ok=True)
        return [[_required_executable("python3"), "/app/reverselens_worker/mobsf_adapter.py",
                 str(apk_path), str(output)]]

    if engine_id == "exodus-standalone":
        script = os.getenv("EXODUS_ANALYZE", "")
        if not script or not Path(script).is_file():
            raise RuntimeError("Exodus is optional; set EXODUS_ANALYZE to a pre-installed exodus_analyze.py.")
        output = raw_dir / "exodus" / "report.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        return [[_required_executable("python3"), script, "-j", "-o", str(output), str(apk_path)]]

    raise ValueError(f"No specialist adapter registered for {engine_id}.")


def _mobsf_request(session, method: str, url: str, *, timeout, **kwargs):
    response = session.request(method, url, timeout=timeout, allow_redirects=False, **kwargs)
    if 300 <= response.status_code < 400:
        raise RuntimeError("MobSF returned a redirect; redirect following is disabled.")
    response.raise_for_status()
    length = response.headers.get("Content-Length")
    if length and length.isdigit() and int(length) > 30 * 1024 * 1024:
        raise RuntimeError("MobSF report exceeds the 30 MiB response limit.")
    return response


def run_mobsf(apk_path: Path, output_dir: Path) -> dict:
    """Submit an APK to an explicitly configured private/self-hosted MobSF instance."""
    import requests

    base = os.getenv("MOBSF_URL", "").rstrip("/")
    api_key = os.getenv("MOBSF_API_KEY", "")
    if not base or not api_key:
        raise RuntimeError("MobSF is disabled until MOBSF_URL and MOBSF_API_KEY are configured.")
    parsed = urlsplit(base)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise RuntimeError("MOBSF_URL must be a plain HTTP(S) private service URL without credentials.")
    host = parsed.hostname.lower()
    allowed_hosts = {"mobsf", "localhost", "127.0.0.1", "::1"}
    allowed_hosts.update(
        value.strip().lower()
        for value in os.getenv("MOBSF_ALLOWED_HOSTS", "").split(",")
        if value.strip()
    )
    if host not in allowed_hosts:
        raise RuntimeError("MobSF hostname is not listed in MOBSF_ALLOWED_HOSTS.")
    try:
        addresses = {
            ipaddress.ip_address(item[4][0].split("%", 1)[0])
            for item in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                           type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError) as exc:
        raise RuntimeError("MobSF host could not be resolved safely.") from exc
    if not addresses or any(
        not (address.is_private or address.is_loopback)
        or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved
        for address in addresses
    ):
        raise RuntimeError("MobSF host must resolve exclusively to private or loopback addresses.")

    output_dir.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    session.trust_env = False
    headers = {"Authorization": api_key}
    with apk_path.open("rb") as apk_file:
        uploaded = _mobsf_request(
            session, "POST", base + "/api/v1/upload", headers=headers,
            files={"file": (apk_path.name, apk_file, "application/vnd.android.package-archive")},
            timeout=(10, 180),
        )
    metadata = uploaded.json()
    file_hash = metadata.get("hash")
    if not isinstance(file_hash, str) or not re.fullmatch(r"[a-fA-F0-9]{32,64}", file_hash):
        raise RuntimeError("MobSF upload response did not include a valid artifact hash.")
    scan = _mobsf_request(
        session, "POST", base + "/api/v1/scan", headers=headers,
        data={"hash": file_hash, "scan_type": "apk", "file_name": apk_path.name},
        timeout=(10, 30),
    )
    report = _mobsf_request(
        session, "POST", base + "/api/v1/report_json", headers=headers,
        data={"hash": file_hash}, timeout=(10, 900),
    )
    data = report.json()
    report_path = output_dir / "mobsf-report.json"
    report_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    (output_dir / "mobsf-submission.json").write_text(
        json.dumps({"uploaded_hash": file_hash, "scan_status": scan.status_code}, indent=2),
        encoding="utf-8",
    )
    session.close()
    return {"uploaded_hash": file_hash, "report": str(report_path)}
