from __future__ import annotations

import json
import os
import platform
import signal
import subprocess
import sys
import time
from pathlib import Path

from .security import extract_apks_safely, inventory_files, safe_workspace_path, sha256_file
from .normalizer import normalize_engine

ADAPTER_VERSION = "0.1.0"
TOOL_VERSIONS = {"jadx": "1.5.7", "apktool": "3.0.3", "androguard": "4.1.4", "apkid": "3.2.0", "bundletool": "1.18.3"}


def run_command(command: list[str], timeout: int, metrics_path: Path) -> tuple[int, str, str, int, dict]:
    started = time.monotonic()
    wrapper_path = Path(__file__).with_name("resource_wrapper.py")
    wrapper = [sys.executable, str(wrapper_path),
               "--metrics", str(metrics_path), "--timeout", str(timeout), "--", *command]
    process = subprocess.Popen(wrapper, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, errors="replace", start_new_session=True,
                               env={"PATH": os.environ.get("PATH", "/opt/venv/bin:/usr/local/bin:/usr/bin:/bin"),
                                    "HOME": "/tmp", "LANG": "C.UTF-8", "PYTHONUNBUFFERED": "1"})
    try:
        stdout, stderr = process.communicate(timeout=timeout + 20)
        code = process.returncode or 0
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
        code = 124
        stderr = (stderr or "") + "\\nReverseLens: resource wrapper timed out."
    elapsed = max(0, int((time.monotonic() - started) * 1000))
    try:
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        metrics = {}
    return code, stdout or "", stderr or "", elapsed, metrics


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def select_base_split(splits: list[Path]) -> Path:
    return next((p for p in splits if "base" in p.name.lower()), splits[0])


def host_profile() -> dict:
    cpu_model = platform.processor() or platform.machine()
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith("model name") and ":" in line:
                cpu_model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    memory_bytes = None
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                memory_bytes = int(line.split()[1]) * 1024
                break
    except (OSError, ValueError, IndexError):
        pass
    return {
        "os": platform.platform(),
        "architecture": platform.machine(),
        "cpu_model": cpu_model[:200],
        "memory_bytes": memory_bytes,
        "python_version": platform.python_version(),
        "processor_count": os.cpu_count(),
        "containerized": Path("/.dockerenv").exists(),
    }


def execute(job: dict, workspace_root: Path) -> dict:
    engine_id = str(job.get("engineId", ""))
    input_path = safe_workspace_path(workspace_root, str(job.get("inputPath", "")))
    output_dir = safe_workspace_path(workspace_root, str(job.get("outputDirectory", "")))
    if not input_path.is_file():
        raise ValueError("Input artifact is missing")
    actual_hash = sha256_file(input_path)
    if actual_hash != str(job.get("inputSha256", "")):
        raise ValueError("Input SHA-256 did not match the API job manifest")
    output_dir.mkdir(parents=True, exist_ok=False)
    raw_dir, logs_dir = output_dir / "raw", output_dir / "logs"
    raw_dir.mkdir()
    logs_dir.mkdir()
    fmt = str(job.get("inputFormat", "")).lower()
    machine_profile = host_profile()
    warnings: list[str] = []
    status, exit_code, duration_ms = "succeeded", 0, 0
    cpu_time_ms, peak_rss_bytes = 0, 0
    tool_version = TOOL_VERSIONS.get(engine_id, "unknown")
    effective_input = input_path
    commands: list[list[str]] = []

    try:
        if fmt == "apks" and engine_id == "bundletool":
            splits = extract_apks_safely(input_path, raw_dir / "split-inventory")
            write_json(raw_dir / "split-inventory.json", {
                "archive": input_path.name, "split_count": len(splits),
                "base_split": select_base_split(splits).name,
                "splits": [{"name": p.name, "size_bytes": p.stat().st_size} for p in splits]
            })
            warnings.append("APKS was safely unpacked for split inventory; no package was rebuilt or installed.")
        else:
            if fmt == "apks":
                splits = extract_apks_safely(input_path, raw_dir / "splits")
                effective_input = select_base_split(splits)
                warnings.append(f"Extracted {len(splits)} split APKs; this baseline analyzes only the selected base split.")
            if engine_id == "jadx":
                commands = [["jadx", "-d", str(raw_dir / "decompiled"), str(effective_input)]]
            elif engine_id == "apktool":
                commands = [["apktool", "d", "-f", "-o", str(raw_dir / "decoded"), str(effective_input)]]
            elif engine_id == "androguard":
                commands = [[sys.executable, "/app/reverselens_worker/androguard_adapter.py",
                             str(effective_input), str(raw_dir / "analysis")]]
            elif engine_id == "apkid":
                (raw_dir / "matches").mkdir()
                commands = [["apkid", "-j", "-o", str(raw_dir / "matches"), str(effective_input)]]
            elif engine_id == "bundletool" and fmt == "aab":
                commands = [
                    ["java", "-jar", "/opt/bundletool.jar", "validate", f"--bundle={input_path}"],
                    ["java", "-jar", "/opt/bundletool.jar", "dump", "manifest",
                     f"--bundle={input_path}", "--module=base"]
                ]
            else:
                raise ValueError(f"Engine {engine_id} does not support format {fmt}")
        for index, command in enumerate(commands, start=1):
            metrics_path = logs_dir / f"command-{index}.metrics.json"
            code, stdout, stderr, elapsed, command_metrics = run_command(command, 900, metrics_path)
            duration_ms += elapsed
            cpu_time_ms += int(command_metrics.get("cpu_time_ms", 0) or 0)
            peak_rss_bytes = max(peak_rss_bytes, int(command_metrics.get("peak_rss_bytes", 0) or 0))
            (logs_dir / f"command-{index}.stdout.txt").write_text(stdout, encoding="utf-8")
            (logs_dir / f"command-{index}.stderr.txt").write_text(stderr, encoding="utf-8")
            if engine_id == "bundletool" and fmt == "aab" and "manifest" in command and code == 0:
                (raw_dir / "manifest.xml").write_text(stdout, encoding="utf-8")
            if code != 0:
                exit_code = code
                status = "timed_out" if code == 124 else ("partial" if index > 1 and any(raw_dir.iterdir()) else "failed")
                warnings.append(f"Command {index} exited with code {code}")
                break
    except Exception as exc:
        status, exit_code = "failed", 1
        warnings.append(f"{type(exc).__name__}: {exc}")

    observations = normalize_engine(engine_id, output_dir)
    for observation in observations:
        observation["schema_version"] = "1.0.0"
        observation["execution_id"] = str(job.get("executionId"))
    (output_dir / "normalized-observations.json").write_text(
        json.dumps(observations, indent=2, sort_keys=True), encoding="utf-8"
    )
    artifacts = inventory_files(output_dir)
    output_bytes = sum(item["size_bytes"] for item in artifacts)
    if not artifacts:
        status = "failed"
        warnings.append("Engine produced no output artifacts.")
    result = {
        "schema_version": "1.0.0", "execution_id": job.get("executionId"), "run_id": job.get("runId"),
        "engine_id": engine_id, "engine_version": tool_version, "adapter_version": ADAPTER_VERSION,
        "input_sha256": actual_hash, "status": status, "exit_code": exit_code,
        "duration_ms": duration_ms, "cpu_time_ms": cpu_time_ms, "peak_rss_bytes": peak_rss_bytes,
        "host_profile": machine_profile,
        "output_bytes": output_bytes, "output_file_count": len(artifacts),
        "artifact_count": len(artifacts), "observation_count": len(observations),
        "warnings": warnings, "artifacts": artifacts, "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    write_json(output_dir / "engine-result.json", result)
    return {**result, "observations": observations, "host_profile": machine_profile,
            "output_directory": str(job.get("outputDirectory")),
            "toolVersion": tool_version, "errorSummary": "; ".join(warnings)[:4000]}
