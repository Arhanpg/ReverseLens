from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path, PurePosixPath


def safe_workspace_path(root: Path, relative: str) -> Path:
    if not relative or "\x00" in relative or "\\" in relative:
        raise ValueError("Invalid workspace-relative path")
    candidate = Path(relative)
    if candidate.is_absolute() or any(part in ("", ".", "..") for part in PurePosixPath(relative).parts):
        raise ValueError("Path must be normalized and relative")
    resolved_root = root.resolve()
    resolved = (resolved_root / candidate).resolve()
    if not resolved.is_relative_to(resolved_root):
        raise ValueError("Path escaped the workspace")
    return resolved


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def inventory_files(root: Path) -> list[dict]:
    records = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative == "artifacts.json":
            continue
        records.append({"path": relative, "size_bytes": path.stat().st_size, "sha256": sha256_file(path)})
    return records


def extract_apks_safely(archive: Path, destination: Path, max_entries: int = 100,
                        max_total_bytes: int = 750 * 1024 * 1024) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    total = 0
    with zipfile.ZipFile(archive) as zf:
        members = [info for info in zf.infolist() if not info.is_dir() and info.filename.lower().endswith(".apk")]
        if len(members) > max_entries:
            raise ValueError("APKS archive contains too many APK splits")
        for info in members:
            name = PurePosixPath(info.filename)
            if name.is_absolute() or ".." in name.parts:
                raise ValueError("Unsafe archive path in APKS package")
            total += info.file_size
            if info.file_size < 0 or total > max_total_bytes:
                raise ValueError("APKS extracted size exceeds configured limit")
            target = (destination / Path(*name.parts)).resolve()
            if not target.is_relative_to(destination.resolve()):
                raise ValueError("APKS extraction escaped destination")
            target.parent.mkdir(parents=True, exist_ok=True)
            copied = 0
            with zf.open(info) as src, target.open("wb") as dst:
                while chunk := src.read(1024 * 1024):
                    copied += len(chunk)
                    if copied > info.file_size or copied > max_total_bytes:
                        raise ValueError("Archive entry exceeded declared/configured size")
                    dst.write(chunk)
            if copied != info.file_size:
                raise ValueError("Archive entry size mismatch")
            extracted.append(target)
    if not extracted:
        raise ValueError("APKS archive did not contain APK split entries")
    return extracted
