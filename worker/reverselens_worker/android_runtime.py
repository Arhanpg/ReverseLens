from __future__ import annotations

import json
import re
import zipfile
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath

HERMES_MAGIC = bytes.fromhex("c61fbc03c103191f")
SUPPORTED_ABIS = {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}
MAX_APK_ENTRIES = 100_000
MAX_RECORDED_LIBRARIES = 5_000


@dataclass(frozen=True)
class AndroidRuntimeProfile:
    classifier_version: str
    runtime_families: tuple[str, ...]
    abis: tuple[str, ...]
    dex_count: int
    native_library_count: int
    native_libraries: tuple[str, ...]
    flutter_libapp_abis: tuple[str, ...]
    hermes_bundle_path: str | None
    hermes_bytecode_version: int | None
    evidence: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


def _safe_member(name: str) -> bool:
    if "\\" in name or "\x00" in name:
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts


def classify_android_apk(apk_path) -> AndroidRuntimeProfile:
    """Classify Android runtimes using bounded ZIP metadata and small header reads."""
    runtime: set[str] = set()
    abis: set[str] = set()
    flutter_abis: set[str] = set()
    native: list[str] = []
    evidence: list[str] = []
    warnings: list[str] = []
    dex_names: set[str] = set()
    hermes_path = None
    hermes_version = None

    with zipfile.ZipFile(apk_path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_APK_ENTRIES:
            raise ValueError("APK has too many ZIP entries for runtime classification")
        for info in entries:
            if not _safe_member(info.filename):
                warnings.append("Unsafe archive member skipped during runtime classification.")
                continue
            if info.is_dir():
                continue
            name = info.filename
            parts = PurePosixPath(name).parts
            if re.fullmatch(r"classes(?:\d+)?\.dex", name):
                dex_names.add(name)
            if (len(parts) == 3 and parts[0] == "lib" and parts[1] in SUPPORTED_ABIS
                    and parts[2].endswith(".so")):
                with archive.open(info) as handle:
                    elf_magic = handle.read(4)
                if elf_magic == b"\x7fELF":
                    abis.add(parts[1])
                    if len(native) < MAX_RECORDED_LIBRARIES:
                        native.append(name)
                    if parts[2] == "libapp.so":
                        flutter_abis.add(parts[1])
                    if parts[2] == "libhermes.so":
                        evidence.append("native/libhermes.so:" + parts[1])
            if parts and parts[-1] == "libflutter.so":
                evidence.append("native/libflutter.so")
            if (name.lower().endswith(("index.android.bundle", "main.jsbundle",
                                       "index.android.bundle.hbc")) and info.file_size >= 12):
                with archive.open(info) as handle:
                    header = handle.read(16)
                if header[:8] == HERMES_MAGIC:
                    hermes_path = name
                    hermes_version = int.from_bytes(header[8:12], "little")
                    evidence.append("Hermes HBC header:" + name)
                else:
                    evidence.append("React Native bundle candidate:" + name)

    if dex_names:
        runtime.add("android-java-kotlin")
        evidence.append(f"DEX files:{len(dex_names)}")
    if flutter_abis:
        runtime.add("flutter-aot")
        evidence.append("Flutter libapp.so")
    if hermes_path:
        runtime.add("react-native-hermes")
    elif any(item.startswith("native/libhermes.so:") for item in evidence):
        runtime.add("react-native-hermes-runtime")
    elif any(item.startswith("React Native bundle candidate:") for item in evidence):
        runtime.add("react-native-bundle-candidate")
    if native:
        runtime.add("native-elf")
    if not runtime:
        runtime.add("unknown")

    return AndroidRuntimeProfile(
        classifier_version="1.0.0",
        runtime_families=tuple(sorted(runtime)),
        abis=tuple(sorted(abis)),
        dex_count=len(dex_names),
        native_library_count=len(native),
        native_libraries=tuple(sorted(native)),
        flutter_libapp_abis=tuple(sorted(flutter_abis)),
        hermes_bundle_path=hermes_path,
        hermes_bytecode_version=hermes_version,
        evidence=tuple(evidence),
        warnings=tuple(warnings),
    )


def compatibility(engine_id: str, profile: AndroidRuntimeProfile) -> tuple[bool, str]:
    families = set(profile.runtime_families)
    if engine_id == "blutter":
        if "flutter-aot" not in families:
            return False, "Blutter requires a Flutter AOT libapp.so."
        if "arm64-v8a" not in profile.flutter_libapp_abis:
            return False, "Blutter currently supports Android ARM64 libapp.so only."
        return True, "Flutter ARM64 libapp.so detected."
    if engine_id == "hermes-dec":
        if not profile.hermes_bundle_path:
            return False, "No Hermes HBC bundle magic was found in the APK."
        return True, f"Hermes HBC bytecode version {profile.hermes_bytecode_version} detected."
    if engine_id == "ghidra":
        if not profile.native_libraries:
            return False, "No native ELF shared libraries were found in the APK."
        return True, "Native ELF shared libraries detected."
    if engine_id in {"jadx", "apktool", "androguard", "apkid", "apkeditor",
                     "apkleaks", "exodus-standalone", "mobsf"}:
        return True, "APK input is supported; tool-specific coverage remains engine-dependent."
    return False, "No compatibility rule is defined for this engine."
