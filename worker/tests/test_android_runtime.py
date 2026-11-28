import zipfile
from pathlib import Path

import pytest

from reverselens_worker.android_runtime import (
    HERMES_MAGIC,
    classify_android_apk,
    compatibility,
)
from reverselens_worker.specialist_adapters import (
    extract_hermes_bundle,
    extract_native_libraries,
)


def make_apk(path: Path, files: dict[str, bytes]):
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)


def test_classifies_flutter_only_when_libapp_is_elf_and_tracks_abis(tmp_path):
    apk = tmp_path / "flutter.apk"
    make_apk(apk, {
        "classes.dex": b"dex\n035\0",
        "lib/arm64-v8a/libflutter.so": b"\x7fELFflutter",
        "lib/arm64-v8a/libapp.so": b"\x7fELFdart",
        "lib/armeabi-v7a/libapp.so": b"\x7fELFdart32",
    })
    profile = classify_android_apk(apk)
    assert "flutter-aot" in profile.runtime_families
    assert "android-java-kotlin" in profile.runtime_families
    assert set(profile.flutter_libapp_abis) == {"arm64-v8a", "armeabi-v7a"}
    assert compatibility("blutter", profile) == (True, "Flutter ARM64 libapp.so detected.")


def test_arm32_flutter_package_is_incompatible_with_blutter(tmp_path):
    apk = tmp_path / "flutter32.apk"
    make_apk(apk, {"lib/armeabi-v7a/libapp.so": b"\x7fELFdart32"})
    profile = classify_android_apk(apk)
    compatible, reason = compatibility("blutter", profile)
    assert compatible is False
    assert "ARM64" in reason


def test_classifies_hermes_only_after_magic_check(tmp_path):
    apk = tmp_path / "react-native.apk"
    bundle = HERMES_MAGIC + (99).to_bytes(4, "little") + b"\x00" * 16
    make_apk(apk, {"assets/index.android.bundle": bundle, "lib/arm64-v8a/libhermes.so": b"\x7fELFhermes"})
    profile = classify_android_apk(apk)
    assert profile.hermes_bundle_path == "assets/index.android.bundle"
    assert profile.hermes_bytecode_version == 99
    assert compatibility("hermes-dec", profile)[0] is True


def test_plain_react_native_bundle_is_not_misidentified_as_hermes(tmp_path):
    apk = tmp_path / "plain-rn.apk"
    make_apk(apk, {"assets/index.android.bundle": b"var __BUNDLE_START_TIME__=Date.now();"})
    profile = classify_android_apk(apk)
    assert profile.hermes_bundle_path is None
    assert compatibility("hermes-dec", profile)[0] is False


def test_ghidra_requires_real_native_elf_not_just_so_suffix(tmp_path):
    apk = tmp_path / "native.apk"
    make_apk(apk, {
        "lib/arm64-v8a/libsample.so": b"\x7fELFsample",
        "lib/arm64-v8a/not-really-elf.so": b"plain-data",
    })
    profile = classify_android_apk(apk)
    assert profile.native_library_count == 1
    assert compatibility("ghidra", profile)[0] is True


def test_extractors_are_bounded_and_preserve_abi_paths(tmp_path):
    apk = tmp_path / "sample.apk"
    make_apk(apk, {
        "assets/index.android.bundle": HERMES_MAGIC + (84).to_bytes(4, "little") + b"\0" * 4,
        "lib/arm64-v8a/libapp.so": b"\x7fELFsample",
    })
    profile = classify_android_apk(apk)
    bundle = extract_hermes_bundle(apk, tmp_path / "out", profile)
    libs = extract_native_libraries(apk, tmp_path / "native", {"arm64-v8a"})
    assert bundle.is_file()
    assert len(libs) == 1
    assert libs[0].relative_to(tmp_path / "native").as_posix() == "arm64-v8a/libapp.so"


def test_classifier_rejects_excessive_entry_count(tmp_path, monkeypatch):
    import reverselens_worker.android_runtime as runtime

    apk = tmp_path / "many.apk"
    make_apk(apk, {"one": b"x", "two": b"y"})
    monkeypatch.setattr(runtime, "MAX_APK_ENTRIES", 1)
    with pytest.raises(ValueError, match="too many"):
        classify_android_apk(apk)


def test_runtime_classifier_rejects_unsafe_archive_names(tmp_path):
    apk = tmp_path / "unsafe.apk"
    make_apk(apk, {"../outside": b"x", "lib/arm64-v8a/libapp.so": b"\x7fELFdata"})
    profile = classify_android_apk(apk)
    assert "flutter-aot" in profile.runtime_families
    assert profile.warnings
