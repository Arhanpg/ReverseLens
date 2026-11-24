import hashlib
import zipfile
import pytest
from reverselens_worker.security import extract_apks_safely, inventory_files, safe_workspace_path, sha256_file


def test_workspace_path_rejects_traversal(tmp_path):
    with pytest.raises(ValueError):
        safe_workspace_path(tmp_path, "../escape.txt")


def test_workspace_path_accepts_normal_relative_path(tmp_path):
    assert safe_workspace_path(tmp_path, "android/target/run/file.apk") == (tmp_path / "android/target/run/file.apk").resolve()


def test_sha256_and_inventory(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("reverse lens")
    assert sha256_file(sample) == hashlib.sha256(b"reverse lens").hexdigest()
    assert inventory_files(tmp_path)[0]["path"] == "sample.txt"


def test_apks_extracts_split_apks_safely(tmp_path):
    archive = tmp_path / "sample.apks"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("splits/base-master.apk", b"base")
        zf.writestr("splits/config.en.apk", b"locale")
    items = extract_apks_safely(archive, tmp_path / "out")
    assert len(items) == 2
    assert (tmp_path / "out/splits/base-master.apk").read_bytes() == b"base"


def test_apks_rejects_path_traversal(tmp_path):
    archive = tmp_path / "unsafe.apks"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../outside.apk", b"bad")
    with pytest.raises(ValueError):
        extract_apks_safely(archive, tmp_path / "out")
