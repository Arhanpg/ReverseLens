import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from reverselens_worker.engine_runner import execute
from reverselens_worker.normalizer import normalize_engine
from reverselens_worker.specialist_adapters import extract_native_libraries, run_mobsf, specialist_commands


def make_apk(path: Path, files: dict[str, bytes]):
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)


def test_native_extractor_ignores_non_elf_so_named_files(tmp_path):
    apk = tmp_path / "mixed.apk"
    make_apk(apk, {
        "lib/arm64-v8a/libgood.so": b"\x7fELFgood",
        "lib/arm64-v8a/libbad.so": b"not an elf",
    })
    extracted = extract_native_libraries(apk, tmp_path / "native")
    assert [p.name for p in extracted] == ["libgood.so"]


def test_apkeditor_adapter_uses_argument_vector(tmp_path, monkeypatch):
    jar = tmp_path / "APKEditor.jar"
    jar.write_bytes(b"fake jar")
    monkeypatch.setenv("APKEDITOR_JAR", str(jar))
    commands = specialist_commands("apkeditor", tmp_path / "input.apk", tmp_path / "raw")
    assert commands[0][:4] == ["java", "-jar", str(jar), "d"]
    assert "-i" in commands[0] and "-o" in commands[0]


def test_apkleaks_adapter_uses_json_output(tmp_path, monkeypatch):
    import reverselens_worker.specialist_adapters as adapters

    monkeypatch.setattr(adapters, "_required_executable", lambda _: "/usr/local/bin/apkleaks")
    commands = adapters.specialist_commands("apkleaks", tmp_path / "sample.apk", tmp_path / "raw")
    assert commands[0] == [
        "/usr/local/bin/apkleaks", "-f", str(tmp_path / "sample.apk"),
        "-o", str(tmp_path / "raw/apkleaks/results.json"), "--json",
    ]


@pytest.mark.parametrize("ip", ["8.8.8.8", "169.254.169.254", "224.0.0.1"])
def test_mobsf_rejects_public_link_local_and_multicast_dns(tmp_path, monkeypatch, ip):
    import reverselens_worker.specialist_adapters as adapters

    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    monkeypatch.setenv("MOBSF_URL", "http://mobsf:8000")
    monkeypatch.setenv("MOBSF_API_KEY", "fake-key")
    monkeypatch.setattr(adapters.socket, "getaddrinfo",
                        lambda *args, **kwargs: [(None, None, None, None, (ip, 8000))])
    with pytest.raises(RuntimeError, match="private"):
        run_mobsf(apk, tmp_path / "out")


def test_ghidra_normalizer_emits_evidence_linked_call_graph(tmp_path):
    raw = tmp_path / "raw/ghidra-export"
    raw.mkdir(parents=True)
    (raw / "libsample.so.json").write_text(json.dumps({
        "schema_version": "1.0.0",
        "binary_name": "libsample.so",
        "language_id": "AARCH64:LE:64:v8A",
        "functions": [
            {"name": "JNI_OnLoad", "entry": "1000", "pseudocode": "return 0;"},
            {"name": "native_init", "entry": "2000", "pseudocode": "return 1;"}
        ],
        "call_edges": [{"caller": "1000", "callee": "2000",
                        "caller_name": "JNI_OnLoad", "callee_name": "native_init"}]
    }))
    rows = normalize_engine("ghidra", tmp_path)
    graph = json.loads((tmp_path / "graphs/call-graph.json").read_text())
    assert len(graph["nodes"]) == 2
    assert len(graph["edges"]) == 1
    assert graph["edges"][0]["validation_status"] == "static_reference"
    assert any(row["capability_class"] == "native_call_graph" for row in rows)
    assert all(len(row["evidence_sha256"]) == 64 for row in rows)


def test_apkleaks_normalizer_redacts_recognized_token_candidates(tmp_path):
    raw = tmp_path / "raw/apkleaks/results.json"
    raw.parent.mkdir(parents=True)
    raw.write_text(json.dumps({"results": ["https://example.test/v1", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"]}))
    rows = normalize_engine("apkleaks", tmp_path)
    values = [row["observed_value"] for row in rows]
    assert any("example.test" in value for value in values)
    assert all("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in value for value in values)
    assert any("REDACTED" in value for value in values)


def test_blutter_on_non_flutter_apk_returns_incompatible_with_runtime_evidence(tmp_path):
    apk = tmp_path / "plain.apk"
    make_apk(apk, {"classes.dex": b"dex\n035\0"})
    digest = hashlib.sha256(apk.read_bytes()).hexdigest()
    root = tmp_path / "workspace"
    input_path = root / "input" / "plain.apk"
    input_path.parent.mkdir(parents=True)
    input_path.write_bytes(apk.read_bytes())
    result = execute({
        "engineId": "blutter",
        "inputFormat": "apk",
        "inputPath": "input/plain.apk",
        "inputSha256": digest,
        "outputDirectory": "outputs/blutter",
        "executionId": "test-execution",
        "runId": "test-run"
    }, root)
    assert result["status"] == "incompatible"
    assert "Flutter" in " ".join(result["warnings"])
    profile = root / "outputs/blutter/raw/android-runtime-profile.json"
    assert json.loads(profile.read_text())["runtime_families"] == ["android-java-kotlin"]
