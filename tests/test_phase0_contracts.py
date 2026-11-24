from pathlib import Path

import yaml

from scripts.validate_phase0 import (
    FIXTURE_SCHEMAS,
    ROOT,
    validation_messages,
    validate_all,
)


def test_phase0_metadata_and_fixtures_validate():
    assert validate_all(ROOT) == []


def test_engine_registry_has_unique_ids_and_many_candidates():
    registry = yaml.safe_load((ROOT / "engines" / "registry.yaml").read_text(encoding="utf-8"))
    engine_ids = [engine["engine_id"] for engine in registry["engines"]]

    assert len(engine_ids) >= 10
    assert len(engine_ids) == len(set(engine_ids))
    assert "jadx" in engine_ids
    assert "playwright" in engine_ids


def test_every_example_fixture_has_a_schema_mapping():
    for filename in FIXTURE_SCHEMAS:
        assert (ROOT / "tests" / "fixtures" / filename).is_file()


def test_example_targets_keep_android_and_web_separate():
    import json

    android = json.loads((ROOT / "tests/fixtures/example-android-target.json").read_text())
    web = json.loads((ROOT / "tests/fixtures/example-web-target.json").read_text())

    assert android["target_type"] == "android_artifact"
    assert web["target_type"] == "web_url"
    assert android["target_id"] != web["target_id"]
    assert web["scope"]["local_lab"] is True


def test_phase2_benchmark_fixtures_have_schema_mappings():
    assert "example-benchmark-profile.json" in FIXTURE_SCHEMAS
    assert "example-benchmark-observation.json" in FIXTURE_SCHEMAS


def test_invalid_engine_status_is_rejected():
    import json

    schema = json.loads((ROOT / "schemas/engine-execution.schema.json").read_text())
    instance = {
        "schema_version": "1.0.0",
        "execution_id": "execution-invalid-001",
        "run_id": "run-invalid-001",
        "engine_id": "jadx",
        "status": "success-ish",
        "created_at": "2026-11-21T00:00:00Z",
        "output_directory": "engines/jadx",
    }

    assert validation_messages(instance, schema)
