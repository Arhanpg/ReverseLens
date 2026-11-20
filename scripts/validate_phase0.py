#!/usr/bin/env python3
"""Validate the ReverseLens Phase 0 contracts, registry and fixtures.

This deliberately validates local metadata only. It does not install or execute analyzers.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
FIXTURE_DIR = ROOT / "tests" / "fixtures"
REGISTRY_PATH = ROOT / "engines" / "registry.yaml"

FIXTURE_SCHEMAS = {
    "example-android-target.json": "target.schema.json",
    "example-web-target.json": "target.schema.json",
    "example-authorization.json": "authorization.schema.json",
    "example-web-authorization.json": "authorization.schema.json",
    "example-analysis-run.json": "analysis-run.schema.json",
    "example-engine-execution.json": "engine-execution.schema.json",
    "example-artifact.json": "artifact.schema.json",
    "example-observation.json": "observation.schema.json",
    "example-finding.json": "finding.schema.json",
    "example-benchmark-experiment.json": "benchmark-experiment.schema.json",
    "example-benchmark-result.json": "benchmark-result.schema.json",
    "example-benchmark-dataset.json": "benchmark-dataset.schema.json",
    "example-ground-truth-item.json": "ground-truth-item.schema.json",
}


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def load_schema(name: str) -> dict[str, Any]:
    path = SCHEMA_DIR / name
    schema = read_json(path)
    Draft202012Validator.check_schema(schema)
    return schema


def validation_messages(instance: Any, schema: dict[str, Any], *, registry: Registry | None = None) -> list[str]:
    validator = Draft202012Validator(
        schema,
        registry=registry or Registry(),
        format_checker=FormatChecker(),
    )
    return [error.message for error in sorted(validator.iter_errors(instance), key=lambda e: list(e.path))]


def validate_all(root: Path = ROOT) -> list[str]:
    """Return all validation errors; an empty list means Phase 0 metadata is valid."""
    errors: list[str] = []
    schema_names = [
        "target.schema.json",
        "authorization.schema.json",
        "engine.schema.json",
        "engine-registry.schema.json",
        "analysis-run.schema.json",
        "engine-execution.schema.json",
        "artifact.schema.json",
        "observation.schema.json",
        "finding.schema.json",
        "benchmark-experiment.schema.json",
        "benchmark-result.schema.json",
        "benchmark-dataset.schema.json",
        "ground-truth-item.schema.json",
    ]
    schemas: dict[str, dict[str, Any]] = {}
    for name in schema_names:
        try:
            schema = read_json(root / "schemas" / name)
            Draft202012Validator.check_schema(schema)
            schemas[name] = schema
        except Exception as exc:  # Keep validating other files to give a complete report.
            errors.append(f"Schema {name}: {exc}")

    engine_schema = schemas.get("engine.schema.json")
    registry_schema = schemas.get("engine-registry.schema.json")
    registry_data: dict[str, Any] | None = None
    if engine_schema and registry_schema:
        try:
            resources = Registry().with_resource(
                engine_schema["$id"], Resource.from_contents(engine_schema)
            )
            registry_data = yaml.safe_load((root / "engines" / "registry.yaml").read_text(encoding="utf-8"))
            if not isinstance(registry_data, dict):
                raise ValueError("Registry must be a YAML mapping")
            messages = validation_messages(registry_data, registry_schema, registry=resources)
            errors.extend(f"engines/registry.yaml: {message}" for message in messages)
        except Exception as exc:
            errors.append(f"engines/registry.yaml: {exc}")

    engine_ids: set[str] = set()
    if registry_data and isinstance(registry_data.get("engines"), list):
        engines = registry_data["engines"]
        for index, engine in enumerate(engines):
            if not isinstance(engine, dict):
                errors.append(f"Engine registry entry {index} must be an object")
                continue
            engine_id = engine.get("engine_id")
            if isinstance(engine_id, str):
                if engine_id in engine_ids:
                    errors.append(f"Duplicate engine_id: {engine_id}")
                engine_ids.add(engine_id)
            if engine_schema:
                errors.extend(
                    f"Engine {engine_id or index}: {message}"
                    for message in validation_messages(engine, engine_schema)
                )
        for engine in engines:
            if not isinstance(engine, dict):
                continue
            for dependency in engine.get("dependencies", []):
                if dependency not in engine_ids:
                    errors.append(
                        f"Engine {engine.get('engine_id')} references unknown dependency {dependency}"
                    )
        if len(engines) < 10:
            errors.append(f"Expected at least 10 candidate engines; found {len(engines)}")

    fixture_data: dict[str, dict[str, Any]] = {}
    for filename, schema_name in FIXTURE_SCHEMAS.items():
        try:
            fixture = read_json(root / "tests" / "fixtures" / filename)
            fixture_data[filename] = fixture
            schema = schemas.get(schema_name)
            if schema:
                errors.extend(
                    f"Fixture {filename}: {message}"
                    for message in validation_messages(fixture, schema)
                )
        except Exception as exc:
            errors.append(f"Fixture {filename}: {exc}")

    # Cross-record references catch errors that individual JSON Schemas cannot express.
    def get_fixture(filename: str) -> dict[str, Any] | None:
        return fixture_data.get(filename)

    android_target = get_fixture("example-android-target.json")
    web_target = get_fixture("example-web-target.json")
    android_auth = get_fixture("example-authorization.json")
    web_auth = get_fixture("example-web-authorization.json")
    run = get_fixture("example-analysis-run.json")
    execution = get_fixture("example-engine-execution.json")
    artifact = get_fixture("example-artifact.json")
    observation = get_fixture("example-observation.json")
    finding = get_fixture("example-finding.json")
    experiment = get_fixture("example-benchmark-experiment.json")
    benchmark_result = get_fixture("example-benchmark-result.json")
    dataset = get_fixture("example-benchmark-dataset.json")
    ground_truth = get_fixture("example-ground-truth-item.json")

    for target, authorization, label in [
        (android_target, android_auth, "Android"),
        (web_target, web_auth, "Web"),
    ]:
        if target and authorization:
            if target.get("authorization_record_id") != authorization.get("authorization_record_id"):
                errors.append(f"{label} target does not reference its example authorization record")
            if target.get("target_id") != authorization.get("target_id"):
                errors.append(f"{label} target and authorization target_id do not match")

    if run:
        if android_target and run.get("target_id") != android_target.get("target_id"):
            errors.append("Example run target_id does not match the Android target fixture")
        for engine_id in run.get("selected_engine_ids", []):
            if engine_id not in engine_ids:
                errors.append(f"Example run references unknown engine {engine_id}")

    if execution:
        if run and execution.get("run_id") != run.get("run_id"):
            errors.append("Example execution run_id does not match run fixture")
        if execution.get("engine_id") not in engine_ids:
            errors.append("Example execution references an unknown engine")

    if artifact and execution and artifact.get("engine_execution_id") != execution.get("execution_id"):
        errors.append("Example artifact engine_execution_id does not match execution fixture")

    if observation and artifact:
        evidence_ids = {item.get("artifact_id") for item in observation.get("evidence", [])}
        if artifact.get("artifact_id") not in evidence_ids:
            errors.append("Example observation does not reference the example artifact")

    if finding:
        observation_ids = {observation.get("observation_id")} if observation else set()
        artifact_ids = {artifact.get("artifact_id")} if artifact else set()
        if not set(finding.get("observation_ids", [])).issubset(observation_ids):
            errors.append("Example finding references an unknown observation")
        if not set(finding.get("evidence_artifact_ids", [])).issubset(artifact_ids):
            errors.append("Example finding references an unknown evidence artifact")

    if experiment:
        if android_target and android_target.get("target_id") not in experiment.get("target_ids", []):
            errors.append("Example experiment does not include the Android target")
        for engine_id in experiment.get("engine_ids", []):
            if engine_id not in engine_ids:
                errors.append(f"Example benchmark references unknown engine {engine_id}")

    if dataset and android_target:
        if android_target.get("target_id") not in dataset.get("targets", []):
            errors.append("Example dataset does not include the Android target")
    if experiment and dataset:
        if experiment.get("dataset_id") != dataset.get("dataset_id"):
            errors.append("Example experiment references the wrong dataset")
        if experiment.get("ground_truth_available") != dataset.get("ground_truth_available"):
            errors.append("Example experiment and dataset disagree about ground truth availability")
    if ground_truth and dataset:
        if ground_truth.get("dataset_id") != dataset.get("dataset_id"):
            errors.append("Example ground-truth item references the wrong dataset")
        if ground_truth.get("target_id") not in dataset.get("targets", []):
            errors.append("Example ground-truth item references a target outside its dataset")
    if benchmark_result:
        if experiment and benchmark_result.get("experiment_id") != experiment.get("experiment_id"):
            errors.append("Example benchmark result references the wrong experiment")
        if execution and benchmark_result.get("execution_id") != execution.get("execution_id"):
            errors.append("Example benchmark result references the wrong execution")

    return errors


def main() -> int:
    errors = validate_all()
    if errors:
        print(f"Phase 0 validation failed with {len(errors)} issue(s):", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1

    registry = yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))
    print(
        "Phase 0 validation passed: "
        f"11 JSON Schemas, {len(registry['engines'])} candidate engines, "
        f"{len(FIXTURE_SCHEMAS)} example fixtures and cross-record references."
    )
    print("No reverse-engineering tools were installed or executed by this validation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
