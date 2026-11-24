# Phase 2 benchmark API

Base URL: `http://localhost:8080/api/v1`.

## Register dataset

```bash
curl -X POST http://localhost:8080/api/v1/benchmarks/datasets \
  -H 'Content-Type: application/json' \
  -d '{
    "datasetId": "demo-android-fixtures",
    "name": "Demo Android fixtures",
    "version": "1.0.0",
    "sourceType": "authorized_exploratory",
    "description": "Local APK samples authorized for benchmark analysis",
    "platforms": ["android"],
    "capabilityClasses": ["apk_parsing", "manifest", "dex_to_source", "smali", "packer_detection"],
    "targetIds": ["TARGET_UUID"],
    "licenseIdentifier": "local-authorized-sample",
    "redistributionStatus": "not_reviewed"
  }'
```

Accepted source types are `source_known`, `owasp_training`, `open_source_with_known_revision`, `authorized_exploratory` and `fictional_example`. License and redistribution fields are required.

## Add target-specific ground truth

```bash
curl -X POST 'http://localhost:8080/api/v1/benchmarks/datasets/demo-android-fixtures/ground-truth?targetId=TARGET_UUID' \
  -H 'Content-Type: application/json' \
  -d '{
    "capabilityClass": "manifest",
    "itemType": "permission",
    "expectedValue": "android.permission.INTERNET",
    "canonicalKey": "permission:android.permission.internet",
    "validationStatus": "verified",
    "reviewer": "maintainer",
    "sourceReference": {
      "source_path": "app/src/main/AndroidManifest.xml",
      "source_revision": "fixture-commit-or-revision"
    },
    "owaspMappings": ["MASVS-PLATFORM-1"]
  }'
```

For `verified` labels, the API requires a reviewer and at least one source path, source revision or source SHA-256. OWASP tags are optional maintainer annotations; they are never inferred automatically. Labels in states other than `verified` are retained but excluded from accuracy scoring.

## Profiles

- `GET /benchmarks/profiles`
- `GET /benchmarks/profiles/{profileKey}`
- `POST /benchmarks/profiles`

Custom profile example:

```json
{
  "profileKey": "android-metadata-custom",
  "name": "Android metadata comparison",
  "platform": "android",
  "capabilityClasses": ["apk_parsing", "manifest"],
  "engineIds": ["androguard", "apktool"],
  "defaultRepetitions": 3,
  "defaultConcurrency": 1,
  "description": "Manifest and package metadata comparison."
}
```

Only integrated engine IDs can be selected. Phase 2 v1 accepts Android profiles and enforces concurrency 1.

## Create experiment

```bash
curl -X POST http://localhost:8080/api/v1/benchmarks/experiments \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Android static core — three repetitions",
    "datasetId": "demo-android-fixtures",
    "profileKey": "android-static-core",
    "repetitions": 3,
    "concurrency": 1,
    "cachePolicy": "not_controlled"
  }'
```

If `targetIds` and `engineIds` are omitted, the dataset targets and profile engines are used. The experiment is limited to 250 target × engine × repetition attempts. Supported cache policy values are `cold_each_run`, `warm_each_run`, `mixed` and `not_controlled`; this field records declared conditions and does not flush OS caches.

## Inspect results and evidence

- `GET /benchmarks/experiments`
- `GET /benchmarks/experiments/{experimentId}`
- `GET /benchmarks/experiments/{experimentId}/observations?engineId=jadx&limit=1000`
- `GET /benchmarks/experiments/{experimentId}/report` — JSON
- `GET /benchmarks/experiments/{experimentId}/report?format=markdown`
- `GET /benchmarks/experiments/{experimentId}/report?format=html`

The observations endpoint is bounded to 5,000 rows per request and can filter by engine ID. Each record contains the target/run/execution IDs, capability, canonical key, confidence, evidence path and evidence SHA-256, plus a run-relative path that can be downloaded via the Phase 1 run file endpoint.

## Key status semantics

- `queued` / `running`: compatible engine attempts are pending or active.
- `completed`: all compatible attempts succeeded, or all non-success entries were explicitly incompatible.
- `partial`: a mixture of successes and failures.
- `failed`: no compatible engine attempt succeeded.
- Per-attempt `incompatible`: the engine does not support that package format; it is excluded from success/accuracy denominators.
