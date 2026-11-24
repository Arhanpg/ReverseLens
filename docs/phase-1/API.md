# Phase 1 API

API base URL: `http://localhost:8080`; public endpoints are under `/api/v1`.

## Engines

```http
GET /api/v1/engines
```

## Upload

```bash
curl -X POST http://localhost:8080/api/v1/targets/android \
  -F 'file=@./sample.apk' \
  -F 'authorizationBasis=owner_or_developer' \
  -F 'authorizationConfirmed=true'
```

Accepted formats are APK, AAB and APKS. The API validates package archive structure, stores a local snapshot and records SHA-256. The authorization checkbox is a user attestation, not a legal determination.

## Queue analysis

```bash
curl -X POST http://localhost:8080/api/v1/targets/TARGET_UUID/runs \
  -H 'Content-Type: application/json' \
  -d '{"engineIds":["jadx","apktool","androguard","apkid"]}'
```

Send `{}` or an empty `engineIds` list to choose the default profile for that package format. The API checks tool/format compatibility and creates a separate Redis job per engine.

## Run and output inventory

```bash
curl http://localhost:8080/api/v1/runs/RUN_UUID
curl http://localhost:8080/api/v1/runs/RUN_UUID/files
curl -OJ 'http://localhost:8080/api/v1/runs/RUN_UUID/file?path=engines%2Fjadx%2Fengine-result.json'
```

Download paths are relative to the run root. Absolute paths, traversal segments and backslashes are rejected.
