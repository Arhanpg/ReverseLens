# Phase 1 — Core Platform and Android Static MVP

**Branch:** `feature/phase-1-android-mvp`  
**Scope:** Local Android static-analysis slice: API/control plane, database, queue, worker, independent engine output, starter dashboard and automation.

## Delivered

- Java 21 / Spring Boot API.
- PostgreSQL schema managed by Flyway for targets, runs and engine executions.
- Redis list queue; jobs are enqueued after the database transaction commits.
- Python worker that executes each selected engine independently.
- Worker image pins JADX 1.5.7, Apktool 3.0.3, Androguard 4.1.4, APKiD 3.2.0 and bundletool 1.18.3.
- SHA-256 hash on upload and input hash re-check by worker.
- APK/AAB/APKS archive shape validation and authorization attestation field.
- Per-target and per-run directories; input snapshot and engine-specific raw/log outputs.
- Execution lifecycle state, exit status, duration, output bytes and per-file hashes.
- Minimal Next.js upload/run dashboard.
- Backend and worker tests; GitHub Actions backend, worker and frontend jobs.

## Supported inputs in this slice

| Input | Behavior |
|---|---|
| APK | Default profile runs JADX, Apktool, Androguard and APKiD independently |
| AAB | bundletool validates the bundle and extracts its base manifest |
| APKS | Worker safely extracts APK entries and records split inventory; bundletool adapter does not rebuild/re-sign/install the package |

For APKS, the optional Java/Smali analyzers may inspect the selected base split if explicitly selected, but other splits are only inventoried. Full split-aware fan-out is deferred. AAB is not passed to APK-only decompilers.

## Local startup

1. Install Docker Desktop with Compose support.
2. Copy `.env.example` to `.env`; replace both example secrets.
3. Run:

```bash
docker compose up --build
```

4. Open http://localhost:3000.
5. API health: http://localhost:8080/actuator/health.

Shutdown:

```bash
docker compose down
```

Data resides in named volumes. **Destructive:** `docker compose down -v` deletes the database, Redis queue and all local analysis workspaces.

## API

- `GET /api/v1/engines`
- `GET /api/v1/targets`
- `POST /api/v1/targets/android` (multipart: `file`, `authorizationBasis`, `authorizationConfirmed=true`)
- `GET /api/v1/targets/{targetId}`
- `POST /api/v1/targets/{targetId}/runs` (JSON `{"engineIds":["jadx","apktool"]}`; empty or omitted list uses compatible defaults)
- `GET /api/v1/targets/{targetId}/runs`
- `GET /api/v1/runs/{runId}`
- `GET /api/v1/runs/{runId}/files`
- `GET /api/v1/runs/{runId}/file?path=...`

Internal worker updates require the shared `X-ReverseLens-Worker-Token`.

## Workspace output

```text
android/<target-id>/run-<run-id>/
├── input/<uploaded-file>
├── engines/
│   ├── jadx/{raw,decompiled,logs,engine-result.json}
│   ├── apktool/{raw,decoded,logs,engine-result.json}
│   ├── androguard/{raw,analysis,logs,engine-result.json}
│   └── apkid/{raw,matches,logs,engine-result.json}
├── normalized/
├── benchmark/
├── reports/
└── run-manifest.json
```

Only selected engines receive output directories. Each engine's outputs are independent; one analyzer failure does not cancel the others.

## Security defaults

- Worker has no general internet egress: it is attached to an internal Compose network.
- Worker runs non-root, drops Linux capabilities, uses a read-only container root and CPU/RAM/PID limits.
- API and worker share only the named analysis workspace; no home directory or Docker socket is mounted.
- Workspace initialization sets the named volume's ownership before non-root services start.
- Uploads are size-limited, archive-checked and SHA-256 hashed.
- Worker rechecks input SHA-256, validates workspace-relative paths and extracts APKS entries with path/size limits.
- Subprocesses use argument vectors, have timeouts and are killed as process groups.
- This phase is static/offline. It adds no website scanning, login, cookie collection, access-control bypass or dynamic instrumentation.

This is a local-development baseline, not a hardened multi-tenant service. Use a disposable VM for untrusted APKs and do not expose API/worker services publicly.

## Third-party license notes

The main ReverseLens source remains under the repository's Apache-2.0 license. The worker image installs upstream tools with their own licenses. In particular, APKiD upstream states that it is dual-licensed under GPL and commercial terms; review the exact license files and compliance obligations before distributing a built image or hosted offering. Do not imply that third-party tools are relicensed by ReverseLens.

## Explicit limitations / Phase 2 handoff

- No benchmark experiment subsystem, ground-truth scoring or tool leaderboard yet.
- Androguard adapter collects package/manifest metadata and DEX inventory; it does not claim complete Java decompilation.
- APKiD detections are signatures/fingerprints, not proof of malware or vulnerability.
- APKS analyzer coverage is not fully split-aware; AAB-to-APKS generation requiring a device spec/signing setup is not implemented.
- Job recovery/reconciliation, leases and durable retry policies need hardening.
- The dashboard is a minimal operator UI, not the final architecture explorer.
- No web target analysis, Flutter Blutter, Hermes decompilation, Ghidra, MobSF or runtime instrumentation in this phase.
- No multi-user auth, remote workers or production secrets manager.

Phase 1 therefore means a working local control plane and APK static MVP, not the full ReverseLens roadmap.
