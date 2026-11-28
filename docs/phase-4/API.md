# Phase 4 API and execution contract

No new public endpoint is required for Phase 4. The existing routes are extended by the engine catalog and worker execution lifecycle.

## Engine catalog

GET /api/v1/engines returns the engine ID, version, supported package formats, capability description and integration status. Core engines and packaged APKEditor/APKLeaks report integrated. Optional tools report optional and require the external configuration described in the implementation guide.

The catalog advertises format compatibility. Runtime compatibility is decided inside the worker after the APK is classified; a format-compatible specialist can still finish with status incompatible.

## Analysis jobs

POST /api/v1/targets/{targetId}/runs accepts the existing engineIds list. The API rejects unknown engine IDs and unsupported archive formats. The worker classifies APK inputs and writes raw/android-runtime-profile.json under that engine's own output directory.

For Blutter, Hermes Decompiler and Ghidra the worker checks the runtime profile before dispatch. A mismatch produces a terminal incompatible status and a reason in engine-result.json / the execution error summary. It is not a tool failure and no external command is executed.

## Internal worker callback

PUT /internal/v1/worker/executions/{executionId} accepts the additional terminal status incompatible, authenticated with the existing worker token. Benchmark result finalization treats incompatible as terminal but excludes it from verified-ground-truth scoring.

The worker still submits benchmark metadata through POST /internal/v1/worker/executions/{executionId}/benchmark-data. Incompatible runs normally contain the runtime profile but no specialist observations.

## Evidence and graph output

Specialist raw files are inventoried with SHA-256. Ghidra's graphs/call-graph.json contains function nodes and static-reference edges with evidence path/hash. Edges are explicitly not labelled as observed runtime calls.
