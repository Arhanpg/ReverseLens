# Phase 2 — Multi-engine Benchmark Engine and Android Evidence Reports

**Implementation branch:** `feature/phase-2-benchmark-engine`  
**Scope:** Android benchmark datasets, profiles, repeated experiment orchestration, capability-aware scoring, evidence normalization, resource/environment provenance, Benchmark Lab UI and JSON/Markdown/HTML reports.

## What Phase 2 adds

- PostgreSQL/Flyway tables for datasets, dataset targets, profiles, verified ground truth, experiments, attempts, normalized observations and per-attempt results.
- Built-in profiles for Android static core, package metadata, DEX recovery and App Bundle inspection.
- Experiment orchestration that creates one independent Phase 1 run per compatible target × engine × repetition.
- Explicit `incompatible` attempts when an engine does not support a target format.
- Sequential repetition controls (1–50, default 3) and a maximum of 250 attempts per experiment.
- Ground-truth review states and maintainer-supplied OWASP tags.
- Worker normalization for package metadata, manifest permissions/components, DEX inventory, Smali/Java classes/methods, safe URL literals, ordinary client strings, packer fingerprints and bundle split inventory.
- Worker-side wall time, CPU time, peak RSS estimate, output bytes/file count and host environment profile.
- API-side validation that every normalized observation references a real file under the engine workspace and the declared SHA-256 matches the bytes.
- Capability-aware precision/recall/F1/coverage, duplicate rate, evidence completeness, unique/shared recoveries and repeated-run scorecards.
- Filterable observation API, evidence download links in the UI, and JSON/Markdown/HTML reports.

## Start the application

Phase 2 builds on the Phase 1 local stack:

```bash
cp .env.example .env
# Replace POSTGRES_PASSWORD and REVERSE_LENS_WORKER_TOKEN.
docker compose up --build
```

Dashboard: http://localhost:3000  
Benchmark Lab: http://localhost:3000/benchmarks  
API health: http://localhost:8080/actuator/health

For local code changes, run the backend, worker and frontend checks in [TESTING.md](TESTING.md).

## Typical workflow

1. Upload an authorized APK in the Phase 1 workbench.
2. Register one or more targets into a benchmark dataset. Record the dataset source, version, license/redistribution status, and source revision where known.
3. Add target-specific expected items for each capability class. Use `verified` only after a maintainer has checked the label and supplied a reviewer plus a source path, source revision or source SHA-256.
4. Choose a built-in/custom profile and create an experiment.
5. Let each compatible engine/repetition run as a separate Phase 1 execution. Other engine failures remain independent.
6. Inspect the per-engine scorecard, unique/shared recoveries, attempt table and normalized evidence.
7. Download JSON, Markdown or HTML result reports.

## Ground-truth scoring rules

Only `verified` ground-truth rows are eligible. The selected engine's declared capability classes further restrict the expected items. Observations are then restricted to only those capability classes for which verified labels exist. This prevents an unlabeled capability from being counted as a false positive just because the same engine has ground truth in another capability.

- Precision = TP / (TP + FP)
- Recall/coverage = TP / (TP + FN)
- F1 = harmonic mean of precision and recall.
- Duplicate rate = redundant normalized observations / all normalized observations in the scored capability set.
- Evidence completeness = observations with a traceable evidence file and SHA-256 / observations in the scored capability set.

If no verified capability-compatible ground truth exists, precision, recall, F1 and coverage are `null` (displayed as N/A), not zero. If applicable ground truth does exist but the engine recovers none of it, the corresponding scores are zero.

All observations remain in the overall evidence inventory even when their capability class is not currently scored.

## Reproducibility controls and honest limits

- Repetitions: 1–50; recommended default: 3.
- Concurrency is deliberately fixed at 1 in Phase 2 v1 to reduce CPU/RAM contention.
- Cache policy is recorded as declared by the experiment. ReverseLens does **not** flush the operating-system filesystem cache. Do not claim cold-cache measurements unless an external lab procedure actually controls cache state.
- Each attempt records input SHA-256, run/execution IDs, tool version, adapter version, wall time, CPU time, peak RSS estimate, output bytes/file count, normalized observation count, warnings and host profile (OS, architecture, CPU model, RAM, Python version and processor count).
- Peak RSS is estimated from Linux child-process resource accounting in the command wrapper. It is not an OS-wide hardware monitor.
- The API re-hashes evidence files before accepting normalized observations.
- The experiment manifest hash binds dataset ID, target hashes, selected engines, repetition count, cache policy and methodology version.

## Normalization coverage in v1

| Engine | Normalized evidence |
|---|---|
| Androguard | Package name, permissions, manifest components and DEX entry inventory |
| Apktool | Manifest permissions/components and bounded Smali class/method declarations |
| JADX | Reconstructed Java classes/methods and client-visible URL/string literals; URL user-info, query and fragment are stripped |
| APKiD | Compiler, packer and protector fingerprints when emitted by the pinned JSON output |
| bundletool | AAB manifest items and APKS split inventory |

This is an evidence-oriented baseline normalizer, not a full semantic parser. It does not claim line-level source reconstruction, complete method coverage, call-graph equivalence or server-side source recovery.

## License and safety

Only benchmark targets the user owns or is explicitly authorized to assess. Keep proprietary source, APKs, user data and secrets out of public fixtures. Dataset license and redistribution state are recorded as metadata but are not legal advice. APKiD retains its upstream dual-license terms; review those before distributing a worker image.

## Phase 2 boundaries

Not included in this phase: web capture/benchmarking, dynamic instrumentation, Flutter/Hermes/Ghidra specialists, a weighted overall winner score, true OS-level cache flushing, parallel experiment concurrency, source-ground-truth acquisition automation, source line-map fidelity, and production multi-user authentication.
