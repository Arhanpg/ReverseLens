# Phase 2 review checklist

Phase 2 is implemented on `feature/phase-2-benchmark-engine`. Merge after reviewing CI and the integrated manual acceptance item.

## Delivered scope

- [x] Dataset registry with target membership, source/version/license/redistribution metadata.
- [x] Custom and built-in Android benchmark profiles.
- [x] Ground-truth states; only verified capability-compatible labels are scored.
- [x] Maintainer-supplied OWASP tags retained as annotations.
- [x] Experiment orchestration with per-engine/per-target/per-repetition Phase 1 runs.
- [x] Explicit incompatible status for unsupported formats.
- [x] Repetitions (1–50), bounded attempt count (250) and sequential concurrency.
- [x] Input manifest hash and run/execution provenance.
- [x] Normalized Android observations linked to raw evidence and SHA-256.
- [x] API-side evidence file/hash verification.
- [x] Wall/CPU time, peak RSS estimate, output size, host profile and tool/adapter versions.
- [x] Capability-aware precision, recall, F1, coverage, duplicate rate and evidence completeness.
- [x] Unique/shared recoveries, attempt scorecards and JSON/Markdown/HTML exports.
- [x] Benchmark Lab dataset, ground-truth, experiment, scorecard and evidence views.
- [x] Phase 0 validator includes benchmark profile and observation schemas/fixtures.

## Review before merge

- [ ] All Phase 2 CI jobs pass on the PR head.
- [ ] Complete integrated run with a representative authorized APK on maintainer hardware.
- [ ] Review APKiD dual-license obligations before distributing worker images.
- [ ] Review dataset redistribution/licensing per target before publishing benchmark data.
- [ ] Verify ground-truth labels and source references before setting status to `verified`.

## Deliberate limitations

- Web benchmarking is Phase 3.
- Dynamic/runtime, Flutter/Hermes/Ghidra specialists are later phases.
- Concurrency is fixed at 1; OS-level cold/warm cache control is not implemented.
- Normalizers provide deterministic baseline observations, not complete semantic/source-line equivalence.
- OWASP mappings are user/maintainer supplied and are not inferred findings.
