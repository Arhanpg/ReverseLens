# Phase 1 review checklist

Phase 1 is implemented in feature/phase-1-android-mvp. Merge only after review and confirmation of CI and local integration checks.

## Scope checklist

- [x] Spring Boot API project.
- [x] PostgreSQL migration for targets, runs and engine executions.
- [x] Redis queue and after-commit job enqueue.
- [x] SHA-256 upload hashing and worker re-verification.
- [x] APK/AAB/APKS upload archive validation.
- [x] Per-target/per-run workspace snapshots.
- [x] Independent engine output directories.
- [x] JADX, Apktool, Androguard, APKiD and bundletool adapters.
- [x] Worker timeouts and process-group termination.
- [x] Local-only worker network policy.
- [x] Next.js starter dashboard.
- [x] Maven, Python and frontend CI workflow.
- [x] Setup, API and testing documentation.
- [ ] Full integration run against a representative authorized APK on maintainer hardware.
- [ ] Confirm all three CI jobs pass on the final PR head.
- [ ] Review APKiD dual-license implications before image distribution.
- [ ] Review tool pins and release asset hashes before release.

## Known limitations

- APKS handling inventories split APKs; full split-aware fan-out is not implemented.
- AAB receives bundletool validation and manifest extraction only.
- Androguard adapter records package metadata and DEX inventory; it does not claim full Java source decompilation.
- Benchmark subsystem is Phase 2.
- Web capture is Phase 3.
- Job leases, recovery and durable retry policy need further hardening.
