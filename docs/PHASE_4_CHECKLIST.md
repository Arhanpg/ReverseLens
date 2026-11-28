# Phase 4 review checklist

## Implemented in this milestone
- [x] Bounded APK runtime classifier for DEX, ELF shared libraries, ABIs, Flutter AOT markers and Hermes HBC magic/version.
- [x] Explicit runtime compatibility routing for Blutter, Hermes Decompiler and Ghidra.
- [x] Bounded native-library and Hermes bundle extraction.
- [x] APKEditor 1.4.9 install with checksum verification.
- [x] APKLeaks 2.6.3 install and safe argument-vector invocation using preinstalled JADX.
- [x] Optional Hermes Decompiler, Blutter and Ghidra adapter contracts.
- [x] Optional private/self-hosted MobSF API adapter with no redirects, no proxy environment, DNS private-address checks and timeouts.
- [x] Optional Exodus Standalone adapter; no authenticated downloader functionality.
- [x] Ghidra headless export script for function metadata, capped pseudocode and static call edges.
- [x] Normalized specialist observations and call-graph artifact with evidence hashes.
- [x] Specialist benchmark capability map and Flutter/Hermes/general profiles.
- [x] Persisted incompatible execution state and exclusion from accuracy scoring.
- [x] Synthetic runtime classifier and extraction tests.

## Maintainer acceptance still required
- [ ] Run the standard worker image build locally and inspect APKEditor/APKLeaks output on a source-known APK.
- [ ] Run Blutter against a source-known ARM64 Flutter libapp.so using pre-provisioned Dart runtime bins.
- [ ] Run Hermes Decompiler against a real supported HBC version fixture and compare recovered function inventory against source.
- [ ] Run Ghidra headless against known ARM64 and/or x86_64 ELF fixtures; verify function/call edge exports.
- [ ] Run MobSF against a private self-hosted instance with the API key supplied from a secret store.
- [ ] Run Exodus Standalone against a redistributable fixture and verify its tracker database/license.
- [ ] Curate capability-compatible verified ground truth for each specialist dataset before using accuracy metrics.
- [ ] Review AGPL/GPL/dual-license obligations before distributing or hosting optional tools.

CI does not claim these external optional-engine acceptance runs. Unsupported formats and runtimes must remain visibly incompatible, not silently treated as successful output.
