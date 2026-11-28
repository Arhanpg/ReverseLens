# Phase 4 — Specialist Android and native analysis

## Scope

Phase 4 adds runtime-aware selection of Android specialist engines and preserves each engine's result separately. The implementation remains static and local-first. It does not install APKs, attach to running apps, bypass protections or claim original-source recovery.

The worker now classifies DEX entries, real ELF shared libraries, ABI directories, Flutter libapp.so, React Native bundle candidates and Hermes HBC magic/version. Runtime profiles are saved per engine execution as raw/android-runtime-profile.json. The classifier is metadata-first and bounded by ZIP entry limits.

## Dispatch rules

| Specialist | Required input/runtime |
|---|---|
| APKEditor | APK; APKEditor decodes resources and manifest XML |
| APKLeaks | APK; URI/string-pattern candidates only |
| Blutter | Flutter ARM64 libapp.so in lib/arm64-v8a |
| Hermes Decompiler | A React Native bundle whose header has Hermes HBC magic |
| Ghidra | One or more ELF native shared libraries from the APK |
| MobSF | APK and private/self-hosted MobSF API credentials |
| Exodus Standalone | APK and pre-installed exodus_analyze.py |

Blutter, Hermes and Ghidra are runtime-gated before commands are dispatched. If a runtime or ABI does not match, the worker reports terminal status incompatible and records the reason. It does not mark that analysis as failed. APK/APKS specialist runs inspect the selected base split only; full split-aware fan-out is not implemented.

## Included and optional tools

The standard worker image installs APKEditor 1.4.9 with SHA-256 verification and APKLeaks 2.6.3. APKLeaks uses the preinstalled JADX binary and does not need to download a disassembler at run time.

Optional tools are not bundled in the default image:

- Hermes Decompiler 0.1.8: install through worker/requirements-specialists.txt in a separately reviewed specialist image/environment. It is AGPL-3.0-or-later.
- Blutter: mount a reviewed checkout with prebuilt Dart VM runtimes at /opt/reverselens-tooling/blutter. Its upstream script can download/build Dart runtimes when missing; ReverseLens requires pre-provisioned bin/ content and the default worker has no public egress.
- Ghidra 12.2: mount an unpacked distribution at /opt/reverselens-tooling/ghidra. The worker invokes support/analyzeHeadless and the repository's capped ExportProgramAnalysis.java script.
- Exodus Standalone 1.5.0: mount a reviewed checkout at /opt/reverselens-tooling/exodus-standalone. Only local static APK analysis is called; credentialed download commands are not used.
- MobSF: provide a separate private/self-hosted service through MOBSF_URL and MOBSF_API_KEY. The adapter disables environment proxies and redirect following, applies bounded timeouts, and rejects DNS results outside private/loopback ranges, including link-local and reserved addresses. Run it only on the internal worker network.

The tooling directory is mounted read-only. Do not commit optional binaries, Dart SDKs, credentials, proprietary APKs or generated reports.

Quark Engine is deliberately not enabled or registered in this milestone. Its canonical repository/release/CLI and licensing need verification before it can be safely presented as an engine.

## Outputs

Every specialist has its own engine workspace with raw output, command logs, engine-result.json, normalized-observations.json and a SHA-256 inventory. Ghidra also emits a call-graph.json with function nodes and static call-reference edges. Pseudocode export and edge counts are capped.

Normalizer semantics:
- Hermes output is partial reconstruction/disassembly, not source-equivalence proof.
- Blutter object-pool data is preserved raw and summarized.
- Ghidra edges are labelled static_reference; they are not runtime traces.
- APKLeaks string matches are unverified candidates; common token formats are redacted in normalized observations.
- Exodus tracker hits are signature matches, not proof of runtime execution.
- MobSF report summaries are analyst-review observations, not confirmed vulnerabilities.

Raw tool output is retained for reproducibility and may contain sensitive material. Protect the local workspace and follow its retention/deletion policy.

## Benchmark profiles

The database migration adds:
- android-specialist-foundation: APKEditor, APKLeaks, Exodus, MobSF and Ghidra.
- android-flutter-aot: Blutter.
- android-react-native-hermes: Hermes Decompiler.

The capability map ensures ground-truth scoring is performed only for capabilities supported by the selected engine. Incompatible executions remain visible as attempts, but they are excluded from accuracy metrics.

## Acceptance boundaries

CI tests synthetic APK archives for runtime classification, ABI/ELF/HBC detection, bounded extraction, command construction, MobSF address rejection, token redaction, Ghidra graph normalization and incompatible-run reporting. CI builds the standard worker image.

CI does not claim a real Blutter, Hermes Decompiler, Ghidra, MobSF or Exodus analysis. Maintainer acceptance requires source-known, redistributable Java/Kotlin, Flutter ARM64, Hermes HBC and native ELF samples, with artifact/source hashes and compatible verified ground truth. See docs/PHASE_4_CHECKLIST.md and docs/phase-4/TESTING.md.
