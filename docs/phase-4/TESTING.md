# Phase 4 testing guide

## Automated worker tests

Run from the repository root:

    python -m pip install -r worker/requirements.txt -r requirements-dev.txt
    python -m pip install pytest
    PYTHONPATH=worker python -m pytest worker/tests -q

The synthetic tests cover runtime classification, Hermes magic/version detection, ABI gating, ELF-header validation, bounded archive entry handling, bounded extraction, APKEditor/APKLeaks command vectors, MobSF private-address rejection, APKLeaks token redaction, Ghidra call-graph normalization and explicit Blutter incompatibility.

## Backend and frontend

    mvn -B -f backend/pom.xml verify
    npm install --prefix frontend --no-audit --no-fund
    npm run lint --prefix frontend
    npm run build --prefix frontend

The Phase 4 workflow also builds the standard worker image. Optional toolchains are not downloaded by CI.

## Manual acceptance matrix

Use only redistributable source-known applications or explicitly authorized test artifacts. Keep source, build command/compiler version, binary hash and expected capability inventory together.

| Fixture | Expected result |
|---|---|
| Java/Kotlin APK | Core pipeline succeeds; Flutter/Hermes specialists become incompatible |
| Flutter ARM64 APK | Blutter eligible when its prebuilt Dart runtime is provisioned |
| Flutter ARM32-only APK | Blutter incompatible with explicit ARM64 explanation |
| React Native Hermes APK | Hermes Decompiler eligible only after the HBC magic check |
| React Native plain JS bundle | Hermes Decompiler incompatible |
| APK containing native ELF .so | Ghidra eligible when Ghidra 12.2 and export script are provisioned |
| APK with only non-ELF .so-like entries | Ghidra incompatible |
| MobSF target | Only a private/self-hosted MobSF API is permitted; verify credentials via secret store |
| Exodus target | Tracker names are signature matches and require analyst review |

CI synthetic tests do not claim that these real tool runs have passed. Mark each maintainer acceptance result with the fixture hash, tool version, host profile, duration, CPU/RSS/output bytes and output inventory.
