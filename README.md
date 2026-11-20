# ReverseLens

**Unified Android & Web Reverse Engineering Workbench**

ReverseLens is an open-source, local-first platform for authorized Android artifact and web client analysis. It orchestrates specialist open-source tools, preserves each tool's output independently, normalizes evidence and benchmarks tools against one another.

> **Core idea:** run multiple engines on the same authorized target, retain separate results, and measure what each engine actually recovers.

## Why ReverseLens?

ReverseLens is not another wrapper around one decompiler. It is a multi-engine workbench and benchmarking environment.

- **Android:** APK, AAB and split package analysis; Java/Kotlin DEX; Flutter; React Native/Hermes; native ARM libraries.
- **Web:** authorized browser capture; DOM, JavaScript bundles, assets, routes and browser-visible network observations.
- **Many engines:** independently selectable adapters with compatibility-aware orchestration.
- **Separate outputs:** every engine has its own folder containing raw output, logs, version and metrics.
- **Benchmarking:** compare recovery coverage, precision/recall where ground truth exists, runtime, memory, output size, repeatability and evidence quality.
- **Interactive analysis:** code explorer, graphs, findings, provenance and reports.
- **Local-first:** run locally first; remote workers are a later optional extension.

## Project status

**Phase 0 completed — Phase 1 is ready to begin.** The repository now contains the architecture baseline, 13 JSON Schemas, a 25-candidate engine registry, sample records, a Phase 0 validator, pytest tests and GitHub Actions validation.

The Phase 0 workflow passed on the recorded commit: [GitHub Actions run](https://github.com/Arhanpg/ReverseLens/actions/runs/44807176269). This validates repository contracts and fixtures; it does not mean any reverse-engineering engine has been installed or integrated.

See [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md), [Phase 0 checklist](docs/PHASE_0_CHECKLIST.md), [architecture overview](docs/architecture/OVERVIEW.md), [benchmark methodology](docs/benchmark-methodology/README.md), [authorization policy](docs/legal-and-authorization/POLICY.md), [threat model](docs/threat-model/THREAT_MODEL.md), and [engine registry](engines/registry.yaml).

No engine integration is complete until it meets the Definition of Done in the development plan.

## Workflow

1. Create a project and register an authorized target or user-supplied artifact.
2. Compute the input hash and identify its format/runtime.
3. Select one engine, a subset, or all compatible installed engines.
4. Run each engine in an isolated worker.
5. Preserve each engine's raw files, logs and metadata separately.
6. Normalize observations with evidence provenance.
7. Compare and benchmark results.
8. Explore code, components, call/dependency/network graphs and findings.
9. Export a technical report.

## Example workspace

```text
workspace/web/<target>/run-<id>/
├── input/
├── engines/
│   ├── 01-playwright/
│   ├── 02-web-check/
│   ├── 03-wappalyzergo/
│   ├── 04-webcrack/
│   ├── 05-wakaru/
│   ├── 06-oxc/
│   ├── 07-retirejs/
│   └── 08-lighthouse/
├── normalized/
├── graphs/
├── benchmark/
├── reports/
└── run-manifest.json
```

Android runs use the same structure with Android-specific tools such as JADX, Apktool, Androguard, APKiD, MobSF, Ghidra, Blutter and hermes-dec. Only selected, compatible or attempted tools are materialized; skipped and incompatible engines are explicitly marked, never shown as successful.

## Candidate engines

### Android
- [JADX](https://github.com/skylot/jadx) — DEX to Java-like source
- [Apktool](https://github.com/iBotPeaches/Apktool) — resources, manifest and Smali
- [Androguard](https://github.com/androguard/androguard) — APK/DEX parsing and analysis
- [APKiD](https://github.com/rednaga/APKiD) — compiler/packer/protector fingerprinting
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) — mobile application security analysis
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) — native binary reverse engineering
- [bundletool](https://github.com/google/bundletool) — Android App Bundle processing
- [Blutter](https://github.com/worawit/blutter) — Flutter AOT analysis
- [hermes-dec](https://github.com/P1sec/hermes-dec) — React Native Hermes bytecode
- [APKEditor](https://github.com/REAndroid/APKEditor) — APK processing
- [APKLeaks](https://github.com/dwisiswant0/apkleaks) — URI/endpoint/secret-pattern triage

### Web
- [Playwright](https://github.com/microsoft/playwright) — browser capture and automation
- [Web-Check](https://github.com/lissy93/web-check) — website configuration/OSINT checks
- [Wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) — technology fingerprinting
- [Webcrack](https://github.com/j4k0xb/webcrack) — JS deobfuscation and unpacking
- [Wakaru](https://github.com/pionxzh/wakaru) — modern JS bundle reconstruction
- [Oxc](https://github.com/oxc-project/oxc) — JavaScript/TypeScript AST tools
- [Retire.js](https://github.com/RetireJS/retire.js) — vulnerable frontend dependency detection
- [Lighthouse](https://github.com/GoogleChrome/lighthouse) — performance and quality auditing

These are candidate integrations, not a guarantee of equal suitability or maintenance. Verify versions, licenses, CLI contracts and compatibility before integration.

## Benchmarking philosophy

Compare tools only on relevant capabilities. A technology fingerprinting tool should not be scored as a failed decompiler. Record input SHA-256, engine/adapter versions, configuration, exit status, runtime, peak memory, output size, warnings, output hashes and ground-truth metrics where available. Repeat performance runs and report median and spread.

Use source-known sample apps, OWASP demos and local labs. Commercial websites do not provide ground truth for their private backend and must not be treated as complete source-recovery benchmarks.

## Architecture direction

- Frontend: Next.js + TypeScript
- Control plane: Java / Spring Boot
- Metadata: PostgreSQL
- Queue: Redis
- Execution: isolated Docker workers with Python, Node.js and Java adapters
- Artifact storage: local filesystem initially; optional MinIO
- Code/graphs: Monaco, Cytoscape.js and React Flow

## Safety and authorization

ReverseLens is designed for user-owned artifacts, authorized assessments and local test labs.

- Do not bypass authentication, paywalls, anti-bot systems, rate limits or technical access controls.
- Website capture requires target authorization and scope, strict allowlisting, DNS/IP/redirect validation, network egress restrictions and bounded request rates.
- Do not import browser cookies or collect credentials by default.
- Treat APKs, archives, binaries and web responses as untrusted; isolate workers and enforce resource limits.
- Do not commit commercial APKs, proprietary source, private traffic captures, cookies, tokens or credentials.
- Respect applicable law, licenses, platform terms and bug bounty scope.

ReverseLens analyzes client-visible artifacts. It cannot recover server-only source code, private databases, model weights or internal backend logic merely from a browser or APK.

## Phase 0 validation

Run locally after installing the development requirements:

```bash
python -m pip install -r requirements-dev.txt
python scripts/validate_phase0.py
python -m pytest
```

The validator checks JSON Schema contracts, registry entries, dependency references, sample fixtures and cross-record references. It does not install or execute reverse-engineering engines.

## Documentation

- [Master Development Plan](DEVELOPMENT_PLAN.md)
- [Phase 0 completion checklist](docs/PHASE_0_CHECKLIST.md)
- [Architecture overview](docs/architecture/OVERVIEW.md)
- [Benchmark methodology](docs/benchmark-methodology/README.md)
- [Authorization policy](docs/legal-and-authorization/POLICY.md)
- [Threat model](docs/threat-model/THREAT_MODEL.md)
- [How to add an engine](docs/engine-registry/ADDING_AN_ENGINE.md)
- [Engine registry](engines/registry.yaml)
- [OWASP Mobile Application Security Testing Guide](https://mas.owasp.org/MASTG/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## Contributing

Contributions should add tested adapters, fixtures, normalized evidence types, benchmark datasets, documentation or UI improvements. Every engine integration must document its license, version, supported inputs, isolation needs, raw outputs, normalized mapping, benchmark and known limitations.

## License

See [LICENSE](LICENSE). Third-party engines retain their own licenses; integration does not relicense them. Review compatibility and attribution requirements before redistribution or hosted deployment.