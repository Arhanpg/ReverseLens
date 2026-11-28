# ReverseLens — Master Development Plan

> Project: ReverseLens | Owner: Arhanpg | Plan version: 1.3 | Updated: 2026-11-28
> Status: Phases 0–2 merged into main; Phase 3 web-capture foundation on review branch | Type: Open-source, local-first, multi-engine Android and web reverse-engineering workbench

## Phase 0 implementation status

Phase 0 has been committed to the repository. Delivered baseline files include:
- `engines/registry.yaml`: 25 candidate analyzers with capability, input/output, network, isolation, resource and license-review metadata.
- `schemas/`: 13 JSON Schemas for targets, authorization, engines, registry, runs, executions, artifacts, observations, findings and benchmark records.
- `tests/fixtures/`: fictional Android and local-lab web records with related authorization, execution and benchmark examples.
- `scripts/validate_phase0.py` and `tests/test_phase0_contracts.py`: local structural and cross-reference validation.
- `.github/workflows/phase0-validation.yml`: automated validation and pytest workflow.
- `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, pull-request template and Dependabot configuration for public project governance.
- `docs/`: architecture, benchmark, authorization, threat-model, engine-onboarding and ADR documentation.

The Phase 0 GitHub Actions run completed successfully: [run 44807176269](https://github.com/Arhanpg/ReverseLens/actions/runs/44807176269). The run validates schemas, registry and fixtures only. It does not mean the candidate tools have been installed, benchmarked on the laptop or integrated into the application.

See [Phase 0 checklist](docs/PHASE_0_CHECKLIST.md) for the acceptance boundary.

## 1. Vision

ReverseLens is a unified workbench for analyzing authorized Android application artifacts and authorized web targets. It orchestrates multiple independent, specialist reverse-engineering and inspection tools, stores each engine's output separately, normalizes results into a common evidence model, and benchmarks the engines against one another.

**Primary goal:** answer what each engine recovers from the same input, how accurately it does so, what it misses, how the tools complement one another, and which combination produces the most complete evidence-backed analysis.

ReverseLens is not a single decompiler and must not claim reconstructed output is identical to original source unless an independent ground-truth comparison establishes that.

## 2. Core principles

1. Multi-engine: support multiple independent tools per target type; allow each to be selected, configured, run, retried and benchmarked independently.
2. Separate raw outputs: every engine gets its own immutable output directory. One tool must never overwrite another tool's result.
3. Reproducibility: record input hashes, tool versions, adapter versions, configuration, execution status, duration, resource use and output hashes.
4. Evidence-first: every normalized observation and finding links to an engine and a raw artifact/location.
5. Local-first: the first usable product runs locally without paid services.
6. Authorization-first: only user-supplied artifacts and targets with an appropriate authorization basis are analyzed.
7. Safe by design: uploaded artifacts and remote responses are untrusted; isolate parsers and browser workers.
8. Honest reconstruction: expose uncertainty, obfuscation, missing maps, unsupported formats and partial results.
9. Pluggable: adding an engine must not require changing the shared job model or existing adapters.
10. Benchmark-first: comparison is a core product feature, not a final optional add-on.

## 3. Scope and visibility model

### 3.1 Android inputs
- APK, AAB, APKS and supported split packages.
- XAPK/APKM only after format, provenance, parser safety and license review.
- Extracted DEX, ELF shared libraries, resources and related user-provided artifacts.
- User-authorized app extraction where permitted by device, platform and application terms.

### 3.2 Android runtime families
- Dalvik/ART bytecode: Java and Kotlin.
- Flutter / Dart AOT.
- React Native / Hermes.
- Native ARM32/ARM64 ELF and JNI libraries.
- Hybrid applications and WebViews.
- Packed, obfuscated and protected applications, with explicit limitations where appropriate.

### 3.3 Web inputs
- Authorized URL with explicit scope.
- Locally hosted test site.
- User-provided HTML/CSS/JS bundle or static site archive.
- HAR and supported browser capture artifacts.
- Publicly available or owner-provided source maps.

### 3.4 In scope
- Client-side code and assets delivered to a browser or device.
- Observable DOM, routes, requests, headers, browser console and runtime behavior within approved scope.
- Bytecode, resources, strings, symbols and native binaries present in supplied artifacts.
- Component/dependency detection and evidence-backed security/privacy observations.
- Comparative evaluation of tools and configurations.

### 3.5 Explicit limitations
- Server-side source, databases, private services, model weights, and internal ranking/pricing/dispatch logic are not recoverable merely from a client.
- Decompilation generally cannot restore original comments, names, build scripts, project layout or exact source.
- Missing source maps, obfuscation and compiler transformations may make reconstruction partial.
- Authentication, authorization, rate limits, anti-bot controls and technical protections must not be bypassed.
- A visible endpoint is not, by itself, a vulnerability.
- Do not claim completeness without a defined ground-truth benchmark.

## 4. Product modes

1. Android artifact analysis: upload a supported package, fingerprint it, and dispatch selected compatible engines.
2. Web target analysis: capture an authorized target with strict scope and request limits.
3. Offline web bundle analysis: analyze user-supplied bundles, source maps, HARs or archives without contacting production.
4. Benchmark lab: run the same corpus/configuration matrix across engines and compare results against ground truth.
5. Manual investigation: browse raw outputs, search files, inspect symbols/references, annotate evidence and export reports.

## 5. Multi-engine strategy

ReverseLens should support 10–15 or more independent tools for suitable target profiles over time. It must not blindly execute all tools on all inputs. Each engine declares compatible formats, runtime, resource requirements, isolation, role and limitations.

Engine roles: primary decompiler/capture engine; complementary analyzer; validator; runtime specialist; security/metadata analyzer; or browser-observability engine.

### 5.1 Android candidate registry

| Engine | Role | Priority |
|---|---|---|
| [JADX](https://github.com/skylot/jadx) | DEX to Java-like source and cross-references | P0 |
| [Apktool](https://github.com/iBotPeaches/Apktool) | Resources, manifest and Smali | P0 |
| [Androguard](https://github.com/androguard/androguard) | Programmatic APK/DEX parsing, analysis and graphs | P0 |
| [APKiD](https://github.com/rednaga/APKiD) | Compiler/packer/protector fingerprinting | P0 |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Broad mobile static/dynamic security analysis | P0/P1 |
| [bundletool](https://github.com/google/bundletool) | Android App Bundle and APK-set processing | P0 |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Native disassembly/decompilation | P1 |
| [APKEditor](https://github.com/REAndroid/APKEditor) | APK and split package processing | P1 |
| [Blutter](https://github.com/worawit/blutter) | Flutter AOT analysis | P1 |
| [hermes-dec](https://github.com/P1sec/hermes-dec) | React Native Hermes bytecode analysis | P1 |
| [APKLeaks](https://github.com/dwisiswant0/apkleaks) | URI/endpoint/secret-pattern triage | P1 |
| [Exodus standalone](https://github.com/Exodus-Privacy/exodus-standalone) | Tracker detection | P2 |
| [Quark Engine](https://github.com/quark-engine/quark-engine) | Rule-based Android behavior analysis | P2 |
| [Frida](https://github.com/frida/frida) | Runtime instrumentation in owned/authorized labs | P2 |
| [Objection](https://github.com/sensepost/objection) | Runtime exploration with Frida in authorized labs | P2 |

### 5.2 Web candidate registry

| Engine | Role | Priority |
|---|---|---|
| [Playwright](https://github.com/microsoft/playwright) | Browser capture, DOM, console, HAR and JS assets | P0 |
| [Web-Check](https://github.com/lissy93/web-check) | Domain/site configuration and OSINT checks | P1 |
| [Wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) | Web technology fingerprinting | P1 |
| [Webcrack](https://github.com/j4k0xb/webcrack) | JS deobfuscation, unminification and bundle unpacking | P1 |
| [Wakaru](https://github.com/pionxzh/wakaru) | Modern JS bundle reconstruction | P1 |
| [Oxc](https://github.com/oxc-project/oxc) | JS/TS parsing and AST analysis | P1 |
| [Retire.js](https://github.com/RetireJS/retire.js) | Known vulnerable frontend dependency detection | P1 |
| [Lighthouse](https://github.com/GoogleChrome/lighthouse) | Performance and quality audit | P1 |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | Technology identification | P2 |
| [source-map-explorer](https://github.com/danvk/source-map-explorer) | Bundle/source-map inspection | P2 |
| [mitmproxy](https://github.com/mitmproxy/mitmproxy) | Lab traffic inspection | P2 |
| [Wireshark](https://github.com/wireshark/wireshark) | Packet-level analysis of authorized captures | P2 |
| [CycloneDX](https://github.com/CycloneDX) | SBOM standards and tooling | P2 |

Web-Check, WhatWeb, Lighthouse and browser capture have different purposes; they are not interchangeable decompilers.

### 5.3 Engine registry governance

For every engine record canonical repository/docs, license, verified release/commit, CLI/API contract, input types, runtime requirements, output formats, resource estimates, isolation/network policy, limitations and last verification date. Revalidate names, maintenance, install instructions, CLI flags, licenses and compatibility before implementation. Copyleft and dual/commercial licensing must be reviewed before distribution or hosting.

## 6. Mandatory per-target output structure

Each target receives a stable workspace and unique run ID. Each engine receives its own output folder. Raw output is immutable; normalized results are derived and versioned.

### 6.1 Example: web target

```text
workspace/
└── web/
    └── <target-host>/
        └── run-<run-id>/
            ├── target.json
            ├── authorization.json
            ├── input/
            │   ├── target-url.txt
            │   └── capture-config.json
            ├── engines/
            │   ├── 01-playwright/{raw,dom,screenshots,network,assets,logs}/
            │   ├── 02-web-check/{raw,logs}/
            │   ├── 03-wappalyzergo/
            │   ├── 04-webcrack/
            │   ├── 05-wakaru/
            │   ├── 06-oxc/
            │   ├── 07-retirejs/
            │   ├── 08-lighthouse/
            │   ├── 09-whatweb/
            │   └── 10-source-map-explorer/
            ├── normalized/{assets,technologies,routes,dependencies,network-observations,findings}.json
            ├── graphs/{dependency-graph,route-graph,network-graph}.json
            ├── benchmark/{engine-matrix,metrics,comparison}.json
            ├── reports/{executive-summary.html,technical-report.md,report.json,findings.sarif}
            └── run-manifest.json
```

### 6.2 Example: Android application

```text
workspace/
└── android/
    └── <package-name>/
        └── run-<run-id>/
            ├── target.json
            ├── authorization.json
            ├── input/{original.apk,sha256.txt,package-inventory.json}
            ├── engines/
            │   ├── 01-jadx/{raw,sources,resources,logs}/
            │   ├── 02-apktool/
            │   ├── 03-androguard/
            │   ├── 04-apkid/
            │   ├── 05-mobsf/
            │   ├── 06-apkleaks/
            │   ├── 07-exodus/
            │   ├── 08-ghidra/
            │   ├── 09-blutter/
            │   ├── 10-hermes-dec/
            │   └── 11-bundletool/
            ├── normalized/{manifest,components,permissions,classes,methods,endpoints,dependencies,trackers,findings}.json
            ├── graphs/{class-graph,call-graph,component-graph}.json
            ├── benchmark/{engine-matrix,metrics,comparison}.json
            ├── reports/{executive-summary.html,technical-report.md,report.json,findings.sarif}
            └── run-manifest.json
```

These are example profiles. Create directories only for selected, compatible or attempted engines. Use explicit lifecycle states: `not_selected`, `incompatible`, `skipped`, `queued`, `running`, `succeeded`, `partial`, `failed`, `timed_out`, `cancelled`. An unselected or incompatible engine must never be represented as a successful run.

Store analyzed apps and captures locally by default. Never commit commercial applications, proprietary code, credentials, cookies, private traffic captures or sensitive output to the public repository.

## 7. Benchmarking is a first-class subsystem

### 7.1 Objectives
- Compare multiple engines on the same input.
- Measure unique and overlapping recoveries.
- Identify omissions, failures, false positives and false negatives.
- Compare combinations of tools as well as individual tools.
- Measure runtime, CPU, peak RAM, disk footprint and analyst review effort.

### 7.2 Fairness rules
- Same input artifact/capture and permitted scope.
- Record SHA-256, capture time, source dataset and tool versions.
- Pin tool versions, adapter versions, container image digests and configuration.
- Separate cold and warm cache tests.
- Repeat performance experiments at least 3 times, preferably 5; report median and spread.
- Record CPU, RAM, OS and runtime versions; record GPU only if relevant.
- Compare like-for-like capabilities. Do not score a technology fingerprinting engine as a failed decompiler.
- Score precision/recall only when labeled ground truth exists.
- Mark unavailable ground truth and unknown results explicitly.
- Include a human review workflow for semantic correctness and false positives.

### 7.3 Metrics

| Metric | Meaning |
|---|---|
| Completion rate | Successful or partial completed jobs / compatible attempted jobs |
| Coverage/recall | Correct ground-truth items recovered / total ground-truth items |
| Precision | Correct reported items / all reviewed reported items |
| F1 | Harmonic mean of precision and recall when valid |
| Structural fidelity | Agreement on packages, modules, functions, components and edges |
| Duplicate rate | Redundant observations after canonicalization |
| Runtime | Wall-clock duration and CPU time |
| Peak memory | Maximum resident memory |
| Output footprint | Output bytes and file count |
| Determinism | Stability of normalized results over repeated runs |
| Evidence completeness | Share of observations with actionable source/asset/location evidence |
| Analyst effort | Human time or steps needed to validate results |

Do not publish an arbitrary single 'best engine' score until weights and ground truth are documented. Publish per-metric results and limitations.

### 7.4 Engine result metadata

Each engine result records target/run ID, input hash, engine/version/commit digest, adapter version, configuration hash, timestamps, duration, exit code/state, resource metrics, output files/hashes/sizes, warnings/errors, normalized observations and ground-truth metrics where available.

### 7.5 Selection and scheduling

Support one engine, a chosen subset, all compatible installed engines, standard benchmark profiles and version/configuration matrices. Show queued/running/failed/incompatible states. Allow retry/cancel without deleting earlier outputs. Execute concurrency according to resource estimates and host limits, not a fixed 'run everything at once' rule.

## 8. Unified result and evidence model

Versioned JSON schemas: Target, AuthorizationRecord, AnalysisRun, EngineDefinition, EngineExecution, Artifact, Observation, Finding, GraphNode, GraphEdge, BenchmarkExperiment, BenchmarkMetric and Report.

Each observation/finding records engine ID/version, target/run ID, raw output path/hash, file/symbol/line/URL/network-event location, evidence excerpt or structured evidence, confidence, validation state, optional OWASP mapping and analyst notes.

Preserve engine-specific data even if normalization fails. Normalization must be repeatable and schema-versioned.

## 9. User experience

Main sections: Dashboard; New Analysis; Engine Selection; Live Execution; Target Workspace; Engine Result Viewer; Code Explorer; Architecture Explorer; Benchmark Lab; Reports; Settings; Authorization and Audit.

UX requirements:
- Show independent raw engine output and normalized result side by side.
- Link each finding to evidence and originating tool output.
- Show 'not applicable' rather than empty success.
- Label code as decompiled/reconstructed.
- Search across outputs; filter engine, category, confidence and status.
- Display tool version and exact configuration/command metadata.
- Mask likely secrets by default and require explicit reveal.
- Provide retry, cancel and export controls.

## 10. Proposed architecture

### Control plane
- Java 21+ and Spring Boot; pin versions after compatibility testing.
- REST API plus optional SSE/WebSocket progress updates.
- PostgreSQL for projects, targets, jobs, metadata, observations and benchmarks.
- Redis for queueing, locks and transient progress.
- Local filesystem initially; optional MinIO later.

### Frontend
- Next.js + TypeScript.
- Monaco Editor for code and results.
- Cytoscape.js for call/dependency graphs.
- React Flow for architecture diagrams.
- Tailwind CSS and accessible components.

### Execution plane
- Python adapters for Python-native tools and analysis glue.
- Node.js adapters for browser and JS tools.
- Dedicated Java/Ghidra worker.
- Isolated Docker worker images by tool family or engine.
- Typed JSON contracts between control plane and workers.

The API must never execute untrusted analyzers or uploaded content in its own process. Workers run non-root, with no Docker socket, no host credentials, bounded resources, controlled scratch mounts and restricted networking.

### Storage
- Record input SHA-256 and provenance.
- Each run gets a unique immutable namespace.
- Store large outputs on disk; do not load full decompilation trees into API memory.
- Apply configurable retention/cleanup.
- Never store passwords, authentication tokens or personal browser profiles in analysis artifacts.

### Initial local deployment

Use Docker Compose for frontend, Spring Boot API, PostgreSQL and Redis. Run heavyweight workers only when required. MinIO is optional for the first milestone.

## 11. Security and authorization requirements

These are acceptance requirements, not polish.

### Website worker
- Require authorization attestation and target scope.
- Use host/path allowlisting.
- Block loopback, private, link-local, multicast, reserved and cloud metadata IP ranges.
- Resolve and validate DNS addresses; revalidate after redirects and before every navigation/request.
- Restrict protocols to HTTP/HTTPS.
- Enforce egress firewall restrictions in addition to application checks.
- No browser login, cookie import or credential collection by default.
- No crawling of authenticated/private content without explicit authorization.
- Enforce bounded request rates, pages, bytes and timeouts.
- No CAPTCHA bypass, bot evasion, proxy rotation or rate-limit bypass.

### Artifact worker
- Treat APK/ZIP/DEX/ELF/JS as hostile input.
- Use non-root containers or disposable VMs.
- Disable networking by default for static artifact analysis.
- Enforce CPU/RAM/disk/process and wall-time quotas.
- Defend against archive traversal and decompression bombs.
- Reject unsafe symlinks/special files where unsupported.
- No host mounts except per-job scratch.
- No Docker socket or host credentials.
- Clean scratch data and enforce retention.

### Legal workflow
- Record authorization basis and permitted scope.
- Store authorization evidence separately from raw analysis.
- Provide stop controls and audit logs.
- Bug-bounty activity must follow exact current program scope.
- Recheck statutes, terms and programs before production research; this document is not legal advice.

## 12. Phased roadmap

The uploaded feasibility proposal estimated 12 weeks / 216 hours at approximately 18 hours per week. That is a useful MVP planning baseline, not a guarantee that every specialist engine and polished feature can be integrated within 12 weeks. The revised plan moves benchmarking and separate output folders into the earliest phases.

### Phase 0 — Repository, research and architecture freeze
**Estimate:** 1 week / 12–18 hours

Deliverables: final scope/non-goals; repository conventions; 10–15 candidate engine matrix; license/maintenance review; threat model; authorization policy; target/run/engine/artifact/observation/benchmark schemas; ground-truth dataset plan; architecture decision records; local hardware/resource profile.

Exit: no engine is adopted without role, license, compatibility, output contract and benchmark fixture plan.

### Phase 1 — Core platform and Android static MVP
**Implementation:** merged into `main` via PR #6 on 2026-11-24.  
**Status:** Phase 1 CI passed; representative authorized APK integration remains a maintainer-side manual acceptance item.

Delivered:
- Java 21 / Spring Boot API, PostgreSQL/Flyway and Redis queue.
- Android APK/AAB/APKS upload, authorization attestation, SHA-256 and per-run snapshots.
- Non-root local worker with isolated, independent JADX, Apktool, Androguard and APKiD APK runs.
- bundletool AAB validation/manifest and APKS split inventory.
- Per-engine raw outputs, logs, output hashes and run manifests.
- Minimal Next.js upload/run dashboard.
- Maven, worker, frontend and worker-image CI checks.

Limitations: APKS split-aware fan-out is not complete; Androguard produces metadata/DEX inventory rather than full Java reconstruction; APKiD dual-license terms require review before image distribution. Dynamic analysis and web capture remain later phases.

See [Phase 1 implementation](docs/phase-1/IMPLEMENTATION.md), [API guide](docs/phase-1/API.md), [testing guide](docs/phase-1/TESTING.md) and [review checklist](docs/PHASE_1_CHECKLIST.md).

### Phase 2 — Benchmark engine and Android report quality
**Implementation:** merged into `main` via PR #7 on 2026-11-24.  
**Status:** Phase 2 CI passed; representative authorized APK benchmarking remains a maintainer-side manual acceptance item.

Delivered in Phase 2 v1:
- PostgreSQL/Flyway datasets, target membership, profiles, ground-truth, experiments, attempts, normalized observations and results.
- Built-in Android static, metadata, DEX recovery and App Bundle profiles; custom Android profiles using integrated engines.
- Repeated independent Phase 1 runs per target × compatible engine × repetition.
- 1–50 repetitions, maximum 250 attempts per experiment, sequential concurrency=1 and explicit incompatible states.
- Capability-aware verified-ground-truth scoring, plus precision, recall, F1, coverage, duplicate rate and evidence completeness.
- Normalized evidence for Androguard, Apktool, JADX, APKiD and bundletool, linked to raw engine output and SHA-256.
- API-side evidence file/hash verification; host OS/architecture/CPU/RAM/runtime, tool and adapter provenance; wall/CPU/peak-RSS/output measurements.
- Unique/shared recovery summaries, maintainer-provided OWASP tags, observation filtering and JSON/Markdown/HTML reports.
- Benchmark Lab UI for dataset registration, ground-truth entry, experiment launch, scorecards and raw evidence access.
- Phase 0 schemas/fixtures/validator extended with benchmark profile and observation contracts.

Phase 2 v1 boundaries:
- Android only; web benchmarking is Phase 3.
- Concurrency fixed to 1; cache policy is recorded but the OS cache is not flushed.
- Ground-truth labels are maintainer curated. Only `verified` labels in capability classes supported by the engine are scored.
- Normalizers are baseline extractors, not complete semantic parsers or source-line fidelity evaluators.
- OWASP tags are supplied by maintainers and are not automatically inferred.
- A real authorized APK experiment on maintainer hardware remains a manual acceptance item; CI uses tests/fixtures and does not claim that run.

See [Phase 2 implementation](docs/phase-2/IMPLEMENTATION.md), [API guide](docs/phase-2/API.md), [testing guide](docs/phase-2/TESTING.md), [review checklist](docs/PHASE_2_CHECKLIST.md) and [benchmark methodology](docs/benchmark-methodology/README.md).

### Phase 3 — Web capture and JavaScript reconstruction
**Estimate:** 3 weeks / 45–60 hours

**Current milestone:** `feature/phase-3-web-reconstruction-v1` adds stored web-target authorization and scope, expiry-bounded API/Redis jobs, worker status callbacks, an opt-in internal-network Playwright worker, a Next.js Web Lab, and initial evidence-linked route/dependency/network graphs; see [Phase 3 checklist](docs/PHASE_3_CHECKLIST.md). It is a partial Phase 3 delivery, not completion of the full Phase 3 exit criteria.

Deliverables: authorization/scope gate; allowlist and SSRF safeguards; bounded Playwright capture of DOM, console, screenshots, HAR and JS assets; Web-Check and Wappalyzergo; Webcrack and Wakaru; Oxc structural extraction; Retire.js and Lighthouse; independent output folders; route/dependency/network graphs; local Juice Shop and RealWorld benchmark corpus.

Exit: local/authorized capture creates isolated outputs per engine; internal-network access is blocked; partial reconstruction is reported honestly; comparisons use known local ground truth.

### Phase 4 — Specialist Android and native engines
**Estimate:** 3–5 weeks / 45–75 hours

**Current milestone:** the Phase 4 branch adds bounded APK runtime classification, explicit Flutter ARM64/Hermes HBC/native ELF compatibility routing, APKEditor 1.4.9, APKLeaks 2.6.3, optional Hermes/Blutter/Ghidra/MobSF/Exodus adapters, a Ghidra headless function/call-graph exporter, normalized specialist evidence and specialist benchmark profiles. See [Phase 4 implementation](docs/phase-4/IMPLEMENTATION.md) and [Phase 4 checklist](docs/PHASE_4_CHECKLIST.md).

**Important boundary:** optional engines require separately provisioned tooling or a private MobSF service. Generic CI covers synthetic runtime/compatibility/extraction fixtures and builds the standard worker image; it does not claim a full Blutter/Hermes/Ghidra/MobSF/Exodus run against real-world binaries. Maintainer acceptance tests and licensing review remain open and are listed in the checklist.

Exit: runtimes dispatch only to compatible specialists; unsupported analysis is explicitly incompatible; specialist outputs/resource use are recorded; static call graphs link to hashed evidence; comparisons use capability-compatible verified ground truth.

### Phase 5 — Architecture explorer and professional dossier
**Estimate:** 2–3 weeks / 30–45 hours

Deliverables: Monaco code/result explorer; Cytoscape call/dependency graph; React Flow architecture view; links from graph nodes to evidence; build/version comparison; SARIF and evidence-rich reports; analyst annotations/confidence/validation; search and filters.

Exit: a user can navigate from summary to raw evidence; graph edges are evidence-backed; reports distinguish observations, hypotheses and verified findings.

### Phase 6 — Hardening, reproducibility and release
**Estimate:** 2–3 weeks / 30–45 hours

Deliverables: worker/VM isolation review; SSRF/DNS rebinding/redirect tests; archive-bomb/path-traversal tests; concurrency/stress tests; quotas; retention/deletion; license notices; CI; installation and demo docs; security policy; release automation; benchmark publication.

Exit: CI passes; worker/network controls are tested; no sensitive commercial artifacts are committed; release artifacts and docs are complete.

**Schedule reality:** a polished 10–15+ engine workbench is likely to exceed the original 12-week estimate for one developer. Ship a strong Android + web MVP, then grow the engine matrix incrementally.

## 13. Benchmark corpus and ground truth

### Android
- OWASP MASTG reference apps and demos: https://github.com/OWASP/MASTG
- OWASP MAS Crackmes / UnCrackable apps: https://github.com/OWASP/mas-crackmes
- OWASP AndroGoat: https://github.com/OWASP/AndroGoat
- OVAA: https://github.com/oversecured/ovaa
- F-Droid: https://f-droid.org/
- Self-built Java/Kotlin, Flutter, React Native and JNI sample apps with source and build artifacts retained as ground truth.

### Web
- OWASP Juice Shop: https://github.com/juice-shop/juice-shop
- RealWorld examples: https://github.com/realworld-apps/realworld
- Self-built React, Next.js, Vue and Angular apps with source maps enabled and disabled.
- Controlled JS bundles for minification, known obfuscation patterns, dynamic imports and WebAssembly.
- Local mock API, SSE and WebSocket fixtures.

Keep source, build scripts, compiler versions, artifact hashes and known routes/functions/dependencies for each fixture. Version datasets and verify redistribution licenses.

Do not use Instagram, ChatGPT, Uber or Google production systems as ground-truth benchmarks: they do not publish complete expected client reconstruction or server implementations. Use commercial targets only under documented authorization and label the results exploratory rather than ground-truth scores.

## 14. Resource and hardware strategy

- The target is local execution with bounded concurrency.
- Do not run 10–15 heavyweight tools simultaneously by default.
- Execute concurrently only when resource estimates and host limits allow.
- Cap Ghidra/JADX memory and job duration; cap Playwright browser workers.
- Use sequential or small-batch jobs on 16 GB RAM systems.
- Stream large outputs to disk; do not load source trees into API memory.
- Add remote workers only after local isolation and scheduling are stable.
- GPU is not required for the core pipeline; the initial toolchain is primarily CPU, memory and storage intensive.
- Keep the development laptop's RTX 3050 optional rather than assuming these analyzers will benefit from it.

## 15. Proposed repository layout

```text
ReverseLens/
├── README.md
├── DEVELOPMENT_PLAN.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── LICENSE
├── docs/
│   ├── architecture/
│   ├── adr/
│   ├── benchmark-methodology/
│   ├── legal-and-authorization/
│   ├── threat-model/
│   └── engine-registry/
├── schemas/
│   ├── target.schema.json
│   ├── authorization.schema.json
│   ├── engine.schema.json
│   ├── engine-registry.schema.json
│   ├── analysis-run.schema.json
│   ├── engine-execution.schema.json
│   ├── artifact.schema.json
│   ├── observation.schema.json
│   ├── finding.schema.json
│   ├── benchmark-dataset.schema.json
│   ├── ground-truth-item.schema.json
│   ├── benchmark-experiment.schema.json
│   └── benchmark-result.schema.json
├── engines/
│   └── registry.yaml
├── scripts/
│   └── validate_phase0.py
├── tests/
│   ├── test_phase0_contracts.py
│   └── fixtures/
├── apps/
│   ├── web/
│   └── api/
├── workers/
│   ├── android/
│   ├── web/
│   ├── native/
│   └── common/
├── benchmarks/
│   ├── datasets/
│   ├── ground-truth/
│   ├── profiles/
│   ├── results/
│   └── reports/
└── deploy/
    ├── docker/
    └── compose/
```

This is the intended end-state structure. Phase 0 has created the documentation, schemas, registry, validation script and test fixtures. Application, worker, benchmark-result and deployment implementation directories will be populated in their respective phases.

Do not check in generated analysis workspaces or large sample APKs. Ignore private workspaces, proprietary outputs, browser profiles and sensitive captures in `.gitignore`.

## 16. Definition of Done for every engine

An engine is not integrated merely because its CLI runs. It must:
1. Document supported inputs and capability category.
2. Have an isolated adapter and pinned runtime/tool version.
3. Invoke subprocesses with argument arrays, not shell-interpolated untrusted strings.
4. Enforce timeout, CPU/RAM/disk/process limits.
5. Preserve stdout, stderr, exit status and raw output files.
6. Generate an engine manifest and output inventory.
7. Normalize supported observations into shared schemas.
8. Have test fixtures and expected-output tests.
9. Have at least one benchmark result on known data.
10. Document false positives, false negatives, gaps and license.
11. Be independently retryable/cancellable.
12. Never be reported as successful if the output is empty, invalid or partial without that state being visible.

## 17. Milestones

| Milestone | Outcome |
|---|---|
| M0 | Scope, research, schemas, threat model and repo baseline |
| M1 | Local platform shell and job/engine registry |
| M2 | Multi-engine Android static pipeline |
| M3 | Per-engine workspace and normalized evidence |
| M4 | Repeatable benchmarking and comparison reports |
| M5 | Authorized web capture and JS reconstruction |
| M6 | Flutter, Hermes and native specialist engines |
| M7 | Interactive code/graph explorer and dossier |
| M8 | Hardening, CI, documentation and public release |

## 18. Immediate implementation order

1. Create repository structure and baseline docs.
2. Add target, run, engine, artifact and benchmark JSON schemas.
3. Implement local workspace manager with immutable run IDs and per-engine folders.
4. Implement engine registry and compatibility declarations.
5. Build Android pipeline with JADX, Apktool, Androguard and APKiD.
6. Build process supervisor for argument-safe execution, timeouts, logs and resource metrics.
7. Build a small source-known Android benchmark corpus.
8. Generate the first comparison report before expanding tool count.
9. Add authorization-gated Playwright capture with network controls.
10. Add web analyzers and benchmark against local apps.
11. Add specialist engines only when adapter and benchmark contracts are stable.

## 19. Research and maintenance policy

This document is a living plan, not a claim that every candidate has been tested on the development machine. Before integrating an engine, re-check its canonical repository, official docs, release and commit activity, issues, supported platforms, CLI/API, license, and output format. Build a proof of compatibility on a representative fixture; record exact versions and commit digests; add automated adapter tests; update the registry when a project is archived, breaks compatibility or changes license.

## 20. Success definition

ReverseLens succeeds when a user can submit an authorized APK or web target, select one or 15 compatible engines, execute them safely and independently, inspect every engine's separate raw output, compare results under a reproducible benchmark, trace normalized claims to evidence, and export an honest technical dossier explaining what was and was not recovered.

**The central differentiator is transparent multi-engine benchmarking plus evidence-linked reconstruction — not a promise of magical 100% source recovery.**