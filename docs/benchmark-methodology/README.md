# ReverseLens Benchmark Methodology

## Purpose

Measure what each engine actually contributes on a known input. The aim is reproducible comparison, not a marketing leaderboard.

## 1. Benchmark categories

Keep capability classes separate:
- Android DEX decompilation.
- Android resource/manifest/Smali decoding.
- Flutter AOT extraction.
- Hermes bytecode inspection.
- Native ELF disassembly and pseudocode.
- Browser/DOM/network capture.
- Web technology fingerprinting.
- JavaScript unminification and bundle reconstruction.
- AST/module extraction.
- Dependency/vulnerability matching.
- Performance and accessibility auditing.

A tool must only be compared with others on overlapping capabilities. A technology detector is not a failed decompiler.

## 2. Dataset tiers

1. **Source-known fixtures:** applications and websites built by the project from known source, with exact source revision and build configuration retained.
2. **OWASP training targets:** purpose-built vulnerable applications and test demos with permitted use.
3. **Open-source applications:** projects with a known corresponding source revision and a documented license.
4. **Authorized exploratory targets:** useful for qualitative research, but not for source-recovery accuracy scores unless ground truth is independently available.

Commercial production sites must not be represented as ground truth for server-side source or full application reconstruction.

## 3. Ground truth

For every source-known fixture, retain:
- Source repository and commit.
- Build scripts and compiler/toolchain versions.
- Build flags, minification and obfuscation settings.
- Input artifact SHA-256.
- Expected classes, methods, resources, routes, dependencies, API references and graph edges as applicable.
- Known intentionally introduced test cases.
- Dataset license and redistribution conditions.

Ground truth is category-specific. For example, a browser engine's DOM snapshot can be tested against known page structure, while a DEX decompiler's reconstructed names can be evaluated only on aspects that survive compilation.

## 4. Measurements

| Metric | Rule |
|---|---|
| Completion rate | Completed or partial compatible executions / compatible attempts |
| Precision | Correct reviewed reported items / all reviewed reported items |
| Recall/coverage | Correct recovered ground-truth items / applicable ground-truth items |
| F1 | Harmonic mean of precision and recall when both exist |
| Structural fidelity | Agreement of relevant graph nodes/edges or module/package structure |
| Duplicate rate | Redundant results after documented canonicalization |
| Duration | Wall-clock time; CPU time where available |
| Peak memory | Peak resident set size |
| Output footprint | Total bytes and file count |
| Stability | Agreement of normalized results across repeated executions |
| Evidence completeness | Portion with a traceable raw artifact and location |
| Analyst effort | Time/steps needed for human verification |

Never convert unknown values into zero. Record null/unavailable when no valid ground truth or measurement exists.

## 5. Repeatability and environment

- Pin engine release/commit, adapter version, container image digest and configuration.
- Record input hash and dataset version.
- Record OS, CPU model, RAM, architecture and runtime versions.
- Use fixed resource limits.
- Separate cold-cache and warm-cache experiments.
- Use at least three repetitions for performance comparison; five or more are preferable.
- Report median and spread (minimum/maximum or interquartile range).
- Keep concurrency constant within a comparison set.
- Do not compare runs with materially different capture scope or hardware without declaring the difference.

## 6. Tool combinations

Benchmark both individual engines and combinations:
- Individual engine profile.
- Complementary engine profile.
- Full compatible profile.

Measure marginal contribution: what additional correctly recovered items does an engine add beyond the other engines? Deduplicate for combined coverage while retaining source provenance from every engine.

## 7. Reporting

Every benchmark report should include:
- Question and capability category.
- Dataset and ground-truth revision.
- Input and configuration hashes.
- Tool/version matrix.
- Compatibility and skipped-tool matrix.
- Per-engine raw metrics.
- Aggregate statistics and repetitions.
- Unique/overlapping recoveries.
- False positives, misses and failure cases.
- Resource use.
- Human review notes.
- Known limitations and confidence statement.

Do not publish a single weighted winner until weighting is justified, documented and sensitivity-tested. Publish the metric vector first.


## 8. Phase 2 implementation notes (Android v1)

Phase 2 executes integrated Android tools as independent attempts. One benchmark attempt represents one dataset target, one engine, and one repetition, mapped to a normal Phase 1 run and execution ID. Raw engine evidence remains in the Phase 1 run workspace.

### Dataset and labels

Datasets reference uploaded targets by UUID and record source type, version, capability classes, source/revision provenance, license and redistribution review. Ground-truth records are target- and capability-specific. Only labels marked `verified` contribute to precision, recall, F1 and coverage; unreviewed, reviewed, disputed and not-applicable labels remain visible but are not scored.

OWASP MASVS/MASTG tags are maintainer-supplied ground-truth annotations. ReverseLens does not infer a control mapping automatically from an observation label.

### Execution controls

- Built-in Android profiles cover static core, package metadata, DEX recovery and App Bundle inspection.
- Repetitions: 1–50, default 3.
- Concurrency is fixed at 1 in Phase 2 v1 to reduce resource contention between analyzers.
- Cache policy is recorded but the worker does not flush the operating-system filesystem cache. Declare `not_controlled` unless an external lab process controls cache state.
- Experiments are capped at 250 target × engine × repetition attempts.
- Unsupported engine/format combinations are recorded as `incompatible` and excluded from success and accuracy denominators.

### Metrics and provenance

Worker outputs record wall time, child-process CPU time, peak RSS estimate, output bytes/file count, normalized observation count, host OS/architecture/CPU/RAM/runtime, tool/adapter versions, status and warnings. Peak RSS uses Linux child-process resource accounting, not an OS-wide hardware monitor.

Normalized observations include capability class, type, canonical key, confidence and raw evidence path/SHA-256. The API verifies that evidence resolves to a real file beneath the per-run workspace and that its SHA-256 matches the worker declaration.

Precision/recall/F1/coverage are null when there is no verified ground truth for a capability class the tool supports. Observations in unlabelled capabilities remain visible but are not treated as false positives. If verified applicable labels exist and no expected items are recovered, scores are zero. Duplicate rate and evidence completeness are separately measured.

The experiment input manifest hash binds target hashes, selected tools, repetitions, cache policy and methodology version.

### Android v1 normalizers

| Engine | Baseline normalized evidence |
|---|---|
| Androguard | Package name, permissions, manifest components and DEX entry inventory |
| Apktool | Manifest permissions/components and bounded Smali class/method declarations |
| JADX | Java class/method declarations, client-visible URL strings and selected client string literals |
| APKiD | Compiler, packer and protector fingerprints present in the JSON output |
| bundletool | AAB manifest permission/component items and APKS split inventory |

This is a deterministic baseline evidence normalizer, not a complete semantic parser. It does not claim full source recovery, line-level mappings, call-graph equivalence, or server-side code access.

### Reports

JSON, Markdown and HTML outputs include experiment/dataset metadata, input manifest hash, repetitions/cache policy, per-engine scorecards, tool/adapter versions, resource measurements, attempt statuses, unique/shared recoveries, misses/false positives, normalized evidence references and maintainer-supplied OWASP tags.

A single weighted “winner” score is intentionally not produced; capability classes and metric trade-offs remain visible.
