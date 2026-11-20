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
