# Adding an Engine to ReverseLens

An upstream tool is a candidate until it has passed this checklist.

## 1. Research

- Confirm the canonical upstream repository and official documentation.
- Verify it is not archived and understand its recent release/commit and issue activity.
- Inspect the actual LICENSE file; do not rely only on a badge or a third-party summary.
- Review transitive dependencies and any dual/commercial license.
- Record tested release/tag/commit, not merely a moving branch.

## 2. Capability contract

Document:
- Exact target platform and input formats.
- Capability class and role (decompiler, decoder, fingerprint, capture, security analysis, etc.).
- Expected outputs and known gaps.
- Runtime, OS/architecture and external dependencies.
- Network needs and permitted environment.
- CPU/RAM/disk class and reasonable timeout.

## 3. Adapter requirements

- Accept a structured job contract.
- Use safe argument arrays; never shell-interpolate target data.
- Run with a dedicated, non-root identity and minimal mounts.
- Enforce timeout and resource budgets.
- Preserve raw stdout/stderr, exit state and output tree.
- Produce an output inventory with hashes and sizes.
- Return an explicit state: succeeded, partial, failed, timed_out, cancelled or incompatible.
- Never silently mark empty/invalid output as success.

## 4. Normalization

Map only supported facts into the shared observation schema. Retain raw output and engine provenance. A string match or endpoint should not automatically become a vulnerability finding.

## 5. Benchmark and test

- Add a deterministic fixture and expected-output tests.
- Run the engine against source-known or labeled data.
- Compare with relevant engines only.
- Record accuracy/coverage where ground truth exists and performance over repeated runs.
- Document false positives, misses and unsupported cases.

## 6. Acceptance

An engine is integrated only after licensing, security, adapter, fixture, normalization and benchmark reviews pass. Update `engines/registry.yaml` and this documentation.
