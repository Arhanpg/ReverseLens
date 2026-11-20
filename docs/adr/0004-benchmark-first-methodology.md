# ADR 0004: Benchmark-first, capability-aware evaluation

- Status: Accepted
- Date: 2026-11-21

## Context

Tools specialize in different jobs. A single undifferentiated score would misrepresent their capabilities and hide missing ground truth.

## Decision

Benchmark by capability category using source-known or otherwise labeled datasets. Record coverage, precision/recall when measurable, structural fidelity, runtime, memory, output footprint, stability, evidence completeness and analyst effort. Pin inputs, tool versions and configuration; repeat performance measurements.

## Consequences

- Benchmark results are more reproducible and interpretable.
- Dataset curation and human ground-truth review are required.
- A single weighted winner is deferred until weighting and validity are justified.
