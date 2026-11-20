# ADR 0001: Multi-engine adapter model

- Status: Accepted
- Date: 2026-11-21

## Context

ReverseLens compares tools with different capabilities and output formats. One hard-coded toolchain would be difficult to benchmark, extend and diagnose.

## Decision

Use a registry-driven adapter architecture. Each adapter declares supported inputs, capability classes, resource requirements, network needs, isolation profile, output artifacts and normalized observations. The scheduler selects compatible tools and stores every execution in a unique per-engine directory.

## Consequences

- New tools can be added without changing the core target/run contracts.
- Engine failures are isolated and independently retryable.
- Results can be compared only across overlapping capabilities.
- Adapter maintenance and schema compatibility become explicit work.
