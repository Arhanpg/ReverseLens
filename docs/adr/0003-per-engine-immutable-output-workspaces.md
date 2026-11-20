# ADR 0003: Per-engine immutable output workspaces

- Status: Accepted
- Date: 2026-11-21

## Context

The project's defining workflow runs many tools against the same target. Tool output must remain independently inspectable and fairly comparable.

## Decision

Every target analysis has a unique run directory. Each selected/attempted engine writes only under `engines/<engine-id>/`. Raw outputs are immutable after an execution finishes. Normalized artifacts, graphs, benchmark metrics and reports live in sibling directories and reference raw artifacts by ID/hash.

## Consequences

- A tool cannot overwrite another tool's evidence.
- The UI can compare engines side by side.
- Storage requirements grow; retention and disk quotas are mandatory.
- Unselected/incompatible tools are recorded as states, not fabricated empty successful folders.
