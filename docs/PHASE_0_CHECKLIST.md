# Phase 0 — Foundation and Architecture Freeze

**Status:** Completed as a repository baseline on 2026-11-21  
**Scope:** Documentation, contracts, registry, fixtures, validation and CI scaffolding.  
**Not included:** Runtime analyzer adapters, API implementation, frontend, worker execution or actual reverse engineering. Those belong to later phases.

## Completion checklist

- [x] Confirm the product vision and explicit client/server visibility limits.
- [x] Define Android, web, offline-bundle and benchmark product modes.
- [x] Define multi-engine principles and per-target/per-engine folder requirements.
- [x] Create a machine-readable candidate engine registry with 25 candidates.
- [x] Record capability categories, priority, input types, output types, network requirements, isolation profile, license-review status and limitations per engine.
- [x] Create JSON Schema contracts for targets, authorization, engine definitions, registry, runs, executions, artifacts, observations, findings and benchmark records.
- [x] Add example Android/web targets and example run/evidence records.
- [x] Document architecture, benchmark methodology, legal/authorization policy and threat model.
- [x] Record key architecture decisions as ADRs.
- [x] Add a Phase 0 validation script, tests, developer dependencies and GitHub Actions workflow.
- [x] Add repository hygiene rules so local workspaces and potentially sensitive analysis outputs are not committed.

## Validation performed

**Workflow run 44807176269 — successful.**

The GitHub Actions run for commit `4142902dbacbe80ad11c647d860cd9b36ee85423` completed successfully. The job steps for dependency installation, Phase 0 validation and pytest all reported success. See the [workflow run](https://github.com/Arhanpg/ReverseLens/actions/runs/44807176269).

The GitHub Actions workflow is configured to:
1. Install the pinned Python dependency ranges from `requirements-dev.txt`.
2. Validate all JSON Schemas.
3. Validate the YAML engine registry and its cross-references.
4. Validate the example fixtures.
5. Run the Phase 0 pytest suite.

A green workflow run is the acceptance signal for CI validation. Merely committing the workflow does not prove that GitHub Actions has run successfully.

## Phase 0 exit criteria

Phase 0 is complete when the default branch contains the design baseline and the automated validation workflow passes. The repository should then proceed to Phase 1: local workspace manager, job model and the first isolated Android static-analysis workers.

## Known deliberate deferrals

- No analyser tool is installed or invoked by this phase.
- Candidate tools are not yet marked integrated or tested on the development laptop.
- Candidate license metadata is a research hint, not a final distribution/legal review.
- No production website capture is implemented.
- No Docker worker images or process supervisor are implemented.
- No database migrations or Spring Boot/Next.js applications are implemented.
