# ADR 0002: Separate control plane from execution workers

- Status: Accepted
- Date: 2026-11-21

## Context

ReverseLens will process untrusted binaries and web content using large third-party tools. Running them inside the HTTP API process would put project metadata, credentials and service availability at unnecessary risk.

## Decision

The control plane uses Java/Spring Boot for metadata, authorization, scheduling and result APIs. Analysis runs in isolated worker processes/containers with tool-specific runtimes. The API never directly executes uploaded content or analyzer binaries.

## Consequences

- Worker APIs and schemas must be versioned.
- Jobs can be retried, cancelled and resource-limited independently.
- More deployment components are required, but the trust boundary is clearer.
