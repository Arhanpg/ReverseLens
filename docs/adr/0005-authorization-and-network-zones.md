# ADR 0005: Authorization gate and network-isolated worker zones

- Status: Accepted
- Date: 2026-11-21

## Context

Static artifact inspection and remote web capture have different security profiles. Web requests can affect third-party systems and can expose internal services through SSRF.

## Decision

Require an authorization/scope record for remote targets and dynamic testing. Separate offline artifact workers from bounded authorized browser workers. Static workers have no network by default. Browser workers require host/path scope, DNS and IP validation, redirect/request revalidation, request budgets and egress firewall restrictions.

## Consequences

- The product does not offer generic unrestricted website scanning.
- Scope validation becomes part of job creation and every outbound request.
- Local training labs remain the preferred default development targets.
