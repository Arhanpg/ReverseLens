# Security Policy

## Scope

Security reports may concern:
- ReverseLens control-plane or frontend vulnerabilities.
- Unsafe worker isolation or resource-boundary failures.
- SSRF, scope-validation or network-egress weaknesses.
- Archive parsing, path traversal or decompression-bomb handling.
- Command injection, output rendering or sensitive-data exposure.
- Dependency and build-supply-chain issues.

Third-party analyzers have their own security policies; report upstream tool vulnerabilities to their maintainers as well.

## Reporting a vulnerability

Please do not open public issues containing exploit details, sensitive artifacts, tokens, credentials, private captures or personal information.

Use GitHub's private vulnerability reporting feature for this repository when it is enabled. If it is unavailable, contact the repository maintainer through the GitHub profile and request a private channel before sending technical details.

Include, where safe:
- A concise description and impact.
- Affected commit, release or component.
- Reproduction steps using a harmless local fixture.
- Any suggested mitigation.
- Whether the issue affects a default configuration.

## Response and disclosure

The maintainer will acknowledge reports as reasonably practicable, investigate and coordinate a fix and disclosure timeline with the reporter. Please allow time for remediation before public disclosure. Do not test against systems or data that you do not own or have explicit authorization to assess.

## Safe testing

Use local training targets and isolated environments. Never include third-party production data or proprietary application artifacts in a public report. See the [authorization policy](docs/legal-and-authorization/POLICY.md).
