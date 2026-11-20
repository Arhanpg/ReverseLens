# ReverseLens Threat Model

## 1. Assets to protect

- Developer workstation and host operating system.
- API/control-plane credentials and signing keys.
- User-supplied APKs, bundles, captures and source code.
- Raw engine outputs and potentially sensitive findings.
- Authorization records and target scope.
- Engine registry, adapter code and tool binaries.
- Database integrity and run provenance.
- Remote targets and their users.

## 2. Trust boundaries

1. User/browser to ReverseLens frontend.
2. Frontend/API to control-plane database and queue.
3. Control plane to worker execution environment.
4. Worker to third-party analyzer process.
5. Web worker to remote DNS/HTTP/TLS services.
6. Worker output to normalizer and report renderer.
7. Optional future remote worker to central API/object storage.

All uploaded files, remote responses, analyzer output and third-party tool updates are untrusted.

## 3. Threats and mitigations

| Threat | Example | Required mitigation |
|---|---|---|
| Malicious binary/parser exploit | Crafted APK triggers parser memory corruption | Disposable worker/VM, no network, non-root, quotas, patch tools |
| Archive traversal | ZIP entry writes outside scratch directory | Canonical path checks, reject traversal/symlink entries |
| Decompression bomb | Small archive expands to huge disk/RAM | Expansion, entry-count, size and ratio limits |
| Command injection | Filename passed through shell string | Use process argument arrays; never build shell commands from user input |
| Worker escape | Tool accesses host filesystem or Docker socket | No Docker socket, minimal mounts, sandbox/VM, patched runtime |
| SSRF | URL redirects to localhost/private infrastructure | DNS/IP validation, redirect revalidation, egress firewall |
| DNS rebinding | Host resolves public then private | Validate all resolved addresses and enforce network-layer egress controls |
| Scope expansion | Crawl follows off-domain link | Strict allowlist at each request and redirect |
| Credential leakage | HAR captures authorization headers or cookies | Do not authenticate by default; redact secrets; restricted access and retention |
| Sensitive-output exposure | Decompiler reveals embedded tokens or proprietary code | Local-first storage, masking, access control and deletion |
| Poisoned analyzer output | Malformed HTML/Markdown injects script into report | Escape untrusted content; sanitize report rendering; safe download headers |
| Supply-chain compromise | Malicious upstream release or package | Pin versions/digests, verify provenance, update review, SBOM |
| Benchmark manipulation | Different inputs/versions used for engine comparison | Hash inputs/configs, pin tool versions, controlled repetitions |
| Resource exhaustion | Many heavyweight jobs run simultaneously | Global and per-job concurrency/resource quotas |
| False security claim | Endpoint or string misreported as vulnerability | Evidence-backed observations, confidence, human triage |

## 4. Security defaults

- Static artifact workers: no network access.
- Web workers: allowlisted network egress only.
- Workers: non-root and resource-limited.
- API: does not parse untrusted binaries or execute analyzers.
- Reports: treat raw output as untrusted text/data.
- Credentials: never mounted into workers by default.
- Retention: configurable, explicit, and documented.
- Logging: avoid logging secrets or complete sensitive payloads.

## 5. Residual risks

Container isolation is not a perfect security boundary. For actively malicious samples, use a disposable VM with patched host software and no sensitive shared folders. Browser automation can also be vulnerable to browser exploits and unexpected navigation. Strong egress controls are required even when application-level URL validation exists.

## 6. Release gate

Before any release that accepts untrusted input or remote URLs:
- Review worker images and dependency vulnerabilities.
- Test path traversal and decompression limits.
- Test redirects, DNS rebinding scenarios and private-address blocking.
- Verify no network from static workers.
- Verify per-job resource limits and cancellation.
- Verify report rendering escapes untrusted analyzer output.
- Review secrets redaction and artifact retention.
