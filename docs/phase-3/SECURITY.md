# Phase 3 web capture security review

| Threat | Control in this milestone |
|---|---|
| Out-of-scope navigation | Exact hostname, allowed-port and path-prefix checks |
| Encoded path traversal | Repeated URL decoding and dot-segment rejection |
| Redirect to another host | Every browser request URL is revalidated |
| Private-infrastructure SSRF | All DNS answers checked against the IP policy |
| URL user-info tricks | Username/password components rejected |
| State-changing browser actions | Only GET/HEAD requests allowed; POST/PUT/PATCH/DELETE blocked |
| Unbounded crawl | Page, total intercepted request, saved-JavaScript-byte and wall-clock budgets |
| Credential persistence | No imported cookies or login; sensitive headers redacted; query strings stripped from persisted URLs |
| Cross-run evidence mixing | Per-target/run/engine workspace |
| Misleading reconstruction claim | Manifest states browser-visible limitations and that server code is not recovered |

## Authorization record and worker queue

The control plane requires explicit confirmation, an authorization basis/reference, a future expiry (no more than 30 days out), exact host allowlist, path prefixes, ports and bounded limits. Jobs inherit persisted scope and are clamped to expiry; the browser worker rejects expired jobs before navigation. Worker callbacks use the existing shared worker token. This is a local single-user application model, not multi-tenant identity/authorization.

The Compose browser worker is opt-in (`--profile web-capture`) and runs on the internal-only backend network. It is intended for local fixture services attached to that network; it cannot reach public websites. Do not attach it to a public network or add public egress without a separate proxy/firewall policy and tests.

## Deployment requirements

Do not attach the browser worker to a network with unrestricted egress. Enforce private/reserved/loopback/link-local/multicast and metadata-service blocking at the network layer. The Python DNS check is defense-in-depth; Chromium can cache DNS and may resolve independently. The current internal-only Compose profile does not include public egress; remote capture is not enabled by this PR. A network-layer policy must also enforce any required total response-byte cap.

Do not mount the Docker socket, host home directory, browser profiles, SSH material, cloud credentials or unrelated workspaces. Use non-root execution, read-only filesystem, bounded tmpfs and CPU/memory/PID/disk quotas.

## Scope semantics

Only exact hostnames are accepted (no wildcard subdomains). Only HTTP/HTTPS is allowed. TCP ports must be explicitly allowed (defaults: 80 and 443). Path prefix matching is segment-aware: `/app` permits `/app` and `/app/...`, not `/application`. Encoded dot-segments are rejected. No authentication, login automation, cookies, proxy rotation, CAPTCHA bypass, or non-read browser methods. Local-lab loopback is an explicit developer-only exception and still blocks link-local, multicast, unspecified and reserved destinations.

## Evidence handling

The worker strips query strings from persisted URLs, redacts sensitive headers and common token-like strings in DOM/console text, and records only JavaScript assets whose declared Content-Length fits the saved-asset budget. This is not a guarantee that arbitrary site content contains no sensitive data. Captures remain private local evidence and require user review before sharing.

Raw captured HTML is untrusted and must not be served as executable same-origin content. HAR is not generated in this milestone because raw HAR can persist secrets/cookies; structured redacted request/response metadata is retained instead.

## Known limitations

- The saved-JavaScript byte cap is not a total network-transfer cap.
- DNS rebinding is not fully defeated by application checks alone.
- The browser worker is not yet wired into the API/database authorization lifecycle.
- No additional web analyzers, graph extraction or ground-truth benchmark corpus are claimed as complete.
