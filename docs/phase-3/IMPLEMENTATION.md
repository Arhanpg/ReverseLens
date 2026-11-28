# Phase 3 — Web Capture and JavaScript Reconstruction

## Current milestone

The first Phase 3 milestone adds an isolated, bounded Playwright capture worker. It is an executable worker capability, not yet a complete control-plane product flow.

## Included

- Exact-host allowlist, explicitly permitted TCP ports and segment-aware path-prefix scope.
- HTTP/HTTPS-only validation; rejects URL credentials and encoded dot-segment paths.
- DNS resolution checks across all returned IPv4/IPv6 addresses; mixed public/private answers are rejected.
- Browser request interception revalidates requests and redirects.
- Passive capture permits GET/HEAD only and blocks state-changing requests.
- Fresh unauthenticated browser context; no cookie import or personal profile.
- Request/page/saved-JavaScript-byte/wall-clock budgets.
- DOM snapshots, screenshots, console/page errors, redacted request/response metadata and bounded JavaScript assets.
- Query strings are stripped from persisted URLs; sensitive headers and common token patterns are redacted.
- Per-run Playwright output directory with SHA-256 file inventory.
- Separate web-worker image; Android analyzer image remains unchanged.

## Security boundary and residual risk

Application DNS checks are defense-in-depth, not an egress firewall. Production must place the browser worker behind a network policy that blocks loopback, private, link-local, multicast, reserved and cloud metadata destinations. DNS rebinding remains possible if the container network permits arbitrary egress.

The saved JavaScript byte limit bounds persisted assets, not all bytes transferred by Chromium. A network egress proxy or firewall with response limits is required for a hard total-transfer boundary. Unknown/chunked JavaScript response lengths are not persisted. This worker must not be deployed with unrestricted network egress.

HAR export is intentionally omitted in this first slice because raw HAR can preserve authorization headers and cookies. Structured, redacted request/response metadata is retained instead. Raw DOM remains sensitive evidence and must not be served as executable same-origin content.

## Run locally

```bash
python -m pip install -r worker/requirements.txt -r worker/requirements-web.txt
python -m playwright install chromium
PYTHONPATH=worker python -m reverselens_worker.web_worker
```

The worker listens to Redis list `reverselens:web:capture`. Jobs contain `url`, `targetId`, `runId` and an explicit `scope` including `allowed_hosts`, `allowed_path_prefixes` and `allowed_ports`. Output is written under `WORKSPACE_ROOT/web/<targetId>/run-<runId>/engines/playwright`.

## Not yet wired or implemented

- Spring API/database persistence for web authorization records and web target registration.
- API job creation, queueing, cancellation and authorization-expiry enforcement.
- Network-layer egress firewall and hard total-transfer limits.
- Safe opt-in HAR export.
- Web-Check, Wappalyzergo, Webcrack, Wakaru, Oxc, Retire.js and Lighthouse adapters.
- Route/dependency/network graph extraction.
- Juice Shop/RealWorld and source-known web benchmark datasets.
- End-to-end local web app acceptance test under the restricted container network.

Candidate names in the engine registry are not counted as completed adapters. Each integration must meet the engine Definition of Done and pass fixture tests before it is presented as executable.

## Test coverage

The Phase 3 tests cover exact host/path/port scope, scheme/credential rejection, encoded dot-segment rejection, public and local-lab DNS policy, loopback/private/link-local/mixed DNS answer rejection, empty DNS results, budget validation and secret-like text redaction. CI also runs the existing contracts, backend and worker regression suites and builds the web-worker image.
