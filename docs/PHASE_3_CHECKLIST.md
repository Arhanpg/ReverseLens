# Phase 3 review checklist

## Implemented first milestone
- [x] Dedicated web capture worker module and separate browser image.
- [x] Exact authorized-host and path-prefix gate.
- [x] HTTP/HTTPS-only URL validation and URL credential rejection.
- [x] DNS validation across all returned IPv4/IPv6 addresses.
- [x] Reject private, loopback, link-local, reserved, multicast and metadata destinations (except explicit local-lab loopback).
- [x] Browser request interception revalidates navigations and redirects.
- [x] Request/page/saved-JavaScript-byte/wall-clock budgets (the JS byte limit is not a total network-transfer cap).
- [x] Fresh unauthenticated browser context.
- [x] DOM, screenshots, console/page errors, redacted request/response metadata and bounded JS assets.
- [x] Per-run Playwright workspace and SHA-256 inventory (excluding the manifest's self-hash).
- [x] Scope and redaction unit tests.
- [x] Implementation/security documentation.

## Remaining Phase 3 exit criteria
- [x] Persist web authorization basis/reference/expiry, exact host/path/port scope and web-target registration API.
- [x] Queue capture jobs through Redis after DB commit; clamp job duration to authorization expiry and recheck expiry before navigation.
- [x] Persist worker status and manifest through the token-protected internal API.
- [ ] Add target disable/revoke and active-job cancel controls.
- [x] Keep the Compose web-capture worker opt-in and on the internal-only backend network (local lab services only).
- [ ] Deploy production browser-worker egress firewall/network policy before remote capture.
- [ ] Safe HAR export with header/cookie redaction and explicit opt-in.
- [ ] Web-Check and Wappalyzergo adapters.
- [ ] Webcrack, Wakaru and Oxc adapters with pinned runtimes and fixtures.
- [ ] Retire.js and Lighthouse adapters against local fixtures.
- [x] Evidence-backed route/dependency/network graph extraction from browser observations (heuristic library matches remain unverified).
- [ ] Source-known Juice Shop and RealWorld benchmark fixtures with hashes/licenses.
- [ ] End-to-end authorized local web app test in an isolated Compose lab and verify the internal-only network boundary.
- [ ] Expanded redirect/DNS rebinding/cancellation/quota threat tests.

Manual acceptance requires a disposable local fixture or documented authorization. A passing unit test is not proof that container egress policy is deployed.
