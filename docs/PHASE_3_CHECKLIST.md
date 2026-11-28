# Phase 3 review checklist

## Implemented first milestone
- [x] Dedicated web capture worker module and separate browser image.
- [x] Exact authorized-host and path-prefix gate.
- [x] HTTP/HTTPS-only URL validation and URL credential rejection.
- [x] DNS validation across all returned IPv4/IPv6 addresses.
- [x] Reject private, loopback, link-local, reserved, multicast and metadata destinations (except explicit local-lab loopback).
- [x] Browser request interception revalidates navigations and redirects.
- [x] Request/page/response-byte/wall-clock budgets.
- [x] Fresh unauthenticated browser context.
- [x] DOM, screenshots, console/page errors, redacted request/response metadata and bounded JS assets.
- [x] Per-run Playwright workspace and SHA-256 inventory.
- [x] Scope and redaction unit tests.
- [x] Implementation/security documentation.

## Remaining Phase 3 exit criteria
- [ ] Persist authorization records in the API/database and expose web-target registration.
- [ ] Queue authorized capture jobs end-to-end; enforce cancellation and authorization expiry.
- [ ] Deploy browser-worker egress firewall/network policy.
- [ ] Safe HAR export with header/cookie redaction and explicit opt-in.
- [ ] Web-Check and Wappalyzergo adapters.
- [ ] Webcrack, Wakaru and Oxc adapters with pinned runtimes and fixtures.
- [ ] Retire.js and Lighthouse adapters against local fixtures.
- [ ] Evidence-backed route/dependency/network graphs.
- [ ] Source-known Juice Shop and RealWorld benchmark fixtures with hashes/licenses.
- [ ] End-to-end authorized local web app test in an isolated Compose lab.
- [ ] Expanded redirect/DNS rebinding/cancellation/quota threat tests.

Manual acceptance requires a disposable local fixture or documented authorization. A passing unit test is not proof that container egress policy is deployed.
