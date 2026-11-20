# Authorization and Responsible Use Policy

**This is an engineering policy, not legal advice.** Laws, contracts, platform terms and vulnerability-research scopes vary and change. Obtain qualified legal advice for uncertain or commercial activity.

## 1. Permitted operating model

ReverseLens is designed for:
- Applications and systems owned by the user or their organization.
- Written-authorized security assessments.
- Local training labs and deliberately vulnerable applications.
- Open-source artifacts where the intended analysis is consistent with the relevant license and law.
- Bug-bounty activity strictly within the current published program scope and rules.

A user being able to download or install an application does not, by itself, prove authorization for every form of reverse engineering, dynamic testing, scraping or security probing.

## 2. Authorization record

Before a web target is contacted or dynamic testing is started, record:
- Target identifiers and exact scope.
- Who is asserting authorization and their role.
- Basis for the activity (ownership, written permission, lab, or a specific program).
- Permitted actions and explicitly excluded actions.
- Allowed hosts, paths, methods, rate/request limits and test window.
- Source/reference for written permission or program rules where available.
- Date confirmed, expiry/revocation state and reviewer notes.

Static offline parsing of user-supplied artifacts should still record provenance and the submitter's asserted lawful basis. The application must not treat a checkbox as legal proof.

## 3. Prohibited product features

Do not implement:
- Credential harvesting or browser-cookie import by default.
- Unauthorized authenticated scraping or account automation.
- CAPTCHA bypass, bot evasion, proxy rotation or rate-limit circumvention.
- Authentication, authorization, paywall or access-control bypass.
- Exploit execution against third-party services outside an explicitly authorized scope.
- Bulk extraction of personal or private user data.
- Automatic downloaders for proprietary apps where the download or use is not authorized.

## 4. Web target safeguards

A web analysis job must:
- Require a current authorization record.
- Enforce exact host/path scope.
- Restrict to HTTP/HTTPS.
- Resolve DNS and reject unsafe IP ranges.
- Recheck every redirect and every request/navigation.
- Block loopback, private, link-local, multicast, reserved and metadata-service addresses.
- Enforce network egress policy independently of application code.
- Apply request, page, byte, duration and concurrency budgets.
- Stop on scope change, repeated errors, authorization expiry or user cancellation.
- Avoid login flows and personal browser profiles by default.

## 5. Artifact and dynamic analysis safeguards

- Treat all uploads as hostile.
- Run parsers in non-root isolated workers or disposable VMs.
- Disable network by default for offline static analysis.
- Enforce resource and time limits.
- Prevent archive path traversal and decompression bombs.
- Do not mount host secrets or the Docker socket.
- Restrict scratch mounts and delete temporary data according to retention settings.
- Dynamic instrumentation and interception are limited to owned or expressly authorized test environments.

## 6. Evidence, privacy and retention

- Keep raw evidence separate from normalized conclusions.
- Mask token/secret-like strings by default in the UI.
- Never send proprietary source or captured content to external AI services without explicit, informed user choice.
- Do not commit sensitive outputs, customer artifacts, commercial APKs, credentials, cookies or private captures.
- Provide export and deletion controls.
- Keep only the evidence necessary for the user's stated analysis.

## 7. Research program scope

For any vulnerability disclosure program, verify the current official policy, eligible assets, excluded test classes, rate limits, account requirements and disclosure instructions immediately before testing. A program's existence is not blanket permission to test all properties or behaviors of the company.

## 8. India-specific caution

The project is developed in India. Relevant legal issues can include the Information Technology Act, 2000, the Copyright Act, 1957, anti-circumvention provisions and contractual terms. Do not assume that good intent, public availability, lawful installation or a generic reverse-engineering exception automatically authorizes a particular activity. Obtain advice for uncertain cases and require explicit owner/program authorization for remote active testing.
