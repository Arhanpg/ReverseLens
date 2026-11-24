# Phase 2 testing guide

## Automated checks

The Phase 2 workflow runs:
1. Phase 0 schemas/registry/fixture validation.
2. Spring Boot Maven tests and compilation on Java 21.
3. Python worker tests, including metric wrapper, normalization and scoring tests.
4. Next.js TypeScript validation and production build.
5. Docker Compose configuration validation and pinned worker image build.

Run locally:

```bash
mvn -B -f backend/pom.xml verify
python -m pip install -r worker/requirements.txt
python -m pip install pytest
PYTHONPATH=worker python -m pytest worker/tests -q
python scripts/validate_phase0.py
cd frontend && npm install && npm run lint && npm run build
```

## Integrated manual test

1. Start the stack with `docker compose up --build`.
2. Upload a legally authorized test APK through the Phase 1 dashboard.
3. Register the target as a benchmark dataset using the Benchmark Lab.
4. Add several target-specific ground-truth items. Verify each label from a known source and provide reviewer/source reference before marking it `verified`.
5. Create the `android-static-core` experiment with 3 repetitions.
6. Wait for all compatible jobs to reach terminal states. Confirm that every attempt maps to one Phase 1 run/execution and owns its independent output directory.
7. Inspect the scorecard and confirm unlabelled capability classes do not contribute false positives.
8. Open normalized evidence and download the source artifact using its link.
9. Export JSON, Markdown and HTML reports and verify that manifest hash, tool/adapter versions, resource metrics and OWASP tags are traceable.
10. Force one engine failure (for example, temporarily misconfigure a local tool in a disposable worker image) and verify that other engine attempts remain independently recorded.

## Scoring test cases

- No verified applicable ground truth → precision/recall/F1/coverage are N/A (null).
- Verified labels exist but engine returns no matching observations → zero precision/recall/F1 with misses recorded.
- Observations in a capability without verified labels → retained in evidence inventory but excluded from false positives.
- Duplicate canonical observations → duplicate rate increases without inflating unique recoveries.
- Evidence path traversal, missing evidence or a mismatched evidence SHA-256 → worker payload rejected.
- Unsupported engine/format pair → `incompatible`, not a failed decompilation.

## Known manual acceptance item

CI validates code, tests, frontend build and the worker Docker image. A complete run on a representative authorized APK in the maintainer's local environment remains a manual acceptance check; no third-party sample APK is committed to this public repository.
