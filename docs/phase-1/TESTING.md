# Phase 1 test and validation guide

## Automated CI

The Phase 1 workflow runs three jobs: Maven verification on Java 21, Python worker tests on Python 3.12, and Next.js type-check/production-build on Node.js 22. CI does not run a full APK decompilation test because sample APK binaries are not committed to this public repository.

## Backend tests

    mvn -f backend/pom.xml verify

## Worker tests

    python -m venv .venv
    python -m pip install -r worker/requirements.txt
    python -m pip install pytest
    PYTHONPATH=worker python -m pytest worker/tests -q

## Frontend checks

    cd frontend
    npm install
    npm run lint
    npm run build

## Integrated stack

    cp .env.example .env
    # Replace the example secrets in .env before starting.
    docker compose up --build

Open http://localhost:3000, upload an authorized local test APK, confirm the authorization basis, leave the default four APK engines selected and start a run.

## Manual integration acceptance checklist

- API health endpoint returns UP.
- Unsupported file extensions are rejected.
- A ZIP that does not match the declared Android package format is rejected.
- Upload stores SHA-256 and appears in the target list.
- Default APK profile creates four independent jobs: JADX, Apktool, Androguard and APKiD.
- Each engine receives a separate output directory.
- One analyzer failure does not cancel the others.
- Logs and result metadata remain available after failure.
- Run manifest is written after all engines reach terminal states.
- Worker rejects an input whose SHA-256 differs from its job record.
- Worker path validation rejects traversal.
- File download rejects paths outside the run root.

Do not use commercial APKs, proprietary source, personal data or production captures as public fixtures.
