# ReverseLens Phase 1 — Android Static MVP

See [Phase 1 implementation notes](docs/phase-1/IMPLEMENTATION.md).

```bash
cp .env.example .env
# Edit .env and replace both development secrets.
docker compose up --build
```

Dashboard: http://localhost:3000  
API health: http://localhost:8080/actuator/health

Phase 1 is a local Android static-analysis slice for authorized artifacts. It does not implement web reverse engineering, runtime instrumentation or production deployment hardening.
