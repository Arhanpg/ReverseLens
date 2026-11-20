# Contributing to ReverseLens

Thank you for helping improve ReverseLens. Contributions are welcome in documentation, schemas, benchmarks, engine adapters, security hardening, tests and the user interface.

## Before opening an issue

- Search existing issues and discussions.
- Explain the problem, expected behavior and how it relates to the project scope.
- For a proposed engine, include its canonical upstream repository and the capability it adds.
- Do not upload proprietary APKs, private source, credentials, cookies, personal data or production traffic captures.

## Development setup

The Phase 0 validation suite requires Python 3.10 or later.

```bash
python -m venv .venv
# Activate the environment for your shell.
python -m pip install -r requirements-dev.txt
python scripts/validate_phase0.py
python -m pytest
```

The validator checks schemas, the engine registry, dependency references, example fixtures and cross-record consistency. It does not install or execute reverse-engineering engines.

## Pull request expectations

Every pull request should:
- Explain the change and its motivation.
- Link related issues where applicable.
- Include tests or fixtures for changed behavior.
- Update schemas, registry and docs together when contracts change.
- Preserve compatibility or document a schema/version migration.
- Avoid committing real analysis workspaces, sample APKs, captured traffic, credentials or proprietary content.
- Pass the Phase 0 validation workflow.

## Adding an engine

Follow [Adding an Engine](docs/engine-registry/ADDING_AN_ENGINE.md). A tool is not considered integrated just because its CLI launches. It needs a reviewed license, input/output contract, isolated adapter, captured raw output, normalized evidence, fixtures and benchmark results.

## Security-sensitive changes

Do not add unrestricted scanning, credential collection, cookie import, access-control bypass, CAPTCHA bypass, bot evasion, proxy rotation or rate-limit circumvention. See [SECURITY.md](SECURITY.md), the [authorization policy](docs/legal-and-authorization/POLICY.md) and the [threat model](docs/threat-model/THREAT_MODEL.md).

## License

By contributing, you agree that your contributions are provided under the repository's Apache-2.0 license, subject to the terms in [LICENSE](LICENSE). Third-party components retain their respective licenses.
