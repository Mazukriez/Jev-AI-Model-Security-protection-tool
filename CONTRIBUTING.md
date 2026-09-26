# Contributing to JevShield

Thank you for helping build open security tooling for AI decision workflows.

## Local workflow

```bash
npm install
npm test
npm run lint
```

Create a focused branch and use a conventional commit prefix such as `feat:`, `security:`, `test:`, or `docs:`.

## Detector requirements

Each detector must document the threat and input assumptions, detection logic and matching limits, severity rationale, expected false positives and false negatives, adversarial and benign regression fixtures, and any privacy impact of evidence fields. Detectors must be deterministic, side-effect free, dependency-light, and safe with malformed input. Never commit real credentials, customer data, production logs, or proprietary model outputs.

## Pull requests

Include the problem statement, threat-model impact, tests, limitations, and documentation changes. Security-sensitive changes require maintainer review. Keep changes small enough for community review. Do not open a public issue for an exploitable vulnerability; follow [SECURITY.md](SECURITY.md).
