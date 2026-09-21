# Contributing to JevShield

Thank you for helping build open security tooling for AI decision systems.

## First contribution

1. Fork the repository.
2. Create a focused branch:
   `git checkout -b feat/my-detector`
3. Make one focused change.
4. Add or update tests.
5. Run `npm test` and `npm run lint`.
6. Update documentation when behavior changes.
7. Open a pull request using the PR template.

## Good first contributions

- Add a detector
- Add a benign fixture
- Add an adversarial fixture
- Improve documentation
- Add a policy example
- Improve CI
- Add an integration example

## Security detector requirements

Every detector should document:

- Threat being detected
- Input assumptions
- Detection logic
- Expected false positives
- Expected false negatives
- Severity rationale
- Regression fixtures

A detector must not silently transform uncertain evidence into an automatic BLOCK without a documented policy rule.

## Testing

Security changes should include both malicious and benign examples. A good detector demonstrates what it catches and what it intentionally does not catch.

## Pull requests

Keep PRs small and reviewable. Include:

- Problem statement
- Threat model
- Implementation
- Tests
- Documentation
- Limitations

Never commit credentials, customer information, proprietary model data or production logs.

## Code of conduct

By participating, you agree to [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
