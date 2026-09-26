# Responsible use

JevShield is defense-in-depth, not a safety certificate. Pattern detectors can miss novel attacks and can flag benign text. A `BLOCK` result is a policy decision based on configured evidence; an `ALLOW` result is not proof of harmlessness.

For production use:

- Keep provider and application authorization checks separate.
- Treat `REVIEW` as a real human or secondary-model path.
- Pin versions and test threshold changes against a representative, licensed corpus.
- Avoid storing raw state, secrets, or personal data in logs.
- Monitor false positives, false negatives, latency, and detector failures.
- Add domain-specific controls before enabling autonomous actions.
