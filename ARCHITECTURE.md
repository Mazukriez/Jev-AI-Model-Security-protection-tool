# Architecture

```text
untrusted state / question / request
              |
              v
      normalizeInput()
              |
              v
     +-------------------+
     | detector pipeline |
     +----+----+----+----+
          |    |    |
      injection secret privacy + size
          \    |    /
           v   v   v
        structured findings
              |
              v
        deterministic policy
        ALLOW / REVIEW / BLOCK
              |
              v
       Jev/provider adapter
```

## Boundaries

Detection is evidence. Detectors return structured findings and must not execute actions. Policy is enforcement: it maps severity to an application decision and is independently testable. Provider credentials, network calls, retries, and output validation belong outside the scanner core. If a security check is unavailable, callers must fail closed rather than report successful validation. Raw state is not returned or logged by default; evidence is opt-in and truncated.

## Adding a detector

Export a function with the shape `(normalizedInput, options) => Finding[]`, pass it through `scan(..., { detectors: [...] })`, and add paired adversarial/benign fixtures. Do not mutate input, call external services, or include secrets in test data.
