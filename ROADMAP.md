# JevShield roadmap

## Delivered in 0.2

The baseline now includes a dependency-free scanner library, instruction-smuggling, secret, privacy, and size detectors, an ALLOW/REVIEW/BLOCK policy engine, CLI and HTTP scan surfaces, regression fixtures, Node 20/22 CI, and contributor/threat-model documentation.

## Next: 0.3 security engine

Add named policy configuration with threshold validation, JSON/SARIF output, detector evidence-quality fields, more privacy and cloud-credential detectors, and fuzz/property tests for parser and size boundaries.

## 0.4 integration layer

Add an explicit Jev request/response adapter with schema validation, redaction middleware, an audit-event schema, OpenTelemetry hooks without raw-content export, and a GitHub Action example for scanning fixtures and changed configuration.

## 1.0 community ecosystem

Publish a versioned detector SDK, benchmark corpus with licensing metadata, reviewed policy registry, maintainer rotation, and a release checklist. Roadmap items are proposals, not claims that the provider or model itself is unsafe.
