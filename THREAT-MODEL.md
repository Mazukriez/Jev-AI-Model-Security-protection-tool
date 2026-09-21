# Threat Model

## Assets

- AI decision integrity
- Application credentials
- User/customer data
- Security policy configuration
- Audit evidence
- Provider credentials

## Threat actors

- Malicious end user
- Malicious content in external data
- Compromised upstream service
- Accidental developer disclosure
- Automated attacker

## Threats

| Threat | Example | Initial control |
|---|---|---|
| Instruction smuggling | "Ignore previous instructions" | Injection detector |
| Secret exposure | API key in state | Secret detector |
| PII leakage | Customer ID/email in unnecessary state | Privacy detector |
| Oversized context | Extremely large untrusted payload | Size guardrail |
| Policy bypass | Input attempts to change decision rules | Policy engine |
| False confidence | Detector failure treated as safe | Fail-safe API contract |

## Out of scope for MVP

- Breaking TypeSafe infrastructure
- Bypassing provider controls
- Offensive exploitation of third-party systems
- Proving model safety mathematically
