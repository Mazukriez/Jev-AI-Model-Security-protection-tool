import { finding } from '../core/scan.js';

const rules = [
  { id: 'INJ-001', detector: 'instruction-smuggling', severity: 'high', title: 'Instruction-smuggling language detected', re: /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?/i },
  { id: 'INJ-002', detector: 'instruction-smuggling', severity: 'medium', title: 'Attempt to alter system or policy instructions', re: /(?:reveal|show|print|leak)\s+(?:the\s+)?(?:system|developer|hidden)\s+(?:prompt|message|instructions?)/i },
  { id: 'INJ-003', detector: 'instruction-smuggling', severity: 'high', title: 'Untrusted content requests bypassing a control', re: /(?:bypass|disable|turn\s+off|override)\s+(?:security|safety|policy|validation|approval)/i },
  { id: 'SEC-001', detector: 'secret-pattern', severity: 'critical', title: 'Possible credential or private key detected', re: /(?:sk-[a-zA-Z0-9]{20,}|gh[pousr]_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/ },
  { id: 'SEC-002', detector: 'secret-pattern', severity: 'high', title: 'Possible assignment-style secret detected', re: /(?:api[_-]?key|secret|password|token)\s*[:=]\s*["']?[^\s"']{10,}/i },
  { id: 'PII-001', detector: 'privacy-indicator', severity: 'medium', title: 'Possible email address in model state', re: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i },
  { id: 'PII-002', detector: 'privacy-indicator', severity: 'medium', title: 'Possible payment-card number in model state', re: /\b(?:\d[ -]*?){13,19}\b/ }
];

export function baselineDetectors(input, options = {}) {
  const fields = ['state', 'question', 'request'];
  const findings = [];
  for (const field of fields) {
    const value = input[field];
    if (!value) continue;
    for (const rule of rules) {
      if (rule.re.test(value)) {
        findings.push(finding({ ...rule, field, detail: `${rule.title} in ${field}.`, evidence: options.includeEvidence ? value.slice(0, 80) : undefined }));
      }
    }
  }
  const maxBytes = options.maxBytes ?? 32_000;
  const totalBytes = Buffer.byteLength(JSON.stringify(input), 'utf8');
  if (totalBytes > maxBytes) {
    findings.push(finding({ id: 'SIZE-001', detector: 'size-guardrail', severity: 'high', title: 'Input exceeds configured size limit', detail: `${totalBytes} UTF-8 bytes received; limit is ${maxBytes}.`, field: 'request' }));
  }
  return findings;
}
