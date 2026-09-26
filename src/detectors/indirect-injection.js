import { finding } from '../core/scan.js';

const rules = [
  {
    id: 'IND-001',
    severity: 'high',
    title: 'Indirect instruction found in external content',
    re: /(?:ignore|disregard|override|forget)\s+(?:the\s+)?(?:system|developer|previous|original)\s+(?:prompt|instructions?|rules?)/i
  },
  {
    id: 'IND-002',
    severity: 'high',
    title: 'External content attempts to redirect the agent',
    re: /(?:assistant|agent|model)\s*[:,\-]?\s*(?:you must|your new task is|do this instead|follow these instructions)/i
  },
  {
    id: 'IND-003',
    severity: 'critical',
    title: 'File or retrieved content requests secret exfiltration',
    re: /(?:upload|send|post|exfiltrate|email|print)\s+(?:the\s+)?(?:api[_ -]?key|password|token|secret|\.env|credentials?|private key)/i
  },
  {
    id: 'IND-004',
    severity: 'high',
    title: 'Attachment content attempts to trigger an external action',
    re: /(?:click|open|visit|download|execute|run)\s+(?:this\s+)?(?:link|url|attachment|file|macro|command)/i
  },
  {
    id: 'IND-005',
    severity: 'medium',
    title: 'Content attempts to conceal instructions from the user',
    re: /(?:do not|don't)\s+(?:tell|show|inform|mention)\s+(?:the\s+)?(?:user|operator|reviewer)|hidden\s+instructions?/i
  },
  {
    id: 'IND-006',
    severity: 'medium',
    title: 'Document or web content marks itself as a higher-trust instruction source',
    re: /(?:system|developer|admin|trusted)\s+(?:message|instruction|directive)\s*[:=]/i
  }
];

const sourceFields = ['state', 'question', 'request', 'externalData', 'fileName', 'fileContent', 'attachmentText', 'retrievedText'];

export function indirectPromptInjectionDetector(input, options = {}) {
  const findings = [];
  for (const field of sourceFields) {
    const value = input[field];
    if (typeof value !== 'string' || value.length === 0) continue;
    for (const rule of rules) {
      if (rule.re.test(value)) {
        findings.push(finding({
          ...rule,
          detector: 'indirect-prompt-injection',
          field,
          detail: `${rule.title} in untrusted source field ${field}. Treat retrieved or uploaded content as data, not instructions.`,
          evidence: options.includeEvidence ? value.slice(0, 80) : undefined
        }));
      }
    }
  }
  return findings;
}
