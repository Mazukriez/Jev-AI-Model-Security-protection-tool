export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const DECISIONS = ['ALLOW', 'REVIEW', 'BLOCK'];

export function normalizeInput(input = {}) {
  return {
    state: typeof input.state === 'string' ? input.state : '',
    question: typeof input.question === 'string' ? input.question : '',
    request: typeof input.request === 'string' ? input.request : ''
  };
}

export function decide(findings, policy = {}) {
  const blockAt = policy.blockAt ?? 'critical';
  const reviewAt = policy.reviewAt ?? 'medium';
  const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const max = findings.reduce((value, finding) => Math.max(value, rank[finding.severity] ?? 0), 0);
  if (max >= rank[blockAt]) return 'BLOCK';
  if (max >= rank[reviewAt]) return 'REVIEW';
  return 'ALLOW';
}

export function finding({ id, severity, title, detail, field, detector, evidence }) {
  return { id, severity, title, detail, ...(field ? { field } : {}), detector, ...(evidence ? { evidence } : {}) };
}
