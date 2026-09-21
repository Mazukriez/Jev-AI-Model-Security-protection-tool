import type { Decision, Finding } from '../core/types';

export function decide(findings: Finding[]): Decision {
  if (findings.some((f) => f.severity === 'critical')) return 'BLOCK';
  if (findings.some((f) => f.severity === 'high' || f.severity === 'medium')) return 'REVIEW';
  return 'ALLOW';
}
