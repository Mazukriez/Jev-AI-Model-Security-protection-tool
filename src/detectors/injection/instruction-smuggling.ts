import type { Detector } from '../../core/types';

const patterns = [
  /ignore\s+(all|any|previous|prior)\s+instructions/i,
  /disregard\s+.*rules/i,
  /system\s+message/i,
  /developer\s+message/i,
];

export const instructionSmuggling: Detector = ({ state, question }) => {
  const findings = [];
  for (const [field, value] of [['state', state], ['question', question]] as const) {
    if (patterns.some((pattern) => pattern.test(value))) {
      findings.push({
        id: 'INJ-001',
        severity: 'high' as const,
        title: 'Instruction-smuggling pattern',
        detail: 'Input contains language commonly used to alter trusted instructions or decision context.',
        field,
        detector: 'instruction-smuggling',
      });
    }
  }
  return findings;
};
