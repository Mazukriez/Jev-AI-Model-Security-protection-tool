import { normalizeInput, decide } from './core/scan.js';
import { baselineDetectors } from './detectors/baseline.js';
import { codeInjectionDetectors } from './detectors/code-injection.js';
import { indirectPromptInjectionDetector } from './detectors/indirect-injection.js';

export function scan(input, options = {}) {
  const normalized = normalizeInput(input);
  const detectors = options.detectors ?? [baselineDetectors, codeInjectionDetectors, indirectPromptInjectionDetector];
  const findings = detectors.flatMap(detector => detector(normalized, options));
  return {
    version: '0.2',
    decision: decide(findings, options.policy),
    findings,
    meta: { detectorCount: detectors.length, bytes: Buffer.byteLength(JSON.stringify(normalized), 'utf8') }
  };
}

export { baselineDetectors } from './detectors/baseline.js';
export { codeInjectionDetectors, maliciousCodeDetector, sqlInjectionDetector } from './detectors/code-injection.js';
export { indirectPromptInjectionDetector } from './detectors/indirect-injection.js';
export { decide, normalizeInput } from './core/scan.js';
