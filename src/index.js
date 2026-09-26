import { normalizeInput, decide } from './core/scan.js';
import { baselineDetectors } from './detectors/baseline.js';

export function scan(input, options = {}) {
  const normalized = normalizeInput(input);
  const findings = (options.detectors ?? [baselineDetectors]).flatMap(detector => detector(normalized, options));
  return {
    version: '0.2',
    decision: decide(findings, options.policy),
    findings,
    meta: { detectorCount: options.detectors?.length ?? 1, bytes: Buffer.byteLength(JSON.stringify(normalized), 'utf8') }
  };
}

export { baselineDetectors } from './detectors/baseline.js';
export { decide, normalizeInput } from './core/scan.js';
