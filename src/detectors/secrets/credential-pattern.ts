import type { Detector } from '../../core/types';

const secretPattern = /(sk-[A-Za-z0-9_-]{20,}|api[_-]?key\s*[:=]\s*[A-Za-z0-9_-]{16,}|bearer\s+[A-Za-z0-9._-]{20,}|password\s*[:=]\s*\S+)/i;

export const credentialPattern: Detector = ({ state }) =>
  secretPattern.test(state)
    ? [{
        id: 'SEC-001',
        severity: 'critical',
        title: 'Possible credential exposure',
        detail: 'State appears to contain a secret or credential-like value.',
        field: 'state',
        detector: 'credential-pattern',
      }]
    : [];
