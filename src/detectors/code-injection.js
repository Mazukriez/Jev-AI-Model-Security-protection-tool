import { finding } from '../core/scan.js';

// These signatures are intentionally conservative heuristics. They identify input
// that deserves review; they do not attempt to parse or prove exploitability.
const sqlRules = [
  {
    id: 'SQL-001',
    severity: 'high',
    title: 'Possible SQL tautology or authentication bypass',
    re: /(?:['"`]\s*(?:or|and)\s+['"`]?\w+['"`]?\s*=\s*['"`]?\w+['"`]?|\b(?:or|and)\s+1\s*=\s*1\b)/i
  },
  {
    id: 'SQL-002',
    severity: 'high',
    title: 'Possible UNION-based SQL injection',
    re: /\bunion\s+(?:all\s+)?select\b/i
  },
  {
    id: 'SQL-003',
    severity: 'critical',
    title: 'Possible stacked SQL command or destructive query',
    re: /(?:;|\bexec(?:ute)?\b)\s*(?:drop\s+(?:table|database)|truncate\s+table|delete\s+from|alter\s+table|xp_cmdshell)\b/i
  },
  {
    id: 'SQL-004',
    severity: 'medium',
    title: 'Possible SQL comment truncation sequence',
    re: /(?:--|#|\/\*)\s*(?:'|\b(?:select|where|from|and|or)\b)?/i
  },
  {
    id: 'SQL-005',
    severity: 'medium',
    title: 'Possible database metadata enumeration',
    re: /\b(?:information_schema|pg_catalog|sqlite_master|sys\.(?:tables|objects))\b/i
  }
];

const codeRules = [
  {
    id: 'CODE-001',
    severity: 'critical',
    title: 'Possible destructive shell command',
    re: /(?:\brm\s+-[rf]{1,2}\b|\bdel\s+\/s\s+\/q\b|\bformat\s+[a-z]:\b|\bmkfs(?:\.|\s)\b)/i
  },
  {
    id: 'CODE-002',
    severity: 'critical',
    title: 'Possible command execution or process spawning request',
    re: /\b(?:child_process\.(?:exec|execFile|spawn|fork)|(?:os|subprocess)\.(?:system|popen)|process\.exec(?:Path|Argv)?|shell(?:_command)?\s*\()/i
  },
  {
    id: 'CODE-003',
    severity: 'high',
    title: 'Possible dynamic code evaluation request',
    re: /\b(?:eval|exec|Function)\s*\(/i
  },
  {
    id: 'CODE-004',
    severity: 'high',
    title: 'Possible reverse-shell or remote command pattern',
    re: /(?:bash|sh|zsh|powershell|cmd)\s+-c\s+|\b(?:nc|ncat|netcat)\b[^\n]{0,100}\s+-e\s+/i
  },
  {
    id: 'CODE-005',
    severity: 'high',
    title: 'Possible encoded payload execution chain',
    re: /(?:base64\s+(?:-d|--decode)|frombase64string)\b[^\n]{0,120}\b(?:eval|exec|invoke-expression|iex)\b/i
  }
];

function scanRules(input, rules, detector, options) {
  const findings = [];
  for (const field of ['state', 'question', 'request']) {
    const value = input[field];
    if (!value) continue;
    for (const rule of rules) {
      if (rule.re.test(value)) {
        findings.push(finding({
          ...rule,
          detector,
          field,
          detail: `${rule.title} in ${field}. Treat as untrusted input and require review before execution.`,
          evidence: options.includeEvidence ? value.slice(0, 80) : undefined
        }));
      }
    }
  }
  return findings;
}

export function sqlInjectionDetector(input, options = {}) {
  return scanRules(input, sqlRules, 'sql-injection', options);
}

export function maliciousCodeDetector(input, options = {}) {
  return scanRules(input, codeRules, 'malicious-code-pattern', options);
}

export function codeInjectionDetectors(input, options = {}) {
  return [
    ...sqlInjectionDetector(input, options),
    ...maliciousCodeDetector(input, options)
  ];
}
