# SQL and malicious-code detector

`src/detectors/code-injection.js` provides a dependency-free custom detector for prompt or state content that may be passed into a database, shell, interpreter, or tool runner.

It currently identifies common signatures for SQL tautologies, `UNION SELECT`, stacked/destructive SQL commands, SQL comments and metadata enumeration, destructive shell commands, process spawning, dynamic evaluation, reverse-shell patterns, and encoded-payload execution chains.

These are **heuristics**, not a SQL parser, shell parser, sandbox, or exploitability proof. A finding means the application should treat the input as untrusted and route it through review or a stronger domain-specific validator. The default policy blocks critical matches and reviews high/medium matches.

The detector is enabled by default through `scan()`. It can also be used independently:

```js
import { sqlInjectionDetector, maliciousCodeDetector } from '../src/index.js';

const input = { state: 'untrusted text', question: 'classify this request' };
const sqlFindings = sqlInjectionDetector(input);
const codeFindings = maliciousCodeDetector(input);
```

When extending the module, add both adversarial and benign fixtures. Avoid broad keywords such as `SELECT`, `eval`, or `shell` without contextual signals, because ordinary security documentation and code review discussions should not be blocked.
