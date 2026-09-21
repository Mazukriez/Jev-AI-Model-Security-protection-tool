# Architecture

```
Untrusted state/question
        |
        v
+-------------------+
| JevShield Scanner |
+---------+---------+
          |
   +------+------+------+
   |             |      |
Injection      Secret   PII
Detector      Detector Detector
   |             |      |
   +------+------+------+
          |
          v
    Policy Engine
          |
    +-----+-----+
    |     |     |
  ALLOW REVIEW BLOCK
          |
          v
      Jev Adapter
          |
          v
    Typed AI Decision
```

## Principles

### Separate detection from enforcement

Detectors return evidence. Policies decide what that evidence means.

### Fail safely

Provider/API failures must not be represented as successful security validation.

### Minimize sensitive data

The scanner should avoid logging raw secrets or unnecessary personal data.

### Extensibility

New detectors should not require rewriting the core scanner.

### Reproducibility

Security behavior should be backed by versioned fixtures and regression tests.
