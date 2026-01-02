# Zecurx CodeGuard

> **Zecurx CodeGuard currently supports JavaScript/TypeScript static analysis with AST-based rules. Python and Java support is planned.**

Zecurx CodeGuard is a Static Application Security Testing (SAST) tool that analyzes JavaScript and TypeScript source code without execution to identify security vulnerabilities and bugs.

## Current Scope

| Language   | Status       |
| ---------- | ------------ |
| JavaScript | ✅ Supported |
| TypeScript | ✅ Supported |
| Python     | 🔜 Planned   |
| Java       | 🔜 Planned   |

## Features

- 🔍 Static code analysis (AST-based)
- 🛡️ Security vulnerability detection with CWE mapping
- 🎯 10 high-quality security rules
- 📊 JSON output for CI/CD integration
- 💻 CLI tool
- 🔌 VS Code extension (WIP)

## Installation

```bash
npm install -g zecurx
```

## Usage

```bash
# Scan a directory
zecurx scan ./src --format json

# Scan with specific output
zecurx scan ./src --format pretty
```

## Security Rules

| Rule ID    | Description                       | Severity | CWE      |
| ---------- | --------------------------------- | -------- | -------- |
| ZCG-JS-001 | Dangerous eval() usage            | High     | CWE-95   |
| ZCG-JS-002 | Dynamic Function constructor      | High     | CWE-95   |
| ZCG-JS-003 | Command injection (child_process) | High     | CWE-78   |
| ZCG-JS-004 | Hardcoded secrets                 | High     | CWE-798  |
| ZCG-JS-005 | Insecure crypto (MD5/SHA1)        | Medium   | CWE-328  |
| ZCG-JS-006 | Unsanitized innerHTML             | Medium   | CWE-79   |
| ZCG-JS-007 | SQL injection                     | High     | CWE-89   |
| ZCG-JS-008 | Path traversal                    | High     | CWE-22   |
| ZCG-JS-009 | Weak randomness                   | Medium   | CWE-330  |
| ZCG-JS-010 | Prototype pollution               | High     | CWE-1321 |

## Output Schema

```typescript
type Finding = {
  id: string;
  ruleId: string;
  language: 'js' | 'ts';
  file: string;
  line: number;
  column: number;
  severity: 'Low' | 'Medium' | 'High';
  message: string;
  confidence: number;
  cwe?: string;
  snippet?: string;
};
```

## Roadmap

- [x] Core AST scanner
- [x] Rule engine
- [ ] Taint analysis
- [ ] VS Code extension
- [ ] AI-powered fix suggestions
- [ ] Dashboard integration

## License

MIT
