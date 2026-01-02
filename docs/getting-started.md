# Getting Started with Zecurx CodeGuard

Zecurx CodeGuard is a Static Application Security Testing (SAST) tool for JavaScript and TypeScript applications.

## Installation

```bash
# Clone the repository
git clone https://github.com/zecurx/zecurx-as.git
cd zecurx-as

# Install dependencies
npm install

# Run a scan
npm run scan ./your-project
```

## Quick Start

### Scanning a Project

```bash
# Scan with pretty output (default)
npx ts-node packages/cli/src/index.ts scan ./src

# Scan with JSON output
npx ts-node packages/cli/src/index.ts scan ./src --format json

# Scan with minimum severity filter
npx ts-node packages/cli/src/index.ts scan ./src --severity High

# Save output to file
npx ts-node packages/cli/src/index.ts scan ./src --format json --output results.json
```

### Listing Available Rules

```bash
npx ts-node packages/cli/src/index.ts rules
```

## Output Formats

### Pretty (Human-readable)

```
🔍 Zecurx CodeGuard - Security Scanner

C:\project\src\auth.js
  15:6 High ZCG-JS-004 [CWE-798]
    Hardcoded secret detected in variable "API_KEY"
```

### JSON

```json
{
  "files": [...],
  "summary": {
    "totalFiles": 10,
    "totalFindings": 5,
    "bySeverity": { "High": 3, "Medium": 2, "Low": 0 }
  }
}
```

### SARIF

SARIF (Static Analysis Results Interchange Format) output is compatible with GitHub Code Scanning and other CI/CD tools.

## Next Steps

- [Architecture Overview](./architecture.md)
- [Writing Custom Rules](./custom-rules.md)
- [API Reference](./api-reference.md)
