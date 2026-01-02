# Vulnerable Express App Example

This is an **intentionally vulnerable** Express.js application designed to test Zecurx CodeGuard's security scanning capabilities.

⚠️ **WARNING**: This code contains intentional security vulnerabilities. **DO NOT** use this code in production or any real application.

## Purpose

This example demonstrates all 10 security rules that Zecurx CodeGuard can detect:

| File          | Vulnerability                       | Rule                               |
| ------------- | ----------------------------------- | ---------------------------------- |
| `app.js`      | Multiple vulnerabilities            | Various                            |
| `auth.js`     | Hardcoded secrets, weak crypto      | ZCG-JS-004, ZCG-JS-005, ZCG-JS-009 |
| `database.js` | SQL injection                       | ZCG-JS-007                         |
| `files.js`    | Path traversal, command injection   | ZCG-JS-008, ZCG-JS-003             |
| `utils.js`    | eval, Function, prototype pollution | ZCG-JS-001, ZCG-JS-002, ZCG-JS-010 |
| `views.js`    | XSS via innerHTML                   | ZCG-JS-006                         |

## Expected Findings

When you run `zecurx scan examples/express-app`, you should see findings for:

1. **ZCG-JS-001** - Dangerous eval() usage
2. **ZCG-JS-002** - Dynamic Function constructor
3. **ZCG-JS-003** - Command injection (child_process)
4. **ZCG-JS-004** - Hardcoded secrets
5. **ZCG-JS-005** - Insecure crypto (MD5/SHA1)
6. **ZCG-JS-006** - Unsanitized innerHTML
7. **ZCG-JS-007** - SQL injection
8. **ZCG-JS-008** - Path traversal
9. **ZCG-JS-009** - Weak randomness
10. **ZCG-JS-010** - Prototype pollution

## Running the Scan

```bash
# From the project root
npm run scan examples/express-app

# Or with JSON output
npm run scan examples/express-app -- --format json

# Or with minimum severity
npm run scan examples/express-app -- --severity High
```

## Learning

Each vulnerability file contains comments explaining:

- What the vulnerability is
- Why it's dangerous
- How to fix it properly

Use this as a learning resource to understand common security issues in JavaScript/Node.js applications.
