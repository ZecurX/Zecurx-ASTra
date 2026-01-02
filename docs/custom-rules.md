# Writing Custom Rules

This guide explains how to create custom security rules for Zecurx CodeGuard.

## Rule Structure

Every rule must implement the `Rule` interface:

```typescript
import type { Rule } from '../core/types';

export const myRule: Rule = {
  meta: {
    id: 'ZCG-JS-XXX', // Unique identifier
    name: 'my-rule-name', // Short name
    description: 'What this rule detects',
    severity: 'High', // 'Low' | 'Medium' | 'High'
    cwe: 'CWE-XXX', // CWE identifier
    owasp: 'A01:2021-...', // OWASP category (optional)
    languages: ['js', 'ts'], // Supported languages
    tags: ['security', 'injection'], // Tags for filtering
  },
  create: (context) => ({
    // Visitor methods here
  }),
};
```

## The Context Object

The `context` parameter provides utilities for analysis:

```typescript
interface RuleContext {
  filePath: string; // Current file path
  language: Language; // 'js' or 'ts'
  sourceCode: string; // Full source code
  ast: File; // Babel AST

  // Report a finding
  report: (finding: PartialFinding) => void;

  // Get source code for a node
  getSource: (node: Node) => string;

  // Get a specific line
  getLine: (lineNumber: number) => string;
}
```

## Visitor Methods

Rules use Babel's visitor pattern. Common node types:

### CallExpression

Detects function calls like `eval()`, `exec()`:

```typescript
create: (context) => ({
  CallExpression(path) {
    const callee = path.node.callee;

    if (callee.type === 'Identifier' && callee.name === 'eval') {
      context.report({
        ruleId: 'ZCG-JS-001',
        message: 'Dangerous eval() detected',
        line: path.node.loc?.start.line ?? 0,
        column: path.node.loc?.start.column ?? 0,
        severity: 'High',
        confidence: 95,
      });
    }
  },
});
```

### MemberExpression

Detects property access like `object.property`:

```typescript
MemberExpression(path) {
  if (
    path.node.object.type === 'Identifier' &&
    path.node.object.name === 'document' &&
    path.node.property.type === 'Identifier' &&
    path.node.property.name === 'write'
  ) {
    context.report({ ... });
  }
}
```

### AssignmentExpression

Detects assignments like `element.innerHTML = value`:

```typescript
AssignmentExpression(path) {
  const { left, right } = path.node;

  if (left.type === 'MemberExpression') {
    // Check what's being assigned
  }
}
```

### VariableDeclarator

Detects variable declarations:

```typescript
VariableDeclarator(path) {
  const { id, init } = path.node;

  if (id.type === 'Identifier' && init?.type === 'StringLiteral') {
    // Check variable name and value
  }
}
```

## Helper Functions

Import helpers from the visitor module:

```typescript
import {
  getMemberExpressionPath,
  isIdentifier,
  isMemberExpression,
  looksLikeSecret,
  isSecretVariableName,
} from '../analyzers/javascript/visitor';

// Get full path: crypto.createHash -> ['crypto', 'createHash']
const memberPath = getMemberExpressionPath(node);

// Check if value looks like a secret
if (looksLikeSecret(stringValue)) { ... }
```

## Complete Example

Here's a rule that detects `console.log` statements:

```typescript
import type { Rule } from '../core/types';
import { getMemberExpressionPath } from '../analyzers/javascript/visitor';

export const noConsoleRule: Rule = {
  meta: {
    id: 'ZCG-JS-100',
    name: 'no-console',
    description: 'Detects console.log statements that may leak sensitive data',
    severity: 'Low',
    languages: ['js', 'ts'],
    tags: ['quality', 'logging'],
  },
  create: (context) => ({
    CallExpression(path) {
      const callee = path.node.callee;

      if (callee.type === 'MemberExpression') {
        const memberPath = getMemberExpressionPath(callee);

        if (memberPath[0] === 'console') {
          context.report({
            ruleId: 'ZCG-JS-100',
            message: `console.${memberPath[1]}() detected. Remove before production.`,
            line: path.node.loc?.start.line ?? 0,
            column: path.node.loc?.start.column ?? 0,
            severity: 'Low',
            confidence: 100,
          });
        }
      }
    },
  }),
};
```

## Registering Rules

Add your rule to `rules/index.ts`:

```typescript
import { noConsoleRule } from './no-console';

export const allRules: Rule[] = [
  // ... existing rules
  noConsoleRule,
];
```

## Testing Rules

Create a test file with vulnerable code and run the scanner:

```bash
# Create test file
echo "console.log('test')" > test.js

# Run scanner
npx ts-node packages/cli/src/index.ts scan test.js
```

## Best Practices

1. **Specificity** - Be precise to avoid false positives
2. **Confidence** - Set appropriate confidence levels (0-100)
3. **CWE Mapping** - Link to relevant CWE identifiers
4. **Helpful Messages** - Include fix suggestions in messages
5. **Performance** - Avoid expensive operations in hot paths
