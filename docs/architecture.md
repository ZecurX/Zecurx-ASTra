# Architecture Overview

Zecurx CodeGuard is built with a modular architecture designed for extensibility and multi-language support.

## Project Structure

```
packages/
├── engine/                 # Core scanning engine
│   └── src/
│       ├── core/          # Core types and engine
│       │   ├── types.ts   # Type definitions
│       │   ├── rule-engine.ts  # Main engine class
│       │   └── finding.ts # Finding utilities
│       ├── analyzers/     # Language-specific analyzers
│       │   └── javascript/
│       │       ├── parser.ts   # Babel AST parser
│       │       └── visitor.ts  # AST visitor
│       └── rules/         # Security rules
├── cli/                   # Command-line interface
│   └── src/
│       └── index.ts       # CLI entry point
└── vscode-extension/      # VS Code extension (WIP)
```

## Core Components

### 1. Rule Engine (`rule-engine.ts`)

The `RuleEngine` class orchestrates the entire scanning process:

```typescript
const engine = createDefaultEngine();
engine.registerRules(allRules);
const result = await engine.scan('./src');
```

**Responsibilities:**

- File discovery and filtering
- AST parsing coordination
- Rule execution
- Finding aggregation
- Event emission

### 2. Parser (`analyzers/javascript/parser.ts`)

Parses JavaScript/TypeScript files into AST using Babel:

```typescript
const result = parseFile(sourceCode, filePath, 'ts');
// result.ast contains the Babel AST
```

**Features:**

- TypeScript and JSX support
- Error recovery
- Source location tracking

### 3. Visitor (`analyzers/javascript/visitor.ts`)

Creates a combined AST visitor from multiple rules:

```typescript
const visitor = createVisitor({
  filePath,
  language,
  sourceCode,
  ast,
  rules: activeRules,
  onFinding: (finding) => { ... }
});

visitor.traverse(ast);
```

### 4. Rules (`rules/*.ts`)

Each rule is a self-contained module:

```typescript
export const myRule: Rule = {
  meta: {
    id: 'ZCG-JS-XXX',
    name: 'my-rule',
    description: '...',
    severity: 'High',
    cwe: 'CWE-XXX',
    languages: ['js', 'ts'],
  },
  create: (context) => ({
    CallExpression(path) {
      // Detection logic
      context.report({ ... });
    }
  })
};
```

## Data Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   CLI/API   │────▶│ Rule Engine │────▶│   Parser    │
└─────────────┘     └─────────────┘     └─────────────┘
                           │                   │
                           ▼                   ▼
                    ┌─────────────┐     ┌─────────────┐
                    │   Rules     │◀────│   Visitor   │
                    └─────────────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  Findings   │
                    └─────────────┘
```

## Event System

The engine emits events during scanning:

```typescript
engine.on((event) => {
  switch (event.type) {
    case 'file:start':
      console.log(`Scanning ${event.file}`);
      break;
    case 'finding':
      console.log(`Found: ${event.finding.message}`);
      break;
    case 'scan:end':
      console.log(`Done: ${event.result.summary.totalFindings} findings`);
      break;
  }
});
```

## Extensibility Points

1. **Custom Rules** - Add new detection logic
2. **Language Analyzers** - Support new languages
3. **Output Formatters** - Custom report formats
4. **Integrations** - CI/CD, IDE plugins
