import traverse, { NodePath, Visitor } from '@babel/traverse';
import type { File, Node } from '@babel/types';
import type {
  Rule,
  RuleContext,
  RuleVisitor,
  Language,
  Severity,
} from '../../core/types';
import { getSourceLines, getSnippetWithContext } from './parser';

/**
 * Partial finding reported by rules (without id, file, language)
 */
export interface PartialFinding {
  ruleId: string;
  line: number;
  column?: number;
  severity: Severity;
  message: string;
  confidence?: number;
  cwe?: string;
  snippet?: string;
  endLine?: number;
  endColumn?: number;
}

/**
 * Options for creating a visitor
 */
export interface VisitorOptions {
  filePath: string;
  language: Language;
  sourceCode: string;
  ast: File;
  rules: Rule[];
  onFinding: (finding: PartialFinding) => void;
}

/**
 * Combined visitor that runs all rules
 */
export interface CombinedVisitor {
  traverse: (ast: File) => void;
}

/**
 * Create a combined visitor from multiple rules
 */
export function createVisitor(options: VisitorOptions): CombinedVisitor {
  const { filePath, language, sourceCode, ast, rules, onFinding } = options;

  // Helper to get source code for a node
  const getSource = (node: Node): string => {
    if (node.loc) {
      return getSourceLines(sourceCode, node.loc.start.line, node.loc.end.line);
    }
    return '';
  };

  // Helper to get a specific line
  const getLine = (lineNumber: number): string => {
    return getSourceLines(sourceCode, lineNumber);
  };

  // Create contexts and visitors for each rule
  const ruleVisitors: {
    rule: Rule;
    visitor: RuleVisitor;
    context: RuleContext;
  }[] = [];

  for (const rule of rules) {
    const context: RuleContext = {
      filePath,
      language,
      sourceCode,
      ast,
      getSource,
      getLine,
      report: (finding) => {
        // Add snippet if not provided
        const snippet =
          finding.snippet ?? getSnippetWithContext(sourceCode, finding.line);

        onFinding({
          ruleId: rule.meta.id,
          line: finding.line,
          column: finding.column ?? 1,
          severity: finding.severity ?? rule.meta.severity,
          message: finding.message,
          confidence: finding.confidence ?? 80,
          cwe: finding.cwe ?? rule.meta.cwe,
          snippet,
          endLine: finding.endLine,
          endColumn: finding.endColumn,
        });
      },
    };

    const visitor = rule.create(context);
    ruleVisitors.push({ rule, visitor, context });
  }

  // Combine all visitors into one
  const combinedVisitor: Visitor = {};

  // Get all unique visitor keys
  const visitorKeys = new Set<string>();
  for (const { visitor } of ruleVisitors) {
    for (const key of Object.keys(visitor)) {
      visitorKeys.add(key);
    }
  }

  // Create combined handlers for each key
  for (const key of visitorKeys) {
    (combinedVisitor as any)[key] = (path: NodePath<any>) => {
      for (const { visitor, context } of ruleVisitors) {
        const handler = (visitor as any)[key];
        if (handler) {
          try {
            handler(path, context);
          } catch (error) {
            console.error(`Error in rule visitor (${key}):`, error);
          }
        }
      }
    };
  }

  return {
    traverse: (ast: File) => {
      traverse(ast, combinedVisitor);
    },
  };
}

/**
 * Helper to check if a node is an identifier with a specific name
 */
export function isIdentifier(
  node: Node | null | undefined,
  name?: string
): boolean {
  if (!node || node.type !== 'Identifier') return false;
  if (name !== undefined) return node.name === name;
  return true;
}

/**
 * Helper to check if a node is a member expression like `obj.prop`
 */
export function isMemberExpression(
  node: Node | null | undefined,
  objectName?: string,
  propertyName?: string
): boolean {
  if (!node || node.type !== 'MemberExpression') return false;

  if (objectName !== undefined) {
    if (node.object.type !== 'Identifier' || node.object.name !== objectName) {
      return false;
    }
  }

  if (propertyName !== undefined) {
    if (
      node.property.type !== 'Identifier' ||
      node.property.name !== propertyName
    ) {
      return false;
    }
  }

  return true;
}

/**
 * Helper to get the full member expression path (e.g., "process.env.SECRET")
 */
export function getMemberExpressionPath(node: Node): string[] {
  if (node.type === 'Identifier') {
    return [node.name];
  }

  if (node.type === 'MemberExpression') {
    const objectPath = getMemberExpressionPath(node.object as Node);

    if (node.property.type === 'Identifier') {
      return [...objectPath, node.property.name];
    }

    if (node.property.type === 'StringLiteral') {
      return [...objectPath, node.property.value];
    }
  }

  return [];
}

/**
 * Helper to check if a string looks like a secret
 */
export function looksLikeSecret(value: string): boolean {
  // Check for common secret patterns
  const secretPatterns = [
    /^[a-f0-9]{32,}$/i, // Hex strings (API keys, hashes)
    /^[a-z0-9+/=]{20,}$/i, // Base64-ish strings
    /^(sk|pk|api|key|secret|token|password|pwd|auth)[-_]/i, // Prefixed secrets
    /^ghp_[a-zA-Z0-9]{36}$/, // GitHub personal access token
    /^xox[baprs]-[a-zA-Z0-9-]+$/, // Slack tokens
    /^AKIA[A-Z0-9]{16}$/, // AWS access key
    /-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----/, // Private keys
  ];

  return secretPatterns.some((pattern) => pattern.test(value));
}

/**
 * Helper to check if a variable name suggests it's a secret
 */
export function isSecretVariableName(name: string): boolean {
  const secretKeywords = [
    'password',
    'passwd',
    'pwd',
    'secret',
    'api_key',
    'apikey',
    'api-key',
    'auth_token',
    'authtoken',
    'access_token',
    'accesstoken',
    'private_key',
    'privatekey',
    'secret_key',
    'secretkey',
    'token',
    'credentials',
    'creds',
    'auth',
    'bearer',
  ];

  const lowerName = name.toLowerCase();
  return secretKeywords.some((keyword) => lowerName.includes(keyword));
}
