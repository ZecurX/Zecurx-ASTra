import type { Rule } from '../core/types';
import {
  isSecretVariableName,
  looksLikeSecret,
} from '../analyzers/javascript/visitor';

/**
 * ZCG-JS-004: Hardcoded secrets
 * Detects hardcoded credentials, API keys, tokens, and passwords
 *
 * CWE-798: Use of Hard-coded Credentials
 */
export const hardcodedSecretsRule: Rule = {
  meta: {
    id: 'ZCG-JS-004',
    name: 'hardcoded-secrets',
    description:
      'Detects hardcoded credentials, API keys, tokens, and passwords',
    severity: 'High',
    cwe: 'CWE-798',
    owasp: 'A07:2021-Identification and Authentication Failures',
    languages: ['js', 'ts'],
    tags: ['security', 'secrets', 'credentials', 'api-keys'],
  },
  create: (context) => ({
    VariableDeclarator(path) {
      const { id, init } = path.node;

      // Check if variable name suggests a secret
      if (id.type === 'Identifier' && isSecretVariableName(id.name)) {
        // Check if initialized with a string literal
        if (init?.type === 'StringLiteral' && init.value.length > 0) {
          // Skip obvious placeholders
          const value = init.value.toLowerCase();
          if (
            value.includes('your_') ||
            value.includes('xxx') ||
            value.includes('placeholder') ||
            value.includes('example') ||
            value.includes('changeme') ||
            value === ''
          ) {
            return;
          }

          context.report({
            ruleId: 'ZCG-JS-004',
            message: `Hardcoded secret detected in variable "${id.name}". Store secrets in environment variables or a secure vault.`,
            line: path.node.loc?.start.line ?? 0,
            column: path.node.loc?.start.column ?? 0,
            severity: 'High',
            confidence: 85,
          });
        }
      }

      // Check if value looks like a secret regardless of variable name
      if (
        id.type === 'Identifier' &&
        init?.type === 'StringLiteral' &&
        init.value.length >= 16 &&
        looksLikeSecret(init.value)
      ) {
        context.report({
          ruleId: 'ZCG-JS-004',
          message: `Potential hardcoded secret detected. The value "${init.value.substring(
            0,
            8
          )}..." looks like an API key or token.`,
          line: path.node.loc?.start.line ?? 0,
          column: path.node.loc?.start.column ?? 0,
          severity: 'High',
          confidence: 70,
        });
      }
    },

    AssignmentExpression(path) {
      const { left, right } = path.node;

      // Check assignment to properties like obj.password = "..."
      if (
        left.type === 'MemberExpression' &&
        left.property.type === 'Identifier' &&
        isSecretVariableName(left.property.name) &&
        right.type === 'StringLiteral' &&
        right.value.length > 0
      ) {
        const value = right.value.toLowerCase();
        if (
          !value.includes('your_') &&
          !value.includes('xxx') &&
          !value.includes('placeholder') &&
          !value.includes('example') &&
          !value.includes('changeme')
        ) {
          context.report({
            ruleId: 'ZCG-JS-004',
            message: `Hardcoded secret detected in property "${left.property.name}". Store secrets in environment variables or a secure vault.`,
            line: path.node.loc?.start.line ?? 0,
            column: path.node.loc?.start.column ?? 0,
            severity: 'High',
            confidence: 80,
          });
        }
      }
    },

    ObjectProperty(path) {
      const { key, value } = path.node;

      // Check object properties like { password: "secret123" }
      if (
        key.type === 'Identifier' &&
        isSecretVariableName(key.name) &&
        value.type === 'StringLiteral' &&
        value.value.length > 0
      ) {
        const val = value.value.toLowerCase();
        if (
          !val.includes('your_') &&
          !val.includes('xxx') &&
          !val.includes('placeholder') &&
          !val.includes('example') &&
          !val.includes('changeme')
        ) {
          context.report({
            ruleId: 'ZCG-JS-004',
            message: `Hardcoded secret detected in property "${key.name}". Store secrets in environment variables or a secure vault.`,
            line: path.node.loc?.start.line ?? 0,
            column: path.node.loc?.start.column ?? 0,
            severity: 'High',
            confidence: 80,
          });
        }
      }
    },
  }),
};

export default hardcodedSecretsRule;
