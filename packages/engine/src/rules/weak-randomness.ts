import type { Rule } from '../core/types';
import { getMemberExpressionPath } from '../analyzers/javascript/visitor';

/**
 * ZCG-JS-009: Weak Randomness
 * Detects use of Math.random() for security-sensitive operations
 *
 * CWE-330: Use of Insufficiently Random Values
 */
export const weakRandomnessRule: Rule = {
  meta: {
    id: 'ZCG-JS-009',
    name: 'weak-randomness',
    description:
      'Detects use of Math.random() which is not cryptographically secure',
    severity: 'Medium',
    cwe: 'CWE-330',
    owasp: 'A02:2021-Cryptographic Failures',
    languages: ['js', 'ts'],
    tags: ['security', 'crypto', 'randomness'],
  },
  create: (context) => ({
    CallExpression(path) {
      const callee = path.node.callee;

      // Math.random()
      if (callee.type === 'MemberExpression') {
        const memberPath = getMemberExpressionPath(callee);

        if (
          memberPath.length === 2 &&
          memberPath[0] === 'Math' &&
          memberPath[1] === 'random'
        ) {
          // Try to determine context - check parent nodes for hints
          let isSensitiveContext = false;
          let contextHint = '';

          // Walk up the tree to find context clues
          let current = path.parentPath;
          for (let i = 0; i < 5 && current; i++) {
            const node = current.node;

            // Check if assigned to a security-related variable
            if (
              node.type === 'VariableDeclarator' &&
              node.id.type === 'Identifier'
            ) {
              const name = node.id.name.toLowerCase();
              if (
                name.includes('token') ||
                name.includes('secret') ||
                name.includes('key') ||
                name.includes('password') ||
                name.includes('session') ||
                name.includes('csrf') ||
                name.includes('nonce') ||
                name.includes('salt') ||
                name.includes('id')
              ) {
                isSensitiveContext = true;
                contextHint = ` (assigned to "${node.id.name}")`;
                break;
              }
            }

            // Check if used in a function with security-related name
            if (
              node.type === 'FunctionDeclaration' &&
              node.id?.type === 'Identifier'
            ) {
              const name = node.id.name.toLowerCase();
              if (
                name.includes('generate') ||
                name.includes('create') ||
                name.includes('token') ||
                name.includes('random')
              ) {
                isSensitiveContext = true;
                contextHint = ` (in function "${node.id.name}")`;
                break;
              }
            }

            current = current.parentPath;
          }

          context.report({
            ruleId: 'ZCG-JS-009',
            message: `Weak randomness: Math.random() is not cryptographically secure${contextHint}. Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive operations.`,
            line: path.node.loc?.start.line ?? 0,
            column: path.node.loc?.start.column ?? 0,
            severity: isSensitiveContext ? 'High' : 'Medium',
            confidence: isSensitiveContext ? 90 : 70,
          });
        }
      }
    },

    NewExpression(path) {
      const callee = path.node.callee;

      // new Date().getTime() is sometimes used for randomness
      // This is a secondary check, lower confidence
    },
  }),
};

export default weakRandomnessRule;
