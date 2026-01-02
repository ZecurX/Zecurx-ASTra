import type { Rule } from '../core/types';
import type { Node } from '@babel/types';
import { getMemberExpressionPath } from '../analyzers/javascript/visitor';

/**
 * ZCG-JS-003: Command injection via child_process
 * Detects dangerous usage of exec, execSync, spawn, etc.
 *
 * CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
 */

const DANGEROUS_CHILD_PROCESS_METHODS = new Set([
  'exec',
  'execSync',
  'execFile',
  'execFileSync',
  'spawn',
  'spawnSync',
  'fork',
]);

export const commandInjectionRule: Rule = {
  meta: {
    id: 'ZCG-JS-003',
    name: 'command-injection',
    description:
      'Detects potential command injection via child_process methods',
    severity: 'High',
    cwe: 'CWE-78',
    owasp: 'A03:2021-Injection',
    languages: ['js', 'ts'],
    tags: ['security', 'injection', 'command-injection', 'child_process'],
  },
  create: (context) => ({
    CallExpression(path) {
      const callee = path.node.callee;

      // Direct call: exec(), execSync(), etc.
      if (
        callee.type === 'Identifier' &&
        DANGEROUS_CHILD_PROCESS_METHODS.has(callee.name)
      ) {
        // Check if there are arguments (potential for injection)
        const args = path.node.arguments;
        const hasStringArg = args.some(
          (arg: Node) =>
            arg.type === 'StringLiteral' ||
            arg.type === 'TemplateLiteral' ||
            arg.type === 'BinaryExpression' ||
            arg.type === 'Identifier'
        );

        if (hasStringArg) {
          context.report({
            ruleId: 'ZCG-JS-003',
            message: `Potential command injection via ${callee.name}(). Ensure user input is properly sanitized before executing shell commands.`,
            line: path.node.loc?.start.line ?? 0,
            column: path.node.loc?.start.column ?? 0,
            severity: 'High',
            confidence: 80,
          });
        }
      }

      // Method call: child_process.exec(), require('child_process').exec(), etc.
      if (callee.type === 'MemberExpression') {
        const memberPath = getMemberExpressionPath(callee);
        const methodName = memberPath[memberPath.length - 1];

        if (methodName && DANGEROUS_CHILD_PROCESS_METHODS.has(methodName)) {
          context.report({
            ruleId: 'ZCG-JS-003',
            message: `Potential command injection via ${methodName}(). Ensure user input is properly sanitized before executing shell commands.`,
            line: path.node.loc?.start.line ?? 0,
            column: path.node.loc?.start.column ?? 0,
            severity: 'High',
            confidence: 85,
          });
        }
      }
    },
  }),
};

export default commandInjectionRule;
