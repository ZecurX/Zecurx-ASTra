import type { Rule } from '../core/types';
import type { TemplateElement } from '@babel/types';
import { getMemberExpressionPath } from '../analyzers/javascript/visitor';

/**
 * ZCG-JS-007: SQL Injection
 * Detects potential SQL injection vulnerabilities
 *
 * CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
 */

const SQL_KEYWORDS =
  /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|UNION|WHERE|FROM|INTO|VALUES|SET)\b/i;

const SQL_METHODS = new Set([
  'query',
  'execute',
  'exec',
  'raw',
  'rawQuery',
  'run',
]);

export const sqlInjectionRule: Rule = {
  meta: {
    id: 'ZCG-JS-007',
    name: 'sql-injection',
    description: 'Detects potential SQL injection vulnerabilities',
    severity: 'High',
    cwe: 'CWE-89',
    owasp: 'A03:2021-Injection',
    languages: ['js', 'ts'],
    tags: ['security', 'injection', 'sql', 'database'],
  },
  create: (context) => ({
    CallExpression(path) {
      const callee = path.node.callee;
      const args = path.node.arguments;

      // db.query(), connection.execute(), etc.
      if (callee.type === 'MemberExpression') {
        const memberPath = getMemberExpressionPath(callee);
        const methodName = memberPath[memberPath.length - 1];

        if (methodName && SQL_METHODS.has(methodName)) {
          const firstArg = args[0];

          // Template literal with expressions: `SELECT * FROM users WHERE id = ${userId}`
          if (
            firstArg?.type === 'TemplateLiteral' &&
            firstArg.expressions.length > 0
          ) {
            // Check if it looks like SQL
            const quasis = firstArg.quasis
              .map((q: TemplateElement) => q.value.raw)
              .join('');
            if (SQL_KEYWORDS.test(quasis)) {
              context.report({
                ruleId: 'ZCG-JS-007',
                message:
                  'Potential SQL injection: Template literal with interpolated values in SQL query. Use parameterized queries instead.',
                line: path.node.loc?.start.line ?? 0,
                column: path.node.loc?.start.column ?? 0,
                severity: 'High',
                confidence: 90,
              });
            }
          }

          // String concatenation: "SELECT * FROM users WHERE id = " + userId
          if (
            firstArg?.type === 'BinaryExpression' &&
            firstArg.operator === '+'
          ) {
            const checkForSql = (node: any): boolean => {
              if (node.type === 'StringLiteral') {
                return SQL_KEYWORDS.test(node.value);
              }
              if (node.type === 'BinaryExpression') {
                return checkForSql(node.left) || checkForSql(node.right);
              }
              return false;
            };

            if (checkForSql(firstArg)) {
              context.report({
                ruleId: 'ZCG-JS-007',
                message:
                  'Potential SQL injection: String concatenation in SQL query. Use parameterized queries instead.',
                line: path.node.loc?.start.line ?? 0,
                column: path.node.loc?.start.column ?? 0,
                severity: 'High',
                confidence: 85,
              });
            }
          }
        }
      }
    },

    TaggedTemplateExpression(path) {
      const tag = path.node.tag;

      // sql`...` or SQL`...` tagged templates (usually safe, but check for dynamic parts)
      if (
        tag.type === 'Identifier' &&
        (tag.name === 'sql' || tag.name === 'SQL')
      ) {
        const template = path.node.quasi;

        // If there are expressions in the template, they might be unsafe
        if (template.expressions.length > 0) {
          // Most sql tagged templates handle parameterization, but warn for awareness
          context.report({
            ruleId: 'ZCG-JS-007',
            message:
              'SQL tagged template with dynamic values. Verify that your SQL library properly parameterizes these values.',
            line: path.node.loc?.start.line ?? 0,
            column: path.node.loc?.start.column ?? 0,
            severity: 'Low',
            confidence: 50,
          });
        }
      }
    },
  }),
};

export default sqlInjectionRule;
