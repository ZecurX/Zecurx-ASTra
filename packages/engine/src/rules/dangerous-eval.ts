import type { Rule } from '../core/types';

/**
 * ZCG-JS-001: Dangerous eval() usage
 * Detects use of eval() which can execute arbitrary code
 *
 * CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
 */
export const dangerousEvalRule: Rule = {
  meta: {
    id: 'ZCG-JS-001',
    name: 'dangerous-eval',
    description:
      'Detects dangerous eval() usage that can execute arbitrary code',
    severity: 'High',
    cwe: 'CWE-95',
    owasp: 'A03:2021-Injection',
    languages: ['js', 'ts'],
    tags: ['security', 'injection', 'code-execution'],
  },
  create: (context) => ({
    CallExpression(path) {
      const callee = path.node.callee;

      // Direct eval() call
      if (callee.type === 'Identifier' && callee.name === 'eval') {
        context.report({
          ruleId: 'ZCG-JS-001',
          message:
            'Dangerous eval() usage detected. eval() can execute arbitrary code and is a common source of code injection vulnerabilities.',
          line: path.node.loc?.start.line ?? 0,
          column: path.node.loc?.start.column ?? 0,
          severity: 'High',
          confidence: 95,
        });
      }

      // window.eval() or global.eval()
      if (
        callee.type === 'MemberExpression' &&
        callee.property.type === 'Identifier' &&
        callee.property.name === 'eval'
      ) {
        context.report({
          ruleId: 'ZCG-JS-001',
          message:
            'Dangerous eval() usage detected via global object. eval() can execute arbitrary code.',
          line: path.node.loc?.start.line ?? 0,
          column: path.node.loc?.start.column ?? 0,
          severity: 'High',
          confidence: 90,
        });
      }
    },
  }),
};

export default dangerousEvalRule;
