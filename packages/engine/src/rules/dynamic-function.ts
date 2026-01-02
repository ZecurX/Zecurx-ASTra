import type { Rule } from '../core/types';

/**
 * ZCG-JS-002: Dynamic Function constructor
 * Detects use of new Function() which can execute arbitrary code
 *
 * CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
 */
export const dynamicFunctionRule: Rule = {
  meta: {
    id: 'ZCG-JS-002',
    name: 'dynamic-function-constructor',
    description:
      'Detects dynamic Function constructor usage that can execute arbitrary code',
    severity: 'High',
    cwe: 'CWE-95',
    owasp: 'A03:2021-Injection',
    languages: ['js', 'ts'],
    tags: ['security', 'injection', 'code-execution'],
  },
  create: (context) => ({
    NewExpression(path) {
      const callee = path.node.callee;

      // new Function()
      if (callee.type === 'Identifier' && callee.name === 'Function') {
        context.report({
          ruleId: 'ZCG-JS-002',
          message:
            'Dynamic Function constructor detected. new Function() is similar to eval() and can execute arbitrary code.',
          line: path.node.loc?.start.line ?? 0,
          column: path.node.loc?.start.column ?? 0,
          severity: 'High',
          confidence: 95,
        });
      }
    },
    CallExpression(path) {
      const callee = path.node.callee;

      // Function() called without new (still creates a function)
      if (callee.type === 'Identifier' && callee.name === 'Function') {
        context.report({
          ruleId: 'ZCG-JS-002',
          message:
            'Dynamic Function constructor detected. Function() call can execute arbitrary code.',
          line: path.node.loc?.start.line ?? 0,
          column: path.node.loc?.start.column ?? 0,
          severity: 'High',
          confidence: 95,
        });
      }
    },
  }),
};

export default dynamicFunctionRule;
