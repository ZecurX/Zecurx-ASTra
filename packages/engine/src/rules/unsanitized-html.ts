import type { Rule } from '../core/types';
import { getMemberExpressionPath } from '../analyzers/javascript/visitor';

/**
 * ZCG-JS-006: Unsanitized innerHTML
 * Detects use of innerHTML, outerHTML which can lead to XSS
 *
 * CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
 */

const DANGEROUS_DOM_PROPERTIES = new Set([
  'innerHTML',
  'outerHTML',
  'insertAdjacentHTML',
]);

const DANGEROUS_DOM_METHODS = new Set(['write', 'writeln']);

export const unsanitizedHtmlRule: Rule = {
  meta: {
    id: 'ZCG-JS-006',
    name: 'unsanitized-html',
    description: 'Detects unsanitized innerHTML and other DOM XSS sinks',
    severity: 'Medium',
    cwe: 'CWE-79',
    owasp: 'A03:2021-Injection',
    languages: ['js', 'ts'],
    tags: ['security', 'xss', 'dom', 'html-injection'],
  },
  create: (context) => ({
    AssignmentExpression(path) {
      const { left, right } = path.node;

      // element.innerHTML = ... or element.outerHTML = ...
      if (left.type === 'MemberExpression') {
        const memberPath = getMemberExpressionPath(left);
        const propertyName = memberPath[memberPath.length - 1];

        if (propertyName && DANGEROUS_DOM_PROPERTIES.has(propertyName)) {
          // Check if the right side is a literal (less dangerous) or dynamic
          const isDynamic = right.type !== 'StringLiteral';

          context.report({
            ruleId: 'ZCG-JS-006',
            message: `Potential XSS vulnerability: "${propertyName}" assignment detected. ${
              isDynamic
                ? 'Dynamic content may contain malicious scripts.'
                : 'Consider using textContent or sanitizing HTML.'
            }`,
            line: path.node.loc?.start.line ?? 0,
            column: path.node.loc?.start.column ?? 0,
            severity: isDynamic ? 'Medium' : 'Low',
            confidence: isDynamic ? 85 : 60,
          });
        }
      }
    },

    CallExpression(path) {
      const callee = path.node.callee;

      // element.insertAdjacentHTML('position', html)
      if (callee.type === 'MemberExpression') {
        const memberPath = getMemberExpressionPath(callee);
        const methodName = memberPath[memberPath.length - 1];

        if (methodName === 'insertAdjacentHTML') {
          const htmlArg = path.node.arguments[1];
          const isDynamic = htmlArg && htmlArg.type !== 'StringLiteral';

          context.report({
            ruleId: 'ZCG-JS-006',
            message: `Potential XSS vulnerability: insertAdjacentHTML() detected. ${
              isDynamic
                ? 'Dynamic content may contain malicious scripts.'
                : 'Ensure HTML content is sanitized.'
            }`,
            line: path.node.loc?.start.line ?? 0,
            column: path.node.loc?.start.column ?? 0,
            severity: isDynamic ? 'Medium' : 'Low',
            confidence: isDynamic ? 85 : 60,
          });
        }

        // document.write() or document.writeln()
        if (methodName && DANGEROUS_DOM_METHODS.has(methodName)) {
          if (memberPath.includes('document')) {
            context.report({
              ruleId: 'ZCG-JS-006',
              message: `Potential XSS vulnerability: document.${methodName}() is dangerous and can execute injected scripts. Use safer DOM manipulation methods.`,
              line: path.node.loc?.start.line ?? 0,
              column: path.node.loc?.start.column ?? 0,
              severity: 'Medium',
              confidence: 80,
            });
          }
        }
      }
    },

    JSXAttribute(path) {
      // React: dangerouslySetInnerHTML={{ __html: ... }}
      if (
        path.node.name.type === 'JSXIdentifier' &&
        path.node.name.name === 'dangerouslySetInnerHTML'
      ) {
        context.report({
          ruleId: 'ZCG-JS-006',
          message:
            'Potential XSS vulnerability: dangerouslySetInnerHTML usage detected. Ensure HTML content is properly sanitized.',
          line: path.node.loc?.start.line ?? 0,
          column: path.node.loc?.start.column ?? 0,
          severity: 'Medium',
          confidence: 85,
        });
      }
    },
  }),
};

export default unsanitizedHtmlRule;
