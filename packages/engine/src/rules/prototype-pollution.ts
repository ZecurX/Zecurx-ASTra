import type { Rule } from '../core/types';
import { getMemberExpressionPath } from '../analyzers/javascript/visitor';

/**
 * ZCG-JS-010: Prototype Pollution
 * Detects potential prototype pollution vulnerabilities
 *
 * CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')
 */
export const prototypePollutionRule: Rule = {
  meta: {
    id: 'ZCG-JS-010',
    name: 'prototype-pollution',
    description: 'Detects potential prototype pollution vulnerabilities',
    severity: 'High',
    cwe: 'CWE-1321',
    owasp: 'A03:2021-Injection',
    languages: ['js', 'ts'],
    tags: ['security', 'prototype-pollution', 'object-injection'],
  },
  create: (context) => ({
    AssignmentExpression(path) {
      const { left } = path.node;

      // obj.__proto__ = ... or obj.prototype = ...
      if (left.type === 'MemberExpression') {
        const memberPath = getMemberExpressionPath(left);
        const propertyName = memberPath[memberPath.length - 1];

        if (propertyName === '__proto__' || propertyName === 'prototype') {
          context.report({
            ruleId: 'ZCG-JS-010',
            message: `Potential prototype pollution: Direct ${propertyName} modification detected. This can lead to security vulnerabilities.`,
            line: path.node.loc?.start.line ?? 0,
            column: path.node.loc?.start.column ?? 0,
            severity: 'High',
            confidence: 90,
          });
        }

        // obj.constructor.prototype = ...
        if (
          memberPath.includes('constructor') &&
          memberPath.includes('prototype')
        ) {
          context.report({
            ruleId: 'ZCG-JS-010',
            message:
              'Potential prototype pollution: Modification via constructor.prototype detected.',
            line: path.node.loc?.start.line ?? 0,
            column: path.node.loc?.start.column ?? 0,
            severity: 'High',
            confidence: 90,
          });
        }
      }

      // obj[key] = value where key could be __proto__, constructor, etc.
      if (
        left.type === 'MemberExpression' &&
        left.computed &&
        left.property.type !== 'StringLiteral' &&
        left.property.type !== 'NumericLiteral'
      ) {
        // This is a computed property access with a dynamic key
        context.report({
          ruleId: 'ZCG-JS-010',
          message:
            'Potential prototype pollution: Dynamic property assignment. Validate that the key is not "__proto__", "constructor", or "prototype".',
          line: path.node.loc?.start.line ?? 0,
          column: path.node.loc?.start.column ?? 0,
          severity: 'Medium',
          confidence: 60,
        });
      }
    },

    CallExpression(path) {
      const callee = path.node.callee;
      const args = path.node.arguments;

      // Object.assign() with spread or user input
      if (callee.type === 'MemberExpression') {
        const memberPath = getMemberExpressionPath(callee);

        // Object.assign({}, userInput)
        if (
          memberPath.length === 2 &&
          memberPath[0] === 'Object' &&
          memberPath[1] === 'assign'
        ) {
          // Check if first argument is an object literal and second is a variable
          if (args.length >= 2) {
            const target = args[0];
            const source = args[1];

            if (
              (target.type === 'ObjectExpression' ||
                target.type === 'Identifier') &&
              source.type === 'Identifier'
            ) {
              context.report({
                ruleId: 'ZCG-JS-010',
                message:
                  'Potential prototype pollution: Object.assign() with potentially untrusted source. Consider using a safe merge function or validating input keys.',
                line: path.node.loc?.start.line ?? 0,
                column: path.node.loc?.start.column ?? 0,
                severity: 'Medium',
                confidence: 50,
              });
            }
          }
        }

        // Object.defineProperty with dynamic property name
        if (
          memberPath.length === 2 &&
          memberPath[0] === 'Object' &&
          (memberPath[1] === 'defineProperty' ||
            memberPath[1] === 'defineProperties')
        ) {
          const propArg = args[1];
          if (propArg && propArg.type !== 'StringLiteral') {
            context.report({
              ruleId: 'ZCG-JS-010',
              message: `Potential prototype pollution: Object.${memberPath[1]}() with dynamic property name. Validate that the property name is safe.`,
              line: path.node.loc?.start.line ?? 0,
              column: path.node.loc?.start.column ?? 0,
              severity: 'Medium',
              confidence: 60,
            });
          }
        }
      }

      // _.merge, lodash.merge, etc. (known vulnerable functions in older versions)
      if (callee.type === 'Identifier') {
        const fnName = callee.name.toLowerCase();
        if (
          fnName === 'merge' ||
          fnName === 'extend' ||
          fnName === 'deepmerge'
        ) {
          context.report({
            ruleId: 'ZCG-JS-010',
            message: `Potential prototype pollution: ${callee.name}() function detected. Ensure you're using a version that protects against prototype pollution or validate input keys.`,
            line: path.node.loc?.start.line ?? 0,
            column: path.node.loc?.start.column ?? 0,
            severity: 'Medium',
            confidence: 50,
          });
        }
      }

      // _.merge(), lodash.merge()
      if (callee.type === 'MemberExpression') {
        const memberPath = getMemberExpressionPath(callee);
        const methodName = memberPath[memberPath.length - 1];

        if (
          methodName === 'merge' ||
          methodName === 'extend' ||
          methodName === 'defaultsDeep'
        ) {
          context.report({
            ruleId: 'ZCG-JS-010',
            message: `Potential prototype pollution: ${methodName}() method detected. Ensure you're using a safe version and validate input.`,
            line: path.node.loc?.start.line ?? 0,
            column: path.node.loc?.start.column ?? 0,
            severity: 'Medium',
            confidence: 50,
          });
        }
      }
    },
  }),
};

export default prototypePollutionRule;
