import type { Rule } from '../core/types';
import { getMemberExpressionPath } from '../analyzers/javascript/visitor';

/**
 * ZCG-JS-005: Insecure cryptographic algorithms
 * Detects use of weak/broken crypto algorithms (MD5, SHA1)
 *
 * CWE-328: Use of Weak Hash
 */

const WEAK_ALGORITHMS = new Set([
  'md5',
  'md4',
  'md2',
  'sha1',
  'sha-1',
  'ripemd',
  'ripemd160',
]);

export const insecureCryptoRule: Rule = {
  meta: {
    id: 'ZCG-JS-005',
    name: 'insecure-crypto',
    description:
      'Detects use of weak/broken cryptographic algorithms like MD5 and SHA1',
    severity: 'Medium',
    cwe: 'CWE-328',
    owasp: 'A02:2021-Cryptographic Failures',
    languages: ['js', 'ts'],
    tags: ['security', 'crypto', 'weak-hash'],
  },
  create: (context) => ({
    CallExpression(path) {
      const callee = path.node.callee;
      const args = path.node.arguments;

      // crypto.createHash('md5') or crypto.createHash('sha1')
      if (callee.type === 'MemberExpression') {
        const memberPath = getMemberExpressionPath(callee);
        const methodName = memberPath[memberPath.length - 1];

        if (methodName === 'createHash' || methodName === 'createHmac') {
          // Check first argument for weak algorithm
          const firstArg = args[0];
          if (firstArg?.type === 'StringLiteral') {
            const algorithm = firstArg.value.toLowerCase();
            if (WEAK_ALGORITHMS.has(algorithm)) {
              context.report({
                ruleId: 'ZCG-JS-005',
                message: `Insecure cryptographic algorithm "${firstArg.value}" detected. Use SHA-256 or stronger algorithms.`,
                line: path.node.loc?.start.line ?? 0,
                column: path.node.loc?.start.column ?? 0,
                severity: 'Medium',
                confidence: 95,
              });
            }
          }
        }

        // crypto.createCipheriv with weak algorithms (DES, RC4, etc.)
        if (
          methodName === 'createCipheriv' ||
          methodName === 'createDecipheriv'
        ) {
          const firstArg = args[0];
          if (firstArg?.type === 'StringLiteral') {
            const algorithm = firstArg.value.toLowerCase();
            if (
              algorithm.includes('des') ||
              algorithm.includes('rc4') ||
              algorithm.includes('rc2') ||
              algorithm.includes('blowfish') ||
              algorithm === 'aes-128-ecb' ||
              algorithm === 'aes-192-ecb' ||
              algorithm === 'aes-256-ecb'
            ) {
              context.report({
                ruleId: 'ZCG-JS-005',
                message: `Insecure cipher "${firstArg.value}" detected. Use AES-256-GCM or AES-256-CBC with proper IV.`,
                line: path.node.loc?.start.line ?? 0,
                column: path.node.loc?.start.column ?? 0,
                severity: 'Medium',
                confidence: 90,
              });
            }
          }
        }
      }

      // Direct function calls like md5(), sha1() from libraries
      if (callee.type === 'Identifier') {
        const fnName = callee.name.toLowerCase();
        if (WEAK_ALGORITHMS.has(fnName)) {
          context.report({
            ruleId: 'ZCG-JS-005',
            message: `Insecure cryptographic function "${callee.name}()" detected. Use SHA-256 or stronger algorithms.`,
            line: path.node.loc?.start.line ?? 0,
            column: path.node.loc?.start.column ?? 0,
            severity: 'Medium',
            confidence: 85,
          });
        }
      }
    },
  }),
};

export default insecureCryptoRule;
