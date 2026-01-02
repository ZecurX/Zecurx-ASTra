import type { Rule } from '../core/types';
import type { Node } from '@babel/types';
import { getMemberExpressionPath } from '../analyzers/javascript/visitor';

/**
 * ZCG-JS-008: Path Traversal
 * Detects potential path traversal vulnerabilities
 *
 * CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
 */

const PATH_METHODS = new Set(['join', 'resolve', 'normalize']);

const FS_READ_METHODS = new Set([
  'readFile',
  'readFileSync',
  'readdir',
  'readdirSync',
  'stat',
  'statSync',
  'lstat',
  'lstatSync',
  'access',
  'accessSync',
  'open',
  'openSync',
  'createReadStream',
]);

const FS_WRITE_METHODS = new Set([
  'writeFile',
  'writeFileSync',
  'appendFile',
  'appendFileSync',
  'mkdir',
  'mkdirSync',
  'unlink',
  'unlinkSync',
  'rmdir',
  'rmdirSync',
  'rm',
  'rmSync',
  'createWriteStream',
]);

export const pathTraversalRule: Rule = {
  meta: {
    id: 'ZCG-JS-008',
    name: 'path-traversal',
    description: 'Detects potential path traversal vulnerabilities',
    severity: 'High',
    cwe: 'CWE-22',
    owasp: 'A01:2021-Broken Access Control',
    languages: ['js', 'ts'],
    tags: ['security', 'path-traversal', 'file-access', 'lfi'],
  },
  create: (context) => ({
    CallExpression(path) {
      const callee = path.node.callee;
      const args = path.node.arguments;

      if (callee.type === 'MemberExpression') {
        const memberPath = getMemberExpressionPath(callee);
        const objectName = memberPath[0];
        const methodName = memberPath[memberPath.length - 1];

        // path.join() or path.resolve() with user input (must be 'path' module)
        if (
          objectName === 'path' &&
          methodName &&
          PATH_METHODS.has(methodName)
        ) {
          // Check if any argument is not a string literal (potential user input)
          const hasDynamicArg = args.some(
            (arg: Node) => arg.type !== 'StringLiteral'
          );

          if (hasDynamicArg) {
            context.report({
              ruleId: 'ZCG-JS-008',
              message: `Potential path traversal: ${methodName}() with dynamic input. Validate and sanitize user-provided paths to prevent directory traversal attacks.`,
              line: path.node.loc?.start.line ?? 0,
              column: path.node.loc?.start.column ?? 0,
              severity: 'Medium',
              confidence: 60,
            });
          }
        }

        // fs.readFile(), fs.writeFile(), etc.
        if (
          methodName &&
          (FS_READ_METHODS.has(methodName) || FS_WRITE_METHODS.has(methodName))
        ) {
          const firstArg = args[0];

          // Check if path argument is dynamic
          if (firstArg && firstArg.type !== 'StringLiteral') {
            const isWrite = FS_WRITE_METHODS.has(methodName);

            context.report({
              ruleId: 'ZCG-JS-008',
              message: `Potential path traversal: ${methodName}() with dynamic path. ${
                isWrite
                  ? 'Arbitrary file write is critical.'
                  : 'Validate paths to prevent unauthorized file access.'
              }`,
              line: path.node.loc?.start.line ?? 0,
              column: path.node.loc?.start.column ?? 0,
              severity: isWrite ? 'High' : 'Medium',
              confidence: 70,
            });
          }
        }
      }

      // Express sendFile, download, etc.
      if (callee.type === 'MemberExpression') {
        const memberPath = getMemberExpressionPath(callee);
        const methodName = memberPath[memberPath.length - 1];

        if (methodName === 'sendFile' || methodName === 'download') {
          const firstArg = args[0];

          if (firstArg && firstArg.type !== 'StringLiteral') {
            context.report({
              ruleId: 'ZCG-JS-008',
              message: `Potential path traversal: res.${methodName}() with dynamic path. Use path.resolve() with a base directory and validate the resolved path.`,
              line: path.node.loc?.start.line ?? 0,
              column: path.node.loc?.start.column ?? 0,
              severity: 'High',
              confidence: 80,
            });
          }
        }
      }
    },
  }),
};

export default pathTraversalRule;
