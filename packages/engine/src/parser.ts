import fs from 'fs';
import path from 'path';
import { parse } from '@babel/parser';
import traverse from '@babel/traverse';
import { File } from '@babel/types';

type Finding = {
  ruleId: string;
  message: string;
  file: string;
  line: number;
  severity: 'Low' | 'Medium' | 'High';
};

const DANGEROUS_FUNCTIONS = new Set(['eval', 'Function', 'exec', 'execSync']);

export function scanFile(filePath: string): Finding[] {
  const code = fs.readFileSync(filePath, 'utf-8');
  const findings: Finding[] = [];

  let ast: File;

  try {
    ast = parse(code, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx'],
    });
  } catch (err) {
    console.error(`❌ Failed to parse ${filePath}`);
    return [];
  }

  traverse(ast, {
    CallExpression(path) {
      const callee = path.node.callee;

      if (callee.type === 'Identifier') {
        const fnName = callee.name;

        if (DANGEROUS_FUNCTIONS.has(fnName)) {
          findings.push({
            ruleId: 'ZCG-JS-001',
            message: `Dangerous function call detected: ${fnName}()`,
            file: filePath,
            line: path.node.loc?.start.line ?? 0,
            severity: 'High',
          });
        }
      }
    },

    NewExpression(path) {
      if (
        path.node.callee.type === 'Identifier' &&
        path.node.callee.name === 'Function'
      ) {
        findings.push({
          ruleId: 'ZCG-JS-002',
          message: 'Dynamic Function constructor detected',
          file: filePath,
          line: path.node.loc?.start.line ?? 0,
          severity: 'High',
        });
      }
    },
  });

  return findings;
}

export function scanDirectory(dir: string): Finding[] {
  const results: Finding[] = [];

  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      results.push(...scanDirectory(fullPath));
    }

    if (
      entry.isFile() &&
      (entry.name.endsWith('.js') || entry.name.endsWith('.ts'))
    ) {
      results.push(...scanFile(fullPath));
    }
  }

  return results;
}
