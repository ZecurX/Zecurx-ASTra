import { parse } from '@babel/parser';
import type { File } from '@babel/types';
import type { Language } from '../../core/types';

/**
 * Result of parsing a file
 */
export interface ParseResult {
  success: boolean;
  ast?: File;
  error?: string;
}

/**
 * Parser options based on language
 */
function getParserPlugins(
  language: Language,
  filePath: string
): import('@babel/parser').ParserPlugin[] {
  const plugins: import('@babel/parser').ParserPlugin[] = ['jsx'];

  // Add TypeScript plugin for TS files
  if (
    language === 'ts' ||
    filePath.endsWith('.ts') ||
    filePath.endsWith('.tsx')
  ) {
    plugins.push('typescript');
  }

  // Common plugins for modern JavaScript
  plugins.push(
    'decorators-legacy',
    'classProperties',
    'classPrivateProperties',
    'classPrivateMethods',
    'exportDefaultFrom',
    'exportNamespaceFrom',
    'dynamicImport',
    'nullishCoalescingOperator',
    'optionalChaining',
    'optionalCatchBinding',
    'objectRestSpread',
    'numericSeparator',
    'bigInt',
    'topLevelAwait'
  );

  return plugins;
}

/**
 * Parse a JavaScript/TypeScript file into an AST
 */
export function parseFile(
  sourceCode: string,
  filePath: string,
  language: Language
): ParseResult {
  try {
    const ast = parse(sourceCode, {
      sourceType: 'unambiguous',
      plugins: getParserPlugins(language, filePath),
      errorRecovery: true, // Continue parsing even with errors
      allowImportExportEverywhere: true,
      allowAwaitOutsideFunction: true,
      allowReturnOutsideFunction: true,
      allowSuperOutsideMethod: true,
      allowUndeclaredExports: true,
    });

    return {
      success: true,
      ast,
    };
  } catch (error) {
    const message =
      error instanceof Error ? error.message : 'Unknown parse error';
    return {
      success: false,
      error: `Failed to parse ${filePath}: ${message}`,
    };
  }
}

/**
 * Get the source code for a specific line range
 */
export function getSourceLines(
  sourceCode: string,
  startLine: number,
  endLine: number = startLine
): string {
  const lines = sourceCode.split('\n');
  const start = Math.max(0, startLine - 1);
  const end = Math.min(lines.length, endLine);
  return lines.slice(start, end).join('\n');
}

/**
 * Get a code snippet with context around a specific line
 */
export function getSnippetWithContext(
  sourceCode: string,
  line: number,
  contextLines: number = 2
): string {
  const lines = sourceCode.split('\n');
  const start = Math.max(0, line - 1 - contextLines);
  const end = Math.min(lines.length, line + contextLines);

  return lines
    .slice(start, end)
    .map((content, index) => {
      const lineNum = start + index + 1;
      const marker = lineNum === line ? '>' : ' ';
      return `${marker} ${lineNum.toString().padStart(4)} | ${content}`;
    })
    .join('\n');
}
