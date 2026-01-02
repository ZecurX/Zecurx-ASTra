import fs from 'fs';
import path from 'path';
import type {
  Rule,
  Finding,
  FileResult,
  ScanResult,
  EngineConfig,
  EngineEvent,
  EngineEventHandler,
  Severity,
  Language,
} from './types';
import { createFinding, calculateSummary } from './finding';
import { parseFile } from '../analyzers/javascript/parser';
import { createVisitor } from '../analyzers/javascript/visitor';

/**
 * Default engine configuration
 */
const DEFAULT_CONFIG: Required<EngineConfig> = {
  rules: [],
  exclude: [],
  severityThreshold: 'Low',
  include: ['**/*.js', '**/*.ts', '**/*.jsx', '**/*.tsx'],
  ignore: [
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
    '**/*.min.js',
    '**/*.d.ts',
  ],
  maxFileSize: 1024 * 1024, // 1MB
};

/**
 * File extensions mapped to languages
 */
const EXTENSION_LANGUAGE_MAP: Record<string, Language> = {
  '.js': 'js',
  '.jsx': 'js',
  '.ts': 'ts',
  '.tsx': 'ts',
  '.mjs': 'js',
  '.cjs': 'js',
  '.mts': 'ts',
  '.cts': 'ts',
};

/**
 * The main rule engine that orchestrates scanning
 */
export class RuleEngine {
  private rules: Map<string, Rule> = new Map();
  private config: Required<EngineConfig>;
  private eventHandlers: EngineEventHandler[] = [];

  constructor(config: EngineConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Register a rule with the engine
   */
  registerRule(rule: Rule): void {
    if (this.rules.has(rule.meta.id)) {
      console.warn(
        `Rule ${rule.meta.id} is already registered, overwriting...`
      );
    }
    this.rules.set(rule.meta.id, rule);
  }

  /**
   * Register multiple rules at once
   */
  registerRules(rules: Rule[]): void {
    for (const rule of rules) {
      this.registerRule(rule);
    }
  }

  /**
   * Get all registered rules
   */
  getRules(): Rule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Get a specific rule by ID
   */
  getRule(id: string): Rule | undefined {
    return this.rules.get(id);
  }

  /**
   * Subscribe to engine events
   */
  on(handler: EngineEventHandler): () => void {
    this.eventHandlers.push(handler);
    return () => {
      const index = this.eventHandlers.indexOf(handler);
      if (index !== -1) {
        this.eventHandlers.splice(index, 1);
      }
    };
  }

  /**
   * Emit an event to all handlers
   */
  private emit(event: EngineEvent): void {
    for (const handler of this.eventHandlers) {
      try {
        handler(event);
      } catch (error) {
        console.error('Error in event handler:', error);
      }
    }
  }

  /**
   * Get the language for a file based on its extension
   */
  private getLanguage(filePath: string): Language | null {
    const ext = path.extname(filePath).toLowerCase();
    return EXTENSION_LANGUAGE_MAP[ext] ?? null;
  }

  /**
   * Check if a file should be analyzed
   */
  private shouldAnalyze(filePath: string): boolean {
    const language = this.getLanguage(filePath);
    if (!language) return false;

    // Check ignore patterns
    for (const pattern of this.config.ignore) {
      if (this.matchPattern(filePath, pattern)) {
        return false;
      }
    }

    // Check file size
    try {
      const stats = fs.statSync(filePath);
      if (stats.size > this.config.maxFileSize) {
        return false;
      }
    } catch {
      return false;
    }

    return true;
  }

  /**
   * Simple glob pattern matching
   */
  private matchPattern(filePath: string, pattern: string): boolean {
    // Convert glob pattern to regex
    const regexPattern = pattern
      .replace(/\./g, '\\.')
      .replace(/\*\*/g, '{{GLOBSTAR}}')
      .replace(/\*/g, '[^/]*')
      .replace(/{{GLOBSTAR}}/g, '.*');
    const regex = new RegExp(regexPattern);
    return regex.test(filePath.replace(/\\/g, '/'));
  }

  /**
   * Get active rules for a given language
   */
  private getActiveRules(language: Language): Rule[] {
    return Array.from(this.rules.values()).filter((rule) => {
      // Check if rule applies to this language
      if (!rule.meta.languages.includes(language)) {
        return false;
      }

      // Check if rule is explicitly enabled/disabled
      if (
        this.config.rules.length > 0 &&
        !this.config.rules.includes(rule.meta.id)
      ) {
        return false;
      }
      if (this.config.exclude.includes(rule.meta.id)) {
        return false;
      }

      return true;
    });
  }

  /**
   * Analyze a single file
   */
  async analyzeFile(filePath: string): Promise<FileResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    this.emit({ type: 'file:start', file: filePath });

    const language = this.getLanguage(filePath);
    if (!language) {
      const result: FileResult = {
        file: filePath,
        findings: [],
        parsed: false,
        error: 'Unsupported file type',
        duration: Date.now() - startTime,
      };
      this.emit({ type: 'file:end', file: filePath, result });
      return result;
    }

    // Read source code
    let sourceCode: string;
    try {
      sourceCode = fs.readFileSync(filePath, 'utf-8');
    } catch (error) {
      const result: FileResult = {
        file: filePath,
        findings: [],
        parsed: false,
        error: `Failed to read file: ${
          error instanceof Error ? error.message : 'Unknown error'
        }`,
        duration: Date.now() - startTime,
      };
      this.emit({ type: 'file:end', file: filePath, result });
      return result;
    }

    // Parse the file
    const parseResult = parseFile(sourceCode, filePath, language);
    if (!parseResult.success || !parseResult.ast) {
      const result: FileResult = {
        file: filePath,
        findings: [],
        parsed: false,
        error: parseResult.error,
        duration: Date.now() - startTime,
      };
      this.emit({ type: 'file:end', file: filePath, result });
      return result;
    }

    // Get active rules for this language
    const activeRules = this.getActiveRules(language);

    // Create visitor and run analysis
    const visitor = createVisitor({
      filePath,
      language,
      sourceCode,
      ast: parseResult.ast,
      rules: activeRules,
      onFinding: (partialFinding) => {
        const finding = createFinding({
          ...partialFinding,
          file: filePath,
          language,
        });

        // Check severity threshold
        const severityWeight = { Low: 1, Medium: 2, High: 3 };
        if (
          severityWeight[finding.severity] >=
          severityWeight[this.config.severityThreshold]
        ) {
          findings.push(finding);
          this.emit({ type: 'finding', finding });
        }
      },
    });

    // Run the visitor
    try {
      visitor.traverse(parseResult.ast);
    } catch (error) {
      const result: FileResult = {
        file: filePath,
        findings,
        parsed: true,
        error: `Analysis error: ${
          error instanceof Error ? error.message : 'Unknown error'
        }`,
        duration: Date.now() - startTime,
      };
      this.emit({ type: 'file:end', file: filePath, result });
      return result;
    }

    const result: FileResult = {
      file: filePath,
      findings,
      parsed: true,
      duration: Date.now() - startTime,
    };

    this.emit({ type: 'file:end', file: filePath, result });
    return result;
  }

  /**
   * Recursively collect all files in a directory
   */
  private collectFiles(dir: string): string[] {
    const files: string[] = [];

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          // Skip ignored directories
          if (
            !this.matchPattern(
              fullPath + '/',
              this.config.ignore.find((p) => p.includes('**')) ?? ''
            )
          ) {
            files.push(...this.collectFiles(fullPath));
          }
        } else if (entry.isFile() && this.shouldAnalyze(fullPath)) {
          files.push(fullPath);
        }
      }
    } catch (error) {
      console.error(`Failed to read directory ${dir}:`, error);
    }

    return files;
  }

  /**
   * Scan a directory or file
   */
  async scan(target: string): Promise<ScanResult> {
    const startTime = Date.now();

    // Resolve the target path
    const targetPath = path.resolve(target);

    // Collect files to analyze
    let files: string[];
    const stats = fs.statSync(targetPath);
    if (stats.isDirectory()) {
      files = this.collectFiles(targetPath);
    } else if (stats.isFile()) {
      files = [targetPath];
    } else {
      throw new Error(`Invalid target: ${targetPath}`);
    }

    this.emit({ type: 'scan:start', files });

    // Analyze all files
    const fileResults: FileResult[] = [];
    for (const file of files) {
      const result = await this.analyzeFile(file);
      fileResults.push(result);
    }

    // Collect all findings
    const allFindings = fileResults.flatMap((r) => r.findings);
    const summary = calculateSummary(allFindings);

    const result: ScanResult = {
      files: fileResults,
      summary: {
        totalFiles: files.length,
        filesWithFindings: fileResults.filter((r) => r.findings.length > 0)
          .length,
        totalFindings: summary.total,
        bySeverity: summary.bySeverity,
        byRule: summary.byRule,
      },
      duration: Date.now() - startTime,
      timestamp: new Date().toISOString(),
    };

    this.emit({ type: 'scan:end', result });
    return result;
  }
}

/**
 * Create a new rule engine instance
 */
export function createEngine(config?: EngineConfig): RuleEngine {
  return new RuleEngine(config);
}
