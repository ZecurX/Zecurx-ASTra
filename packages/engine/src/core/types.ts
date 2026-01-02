import type { NodePath } from '@babel/traverse';
import type { File, Node } from '@babel/types';

/**
 * Supported languages for analysis
 */
export type Language = 'js' | 'ts';

/**
 * Severity levels for findings
 */
export type Severity = 'Low' | 'Medium' | 'High';

/**
 * Confidence levels for findings
 */
export type Confidence = 'Low' | 'Medium' | 'High';

/**
 * A security finding detected by the engine
 */
export interface Finding {
  /** Unique identifier for this finding instance */
  id: string;
  /** Rule identifier (e.g., ZCG-JS-001) */
  ruleId: string;
  /** Language of the analyzed file */
  language: Language;
  /** Absolute path to the file */
  file: string;
  /** Line number (1-based) */
  line: number;
  /** Column number (1-based) */
  column: number;
  /** Severity of the vulnerability */
  severity: Severity;
  /** Human-readable description */
  message: string;
  /** Confidence score (0-100) */
  confidence: number;
  /** CWE identifier if applicable */
  cwe?: string;
  /** Code snippet around the finding */
  snippet?: string;
  /** End line for multi-line findings */
  endLine?: number;
  /** End column for multi-line findings */
  endColumn?: number;
}

/**
 * Metadata about a security rule
 */
export interface RuleMetadata {
  /** Unique rule identifier */
  id: string;
  /** Short name for the rule */
  name: string;
  /** Detailed description */
  description: string;
  /** Severity of issues detected by this rule */
  severity: Severity;
  /** CWE identifier */
  cwe?: string;
  /** OWASP category */
  owasp?: string;
  /** Languages this rule applies to */
  languages: Language[];
  /** Tags for categorization */
  tags?: string[];
}

/**
 * Context passed to rule visitors during analysis
 */
export interface RuleContext {
  /** The file being analyzed */
  filePath: string;
  /** Language of the file */
  language: Language;
  /** Source code of the file */
  sourceCode: string;
  /** The parsed AST */
  ast: File;
  /** Report a finding */
  report: (finding: Omit<Finding, 'id' | 'file' | 'language'>) => void;
  /** Get source code for a node */
  getSource: (node: Node) => string;
  /** Get the line of code at a specific line number */
  getLine: (lineNumber: number) => string;
}

/**
 * Visitor methods that can be implemented by rules
 */
export type RuleVisitor = {
  [K in keyof import('@babel/traverse').Visitor]?: (
    path: NodePath<any>,
    context: RuleContext
  ) => void;
};

/**
 * A security rule definition
 */
export interface Rule {
  /** Rule metadata */
  meta: RuleMetadata;
  /** Create visitor for this rule */
  create: (context: RuleContext) => RuleVisitor;
}

/**
 * Configuration for the rule engine
 */
export interface EngineConfig {
  /** Rules to enable (by ID or pattern) */
  rules?: string[];
  /** Rules to disable */
  exclude?: string[];
  /** Severity threshold (only report findings >= this severity) */
  severityThreshold?: Severity;
  /** File patterns to include */
  include?: string[];
  /** File patterns to ignore */
  ignore?: string[];
  /** Maximum file size to analyze (bytes) */
  maxFileSize?: number;
}

/**
 * Result of scanning a single file
 */
export interface FileResult {
  /** Path to the file */
  file: string;
  /** Findings in this file */
  findings: Finding[];
  /** Whether parsing succeeded */
  parsed: boolean;
  /** Error message if parsing failed */
  error?: string;
  /** Time taken to analyze (ms) */
  duration: number;
}

/**
 * Result of scanning a directory or project
 */
export interface ScanResult {
  /** All file results */
  files: FileResult[];
  /** Summary statistics */
  summary: {
    totalFiles: number;
    filesWithFindings: number;
    totalFindings: number;
    bySeverity: Record<Severity, number>;
    byRule: Record<string, number>;
  };
  /** Total scan duration (ms) */
  duration: number;
  /** Timestamp of the scan */
  timestamp: string;
}

/**
 * Events emitted by the rule engine during analysis
 */
export type EngineEvent =
  | { type: 'file:start'; file: string }
  | { type: 'file:end'; file: string; result: FileResult }
  | { type: 'finding'; finding: Finding }
  | { type: 'error'; file: string; error: Error }
  | { type: 'scan:start'; files: string[] }
  | { type: 'scan:end'; result: ScanResult };

/**
 * Event handler for engine events
 */
export type EngineEventHandler = (event: EngineEvent) => void;
