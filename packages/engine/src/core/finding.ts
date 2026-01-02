import { randomUUID } from 'crypto';
import type { Finding, Severity, Language } from './types';

/**
 * Creates a unique finding ID
 */
export function createFindingId(): string {
  return randomUUID();
}

/**
 * Creates a Finding object with all required fields
 */
export function createFinding(params: {
  ruleId: string;
  language: Language;
  file: string;
  line: number;
  column?: number;
  severity: Severity;
  message: string;
  confidence?: number;
  cwe?: string;
  snippet?: string;
  endLine?: number;
  endColumn?: number;
}): Finding {
  return {
    id: createFindingId(),
    ruleId: params.ruleId,
    language: params.language,
    file: params.file,
    line: params.line,
    column: params.column ?? 1,
    severity: params.severity,
    message: params.message,
    confidence: params.confidence ?? 80,
    cwe: params.cwe,
    snippet: params.snippet,
    endLine: params.endLine,
    endColumn: params.endColumn,
  };
}

/**
 * Severity weight for sorting/filtering
 */
const SEVERITY_WEIGHT: Record<Severity, number> = {
  Low: 1,
  Medium: 2,
  High: 3,
};

/**
 * Compare two findings by severity (higher severity first)
 */
export function compareBySeverity(a: Finding, b: Finding): number {
  return SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity];
}

/**
 * Compare two findings by file and line
 */
export function compareByLocation(a: Finding, b: Finding): number {
  const fileCompare = a.file.localeCompare(b.file);
  if (fileCompare !== 0) return fileCompare;
  return a.line - b.line;
}

/**
 * Group findings by file
 */
export function groupByFile(findings: Finding[]): Map<string, Finding[]> {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const existing = groups.get(finding.file) ?? [];
    existing.push(finding);
    groups.set(finding.file, existing);
  }
  return groups;
}

/**
 * Group findings by rule ID
 */
export function groupByRule(findings: Finding[]): Map<string, Finding[]> {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const existing = groups.get(finding.ruleId) ?? [];
    existing.push(finding);
    groups.set(finding.ruleId, existing);
  }
  return groups;
}

/**
 * Group findings by severity
 */
export function groupBySeverity(findings: Finding[]): Map<Severity, Finding[]> {
  const groups = new Map<Severity, Finding[]>();
  for (const finding of findings) {
    const existing = groups.get(finding.severity) ?? [];
    existing.push(finding);
    groups.set(finding.severity, existing);
  }
  return groups;
}

/**
 * Filter findings by minimum severity
 */
export function filterBySeverity(
  findings: Finding[],
  minSeverity: Severity
): Finding[] {
  const minWeight = SEVERITY_WEIGHT[minSeverity];
  return findings.filter((f) => SEVERITY_WEIGHT[f.severity] >= minWeight);
}

/**
 * Filter findings by minimum confidence
 */
export function filterByConfidence(
  findings: Finding[],
  minConfidence: number
): Finding[] {
  return findings.filter((f) => f.confidence >= minConfidence);
}

/**
 * Deduplicate findings (same rule, file, line)
 */
export function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];

  for (const finding of findings) {
    const key = `${finding.ruleId}:${finding.file}:${finding.line}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(finding);
    }
  }

  return result;
}

/**
 * Calculate summary statistics for findings
 */
export function calculateSummary(findings: Finding[]): {
  total: number;
  bySeverity: Record<Severity, number>;
  byRule: Record<string, number>;
} {
  const bySeverity: Record<Severity, number> = {
    Low: 0,
    Medium: 0,
    High: 0,
  };

  const byRule: Record<string, number> = {};

  for (const finding of findings) {
    bySeverity[finding.severity]++;
    byRule[finding.ruleId] = (byRule[finding.ruleId] ?? 0) + 1;
  }

  return {
    total: findings.length,
    bySeverity,
    byRule,
  };
}

/**
 * Format a finding as a human-readable string
 */
export function formatFinding(finding: Finding): string {
  const severity = finding.severity.toUpperCase().padEnd(6);
  const location = `${finding.file}:${finding.line}:${finding.column}`;
  const cwe = finding.cwe ? ` [${finding.cwe}]` : '';
  return `[${severity}] ${finding.ruleId}${cwe}: ${finding.message}\n  at ${location}`;
}

/**
 * Convert findings to SARIF format (Static Analysis Results Interchange Format)
 */
export function toSARIF(
  findings: Finding[],
  toolName = 'Zecurx CodeGuard',
  version = '1.0.0'
) {
  return {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: toolName,
            version,
            informationUri: 'https://zecurx.com',
            rules: [], // Would be populated from rule metadata
          },
        },
        results: findings.map((finding) => ({
          ruleId: finding.ruleId,
          level:
            finding.severity === 'High'
              ? 'error'
              : finding.severity === 'Medium'
              ? 'warning'
              : 'note',
          message: {
            text: finding.message,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: finding.file,
                },
                region: {
                  startLine: finding.line,
                  startColumn: finding.column,
                  endLine: finding.endLine ?? finding.line,
                  endColumn: finding.endColumn ?? finding.column,
                },
              },
            },
          ],
          properties: {
            confidence: finding.confidence,
            cwe: finding.cwe,
          },
        })),
      },
    ],
  };
}
