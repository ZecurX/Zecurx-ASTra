/**
 * Zecurx CodeGuard Engine
 *
 * Static Application Security Testing (SAST) engine for JavaScript/TypeScript
 */

// Core types
export type {
  Finding,
  Rule,
  RuleMetadata,
  RuleContext,
  RuleVisitor,
  EngineConfig,
  FileResult,
  ScanResult,
  EngineEvent,
  EngineEventHandler,
  Language,
  Severity,
  Confidence,
} from './core/types';

// Core modules
export { RuleEngine, createEngine } from './core/rule-engine';
export {
  createFinding,
  createFindingId,
  compareBySeverity,
  compareByLocation,
  groupByFile,
  groupByRule,
  groupBySeverity,
  filterBySeverity,
  filterByConfidence,
  deduplicateFindings,
  calculateSummary,
  formatFinding,
  toSARIF,
} from './core/finding';

// JavaScript analyzer
export {
  parseFile,
  getSourceLines,
  getSnippetWithContext,
} from './analyzers/javascript/parser';
export { createVisitor } from './analyzers/javascript/visitor';

// Rules
export {
  allRules,
  getRuleById,
  getRulesBySeverity,
  getRulesByTag,
  getRulesByCwe,
} from './rules';

// Convenience function to create a fully configured engine
import { createEngine } from './core/rule-engine';
import { allRules } from './rules';
import type { EngineConfig, ScanResult } from './core/types';

/**
 * Create a pre-configured engine with all built-in rules
 */
export function createDefaultEngine(config?: EngineConfig) {
  const engine = createEngine(config);
  engine.registerRules(allRules);
  return engine;
}

/**
 * Quick scan function for simple usage
 */
export async function scan(
  target: string,
  config?: EngineConfig
): Promise<ScanResult> {
  const engine = createDefaultEngine(config);
  return engine.scan(target);
}
