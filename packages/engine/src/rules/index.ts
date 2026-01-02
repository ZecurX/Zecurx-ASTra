/**
 * Zecurx CodeGuard - Security Rules
 *
 * All rules exported from this module
 */

export { dangerousEvalRule } from './dangerous-eval';
export { dynamicFunctionRule } from './dynamic-function';
export { commandInjectionRule } from './command-injection';
export { hardcodedSecretsRule } from './hardcoded-secrets';
export { insecureCryptoRule } from './insecure-crypto';
export { unsanitizedHtmlRule } from './unsanitized-html';
export { sqlInjectionRule } from './sql-injection';
export { pathTraversalRule } from './path-traversal';
export { weakRandomnessRule } from './weak-randomness';
export { prototypePollutionRule } from './prototype-pollution';

import { dangerousEvalRule } from './dangerous-eval';
import { dynamicFunctionRule } from './dynamic-function';
import { commandInjectionRule } from './command-injection';
import { hardcodedSecretsRule } from './hardcoded-secrets';
import { insecureCryptoRule } from './insecure-crypto';
import { unsanitizedHtmlRule } from './unsanitized-html';
import { sqlInjectionRule } from './sql-injection';
import { pathTraversalRule } from './path-traversal';
import { weakRandomnessRule } from './weak-randomness';
import { prototypePollutionRule } from './prototype-pollution';
import type { Rule } from '../core/types';

/**
 * All built-in rules
 */
export const allRules: Rule[] = [
  dangerousEvalRule,
  dynamicFunctionRule,
  commandInjectionRule,
  hardcodedSecretsRule,
  insecureCryptoRule,
  unsanitizedHtmlRule,
  sqlInjectionRule,
  pathTraversalRule,
  weakRandomnessRule,
  prototypePollutionRule,
];

/**
 * Get rule by ID
 */
export function getRuleById(id: string): Rule | undefined {
  return allRules.find((rule) => rule.meta.id === id);
}

/**
 * Get rules by severity
 */
export function getRulesBySeverity(
  severity: 'Low' | 'Medium' | 'High'
): Rule[] {
  return allRules.filter((rule) => rule.meta.severity === severity);
}

/**
 * Get rules by tag
 */
export function getRulesByTag(tag: string): Rule[] {
  return allRules.filter((rule) => rule.meta.tags?.includes(tag));
}

/**
 * Get rules by CWE
 */
export function getRulesByCwe(cwe: string): Rule[] {
  return allRules.filter((rule) => rule.meta.cwe === cwe);
}
