/**
 * INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * Utility functions with eval, Function, and prototype pollution
 *
 * Vulnerabilities:
 * - ZCG-JS-001: Dangerous eval() usage
 * - ZCG-JS-002: Dynamic Function constructor
 * - ZCG-JS-010: Prototype pollution
 */

const _ = require('lodash'); // Assuming older vulnerable version

/**
 * Parse configuration string
 *
 * ❌ VULNERABLE: eval() with user input - ZCG-JS-001
 * Input could be: "process.exit(1)" or "require('child_process').execSync('rm -rf /')"
 * ✅ FIX: Use JSON.parse() for JSON data, or a safe expression parser
 */
function parseConfig(configString) {
  // Extremely dangerous: eval on user input
  return eval('(' + configString + ')');
}

/**
 * Calculate expression
 *
 * ❌ VULNERABLE: eval() for math expressions - ZCG-JS-001
 */
function calculate(expression) {
  // User could inject code: "1+1; process.exit()"
  return eval(expression);
}

/**
 * Dynamic property access via eval
 *
 * ❌ VULNERABLE: eval() - ZCG-JS-001
 */
function getProperty(obj, path) {
  return eval(`obj.${path}`);
}

/**
 * Execute template
 *
 * ❌ VULNERABLE: new Function() with user input - ZCG-JS-002
 * ✅ FIX: Use a proper templating library like Handlebars or EJS
 */
function executeTemplate(templateCode, data) {
  // Dynamic Function constructor - similar to eval
  const fn = new Function('data', `return \`${templateCode}\``);
  return fn(data);
}

/**
 * Create dynamic function
 *
 * ❌ VULNERABLE: Function constructor - ZCG-JS-002
 */
function createDynamicFunction(params, body) {
  return new Function(params, body);
}

/**
 * Transform data using dynamic code
 *
 * ❌ VULNERABLE: Function constructor - ZCG-JS-002
 */
function transformData(data, transformCode) {
  const transform = Function('item', `return ${transformCode}`);
  return data.map(transform);
}

/**
 * Merge objects deeply
 *
 * ❌ VULNERABLE: Prototype pollution via lodash.merge - ZCG-JS-010
 * (older versions of lodash were vulnerable)
 */
function deepMerge(target, source) {
  return _.merge(target, source);
}

/**
 * Extend object
 *
 * ❌ VULNERABLE: Prototype pollution - ZCG-JS-010
 */
function extendObject(target, ...sources) {
  return _.extend(target, ...sources);
}

/**
 * Set nested property
 *
 * ❌ VULNERABLE: Prototype pollution via direct __proto__ access - ZCG-JS-010
 */
function setNestedProperty(obj, path, value) {
  // Direct __proto__ manipulation
  if (path === '__proto__') {
    obj.__proto__ = value;
    return;
  }

  // Using Object.assign with untrusted data
  Object.assign(obj, { [path]: value });
}

/**
 * Clone and modify object
 *
 * ❌ VULNERABLE: Prototype pollution - ZCG-JS-010
 */
function cloneAndModify(source, modifications) {
  const clone = Object.assign({}, source);
  // modifications could contain __proto__
  return Object.assign(clone, modifications);
}

/**
 * Dynamic property setter
 *
 * ❌ VULNERABLE: Prototype pollution via computed property - ZCG-JS-010
 */
function setProperty(obj, key, value) {
  // key could be "__proto__" or "constructor"
  obj[key] = value;
}

/**
 * Parse and execute JSON with code
 *
 * ❌ VULNERABLE: eval() - ZCG-JS-001
 */
function parseJsonWithCode(jsonString) {
  // Extremely dangerous
  const data = eval('(' + jsonString + ')');
  return data;
}

// ============================================
// SAFE IMPLEMENTATIONS (for reference)
// ============================================

/**
 * ✅ SAFE: Parse config using JSON.parse
 */
function parseConfigSafe(configString) {
  try {
    return JSON.parse(configString);
  } catch (e) {
    throw new Error('Invalid JSON configuration');
  }
}

/**
 * ✅ SAFE: Safe object merge that protects against prototype pollution
 */
function safeMerge(target, source) {
  const result = { ...target };

  for (const key of Object.keys(source)) {
    // Block prototype pollution attempts
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }

    if (typeof source[key] === 'object' && source[key] !== null) {
      result[key] = safeMerge(result[key] || {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }

  return result;
}

module.exports = {
  parseConfig,
  calculate,
  getProperty,
  executeTemplate,
  createDynamicFunction,
  transformData,
  deepMerge,
  extendObject,
  setNestedProperty,
  cloneAndModify,
  setProperty,
  parseJsonWithCode,
  parseConfigSafe,
  safeMerge,
};
