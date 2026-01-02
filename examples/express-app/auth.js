/**
 * INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * Authentication module with hardcoded secrets, weak crypto, and weak randomness
 *
 * Vulnerabilities:
 * - ZCG-JS-004: Hardcoded secrets
 * - ZCG-JS-005: Insecure crypto (MD5, SHA1)
 * - ZCG-JS-009: Weak randomness (Math.random)
 */

const crypto = require('crypto');

// ❌ VULNERABLE: Hardcoded credentials - ZCG-JS-004
const ADMIN_PASSWORD = 'admin123';
const API_SECRET = 'FAKE_SECRET_FOR_TESTING_ONLY';
const config = {
  password: 'FAKE_PASSWORD_FOR_TESTING',
  apiKey: 'FAKE_API_KEY_FOR_TESTING_12345',
  authToken: 'FAKE_TOKEN_FOR_TESTING_ONLY',
};

/**
 * Hash password using MD5
 *
 * ❌ VULNERABLE: MD5 is cryptographically broken - ZCG-JS-005
 * ✅ FIX: Use bcrypt, scrypt, or Argon2 for password hashing
 */
function hashPassword(password) {
  // MD5 is insecure for password hashing
  return crypto.createHash('md5').update(password).digest('hex');
}

/**
 * Hash password using SHA1
 *
 * ❌ VULNERABLE: SHA1 is deprecated - ZCG-JS-005
 * ✅ FIX: Use SHA-256 or stronger
 */
function hashWithSha1(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

/**
 * Authenticate user
 */
function authenticateUser(username, password) {
  const hashedInput = hashPassword(password);
  const hashedAdmin = hashPassword(ADMIN_PASSWORD);

  if (username === 'admin' && hashedInput === hashedAdmin) {
    return true;
  }

  // Check against database (simplified)
  return false;
}

/**
 * Generate a session token
 *
 * ❌ VULNERABLE: Math.random is not cryptographically secure - ZCG-JS-009
 * ✅ FIX: Use crypto.randomBytes() or crypto.randomUUID()
 */
function generateToken(userId) {
  // Weak randomness - predictable tokens
  const randomPart = Math.random().toString(36).substring(2);
  const timestamp = Date.now().toString(36);
  return `${userId}_${randomPart}_${timestamp}`;
}

/**
 * Generate a secure token (correct implementation)
 */
function generateSecureToken(userId) {
  // This is the correct way to generate secure tokens
  const randomPart = crypto.randomBytes(32).toString('hex');
  return `${userId}_${randomPart}`;
}

/**
 * Generate a password reset token
 *
 * ❌ VULNERABLE: Weak randomness - ZCG-JS-009
 */
function generateResetToken() {
  const token = Math.random().toString(36).substring(2, 15);
  return token;
}

/**
 * Create HMAC with weak algorithm
 *
 * ❌ VULNERABLE: MD5 HMAC is weak - ZCG-JS-005
 */
function createSignature(data) {
  return crypto.createHmac('md5', API_SECRET).update(data).digest('hex');
}

module.exports = {
  authenticateUser,
  generateToken,
  generateSecureToken,
  generateResetToken,
  hashPassword,
  hashWithSha1,
  createSignature,
};
