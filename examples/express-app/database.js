/**
 * INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * Database module with SQL injection vulnerabilities
 *
 * Vulnerabilities:
 * - ZCG-JS-007: SQL injection via string concatenation and template literals
 */

/**
 * Simulated database connection
 */
const db = {
  query: (sql) => {
    console.log('Executing SQL:', sql);
    return Promise.resolve([]);
  },
  execute: (sql) => {
    console.log('Executing SQL:', sql);
    return Promise.resolve([]);
  },
};

/**
 * Query the database
 *
 * ❌ VULNERABLE: Direct string interpolation in SQL - ZCG-JS-007
 * ✅ FIX: Use parameterized queries
 */
async function query(sql) {
  return db.query(sql);
}

/**
 * Get user by ID
 *
 * ❌ VULNERABLE: Template literal SQL injection - ZCG-JS-007
 */
async function getUserById(userId) {
  // Vulnerable: user input directly in query
  const sql = `SELECT * FROM users WHERE id = ${userId}`;
  return db.query(sql);
}

/**
 * Search users by name
 *
 * ❌ VULNERABLE: String concatenation SQL injection - ZCG-JS-007
 */
async function searchUsers(searchTerm) {
  // Vulnerable: string concatenation
  const sql = "SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%'";
  return db.query(sql);
}

/**
 * Update user email
 *
 * ❌ VULNERABLE: Multiple injections possible - ZCG-JS-007
 */
async function updateUserEmail(userId, newEmail) {
  const sql = `UPDATE users SET email = '${newEmail}' WHERE id = ${userId}`;
  return db.execute(sql);
}

/**
 * Delete user
 *
 * ❌ VULNERABLE: Template literal injection - ZCG-JS-007
 */
async function deleteUser(userId) {
  const sql = `DELETE FROM users WHERE id = ${userId}`;
  return db.execute(sql);
}

/**
 * Get user orders
 *
 * ❌ VULNERABLE: Complex query with multiple injection points
 */
async function getUserOrders(userId, status, sortBy) {
  const sql = `
    SELECT * FROM orders 
    WHERE user_id = ${userId} 
    AND status = '${status}'
    ORDER BY ${sortBy}
  `;
  return db.query(sql);
}

/**
 * Insert new user (vulnerable)
 */
async function createUser(username, email, password) {
  const sql = `INSERT INTO users (username, email, password) VALUES ('${username}', '${email}', '${password}')`;
  return db.execute(sql);
}

/**
 * Raw query execution
 *
 * ❌ VULNERABLE: Direct raw query execution
 */
async function rawQuery(sql) {
  return db.raw(sql);
}

// ============================================
// SAFE IMPLEMENTATIONS (for reference)
// ============================================

/**
 * ✅ SAFE: Parameterized query example
 */
async function getUserByIdSafe(userId) {
  // Using parameterized query
  const sql = 'SELECT * FROM users WHERE id = ?';
  return db.query(sql, [userId]);
}

/**
 * ✅ SAFE: Prepared statement example
 */
async function searchUsersSafe(searchTerm) {
  const sql = 'SELECT * FROM users WHERE name LIKE ?';
  return db.query(sql, [`%${searchTerm}%`]);
}

module.exports = {
  query,
  getUserById,
  searchUsers,
  updateUserEmail,
  deleteUser,
  getUserOrders,
  createUser,
  rawQuery,
  getUserByIdSafe,
  searchUsersSafe,
};
