/**
 * INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * View rendering module with XSS vulnerabilities
 *
 * Vulnerabilities:
 * - ZCG-JS-006: Unsanitized innerHTML and other DOM XSS sinks
 */

/**
 * Render user content into HTML
 *
 * ❌ VULNERABLE: innerHTML with user input - ZCG-JS-006
 * User could inject: <script>alert('XSS')</script>
 * ✅ FIX: Use textContent for plain text, or sanitize HTML with DOMPurify
 */
function renderUserContent(userContent) {
  // Simulating innerHTML assignment
  const element = { innerHTML: '' };
  element.innerHTML = userContent; // XSS vulnerability
  return element.innerHTML;
}

/**
 * Render user profile
 *
 * ❌ VULNERABLE: outerHTML assignment - ZCG-JS-006
 */
function renderProfile(profileData) {
  const element = { outerHTML: '' };
  element.outerHTML = `<div class="profile">${profileData.bio}</div>`;
  return element.outerHTML;
}

/**
 * Insert content at position
 *
 * ❌ VULNERABLE: insertAdjacentHTML - ZCG-JS-006
 */
function insertContent(position, content) {
  const element = {
    insertAdjacentHTML: (pos, html) => html,
  };
  return element.insertAdjacentHTML(position, content);
}

/**
 * Write to document
 *
 * ❌ VULNERABLE: document.write - ZCG-JS-006
 */
function writeToDocument(content) {
  // This would be in browser code
  document.write(content);
}

/**
 * Write line to document
 *
 * ❌ VULNERABLE: document.writeln - ZCG-JS-006
 */
function writeLineToDocument(content) {
  document.writeln(content);
}

/**
 * Render comment with dynamic HTML
 *
 * ❌ VULNERABLE: innerHTML with template literal - ZCG-JS-006
 */
function renderComment(username, comment) {
  const element = { innerHTML: '' };
  element.innerHTML = `
    <div class="comment">
      <strong>${username}</strong>
      <p>${comment}</p>
    </div>
  `;
  return element.innerHTML;
}

/**
 * Create user list
 *
 * ❌ VULNERABLE: innerHTML in loop - ZCG-JS-006
 */
function createUserList(users) {
  const container = { innerHTML: '' };

  for (const user of users) {
    container.innerHTML += `<li>${user.name} - ${user.email}</li>`;
  }

  return container.innerHTML;
}

/**
 * Render notification
 *
 * ❌ VULNERABLE: Dynamic innerHTML - ZCG-JS-006
 */
function showNotification(message, type) {
  const notification = { innerHTML: '' };
  notification.innerHTML = `<div class="notification ${type}">${message}</div>`;
  return notification.innerHTML;
}

// React-style example (would be in JSX file)
/**
 * ❌ VULNERABLE: dangerouslySetInnerHTML in React - ZCG-JS-006
 *
 * function UserBio({ bio }) {
 *   return <div dangerouslySetInnerHTML={{ __html: bio }} />;
 * }
 */

// ============================================
// SAFE IMPLEMENTATIONS (for reference)
// ============================================

/**
 * ✅ SAFE: Use textContent for plain text
 */
function renderUserContentSafe(userContent) {
  const element = { textContent: '' };
  element.textContent = userContent; // Safe: will escape HTML
  return element.textContent;
}

/**
 * ✅ SAFE: Sanitize HTML before insertion
 *
 * const DOMPurify = require('dompurify');
 *
 * function renderCommentSafe(username, comment) {
 *   const sanitizedUsername = DOMPurify.sanitize(username);
 *   const sanitizedComment = DOMPurify.sanitize(comment);
 *   // Now safe to use
 * }
 */

/**
 * ✅ SAFE: Use DOM APIs to create elements
 */
function createUserListSafe(users) {
  // In browser:
  // const ul = document.createElement('ul');
  // for (const user of users) {
  //   const li = document.createElement('li');
  //   li.textContent = `${user.name} - ${user.email}`;
  //   ul.appendChild(li);
  // }
  // return ul;

  // Server-side: use proper escaping
  const escapeHtml = (str) => {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };

  return users
    .map((u) => `<li>${escapeHtml(u.name)} - ${escapeHtml(u.email)}</li>`)
    .join('');
}

module.exports = {
  renderUserContent,
  renderProfile,
  insertContent,
  writeToDocument,
  writeLineToDocument,
  renderComment,
  createUserList,
  showNotification,
  renderUserContentSafe,
  createUserListSafe,
};
