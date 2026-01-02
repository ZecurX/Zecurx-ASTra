/**
 * INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * This file contains multiple vulnerabilities for testing Zecurx CodeGuard
 */

const express = require('express');
const { authenticateUser, generateToken } = require('./auth');
const { query } = require('./database');
const { readUserFile, processFile } = require('./files');
const { parseConfig, executeTemplate } = require('./utils');
const { renderUserContent } = require('./views');

const app = express();
app.use(express.json());

// Hardcoded secret - ZCG-JS-004
const API_KEY = 'FAKE_API_KEY_FOR_TESTING';
const JWT_SECRET = 'FAKE_JWT_SECRET_FOR_TESTING';

// Login endpoint with multiple vulnerabilities
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // SQL injection possible here
  const user = await query(
    `SELECT * FROM users WHERE username = '${username}'`
  );

  if (user && authenticateUser(username, password)) {
    const token = generateToken(user.id);
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// User profile with path traversal vulnerability
app.get('/profile/:userId/files/:filename', async (req, res) => {
  const { userId, filename } = req.params;

  // Path traversal - user could request ../../etc/passwd
  const content = readUserFile(userId, filename);
  res.send(content);
});

// Admin endpoint with command injection
app.post('/admin/process', async (req, res) => {
  const { file } = req.body;

  // Command injection - file could be "; rm -rf /"
  const result = processFile(file);
  res.json({ result });
});

// Config parser with eval vulnerability
app.post('/config', async (req, res) => {
  const { config } = req.body;

  // Uses eval internally - dangerous!
  const parsed = parseConfig(config);
  res.json(parsed);
});

// Template engine with Function constructor
app.post('/template', async (req, res) => {
  const { template, data } = req.body;

  // Uses new Function() internally
  const result = executeTemplate(template, data);
  res.json({ html: result });
});

// User content with XSS vulnerability
app.post('/render', async (req, res) => {
  const { content } = req.body;

  // Uses innerHTML internally - XSS risk
  const html = renderUserContent(content);
  res.send(html);
});

// Weak randomness for session IDs
app.get('/session', (req, res) => {
  // Math.random() is not cryptographically secure - ZCG-JS-009
  const sessionId = Math.random().toString(36).substring(2);
  res.json({ sessionId });
});

// Prototype pollution via Object.assign
app.post('/merge', (req, res) => {
  const defaults = { role: 'user', active: true };

  // Prototype pollution - req.body could contain __proto__
  const config = Object.assign({}, defaults, req.body);
  res.json(config);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
