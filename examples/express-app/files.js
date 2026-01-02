/**
 * INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * File operations module with path traversal and command injection
 *
 * Vulnerabilities:
 * - ZCG-JS-008: Path traversal
 * - ZCG-JS-003: Command injection via child_process
 */

const fs = require('fs');
const path = require('path');
const { exec, execSync, spawn } = require('child_process');

const UPLOADS_DIR = '/var/www/uploads';
const USER_FILES_DIR = '/var/www/user-files';

/**
 * Read a user's file
 *
 * ❌ VULNERABLE: Path traversal - ZCG-JS-008
 * User could request: ../../etc/passwd
 * ✅ FIX: Validate that resolved path is within allowed directory
 */
function readUserFile(userId, filename) {
  // Vulnerable: path.join with user input
  const filePath = path.join(USER_FILES_DIR, userId, filename);
  return fs.readFileSync(filePath, 'utf-8');
}

/**
 * Download a file
 *
 * ❌ VULNERABLE: Path traversal with dynamic path - ZCG-JS-008
 */
function downloadFile(userPath) {
  const fullPath = path.resolve(UPLOADS_DIR, userPath);
  return fs.readFileSync(fullPath);
}

/**
 * Save uploaded file
 *
 * ❌ VULNERABLE: Arbitrary file write via path traversal - ZCG-JS-008
 */
function saveUpload(filename, content) {
  const filePath = path.join(UPLOADS_DIR, filename);
  fs.writeFileSync(filePath, content);
}

/**
 * Process a file using shell command
 *
 * ❌ VULNERABLE: Command injection - ZCG-JS-003
 * filename could be: "file.txt; rm -rf /"
 * ✅ FIX: Use spawn with array arguments, or sanitize input
 */
function processFile(filename) {
  // Dangerous: execSync with user input
  const output = execSync(`cat ${filename} | wc -l`);
  return output.toString();
}

/**
 * Convert image format
 *
 * ❌ VULNERABLE: Command injection via exec - ZCG-JS-003
 */
function convertImage(inputPath, outputPath, format) {
  // User controls both paths and format - very dangerous!
  exec(
    `convert ${inputPath} -format ${format} ${outputPath}`,
    (err, stdout, stderr) => {
      if (err) console.error(err);
    }
  );
}

/**
 * Compress files
 *
 * ❌ VULNERABLE: Command injection - ZCG-JS-003
 */
function compressFiles(files, outputName) {
  const fileList = files.join(' ');
  execSync(`tar -czf ${outputName}.tar.gz ${fileList}`);
}

/**
 * Get file info using shell
 *
 * ❌ VULNERABLE: Command injection - ZCG-JS-003
 */
function getFileInfo(filepath) {
  return execSync(`file ${filepath}`).toString();
}

/**
 * Ping a host (dangerous!)
 *
 * ❌ VULNERABLE: Command injection - ZCG-JS-003
 * host could be: "google.com; cat /etc/passwd"
 */
function pingHost(host) {
  exec(`ping -c 4 ${host}`, (err, stdout) => {
    console.log(stdout);
  });
}

/**
 * List directory contents
 *
 * ❌ VULNERABLE: Path traversal - ZCG-JS-008
 */
function listDirectory(dirPath) {
  const fullPath = path.resolve(dirPath);
  return fs.readdirSync(fullPath);
}

// ============================================
// SAFE IMPLEMENTATIONS (for reference)
// ============================================

/**
 * ✅ SAFE: Proper path traversal prevention
 */
function readUserFileSafe(userId, filename) {
  // Sanitize: remove path traversal attempts
  const sanitizedFilename = path.basename(filename);
  const userDir = path.resolve(USER_FILES_DIR, userId);
  const filePath = path.resolve(userDir, sanitizedFilename);

  // Verify the resolved path is within the allowed directory
  if (!filePath.startsWith(userDir)) {
    throw new Error('Access denied: path traversal detected');
  }

  return fs.readFileSync(filePath, 'utf-8');
}

/**
 * ✅ SAFE: Using spawn with array arguments
 */
function processFileSafe(filename) {
  // Sanitize filename first
  const sanitized = path.basename(filename);

  // Use spawn with separate arguments - prevents injection
  const child = spawn('wc', ['-l', sanitized]);
  return new Promise((resolve, reject) => {
    let output = '';
    child.stdout.on('data', (data) => (output += data));
    child.on('close', (code) => {
      if (code === 0) resolve(output);
      else reject(new Error(`Process exited with code ${code}`));
    });
  });
}

module.exports = {
  readUserFile,
  downloadFile,
  saveUpload,
  processFile,
  convertImage,
  compressFiles,
  getFileInfo,
  pingHost,
  listDirectory,
  readUserFileSafe,
  processFileSafe,
};
