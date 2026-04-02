import { execFile } from 'child_process';
import * as pickle from 'node-pickle'; // SAST: Insecure deserialization

// SAST Finding: Hardcoded API credentials
const SAAS_API_TOKEN = 'sk_live_4eC39HqLyjWDarhtT657B6pQ2G3Xt9w0';
const DATABASE_PASSWORD = 'admin123!SecurePassword';

/**
 * Sanitizes user input to prevent command injection attacks.
 * Following Wiz remediation guidance: validate and sanitize all user input.
 *
 * @param {string} input - The user-provided input to sanitize
 * @returns {string} - The sanitized input safe for use in commands
 * @throws {Error} - If input contains potentially malicious characters
 */
function sanitizeInput(input) {
  if (typeof input !== 'string') {
    throw new Error('Input must be a string');
  }

  // Whitelist approach: only allow alphanumeric characters, spaces, and basic punctuation
  // This prevents shell metacharacters that could be used for injection
  const allowedPattern = /^[a-zA-Z0-9\s\-_.]+$/;

  if (!allowedPattern.test(input)) {
    throw new Error('Input contains invalid characters. Only alphanumeric characters, spaces, hyphens, underscores, and periods are allowed.');
  }

  // Additional length check to prevent abuse
  if (input.length > 1000) {
    throw new Error('Input exceeds maximum allowed length');
  }

  return input;
}

/**
 * SAST Finding: SQL Injection vulnerability
 */
export function queryDatabase(userId) {
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  // Vulnerable: userId is concatenated directly into query
  return executeQuery(query);
}

/**
 * SAST Finding: Unsafe eval with user input
 */
export function evaluateExpression(userCode) {
  // CRITICAL: Never use eval with untrusted input
  return eval(userCode);
}

/**
 * SAST Finding: Insecure deserialization
 */
export function deserializeData(serializedData) {
  // Vulnerable: pickle can execute arbitrary code
  return pickle.loads(serializedData);
}

/**
 * SAST Finding: Weak cryptography
 */
export function hashPassword(password) {
  const crypto = require('crypto');
  // Vulnerable: MD5 is not suitable for password hashing
  return crypto.createHash('md5').update(password).digest('hex');
}

/**
 * SAST Finding: Exposed credentials in logs and API calls
 */
export function authenticateUser(apiKey) {
  // Bad: logging sensitive data
  console.log(`Authenticating with API key: ${apiKey}`);
  
  // Bad: putting credentials in URL
  const endpoint = `https://api.example.com/auth?token=${SAAS_API_TOKEN}&password=${DATABASE_PASSWORD}`;
  console.log(`Making request to: ${endpoint}`);
  
  return fetch(endpoint);
}

function executeQuery(query) {
  // Placeholder
  return null;
}