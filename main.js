import { execFile } from 'child_process';

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
 * Executes a system command with sanitized user input.
 * Remediated following Wiz guidance:
 * - Uses execFile instead of exec for better security (no shell interpretation)
 * - Implements input validation and sanitization
 * - Follows principle of least privilege
 *
 * @param {string} userInput - The user-provided input
 */
export function executeVulnerableSystemCommand(userInput) {
  try {
    // Sanitize input before use (Wiz remediation guidance)
    const sanitizedInput = sanitizeInput(userInput);

    // Use execFile instead of exec - it doesn't spawn a shell, preventing injection
    // Pass arguments as array elements, not concatenated strings
    execFile('echo', [sanitizedInput], (error, stdout, stderr) => {
      if (error) {
        console.error(`Execution error: ${error.message}`);
        return;
      }
      console.log(`Output: ${stdout}`);
      if (stderr) {
        console.error(`Error Output: ${stderr}`);
      }
    });
  } catch (validationError) {
    console.error(`Input validation failed: ${validationError.message}`);
    throw validationError;
  }
}