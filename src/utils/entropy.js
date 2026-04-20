'use strict';

/**
 * Shannon entropy calculation for detecting high-entropy strings
 *
 * CHANGES v2.1.2:
 *  - isHighEntropy default threshold raised 4.0 -> 4.5
 *    (reduces false positives from checksums, UUIDs, JWT headers)
 *  - Added isLikelyNoise() to reject known non-secret high-entropy patterns
 */

function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Patterns that look high-entropy but are NOT secrets
const NOISE_PATTERNS = [
  /^sha(256|384|512)-[A-Za-z0-9+/=]{20,}/i,   // npm/yarn integrity hashes
  /^[0-9a-f]{32,64}$/i,                         // pure hex hashes (md5/sha256)
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUID
  /^[A-Za-z0-9+/]{50,}={0,2}$/.test            // raw base64 blobs (checksums)
    ? null : /^[A-Za-z0-9+/]{80,}={0,2}$/,      // only flag very long base64
  /^v?\d+\.\d+\.\d+/,                          // semver strings
  /^[0-9]{10,}$/,                               // pure numeric (timestamps etc)
  /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/,        // JWT (handled by named pattern)
].filter(Boolean);

/**
 * Returns true if the string looks like a known-noise pattern
 * (checksum, UUID, raw base64 blob, etc.) rather than a secret
 */
function isLikelyNoise(str) {
  if (!str) return false;
  const s = str.trim();
  for (const re of NOISE_PATTERNS) {
    if (re.test(s)) return true;
  }
  // Pure hex of common hash lengths = checksum, not secret
  if (/^[0-9a-f]+$/i.test(s) && [32, 40, 56, 64, 96, 128].includes(s.length)) return true;
  return false;
}

/**
 * Check if a string looks like a secret based on entropy + charset + noise filter
 * Default threshold raised to 4.5 to reduce false positives
 */
function isHighEntropy(str, threshold = 4.5) {
  if (!str) return false;
  const trimmed = str.trim();
  if (trimmed.length < 16) return false;

  const entropy = shannonEntropy(trimmed);
  if (entropy < threshold) return false;

  // Reject known-noise patterns regardless of entropy
  if (isLikelyNoise(trimmed)) return false;

  // Must have a mix of character types
  const hasLower   = /[a-z]/.test(trimmed);
  const hasUpper   = /[A-Z]/.test(trimmed);
  const hasDigit   = /[0-9]/.test(trimmed);
  const hasSpecial = /[^a-zA-Z0-9]/.test(trimmed);
  const diversity  = [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length;
  return diversity >= 2;
}

module.exports = { shannonEntropy, isHighEntropy, isLikelyNoise };
