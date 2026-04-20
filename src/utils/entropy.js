'use strict';

/**
 * Shannon entropy calculation for detecting high-entropy strings (potential secrets)
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Check if a string looks like a secret based on entropy + charset
 */
function isHighEntropy(str, threshold = 4.0) {
  if (!str) return false;
  const trimmed = str.trim();
  if (trimmed.length < 16) return false;

  const entropy = shannonEntropy(trimmed);
  if (entropy < threshold) return false;

  // Must have a mix of character types
  const hasLower = /[a-z]/.test(trimmed);
  const hasUpper = /[A-Z]/.test(trimmed);
  const hasDigit = /[0-9]/.test(trimmed);
  const hasSpecial = /[^a-zA-Z0-9]/.test(trimmed);

  const diversity = [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length;
  return diversity >= 2;
}

module.exports = { shannonEntropy, isHighEntropy };
