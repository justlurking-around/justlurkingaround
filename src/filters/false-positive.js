'use strict';

/**
 * PHASE 5 — False Positive Filter
 *
 * Filters out files and secrets that are clearly not real:
 * - Test files, mock data, fixtures, sample files
 * - .env.example and similar template files
 * - Dummy data, placeholder values
 * - Known-safe patterns
 */

// Exact filenames to always skip regardless of extension
const SKIP_FILENAMES = new Set([
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'composer.lock',
  'Gemfile.lock',
  'Pipfile.lock',
  'poetry.lock',
  'cargo.lock',
  'mix.lock',
  'packages.lock.json',
  'shrinkwrap.json',
  'npm-shrinkwrap.json',
  'bun.lockb',
]);

// File path patterns to always skip
const SKIP_PATH_PATTERNS = [
  /\.spec\.(js|ts|py|rb|go)$/i,
  /\.test\.(js|ts|py|rb|go)$/i,
  /__tests__\//i,
  /\/tests?\//i,
  /\/mocks?\//i,
  /\/fixtures?\//i,
  /\/samples?\//i,
  /\/examples?\//i,
  /\/demo\//i,
  /\/stubs?\//i,
  /\/fakes?\//i,
  /\/dummies?\//i,
  /\.env\.example$/i,
  /\.env\.sample$/i,
  /\.env\.template$/i,
  /\.env\.test$/i,
  /\.env\.local\.example$/i,
  /\/testdata\//i,
  /\/test-data\//i,
  /\/mock-data\//i,
  /vendor\//i,
  /node_modules\//i,
  /\.git\//i,
  /dist\//i,
  /build\//i,
  /coverage\//i,
  /\.nyc_output\//i,
  // Lock files by path pattern
  /package-lock\.json$/i,
  /pnpm-lock\.yaml$/i,
  /yarn\.lock$/i,
  /composer\.lock$/i,
  /Gemfile\.lock$/i,
  /Pipfile\.lock$/i,
  /poetry\.lock$/i,
  /cargo\.lock$/i,
  /\.lockb$/i,
  // Minified / bundled files
  /\.min\.(js|css)$/i,
  /\.bundle\.js$/i,
  /\.chunk\.js$/i,
  // Generated files
  /\.d\.ts$/i,
  /swagger.*\.json$/i,
  /openapi.*\.json$/i,
];

// File extensions to skip (binary / non-text)
const SKIP_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
  '.mp4', '.mp3', '.wav', '.avi', '.mov',
  '.zip', '.tar', '.gz', '.rar', '.7z',
  '.pdf', '.docx', '.xlsx', '.pptx',
  '.lock',         // package-lock.json, yarn.lock — too noisy
  '.map',          // source maps
]);

// Placeholder / dummy secret patterns (false positives)
const DUMMY_VALUE_PATTERNS = [
  /^(your[-_]?)?api[-_]?key[-_]?(here)?$/i,
  /^(your[-_]?)?secret[-_]?(here|key)?$/i,
  /^(insert|add|put|enter|replace)[-_ ]?(your|the)?[-_ ]?(key|token|secret)/i,
  /^(xxx+|yyy+|zzz+|aaa+|bbb+|test+|dummy+|fake+|placeholder+|example+|sample+)/i,
  /^<.*>$/,                          // <YOUR_API_KEY>
  /^\$\{[A-Z_]+\}$/,                 // ${ENV_VAR}
  /^\{\{[A-Z_]+\}\}$/,               // {{ENV_VAR}}
  /^0{8,}$/,                         // 00000000...
  /^1{8,}$/,                         // 11111111...
  /^(sk-)?[xX]{8,}$/,                // xxxxxxxxx
  /^(abcdef|123456|password|changeme|secret|token|key)/i,
  /^[a-z]{8,}_(key|token|secret|password)$/i,  // simple_variable_name
];

// File extensions that are high-value to scan
const HIGH_VALUE_EXTENSIONS = new Set([
  '.js', '.ts', '.jsx', '.tsx',
  '.py', '.rb', '.php', '.go', '.java', '.cs', '.cpp', '.c', '.rs',
  '.env', '.sh', '.bash', '.zsh', '.fish',
  '.yml', '.yaml', '.json', '.toml', '.ini', '.cfg', '.conf', '.config',
  '.tf', '.tfvars',                    // Terraform
  '.pem', '.key', '.crt',              // Certs/keys
  '.properties',                       // Java properties
  '.gradle',
  '',                                  // dotfiles
]);

/**
 * Check if a file path should be skipped
 * @param {string} filePath
 * @returns {{ skip: boolean, reason: string|null }}
 */
function shouldSkipFile(filePath) {
  if (!filePath) return { skip: true, reason: 'empty path' };

  // Exact filename check (fastest)
  const basename = filePath.split('/').pop();
  if (SKIP_FILENAMES.has(basename)) {
    return { skip: true, reason: `skip filename: ${basename}` };
  }

  // Extension check
  const ext = '.' + filePath.split('.').pop().toLowerCase();
  const bareExt = filePath.includes('.') ? ext : '';
  if (SKIP_EXTENSIONS.has(bareExt)) {
    return { skip: true, reason: `binary/skip extension: ${bareExt}` };
  }

  // Path pattern check
  for (const pattern of SKIP_PATH_PATTERNS) {
    if (pattern.test(filePath)) {
      return { skip: true, reason: `path pattern: ${pattern}` };
    }
  }

  return { skip: false, reason: null };
}

/**
 * Check if a matched secret value is a dummy/placeholder
 * @param {string} value
 * @returns {boolean}
 */
function isDummyValue(value) {
  if (!value) return true;
  const trimmed = value.trim();
  if (trimmed.length < 8) return true;

  for (const pattern of DUMMY_VALUE_PATTERNS) {
    if (pattern.test(trimmed)) return true;
  }

  // All same character repeated = dummy
  if (/^(.)\1{7,}$/.test(trimmed)) return true;

  return false;
}

/**
 * Is this a high-value file worth scanning?
 * @param {string} filePath
 * @returns {boolean}
 */
function isHighValueFile(filePath) {
  if (!filePath) return false;
  const parts = filePath.split('.');
  const ext = parts.length > 1 ? '.' + parts.pop().toLowerCase() : '';

  if (HIGH_VALUE_EXTENSIONS.has(ext)) return true;

  // Dotfiles with no extension (e.g. .env, .bashrc)
  const basename = filePath.split('/').pop();
  if (basename.startsWith('.') && !basename.includes('.', 1)) return true;

  return false;
}

/**
 * Extra noise check — rejects checksums, UUIDs, hex hashes, npm integrity
 * values that look high-entropy but are not secrets.
 */
function isNoisyValue(value) {
  if (!value) return false;
  try {
    const { isLikelyNoise } = require('../utils/entropy');
    return isLikelyNoise(value);
  } catch { return false; }
}

module.exports = { shouldSkipFile, isDummyValue, isHighValueFile, isNoisyValue, SKIP_PATH_PATTERNS, SKIP_FILENAMES };
