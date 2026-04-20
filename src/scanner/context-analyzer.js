'use strict';

/**
 * DAY 2 — Context Analyzer
 *
 * Reduces false positives by analyzing the CONTEXT around a matched secret:
 *  - Variable name suggests it's a real credential (not a log/comment)
 *  - Not inside a comment block
 *  - Assignment context (= or :) present
 *  - Not in a string that's clearly a UI label
 *  - Language-specific context rules (JS, Python, YAML, etc.)
 *
 * Inspired by GitGuardian's assigned_variable + value analysis
 */

// Variable names that strongly indicate a real credential
const SENSITIVE_VAR_NAMES = [
  'api_key', 'apikey', 'api_secret', 'apisecret',
  'access_key', 'secret_key', 'secret_access_key',
  'private_key', 'auth_token', 'access_token',
  'bearer_token', 'client_secret', 'client_id',
  'password', 'passwd', 'pwd', 'passphrase',
  'token', 'secret', 'credential', 'auth',
  'database_url', 'db_password', 'db_pass',
  'connection_string', 'conn_string',
  'webhook_url', 'webhook_secret',
  'encryption_key', 'signing_key', 'jwt_secret',
  'oauth_token', 'refresh_token',
];

// Variable names that indicate it's NOT a real credential (false positive)
const SAFE_VAR_NAMES = [
  'example', 'sample', 'test', 'dummy', 'mock', 'fake',
  'placeholder', 'default', 'template', 'demo',
  'your_', 'my_', 'the_', 'some_',
  'description', 'label', 'title', 'name',
  'comment', 'note', 'message', 'text',
  'color', 'theme', 'style',
  'version', 'release', 'tag',
];

// Comment-line prefixes (skip secrets inside comments)
const COMMENT_PREFIXES = [
  /^\s*\/\//, /^\s*#/, /^\s*\*/, /^\s*<!--/,
];

/**
 * Analyze context around a finding to assess real/false-positive probability
 * @param {string} matchContext - line of code around the match
 * @param {string} filePath - file path for language detection
 * @param {string} patternId - pattern that matched
 * @returns {{ score: number, flags: string[] }} score 0-100, flags for debug
 */
function analyzeContext(matchContext, filePath, patternId) {
  if (!matchContext) return { score: 50, flags: ['no_context'] };

  const flags = [];
  let score = 50; // neutral baseline

  const line = matchContext.toLowerCase();
  const ext = filePath?.split('.').pop()?.toLowerCase() || '';

  // ── Check if line is a comment ────────────────────────────────────────────
  const isComment = COMMENT_PREFIXES.some(re => re.test(matchContext));
  if (isComment) {
    score -= 20;
    flags.push('in_comment');
  }

  // ── Check for assignment operator (good signal) ──────────────────────────
  const hasAssignment = /[=:]\s*["']?[A-Za-z0-9]/.test(matchContext);
  if (hasAssignment) {
    score += 15;
    flags.push('has_assignment');
  }

  // ── Check variable name ───────────────────────────────────────────────────
  const hasSensitiveVar = SENSITIVE_VAR_NAMES.some(name => line.includes(name));
  const hasSafeVar = SAFE_VAR_NAMES.some(name => line.includes(name));

  if (hasSensitiveVar) { score += 20; flags.push('sensitive_var'); }
  if (hasSafeVar)      { score -= 15; flags.push('safe_var'); }

  // ── File type signals ─────────────────────────────────────────────────────
  if (['.env', ''].includes(ext) && filePath?.includes('.env')) {
    score += 20; // .env files are very likely real
    flags.push('env_file');
  }
  if (['yml', 'yaml'].includes(ext) && line.includes(':')) {
    score += 10; flags.push('yaml_config');
  }
  if (['tf', 'tfvars'].includes(ext)) {
    score += 15; flags.push('terraform');
  }
  if (ext === 'json' && hasAssignment) {
    score += 10; flags.push('json_config');
  }

  // ── README / documentation signals (lower confidence) ─────────────────────
  const isDoc = /readme|docs?\/|\.md$|\.rst$|\.txt$/i.test(filePath || '');
  if (isDoc) {
    score -= 25; flags.push('documentation_file');
  }

  // ── Known-good pattern IDs (high confidence by format) ───────────────────
  const highConfidencePatterns = [
    'aws_access_key', 'openai_key', 'openai_key_new', 'anthropic_key',
    'github_pat', 'github_oauth', 'github_app',
    'stripe_live_sk', 'stripe_rk',
    'sendgrid', 'slack_bot', 'npm_token', 'pypi_token',
    'telegram_bot', 'mapbox', 'mapbox_sk',
    'ssh_private_key', 'pgp_private_key',
    'mongodb_conn', 'postgres_conn',
  ];
  if (highConfidencePatterns.includes(patternId)) {
    score += 25;
    flags.push('high_confidence_pattern');
  }

  return { score: Math.max(0, Math.min(100, score)), flags };
}

/**
 * Annotate a list of findings with context scores
 */
function annotateWithContext(findings) {
  return findings.map(f => {
    const { score, flags } = analyzeContext(f.matchContext, f.filePath, f.patternId);
    return {
      ...f,
      contextScore: score,
      contextFlags: flags,
      // Combined confidence: average of pattern confidence and context score
      confidence: Math.round(((f.confidence || 50) + score) / 2)
    };
  });
}

module.exports = { analyzeContext, annotateWithContext, SENSITIVE_VAR_NAMES };
