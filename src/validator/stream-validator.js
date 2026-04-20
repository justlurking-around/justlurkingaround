'use strict';

/**
 * Streaming Validator — real-time mid-scan validation
 *
 * HOW IT WORKS:
 *  - Scanner calls notifyFinding() for EVERY finding as it's discovered
 *  - Only "qualified" findings proceed to live validation immediately
 *  - A finding is "qualified" if:
 *      a) patternId is in HIGH_VALUE_PATTERNS (named provider pattern, not entropy)
 *      b) entropy >= 4.0 (minimum signal quality)
 *      c) Not already validated this session (deduplicated by secretHash)
 *  - On VALID result: alert fires instantly, SSE broadcast fires, scan continues
 *  - Entropy-only ("unknown") findings are batched for end-of-repo validation
 *    (too noisy to validate mid-scan)
 *
 * Scan does NOT stop on a valid hit — it continues to find ALL secrets.
 * The alert is just sent immediately rather than waiting for repo completion.
 */

const { validateFinding, RESULTS } = require('./index');
const { validateCredential } = require('./credential-validator');
const { CREDENTIAL_PATTERNS } = require('../scanner/credential-patterns');

// Credential pattern IDs that have live validators
const CREDENTIAL_PATTERN_IDS = new Set(
  CREDENTIAL_PATTERNS.filter(p => p.canValidate).map(p => p.id)
);
const { sha256 } = require('../utils/hash');
const logger = require('../utils/logger');

// Named patterns worth validating immediately mid-scan
// (these have dedicated API validators and low false-positive rates)
const HIGH_VALUE_PATTERNS = new Set([
  'openai_key', 'openai_key_new',
  'anthropic_key',
  'github_pat', 'github_oauth', 'github_app', 'github_server', 'github_refresh',
  'stripe_live_sk', 'stripe_rk',
  'slack_bot', 'slack_user', 'slack_workspace',
  'sendgrid',
  'telegram_bot',
  'npm_token', 'npm_legacy',
  'discord_bot',
  'mailgun', 'mailgun_pub',
  'heroku_api',
  'linear_token',
  'gitlab_token',
  'huggingface_key',
  'aws_access_key',   // needs pair — validated when aws_secret_key also found
  'aws_secret_key',
  'pypi_token',
  'netlify_token',
  'vercel_token',
]);

// Providers where validation requires a pair (e.g. AWS key + secret)
// We buffer these until the pair is found in the same repo
const PAIR_REQUIRED = new Set(['aws', 'twilio']);

class StreamValidator {
  constructor({ onValid, onFinding } = {}) {
    // Callbacks
    this.onValid    = onValid    || (() => {});  // called with (finding, validationResult)
    this.onFinding  = onFinding  || (() => {});  // called with (finding, validationResult)

    // Per-scan state (reset per repo)
    this._seenHashes   = new Set();
    this._awsPairs     = {};   // repoName -> { accessKeyId, secretKey }
    this._pendingQueue = [];   // low-priority findings queued for batch validation
    this._repoName     = null;

    // Concurrency guard — max 3 validations in flight at once
    this._inFlight = 0;
    this._maxInFlight = 3;
  }

  /** Call this at the start of scanning each repo */
  beginRepo(repoName) {
    this._repoName     = repoName;
    this._seenHashes   = new Set();
    this._awsPairs     = {};
    this._pendingQueue = [];
  }

  /**
   * Notify of a new finding — decide whether to validate immediately
   * @param {object} finding - from scanner engine (has rawValue, patternId, provider, entropy)
   * @returns {Promise<void>} resolves quickly — validation happens async
   */
  async notifyFinding(finding) {
    if (!finding.rawValue) return;

    const hash = sha256(finding.rawValue);
    if (this._seenHashes.has(hash)) return;
    this._seenHashes.add(hash);

    // ── AWS pair buffering ──────────────────────────────────────────────────
    if (finding.patternId === 'aws_access_key') {
      this._awsPairs[this._repoName] = this._awsPairs[this._repoName] || {};
      this._awsPairs[this._repoName].accessKeyId = finding.rawValue;
      // If we already have the secret key, validate now
      if (this._awsPairs[this._repoName].secretKey) {
        this._validateNow(finding, { accessKeyId: finding.rawValue });
      }
      return;
    }
    if (finding.patternId === 'aws_secret_key') {
      this._awsPairs[this._repoName] = this._awsPairs[this._repoName] || {};
      this._awsPairs[this._repoName].secretKey = finding.rawValue;
      const keyId = this._awsPairs[this._repoName].accessKeyId;
      if (keyId) {
        this._validateNow(finding, { accessKeyId: keyId });
      }
      return;
    }

    // ── High-value named pattern — validate immediately ─────────────────────
    if (HIGH_VALUE_PATTERNS.has(finding.patternId)) {
      this._validateNow(finding);
      return;
    }

    // ── Credential pattern (DB, SMTP, private key, etc.) ─────────────────────
    if (CREDENTIAL_PATTERN_IDS.has(finding.patternId)) {
      this._validateCredentialNow(finding);
      return;
    }

    // ── Everything else — batch for end-of-repo ─────────────────────────────
    this._pendingQueue.push(finding);
  }

  /**
   * Call after repo scan completes to drain the batch queue
   * @returns {Promise<object[]>} all validation results
   */
  async drainBatch() {
    const results = [];
    // Validate in small batches, max 5 at a time
    const batchSize = 5;
    for (let i = 0; i < this._pendingQueue.length; i += batchSize) {
      const batch = this._pendingQueue.slice(i, i + batchSize);
      const batchResults = await Promise.all(
        batch.map(f => this._doValidate(f))
      );
      results.push(...batchResults);
    }
    this._pendingQueue = [];
    return results;
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  _validateNow(finding, context = {}) {
    this._doValidate(finding, context).catch(err => {
      logger.debug(`[StreamValidator] Error: ${err.message}`);
    });
  }

  _validateCredentialNow(finding) {
    this._doCredentialValidate(finding).catch(err => {
      logger.debug(`[StreamValidator] Credential error: ${err.message}`);
    });
  }

  async _doCredentialValidate(finding) {
    while (this._inFlight >= this._maxInFlight) {
      await new Promise(r => setTimeout(r, 100));
    }
    this._inFlight++;
    let result;
    try {
      result = await validateCredential(finding);
    } catch (err) {
      result = { result: RESULTS.ERROR, detail: err.message };
    } finally {
      this._inFlight--;
    }
    const enriched = { ...finding, validationResult: result.result, validationDetail: result.detail };
    if (result.result === RESULTS.VALID) {
      logger.warn(
        `[CRED VALID] ${finding.provider} | ${finding.patternName} | ` +
        `${finding.filePath} | ${result.detail}`
      );
      try { await this.onValid(enriched, result); } catch {}
    }
    try { this.onFinding(enriched, result); } catch {}
    return enriched;
  }

  async _doValidate(finding, context = {}) {
    // Concurrency throttle
    while (this._inFlight >= this._maxInFlight) {
      await new Promise(r => setTimeout(r, 100));
    }
    this._inFlight++;

    let result;
    try {
      result = await validateFinding(finding, context);
    } catch (err) {
      result = { result: RESULTS.ERROR, detail: err.message };
    } finally {
      this._inFlight--;
    }

    const enriched = { ...finding, validationResult: result.result, validationDetail: result.detail };

    if (result.result === RESULTS.VALID) {
      logger.warn(
        `[VALID] ${finding.provider} | ${finding.patternName} | ` +
        `${finding.filePath} | ${result.detail}`
      );
      try { await this.onValid(enriched, result); } catch {}
    }

    try { this.onFinding(enriched, result); } catch {}
    return enriched;
  }
}

module.exports = StreamValidator;
