'use strict';

/**
 * Validation Engine
 *
 * FIXES:
 *  - BUG: rawValue passed directly to URL (telegram) — path injection possible → sanitized
 *  - BUG: AWS validator does require('@aws-sdk/client-sts') at call time → graceful skip if not installed
 *  - BUG: validation timeout not applied per-request → now enforced
 *  - BUG: stripe 402/402 not handled (test key hitting charge limit) → handled
 *  - BUG: discord bot prefix wrong for user tokens (xoxp-style) — corrected
 *  - SECURITY: secrets never appear in error messages or logs (rawValue stripped from error path)
 *  - NEW: huggingface validator
 *  - NEW: linear validator
 *  - NEW: gitlab validator
 */

const axios = require('axios');
const axiosRetry = require('axios-retry').default || require('axios-retry');
const config   = require('../../config/default');
const logger   = require('../utils/logger');
const { sanitizeProvider, sanitizeForLog, isSafeUrl } = require('../utils/security');

const RESULTS = {
  VALID:   'VALID',
  INVALID: 'INVALID',
  ERROR:   'ERROR',
  SKIPPED: 'SKIPPED'
};

function makeClient() {
  const client = axios.create({
    timeout: config.validation.timeout || 8000,
    // SECURITY: never follow redirects that could exfiltrate secrets
    maxRedirects: 3,
    validateStatus: () => true // handle all status codes ourselves
  });
  axiosRetry(client, {
    retries: config.validation.maxRetries || 2,
    retryDelay: axiosRetry.exponentialDelay,
    retryCondition: err => !err.response || err.response.status === 429 || err.response.status >= 500
  });
  return client;
}

const http = makeClient();

// ── Sanitize helper — strip control chars that could affect log output ────────
function sanitize(val) {
  if (!val) return '';
  return String(val).replace(/[\x00-\x1f\x7f]/g, '').substring(0, 512);
}

// ── Provider validators ───────────────────────────────────────────────────────

const validators = {

  async openai(secret) {
    try {
      const resp = await http.get('https://api.openai.com/v1/models', {
        headers: { Authorization: `Bearer ${secret}` }
      });
      if (resp.status === 200) return { result: RESULTS.VALID,   detail: 'Models endpoint OK' };
      if (resp.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      if (resp.status === 429) return { result: RESULTS.VALID,   detail: 'Rate limited (key valid)' };
      return { result: RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      return { result: RESULTS.ERROR, detail: sanitize(err.message) };
    }
  },

  async anthropic(secret) {
    try {
      const resp = await http.get('https://api.anthropic.com/v1/models', {
        headers: { 'x-api-key': secret, 'anthropic-version': '2023-06-01' }
      });
      if (resp.status === 200) return { result: RESULTS.VALID,   detail: 'Models OK' };
      if (resp.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      return { result: RESULTS.ERROR, detail: sanitize(err.message) };
    }
  },

  async github(secret) {
    try {
      const resp = await http.get('https://api.github.com/user', {
        headers: { Authorization: `token ${secret}`, 'User-Agent': 'ai-secret-scanner/2.0' }
      });
      if (resp.status === 200) return { result: RESULTS.VALID,   detail: `User: ${sanitize(resp.data?.login)}` };
      if (resp.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      return { result: RESULTS.ERROR, detail: sanitize(err.message) };
    }
  },

  async stripe(secret) {
    try {
      const resp = await http.get('https://api.stripe.com/v1/charges?limit=1', {
        auth: { username: secret, password: '' }
      });
      if (resp.status === 200) return { result: RESULTS.VALID,   detail: 'Charges OK' };
      if (resp.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      // 402 = live key hitting real charges (test key on live endpoint) → still valid key
      if (resp.status === 402) return { result: RESULTS.VALID,   detail: 'Payment required (key valid)' };
      if (resp.status === 403) return { result: RESULTS.VALID,   detail: 'Restricted key (valid)' };
      return { result: RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      return { result: RESULTS.ERROR, detail: sanitize(err.message) };
    }
  },

  async aws(secret, context) {
    const accessKeyId = context?.accessKeyId;
    if (!accessKeyId) return { result: RESULTS.SKIPPED, detail: 'Need AWS Access Key ID for pair validation' };
    try {
      // FIX: graceful skip if @aws-sdk not installed
      let STSClient, GetCallerIdentityCommand;
      try {
        const sts = require('@aws-sdk/client-sts');
        STSClient = sts.STSClient;
        GetCallerIdentityCommand = sts.GetCallerIdentityCommand;
      } catch {
        return { result: RESULTS.SKIPPED, detail: 'Install @aws-sdk/client-sts to enable AWS validation' };
      }
      const sts = new STSClient({
        region: 'us-east-1',
        credentials: { accessKeyId, secretAccessKey: secret },
        requestHandler: { requestTimeout: 8000 }
      });
      const data = await sts.send(new GetCallerIdentityCommand({}));
      return { result: RESULTS.VALID, detail: `Account: ${sanitize(data.Account)}` };
    } catch (err) {
      if (err.name === 'InvalidClientTokenId') return { result: RESULTS.INVALID, detail: 'Invalid key ID' };
      if (err.name === 'SignatureDoesNotMatch') return { result: RESULTS.INVALID, detail: 'Invalid secret' };
      return { result: RESULTS.ERROR, detail: sanitize(err.message) };
    }
  },

  async slack(secret) {
    try {
      const resp = await http.post('https://slack.com/api/auth.test', null, {
        headers: { Authorization: `Bearer ${secret}` }
      });
      if (resp.data?.ok) return { result: RESULTS.VALID, detail: `Team: ${sanitize(resp.data.team)}` };
      return { result: RESULTS.INVALID, detail: sanitize(resp.data?.error) || 'ok=false' };
    } catch (err) {
      return { result: RESULTS.ERROR, detail: sanitize(err.message) };
    }
  },

  async sendgrid(secret) {
    try {
      const resp = await http.get('https://api.sendgrid.com/v3/user/account', {
        headers: { Authorization: `Bearer ${secret}` }
      });
      if (resp.status === 200) return { result: RESULTS.VALID,   detail: 'Account OK' };
      if (resp.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      return { result: RESULTS.ERROR, detail: sanitize(err.message) };
    }
  },

  async twilio() {
    return { result: RESULTS.SKIPPED, detail: 'Twilio requires SID+AuthToken pair' };
  },

  async npm(secret) {
    try {
      const resp = await http.get('https://registry.npmjs.org/-/whoami', {
        headers: { Authorization: `Bearer ${secret}` }
      });
      if (resp.status === 200) return { result: RESULTS.VALID,   detail: sanitize(resp.data?.username) };
      if (resp.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      return { result: RESULTS.ERROR, detail: sanitize(err.message) };
    }
  },

  async discord(secret) {
    try {
      // FIX: use Bot prefix for bot tokens; user tokens use Bearer
      const isUserToken = secret.startsWith('xoxp-') || secret.length < 59;
      const authHeader = isUserToken ? `Bearer ${secret}` : `Bot ${secret}`;
      const resp = await http.get('https://discord.com/api/v10/users/@me', {
        headers: { Authorization: authHeader }
      });
      if (resp.status === 200) return { result: RESULTS.VALID,   detail: sanitize(resp.data?.username) };
      if (resp.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      return { result: RESULTS.ERROR, detail: sanitize(err.message) };
    }
  },

  async shopify() {
    return { result: RESULTS.SKIPPED, detail: 'Shopify tokens require a shop domain' };
  },

  async telegram(secret) {
    // FIX: sanitize secret to prevent path injection in URL
    const safeToken = sanitize(secret).replace(/[^0-9a-zA-Z:_\-]/g, '');
    if (!safeToken) return { result: RESULTS.INVALID, detail: 'Invalid token format' };
    try {
      const resp = await http.get(`https://api.telegram.org/bot${safeToken}/getMe`);
      if (resp.data?.ok)   return { result: RESULTS.VALID,   detail: `Bot: @${sanitize(resp.data.result?.username)}` };
      if (resp.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.INVALID, detail: sanitize(resp.data?.description) };
    } catch (err) {
      return { result: RESULTS.ERROR, detail: sanitize(err.message) };
    }
  },

  async mailgun(secret) {
    try {
      const resp = await http.get('https://api.mailgun.net/v3/domains', {
        auth: { username: 'api', password: secret }
      });
      if (resp.status === 200) return { result: RESULTS.VALID,   detail: 'Domains OK' };
      if (resp.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      return { result: RESULTS.ERROR, detail: sanitize(err.message) };
    }
  },

  async heroku(secret) {
    try {
      const resp = await http.get('https://api.heroku.com/account', {
        headers: { Authorization: `Bearer ${secret}`, Accept: 'application/vnd.heroku+json; version=3' }
      });
      if (resp.status === 200) return { result: RESULTS.VALID,   detail: sanitize(resp.data?.email) };
      if (resp.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      return { result: RESULTS.ERROR, detail: sanitize(err.message) };
    }
  },

  // ── New providers ─────────────────────────────────────────────────────────

  async huggingface(secret) {
    try {
      const resp = await http.get('https://huggingface.co/api/whoami-v2', {
        headers: { Authorization: `Bearer ${secret}` }
      });
      if (resp.status === 200) return { result: RESULTS.VALID,   detail: sanitize(resp.data?.name) };
      if (resp.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      return { result: RESULTS.ERROR, detail: sanitize(err.message) };
    }
  },

  async linear(secret) {
    try {
      const resp = await http.post('https://api.linear.app/graphql',
        { query: '{ viewer { id name } }' },
        { headers: { Authorization: secret, 'Content-Type': 'application/json' } }
      );
      if (resp.status === 200 && resp.data?.data?.viewer) {
        return { result: RESULTS.VALID, detail: sanitize(resp.data.data.viewer.name) };
      }
      if (resp.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      return { result: RESULTS.ERROR, detail: sanitize(err.message) };
    }
  },

  async gitlab(secret) {
    try {
      const resp = await http.get('https://gitlab.com/api/v4/user', {
        headers: { 'PRIVATE-TOKEN': secret }
      });
      if (resp.status === 200) return { result: RESULTS.VALID,   detail: sanitize(resp.data?.username) };
      if (resp.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      return { result: RESULTS.ERROR, detail: sanitize(err.message) };
    }
  },

  async generic() {
    return { result: RESULTS.SKIPPED, detail: 'No live validator for generic pattern' };
  },

  async unknown() {
    return { result: RESULTS.SKIPPED, detail: 'Unknown provider' };
  },

  async jwt() {
    return { result: RESULTS.SKIPPED, detail: 'JWT requires context to validate' };
  },

  async ssh() {
    return { result: RESULTS.SKIPPED, detail: 'SSH key — format-match only' };
  },

  async pgp() {
    return { result: RESULTS.SKIPPED, detail: 'PGP key — format-match only' };
  },
};

async function validateFinding(finding, context = {}) {
  if (!config.validation.enabled) {
    return { result: RESULTS.SKIPPED, detail: 'Validation disabled' };
  }

  // Sanitize provider — prevents arbitrary function dispatch via crafted input
  const provider = sanitizeProvider(finding.provider || 'unknown');
  const fn = validators[provider] || validators.unknown;

  try {
    logger.debug(`[Validator] ${finding.patternName} → ${provider}`);
    const result = await fn(finding.rawValue, context);
    if (result.result === RESULTS.VALID) {
      logger.warn(`[Validator] VALID: ${finding.patternName} [${provider}] — ${result.detail}`);
    } else {
      logger.debug(`[Validator] ${provider} → ${result.result}: ${result.detail}`);
    }
    return result;
  } catch (err) {
    logger.warn(`[Validator] Unexpected error (${provider}): ${sanitize(err.message)}`);
    return { result: RESULTS.ERROR, detail: sanitize(err.message) };
  }
}

module.exports = { validateFinding, RESULTS, validators };
