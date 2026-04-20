'use strict';

/**
 * PHASE 9 — Validation Engine
 *
 * Validates detected secrets via live API calls.
 * Uses axios-retry with exponential backoff.
 * Never stores plain-text secrets — validates and records status only.
 *
 * Validation results:
 *   VALID     — secret is live and accepted by the provider API
 *   INVALID   — secret format matches but API rejected it
 *   ERROR     — API call failed (network, rate limit, etc.)
 *   SKIPPED   — no validator for this provider
 */

const axios = require('axios');
const axiosRetry = require('axios-retry').default || require('axios-retry');
const config = require('../../config/default');
const logger = require('../utils/logger');

const RESULTS = {
  VALID:   'VALID',
  INVALID: 'INVALID',
  ERROR:   'ERROR',
  SKIPPED: 'SKIPPED'
};

// Build a hardened validator axios instance
function makeClient() {
  const client = axios.create({ timeout: config.validation.timeout });
  axiosRetry(client, {
    retries: config.validation.maxRetries,
    retryDelay: axiosRetry.exponentialDelay,
    retryCondition: err => {
      if (!err.response) return true;
      return err.response.status === 429 || err.response.status >= 500;
    }
  });
  return client;
}

const http = makeClient();

// ─── Provider Validators ──────────────────────────────────────────────────────

const validators = {

  async openai(secret) {
    try {
      const resp = await http.get('https://api.openai.com/v1/models', {
        headers: { Authorization: `Bearer ${secret}` }
      });
      return { result: resp.status === 200 ? RESULTS.VALID : RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      if (err.response?.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      if (err.response?.status === 429) return { result: RESULTS.VALID, detail: 'Rate limited (key is valid)' };
      return { result: RESULTS.ERROR, detail: err.message };
    }
  },

  async anthropic(secret) {
    try {
      const resp = await http.get('https://api.anthropic.com/v1/models', {
        headers: { 'x-api-key': secret, 'anthropic-version': '2023-06-01' }
      });
      return { result: resp.status === 200 ? RESULTS.VALID : RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      if (err.response?.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.ERROR, detail: err.message };
    }
  },

  async github(secret) {
    try {
      const resp = await http.get('https://api.github.com/user', {
        headers: {
          Authorization: `token ${secret}`,
          'User-Agent': 'ai-secret-scanner/1.0'
        }
      });
      const login = resp.data?.login;
      return { result: resp.status === 200 ? RESULTS.VALID : RESULTS.INVALID, detail: login ? `User: ${login}` : `HTTP ${resp.status}` };
    } catch (err) {
      if (err.response?.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.ERROR, detail: err.message };
    }
  },

  async stripe(secret) {
    try {
      const resp = await http.get('https://api.stripe.com/v1/charges?limit=1', {
        auth: { username: secret, password: '' }
      });
      return { result: resp.status === 200 ? RESULTS.VALID : RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      if (err.response?.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      if (err.response?.status === 403) return { result: RESULTS.VALID, detail: 'Forbidden (restricted key, but valid)' };
      return { result: RESULTS.ERROR, detail: err.message };
    }
  },

  async aws(secret, context) {
    // AWS validation requires Access Key ID + Secret together
    // We check if the access key format is valid via STS GetCallerIdentity
    const accessKeyId = context?.accessKeyId;
    if (!accessKeyId) return { result: RESULTS.SKIPPED, detail: 'Need Access Key ID for AWS validation' };

    try {
      const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
      const sts = new STSClient({
        region: 'us-east-1',
        credentials: { accessKeyId, secretAccessKey: secret }
      });
      const data = await sts.send(new GetCallerIdentityCommand({}));
      return { result: RESULTS.VALID, detail: `Account: ${data.Account}` };
    } catch (err) {
      if (err.name === 'InvalidClientTokenId' || err.name === 'SignatureDoesNotMatch') {
        return { result: RESULTS.INVALID, detail: err.name };
      }
      return { result: RESULTS.ERROR, detail: err.message };
    }
  },

  async slack(secret) {
    try {
      const resp = await http.post('https://slack.com/api/auth.test', null, {
        headers: { Authorization: `Bearer ${secret}` }
      });
      if (resp.data?.ok) return { result: RESULTS.VALID, detail: `Team: ${resp.data.team}` };
      return { result: RESULTS.INVALID, detail: resp.data?.error || 'ok=false' };
    } catch (err) {
      return { result: RESULTS.ERROR, detail: err.message };
    }
  },

  async sendgrid(secret) {
    try {
      const resp = await http.get('https://api.sendgrid.com/v3/user/account', {
        headers: { Authorization: `Bearer ${secret}` }
      });
      return { result: resp.status === 200 ? RESULTS.VALID : RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      if (err.response?.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.ERROR, detail: err.message };
    }
  },

  async twilio(secret) {
    // Twilio needs AccountSID + AuthToken — skip if we only have one
    return { result: RESULTS.SKIPPED, detail: 'Twilio requires SID+Token pair' };
  },

  async npm(secret) {
    try {
      const resp = await http.get('https://registry.npmjs.org/-/whoami', {
        headers: { Authorization: `Bearer ${secret}` }
      });
      return { result: resp.status === 200 ? RESULTS.VALID : RESULTS.INVALID, detail: resp.data?.username || `HTTP ${resp.status}` };
    } catch (err) {
      if (err.response?.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.ERROR, detail: err.message };
    }
  },

  async discord(secret) {
    try {
      const resp = await http.get('https://discord.com/api/v10/users/@me', {
        headers: { Authorization: `Bot ${secret}` }
      });
      return { result: resp.status === 200 ? RESULTS.VALID : RESULTS.INVALID, detail: resp.data?.username || `HTTP ${resp.status}` };
    } catch (err) {
      if (err.response?.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.ERROR, detail: err.message };
    }
  },

  async shopify(secret) {
    // Shopify tokens are shop-scoped — skip without shop domain
    return { result: RESULTS.SKIPPED, detail: 'Shopify requires shop domain' };
  },

  async telegram(secret) {
    try {
      const resp = await http.get(`https://api.telegram.org/bot${secret}/getMe`);
      if (resp.data?.ok) return { result: RESULTS.VALID, detail: `Bot: @${resp.data.result?.username}` };
      return { result: RESULTS.INVALID, detail: resp.data?.description };
    } catch (err) {
      if (err.response?.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.ERROR, detail: err.message };
    }
  },

  async mailgun(secret) {
    try {
      const resp = await http.get('https://api.mailgun.net/v3/domains', {
        auth: { username: 'api', password: secret }
      });
      return { result: resp.status === 200 ? RESULTS.VALID : RESULTS.INVALID, detail: `HTTP ${resp.status}` };
    } catch (err) {
      if (err.response?.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.ERROR, detail: err.message };
    }
  },

  async heroku(secret) {
    try {
      const resp = await http.get('https://api.heroku.com/account', {
        headers: {
          Authorization: `Bearer ${secret}`,
          Accept: 'application/vnd.heroku+json; version=3'
        }
      });
      return { result: resp.status === 200 ? RESULTS.VALID : RESULTS.INVALID, detail: resp.data?.email || `HTTP ${resp.status}` };
    } catch (err) {
      if (err.response?.status === 401) return { result: RESULTS.INVALID, detail: 'Unauthorized' };
      return { result: RESULTS.ERROR, detail: err.message };
    }
  },

  async generic(secret) {
    // No specific validator — rely on entropy/pattern match alone
    return { result: RESULTS.SKIPPED, detail: 'Generic pattern — no live validation' };
  },

  async unknown(secret) {
    return { result: RESULTS.SKIPPED, detail: 'Unknown provider' };
  },

  async jwt(secret) {
    return { result: RESULTS.SKIPPED, detail: 'JWT secrets require context to validate' };
  },

  async ssh(secret) {
    return { result: RESULTS.SKIPPED, detail: 'SSH keys validated by format only' };
  },
};

/**
 * Validate a finding
 * @param {object} finding - from scanner engine
 * @param {object} [context] - extra context (e.g. accessKeyId for AWS)
 * @returns {Promise<{ result: string, detail: string }>}
 */
async function validateFinding(finding, context = {}) {
  if (!config.validation.enabled) {
    return { result: RESULTS.SKIPPED, detail: 'Validation disabled' };
  }

  const provider = finding.provider || 'unknown';
  const validatorFn = validators[provider] || validators.unknown;

  try {
    logger.debug(`[Validator] Validating ${finding.patternName} via ${provider}`);
    const result = await validatorFn(finding.rawValue, context);
    logger.info(`[Validator] ${finding.patternName} [${provider}] → ${result.result} (${result.detail})`);
    return result;
  } catch (err) {
    logger.warn(`[Validator] Unexpected error for ${provider}: ${err.message}`);
    return { result: RESULTS.ERROR, detail: err.message };
  }
}

module.exports = { validateFinding, RESULTS, validators };
