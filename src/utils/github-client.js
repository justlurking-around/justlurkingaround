'use strict';

/**
 * GitHub API client
 * FIX: MaxListenersExceededWarning — bump EventEmitter limit before
 *      axios-rate-limit attaches per-request socket listeners
 */

// FIX: raise max listeners BEFORE requiring axios to prevent
// "Possible EventEmitter memory leak" warnings on concurrent scans
require('events').EventEmitter.defaultMaxListeners = 30;

const axios = require('axios');
const axiosRetry = require('axios-retry').default || require('axios-retry');
const rateLimit = require('axios-rate-limit');
const config = require('../../config/default');
const logger = require('./logger');

function createGitHubClient(token) {
  const tok = token || config.github.token || process.env.GITHUB_TOKEN || '';

  const headers = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'ai-secret-scanner/2.0.0'
  };
  if (tok) {
    headers['Authorization'] = `token ${tok}`;
  }

  // Authenticated: up to 5 000 req/hr → 8 rps safe
  // Unauthenticated: 60 req/hr → 1 rps, but GitHub abuse detection kicks in
  // at repeated bursts so we cap lower
  const http = rateLimit(
    axios.create({
      baseURL: config.github.apiBase,
      timeout: tok ? 15000 : 20000,
      headers
    }),
    { maxRPS: tok ? 8 : 1 }
  );

  axiosRetry(http, {
    retries: 3,
    retryDelay: (retryCount, error) => {
      // Respect Retry-After on 403 secondary-rate-limit and 429 primary
      const retryAfter = error?.response?.headers?.['retry-after'];
      if (retryAfter) {
        const wait = (parseInt(retryAfter, 10) || 60) * 1000 + 500;
        logger.warn(`[GHClient] Rate limited — retrying in ${Math.round(wait / 1000)}s`);
        return wait;
      }
      return axiosRetry.exponentialDelay(retryCount);
    },
    retryCondition: (error) => {
      if (!error.response) return true; // network error → retry
      const status = error.response.status;
      // 403 with Retry-After = secondary rate limit → retry
      if (status === 403 && error.response.headers?.['retry-after']) return true;
      if (status === 429) return true;
      if (status >= 500) return true;
      return false;
    },
    onRetry: (retryCount, error) => {
      logger.warn(`[GHClient] Retry ${retryCount}/3 — ${error.message}`);
    }
  });

  return http;
}

// ── Singleton with token-change support ──────────────────────────────────────
let _client = null;
let _clientToken = null;

function getClient() {
  const currentToken = process.env.GITHUB_TOKEN || config.github.token || '';
  // Recreate client if token changed (e.g. user set it in menu)
  if (!_client || _clientToken !== currentToken) {
    _client = createGitHubClient(currentToken);
    _clientToken = currentToken;
    logger.debug(`[GHClient] Client (re)created — auth=${!!currentToken}`);
  }
  return _client;
}

/** Force client reset — call after token config changes */
function resetClient() {
  _client = null;
  _clientToken = null;
}

module.exports = { createGitHubClient, getClient, resetClient };
