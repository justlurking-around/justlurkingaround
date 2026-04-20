'use strict';

const axios = require('axios');
const axiosRetry = require('axios-retry').default || require('axios-retry');
const rateLimit = require('axios-rate-limit');
const config = require('../../config/default');
const logger = require('./logger');

/**
 * Build a GitHub API client with rate limiting, retry, and ETag support.
 */
function createGitHubClient(token) {
  const tok = token || config.github.token;

  const headers = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'ai-secret-scanner/1.0'
  };
  if (tok) {
    headers['Authorization'] = `token ${tok}`;
  }

  // 60 req/min unauthenticated, 5000/hr authenticated → safe at 1 req/sec
  const http = rateLimit(
    axios.create({
      baseURL: config.github.apiBase,
      timeout: 15000,
      headers
    }),
    { maxRPS: tok ? 8 : 1 }
  );

  axiosRetry(http, {
    retries: 3,
    retryDelay: (retryCount, error) => {
      // Respect Retry-After header on 403/429
      const retryAfter = error?.response?.headers?.['retry-after'];
      if (retryAfter) {
        const wait = parseInt(retryAfter) * 1000 + 500;
        logger.warn(`Rate limited — retrying in ${wait}ms`);
        return wait;
      }
      return axiosRetry.exponentialDelay(retryCount);
    },
    retryCondition: (error) => {
      if (!error.response) return true; // network error
      const status = error.response.status;
      if (status === 403 || status === 429) return true;
      if (status >= 500) return true;
      return false;
    }
  });

  return http;
}

// Singleton client
let _client = null;
function getClient() {
  if (!_client) _client = createGitHubClient();
  return _client;
}

module.exports = { createGitHubClient, getClient };
