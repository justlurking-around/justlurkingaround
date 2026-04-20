'use strict';

/**
 * Security utilities — protection layers
 *
 * Covers:
 *  - Input sanitization (all user-supplied strings)
 *  - RepoName validation (prevent path traversal)
 *  - URL validation (prevent SSRF)
 *  - Rate limiting per IP (API endpoints)
 *  - Shell injection prevention
 *  - Log injection prevention (strip ANSI + control chars)
 */

// ── Input sanitization ────────────────────────────────────────────────────────

/**
 * Sanitize a GitHub repo name (owner/repo format)
 * Prevents path traversal: ../../../etc/passwd
 */
function sanitizeRepoName(name) {
  if (!name || typeof name !== 'string') return null;
  // Allow only alphanumeric, hyphens, underscores, dots, single slash
  const clean = name.trim().replace(/[^a-zA-Z0-9\-_.\/]/g, '');
  // Must match owner/repo exactly
  if (!/^[a-zA-Z0-9_.-]{1,100}\/[a-zA-Z0-9_.-]{1,100}$/.test(clean)) return null;
  // Prevent path traversal
  if (clean.includes('..') || clean.includes('./') || clean.startsWith('/')) return null;
  return clean;
}

/**
 * Sanitize a GitHub URL
 * Only allows https://github.com/* URLs
 */
function sanitizeGitHubUrl(url) {
  if (!url || typeof url !== 'string') return null;
  // Strip query + fragment first so regex matches cleanly
  const clean = url.trim().split('?')[0].split('#')[0];
  if (!/^https:\/\/github\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+(\/.*)?$/.test(clean)) {
    return null;
  }
  if (clean.includes('@')) return null;
  return clean;
}

/**
 * Sanitize a file path (prevent path traversal in reports/vault)
 */
function sanitizeFilePath(p) {
  if (!p || typeof p !== 'string') return 'unknown';
  // Strip everything before the last safe segment
  const clean = p.replace(/\.\.\//g, '').replace(/\\/g, '/').trim();
  // Max length
  return clean.substring(0, 500);
}

/**
 * Sanitize a string for safe logging (strip ANSI, control chars, newlines)
 * Prevents log injection attacks
 */
function sanitizeForLog(val, maxLen = 200) {
  if (!val) return '';
  return String(val)
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // control chars
    .replace(/\x1B\[[0-9;]*[mGKHF]/g, '')               // ANSI escape codes
    .replace(/[\r\n]+/g, ' ')                            // collapse newlines
    .trim()
    .substring(0, maxLen);
}

/**
 * Sanitize a string for safe shell argument use
 * Use this if you MUST pass user input to execSync (prefer never doing this)
 */
function sanitizeForShell(val) {
  if (!val || typeof val !== 'string') return '';
  // Remove shell metacharacters
  return val.replace(/[;&|`$<>\\!*?{}()\[\]'"]/g, '').trim().substring(0, 200);
}

/**
 * Validate provider name (prevent arbitrary validator dispatch)
 */
const VALID_PROVIDERS = new Set([
  'openai','anthropic','github','stripe','aws','slack','sendgrid','twilio',
  'npm','discord','shopify','telegram','mailgun','heroku','huggingface',
  'linear','gitlab','jwt','ssh','ssl','generic','unknown','mysql','postgres',
  'mongodb','redis','smtp','database','kubernetes','docker','apache','http','ftp',
  'pgp','google','firebase','cloudflare','vercel','netlify','supabase','plaid',
  'salesforce','dropbox','box','cloudinary','mapbox','algolia','contentful',
  'okta','auth0','binance','coinbase','braintree','paypal','pusher','intercom',
  'zendesk','atlassian','airtable','notion','figma','segment','mixpanel',
  'amplitude','datadog','newrelic','sentry','elastic','rabbitmq',
]);

function sanitizeProvider(provider) {
  if (!provider || typeof provider !== 'string') return 'unknown';
  const clean = provider.toLowerCase().trim().replace(/[^a-z0-9_-]/g, '');
  return VALID_PROVIDERS.has(clean) ? clean : 'unknown';
}

// ── Rate limiter (for API endpoints) ─────────────────────────────────────────

class RateLimiter {
  constructor({ windowMs = 60_000, max = 60 } = {}) {
    this._window = windowMs;
    this._max    = max;
    this._hits   = new Map(); // ip -> { count, resetAt }
  }

  check(ip) {
    const now = Date.now();
    const key = sanitizeForLog(ip || 'unknown', 50);
    let rec = this._hits.get(key);

    if (!rec || now > rec.resetAt) {
      rec = { count: 0, resetAt: now + this._window };
      this._hits.set(key, rec);
    }

    rec.count++;

    // Evict old entries periodically
    if (this._hits.size > 10_000) {
      for (const [k, v] of this._hits) {
        if (now > v.resetAt) this._hits.delete(k);
      }
    }

    return {
      allowed:   rec.count <= this._max,
      remaining: Math.max(0, this._max - rec.count),
      resetAt:   rec.resetAt,
    };
  }

  middleware() {
    return (req, res, next) => {
      const ip     = req.ip || req.connection?.remoteAddress || 'unknown';
      const result = this.check(ip);
      res.setHeader('X-RateLimit-Limit',     this._max);
      res.setHeader('X-RateLimit-Remaining', result.remaining);
      res.setHeader('X-RateLimit-Reset',     Math.ceil(result.resetAt / 1000));

      if (!result.allowed) {
        return res.status(429).json({ error: 'Too many requests', retryAfter: Math.ceil((result.resetAt - Date.now()) / 1000) });
      }
      next();
    };
  }
}

// ── SSRF prevention ───────────────────────────────────────────────────────────

const BLOCKED_HOSTS = new Set([
  'localhost', '127.0.0.1', '0.0.0.0', '::1',
  '169.254.169.254',    // AWS metadata
  '169.254.170.2',      // ECS metadata
  'metadata.google.internal',
  '100.100.100.200',    // Alibaba metadata
]);

const BLOCKED_IP_RANGES = [
  /^10\./,              // RFC1918
  /^172\.(1[6-9]|2\d|3[01])\./,  // RFC1918
  /^192\.168\./,        // RFC1918
  /^127\./,             // loopback
  /^169\.254\./,        // link-local
  /^fc00:/i,            // IPv6 ULA
  /^fe80:/i,            // IPv6 link-local
];

function isSafeHost(hostname) {
  if (!hostname) return false;
  const h = hostname.toLowerCase().trim();
  if (BLOCKED_HOSTS.has(h)) return false;
  if (BLOCKED_IP_RANGES.some(re => re.test(h))) return false;
  return true;
}

/**
 * Validate a URL is safe for outbound requests (prevents SSRF)
 * Only allows https:// to public hosts
 */
function isSafeUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return false;
    if (!isSafeHost(parsed.hostname)) return false;
    if (parsed.username || parsed.password) return false; // no embedded creds
    return true;
  } catch { return false; }
}

module.exports = {
  sanitizeRepoName,
  sanitizeGitHubUrl,
  sanitizeFilePath,
  sanitizeForLog,
  sanitizeForShell,
  sanitizeProvider,
  isSafeUrl,
  isSafeHost,
  RateLimiter,
  VALID_PROVIDERS,
};
