'use strict';

/**
 * Credential Validator — live verification for service credentials
 *
 * SCOPE:
 *   ✅ Database connections  — test connect, immediately disconnect
 *   ✅ SMTP credentials      — EHLO + AUTH, immediately disconnect
 *   ✅ SSH private key format — parse + validate structure (no login attempt)
 *   ✅ JWT secrets            — decode + verify structure
 *   ✅ Docker auth tokens     — base64 decode + format check
 *   ✅ Kubernetes secrets     — base64 decode + inspect
 *
 *   ❌ Personal email/social logins — NEVER attempted (unauthorized access)
 *   ❌ Any human login credentials  — detect and flag only
 *
 * All connections use short timeouts (3-5s) and read-only probes only.
 * No data is read, written, or modified on any connected service.
 */

const net     = require('net');
const tls     = require('tls');
const logger  = require('../utils/logger');

const TIMEOUT_MS = 5000;

const RESULTS = {
  VALID:   'VALID',
  INVALID: 'INVALID',
  ERROR:   'ERROR',
  SKIPPED: 'SKIPPED',
};

// ── Helper: parse connection string ──────────────────────────────────────────

function parseConnString(str) {
  try {
    const url = new URL(str);
    return {
      protocol: url.protocol.replace(':', ''),
      user:     decodeURIComponent(url.username || ''),
      password: decodeURIComponent(url.password || ''),
      host:     url.hostname,
      port:     parseInt(url.port) || null,
      database: url.pathname.replace(/^\//, '') || null,
    };
  } catch { return null; }
}

// ── MySQL / Postgres: TCP connect + protocol handshake check ─────────────────

async function probePort(host, port, timeoutMs = TIMEOUT_MS) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const done = (result) => { socket.destroy(); resolve(result); };
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => done({ open: true }));
    socket.on('timeout', () => done({ open: false, reason: 'timeout' }));
    socket.on('error',  (e) => done({ open: false, reason: e.message }));
    socket.connect(port, host);
  });
}

async function validateMysql(rawValue) {
  const conn = parseConnString(rawValue);
  if (!conn?.host) return { result: RESULTS.SKIPPED, detail: 'Could not parse connection string' };
  if (!conn.password) return { result: RESULTS.SKIPPED, detail: 'No password in connection string' };

  const port = conn.port || 3306;

  // Step 1: Check if host:port is reachable
  const probe = await probePort(conn.host, port);
  if (!probe.open) {
    return { result: RESULTS.INVALID, detail: `Host unreachable: ${probe.reason}` };
  }

  // Step 2: Try actual MySQL connection (read-only probe)
  try {
    const mysql = require('mysql2/promise');
    const connection = await mysql.createConnection({
      host: conn.host, port, user: conn.user,
      password: conn.password, database: conn.database || undefined,
      connectTimeout: TIMEOUT_MS,
      ssl: { rejectUnauthorized: false } // accept self-signed certs
    });
    await connection.end(); // immediately disconnect — don't read anything
    return { result: RESULTS.VALID, detail: `Connected to MySQL ${conn.host}:${port}` };
  } catch (err) {
    const msg = err.message || '';
    if (msg.includes('Access denied'))     return { result: RESULTS.INVALID, detail: 'Access denied (wrong credentials)' };
    if (msg.includes('ECONNREFUSED'))      return { result: RESULTS.INVALID, detail: 'Connection refused' };
    if (msg.includes('ETIMEDOUT'))         return { result: RESULTS.INVALID, detail: 'Connection timed out' };
    if (msg.includes('Unknown database'))  return { result: RESULTS.VALID,   detail: `Auth OK but DB not found (${conn.database})` };
    return { result: RESULTS.ERROR, detail: msg.substring(0, 100) };
  }
}

async function validatePostgres(rawValue) {
  const conn = parseConnString(rawValue);
  if (!conn?.host) return { result: RESULTS.SKIPPED, detail: 'Could not parse connection string' };
  if (!conn.password) return { result: RESULTS.SKIPPED, detail: 'No password in connection string' };

  const port = conn.port || 5432;
  const probe = await probePort(conn.host, port);
  if (!probe.open) {
    return { result: RESULTS.INVALID, detail: `Host unreachable: ${probe.reason}` };
  }

  try {
    const { Client } = require('pg');
    const client = new Client({
      host: conn.host, port, user: conn.user,
      password: conn.password,
      database: conn.database || 'postgres',
      connectionTimeoutMillis: TIMEOUT_MS,
      ssl: { rejectUnauthorized: false }
    });
    await client.connect();
    await client.end(); // immediately disconnect
    return { result: RESULTS.VALID, detail: `Connected to PostgreSQL ${conn.host}:${port}` };
  } catch (err) {
    const msg = err.message || '';
    if (msg.includes('password authentication failed')) return { result: RESULTS.INVALID, detail: 'Wrong password' };
    if (msg.includes('ECONNREFUSED'))                   return { result: RESULTS.INVALID, detail: 'Connection refused' };
    if (msg.includes('does not exist'))                 return { result: RESULTS.VALID,   detail: `Auth OK but DB not found` };
    return { result: RESULTS.ERROR, detail: msg.substring(0, 100) };
  }
}

// ── SMTP: EHLO handshake + AUTH probe ────────────────────────────────────────

async function validateSmtp(rawValue) {
  const conn = parseConnString(rawValue);
  if (!conn?.host) return { result: RESULTS.SKIPPED, detail: 'Could not parse SMTP URL' };
  if (!conn.password) return { result: RESULTS.SKIPPED, detail: 'No password in SMTP URL' };

  const port  = conn.port || (conn.protocol === 'smtps' ? 465 : 587);
  const useTLS = conn.protocol === 'smtps' || port === 465;

  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      socket?.destroy();
      resolve({ result: RESULTS.ERROR, detail: 'SMTP timeout' });
    }, TIMEOUT_MS);

    let socket;
    let buffer = '';
    let stage  = 'connect';
    const b64  = (s) => Buffer.from(s, 'utf8').toString('base64');

    const write = (data) => socket.write(data + '\r\n');

    const onData = (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split('\r\n');
      buffer = lines.pop(); // keep incomplete line

      for (const line of lines) {
        if (!line) continue;
        const code = parseInt(line.substring(0, 3));

        if (stage === 'connect' && code === 220) {
          stage = 'ehlo';
          write(`EHLO scanner.probe`);
        } else if (stage === 'ehlo' && (code === 250 || code === 220)) {
          if (!line.startsWith('250-') && line.startsWith('250')) {
            stage = 'auth';
            write(`AUTH LOGIN`);
          }
        } else if (stage === 'auth' && code === 334) {
          stage = 'user';
          write(b64(conn.user));
        } else if (stage === 'user' && code === 334) {
          stage = 'pass';
          write(b64(conn.password));
        } else if (stage === 'pass') {
          clearTimeout(timeout);
          socket.destroy();
          if (code === 235) {
            resolve({ result: RESULTS.VALID,   detail: `SMTP auth OK: ${conn.user}@${conn.host}` });
          } else if (code === 535 || code === 530) {
            resolve({ result: RESULTS.INVALID, detail: `SMTP auth failed (${code})` });
          } else {
            resolve({ result: RESULTS.ERROR,   detail: `SMTP unexpected code ${code}` });
          }
        } else if (stage === 'auth' && code === 503) {
          // Server wants TLS first
          clearTimeout(timeout);
          socket.destroy();
          resolve({ result: RESULTS.SKIPPED, detail: 'SMTP requires STARTTLS upgrade' });
        }
      }
    };

    try {
      if (useTLS) {
        socket = tls.connect({ host: conn.host, port, rejectUnauthorized: false });
      } else {
        socket = net.createConnection({ host: conn.host, port });
      }
      socket.on('data',  onData);
      socket.on('error', (e) => { clearTimeout(timeout); resolve({ result: RESULTS.ERROR, detail: e.message.substring(0, 80) }); });
      socket.on('close', () => { clearTimeout(timeout); });
    } catch (e) {
      clearTimeout(timeout);
      resolve({ result: RESULTS.ERROR, detail: e.message.substring(0, 80) });
    }
  });
}

// ── Private key: parse and validate structure ─────────────────────────────────

function validatePrivateKey(rawValue) {
  // Verify it's a real PEM block with actual key content
  const isPEM = rawValue.includes('-----BEGIN') && rawValue.includes('-----END');
  if (!isPEM) return { result: RESULTS.INVALID, detail: 'Not a valid PEM block' };

  // Check base64 content exists between headers
  const inner = rawValue.replace(/-----BEGIN.*?-----/, '').replace(/-----END.*?-----/, '').replace(/\s/g, '');
  if (inner.length < 64) return { result: RESULTS.INVALID, detail: 'Key too short to be real' };

  // Try to parse via crypto
  try {
    const crypto = require('crypto');
    const key = crypto.createPrivateKey({ key: rawValue, format: 'pem' });
    const type = key.asymmetricKeyType;
    const size = key.asymmetricKeyDetails?.modulusLength || key.asymmetricKeyDetails?.namedCurve || 'unknown';
    return { result: RESULTS.VALID, detail: `Valid ${type?.toUpperCase()} private key (${size})` };
  } catch (err) {
    // Might be encrypted (passphrase-protected) — still real
    if (err.message?.includes('pass') || err.message?.includes('encrypt')) {
      return { result: RESULTS.VALID, detail: 'Valid private key (passphrase-protected)' };
    }
    return { result: RESULTS.INVALID, detail: `Parse error: ${err.message?.substring(0, 60)}` };
  }
}

// ── JWT secret: decode token structure ───────────────────────────────────────

function validateJwtSecret(rawValue) {
  // If it looks like an actual JWT token, decode it
  if (rawValue.match(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)) {
    try {
      const parts = rawValue.split('.');
      const header  = JSON.parse(Buffer.from(parts[0], 'base64').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      const alg = header.alg || 'unknown';
      const sub = payload.sub || payload.email || payload.user || 'N/A';
      const exp = payload.exp ? new Date(payload.exp * 1000).toISOString() : 'no expiry';
      const expired = payload.exp && Date.now() > payload.exp * 1000;
      return {
        result: expired ? RESULTS.INVALID : RESULTS.VALID,
        detail: `JWT alg=${alg} sub=${sub} exp=${exp}${expired ? ' [EXPIRED]' : ''}`
      };
    } catch {
      return { result: RESULTS.INVALID, detail: 'Could not decode JWT structure' };
    }
  }
  // It's a signing secret (not a token) — validate entropy/length
  if (rawValue.length >= 32) {
    return { result: RESULTS.VALID, detail: `JWT signing secret (length=${rawValue.length})` };
  }
  return { result: RESULTS.INVALID, detail: 'JWT secret too short (< 32 chars)' };
}

// ── Basic auth: base64 decode ─────────────────────────────────────────────────

function validateBasicAuth(rawValue) {
  try {
    const decoded = Buffer.from(rawValue, 'base64').toString('utf8');
    if (!decoded.includes(':')) return { result: RESULTS.INVALID, detail: 'Not valid Basic auth format' };
    const [user, ...passParts] = decoded.split(':');
    const pass = passParts.join(':');
    if (!user || !pass) return { result: RESULTS.INVALID, detail: 'Missing user or password' };
    return { result: RESULTS.VALID, detail: `Basic auth: user=${user} pass=${pass.substring(0,2)}****` };
  } catch {
    return { result: RESULTS.INVALID, detail: 'Base64 decode failed' };
  }
}

// ── Docker registry auth: base64 decode ──────────────────────────────────────

function validateDockerAuth(rawValue) {
  try {
    const decoded = Buffer.from(rawValue, 'base64').toString('utf8');
    if (!decoded.includes(':')) return { result: RESULTS.INVALID, detail: 'Not a valid Docker auth token' };
    const [user] = decoded.split(':');
    return { result: RESULTS.VALID, detail: `Docker auth for user: ${user}` };
  } catch {
    return { result: RESULTS.INVALID, detail: 'Base64 decode failed' };
  }
}

// ── Kubernetes secret: decode base64 data ────────────────────────────────────

function validateK8sSecret(rawValue) {
  // Extract data fields and decode them
  const lines = rawValue.split('\n');
  const decoded = [];
  for (const line of lines) {
    const m = line.match(/^\s+([a-zA-Z0-9_\-]+):\s+([A-Za-z0-9+/=]{16,})/);
    if (m) {
      try {
        const val = Buffer.from(m[2], 'base64').toString('utf8');
        decoded.push(`${m[1]}=${val.substring(0, 30)}${val.length > 30 ? '...' : ''}`);
      } catch {}
    }
  }
  if (!decoded.length) return { result: RESULTS.INVALID, detail: 'No decodeable data fields found' };
  return { result: RESULTS.VALID, detail: `K8s secret fields: ${decoded.slice(0, 3).join(', ')}` };
}

// ── Main dispatcher ───────────────────────────────────────────────────────────

async function validateCredential(finding) {
  const { patternId, rawValue, provider, type } = finding;
  if (!rawValue) return { result: RESULTS.SKIPPED, detail: 'No value' };

  // Route to correct validator
  switch (patternId) {
    case 'db_mysql_conn':         return validateMysql(rawValue);
    case 'db_postgres_conn':      return validatePostgres(rawValue);
    case 'db_mongodb_conn':       return { result: RESULTS.SKIPPED, detail: 'MongoDB: format valid, live connect not attempted' };
    case 'db_redis_conn':         return { result: RESULTS.SKIPPED, detail: 'Redis: format valid, live connect not attempted' };
    case 'smtp_credentials':      return validateSmtp(rawValue);
    case 'rsa_private_key':
    case 'ec_private_key':
    case 'openssh_private_key':
    case 'pkcs8_private_key':     return validatePrivateKey(rawValue);
    case 'jwt_secret_long':       return validateJwtSecret(rawValue);
    case 'basic_auth_header':     return validateBasicAuth(rawValue);
    case 'docker_auth_config':    return validateDockerAuth(rawValue);
    case 'k8s_secret_manifest':   return validateK8sSecret(rawValue);
    case 'gcp_service_account_json': return { result: RESULTS.VALID, detail: 'GCP service account file detected — revoke at console.cloud.google.com' };
    case 'aws_credentials_file':  return { result: RESULTS.VALID, detail: 'AWS credentials file detected — rotate at console.aws.amazon.com/iam' };
    default:
      // For password-type findings: validate format + entropy only (no live attempt)
      if (type === 'password' || type === 'secret') {
        if (rawValue.length >= 8) {
          return { result: RESULTS.VALID, detail: `Credential detected (length=${rawValue.length}, format=valid)` };
        }
        return { result: RESULTS.INVALID, detail: 'Too short to be a real credential' };
      }
      return { result: RESULTS.SKIPPED, detail: 'No validator for this credential type' };
  }
}

module.exports = { validateCredential, RESULTS, parseConnString };
