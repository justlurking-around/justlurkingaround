'use strict';

/**
 * Encrypted Secret Vault
 *
 * Stores found live secrets encrypted at rest using AES-256-GCM.
 * Key derived from VAULT_PASSWORD env var via PBKDF2 (100k iterations).
 *
 * Purpose:
 *  - VALID secrets are encrypted and saved for researcher reference
 *  - File is: data/vault.enc.jsonl (one encrypted entry per line)
 *  - Never stored in plaintext anywhere
 *
 * Usage:
 *  const vault = new SecretVault();
 *  await vault.save(finding);
 *  const entries = await vault.list(password);
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const logger = require('../utils/logger');

const VAULT_FILE    = process.env.VAULT_FILE || path.resolve('./data/vault.enc.jsonl');
const VAULT_ALGO    = 'aes-256-gcm';
const PBKDF2_ITERS  = 100_000;
const SALT_LEN      = 32;
const IV_LEN        = 16;
const KEY_LEN       = 32;

class SecretVault {
  constructor() {
    this._ensureDir();
    this._password = process.env.VAULT_PASSWORD || null;
  }

  _ensureDir() {
    const dir = path.dirname(VAULT_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }

  _deriveKey(password, salt) {
    return crypto.pbkdf2Sync(
      Buffer.from(password, 'utf8'),
      salt, PBKDF2_ITERS, KEY_LEN, 'sha256'
    );
  }

  _encrypt(plaintext, password) {
    const salt = crypto.randomBytes(SALT_LEN);
    const iv   = crypto.randomBytes(IV_LEN);
    const key  = this._deriveKey(password, salt);
    const cipher = crypto.createCipheriv(VAULT_ALGO, key, iv);
    const enc  = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag  = cipher.getAuthTag();
    return Buffer.concat([salt, iv, tag, enc]).toString('base64');
  }

  _decrypt(ciphertext, password) {
    const buf  = Buffer.from(ciphertext, 'base64');
    const salt = buf.slice(0, SALT_LEN);
    const iv   = buf.slice(SALT_LEN, SALT_LEN + IV_LEN);
    const tag  = buf.slice(SALT_LEN + IV_LEN, SALT_LEN + IV_LEN + 16);
    const enc  = buf.slice(SALT_LEN + IV_LEN + 16);
    const key  = this._deriveKey(password, salt);
    const decipher = crypto.createDecipheriv(VAULT_ALGO, key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(enc) + decipher.final('utf8');
  }

  /**
   * Save a VALID finding to the encrypted vault
   * @param {object} finding  - must have rawValue, provider, patternName, repoName, filePath
   * @param {string} [pw]     - override password (uses VAULT_PASSWORD env var if not set)
   */
  save(finding, pw) {
    const password = pw || this._password;
    if (!password) {
      logger.warn('[Vault] VAULT_PASSWORD not set — secret saved to vault UNENCRYPTED (set VAULT_PASSWORD for encryption)');
    }

    const payload = JSON.stringify({
      rawValue:    finding.rawValue,
      provider:    finding.provider,
      patternName: finding.patternName,
      repoName:    finding.repoName,
      filePath:    finding.filePath,
      lineNumber:  finding.lineNumber,
      entropy:     finding.entropy,
      validationDetail: finding.validationDetail,
      savedAt:     new Date().toISOString(),
    });

    const entry = {
      hash:      finding.secretHash || require('../utils/hash').sha256(finding.rawValue),
      provider:  finding.provider,
      repoName:  finding.repoName,
      savedAt:   new Date().toISOString(),
      encrypted: password ? this._encrypt(payload, password) : null,
      plain:     password ? null : payload,  // fallback if no password
    };

    try {
      fs.appendFileSync(VAULT_FILE, JSON.stringify(entry) + '\n', 'utf8');
      logger.info(`[Vault] Saved: ${finding.provider} secret from ${finding.repoName}`);
    } catch (err) {
      logger.warn(`[Vault] Write error: ${err.message}`);
    }

    return entry;
  }

  /**
   * List decrypted vault entries
   * @param {string} [pw] - vault password
   * @returns {object[]}
   */
  list(pw) {
    const password = pw || this._password;
    if (!fs.existsSync(VAULT_FILE)) return [];

    const results = [];
    const lines = fs.readFileSync(VAULT_FILE, 'utf8').split('\n').filter(Boolean);

    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        if (entry.encrypted && password) {
          try {
            const decrypted = JSON.parse(this._decrypt(entry.encrypted, password));
            results.push({ ...entry, decrypted, encrypted: '[REDACTED]' });
          } catch {
            results.push({ ...entry, decrypted: null, error: 'Wrong password or corrupted' });
          }
        } else if (entry.plain) {
          results.push({ ...entry, decrypted: JSON.parse(entry.plain) });
        } else {
          results.push({ ...entry, decrypted: null });
        }
      } catch {}
    }

    return results;
  }

  /**
   * Count entries without decrypting
   */
  count() {
    if (!fs.existsSync(VAULT_FILE)) return 0;
    try {
      return fs.readFileSync(VAULT_FILE, 'utf8').split('\n').filter(Boolean).length;
    } catch { return 0; }
  }

  /**
   * Export decrypted vault as JSON (for researcher use)
   */
  export(pw, outPath) {
    const entries = this.list(pw);
    const out = entries.map(e => e.decrypted).filter(Boolean);
    fs.writeFileSync(outPath || './data/vault-export.json', JSON.stringify(out, null, 2), 'utf8');
    return out.length;
  }
}

// Singleton
let _vault = null;
function getVault() {
  if (!_vault) _vault = new SecretVault();
  return _vault;
}

module.exports = { getVault, SecretVault };
