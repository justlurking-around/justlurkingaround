'use strict';

/**
 * SQLite Backend — Termux-friendly, zero-config, fast
 *
 * Uses better-sqlite3 (synchronous, no server needed, works on Termux/Android)
 * Auto-migrates schema on first run.
 * Falls back to JSONL if better-sqlite3 not available.
 */

const path   = require('path');
const fs     = require('fs');
const logger = require('../utils/logger');

const DB_PATH = process.env.SQLITE_PATH || path.resolve('./data/scanner.db');

class SQLiteDB {
  constructor() {
    this._db = null;
  }

  async migrate() {
    const dir = path.dirname(DB_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    const Database = require('better-sqlite3');
    this._db = new Database(DB_PATH);
    this._db.pragma('journal_mode = WAL');   // safe concurrent writes
    this._db.pragma('synchronous = NORMAL'); // fast + safe

    this._db.exec(`
      CREATE TABLE IF NOT EXISTS repositories (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_name       TEXT NOT NULL UNIQUE,
        repo_url        TEXT,
        is_ai_generated INTEGER DEFAULT 0,
        ai_confidence   INTEGER DEFAULT 0,
        ai_signals      TEXT,
        priority        TEXT,
        first_seen      TEXT DEFAULT (datetime('now')),
        last_scanned    TEXT,
        scan_count      INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS findings (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_name         TEXT NOT NULL,
        file_path         TEXT NOT NULL,
        pattern_id        TEXT,
        pattern_name      TEXT,
        provider          TEXT,
        secret_hash       TEXT NOT NULL,
        secret_redacted   TEXT,
        entropy           REAL,
        line_number       INTEGER,
        match_context     TEXT,
        validation_result TEXT DEFAULT 'PENDING',
        validation_detail TEXT,
        is_historical     INTEGER DEFAULT 0,
        commit_sha        TEXT,
        is_paired         INTEGER DEFAULT 0,
        confidence        INTEGER DEFAULT 50,
        detected_at       TEXT DEFAULT (datetime('now')),
        validated_at      TEXT,
        UNIQUE(repo_name, file_path, secret_hash)
      );

      CREATE TABLE IF NOT EXISTS vault (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        secret_hash     TEXT NOT NULL UNIQUE,
        repo_name       TEXT,
        file_path       TEXT,
        provider        TEXT,
        pattern_name    TEXT,
        secret_enc      TEXT NOT NULL,
        validation_result TEXT,
        saved_at        TEXT DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_findings_repo      ON findings(repo_name);
      CREATE INDEX IF NOT EXISTS idx_findings_provider  ON findings(provider);
      CREATE INDEX IF NOT EXISTS idx_findings_valid     ON findings(validation_result);
      CREATE INDEX IF NOT EXISTS idx_findings_detected  ON findings(detected_at DESC);
      CREATE INDEX IF NOT EXISTS idx_vault_hash         ON vault(secret_hash);
    `);

    logger.info(`[DB] SQLite ready: ${DB_PATH}`);
  }

  upsertRepo(repo) {
    this._db.prepare(`
      INSERT INTO repositories (repo_name,repo_url,is_ai_generated,ai_confidence,ai_signals,priority,last_scanned,scan_count)
      VALUES (?,?,?,?,?,?,datetime('now'),1)
      ON CONFLICT(repo_name) DO UPDATE SET
        is_ai_generated=excluded.is_ai_generated,
        ai_confidence=excluded.ai_confidence,
        ai_signals=excluded.ai_signals,
        priority=excluded.priority,
        last_scanned=datetime('now'),
        scan_count=scan_count+1
    `).run(
      repo.repoName, repo.repoUrl,
      repo.isAI ? 1 : 0, repo.aiConfidence || 0,
      JSON.stringify(repo.aiSignals || {}),
      repo.priority
    );
  }

  insertFinding(f) {
    try {
      this._db.prepare(`
        INSERT INTO findings
          (repo_name,file_path,pattern_id,pattern_name,provider,secret_hash,
           secret_redacted,entropy,line_number,match_context,validation_result,
           validation_detail,is_historical,commit_sha,is_paired,confidence,validated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(repo_name,file_path,secret_hash) DO UPDATE SET
          validation_result=excluded.validation_result,
          validation_detail=excluded.validation_detail,
          validated_at=excluded.validated_at
      `).run(
        f.repoName, f.filePath, f.patternId, f.patternName, f.provider,
        f.secretHash, f.value, f.entropy, f.lineNumber, f.matchContext,
        f.validationResult, f.validationDetail,
        f.isHistorical ? 1 : 0, f.commitSha || null,
        f.isPaired ? 1 : 0, f.confidence || 50,
        f.validationResult !== 'PENDING' ? new Date().toISOString() : null
      );
    } catch (err) {
      if (!err.message?.includes('UNIQUE')) logger.warn(`[DB] Insert error: ${err.message}`);
    }
  }

  insertVaultEntry(entry) {
    try {
      this._db.prepare(`
        INSERT INTO vault (secret_hash,repo_name,file_path,provider,pattern_name,secret_enc,validation_result)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(secret_hash) DO UPDATE SET
          validation_result=excluded.validation_result
      `).run(
        entry.secretHash, entry.repoName, entry.filePath,
        entry.provider, entry.patternName, entry.secretEnc, entry.validationResult
      );
    } catch {}
  }

  getStats() {
    const repos   = this._db.prepare('SELECT COUNT(*) as c FROM repositories').get().c;
    const findings= this._db.prepare('SELECT COUNT(*) as c FROM findings').get().c;
    const valid   = this._db.prepare("SELECT COUNT(*) as c FROM findings WHERE validation_result='VALID'").get().c;
    const vault   = this._db.prepare('SELECT COUNT(*) as c FROM vault').get().c;
    const rows    = this._db.prepare(
      "SELECT provider, COUNT(*) as c FROM findings GROUP BY provider ORDER BY c DESC LIMIT 10"
    ).all();
    const topProviders = {};
    for (const r of rows) topProviders[r.provider] = r.c;
    return { repositories: repos, findings, validSecrets: valid, vaultEntries: vault, topProviders };
  }

  getRecentFindings(limit = 50, filters = {}) {
    let q = 'SELECT * FROM findings';
    const params = [];
    const where  = [];
    if (filters.provider) { where.push('provider=?');            params.push(filters.provider); }
    if (filters.status)   { where.push('validation_result=?');   params.push(filters.status); }
    if (filters.repo)     { where.push('repo_name LIKE ?');       params.push(`%${filters.repo}%`); }
    if (where.length) q += ' WHERE ' + where.join(' AND ');
    q += ` ORDER BY detected_at DESC LIMIT ?`;
    params.push(limit);
    return this._db.prepare(q).all(...params);
  }

  getVaultEntries(limit = 50) {
    return this._db.prepare('SELECT * FROM vault ORDER BY saved_at DESC LIMIT ?').all(limit);
  }

  async close() {
    if (this._db) { this._db.close(); this._db = null; }
  }
}

module.exports = SQLiteDB;
