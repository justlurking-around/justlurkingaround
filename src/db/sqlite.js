'use strict';

/**
 * SQLite Backend — platform-adaptive
 *
 * Strategy (tried in order):
 *   1. better-sqlite3  — native, fast, synchronous (Linux/macOS/Windows)
 *   2. sql.js          — pure WebAssembly, no compilation (Termux/Android, CI, any platform)
 *   3. Falls back to JSONL automatically (handled by db/index.js factory)
 *
 * This means:
 *   - Desktop/server: uses better-sqlite3 (fastest)
 *   - Android Termux: uses sql.js (WASM, zero native deps)
 *   - Any platform:   never crashes due to native build failure
 */

const path   = require('path');
const fs     = require('fs');
const logger = require('../utils/logger');

const DB_PATH = process.env.SQLITE_PATH || path.resolve('./data/scanner.db');

// ─── Detect which SQLite driver is available ──────────────────────────────────

function detectDriver() {
  // Try native first (faster)
  try {
    require('better-sqlite3');
    return 'better-sqlite3';
  } catch {
    // Expected on Termux/Android — sql.js WASM used instead (debug only, not a problem)
    logger.debug('[SQLite] better-sqlite3 not available, using sql.js WASM fallback');
  }
  // Try WASM (Termux-safe, zero native deps)
  try {
    require('sql.js');
    return 'sql.js';
  } catch {}
  return null;
}

const DRIVER = detectDriver();
if (DRIVER) {
  logger.debug(`[SQLite] Using driver: ${DRIVER}`);
} else {
  logger.debug('[SQLite] No SQLite driver available — will use JSONL fallback');
}

// ─── Better-SQLite3 wrapper (synchronous native) ──────────────────────────────

class BetterSQLiteDB {
  constructor() { this._db = null; }

  async migrate() {
    const dir = path.dirname(DB_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const Database = require('better-sqlite3');
    this._db = new Database(DB_PATH);
    this._db.pragma('journal_mode = WAL');
    this._db.pragma('synchronous = NORMAL');
    this._applySchema();
    logger.info(`[DB] SQLite (native) ready: ${DB_PATH}`);
  }

  _applySchema() {
    this._db.exec(SCHEMA);
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
    `).run(repo.repoName, repo.repoUrl, repo.isAI?1:0, repo.aiConfidence||0,
      JSON.stringify(repo.aiSignals||{}), repo.priority);
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
        f.isHistorical?1:0, f.commitSha||null, f.isPaired?1:0, f.confidence||50,
        f.validationResult !== 'PENDING' ? new Date().toISOString() : null
      );
    } catch (err) {
      if (!err.message?.includes('UNIQUE')) logger.warn(`[DB] Insert: ${err.message}`);
    }
  }

  getStats() {
    const repos  = this._db.prepare('SELECT COUNT(*) AS c FROM repositories').get().c;
    const total  = this._db.prepare('SELECT COUNT(*) AS c FROM findings').get().c;
    const valid  = this._db.prepare("SELECT COUNT(*) AS c FROM findings WHERE validation_result='VALID'").get().c;
    const rows   = this._db.prepare("SELECT provider,COUNT(*) AS c FROM findings GROUP BY provider ORDER BY c DESC LIMIT 10").all();
    const top    = {};
    for (const r of rows) top[r.provider] = r.c;
    return { repositories: repos, findings: total, validSecrets: valid, topProviders: top };
  }

  getRecentFindings(limit = 50, filters = {}) {
    let q = 'SELECT * FROM findings';
    const params = [], where = [];
    if (filters.provider) { where.push('provider=?');          params.push(filters.provider); }
    if (filters.status)   { where.push('validation_result=?'); params.push(filters.status); }
    if (filters.repo)     { where.push('repo_name LIKE ?');    params.push(`%${filters.repo}%`); }
    if (where.length) q += ' WHERE ' + where.join(' AND ');
    q += ' ORDER BY detected_at DESC LIMIT ?';
    params.push(limit);
    return this._db.prepare(q).all(...params);
  }

  async close() {
    if (this._db) { this._db.close(); this._db = null; }
  }
}

// ─── sql.js wrapper (WASM, Termux-safe, async-compatible) ────────────────────

class SqlJsDB {
  constructor() { this._db = null; this._dirty = false; }

  async migrate() {
    const dir = path.dirname(DB_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    const initSqlJs = require('sql.js');
    const SQL = await initSqlJs();

    // Load existing DB file if it exists
    if (fs.existsSync(DB_PATH)) {
      const fileBuffer = fs.readFileSync(DB_PATH);
      this._db = new SQL.Database(fileBuffer);
    } else {
      this._db = new SQL.Database();
    }

    this._db.run(SCHEMA);
    this._save(); // write initial file
    logger.info(`[DB] SQLite (WASM/sql.js) ready: ${DB_PATH}`);

    // Auto-save every 60s if dirty
    this._saveInterval = setInterval(() => {
      if (this._dirty) this._save();
    }, 60_000);
    process.once('exit', () => { this._save(); clearInterval(this._saveInterval); });
  }

  _save() {
    if (!this._db) return;
    try {
      const data = this._db.export();
      if (!data || data.length === 0) return;
      // Use the instance path, not the module-level constant
      const dbPath = process.env.SQLITE_PATH || path.resolve('./data/scanner.db');
      fs.writeFileSync(dbPath, Buffer.from(data));
      this._dirty = false;
    } catch (err) {
      if (err.message !== 'undefined') {
        logger.warn(`[DB] SQLite save error: ${err.message}`);
      }
    }
  }

  _run(sql, params = []) {
    this._db.run(sql, params);
    this._dirty = true;
  }

  _get(sql, params = []) {
    const stmt = this._db.prepare(sql);
    stmt.bind(params);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return row;
    }
    stmt.free();
    return null;
  }

  _all(sql, params = []) {
    const results = [];
    const stmt = this._db.prepare(sql);
    stmt.bind(params);
    while (stmt.step()) results.push(stmt.getAsObject());
    stmt.free();
    return results;
  }

  upsertRepo(repo) {
    this._run(`
      INSERT INTO repositories (repo_name,repo_url,is_ai_generated,ai_confidence,ai_signals,priority,last_scanned,scan_count)
      VALUES (?,?,?,?,?,?,datetime('now'),1)
      ON CONFLICT(repo_name) DO UPDATE SET
        is_ai_generated=excluded.is_ai_generated,
        ai_confidence=excluded.ai_confidence,
        ai_signals=excluded.ai_signals,
        priority=excluded.priority,
        last_scanned=datetime('now'),
        scan_count=scan_count+1
    `, [repo.repoName, repo.repoUrl, repo.isAI?1:0, repo.aiConfidence||0,
        JSON.stringify(repo.aiSignals||{}), repo.priority]);
  }

  insertFinding(f) {
    try {
      this._run(`
        INSERT INTO findings
          (repo_name,file_path,pattern_id,pattern_name,provider,secret_hash,
           secret_redacted,entropy,line_number,match_context,validation_result,
           validation_detail,is_historical,commit_sha,is_paired,confidence,validated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(repo_name,file_path,secret_hash) DO UPDATE SET
          validation_result=excluded.validation_result,
          validation_detail=excluded.validation_detail,
          validated_at=excluded.validated_at
      `, [
        f.repoName, f.filePath, f.patternId, f.patternName, f.provider,
        f.secretHash, f.value, f.entropy, f.lineNumber, f.matchContext,
        f.validationResult, f.validationDetail,
        f.isHistorical?1:0, f.commitSha||null, f.isPaired?1:0, f.confidence||50,
        f.validationResult !== 'PENDING' ? new Date().toISOString() : null
      ]);
    } catch (err) {
      if (!String(err.message).includes('UNIQUE')) logger.warn(`[DB] Insert: ${err.message}`);
    }
  }

  getStats() {
    const repos = this._get('SELECT COUNT(*) AS c FROM repositories')?.c || 0;
    const total = this._get('SELECT COUNT(*) AS c FROM findings')?.c || 0;
    const valid = this._get("SELECT COUNT(*) AS c FROM findings WHERE validation_result='VALID'")?.c || 0;
    const rows  = this._all("SELECT provider,COUNT(*) AS c FROM findings GROUP BY provider ORDER BY c DESC LIMIT 10");
    const top   = {};
    for (const r of rows) top[r.provider] = r.c;
    return { repositories: repos, findings: total, validSecrets: valid, topProviders: top };
  }

  getRecentFindings(limit = 50, filters = {}) {
    let q = 'SELECT * FROM findings';
    const params = [], where = [];
    if (filters.provider) { where.push('provider=?');          params.push(filters.provider); }
    if (filters.status)   { where.push('validation_result=?'); params.push(filters.status); }
    if (filters.repo)     { where.push('repo_name LIKE ?');    params.push(`%${filters.repo}%`); }
    if (where.length) q += ' WHERE ' + where.join(' AND ');
    q += ' ORDER BY detected_at DESC LIMIT ?';
    params.push(limit);
    return this._all(q, params);
  }

  async close() {
    this._save();
    clearInterval(this._saveInterval);
    this._db.close();
  }
}

// ─── Shared schema ────────────────────────────────────────────────────────────

const SCHEMA = `
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

  CREATE INDEX IF NOT EXISTS idx_findings_repo     ON findings(repo_name);
  CREATE INDEX IF NOT EXISTS idx_findings_provider ON findings(provider);
  CREATE INDEX IF NOT EXISTS idx_findings_valid    ON findings(validation_result);
  CREATE INDEX IF NOT EXISTS idx_findings_detected ON findings(detected_at);
`;

// ─── Factory ──────────────────────────────────────────────────────────────────

/**
 * Create the best available SQLite instance.
 * Returns null if neither driver is available (caller falls back to JSONL).
 */
async function createSQLiteDB() {
  if (DRIVER === 'better-sqlite3') {
    const db = new BetterSQLiteDB();
    await db.migrate();
    return db;
  }
  if (DRIVER === 'sql.js') {
    const db = new SqlJsDB();
    await db.migrate();
    return db;
  }
  return null; // no driver — use JSONL
}

module.exports = { createSQLiteDB, BetterSQLiteDB, SqlJsDB, DRIVER };
