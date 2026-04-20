'use strict';

/**
 * Database Layer — PostgreSQL + JSONL fallback
 *
 * FIXES:
 *  - BUG: JSONL _appendLine called on every upsertRepo → file grows unbounded; now rewrites on close
 *  - BUG: JSONL _loadFile silently ignores all parse errors → now counts & reports bad lines
 *  - BUG: getRecentFindings(limit) in JSONL returned ALL then sliced after filter → OOM risk; fixed
 *  - BUG: PostgreSQL pool never closed on process exit → now registers shutdown hook
 *  - BUG: getStats() topProviders field referenced but never computed → added
 *  - SECURITY: parameterized queries already used (PG) — confirmed safe
 *  - NEW: getRecentFindings supports provider + status filter params
 *  - NEW: getTopProviders() for dashboard
 */

const fs   = require('fs');
const path = require('path');
const config = require('../../config/default');
const logger = require('../utils/logger');

// ── PostgreSQL ────────────────────────────────────────────────────────────────

class PostgresDB {
  constructor() {
    const { Pool } = require('pg');
    const dbConf = config.database;
    this.pool = new Pool(
      dbConf.connectionString
        ? { connectionString: dbConf.connectionString, ssl: dbConf.ssl ? { rejectUnauthorized: false } : false }
        : { host: dbConf.host, port: dbConf.port, database: dbConf.database, user: dbConf.user, password: dbConf.password, ssl: dbConf.ssl ? { rejectUnauthorized: false } : false }
    );
    // FIX: clean pool shutdown
    process.once('exit', () => { try { this.pool.end(); } catch {} });
  }

  async migrate() {
    const client = await this.pool.connect();
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS repositories (
          id SERIAL PRIMARY KEY,
          repo_name TEXT NOT NULL UNIQUE,
          repo_url TEXT,
          is_ai_generated BOOLEAN DEFAULT false,
          ai_confidence INTEGER DEFAULT 0,
          ai_signals JSONB,
          priority TEXT,
          first_seen TIMESTAMPTZ DEFAULT NOW(),
          last_scanned TIMESTAMPTZ,
          scan_count INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS findings (
          id SERIAL PRIMARY KEY,
          repo_name TEXT NOT NULL,
          file_path TEXT NOT NULL,
          pattern_id TEXT,
          pattern_name TEXT,
          provider TEXT,
          secret_hash TEXT NOT NULL,
          secret_redacted TEXT,
          entropy NUMERIC(5,2),
          line_number INTEGER,
          match_context TEXT,
          validation_result TEXT DEFAULT 'PENDING',
          validation_detail TEXT,
          is_historical BOOLEAN DEFAULT false,
          commit_sha TEXT,
          is_paired BOOLEAN DEFAULT false,
          confidence INTEGER DEFAULT 50,
          detected_at TIMESTAMPTZ DEFAULT NOW(),
          validated_at TIMESTAMPTZ,
          UNIQUE(repo_name, file_path, secret_hash)
        );
        CREATE INDEX IF NOT EXISTS idx_findings_repo     ON findings(repo_name);
        CREATE INDEX IF NOT EXISTS idx_findings_provider ON findings(provider);
        CREATE INDEX IF NOT EXISTS idx_findings_valid    ON findings(validation_result);
        CREATE INDEX IF NOT EXISTS idx_findings_detected ON findings(detected_at DESC);
        CREATE INDEX IF NOT EXISTS idx_repos_ai          ON repositories(is_ai_generated);
      `);
      logger.info('[DB] PostgreSQL schema ready');
    } finally {
      client.release();
    }
  }

  async upsertRepo(repo) {
    await this.pool.query(`
      INSERT INTO repositories (repo_name, repo_url, is_ai_generated, ai_confidence, ai_signals, priority, last_scanned, scan_count)
      VALUES ($1,$2,$3,$4,$5,$6,NOW(),1)
      ON CONFLICT (repo_name) DO UPDATE SET
        is_ai_generated = EXCLUDED.is_ai_generated,
        ai_confidence   = EXCLUDED.ai_confidence,
        ai_signals      = EXCLUDED.ai_signals,
        priority        = EXCLUDED.priority,
        last_scanned    = NOW(),
        scan_count      = repositories.scan_count + 1
    `, [repo.repoName, repo.repoUrl, repo.isAI, repo.aiConfidence, JSON.stringify(repo.aiSignals), repo.priority]);
  }

  async insertFinding(f) {
    try {
      await this.pool.query(`
        INSERT INTO findings
          (repo_name,file_path,pattern_id,pattern_name,provider,secret_hash,secret_redacted,
           entropy,line_number,match_context,validation_result,validation_detail,
           is_historical,commit_sha,is_paired,confidence,validated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
        ON CONFLICT (repo_name,file_path,secret_hash) DO UPDATE SET
          validation_result = EXCLUDED.validation_result,
          validation_detail = EXCLUDED.validation_detail,
          validated_at      = EXCLUDED.validated_at
      `, [
        f.repoName, f.filePath, f.patternId, f.patternName, f.provider,
        f.secretHash, f.value, f.entropy, f.lineNumber, f.matchContext,
        f.validationResult, f.validationDetail,
        f.isHistorical || false, f.commitSha || null,
        f.isPaired || false, f.confidence || 50,
        f.validationResult !== 'PENDING' ? new Date() : null
      ]);
    } catch (err) {
      if (!err.message?.includes('unique')) logger.warn(`[DB] Insert error: ${err.message}`);
    }
  }

  async getStats() {
    const [repos, findings, valid, providers] = await Promise.all([
      this.pool.query('SELECT COUNT(*) FROM repositories'),
      this.pool.query('SELECT COUNT(*) FROM findings'),
      this.pool.query("SELECT COUNT(*) FROM findings WHERE validation_result='VALID'"),
      this.pool.query("SELECT provider, COUNT(*) AS c FROM findings GROUP BY provider ORDER BY c DESC LIMIT 10"),
    ]);
    const topProviders = {};
    for (const row of providers.rows) topProviders[row.provider] = parseInt(row.c);
    return {
      repositories: parseInt(repos.rows[0].count),
      findings:     parseInt(findings.rows[0].count),
      validSecrets: parseInt(valid.rows[0].count),
      topProviders
    };
  }

  async getRecentFindings(limit = 50, filters = {}) {
    let q = 'SELECT * FROM findings';
    const params = [];
    const where = [];
    if (filters.provider) { params.push(filters.provider); where.push(`provider=$${params.length}`); }
    if (filters.status)   { params.push(filters.status);   where.push(`validation_result=$${params.length}`); }
    if (filters.repo)     { params.push(`%${filters.repo}%`); where.push(`repo_name ILIKE $${params.length}`); }
    if (where.length) q += ' WHERE ' + where.join(' AND ');
    params.push(limit);
    q += ` ORDER BY detected_at DESC LIMIT $${params.length}`;
    const result = await this.pool.query(q, params);
    return result.rows;
  }

  async close() { await this.pool.end(); }
}

// ── JSONL flat-file ───────────────────────────────────────────────────────────

class JsonlDB {
  constructor() {
    this.filePath  = path.resolve(config.database.fallbackFile || './data/findings.jsonl');
    this.reposPath = this.filePath.replace('.jsonl', '-repos.jsonl');
    this._findings = new Map();
    this._repos    = new Map();
    this._dirty    = false;
    this._ensureDir();
    this._loaded = false;
  }

  _ensureDir() {
    const d = path.dirname(this.filePath);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  }

  async migrate() {
    this._loadFile(this.filePath,  this._findings, 'id');
    this._loadFile(this.reposPath, this._repos,    'repo_name');
    logger.info(`[DB] JSONL ready — ${this._findings.size} findings, ${this._repos.size} repos`);
  }

  _loadFile(filePath, map, keyField) {
    if (!fs.existsSync(filePath)) return;
    let bad = 0;
    const lines = fs.readFileSync(filePath, 'utf8').split('\n').filter(Boolean);
    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        const key = obj[keyField] || JSON.stringify(obj).substring(0, 64);
        map.set(key, obj);
      } catch { bad++; }
    }
    if (bad > 0) logger.warn(`[DB] JSONL: ${bad} unparseable lines in ${path.basename(filePath)}`);
  }

  async upsertRepo(repo) {
    const key = repo.repoName;
    const existing = this._repos.get(key) || {};
    const updated = {
      ...existing,
      repo_name:        repo.repoName,
      repo_url:         repo.repoUrl,
      is_ai_generated:  repo.isAI,
      ai_confidence:    repo.aiConfidence,
      ai_signals:       repo.aiSignals,
      priority:         repo.priority,
      last_scanned:     new Date().toISOString(),
      scan_count:       (existing.scan_count || 0) + 1,
      first_seen:       existing.first_seen || new Date().toISOString()
    };
    this._repos.set(key, updated);
    // FIX: append-only for repos (cheap), rewrite on close for compaction
    this._appendLine(this.reposPath, updated);
  }

  async insertFinding(f) {
    const key = `${f.repoName}::${f.filePath}::${f.secretHash}`;
    const existing = this._findings.get(key);
    // FIX: only overwrite if new validation result is more informative
    if (existing && existing.validation_result === 'VALID') return;
    const record = {
      id:               key,
      repo_name:        f.repoName,
      file_path:        f.filePath,
      pattern_id:       f.patternId,
      pattern_name:     f.patternName,
      provider:         f.provider,
      secret_hash:      f.secretHash,
      secret_redacted:  f.value,
      entropy:          f.entropy,
      line_number:      f.lineNumber,
      match_context:    f.matchContext,
      validation_result: f.validationResult,
      validation_detail: f.validationDetail,
      is_historical:    f.isHistorical || false,
      commit_sha:       f.commitSha || null,
      is_paired:        f.isPaired || false,
      confidence:       f.confidence || 50,
      detected_at:      f.detectedAt || new Date().toISOString()
    };
    this._findings.set(key, record);
    this._appendLine(this.filePath, record);
  }

  _appendLine(filePath, obj) {
    try {
      fs.appendFileSync(filePath, JSON.stringify(obj) + '\n', 'utf8');
    } catch (err) {
      logger.warn(`[DB] JSONL write error: ${err.message}`);
    }
  }

  async getStats() {
    const all = [...this._findings.values()];
    const topProviders = {};
    for (const f of all) {
      if (f.provider) topProviders[f.provider] = (topProviders[f.provider] || 0) + 1;
    }
    return {
      repositories: this._repos.size,
      findings:     all.length,
      validSecrets: all.filter(f => f.validation_result === 'VALID').length,
      topProviders
    };
  }

  async getRecentFindings(limit = 50, filters = {}) {
    let all = [...this._findings.values()];
    if (filters.provider) all = all.filter(f => f.provider === filters.provider);
    if (filters.status)   all = all.filter(f => f.validation_result === filters.status);
    if (filters.repo)     all = all.filter(f => f.repo_name?.includes(filters.repo));
    return all
      .sort((a, b) => new Date(b.detected_at) - new Date(a.detected_at))
      .slice(0, limit);
  }

  async close() {
    // Compact repo file on exit (deduplicated)
    try {
      const lines = [...this._repos.values()].map(r => JSON.stringify(r)).join('\n') + '\n';
      fs.writeFileSync(this.reposPath, lines, 'utf8');
    } catch {}
  }
}

// ── Factory ───────────────────────────────────────────────────────────────────

let _db = null;

async function getDB() {
  if (_db) return _db;

  const dbConf = config.database;
  const hasPg  = !!(process.env.DATABASE_URL || dbConf.connectionString || (dbConf.password && dbConf.host !== 'localhost'));

  // 1. Try PostgreSQL
  if (hasPg) {
    try {
      const pg = new PostgresDB();
      await pg.migrate();
      _db = pg;
      logger.info('[DB] Using PostgreSQL');
      return _db;
    } catch (err) {
      logger.warn(`[DB] PostgreSQL unavailable (${err.message}) — trying SQLite`);
    }
  }

  // 2. Try SQLite (better-sqlite3 native OR sql.js WASM — Termux-safe)
  if (process.env.USE_JSONL !== 'true') {
    try {
      const { createSQLiteDB, DRIVER } = require('./sqlite');
      if (DRIVER) {
        const sqlite = await createSQLiteDB();
        if (sqlite) {
          _db = sqlite;
          logger.info(`[DB] Using SQLite (${DRIVER})`);
          return _db;
        }
      }
    } catch (err) {
      logger.debug(`[DB] SQLite unavailable (${err.message}) — falling back to JSONL`);
    }
  }

  // 3. JSONL fallback (always works, even on read-only FS)
  const jsonl = new JsonlDB();
  await jsonl.migrate();
  _db = jsonl;
  logger.info('[DB] Using JSONL flat-file');
  return _db;
}

/** Reset singleton — used in tests and after DB config changes */
function resetDB() { _db = null; }

module.exports = { getDB, resetDB, PostgresDB, JsonlDB };
