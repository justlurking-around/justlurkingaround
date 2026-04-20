'use strict';

/**
 * PHASE 10 — Database Layer
 *
 * Primary: PostgreSQL (pg)
 * Fallback: JSONL flat-file (no Postgres required for local/Termux use)
 *
 * Tables:
 *   repositories  — every scanned repo
 *   findings      — every detected secret
 */

const fs = require('fs');
const path = require('path');
const config = require('../../config/default');
const logger = require('../utils/logger');

// ─── PostgreSQL Backend ───────────────────────────────────────────────────────

class PostgresDB {
  constructor() {
    const { Pool } = require('pg');
    const dbConf = config.database;
    this.pool = new Pool(
      dbConf.connectionString
        ? { connectionString: dbConf.connectionString, ssl: dbConf.ssl ? { rejectUnauthorized: false } : false }
        : {
            host: dbConf.host,
            port: dbConf.port,
            database: dbConf.database,
            user: dbConf.user,
            password: dbConf.password,
            ssl: dbConf.ssl ? { rejectUnauthorized: false } : false,
          }
    );
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
          detected_at TIMESTAMPTZ DEFAULT NOW(),
          validated_at TIMESTAMPTZ,
          UNIQUE(repo_name, file_path, secret_hash)
        );

        CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo_name);
        CREATE INDEX IF NOT EXISTS idx_findings_provider ON findings(provider);
        CREATE INDEX IF NOT EXISTS idx_findings_validation ON findings(validation_result);
        CREATE INDEX IF NOT EXISTS idx_repos_ai ON repositories(is_ai_generated);
      `);
      logger.info('[DB] PostgreSQL schema ready');
    } finally {
      client.release();
    }
  }

  async upsertRepo(repo) {
    await this.pool.query(`
      INSERT INTO repositories (repo_name, repo_url, is_ai_generated, ai_confidence, ai_signals, priority, last_scanned, scan_count)
      VALUES ($1, $2, $3, $4, $5, $6, NOW(), 1)
      ON CONFLICT (repo_name) DO UPDATE SET
        is_ai_generated = EXCLUDED.is_ai_generated,
        ai_confidence = EXCLUDED.ai_confidence,
        ai_signals = EXCLUDED.ai_signals,
        priority = EXCLUDED.priority,
        last_scanned = NOW(),
        scan_count = repositories.scan_count + 1
    `, [repo.repoName, repo.repoUrl, repo.isAI, repo.aiConfidence, JSON.stringify(repo.aiSignals), repo.priority]);
  }

  async insertFinding(finding) {
    try {
      await this.pool.query(`
        INSERT INTO findings
          (repo_name, file_path, pattern_id, pattern_name, provider, secret_hash, secret_redacted, entropy, line_number, match_context, validation_result, validation_detail, validated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        ON CONFLICT (repo_name, file_path, secret_hash) DO UPDATE SET
          validation_result = EXCLUDED.validation_result,
          validation_detail = EXCLUDED.validation_detail,
          validated_at = EXCLUDED.validated_at
      `, [
        finding.repoName, finding.filePath, finding.patternId, finding.patternName,
        finding.provider, finding.secretHash, finding.value, finding.entropy,
        finding.lineNumber, finding.matchContext,
        finding.validationResult, finding.validationDetail,
        finding.validationResult !== 'PENDING' ? new Date() : null
      ]);
    } catch (err) {
      if (!err.message.includes('duplicate')) {
        logger.warn(`[DB] Insert finding error: ${err.message}`);
      }
    }
  }

  async getStats() {
    const [repos, findings, valid] = await Promise.all([
      this.pool.query('SELECT COUNT(*) FROM repositories'),
      this.pool.query('SELECT COUNT(*) FROM findings'),
      this.pool.query("SELECT COUNT(*) FROM findings WHERE validation_result = 'VALID'"),
    ]);
    return {
      repositories: parseInt(repos.rows[0].count),
      findings: parseInt(findings.rows[0].count),
      validSecrets: parseInt(valid.rows[0].count),
    };
  }

  async getRecentFindings(limit = 50) {
    const result = await this.pool.query(`
      SELECT * FROM findings ORDER BY detected_at DESC LIMIT $1
    `, [limit]);
    return result.rows;
  }

  async close() {
    await this.pool.end();
  }
}

// ─── JSONL Fallback Backend ───────────────────────────────────────────────────

class JsonlDB {
  constructor() {
    this.filePath = path.resolve(config.database.fallbackFile);
    this.reposPath = this.filePath.replace('.jsonl', '-repos.jsonl');
    this._ensureDir();
    this._repos = new Map();
    this._findings = new Map();
    this._loaded = false;
  }

  _ensureDir() {
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }

  async migrate() {
    this._ensureDir();
    // Load existing data
    this._loadFile(this.filePath, this._findings);
    this._loadFile(this.reposPath, this._repos);
    logger.info(`[DB] JSONL store ready — ${this._findings.size} findings, ${this._repos.size} repos`);
  }

  _loadFile(filePath, map) {
    if (!fs.existsSync(filePath)) return;
    const lines = fs.readFileSync(filePath, 'utf8').split('\n').filter(Boolean);
    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        const key = obj.id || obj.repo_name || JSON.stringify(obj);
        map.set(key, obj);
      } catch {}
    }
  }

  async upsertRepo(repo) {
    const key = repo.repoName;
    const existing = this._repos.get(key) || {};
    const updated = {
      ...existing,
      repo_name: repo.repoName,
      repo_url: repo.repoUrl,
      is_ai_generated: repo.isAI,
      ai_confidence: repo.aiConfidence,
      ai_signals: repo.aiSignals,
      priority: repo.priority,
      last_scanned: new Date().toISOString(),
      scan_count: (existing.scan_count || 0) + 1
    };
    this._repos.set(key, updated);
    this._appendLine(this.reposPath, updated);
  }

  async insertFinding(finding) {
    const key = `${finding.repoName}::${finding.filePath}::${finding.secretHash}`;
    if (this._findings.has(key) && finding.validationResult === 'PENDING') return;
    const record = {
      id: key,
      repo_name: finding.repoName,
      file_path: finding.filePath,
      pattern_id: finding.patternId,
      pattern_name: finding.patternName,
      provider: finding.provider,
      secret_hash: finding.secretHash,
      secret_redacted: finding.value,
      entropy: finding.entropy,
      line_number: finding.lineNumber,
      match_context: finding.matchContext,
      validation_result: finding.validationResult,
      validation_detail: finding.validationDetail,
      detected_at: finding.detectedAt || new Date().toISOString()
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
    return {
      repositories: this._repos.size,
      findings: this._findings.size,
      validSecrets: [...this._findings.values()].filter(f => f.validation_result === 'VALID').length,
    };
  }

  async getRecentFindings(limit = 50) {
    return [...this._findings.values()]
      .sort((a, b) => new Date(b.detected_at) - new Date(a.detected_at))
      .slice(0, limit);
  }

  async close() {}
}

// ─── Factory ──────────────────────────────────────────────────────────────────

let _db = null;

async function getDB() {
  if (_db) return _db;

  const dbConf = config.database;
  const hasPostgres = !!(dbConf.connectionString || dbConf.password || process.env.DATABASE_URL);

  if (hasPostgres) {
    try {
      const pg = new PostgresDB();
      await pg.migrate();
      _db = pg;
      logger.info('[DB] Using PostgreSQL');
      return _db;
    } catch (err) {
      logger.warn(`[DB] PostgreSQL unavailable (${err.message}), falling back to JSONL`);
    }
  }

  const jsonl = new JsonlDB();
  await jsonl.migrate();
  _db = jsonl;
  logger.info('[DB] Using JSONL flat-file store');
  return _db;
}

module.exports = { getDB, PostgresDB, JsonlDB };
