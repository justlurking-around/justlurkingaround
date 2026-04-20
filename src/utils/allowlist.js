'use strict';

/**
 * Allowlist / Denylist System
 *
 * allowlist.json  — repos/orgs/patterns to ALWAYS skip
 * denylist.json   — repos/orgs to ALWAYS scan (even if not AI-detected)
 *
 * File format: data/allowlist.json
 * {
 *   "repos":    ["owner/repo", ...],
 *   "orgs":     ["myorg", ...],
 *   "patterns": ["entropy", "generic_api_key"],
 *   "filepaths": ["test/", "docs/"]
 * }
 */

const fs   = require('fs');
const path = require('path');
const logger = require('./logger');

const ALLOWLIST_FILE = process.env.ALLOWLIST_FILE || path.resolve('./data/allowlist.json');
const DENYLIST_FILE  = process.env.DENYLIST_FILE  || path.resolve('./data/denylist.json');

function loadJSON(filePath, defaultVal = {}) {
  try {
    if (!fs.existsSync(filePath)) return defaultVal;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    logger.warn(`[Allowlist] Could not load ${filePath}: ${err.message}`);
    return defaultVal;
  }
}

function saveJSON(filePath, data) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

function getDefault() {
  return { repos: [], orgs: [], patterns: [], filepaths: [] };
}

class AllowlistManager {
  constructor() {
    this._allowlist = loadJSON(ALLOWLIST_FILE, getDefault());
    this._denylist  = loadJSON(DENYLIST_FILE,  getDefault());
  }

  reload() {
    this._allowlist = loadJSON(ALLOWLIST_FILE, getDefault());
    this._denylist  = loadJSON(DENYLIST_FILE,  getDefault());
  }

  // ── Allowlist (SKIP) ──────────────────────────────────────────────────────

  isAllowlisted(repoName) {
    if (!repoName) return false;
    const [org] = repoName.split('/');

    if (this._allowlist.repos?.includes(repoName)) return true;
    if (this._allowlist.orgs?.includes(org)) return true;
    return false;
  }

  isPatternAllowlisted(patternId) {
    return this._allowlist.patterns?.includes(patternId) || false;
  }

  isFileAllowlisted(filePath) {
    if (!filePath) return false;
    const fps = this._allowlist.filepaths || [];
    return fps.some(pattern => {
      // Simple glob: prefix match, wildcard suffix
      if (pattern.endsWith('*')) return filePath.startsWith(pattern.slice(0, -1));
      if (pattern.includes('**')) {
        const parts = pattern.replace('**/', '');
        return filePath.includes(parts);
      }
      return filePath === pattern || filePath.startsWith(pattern);
    });
  }

  addAllowlistRepo(repoName) {
    if (!this._allowlist.repos.includes(repoName)) {
      this._allowlist.repos.push(repoName);
      saveJSON(ALLOWLIST_FILE, this._allowlist);
      logger.info(`[Allowlist] Added repo: ${repoName}`);
    }
  }

  removeAllowlistRepo(repoName) {
    this._allowlist.repos = this._allowlist.repos.filter(r => r !== repoName);
    saveJSON(ALLOWLIST_FILE, this._allowlist);
  }

  // ── Denylist (FORCE SCAN) ─────────────────────────────────────────────────

  isDeeplisted(repoName) {
    if (!repoName) return false;
    const [org] = repoName.split('/');
    if (this._denylist.repos?.includes(repoName)) return true;
    if (this._denylist.orgs?.includes(org)) return true;
    return false;
  }

  addDenylistRepo(repoName) {
    if (!this._denylist.repos.includes(repoName)) {
      this._denylist.repos.push(repoName);
      saveJSON(DENYLIST_FILE, this._denylist);
      logger.info(`[Denylist] Added: ${repoName}`);
    }
  }

  // ── Status ────────────────────────────────────────────────────────────────

  summary() {
    return {
      allowlist: {
        repos:    this._allowlist.repos?.length    || 0,
        orgs:     this._allowlist.orgs?.length     || 0,
        patterns: this._allowlist.patterns?.length || 0,
      },
      denylist: {
        repos: this._denylist.repos?.length || 0,
        orgs:  this._denylist.orgs?.length  || 0,
      }
    };
  }

  getAll() {
    return { allowlist: this._allowlist, denylist: this._denylist };
  }
}

let _manager = null;
function getAllowlist() {
  if (!_manager) _manager = new AllowlistManager();
  return _manager;
}

module.exports = { getAllowlist, AllowlistManager };
