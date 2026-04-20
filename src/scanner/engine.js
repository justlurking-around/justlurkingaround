'use strict';

/**
 * PHASE 7+8 — Scanner Engine + Deduplication
 *
 * Fetches repo file tree, downloads each scannable file,
 * runs regex patterns + entropy analysis, deduplicates by SHA-256 hash.
 */

const pLimit = require('p-limit');
const { getClient } = require('../utils/github-client');
const { shannonEntropy, isHighEntropy } = require('../utils/entropy');
const { fileHash } = require('../utils/hash');
const { shouldSkipFile, isDummyValue, isHighValueFile } = require('../filters/false-positive');
const { PATTERNS } = require('./patterns');
const config = require('../../config/default');
const logger = require('../utils/logger');

// In-memory dedup store (SHA-256 → true)
// In production, this would be backed by DB / Redis
const scannedHashes = new Set();

class ScannerEngine {
  constructor() {
    this.client = getClient();
    this.fileLimit = pLimit(config.scanner.concurrentFiles);
    this.maxFileSizeBytes = config.github.maxFileSizeKB * 1024;
    this.maxFilesPerRepo = config.github.maxFilesPerRepo;
  }

  /**
   * Scan a single repo — fetch tree, filter files, scan each one.
   * @param {object} repoEvent - normalized event from poller
   * @returns {Promise<Finding[]>}
   */
  async scanRepo(repoEvent) {
    const repoName = repoEvent.repoName;
    logger.info(`[Scanner] Scanning repo: ${repoName}`);

    let tree;
    try {
      tree = await this._getFileTree(repoName);
    } catch (err) {
      logger.warn(`[Scanner] Failed to get file tree for ${repoName}: ${err.message}`);
      return [];
    }

    if (!tree || tree.length === 0) {
      logger.debug(`[Scanner] Empty tree for ${repoName}`);
      return [];
    }

    // Filter to scannable files
    const files = tree
      .filter(f => f.type === 'blob')
      .filter(f => {
        const { skip } = shouldSkipFile(f.path);
        return !skip;
      })
      .filter(f => !f.size || f.size <= this.maxFileSizeBytes)
      .slice(0, this.maxFilesPerRepo);

    logger.debug(`[Scanner] ${files.length} files to scan in ${repoName} (${tree.length} total)`);

    // Prioritize high-value files
    const highValue = files.filter(f => isHighValueFile(f.path));
    const rest = files.filter(f => !isHighValueFile(f.path));
    const ordered = [...highValue, ...rest];

    const findings = [];
    const scanTasks = ordered.map(file =>
      this.fileLimit(async () => {
        try {
          const result = await this._scanFile(repoName, file);
          if (result.length > 0) findings.push(...result);
        } catch (err) {
          logger.debug(`[Scanner] File scan error ${file.path}: ${err.message}`);
        }
      })
    );

    await Promise.all(scanTasks);
    logger.info(`[Scanner] ${repoName} — ${findings.length} findings`);
    return findings;
  }

  /**
   * Get full file tree for a repo via Git Trees API
   */
  async _getFileTree(repoName) {
    // First, get default branch
    let defaultBranch = 'main';
    try {
      const repoInfo = await this.client.get(`/repos/${repoName}`);
      defaultBranch = repoInfo.data.default_branch || 'main';
    } catch {}

    // Get recursive tree
    const resp = await this.client.get(
      `/repos/${repoName}/git/trees/${defaultBranch}`,
      { params: { recursive: '1' } }
    );

    return resp.data?.tree || [];
  }

  /**
   * Download a single file and scan it for secrets
   */
  async _scanFile(repoName, file) {
    const findings = [];

    // Fetch raw file content
    let content;
    try {
      const rawUrl = `https://raw.githubusercontent.com/${repoName}/HEAD/${file.path}`;
      const resp = await this.client.get(rawUrl, {
        baseURL: '',
        responseType: 'text',
        timeout: 10000
      });
      content = resp.data;
    } catch {
      return [];
    }

    if (!content || typeof content !== 'string') return [];

    // Deduplication check
    const hash = fileHash(repoName, file.path, content);
    if (scannedHashes.has(hash)) {
      logger.debug(`[Scanner] Skipping already-scanned file: ${file.path}`);
      return [];
    }
    scannedHashes.add(hash);
    // Trim cache
    if (scannedHashes.size > 100_000) {
      const iter = scannedHashes.values();
      for (let i = 0; i < 10_000; i++) scannedHashes.delete(iter.next().value);
    }

    // ── Regex pattern scan ─────────────────────────────────────────────────
    for (const pattern of PATTERNS) {
      try {
        const matches = this._matchPattern(content, pattern, file.path);
        findings.push(...matches);
      } catch {}
    }

    // ── Entropy scan — catch any remaining high-entropy strings ───────────
    const entropyFindings = this._entropyAnalysis(content, repoName, file.path);
    findings.push(...entropyFindings);

    return findings;
  }

  /**
   * Apply a single pattern to file content
   */
  _matchPattern(content, pattern, filePath) {
    const findings = [];
    const regex = new RegExp(pattern.regex.source, 'gim');
    let match;

    while ((match = regex.exec(content)) !== null) {
      // Context check (some patterns require surrounding context)
      if (pattern.requireContext) {
        const contextWindow = content.substring(
          Math.max(0, match.index - 100),
          Math.min(content.length, match.index + 200)
        );
        if (!pattern.requireContext.test(contextWindow)) continue;
      }

      const rawValue = pattern.group === 0
        ? match[0]
        : (match[pattern.group] || match[0]);

      if (!rawValue) continue;
      const value = rawValue.trim();

      // Skip dummy/placeholder values
      if (isDummyValue(value)) continue;

      // Minimum length check
      if (value.length < config.scanner.minSecretLength) continue;

      const entropy = shannonEntropy(value);

      findings.push({
        patternId: pattern.id,
        patternName: pattern.name,
        provider: pattern.provider,
        filePath,
        value: this._redact(value),    // Store redacted for logs; full for DB
        rawValue: value,               // Full value for validation
        entropy: Math.round(entropy * 100) / 100,
        lineNumber: this._getLineNumber(content, match.index),
        matchContext: this._getContext(content, match.index),
        detectedAt: new Date().toISOString()
      });

      // Prevent infinite loops on zero-length matches
      if (match.index === regex.lastIndex) regex.lastIndex++;
    }

    return findings;
  }

  /**
   * Entropy-based detection for strings not caught by specific patterns
   */
  _entropyAnalysis(content, repoName, filePath) {
    const findings = [];
    const lines = content.split('\n');
    const threshold = config.scanner.entropyThreshold;

    const tokenRegex = /["']([A-Za-z0-9+/=_\-]{20,256})["']/g;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      let match;
      tokenRegex.lastIndex = 0;

      while ((match = tokenRegex.exec(line)) !== null) {
        const token = match[1];
        if (!isHighEntropy(token, threshold)) continue;
        if (isDummyValue(token)) continue;

        // Skip if already caught by a named pattern
        const alreadyCaught = PATTERNS.some(p => {
          try { return new RegExp(p.regex.source, 'i').test(token); } catch { return false; }
        });
        if (alreadyCaught) continue;

        findings.push({
          patternId: 'entropy',
          patternName: 'High-Entropy String',
          provider: 'unknown',
          filePath,
          value: this._redact(token),
          rawValue: token,
          entropy: Math.round(shannonEntropy(token) * 100) / 100,
          lineNumber: i + 1,
          matchContext: line.trim().substring(0, 200),
          detectedAt: new Date().toISOString()
        });
      }
    }

    return findings;
  }

  _redact(value) {
    if (!value || value.length <= 8) return '***';
    return value.substring(0, 4) + '****' + value.substring(value.length - 4);
  }

  _getLineNumber(content, index) {
    return content.substring(0, index).split('\n').length;
  }

  _getContext(content, index) {
    const start = content.lastIndexOf('\n', index - 1) + 1;
    const end = content.indexOf('\n', index);
    return content.substring(start, end === -1 ? content.length : end).trim().substring(0, 200);
  }
}

module.exports = ScannerEngine;
