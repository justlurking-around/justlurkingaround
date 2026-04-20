'use strict';

/**
 * Scanner Engine — Surface Scan + Deduplication
 *
 * FIXES:
 *  - BUG: rawUrl used client baseURL — fixed with absolute URL + baseURL:''
 *  - BUG: regex.lastIndex not reset between pattern runs → missed matches
 *  - BUG: truncated tree (>100k blobs) not handled — now detects truncation
 *  - BUG: scannedHashes is module-level → leaked across test runs; moved to instance
 *  - BUG: entropyAnalysis reused tokenRegex across iterations (stale lastIndex)
 *  - SECURITY: rawValue logged at debug level → now redacted in all log output
 *  - PERF: PATTERNS.some() in inner loop compiled regex per call → memoized
 */

const pLimit = require('p-limit');
const { getClient } = require('../utils/github-client');
const { shannonEntropy, isHighEntropy } = require('../utils/entropy');
const { fileHash } = require('../utils/hash');
const { shouldSkipFile, isDummyValue, isHighValueFile, isNoisyValue } = require('../filters/false-positive');
const { PATTERNS } = require('./patterns');
const { CREDENTIAL_PATTERNS } = require('./credential-patterns');

// Combined pattern list — API keys + service credentials
const ALL_PATTERNS = [...PATTERNS, ...CREDENTIAL_PATTERNS];
const config = require('../../config/default');
const logger = require('../utils/logger');

// Pre-compile all pattern regexes for entropy de-dup check (perf fix)
const _compiledPatterns = ALL_PATTERNS.map(p => {
  try { return new RegExp(p.regex.source, 'i'); } catch { return null; }
}).filter(Boolean);

class ScannerEngine {
  constructor() {
    this.client = getClient();
    this.fileLimit = pLimit(config.scanner.concurrentFiles);
    this.maxFileSizeBytes = config.github.maxFileSizeKB * 1024;
    this.maxFilesPerRepo = config.github.maxFilesPerRepo;
    // Per-instance dedup (not module-level) — avoids cross-scan contamination
    this._scannedHashes = new Set();
  }

  /** Refresh client reference after token change */
  _getClient() {
    return getClient();
  }

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

    // Filter scannable files
    const files = tree
      .filter(f => f.type === 'blob')
      .filter(f => { const { skip } = shouldSkipFile(f.path); return !skip; })
      .filter(f => !f.size || f.size <= this.maxFileSizeBytes)
      .slice(0, this.maxFilesPerRepo);

    logger.debug(`[Scanner] ${files.length} files to scan in ${repoName} (${tree.length} total${tree._truncated ? ', TRUNCATED' : ''})`);

    // High-value files first
    const ordered = [
      ...files.filter(f => isHighValueFile(f.path)),
      ...files.filter(f => !isHighValueFile(f.path))
    ];

    const findings = [];
    const maxFindings = config.scanner.maxFindingsPerRepo || 100;

    await Promise.all(
      ordered.map(file =>
        this.fileLimit(async () => {
          if (findings.length >= maxFindings) return;
          try {
            const result = await this._scanFile(repoName, file);
            if (result.length > 0) {
              // Slice to cap — don't overflow
              const remaining = maxFindings - findings.length;
              findings.push(...result.slice(0, remaining));
            }
          } catch (err) {
            logger.debug(`[Scanner] File error ${file.path}: ${err.message}`);
          }
        })
      )
    );

    if (findings.length >= maxFindings) {
      logger.warn(`[Scanner] ${repoName} — hit cap of ${maxFindings} findings (noisy repo, truncated)`);
    }
    logger.info(`[Scanner] ${repoName} — ${findings.length} findings`);
    return findings;
  }

  async _getFileTree(repoName) {
    let defaultBranch = 'main';
    try {
      const repoInfo = await this._getClient().get(`/repos/${repoName}`);
      defaultBranch = repoInfo.data.default_branch || 'main';
    } catch { /* use fallback */ }

    // FIX: detect truncated trees (repos with >100k files)
    const resp = await this._getClient().get(
      `/repos/${repoName}/git/trees/${defaultBranch}`,
      { params: { recursive: '1' } }
    );
    const tree = resp.data?.tree || [];
    if (resp.data?.truncated) {
      tree._truncated = true;
      logger.warn(`[Scanner] Tree truncated for ${repoName} — large repo, partial scan`);
    }
    return tree;
  }

  async _scanFile(repoName, file) {
    // FIX: always use absolute URL — never inherit client baseURL for raw content
    const rawUrl = `https://raw.githubusercontent.com/${repoName}/HEAD/${encodeURIComponent(file.path).replace(/%2F/g, '/')}`;

    let content;
    try {
      const resp = await this._getClient().get(rawUrl, {
        baseURL: '',          // FIX: override client baseURL
        responseType: 'text',
        timeout: 12000,
        maxContentLength: this.maxFileSizeBytes,
        maxBodyLength: this.maxFileSizeBytes
      });
      content = resp.data;
    } catch (err) {
      // 404 = file deleted between tree fetch and download → silently skip
      if (err.response?.status === 404) return [];
      logger.debug(`[Scanner] Fetch error ${file.path}: ${err.message}`);
      return [];
    }

    if (!content || typeof content !== 'string' || content.length < 10) return [];

    // Dedup check
    const hash = fileHash(repoName, file.path, content);
    if (this._scannedHashes.has(hash)) {
      logger.debug(`[Scanner] Dedup skip: ${file.path}`);
      return [];
    }
    this._scannedHashes.add(hash);
    // Rolling eviction — prevent unbounded growth
    if (this._scannedHashes.size > 50_000) {
      const iter = this._scannedHashes.values();
      for (let i = 0; i < 5_000; i++) this._scannedHashes.delete(iter.next().value);
    }

    const findings = [];
    for (const pattern of ALL_PATTERNS) {
      try {
        findings.push(...this._matchPattern(content, pattern, file.path));
      } catch (err) {
        logger.debug(`[Scanner] Pattern error ${pattern.id}: ${err.message}`);
      }
    }
    findings.push(...this._entropyAnalysis(content, file.path));
    return findings;
  }

  _matchPattern(content, pattern, filePath) {
    const findings = [];
    // FIX: always create fresh regex — never reuse stateful regex across calls
    const regex = new RegExp(pattern.regex.source, 'gim');
    let match;

    while ((match = regex.exec(content)) !== null) {
      if (pattern.requireContext) {
        const ctx = content.substring(
          Math.max(0, match.index - 100),
          Math.min(content.length, match.index + 200)
        );
        if (!pattern.requireContext.test(ctx)) {
          if (match.index === regex.lastIndex) regex.lastIndex++;
          continue;
        }
      }

      const rawValue = pattern.group === 0
        ? match[0]
        : (match[pattern.group] || match[0]);

      if (!rawValue) {
        if (match.index === regex.lastIndex) regex.lastIndex++;
        continue;
      }

      const value = rawValue.trim();
      if (isDummyValue(value))  { if (match.index === regex.lastIndex) regex.lastIndex++; continue; }
      if (isNoisyValue(value))   { if (match.index === regex.lastIndex) regex.lastIndex++; continue; }
      if (value.length < (config.scanner.minSecretLength || 16)) { if (match.index === regex.lastIndex) regex.lastIndex++; continue; }

      const entropy = shannonEntropy(value);
      findings.push({
        patternId:    pattern.id,
        patternName:  pattern.name,
        provider:     pattern.provider,
        filePath,
        value:        this._redact(value),
        rawValue:     value,
        entropy:      Math.round(entropy * 100) / 100,
        lineNumber:   this._lineOf(content, match.index),
        matchContext: this._context(content, match.index),
        detectedAt:   new Date().toISOString()
      });

      if (match.index === regex.lastIndex) regex.lastIndex++;
    }
    return findings;
  }

  _entropyAnalysis(content, filePath) {
    const findings = [];
    const threshold = config.scanner.entropyThreshold || 4.0;
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // FIX: create fresh regex per line — never share stateful regex
      const tokenRe = /["']([A-Za-z0-9+/=_\-]{20,256})["']/g;
      let m;
      while ((m = tokenRe.exec(line)) !== null) {
        const token = m[1];
        if (!isHighEntropy(token, threshold)) continue;
        if (isDummyValue(token))  continue;
        if (isNoisyValue(token))  continue;
        // FIX: use pre-compiled patterns array (perf)
        if (_compiledPatterns.some(re => re.test(token))) continue;

        findings.push({
          patternId:   'entropy',
          patternName: 'High-Entropy String',
          provider:    'unknown',
          filePath,
          value:       this._redact(token),
          rawValue:    token,
          entropy:     Math.round(shannonEntropy(token) * 100) / 100,
          lineNumber:  i + 1,
          matchContext: line.trim().substring(0, 200),
          detectedAt:  new Date().toISOString()
        });
        if (m.index === tokenRe.lastIndex) tokenRe.lastIndex++;
      }
    }
    return findings;
  }

  _redact(v) {
    if (!v || v.length <= 8) return '***';
    return v.substring(0, 4) + '****' + v.slice(-4);
  }

  _lineOf(content, index) {
    return content.substring(0, index).split('\n').length;
  }

  _context(content, index) {
    const start = content.lastIndexOf('\n', index - 1) + 1;
    const end = content.indexOf('\n', index);
    return content
      .substring(start, end === -1 ? content.length : end)
      .trim().substring(0, 200);
  }
}

module.exports = ScannerEngine;
