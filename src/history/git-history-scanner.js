'use strict';

/**
 * Git History Scanner
 *
 * FIXES:
 *  - BUG: scannedCommits/scannedBlobs are module-level Sets → shared across instances,
 *         causing misses on second scan; moved to instance
 *  - BUG: _extractAddedLines included +++ header line content in some edge cases → stricter filter
 *  - BUG: per-scan commit cap not enforced — could run forever on repos with 10k+ commits → enforced
 *  - BUG: dangling commit scan fetched 100 events but most are irrelevant → now deduplicated by SHA
 *  - BUG: error swallowed in _scanCommitDiff without logging → added debug log
 *  - PERF: regex recompiled per token in inner loop → use pre-compiled from patterns
 */

const { getClient } = require('../utils/github-client');
const { shouldSkipFile, isDummyValue } = require('../filters/false-positive');
const { PATTERNS } = require('../scanner/patterns');
const { shannonEntropy, isHighEntropy } = require('../utils/entropy');
const config = require('../../config/default');
const logger = require('../utils/logger');

// Pre-compiled for entropy dedup (perf)
const _compiledPatterns = PATTERNS.map(p => {
  try { return new RegExp(p.regex.source, 'i'); } catch { return null; }
}).filter(Boolean);

class GitHistoryScanner {
  constructor() {
    // FIX: instance-level sets — no cross-scan contamination
    this._scannedCommits = new Set();
    this._scannedBlobs   = new Set();
    this.maxCommitsPerBranch = parseInt(process.env.MAX_COMMITS_PER_BRANCH || '50');
    this.maxBranches         = parseInt(process.env.MAX_BRANCHES || '10');
  }

  async deepScan(repoName) {
    logger.info(`[History] Deep scan: ${repoName}`);
    const all = [];

    const branches = await this._getBranches(repoName);
    logger.info(`[History] ${repoName} — ${branches.length} branches, scanning up to ${this.maxBranches}`);

    for (const branch of branches.slice(0, this.maxBranches)) {
      try {
        const findings = await this._scanBranch(repoName, branch.name);
        all.push(...findings);
      } catch (err) {
        logger.debug(`[History] Branch ${branch.name} error: ${err.message}`);
      }
    }

    try {
      const dangling = await this._scanDanglingCommits(repoName);
      all.push(...dangling);
    } catch (err) {
      logger.debug(`[History] Dangling scan error: ${err.message}`);
    }

    logger.info(`[History] ${repoName} complete — ${all.length} history findings`);
    return all;
  }

  async _getBranches(repoName) {
    try {
      const resp = await getClient().get(`/repos/${repoName}/branches`, { params: { per_page: 100 } });
      return resp.data || [];
    } catch {
      return [{ name: 'main' }, { name: 'master' }];
    }
  }

  async _scanBranch(repoName, branchName) {
    const findings = [];
    let commits = [];
    try {
      const resp = await getClient().get(`/repos/${repoName}/commits`, {
        params: { sha: branchName, per_page: this.maxCommitsPerBranch }
      });
      commits = resp.data || [];
    } catch { return []; }

    logger.debug(`[History] Branch ${branchName}: ${commits.length} commits`);

    // FIX: enforce hard cap — maxCommitsPerBranch respected
    for (const commit of commits.slice(0, this.maxCommitsPerBranch)) {
      const sha = commit.sha;
      if (this._scannedCommits.has(sha)) continue;
      this._scannedCommits.add(sha);

      // Rolling eviction
      if (this._scannedCommits.size > 100_000) {
        const iter = this._scannedCommits.values();
        for (let i = 0; i < 10_000; i++) this._scannedCommits.delete(iter.next().value);
      }

      try {
        findings.push(...await this._scanCommitDiff(repoName, sha, branchName));
      } catch (err) {
        logger.debug(`[History] Commit ${sha.substring(0,8)} error: ${err.message}`);
      }
    }
    return findings;
  }

  async _scanCommitDiff(repoName, sha, branchName) {
    const findings = [];
    let commitData;
    try {
      const resp = await getClient().get(`/repos/${repoName}/commits/${sha}`);
      commitData = resp.data;
    } catch { return []; }

    const files      = commitData.files || [];
    const commitMsg  = (commitData.commit?.message || '').substring(0, 500);
    const authorName = (commitData.commit?.author?.name || '').substring(0, 100);
    const commitDate = commitData.commit?.author?.date || '';

    for (const file of files) {
      const { skip } = shouldSkipFile(file.filename || '');
      if (skip) continue;

      // FIX: skip if blob already scanned
      if (file.sha && this._scannedBlobs.has(file.sha)) continue;
      if (file.sha) {
        this._scannedBlobs.add(file.sha);
        if (this._scannedBlobs.size > 50_000) {
          const iter = this._scannedBlobs.values();
          for (let i = 0; i < 5_000; i++) this._scannedBlobs.delete(iter.next().value);
        }
      }

      const addedLines = this._extractAddedLines(file.patch || '');
      if (!addedLines.trim()) continue;

      for (const f of this._scanText(addedLines, file.filename || '')) {
        findings.push({
          ...f,
          repoName,
          commitSha:    sha,
          branchName,
          commitMessage: commitMsg,
          authorName,
          commitDate,
          isHistorical: true,
          isDeleted:    file.status === 'removed'
        });
      }
    }
    return findings;
  }

  // FIX: stricter filter — skip +++ header lines (unified diff format)
  _extractAddedLines(patch) {
    return patch
      .split('\n')
      .filter(l => l.startsWith('+') && !l.startsWith('+++'))
      .map(l => l.substring(1))
      .join('\n');
  }

  async _scanDanglingCommits(repoName) {
    const findings = [];
    let events = [];
    try {
      const resp = await getClient().get(`/repos/${repoName}/events`, { params: { per_page: 100 } });
      events = resp.data || [];
    } catch { return []; }

    // FIX: collect only unique SHAs not already scanned
    const danglings = new Set();
    for (const ev of events) {
      if (ev.type !== 'PushEvent') continue;
      for (const c of (ev.payload?.commits || [])) {
        if (c.sha && !this._scannedCommits.has(c.sha)) danglings.add(c.sha);
      }
    }

    logger.debug(`[History] ${repoName}: ${danglings.size} potential dangling commits`);
    for (const sha of danglings) {
      try {
        const f = await this._scanCommitDiff(repoName, sha, 'dangling');
        findings.push(...f.map(x => ({ ...x, isDangling: true })));
      } catch {}
    }
    return findings;
  }

  _scanText(text, filePath) {
    const findings = [];
    for (const pattern of PATTERNS) {
      const regex = new RegExp(pattern.regex.source, 'gim');
      let m;
      while ((m = regex.exec(text)) !== null) {
        if (pattern.requireContext) {
          const ctx = text.substring(Math.max(0, m.index - 100), m.index + 200);
          if (!pattern.requireContext.test(ctx)) { if (m.index === regex.lastIndex) regex.lastIndex++; continue; }
        }
        const rawValue = pattern.group === 0 ? m[0] : (m[pattern.group] || m[0]);
        if (!rawValue) { if (m.index === regex.lastIndex) regex.lastIndex++; continue; }
        const value = rawValue.trim();
        if (isDummyValue(value) || value.length < 16) { if (m.index === regex.lastIndex) regex.lastIndex++; continue; }
        findings.push({
          patternId:    pattern.id,
          patternName:  pattern.name,
          provider:     pattern.provider,
          filePath,
          value:        this._redact(value),
          rawValue:     value,
          entropy:      Math.round(shannonEntropy(value) * 100) / 100,
          lineNumber:   text.substring(0, m.index).split('\n').length,
          matchContext: text.substring(Math.max(0, m.index - 50), m.index + 100).trim().replace(/\n/g, ' ').substring(0, 200),
          detectedAt:   new Date().toISOString()
        });
        if (m.index === regex.lastIndex) regex.lastIndex++;
      }
    }
    // Entropy pass
    const tokenRe = /["']([A-Za-z0-9+/=_\-]{20,256})["']/g;
    let m2;
    while ((m2 = tokenRe.exec(text)) !== null) {
      const token = m2[1];
      if (!isHighEntropy(token, config.scanner.entropyThreshold || 4.0)) continue;
      if (isDummyValue(token)) continue;
      if (_compiledPatterns.some(re => re.test(token))) continue;
      findings.push({
        patternId: 'entropy', patternName: 'High-Entropy (History)', provider: 'unknown',
        filePath, value: this._redact(token), rawValue: token,
        entropy: Math.round(shannonEntropy(token) * 100) / 100,
        lineNumber: text.substring(0, m2.index).split('\n').length,
        matchContext: text.substring(Math.max(0, m2.index - 50), m2.index + 100).trim().substring(0, 200),
        detectedAt: new Date().toISOString()
      });
      if (m2.index === tokenRe.lastIndex) tokenRe.lastIndex++;
    }
    return findings;
  }

  _redact(v) {
    if (!v || v.length <= 8) return '***';
    return v.substring(0, 4) + '****' + v.slice(-4);
  }
}

module.exports = GitHistoryScanner;
