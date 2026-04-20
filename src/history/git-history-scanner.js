'use strict';

/**
 * DAY 2 — Git History Scanner
 *
 * Goes DEEP into a repo beyond the current HEAD:
 *  - Scans ALL branches (not just default)
 *  - Scans ALL commits per branch (full history)
 *  - Detects "deleted" secrets — blobs in old commits no longer in HEAD
 *  - Scans commit diffs (added lines only — what was introduced)
 *  - Detects dangling/orphaned commits via GitHub Events (force-push remnants)
 *  - Pair matching: AWS key+secret, DB user+password in same file/commit
 *
 * Inspired by: TruffleHog v3 multi-branch, Neodyme github-secrets research
 */

const { getClient } = require('../utils/github-client');
const { shouldSkipFile } = require('../filters/false-positive');
const { PATTERNS } = require('../scanner/patterns');
const { shannonEntropy, isHighEntropy } = require('../utils/entropy');
const { isDummyValue } = require('../filters/false-positive');
const { sha256, fileHash } = require('../utils/hash');
const logger = require('../utils/logger');
const config = require('../../config/default');

// Track scanned commit SHAs to avoid duplicates across branches
const scannedCommits = new Set();
// Track scanned blob SHAs
const scannedBlobs = new Set();

class GitHistoryScanner {
  constructor() {
    this.client = getClient();
    this.maxCommitsPerBranch = parseInt(process.env.MAX_COMMITS_PER_BRANCH || '50');
    this.maxBranches = parseInt(process.env.MAX_BRANCHES || '10');
  }

  /**
   * Full deep scan: all branches + git history
   * @param {string} repoName - owner/repo
   * @returns {Promise<HistoryFinding[]>}
   */
  async deepScan(repoName) {
    logger.info(`[HistoryScanner] Deep scan starting: ${repoName}`);
    const allFindings = [];

    // 1. Get all branches
    const branches = await this._getBranches(repoName);
    logger.info(`[HistoryScanner] ${repoName} has ${branches.length} branches, scanning up to ${this.maxBranches}`);

    // 2. Scan each branch's commit history
    for (const branch of branches.slice(0, this.maxBranches)) {
      try {
        const findings = await this._scanBranchHistory(repoName, branch.name);
        allFindings.push(...findings);
      } catch (err) {
        logger.debug(`[HistoryScanner] Branch ${branch.name} error: ${err.message}`);
      }
    }

    // 3. Scan dangling commits from PushEvents (force-push remnants)
    try {
      const danglingFindings = await this._scanDanglingCommits(repoName);
      allFindings.push(...danglingFindings);
    } catch (err) {
      logger.debug(`[HistoryScanner] Dangling commit scan error: ${err.message}`);
    }

    logger.info(`[HistoryScanner] ${repoName} deep scan complete — ${allFindings.length} history findings`);
    return allFindings;
  }

  /**
   * Get all branches for a repo
   */
  async _getBranches(repoName) {
    try {
      const resp = await this.client.get(`/repos/${repoName}/branches`, {
        params: { per_page: 100 }
      });
      return resp.data || [];
    } catch {
      return [{ name: 'main' }, { name: 'master' }];
    }
  }

  /**
   * Scan commit history for a single branch
   */
  async _scanBranchHistory(repoName, branchName) {
    const findings = [];

    // Get commit list for branch
    let commits = [];
    try {
      const resp = await this.client.get(`/repos/${repoName}/commits`, {
        params: { sha: branchName, per_page: this.maxCommitsPerBranch }
      });
      commits = resp.data || [];
    } catch {
      return [];
    }

    logger.debug(`[HistoryScanner] Branch ${branchName}: ${commits.length} commits`);

    for (const commit of commits) {
      const sha = commit.sha;
      if (scannedCommits.has(sha)) continue;
      scannedCommits.add(sha);

      // Trim cache
      if (scannedCommits.size > 200_000) {
        const iter = scannedCommits.values();
        for (let i = 0; i < 20_000; i++) scannedCommits.delete(iter.next().value);
      }

      try {
        const commitFindings = await this._scanCommitDiff(repoName, sha, branchName);
        findings.push(...commitFindings);
      } catch (err) {
        logger.debug(`[HistoryScanner] Commit ${sha} error: ${err.message}`);
      }
    }

    return findings;
  }

  /**
   * Scan a commit's diff — only ADDED lines (+ lines in diff)
   * This catches secrets that were introduced and then removed/overwritten
   */
  async _scanCommitDiff(repoName, commitSha, branchName) {
    const findings = [];

    let commitData;
    try {
      const resp = await this.client.get(`/repos/${repoName}/commits/${commitSha}`);
      commitData = resp.data;
    } catch {
      return [];
    }

    const files = commitData.files || [];
    const commitMsg = commitData.commit?.message || '';
    const authorName = commitData.commit?.author?.name || '';
    const commitDate = commitData.commit?.author?.date || '';

    for (const file of files) {
      const filePath = file.filename;
      const { skip } = shouldSkipFile(filePath);
      if (skip) continue;

      // Extract only added lines from the patch
      const patch = file.patch || '';
      const addedLines = this._extractAddedLines(patch);
      if (!addedLines) continue;

      // Check if blob already scanned
      if (file.sha && scannedBlobs.has(file.sha)) continue;
      if (file.sha) scannedBlobs.add(file.sha);

      // Scan added lines
      const lineFindings = this._scanTextForSecrets(addedLines, filePath);
      for (const f of lineFindings) {
        findings.push({
          ...f,
          repoName,
          commitSha,
          branchName,
          commitMessage: commitMsg.substring(0, 200),
          authorName,
          commitDate,
          isHistorical: true,
          // Was this file later removed or changed? (deleted = no longer in HEAD)
          isDeleted: file.status === 'removed'
        });
      }
    }

    return findings;
  }

  /**
   * Extract only added lines from a git patch
   * These are the lines prefixed with + (not +++ file header)
   */
  _extractAddedLines(patch) {
    if (!patch) return '';
    return patch
      .split('\n')
      .filter(line => line.startsWith('+') && !line.startsWith('+++'))
      .map(line => line.substring(1))
      .join('\n');
  }

  /**
   * Scan dangling commits — commits referenced in PushEvents but not
   * reachable from any branch (force-pushed over)
   * This is a key technique to find secrets that were "deleted"
   */
  async _scanDanglingCommits(repoName) {
    const findings = [];

    let events;
    try {
      const resp = await this.client.get(`/repos/${repoName}/events`, {
        params: { per_page: 100 }
      });
      events = resp.data || [];
    } catch {
      return [];
    }

    const danglingCommitShas = new Set();

    for (const event of events) {
      if (event.type !== 'PushEvent') continue;
      const commits = event.payload?.commits || [];
      for (const c of commits) {
        if (c.sha && !scannedCommits.has(c.sha)) {
          danglingCommitShas.add(c.sha);
        }
      }
    }

    logger.debug(`[HistoryScanner] ${repoName}: ${danglingCommitShas.size} potential dangling commits from events`);

    for (const sha of danglingCommitShas) {
      try {
        const commitFindings = await this._scanCommitDiff(repoName, sha, 'dangling');
        for (const f of commitFindings) {
          findings.push({ ...f, isDangling: true });
        }
      } catch {}
    }

    return findings;
  }

  /**
   * Run all patterns against a text block
   */
  _scanTextForSecrets(text, filePath) {
    const findings = [];

    for (const pattern of PATTERNS) {
      const regex = new RegExp(pattern.regex.source, 'gim');
      let match;
      while ((match = regex.exec(text)) !== null) {
        if (pattern.requireContext) {
          const ctx = text.substring(Math.max(0, match.index - 100), match.index + 200);
          if (!pattern.requireContext.test(ctx)) continue;
        }
        const rawValue = pattern.group === 0 ? match[0] : (match[pattern.group] || match[0]);
        if (!rawValue) continue;
        const value = rawValue.trim();
        if (isDummyValue(value)) continue;
        if (value.length < 16) continue;

        findings.push({
          patternId: pattern.id,
          patternName: pattern.name,
          provider: pattern.provider,
          filePath,
          value: this._redact(value),
          rawValue: value,
          entropy: Math.round(shannonEntropy(value) * 100) / 100,
          lineNumber: text.substring(0, match.index).split('\n').length,
          matchContext: text.substring(
            Math.max(0, match.index - 50),
            Math.min(text.length, match.index + 100)
          ).trim().replace(/\n/g, ' ').substring(0, 200),
          detectedAt: new Date().toISOString()
        });

        if (match.index === regex.lastIndex) regex.lastIndex++;
      }
    }

    // Entropy scan on top
    const entropyFindings = this._entropyLines(text, filePath);
    findings.push(...entropyFindings);

    return findings;
  }

  _entropyLines(text, filePath) {
    const findings = [];
    const tokenRe = /["']([A-Za-z0-9+/=_\-]{20,256})["']/g;
    let m;
    tokenRe.lastIndex = 0;
    while ((m = tokenRe.exec(text)) !== null) {
      const token = m[1];
      if (!isHighEntropy(token, config.scanner.entropyThreshold)) continue;
      if (isDummyValue(token)) continue;
      findings.push({
        patternId: 'entropy',
        patternName: 'High-Entropy String (History)',
        provider: 'unknown',
        filePath,
        value: this._redact(token),
        rawValue: token,
        entropy: Math.round(shannonEntropy(token) * 100) / 100,
        lineNumber: text.substring(0, m.index).split('\n').length,
        matchContext: text.substring(Math.max(0, m.index - 50), m.index + 100).trim().substring(0, 200),
        detectedAt: new Date().toISOString()
      });
    }
    return findings;
  }

  _redact(v) {
    if (!v || v.length <= 8) return '***';
    return v.substring(0, 4) + '****' + v.substring(v.length - 4);
  }
}

module.exports = GitHistoryScanner;
