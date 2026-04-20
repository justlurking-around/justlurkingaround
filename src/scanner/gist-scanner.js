'use strict';

/**
 * GitHub Gist Scanner
 *
 * Scans public GitHub Gists for secrets.
 * Gists are a major source of accidental credential exposure —
 * devs paste .env files, config snippets, test scripts with live keys.
 *
 * Sources:
 *  - Public gist timeline: GET /gists/public
 *  - User gists (if username given): GET /users/:user/gists
 *  - Search-triggered gists: from GitHub code search
 */

const { getClient } = require('../utils/github-client');
const { PATTERNS }  = require('./patterns');
const { shouldSkipFile, isDummyValue, isNoisyValue } = require('../filters/false-positive');
const { isHighEntropy, shannonEntropy } = require('../utils/entropy');
const logger = require('../utils/logger');

class GistScanner {
  constructor() {
    this.client = getClient();
    this._seenGistIds = new Set();
  }

  /**
   * Scan recent public gists
   * @param {number} pages  - number of pages to fetch (each = 30 gists)
   */
  async scanPublicGists(pages = 3) {
    const allFindings = [];
    logger.info(`[GistScanner] Scanning public gists (${pages} pages)...`);

    for (let page = 1; page <= pages; page++) {
      try {
        const resp = await this.client.get('/gists/public', {
          params: { per_page: 30, page }
        });
        const gists = resp.data || [];

        for (const gist of gists) {
          if (this._seenGistIds.has(gist.id)) continue;
          this._seenGistIds.add(gist.id);

          const findings = await this._scanGist(gist);
          allFindings.push(...findings);
        }
      } catch (err) {
        logger.warn(`[GistScanner] Page ${page} error: ${err.message}`);
      }
    }

    logger.info(`[GistScanner] Gist scan complete — ${allFindings.length} findings`);
    return allFindings;
  }

  /**
   * Scan all public gists for a specific GitHub user
   */
  async scanUserGists(username) {
    const allFindings = [];
    try {
      const resp = await this.client.get(`/users/${username}/gists`, {
        params: { per_page: 100 }
      });
      const gists = resp.data || [];
      logger.info(`[GistScanner] User ${username}: ${gists.length} gists`);

      for (const gist of gists) {
        const findings = await this._scanGist(gist);
        allFindings.push(...findings);
      }
    } catch (err) {
      logger.warn(`[GistScanner] User ${username} error: ${err.message}`);
    }
    return allFindings;
  }

  async _scanGist(gist) {
    const findings = [];
    const gistUrl  = gist.html_url;
    const gistId   = gist.id;
    const owner    = gist.owner?.login || 'unknown';
    const files    = gist.files || {};

    for (const [filename, fileInfo] of Object.entries(files)) {
      const { skip } = shouldSkipFile(filename);
      if (skip) continue;
      if (!fileInfo.raw_url) continue;

      // File size guard
      if (fileInfo.size > 500 * 1024) continue;

      let content;
      try {
        const resp = await this.client.get(fileInfo.raw_url, {
          baseURL: '', responseType: 'text', timeout: 10000
        });
        content = resp.data;
      } catch { continue; }

      if (!content || typeof content !== 'string') continue;

      const fileFindings = this._scanContent(content, filename);
      for (const f of fileFindings) {
        findings.push({
          ...f,
          repoName:   `gist:${owner}/${gistId}`,
          repoUrl:    gistUrl,
          gistId,
          gistOwner:  owner,
          isGist:     true,
          filePath:   filename,
        });
      }
    }
    return findings;
  }

  _scanContent(content, filename) {
    const findings = [];

    for (const pattern of PATTERNS) {
      const regex = new RegExp(pattern.regex.source, 'gim');
      let m;
      while ((m = regex.exec(content)) !== null) {
        if (pattern.requireContext) {
          const ctx = content.substring(Math.max(0, m.index - 100), m.index + 200);
          if (!pattern.requireContext.test(ctx)) { if (m.index === regex.lastIndex) regex.lastIndex++; continue; }
        }
        const raw = pattern.group === 0 ? m[0] : (m[pattern.group] || m[0]);
        if (!raw) { if (m.index === regex.lastIndex) regex.lastIndex++; continue; }
        const value = raw.trim();
        if (isDummyValue(value) || isNoisyValue(value) || value.length < 16) { if (m.index === regex.lastIndex) regex.lastIndex++; continue; }
        findings.push({
          patternId:   pattern.id,
          patternName: pattern.name,
          provider:    pattern.provider,
          filePath:    filename,
          value:       this._redact(value),
          rawValue:    value,
          entropy:     Math.round(shannonEntropy(value) * 100) / 100,
          lineNumber:  content.substring(0, m.index).split('\n').length,
          matchContext: content.substring(Math.max(0, m.index - 50), m.index + 100).trim().substring(0, 200),
          detectedAt:  new Date().toISOString(),
        });
        if (m.index === regex.lastIndex) regex.lastIndex++;
      }
    }

    // Entropy pass
    const tokenRe = /["']([A-Za-z0-9+/=_\-]{20,256})["']/g;
    let m2;
    while ((m2 = tokenRe.exec(content)) !== null) {
      const token = m2[1];
      if (!isHighEntropy(token, 4.5)) continue;
      if (isDummyValue(token) || isNoisyValue(token)) continue;
      findings.push({
        patternId: 'entropy', patternName: 'High-Entropy String (Gist)', provider: 'unknown',
        filePath: filename, value: this._redact(token), rawValue: token,
        entropy: Math.round(shannonEntropy(token) * 100) / 100,
        lineNumber: content.substring(0, m2.index).split('\n').length,
        matchContext: content.substring(Math.max(0, m2.index - 50), m2.index + 100).trim().substring(0, 200),
        detectedAt: new Date().toISOString(),
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

module.exports = GistScanner;
