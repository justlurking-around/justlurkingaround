'use strict';

/**
 * DAY 3 — Scan Reporter
 *
 * Generates structured reports from scan results:
 *  - JSON report (machine-readable)
 *  - Markdown report (human-readable, GitHub-ready)
 *  - CSV export
 *  - SARIF format (industry standard for security tools)
 *
 * SARIF = Static Analysis Results Interchange Format
 * Used by GitHub Advanced Security, VS Code, and CI tools
 */

const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

class Reporter {
  constructor(outputDir = './reports') {
    this.outputDir = outputDir;
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
  }

  /**
   * Generate all report formats for a scan run
   */
  async generateAll(scanResult) {
    const { repoName, findings, stats, scanDate } = scanResult;
    const safeName = repoName.replace('/', '_');
    const dateStr = (scanDate || new Date().toISOString()).split('T')[0];
    const prefix = `${this.outputDir}/${safeName}_${dateStr}`;

    const reports = {};

    reports.json = await this.generateJSON(scanResult, `${prefix}.json`);
    reports.markdown = await this.generateMarkdown(scanResult, `${prefix}.md`);
    reports.csv = await this.generateCSV(findings, `${prefix}.csv`);
    reports.sarif = await this.generateSARIF(scanResult, `${prefix}.sarif.json`);

    logger.info(`[Reporter] Reports written to ${this.outputDir}/`);
    return reports;
  }

  // ── JSON Report ─────────────────────────────────────────────────────────────

  async generateJSON(scanResult, outPath) {
    const output = {
      meta: {
        tool: 'ai-secret-scanner',
        version: '2.0.0',
        scanDate: scanResult.scanDate || new Date().toISOString(),
        repoName: scanResult.repoName,
        repoUrl: `https://github.com/${scanResult.repoName}`
      },
      stats: scanResult.stats || {},
      findings: (scanResult.findings || []).map(f => ({
        ...f,
        rawValue: undefined  // never export raw secrets
      }))
    };
    fs.writeFileSync(outPath, JSON.stringify(output, null, 2), 'utf8');
    logger.debug(`[Reporter] JSON: ${outPath}`);
    return outPath;
  }

  // ── Markdown Report ─────────────────────────────────────────────────────────

  async generateMarkdown(scanResult, outPath) {
    const { repoName, findings = [], stats = {} } = scanResult;
    const repoUrl = `https://github.com/${repoName}`;
    const scanDate = scanResult.scanDate || new Date().toISOString();

    const validFindings = findings.filter(f => f.validationResult === 'VALID');
    const invalidFindings = findings.filter(f => f.validationResult !== 'VALID');

    const lines = [
      `# 🔍 Secret Scan Report`,
      ``,
      `**Repository:** [${repoName}](${repoUrl})  `,
      `**Scan Date:** ${scanDate}  `,
      `**Tool:** AI Secret Scanner v2.0.0  `,
      ``,
      `---`,
      ``,
      `## Summary`,
      ``,
      `| Metric | Value |`,
      `|--------|-------|`,
      `| Total Findings | ${findings.length} |`,
      `| 🚨 Live/Validated Secrets | **${validFindings.length}** |`,
      `| ⚠️ Unvalidated | ${invalidFindings.length} |`,
      `| Files Scanned | ${stats.filesScanned || 'N/A'} |`,
      `| Branches Scanned | ${stats.branchesScanned || 'N/A'} |`,
      `| Historical Commits | ${stats.commitsScanned || 'N/A'} |`,
      ``,
    ];

    if (validFindings.length > 0) {
      lines.push(`## 🚨 Critical — Live Secrets`, ``);
      for (const f of validFindings) {
        lines.push(
          `### ${f.patternName} — \`${f.provider}\``,
          ``,
          `- **File:** \`${f.filePath}\` (line ${f.lineNumber || '?'})`,
          `- **Secret:** \`${f.value || f.secretRedacted}\``,
          `- **Entropy:** ${f.entropy}`,
          `- **Validation:** ${f.validationResult} — ${f.validationDetail || ''}`,
          ...(f.isHistorical ? [`- **⚠️ Historical:** Found in commit \`${f.commitSha?.substring(0,8)}\``] : []),
          ``,
        );
      }
    }

    if (invalidFindings.length > 0) {
      lines.push(`## ⚠️ Other Findings`, ``);
      lines.push(`| Provider | Pattern | File | Line | Entropy | Status |`);
      lines.push(`|----------|---------|------|------|---------|--------|`);
      for (const f of invalidFindings.slice(0, 50)) {
        lines.push(`| ${f.provider} | ${f.patternName} | \`${f.filePath?.substring(0,40)}\` | ${f.lineNumber || '?'} | ${f.entropy} | ${f.validationResult} |`);
      }
      if (invalidFindings.length > 50) {
        lines.push(``, `_...and ${invalidFindings.length - 50} more findings (see JSON report for full list)_`);
      }
      lines.push(``);
    }

    lines.push(
      `---`,
      ``,
      `## Remediation`,
      ``,
      `For each live secret found:`,
      `1. **Immediately revoke** the credential in the provider's dashboard`,
      `2. **Rotate** — generate a new credential`,
      `3. **Remove** from repository history using \`git filter-repo\` or BFG Repo Cleaner`,
      `4. **Add** to \`.gitignore\` / use environment variables going forward`,
      ``,
      `> ⚠️ Even after removal from git history, secrets may be cached by GitHub or other services.`,
      `> Contact GitHub Support to fully purge cached views of removed data.`,
      ``,
      `---`,
      `*Generated by [AI Secret Scanner](https://github.com/justlurking-around/justlurkingaround)*`
    );

    fs.writeFileSync(outPath, lines.join('\n'), 'utf8');
    logger.debug(`[Reporter] Markdown: ${outPath}`);
    return outPath;
  }

  // ── CSV Export ──────────────────────────────────────────────────────────────

  async generateCSV(findings, outPath) {
    const headers = ['repo_name','file_path','pattern_name','provider','entropy','line_number','validation_result','is_historical','commit_sha','detected_at'];
    const rows = (findings || []).map(f => [
      f.repoName || '', f.filePath || '', f.patternName || '', f.provider || '',
      f.entropy || '', f.lineNumber || '', f.validationResult || '', f.isHistorical || false,
      f.commitSha || '', f.detectedAt || ''
    ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));

    fs.writeFileSync(outPath, [headers.join(','), ...rows].join('\n'), 'utf8');
    logger.debug(`[Reporter] CSV: ${outPath}`);
    return outPath;
  }

  // ── SARIF Report (GitHub Advanced Security compatible) ─────────────────────

  async generateSARIF(scanResult, outPath) {
    const { repoName, findings = [] } = scanResult;

    const sarif = {
      version: '2.1.0',
      $schema: 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json',
      runs: [{
        tool: {
          driver: {
            name: 'ai-secret-scanner',
            version: '2.0.0',
            informationUri: 'https://github.com/justlurking-around/justlurkingaround',
            rules: this._buildSARIFRules(findings)
          }
        },
        results: findings.map(f => ({
          ruleId: f.patternId || 'secret',
          level: f.validationResult === 'VALID' ? 'error' : 'warning',
          message: {
            text: `${f.patternName} detected in ${f.filePath}${f.isHistorical ? ' (historical commit)' : ''}. Entropy: ${f.entropy}. Validation: ${f.validationResult}.`
          },
          locations: [{
            physicalLocation: {
              artifactLocation: {
                uri: f.filePath || '',
                uriBaseId: '%SRCROOT%'
              },
              region: {
                startLine: f.lineNumber || 1,
                snippet: { text: f.matchContext || '' }
              }
            }
          }],
          partialFingerprints: {
            secretHash: f.secretHash || ''
          },
          properties: {
            provider: f.provider,
            entropy: f.entropy,
            validationResult: f.validationResult,
            isHistorical: f.isHistorical || false
          }
        }))
      }]
    };

    fs.writeFileSync(outPath, JSON.stringify(sarif, null, 2), 'utf8');
    logger.debug(`[Reporter] SARIF: ${outPath}`);
    return outPath;
  }

  _buildSARIFRules(findings) {
    const seen = new Set();
    const rules = [];
    for (const f of findings) {
      if (seen.has(f.patternId)) continue;
      seen.add(f.patternId);
      rules.push({
        id: f.patternId || 'secret',
        name: f.patternName || 'Secret',
        shortDescription: { text: `${f.patternName} (${f.provider})` },
        fullDescription: { text: `Detects ${f.patternName} credentials for ${f.provider}` },
        defaultConfiguration: { level: 'warning' }
      });
    }
    return rules;
  }
}

module.exports = Reporter;
