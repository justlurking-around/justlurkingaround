'use strict';

/**
 * WORKER v2 — Full Orchestration Loop (Day 2-5 enhanced)
 *
 * Integrates:
 *  - Real-time Events poller (Phase 2)
 *  - GitHub Search Scanner (Day 5) — proactive discovery
 *  - Git History Scanner (Day 2) — deep historical scan
 *  - Context Analyzer + Pair Matcher (Day 2)
 *  - Notification System (Day 3) — Discord/Slack/Telegram
 *  - Scan Reporter (Day 3) — JSON/MD/CSV/SARIF
 *  - REST API + Dashboard (Day 4)
 *  - Rate limit handling throughout
 */

require('dotenv').config();

const pLimit = require('p-limit');

const EventsPoller       = require('../poller/events');
const { classifyRepo }   = require('../filters/active-repo');
const { detectAIRepo }   = require('../filters/ai-detector');
const { getQueue }       = require('../queue');
const ScannerEngine      = require('../scanner/engine');
const GitHistoryScanner  = require('../history/git-history-scanner');
const GitHubSearchScanner= require('../search/github-search');
const { annotatePairs }  = require('../scanner/pair-matcher');
const { annotateWithContext } = require('../scanner/context-analyzer');
const { validateFinding, RESULTS } = require('../validator');
const StreamValidator    = require('../validator/stream-validator');
const { getDB }          = require('../db');
const { getVault }       = require('../db/vault');
const { getClient }      = require('../utils/github-client');
const { getNotifier }    = require('../notifications');
const { getAllowlist }   = require('../utils/allowlist');
const { getBlame }       = require('../scanner/blame');
const GistScanner        = require('../scanner/gist-scanner');
const { getRevocationGuide } = require('../scanner/revocation-guide');
const Reporter           = require('../reporter');
const APIServer          = require('../api/server');
const { sha256 }         = require('../utils/hash');
const { sanitizeRepoName, sanitizeForLog } = require('../utils/security');
const logger             = require('../utils/logger');
const config             = require('../../config/default');

const repoLimit = pLimit(config.scanner.concurrentRepos);

class Worker {
  constructor() {
    this.poller       = null;
    this.queue        = null;
    this.db           = null;
    this.scanner      = new ScannerEngine();
    this.histScanner  = new GitHistoryScanner();
    this.searchScanner= new GitHubSearchScanner();
    this.reporter     = new Reporter('./reports');
    this.notifier     = getNotifier();
    this.client       = getClient();
    this.vault        = getVault();
    this.allowlist    = getAllowlist();
    this.gistScanner  = new GistScanner();
    this.apiServer    = null;
    this.running      = false;

    this.stats = {
      polled: 0, queued: 0, scanned: 0,
      findings: 0, valid: 0, historical: 0
    };

    // Daily summary cron
    this._lastDailySummary = Date.now();
  }

  async start() {
    logger.info('╔══════════════════════════════════════════════════╗');
    logger.info('║   AI Secret Scanner v2.0 — Worker Starting       ║');
    logger.info('║   Deep Scan | History | Notifications | Dashboard ║');
    logger.info('╚══════════════════════════════════════════════════╝');

    if (process.env.GITHUB_TOKEN) {
      logger.info('[Worker] GitHub token detected — authenticated mode (5000 req/hr)');
    } else {
      logger.warn('[Worker] No GITHUB_TOKEN — unauthenticated mode (60 req/hr), set GITHUB_TOKEN for best results');
    }

    this.db     = await getDB();
    this.queue  = await getQueue();
    this.running = true;

    // Start web dashboard + API
    if (process.env.ENABLE_API !== 'false') {
      this.apiServer = new APIServer();
      this.apiServer.start();
    }

    // Start real-time Events poller
    this.poller = new EventsPoller({ pollInterval: 60_000 });
    this.poller.on('repo', event => this._handlePolledRepo(event));
    this.poller.start();

    // Run GitHub Search Scanner immediately then every 30 min
    this._runSearchScanner();
    setInterval(() => this._runSearchScanner(), 30 * 60_000);

    // Scan public Gists every 15 min
    if (process.env.GITHUB_TOKEN) {
      setTimeout(() => this._runGistScanner(), 30_000);
      setInterval(() => this._runGistScanner(), 15 * 60_000);
    }

    // Start queue consumer
    this._consumeLoop();

    // Stats every 5 min
    setInterval(() => this._printStats(), 5 * 60_000);

    // Daily summary notification
    setInterval(() => this._maybeSendDailySummary(), 60 * 60_000);

    logger.info('[Worker] All systems running. Dashboard at http://localhost:' +
      (process.env.API_PORT || '3000'));
  }

  stop() {
    this.running = false;
    if (this.poller) this.poller.stop();
    logger.info('[Worker] Stopped gracefully.');
  }

  // ── Search Scanner (proactive discovery) ──────────────────────────────────

  async _runSearchScanner() {
    if (!process.env.GITHUB_TOKEN) return; // search requires auth
    logger.info('[Worker] Running GitHub Search Scanner...');
    try {
      const repos = await this.searchScanner.findRecentAIRepos();
      for (const repo of repos) {
        await this.queue.push({
          ...repo,
          priority: { label: 'active', intervalMs: 300_000 },
          fromSearch: true
        });
      }
      logger.info(`[Worker] Search scanner added ${repos.length} repos to queue`);
    } catch (err) {
      logger.warn(`[Worker] Search scanner error: ${err.message}`);
    }
  }

  // ── Event Handler ──────────────────────────────────────────────────────────

  async _runGistScanner() {
    logger.info('[Worker] Scanning public Gists...');
    try {
      const findings = await this.gistScanner.scanPublicGists(2);
      for (const f of findings) {
        const sv = new StreamValidator({
          onValid: async (finding, validation) => {
            this.stats.valid++;
            const record = this._buildRecord(
              { repoName: finding.repoName, repoUrl: finding.repoUrl },
              finding, validation
            );
            await this.db.insertFinding(record);
            this.vault.save({ ...finding, validationDetail: validation.detail });
            await this.notifier.alert({ ...record, repoUrl: finding.repoUrl }, true);
            logger.warn(`!! GIST LIVE SECRET! Gist=${finding.repoName} Provider=${finding.provider}`);
          },
          onFinding: () => {}
        });
        sv.beginRepo(f.repoName);
        await sv.notifyFinding(f);
      }
    } catch (err) {
      logger.warn(`[Worker] Gist scanner error: ${err.message}`);
    }
  }

  async _handlePolledRepo(event) {
    this.stats.polled++;
    // Sanitize repo name from untrusted GitHub Events API payload
    const safeRepoName = sanitizeRepoName(event.repoName);
    if (!safeRepoName) {
      logger.debug(`[Worker] Invalid repo name rejected: ${sanitizeForLog(event.repoName)}`);
      return;
    }
    event = { ...event, repoName: safeRepoName };

    // Allowlist check
    if (this.allowlist.isAllowlisted(event.repoName)) {
      logger.debug(`[Worker] Skipping allowlisted repo: ${event.repoName}`);
      return;
    }
    const { allowed, priority } = classifyRepo(event);
    if (!allowed) return;

    const enriched = await this._enrichWithAISignals(event);
    const queued = await this.queue.push({ ...event, ...enriched, priority });
    if (queued) {
      this.stats.queued++;
      logger.debug(`[Worker] Queued [${priority.label}] ${event.repoName}`);
    }
  }

  async _enrichWithAISignals(event) {
    try {
      const resp = await this.client.get(`/repos/${event.repoName}/contents/`);
      const files = (resp.data || []).map(f => f.name);

      let readmeContent = '';
      try {
        const r = await this.client.get(`/repos/${event.repoName}/readme`,
          { headers: { Accept: 'application/vnd.github.v3.raw' } });
        readmeContent = r.data || '';
      } catch {}

      const aiResult = detectAIRepo({
        filePaths: files, description: event.description || '',
        readmeContent, commitMessages: (event.commits || []).map(c => c.message)
      });
      return { isAI: aiResult.isAI, aiConfidence: aiResult.confidence, aiSignals: aiResult.signals };
    } catch {
      return { isAI: false, aiConfidence: 0, aiSignals: {} };
    }
  }

  // ── Queue Consumer ─────────────────────────────────────────────────────────

  async _consumeLoop() {
    while (this.running) {
      try {
        const item = await this.queue.pop();
        if (!item) { await this._sleep(5000); continue; }

        repoLimit(async () => {
          try { await this._processRepo(item); }
          catch (err) { logger.error(`[Worker] processRepo error ${item.repoName}: ${err.message}`); }
        });
      } catch (err) {
        logger.error(`[Worker] consumeLoop error: ${err.message}`);
        await this._sleep(10_000);
      }
    }
  }

  // ── Repo Processor — streaming validation ───────────────────────────────

  async _processRepo(item) {
    logger.info(`[Worker] Processing: ${item.repoName} [AI=${item.isAI}, conf=${item.aiConfidence}, src=${item.fromSearch ? 'search' : 'events'}]`);

    await this.db.upsertRepo({
      repoName: item.repoName, repoUrl: item.repoUrl,
      isAI: item.isAI || false, aiConfidence: item.aiConfidence || 0,
      aiSignals: item.aiSignals || {}, priority: item.priority?.label || 'unknown'
    });

    // ── Set up streaming validator (fires validation mid-scan on hits) ──────
    const streamValidator = new StreamValidator({
      onValid: async (finding, validation) => {
        // VALID secret found mid-scan — alert immediately
        this.stats.valid++;
        const record = this._buildRecord(item, finding, validation);
        await this.db.insertFinding(record);

        // Save encrypted to vault
        this.vault.save({
          ...finding,
          repoName: item.repoName,
          validationDetail: validation.detail,
          secretHash: record.secretHash
        });

        // Get blame info (who committed it)
        let blameInfo = null;
        try {
          blameInfo = await getBlame(item.repoName, finding.filePath, finding.lineNumber);
        } catch {}

        // Get revocation guide
        const guide = getRevocationGuide(finding.provider);

        logger.warn(
          `!! LIVE SECRET FOUND! Repo=${item.repoName} ` +
          `Provider=${finding.provider} Pattern=${finding.patternName} ` +
          `File=${finding.filePath}` +
          (finding.isHistorical ? ' [HISTORICAL]' : '') +
          (blameInfo ? ` | Author=${blameInfo.authorName} <${blameInfo.authorEmail}>` : '') +
          ` | ${validation.detail}`
        );
        logger.warn(`   Severity: ${guide.severity} | Revoke: ${guide.revokeUrl || 'see provider docs'}`);

        await this.notifier.alert({
          ...record,
          repoUrl: item.repoUrl,
          blameInfo,
          revocationUrl: guide.revokeUrl,
          severity: guide.severity
        }, true);
        if (this.apiServer) this.apiServer.pushFinding(record);
      },
      onFinding: (finding, validation) => {
        if (this.apiServer) this.apiServer.pushFinding(
          this._buildRecord(item, finding, validation)
        );
      }
    });

    streamValidator.beginRepo(item.repoName);

    // ── Layer 1: Surface scan — findings streamed to validator as found ──────
    let surfaceFindings = await this.scanner.scanRepo(item);
    this.stats.scanned++;

    // Stream surface findings through validator immediately
    for (const f of surfaceFindings) {
      await streamValidator.notifyFinding({ ...f, repoName: item.repoName });
    }

    // ── Layer 2: Deep git history scan (for AI / active / has-surface-hits) ─
    let historyFindings = [];
    const shouldDeepScan = item.isAI ||
      item.aiConfidence > 30 ||
      item.priority?.label === 'very_active' ||
      surfaceFindings.length > 0;

    if (shouldDeepScan) {
      logger.info(`[Worker] Starting deep history scan: ${item.repoName}`);
      historyFindings = await this.histScanner.deepScan(item.repoName);
      this.stats.historical += historyFindings.length;
      for (const f of historyFindings) {
        await streamValidator.notifyFinding({ ...f, repoName: item.repoName, isHistorical: true });
      }
    }

    // ── Drain batch queue (entropy + low-priority findings) ─────────────────
    const batchResults = await streamValidator.drainBatch();

    // ── Merge all findings for reporting ────────────────────────────────────
    const allFindings = [
      ...surfaceFindings.map(f  => ({ ...f,  repoName: item.repoName, repoUrl: item.repoUrl })),
      ...historyFindings.map(f  => ({ ...f,  repoName: item.repoName, repoUrl: item.repoUrl, isHistorical: true })),
    ];

    if (allFindings.length === 0) return;

    const annotated = annotateWithContext(annotatePairs(allFindings));

    // ── Persist findings not yet saved by stream validator ─────────────────
    const alertedPairs = new Set();
    const seenHashes   = new Set();

    const scanResult = {
      repoName: item.repoName,
      findings: [],
      stats: { filesScanned: 0, branchesScanned: 0, commitsScanned: 0 },
      scanDate: new Date().toISOString()
    };

    for (const finding of annotated) {
      const secretHash = sha256(finding.rawValue || '');
      if (seenHashes.has(secretHash)) continue;
      seenHashes.add(secretHash);

      // Stream validator may have already validated this — use cached result if available
      const cachedResult = batchResults.find(r => sha256(r.rawValue || '') === secretHash);
      const validation = cachedResult
        ? { result: cachedResult.validationResult, detail: cachedResult.validationDetail }
        : { result: RESULTS.SKIPPED, detail: 'already validated by stream' };

      const record = this._buildRecord(item, finding, validation);

      // Only insert if not already inserted by onValid callback
      if (validation.result !== RESULTS.VALID) {
        await this.db.insertFinding(record);
      }
      scanResult.findings.push(record);
      this.stats.findings++;

      // Pair alerts
      if (finding.confidence >= 75 && finding.isPaired) {
        const pairKey = `${finding.pairName}::${finding.filePath}`;
        if (!alertedPairs.has(pairKey)) {
          alertedPairs.add(pairKey);
          logger.warn(`[HIGH-CONF PAIR] ${item.repoName} | ${finding.pairName} | ${finding.filePath}`);
          await this.notifier.alert(record, false);
        }
      } else if (validation.result !== RESULTS.VALID) {
        // SKIPPED/INVALID are debug only — they flood the screen at info level
        const logFn = validation.result === 'VALID' ? 'warn'
                    : validation.result === 'ERROR'  ? 'warn'
                    : 'debug';
        logger[logFn](`[Finding] ${item.repoName} | ${finding.patternName} | ${finding.filePath} | ${validation.result}`);
      }
    }

    // ── Generate report ────────────────────────────────────────────────────
    if (scanResult.findings.length > 0) {
      try { await this.reporter.generateAll(scanResult); }
      catch (err) { logger.debug(`[Worker] Report error: ${err.message}`); }
    }
  }

  // ── Helper: build DB record from finding + validation ────────────────────
  _buildRecord(item, finding, validation) {
    return {
      repoName:         item.repoName,
      repoUrl:          item.repoUrl,
      filePath:         finding.filePath,
      patternId:        finding.patternId,
      patternName:      finding.patternName,
      provider:         finding.provider,
      secretHash:       sha256(finding.rawValue || ''),
      value:            finding.value,
      entropy:          finding.entropy,
      lineNumber:       finding.lineNumber,
      matchContext:     finding.matchContext,
      validationResult: validation.result,
      validationDetail: validation.detail,
      detectedAt:       finding.detectedAt || new Date().toISOString(),
      isHistorical:     finding.isHistorical || false,
      commitSha:        finding.commitSha    || null,
      isPaired:         finding.isPaired     || false,
      confidence:       finding.confidence   || 50
    };
  }

  // ── Daily Summary ──────────────────────────────────────────────────────────

  async _maybeSendDailySummary() {
    const hoursSinceLast = (Date.now() - this._lastDailySummary) / (60 * 60_000);
    if (hoursSinceLast < 23) return;

    try {
      const stats = await this.db.getStats();
      await this.notifier.dailySummary(stats);
      this._lastDailySummary = Date.now();
    } catch (err) {
      logger.warn(`[Worker] Daily summary error: ${err.message}`);
    }
  }

  _printStats() {
    logger.info(`[Stats] Polled=${this.stats.polled} Queued=${this.stats.queued} ` +
      `Scanned=${this.stats.scanned} Findings=${this.stats.findings} ` +
      `Historical=${this.stats.historical} Valid🔑=${this.stats.valid}`);
  }

  _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}

// ── Entry point ───────────────────────────────────────────────────────────────

async function main() {
  const worker = new Worker();

  process.on('SIGINT',  () => { worker.stop(); process.exit(0); });
  process.on('SIGTERM', () => { worker.stop(); process.exit(0); });
  process.on('uncaughtException', err => {
    logger.error(`[Worker] Uncaught: ${err.message}\n${err.stack}`);
  });
  process.on('unhandledRejection', reason => {
    logger.error(`[Worker] Unhandled rejection: ${reason}`);
  });

  await worker.start();
}

main().catch(err => {
  logger.error(`[Worker] Fatal: ${err.message}`);
  process.exit(1);
});
