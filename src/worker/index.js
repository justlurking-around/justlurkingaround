'use strict';

/**
 * PHASE 11 — Background Worker
 *
 * Full orchestration loop:
 *   1. Poll GitHub Events API
 *   2. Filter active repos
 *   3. Detect AI signatures
 *   4. Push to priority queue
 *   5. Pop from queue → scan files
 *   6. Validate secrets
 *   7. Persist findings to DB
 *
 * Runs continuously. Auto-restarts on error.
 */

require('dotenv').config();

const pLimit = require('p-limit');
const EventsPoller    = require('../poller/events');
const { classifyRepo } = require('../filters/active-repo');
const { detectAIRepo } = require('../filters/ai-detector');
const { getQueue }    = require('../queue');
const ScannerEngine   = require('../scanner/engine');
const { validateFinding, RESULTS } = require('../validator');
const { getDB }       = require('../db');
const { getClient }   = require('../utils/github-client');
const { sha256 }      = require('../utils/hash');
const logger          = require('../utils/logger');
const config          = require('../../config/default');

const repoLimit = pLimit(config.scanner.concurrentRepos);

class Worker {
  constructor() {
    this.poller  = null;
    this.queue   = null;
    this.db      = null;
    this.scanner = new ScannerEngine();
    this.client  = getClient();
    this.running = false;
    this.stats   = { polled: 0, queued: 0, scanned: 0, findings: 0, valid: 0 };
  }

  async start() {
    logger.info('╔══════════════════════════════════════════╗');
    logger.info('║   AI Secret Scanner — Worker Starting    ║');
    logger.info('╚══════════════════════════════════════════╝');

    this.db    = await getDB();
    this.queue = await getQueue();
    this.running = true;

    // Start event poller
    this.poller = new EventsPoller({ pollInterval: 60_000 });
    this.poller.on('repo', event => this._handlePolledRepo(event));
    this.poller.start();

    // Start queue consumer loop
    this._consumeLoop();

    // Stats printer every 5 minutes
    setInterval(() => this._printStats(), 5 * 60_000);

    logger.info('[Worker] Running. Ctrl+C to stop.');
  }

  stop() {
    this.running = false;
    if (this.poller) this.poller.stop();
    logger.info('[Worker] Stopped.');
  }

  // ── Step 1-4: Handle incoming events ─────────────────────────────────────

  async _handlePolledRepo(event) {
    this.stats.polled++;

    // Filter: must be recently active
    const { allowed, priority, ageMinutes } = classifyRepo(event);
    if (!allowed) return;

    // Enrich: fetch AI detection signals
    const enriched = await this._enrichWithAISignals(event);

    // Push to queue with priority
    const item = {
      ...event,
      ...enriched,
      priority
    };

    const queued = await this.queue.push(item);
    if (queued) {
      this.stats.queued++;
      logger.debug(`[Worker] Queued [${priority.label}] ${event.repoName} (age: ${Math.round(ageMinutes)}m)`);
    }
  }

  async _enrichWithAISignals(event) {
    try {
      // Get file listing to check for AI indicator files
      const resp = await this.client.get(`/repos/${event.repoName}/contents/`);
      const files = (resp.data || []).map(f => f.name);

      // Fetch README for keyword scan
      let readmeContent = '';
      try {
        const readmeResp = await this.client.get(`/repos/${event.repoName}/readme`, {
          headers: { Accept: 'application/vnd.github.v3.raw' }
        });
        readmeContent = readmeResp.data || '';
      } catch {}

      const aiResult = detectAIRepo({
        filePaths: files,
        description: event.description || '',
        readmeContent,
        commitMessages: (event.commits || []).map(c => c.message)
      });

      return {
        isAI: aiResult.isAI,
        aiConfidence: aiResult.confidence,
        aiSignals: aiResult.signals
      };
    } catch {
      return { isAI: false, aiConfidence: 0, aiSignals: {} };
    }
  }

  // ── Step 5-7: Queue consumer ───────────────────────────────────────────────

  async _consumeLoop() {
    while (this.running) {
      try {
        const item = await this.queue.pop();
        if (!item) {
          await this._sleep(5000); // no work, wait 5s
          continue;
        }

        // Process in parallel up to concurrentRepos limit
        repoLimit(async () => {
          try {
            await this._processRepo(item);
          } catch (err) {
            logger.error(`[Worker] processRepo error for ${item.repoName}: ${err.message}`);
          }
        });

      } catch (err) {
        logger.error(`[Worker] consumeLoop error: ${err.message}`);
        await this._sleep(10_000);
      }
    }
  }

  async _processRepo(item) {
    logger.info(`[Worker] Processing: ${item.repoName} [AI=${item.isAI}, conf=${item.aiConfidence}]`);

    // Persist repo record
    await this.db.upsertRepo({
      repoName:    item.repoName,
      repoUrl:     item.repoUrl,
      isAI:        item.isAI || false,
      aiConfidence: item.aiConfidence || 0,
      aiSignals:   item.aiSignals || {},
      priority:    item.priority?.label || 'unknown'
    });

    // Scan all files
    const findings = await this.scanner.scanRepo(item);
    this.stats.scanned++;

    if (findings.length === 0) return;
    logger.info(`[Worker] ${item.repoName} — ${findings.length} raw findings, validating...`);

    // Validate + persist each finding
    for (const finding of findings) {
      const secretHash = sha256(finding.rawValue);
      const validation = await validateFinding(finding);

      const record = {
        repoName:         item.repoName,
        filePath:         finding.filePath,
        patternId:        finding.patternId,
        patternName:      finding.patternName,
        provider:         finding.provider,
        secretHash,
        value:            finding.value,         // redacted
        entropy:          finding.entropy,
        lineNumber:       finding.lineNumber,
        matchContext:     finding.matchContext,
        validationResult: validation.result,
        validationDetail: validation.detail,
        detectedAt:       finding.detectedAt
      };

      await this.db.insertFinding(record);
      this.stats.findings++;

      if (validation.result === RESULTS.VALID) {
        this.stats.valid++;
        logger.warn(`🔑 VALID SECRET FOUND! Repo=${item.repoName} Provider=${finding.provider} Pattern=${finding.patternName} File=${finding.filePath} Detail=${validation.detail}`);
      } else {
        logger.info(`[Finding] ${item.repoName} | ${finding.patternName} | ${finding.filePath} | ${validation.result}`);
      }
    }
  }

  _printStats() {
    logger.info(`[Stats] Polled=${this.stats.polled} Queued=${this.stats.queued} Scanned=${this.stats.scanned} Findings=${this.stats.findings} ValidSecrets=${this.stats.valid}`);
  }

  _sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// ── Entry point ───────────────────────────────────────────────────────────────

async function main() {
  const worker = new Worker();

  process.on('SIGINT', () => {
    logger.info('[Worker] SIGINT received, shutting down...');
    worker.stop();
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    logger.info('[Worker] SIGTERM received, shutting down...');
    worker.stop();
    process.exit(0);
  });
  process.on('uncaughtException', err => {
    logger.error(`[Worker] Uncaught exception: ${err.message}\n${err.stack}`);
    // Don't crash — log and continue
  });
  process.on('unhandledRejection', (reason) => {
    logger.error(`[Worker] Unhandled rejection: ${reason}`);
  });

  await worker.start();
}

main().catch(err => {
  logger.error(`[Worker] Fatal: ${err.message}`);
  process.exit(1);
});
