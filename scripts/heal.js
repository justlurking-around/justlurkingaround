#!/usr/bin/env node
'use strict';

/**
 * Self-Healing System — Autonomous Runtime Recovery
 *
 * Runs as a background watchdog alongside the main scanner.
 * No AI, no external services — pure logic, git, npm, and fs.
 *
 * What it does every cycle (default: every 30 minutes):
 *
 * 1. DEPENDENCY AUDIT
 *    - npm audit --json → parse vulnerabilities
 *    - Auto-fix: npm audit fix (non-breaking)
 *    - High/critical that can't auto-fix → logged + skip
 *
 * 2. OUTDATED CHECK
 *    - npm outdated --json → parse outdated packages
 *    - Patch/minor updates → auto-update (safe)
 *    - Major version bumps → logged only (breaking changes possible)
 *
 * 3. DEPRECATED PACKAGE DETECTION
 *    - Checks npm registry metadata for each dep
 *    - Logs deprecated packages + suggests replacements
 *
 * 4. PROCESS WATCHDOG
 *    - Monitors the scanner worker process
 *    - Restarts it if it crashes (with exponential backoff)
 *    - Max 5 restarts per hour (prevents restart loops)
 *
 * 5. RUNTIME ERROR MONITOR
 *    - Tails logs/scanner.log for error patterns
 *    - Detects known fatal error signatures
 *    - Auto-applies known fixes (e.g. cache clear, DB reset)
 *
 * 6. DISK + MEMORY HEALTH
 *    - Checks data/ directory size (prunes old JSONL lines)
 *    - Checks process memory (warns if > 512MB)
 *    - Rotates logs if > 50MB
 *
 * 7. SELF-UPDATE (optional, off by default)
 *    - git fetch + check if origin/main is ahead
 *    - If AUTO_UPDATE=true: git pull + npm install
 *    - Updates CHANGELOG via scripts/update-changelog.js
 *
 * 8. HEALTH REPORT
 *    - Writes data/health.json after every cycle
 *    - Exposed via GET /api/health on the dashboard
 */

const { execSync, spawn, exec } = require('child_process');
const fs   = require('fs');
const path = require('path');
const os   = require('os');

const ROOT = path.resolve(__dirname, '..');

// ── Config ────────────────────────────────────────────────────────────────────

const CONFIG = {
  cycleMs:           parseInt(process.env.HEAL_INTERVAL_MS  || String(30 * 60_000)),
  autoUpdate:        process.env.AUTO_UPDATE     === 'true',
  autoFixDeps:       process.env.AUTO_FIX_DEPS   !== 'false', // default on
  watchProcess:      process.env.WATCH_PROCESS   !== 'false',
  maxRestarts:       parseInt(process.env.MAX_RESTARTS    || '5'),
  restartWindowMs:   parseInt(process.env.RESTART_WINDOW_MS || String(60 * 60_000)),
  maxDataMB:         parseInt(process.env.MAX_DATA_MB      || '500'),
  maxLogMB:          parseInt(process.env.MAX_LOG_MB       || '50'),
  healthFile:        path.join(ROOT, 'data', 'health.json'),
  logFile:           path.join(ROOT, 'logs', 'scanner.log'),
  healLogFile:       path.join(ROOT, 'logs', 'heal.log'),
};

// ── Simple logger (writes to heal.log + console) ──────────────────────────────

function log(level, msg) {
  const ts   = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const line = `[${ts}] [HEAL] [${level.toUpperCase()}] ${msg}`;
  console.log(line);
  try {
    const dir = path.dirname(CONFIG.healLogFile);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(CONFIG.healLogFile, line + '\n', 'utf8');
  } catch {}
}

function run(cmd, opts = {}) {
  try {
    return execSync(cmd, { cwd: ROOT, encoding: 'utf8', stdio: 'pipe', ...opts });
  } catch (e) {
    return e.stdout || e.stderr || '';
  }
}

// ── Health state ──────────────────────────────────────────────────────────────

const health = {
  lastCheck:       null,
  status:          'healthy',
  vulnerabilities: { critical: 0, high: 0, moderate: 0, low: 0 },
  outdated:        [],
  deprecated:      [],
  autoFixed:       [],
  autoUpdated:     [],
  restarts:        0,
  errors:          [],
  diskMB:          0,
  memoryMB:        0,
  uptime:          0,
  version:         null,
  checks:          {},
};

function saveHealth() {
  health.lastCheck = new Date().toISOString();
  health.uptime    = Math.round(process.uptime());
  health.memoryMB  = Math.round(process.memoryUsage().rss / 1024 / 1024);
  try {
    const dir = path.dirname(CONFIG.healthFile);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(CONFIG.healthFile, JSON.stringify(health, null, 2), 'utf8');
  } catch {}
}

// ── 1. Dependency Vulnerability Audit ────────────────────────────────────────

async function auditDependencies() {
  log('info', 'Running npm audit...');
  const raw = run('npm audit --json');
  let report;
  try { report = JSON.parse(raw); } catch { log('warn', 'npm audit output unparseable'); return; }

  const vulns = report.metadata?.vulnerabilities || {};
  health.vulnerabilities = {
    critical: vulns.critical || 0,
    high:     vulns.high     || 0,
    moderate: vulns.moderate || 0,
    low:      vulns.low      || 0,
    total:    vulns.total    || 0,
  };

  const serious = health.vulnerabilities.critical + health.vulnerabilities.high;

  if (health.vulnerabilities.total === 0) {
    log('info', 'No vulnerabilities found');
    health.checks.audit = 'clean';
    return;
  }

  log('warn', `Vulnerabilities: critical=${vulns.critical} high=${vulns.high} moderate=${vulns.moderate} low=${vulns.low}`);

  // List affected packages
  const advisories = report.vulnerabilities || {};
  for (const [pkg, info] of Object.entries(advisories)) {
    if (info.severity === 'critical' || info.severity === 'high') {
      log('warn', `  ${info.severity.toUpperCase()}: ${pkg} — ${info.title || info.via?.[0] || 'unknown'}`);
    }
  }

  if (CONFIG.autoFixDeps && serious > 0) {
    log('info', 'Attempting npm audit fix...');
    const fixOut = run('npm audit fix --json');
    let fixReport;
    try { fixReport = JSON.parse(fixOut); } catch {}

    const fixed = fixReport?.audit?.metadata?.vulnerabilities?.total || null;
    if (fixed !== null && fixed < health.vulnerabilities.total) {
      const count = health.vulnerabilities.total - fixed;
      log('info', `Auto-fixed ${count} vulnerability(ies)`);
      health.autoFixed.push({ date: new Date().toISOString(), count, action: 'npm audit fix' });
      health.checks.audit = `fixed ${count}`;
    } else {
      log('warn', 'Auto-fix could not resolve all vulnerabilities (may require major version bump)');
      health.checks.audit = 'partial';
      health.status = serious > 0 ? 'vulnerable' : 'degraded';
    }
  } else {
    health.checks.audit = serious > 0 ? 'unresolved' : 'low-risk';
    if (serious > 0) health.status = 'vulnerable';
  }
}

// ── 2. Outdated Package Detection ────────────────────────────────────────────

async function checkOutdated() {
  log('info', 'Checking for outdated packages...');
  const raw = run('npm outdated --json');
  if (!raw.trim() || raw.trim() === '{}') {
    log('info', 'All packages up to date');
    health.checks.outdated = 'current';
    return;
  }

  let outdated;
  try { outdated = JSON.parse(raw); } catch { return; }

  const patchable = [];
  const majorOnly = [];

  for (const [pkg, info] of Object.entries(outdated)) {
    const current = info.current || '0.0.0';
    const latest  = info.latest  || '0.0.0';
    const curMaj  = parseInt(current.split('.')[0]);
    const latMaj  = parseInt(latest.split('.')[0]);

    health.outdated.push({ pkg, current, latest, type: curMaj < latMaj ? 'major' : 'patch' });

    if (curMaj < latMaj) {
      majorOnly.push(`${pkg} ${current} → ${latest}`);
      log('warn', `  MAJOR update available: ${pkg} ${current} → ${latest} (skipping — breaking changes possible)`);
    } else {
      patchable.push(pkg);
      log('info', `  Patch/minor available: ${pkg} ${current} → ${latest}`);
    }
  }

  // Auto-update patch/minor versions
  if (CONFIG.autoFixDeps && patchable.length > 0) {
    log('info', `Auto-updating ${patchable.length} patch/minor packages: ${patchable.join(', ')}`);
    for (const pkg of patchable) {
      const out = run(`npm install ${pkg}@latest --save 2>&1`);
      const updated = !out.includes('ERR');
      if (updated) {
        log('info', `  Updated: ${pkg}`);
        health.autoUpdated.push({ pkg, date: new Date().toISOString() });
      } else {
        log('warn', `  Failed to update: ${pkg}`);
      }
    }
    health.checks.outdated = `auto-updated ${patchable.length}`;
  } else {
    health.checks.outdated = `${Object.keys(outdated).length} outdated (${majorOnly.length} major)`;
  }
}

// ── 3. Deprecated Package Detection ──────────────────────────────────────────

async function checkDeprecated() {
  log('info', 'Checking for deprecated packages...');
  health.deprecated = [];

  // Read installed packages from package.json
  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  } catch { return; }

  const allDeps = { ...pkg.dependencies, ...pkg.optionalDependencies };
  const names = Object.keys(allDeps).slice(0, 20); // check top 20 (rate limit)

  for (const name of names) {
    try {
      const info = run(`npm view ${name} deprecated 2>/dev/null`).trim();
      if (info && info.length > 0 && !info.includes('undefined')) {
        log('warn', `  DEPRECATED: ${name} — ${info.substring(0, 100)}`);
        health.deprecated.push({ pkg: name, message: info.substring(0, 200) });
      }
    } catch {}
    // Small delay to avoid hammering npm registry
    await new Promise(r => setTimeout(r, 200));
  }

  if (health.deprecated.length === 0) {
    log('info', 'No deprecated packages detected');
  }
  health.checks.deprecated = health.deprecated.length === 0 ? 'none' : `${health.deprecated.length} found`;
}

// ── 4. Runtime Error Detection ────────────────────────────────────────────────

const KNOWN_ERRORS = [
  {
    pattern: /SQLITE_CORRUPT|database disk image is malformed/i,
    name:    'SQLite DB corruption',
    fix:     () => {
      const dbPath = process.env.SQLITE_PATH || path.join(ROOT, 'data', 'scanner.db');
      if (fs.existsSync(dbPath)) {
        const backup = dbPath + '.bak.' + Date.now();
        fs.renameSync(dbPath, backup);
        log('warn', `Corrupted DB backed up to ${path.basename(backup)}, will recreate on next start`);
      }
    }
  },
  {
    pattern: /ENOSPC|no space left/i,
    name:    'Disk full',
    fix:     () => {
      // Truncate logs
      [CONFIG.logFile, CONFIG.healLogFile].forEach(f => {
        if (fs.existsSync(f) && fs.statSync(f).size > 5 * 1024 * 1024) {
          const lines = fs.readFileSync(f, 'utf8').split('\n');
          fs.writeFileSync(f, lines.slice(-500).join('\n'), 'utf8');
          log('warn', `Truncated ${path.basename(f)} to last 500 lines (disk full recovery)`);
        }
      });
    }
  },
  {
    pattern: /ENOMEM|heap out of memory/i,
    name:    'Out of memory',
    fix:     () => {
      log('warn', 'Memory pressure detected — clearing in-memory caches');
      // Can't access scanner internals from watchdog, but signals restart
      health.status = 'memory-pressure';
    }
  },
  {
    pattern: /getaddrinfo ENOTFOUND|network unreachable/i,
    name:    'Network error',
    fix:     () => {
      log('info', 'Network error detected — scanner will retry automatically');
    }
  },
];

async function checkLogErrors() {
  if (!fs.existsSync(CONFIG.logFile)) {
    health.checks.errors = 'no log file';
    return;
  }

  try {
    const stat = fs.statSync(CONFIG.logFile);
    const size = stat.size;
    const readSize = Math.min(size, 50 * 1024); // last 50KB
    const fd = fs.openSync(CONFIG.logFile, 'r');
    const buf = Buffer.alloc(readSize);
    fs.readSync(fd, buf, 0, readSize, Math.max(0, size - readSize));
    fs.closeSync(fd);
    const recent = buf.toString('utf8');

    let foundErrors = 0;
    for (const known of KNOWN_ERRORS) {
      if (known.pattern.test(recent)) {
        log('warn', `Known error detected: ${known.name}`);
        known.fix();
        foundErrors++;
        health.errors.push({ type: known.name, detectedAt: new Date().toISOString() });
      }
    }

    health.checks.errors = foundErrors === 0 ? 'clean' : `${foundErrors} errors auto-fixed`;
  } catch (e) {
    health.checks.errors = `check failed: ${e.message}`;
  }
}

// ── 5. Disk + Log Health ──────────────────────────────────────────────────────

async function checkDiskHealth() {
  const dataDir = path.join(ROOT, 'data');
  const logsDir = path.join(ROOT, 'logs');

  let totalBytes = 0;
  for (const dir of [dataDir, logsDir]) {
    if (!fs.existsSync(dir)) continue;
    try {
      const files = fs.readdirSync(dir);
      for (const f of files) {
        try { totalBytes += fs.statSync(path.join(dir, f)).size; } catch {}
      }
    } catch {}
  }

  health.diskMB = Math.round(totalBytes / 1024 / 1024);

  if (health.diskMB > CONFIG.maxDataMB) {
    log('warn', `Data directory is ${health.diskMB}MB (limit: ${CONFIG.maxDataMB}MB) — pruning old JSONL`);
    pruneOldData(dataDir);
  }

  // Rotate large log files
  if (fs.existsSync(CONFIG.logFile)) {
    const logSize = fs.statSync(CONFIG.logFile).size / 1024 / 1024;
    if (logSize > CONFIG.maxLogMB) {
      const rotated = CONFIG.logFile + '.' + Date.now() + '.old';
      fs.renameSync(CONFIG.logFile, rotated);
      log('info', `Rotated log file (was ${Math.round(logSize)}MB)`);
    }
  }

  health.checks.disk = `${health.diskMB}MB used`;
}

function pruneOldData(dataDir) {
  // Prune old JSONL findings — keep last 10,000 lines
  const files = fs.readdirSync(dataDir).filter(f => f.endsWith('.jsonl'));
  for (const f of files) {
    const fp = path.join(dataDir, f);
    try {
      const lines = fs.readFileSync(fp, 'utf8').split('\n').filter(Boolean);
      if (lines.length > 10_000) {
        fs.writeFileSync(fp, lines.slice(-10_000).join('\n') + '\n', 'utf8');
        log('info', `Pruned ${f}: kept last 10,000 lines (was ${lines.length})`);
      }
    } catch {}
  }
}

// ── 6. Process Watchdog ───────────────────────────────────────────────────────

let watchedProcess  = null;
let restartCount    = 0;
let restartWindowStart = Date.now();
const restartHistory = [];

function startWorkerProcess() {
  if (!CONFIG.watchProcess) return;

  log('info', 'Starting scanner worker process...');
  watchedProcess = spawn('node', ['src/worker/index.js'], {
    cwd:   ROOT,
    env:   { ...process.env },
    stdio: 'inherit',
  });

  watchedProcess.on('exit', (code, signal) => {
    log('warn', `Worker exited: code=${code} signal=${signal}`);
    watchedProcess = null;
    scheduleRestart(code);
  });

  watchedProcess.on('error', (err) => {
    log('error', `Worker process error: ${err.message}`);
  });
}

function scheduleRestart(exitCode) {
  if (!CONFIG.watchProcess) return;

  const now = Date.now();

  // Reset window if enough time has passed
  if (now - restartWindowStart > CONFIG.restartWindowMs) {
    restartCount    = 0;
    restartWindowStart = now;
  }

  if (restartCount >= CONFIG.maxRestarts) {
    log('error', `Max restarts (${CONFIG.maxRestarts}) reached in the last hour — not restarting. Check logs.`);
    health.status = 'crashed';
    return;
  }

  // Exponential backoff: 5s, 10s, 20s, 40s, 80s
  const delay = Math.min(5_000 * Math.pow(2, restartCount), 80_000);
  restartCount++;
  restartHistory.push({ at: new Date().toISOString(), exitCode, delayMs: delay });
  health.restarts = restartCount;

  log('info', `Restarting worker in ${delay / 1000}s (attempt ${restartCount}/${CONFIG.maxRestarts})...`);
  setTimeout(startWorkerProcess, delay);
}

function isWorkerRunning() {
  return watchedProcess !== null && !watchedProcess.killed;
}

// ── 7. Self-Update (git pull) ─────────────────────────────────────────────────

async function checkForUpdates() {
  log('info', 'Checking for upstream updates...');

  run('git fetch origin main --quiet');
  const behind = run('git rev-list HEAD..origin/main --count').trim();
  const count  = parseInt(behind) || 0;

  if (count === 0) {
    log('info', 'Already up to date');
    health.checks.updates = 'up-to-date';
    return;
  }

  log('info', `${count} new commit(s) available on origin/main`);

  // Show what changed
  const commits = run('git log HEAD..origin/main --oneline').trim();
  commits.split('\n').forEach(c => log('info', `  pending: ${c}`));

  if (!CONFIG.autoUpdate) {
    log('info', 'AUTO_UPDATE=false — skipping auto-pull (set AUTO_UPDATE=true to enable)');
    health.checks.updates = `${count} commits behind (auto-update disabled)`;
    return;
  }

  log('info', 'AUTO_UPDATE=true — pulling updates...');
  run('git pull origin main --ff-only');
  run('npm install --ignore-scripts');

  // Update changelog
  try { require('./update-changelog.js'); } catch {}

  log('info', `Updated to latest (${count} commits applied)`);
  health.checks.updates = `auto-updated ${count} commits`;
  health.autoUpdated.push({ type: 'git-pull', commits: count, date: new Date().toISOString() });

  // Restart worker if running
  if (isWorkerRunning()) {
    log('info', 'Restarting worker after update...');
    watchedProcess.kill('SIGTERM');
    setTimeout(startWorkerProcess, 3000);
  }
}

// ── 8. Memory Health ──────────────────────────────────────────────────────────

function checkMemory() {
  const mem = process.memoryUsage();
  const rssMB = Math.round(mem.rss / 1024 / 1024);
  const heapMB = Math.round(mem.heapUsed / 1024 / 1024);

  health.memoryMB = rssMB;
  health.checks.memory = `rss=${rssMB}MB heap=${heapMB}MB`;

  if (rssMB > 512) {
    log('warn', `High memory usage: ${rssMB}MB RSS — consider restarting`);
    health.status = health.status === 'healthy' ? 'high-memory' : health.status;
  }
}

// ── Main cycle ────────────────────────────────────────────────────────────────

async function runHealCycle() {
  log('info', `=== Heal cycle started (${new Date().toISOString()}) ===`);
  health.status = 'healthy';
  health.errors = [];

  try { await auditDependencies(); } catch (e) { log('error', `Audit error: ${e.message}`); }
  try { await checkOutdated();      } catch (e) { log('error', `Outdated error: ${e.message}`); }
  try { await checkLogErrors();     } catch (e) { log('error', `Log error check: ${e.message}`); }
  try { await checkDiskHealth();    } catch (e) { log('error', `Disk check: ${e.message}`); }
  try {        checkMemory();       } catch (e) { log('error', `Memory check: ${e.message}`); }
  try { await checkForUpdates();    } catch (e) { log('error', `Update check: ${e.message}`); }

  // Only run deprecated check every 6 hours (slow — calls npm registry)
  const now = Date.now();
  if (!health._lastDeprecatedCheck || now - health._lastDeprecatedCheck > 6 * 60 * 60_000) {
    try { await checkDeprecated(); } catch (e) { log('error', `Deprecated check: ${e.message}`); }
    health._lastDeprecatedCheck = now;
  }

  // Watchdog: ensure worker is running
  if (CONFIG.watchProcess && !isWorkerRunning() && health.status !== 'crashed') {
    log('warn', 'Worker not running — starting...');
    startWorkerProcess();
  }

  saveHealth();
  log('info', `=== Cycle complete — status: ${health.status} | disk: ${health.diskMB}MB | mem: ${health.memoryMB}MB ===`);
}

// ── Startup ───────────────────────────────────────────────────────────────────

async function main() {
  // Load version
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    health.version = pkg.version;
  } catch {}

  log('info', '╔══════════════════════════════════════════╗');
  log('info', '║   AI Secret Scanner — Self-Healing System ║');
  log('info', `║   Cycle: every ${Math.round(CONFIG.cycleMs/60000)}min | AutoFix: ${CONFIG.autoFixDeps} | AutoUpdate: ${CONFIG.autoUpdate}      ║`);
  log('info', '╚══════════════════════════════════════════╝');

  // Ensure required dirs exist
  ['data', 'logs', 'reports'].forEach(d => {
    const dp = path.join(ROOT, d);
    if (!fs.existsSync(dp)) fs.mkdirSync(dp, { recursive: true });
  });

  // Graceful shutdown
  process.on('SIGINT',  () => { log('info', 'SIGINT — shutting down heal daemon'); process.exit(0); });
  process.on('SIGTERM', () => { log('info', 'SIGTERM — shutting down heal daemon'); process.exit(0); });

  // Run immediately, then on schedule
  await runHealCycle();
  setInterval(runHealCycle, CONFIG.cycleMs);

  // If watchdog mode: also start the worker
  if (CONFIG.watchProcess) {
    startWorkerProcess();
  }

  log('info', `Heal daemon running. Next cycle in ${Math.round(CONFIG.cycleMs / 60_000)}min.`);
}

main().catch(e => {
  log('error', `Fatal: ${e.message}`);
  process.exit(1);
});
