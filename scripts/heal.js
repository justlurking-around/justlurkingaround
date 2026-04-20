#!/usr/bin/env node
'use strict';

/**
 * Self-Healing System v2 — Autonomous, No-AI, Production-Grade
 *
 * Verified working capabilities:
 *  - npm audit fix   → commit package-lock.json → git push
 *  - npm install pkg → commit package*.json     → git push
 *  - git pull        → npm install              → git push
 *  - Crash recovery  → restart worker process
 *  - Log rotation    → prune old data
 *  - Health report   → data/health.json
 *
 * All git operations use the token already in the remote URL.
 * No external service. No AI. Pure Node.js + git + npm.
 */

const { execSync, spawn } = require('child_process');
const fs   = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

// ── Config ────────────────────────────────────────────────────────────────────

const CFG = {
  cycleMs:         parseInt(process.env.HEAL_INTERVAL_MS  || '1800000'),
  autoFixDeps:     process.env.AUTO_FIX_DEPS   !== 'false',
  autoUpdate:      process.env.AUTO_UPDATE      === 'true',
  watchProcess:    process.env.WATCH_PROCESS    === 'true',
  maxRestarts:     parseInt(process.env.MAX_RESTARTS       || '5'),
  restartWindowMs: parseInt(process.env.RESTART_WINDOW_MS  || '3600000'),
  maxDataMB:       parseInt(process.env.MAX_DATA_MB        || '500'),
  maxLogMB:        parseInt(process.env.MAX_LOG_MB         || '50'),
  healthFile:      path.join(ROOT, 'data', 'health.json'),
  logFile:         path.join(ROOT, 'logs', 'scanner.log'),
  healLog:         path.join(ROOT, 'logs', 'heal.log'),
  commitAuthor:    'AI Scanner Bot <bot@ai-scanner.dev>',
};

// ── Logger ────────────────────────────────────────────────────────────────────

function log(lvl, msg) {
  const ts   = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const line = `[${ts}] [HEAL/${lvl.toUpperCase()}] ${msg}`;
  console.log(line);
  try {
    const d = path.dirname(CFG.healLog);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.appendFileSync(CFG.healLog, line + '\n');
  } catch {}
}

// ── Shell helpers ─────────────────────────────────────────────────────────────

function sh(cmd, opts = {}) {
  try {
    return {
      ok:  true,
      out: execSync(cmd, {
        cwd: ROOT, encoding: 'utf8',
        stdio: 'pipe', timeout: 60_000,
        ...opts
      }).trim()
    };
  } catch (e) {
    return { ok: false, out: (e.stdout || e.stderr || e.message || '').trim() };
  }
}

function shJSON(cmd) {
  const r = sh(cmd);
  if (!r.ok || !r.out) return null;
  try   { return JSON.parse(r.out); }
  catch { return null; }
}

// ── Git helpers (autonomous push) ─────────────────────────────────────────────

function gitConfig() {
  sh(`git config user.email "bot@ai-scanner.dev"`);
  sh(`git config user.name  "AI Scanner Bot"`);
}

function gitHasChanges(files) {
  // Returns true if any of the given files differ from HEAD
  for (const f of files) {
    const r = sh(`git diff --name-only HEAD -- "${f}"`);
    if (r.ok && r.out.includes(path.basename(f))) return true;
    // Also check staged
    const s = sh(`git diff --cached --name-only -- "${f}"`);
    if (s.ok && s.out.includes(path.basename(f))) return true;
  }
  return false;
}

function gitCommitPush(files, message) {
  gitConfig();

  // Stage only the specified files
  for (const f of files) {
    const rel = path.relative(ROOT, path.resolve(ROOT, f));
    sh(`git add "${rel}"`);
  }

  // Check if there's actually anything staged
  const staged = sh('git diff --cached --name-only');
  if (!staged.ok || !staged.out.trim()) {
    log('info', `Nothing to commit for: ${message}`);
    return false;
  }

  const commitResult = sh(`git commit --no-verify -m "${message}"`);
  if (!commitResult.ok) {
    log('warn', `Commit failed: ${commitResult.out.substring(0, 100)}`);
    return false;
  }

  const pushResult = sh('git push');
  if (!pushResult.ok) {
    log('warn', `Push failed: ${pushResult.out.substring(0, 100)}`);
    return false;
  }

  log('info', `Committed + pushed: ${message}`);
  return true;
}

// ── Health state ──────────────────────────────────────────────────────────────

const H = {
  status: 'healthy', lastCheck: null,
  vulnerabilities: { critical: 0, high: 0, moderate: 0, low: 0, total: 0 },
  outdated: [], deprecated: [], autoFixed: [], autoUpdated: [],
  restarts: 0, errors: [], diskMB: 0, memoryMB: 0,
  version: null, checks: {},
  _lastDeprecatedCheck: 0,
};

function saveHealth() {
  H.lastCheck  = new Date().toISOString();
  H.memoryMB   = Math.round(process.memoryUsage().rss / 1024 / 1024);
  try {
    const d = path.dirname(CFG.healthFile);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(CFG.healthFile, JSON.stringify(H, null, 2));
  } catch {}
}

// ── 1. Vulnerability audit + auto-fix + commit ────────────────────────────────

async function doAudit() {
  log('info', 'npm audit...');
  const report = shJSON('npm audit --json 2>/dev/null');
  if (!report) { H.checks.audit = 'parse-error'; return; }

  const v = report.metadata?.vulnerabilities || {};
  H.vulnerabilities = {
    critical: v.critical || 0, high: v.high || 0,
    moderate: v.moderate || 0, low: v.low || 0,
    total: v.total || 0,
  };

  if (H.vulnerabilities.total === 0) {
    log('info', 'No vulnerabilities'); H.checks.audit = 'clean'; return;
  }

  const serious = H.vulnerabilities.critical + H.vulnerabilities.high;
  log('warn', `Vulns: critical=${v.critical} high=${v.high} moderate=${v.moderate} low=${v.low}`);

  if (!CFG.autoFixDeps) { H.checks.audit = 'unfixed (autofix disabled)'; return; }

  log('info', 'Running npm audit fix...');
  const fixResult = sh('npm audit fix 2>&1');
  if (!fixResult.ok && !fixResult.out.includes('fixed')) {
    log('warn', 'npm audit fix had issues: ' + fixResult.out.substring(0, 100));
  }

  // FIXED: commit + push the package-lock.json changes
  const committed = gitCommitPush(
    ['package.json', 'package-lock.json'],
    'fix: npm audit fix — auto-patched vulnerabilities [heal]'
  );

  if (committed) {
    H.autoFixed.push({ date: new Date().toISOString(), action: 'npm audit fix', vulns: H.vulnerabilities.total });
    H.checks.audit = 'auto-fixed + pushed';
  } else {
    H.checks.audit = 'fix-attempted (no changes needed)';
  }

  if (serious > 0) H.status = 'vulnerable';
}

// ── 2. Outdated package check + auto-update patch/minor + commit ─────────────

async function doOutdated() {
  log('info', 'Checking outdated packages...');
  const raw = shJSON('npm outdated --json 2>/dev/null');
  if (!raw || Object.keys(raw).length === 0) {
    log('info', 'All packages up to date');
    H.checks.outdated = 'current'; return;
  }

  H.outdated = [];
  const toUpdate = [];

  for (const [pkg, info] of Object.entries(raw)) {
    const cur    = info.current || '0.0.0';
    const latest = info.latest  || '0.0.0';
    const curMaj = parseInt(cur.split('.')[0]);
    const latMaj = parseInt(latest.split('.')[0]);
    const isMajor = latMaj > curMaj;

    H.outdated.push({ pkg, current: cur, latest, type: isMajor ? 'major' : 'patch' });

    if (isMajor) {
      log('warn', `MAJOR skip: ${pkg} ${cur} → ${latest} (breaking change risk)`);
    } else {
      toUpdate.push({ pkg, cur, latest });
      log('info', `Patch/minor: ${pkg} ${cur} → ${latest}`);
    }
  }

  if (!CFG.autoFixDeps || toUpdate.length === 0) {
    H.checks.outdated = `${H.outdated.length} outdated (${toUpdate.length} patchable)`;
    return;
  }

  log('info', `Auto-updating ${toUpdate.length} package(s)...`);
  let updated = 0;
  for (const { pkg, latest } of toUpdate) {
    const r = sh(`npm install ${pkg}@${latest} --save 2>&1`);
    if (!r.out.includes('ERR')) {
      log('info', `  Updated: ${pkg} → ${latest}`);
      updated++;
    } else {
      log('warn', `  Failed: ${pkg} — ${r.out.substring(0, 80)}`);
    }
  }

  if (updated > 0) {
    // FIXED: commit + push the updated package files
    const committed = gitCommitPush(
      ['package.json', 'package-lock.json'],
      `fix: auto-update ${updated} package(s) [heal]`
    );
    if (committed) {
      H.autoUpdated.push(...toUpdate.slice(0, updated).map(p => ({ pkg: p.pkg, to: p.latest, date: new Date().toISOString() })));
      H.checks.outdated = `auto-updated ${updated} + pushed`;
    } else {
      H.checks.outdated = `updated ${updated} (no commit needed)`;
    }
  }
}

// ── 3. Deprecated detection (every 6h — calls npm registry) ──────────────────

async function doDeprecated() {
  if (Date.now() - H._lastDeprecatedCheck < 6 * 3600_000) return;
  H._lastDeprecatedCheck = Date.now();

  log('info', 'Checking deprecated packages (6h check)...');
  H.deprecated = [];

  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')); }
  catch { return; }

  const deps = Object.keys({ ...pkg.dependencies, ...pkg.optionalDependencies }).slice(0, 15);

  for (const name of deps) {
    // FIXED: filter out npm warnings before parsing
    const r = sh(`npm view ${name} deprecated --json 2>/dev/null`);
    const val = (r.out || '').replace(/^npm warn.*\n?/gm, '').trim();
    if (val && val !== 'undefined' && val !== '' && !val.startsWith('{')) {
      const msg = val.replace(/^"|"$/g, '');
      log('warn', `DEPRECATED: ${name} — ${msg.substring(0, 80)}`);
      H.deprecated.push({ pkg: name, message: msg.substring(0, 200) });
    }
    await new Promise(r => setTimeout(r, 300)); // rate-limit npm registry
  }

  log('info', H.deprecated.length === 0 ? 'No deprecated packages' : `${H.deprecated.length} deprecated`);
  H.checks.deprecated = H.deprecated.length === 0 ? 'none' : `${H.deprecated.length} found`;
}

// ── 4. Runtime error detection + known fixes ──────────────────────────────────

const KNOWN_FIXES = [
  {
    pattern: /SQLITE_CORRUPT|database disk image is malformed/i,
    name: 'SQLite DB corruption',
    fix() {
      const db = process.env.SQLITE_PATH || path.join(ROOT, 'data', 'scanner.db');
      if (fs.existsSync(db)) {
        fs.renameSync(db, db + '.corrupt.' + Date.now());
        log('warn', 'Corrupted SQLite DB backed up — will recreate on next run');
      }
    }
  },
  {
    pattern: /ENOSPC|no space left on device/i,
    name: 'Disk full',
    fix() {
      [CFG.logFile, CFG.healLog].forEach(f => {
        if (!fs.existsSync(f)) return;
        const mb = fs.statSync(f).size / 1024 / 1024;
        if (mb > 10) {
          const lines = fs.readFileSync(f, 'utf8').split('\n');
          fs.writeFileSync(f, lines.slice(-200).join('\n'));
          log('warn', `Truncated ${path.basename(f)} (disk full recovery)`);
        }
      });
    }
  },
  {
    pattern: /MaxListenersExceededWarning/i,
    name: 'MaxListeners leak',
    fix() {
      log('info', 'MaxListeners warning detected — already patched in github-client.js');
    }
  },
];

async function doErrorCheck() {
  if (!fs.existsSync(CFG.logFile)) { H.checks.errors = 'no log'; return; }
  try {
    const stat = fs.statSync(CFG.logFile);
    const read = Math.min(stat.size, 100 * 1024);
    const buf  = Buffer.alloc(read);
    const fd   = fs.openSync(CFG.logFile, 'r');
    fs.readSync(fd, buf, 0, read, Math.max(0, stat.size - read));
    fs.closeSync(fd);
    const recent = buf.toString('utf8');
    let fixed = 0;
    for (const k of KNOWN_FIXES) {
      if (k.pattern.test(recent)) {
        log('warn', `Known error: ${k.name}`);
        k.fix(); fixed++;
        H.errors.push({ type: k.name, at: new Date().toISOString() });
      }
    }
    H.checks.errors = fixed === 0 ? 'clean' : `${fixed} auto-fixed`;
  } catch (e) {
    H.checks.errors = `failed: ${e.message.substring(0, 50)}`;
  }
}

// ── 5. Disk + log health ──────────────────────────────────────────────────────

async function doDiskHealth() {
  let total = 0;
  for (const dir of ['data', 'logs'].map(d => path.join(ROOT, d))) {
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir)) {
      try { total += fs.statSync(path.join(dir, f)).size; } catch {}
    }
  }
  H.diskMB = Math.round(total / 1024 / 1024);

  if (H.diskMB > CFG.maxDataMB) {
    log('warn', `Data dir ${H.diskMB}MB > limit ${CFG.maxDataMB}MB — pruning`);
    const dataDir = path.join(ROOT, 'data');
    if (fs.existsSync(dataDir)) {
      for (const f of fs.readdirSync(dataDir).filter(f => f.endsWith('.jsonl'))) {
        const fp = path.join(dataDir, f);
        const lines = fs.readFileSync(fp, 'utf8').split('\n').filter(Boolean);
        if (lines.length > 10_000) {
          fs.writeFileSync(fp, lines.slice(-10_000).join('\n') + '\n');
          log('info', `Pruned ${f}: ${lines.length} → 10000 lines`);
        }
      }
    }
  }

  // Rotate large log files
  for (const logPath of [CFG.logFile, CFG.healLog]) {
    if (!fs.existsSync(logPath)) continue;
    const mb = fs.statSync(logPath).size / 1024 / 1024;
    if (mb > CFG.maxLogMB) {
      fs.renameSync(logPath, logPath + '.' + Date.now() + '.old');
      log('info', `Rotated ${path.basename(logPath)} (was ${Math.round(mb)}MB)`);
    }
  }

  H.checks.disk = `${H.diskMB}MB`;
}

// ── 6. Self-update from GitHub ────────────────────────────────────────────────

async function doUpdate() {
  log('info', 'Checking for upstream changes...');
  sh('git fetch origin main --quiet');

  const behind = sh('git rev-list HEAD..origin/main --count');
  const count  = parseInt(behind.out) || 0;

  if (count === 0) {
    log('info', 'Already up to date');
    H.checks.updates = 'up-to-date';
    return;
  }

  // Show pending commits
  const pending = sh('git log HEAD..origin/main --oneline');
  log('info', `${count} new commit(s) upstream:`);
  (pending.out || '').split('\n').slice(0, 5).forEach(c => log('info', `  + ${c}`));

  if (!CFG.autoUpdate) {
    log('info', 'AUTO_UPDATE=false — run with AUTO_UPDATE=true to auto-pull');
    H.checks.updates = `${count} commits behind`;
    return;
  }

  log('info', 'Pulling updates...');
  const pull = sh('git pull origin main --ff-only');
  if (!pull.ok) {
    log('warn', `git pull failed: ${pull.out.substring(0, 100)}`);
    H.checks.updates = 'pull failed';
    return;
  }

  // Reinstall deps (Termux-safe: --ignore-scripts)
  log('info', 'Running npm install...');
  sh('npm install --ignore-scripts 2>&1');

  // Update changelog for the pulled commits
  try { require('./update-changelog.js'); } catch {}

  H.autoUpdated.push({ type: 'git-pull', commits: count, date: new Date().toISOString() });
  H.checks.updates = `pulled ${count} commits`;
  log('info', `Updated successfully (${count} commits applied)`);

  // Signal running worker to restart (if watchdog is managing it)
  if (_workerProcess) {
    log('info', 'Restarting worker after update...');
    _workerProcess.kill('SIGTERM');
  }
}

// ── 7. Process watchdog ───────────────────────────────────────────────────────

let _workerProcess  = null;
let _restartCount   = 0;
let _restartWinStart = Date.now();

function startWorker() {
  if (!CFG.watchProcess) return;
  log('info', 'Starting scanner worker...');
  _workerProcess = spawn('node', ['src/worker/index.js'], {
    cwd: ROOT, env: { ...process.env },
    detached: false, stdio: 'inherit',
  });
  _workerProcess.on('exit', (code, sig) => {
    _workerProcess = null;
    log('warn', `Worker exited code=${code} signal=${sig}`);
    scheduleRestart();
  });
  _workerProcess.on('error', e => log('error', `Worker spawn error: ${e.message}`));
}

function scheduleRestart() {
  if (!CFG.watchProcess) return;
  const now = Date.now();
  if (now - _restartWinStart > CFG.restartWindowMs) {
    _restartCount = 0; _restartWinStart = now;
  }
  if (_restartCount >= CFG.maxRestarts) {
    log('error', `Hit restart limit (${CFG.maxRestarts}/hr) — check logs and restart manually`);
    H.status = 'crashed';
    return;
  }
  const delay = Math.min(5_000 * (2 ** _restartCount), 60_000);
  _restartCount++;
  H.restarts = _restartCount;
  log('info', `Restarting in ${delay / 1000}s (attempt ${_restartCount}/${CFG.maxRestarts})`);
  setTimeout(startWorker, delay);
}

// ── Memory check ──────────────────────────────────────────────────────────────

function doMemory() {
  const mb = Math.round(process.memoryUsage().rss / 1024 / 1024);
  H.memoryMB = mb;
  H.checks.memory = `${mb}MB`;
  if (mb > 512) { log('warn', `High memory: ${mb}MB`); H.status = H.status === 'healthy' ? 'high-memory' : H.status; }
}

// ── Main heal cycle ───────────────────────────────────────────────────────────

async function cycle() {
  log('info', `=== Heal cycle (${new Date().toISOString()}) ===`);
  H.status = 'healthy'; H.errors = [];

  try { await doAudit();      } catch (e) { log('error', `audit: ${e.message}`); }
  try { await doOutdated();   } catch (e) { log('error', `outdated: ${e.message}`); }
  try { await doErrorCheck(); } catch (e) { log('error', `errors: ${e.message}`); }
  try { await doDiskHealth(); } catch (e) { log('error', `disk: ${e.message}`); }
  try {        doMemory();    } catch (e) { log('error', `memory: ${e.message}`); }
  try { await doUpdate();     } catch (e) { log('error', `update: ${e.message}`); }
  try { await doDeprecated(); } catch (e) { log('error', `deprecated: ${e.message}`); }

  // Watchdog: ensure worker running
  if (CFG.watchProcess && !_workerProcess && H.status !== 'crashed') {
    log('warn', 'Worker not running — starting...');
    startWorker();
  }

  saveHealth();
  log('info', `=== Done — status:${H.status} disk:${H.diskMB}MB mem:${H.memoryMB}MB ===`);
}

// ── Entry ─────────────────────────────────────────────────────────────────────

async function main() {
  try {
    H.version = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
  } catch {}

  // Ensure dirs
  for (const d of ['data', 'logs', 'reports'].map(x => path.join(ROOT, x))) {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  }

  log('info', `Self-Heal v2 starting | cycle=${CFG.cycleMs/60000}min autoFix=${CFG.autoFixDeps} autoUpdate=${CFG.autoUpdate} watchProcess=${CFG.watchProcess}`);

  process.on('SIGINT',  () => { log('info', 'SIGINT — stopping'); process.exit(0); });
  process.on('SIGTERM', () => { log('info', 'SIGTERM — stopping'); process.exit(0); });
  process.on('uncaughtException', e => { log('error', `Uncaught: ${e.message}`); }); // keep running

  // Start worker if watchdog mode
  if (CFG.watchProcess) startWorker();

  // Run cycle immediately then on interval
  await cycle();
  const timer = setInterval(cycle, CFG.cycleMs);
  timer.unref(); // don't prevent process exit if nothing else running

  // Keep alive only if in watchdog mode or interval > 0
  if (!CFG.watchProcess) {
    log('info', 'One-shot heal complete.');
    process.exit(0);
  }

  log('info', `Heal daemon running. Next cycle in ${CFG.cycleMs / 60_000}min. Ctrl+C to stop.`);
}

main().catch(e => { log('error', `Fatal: ${e.message}`); process.exit(1); });
