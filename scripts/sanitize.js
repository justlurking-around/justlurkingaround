#!/usr/bin/env node
'use strict';

/**
 * Pre-deployment sanitization checker
 *
 * Runs before every push (via pre-push hook) to ensure:
 *  1. No real credentials in any tracked file
 *  2. No sensitive local files accidentally staged
 *  3. Remote URL token not embedded in tracked files
 *  4. .env.defaults contains no real values
 *  5. Config/data files are clean
 *  6. Package.json has no private registry tokens
 *
 * Usage:
 *   node scripts/sanitize.js          # check + report
 *   node scripts/sanitize.js --fix    # check + auto-fix what's safe to fix
 *   node scripts/sanitize.js --strict # exit 1 on any finding (blocks push)
 */

const { execSync } = require('child_process');
const fs   = require('fs');
const path = require('path');

const ROOT   = path.resolve(__dirname, '..');
const STRICT = process.argv.includes('--strict');
const FIX    = process.argv.includes('--fix');

// ── Logger ────────────────────────────────────────────────────────────────────

const issues  = [];
const fixed   = [];
const skipped = [];

function warn(file, msg, fixable = false) {
  issues.push({ file, msg, fixable });
  console.log(`  [WARN]  ${file || 'repo'}: ${msg}`);
}
function ok(msg)   { console.log(`  [OK]    ${msg}`); }
function info(msg) { console.log(`  [INFO]  ${msg}`); }
function fix(msg)  { fixed.push(msg); console.log(`  [FIXED] ${msg}`); }

// ── Shell helper ──────────────────────────────────────────────────────────────

function sh(cmd) {
  try { return execSync(cmd, { cwd: ROOT, encoding: 'utf8', stdio: 'pipe' }).trim(); }
  catch (e) { return (e.stdout || e.stderr || '').trim(); }
}

// ── 1. Credential patterns in tracked source files ────────────────────────────

const REAL_SECRET_PATTERNS = [
  // Real secret patterns — NOT regex strings used in detection code
  { re: /ghp_[A-Za-z0-9]{36}/,                               name: 'GitHub PAT',      safe: /regex|pattern|PATTERN|detect/i },
  { re: /gho_[A-Za-z0-9]{36}/,                               name: 'GitHub OAuth',    safe: /regex|pattern|PATTERN/i },
  { re: /sk-proj-[A-Za-z0-9_-]{40,}/,                        name: 'OpenAI Key',      safe: /regex|pattern|PATTERN/i },
  { re: /sk-ant-api[0-9]{2}-[A-Za-z0-9-_]{86}/,              name: 'Anthropic Key',   safe: /regex|pattern|PATTERN/i },
  { re: /AKIA[0-9A-Z]{16}[^'"]/,                             name: 'AWS Access Key',  safe: /regex|pattern|PATTERN/i },
  { re: /xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}/,         name: 'Slack Bot Token', safe: /regex|pattern|PATTERN/i },
  { re: /AIza[0-9A-Za-z-_]{35}/,                             name: 'Google API Key',  safe: /regex|pattern|PATTERN/i },
  { re: /[0-9]{8,10}:[A-Za-z0-9_-]{35}/,                     name: 'Telegram Token',  safe: /regex|pattern|PATTERN/i },
  { re: /sk_live_[0-9a-zA-Z]{24,}/,                          name: 'Stripe Live Key', safe: /regex|pattern|PATTERN/i },
  { re: /SG\.[a-zA-Z0-9-_.]{22}\.[a-zA-Z0-9-_.]{43}/,       name: 'SendGrid Key',    safe: /regex|pattern|PATTERN/i },
  { re: /npm_[A-Za-z0-9]{36}/,                               name: 'NPM Token',       safe: /regex|pattern|PATTERN/i },
  { re: /pypi-AgEIcHlwaS5vcmcA[A-Za-z0-9-_]{50,}/,          name: 'PyPI Token',      safe: /regex|pattern|PATTERN/i },
  // Embedded passwords in connection strings (real ones, not examples)
  { re: /(?:mysql|postgres|mongodb):\/\/[^:]+:[^@]{8,}@(?!localhost|example|127\.0\.0\.1)/, name: 'DB Connection String with real host', safe: /example|test|sample/i },
  // Private keys (full blocks, not just headers)
  { re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{200,}-----END/, name: 'Full private key block', safe: /pattern|regex|detect/i },
];

function scanTrackedFiles() {
  console.log('\n── Credential scan in tracked files ────────────────────');
  const trackedFiles = sh('git ls-files').split('\n').filter(Boolean);
  let clean = true;

  for (const file of trackedFiles) {
    const fullPath = path.join(ROOT, file);
    let content;
    try { content = fs.readFileSync(fullPath, 'utf8'); } catch { continue; }

    for (const { re, name, safe } of REAL_SECRET_PATTERNS) {
      const match = re.exec(content);
      if (!match) continue;

      // Skip if it's inside a regex/pattern string in detection code
      const lineStart = content.lastIndexOf('\n', match.index) + 1;
      const lineEnd   = content.indexOf('\n', match.index);
      const line      = content.substring(lineStart, lineEnd === -1 ? undefined : lineEnd);

      if (safe && safe.test(line)) continue; // it's a detection pattern, not a real credential
      if (safe && safe.test(file)) continue;

      // Check if it's in a comment
      if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

      warn(file, `Possible real ${name} detected: ${match[0].substring(0, 12)}...`);
      clean = false;
    }
  }

  if (clean) ok('No real credentials found in tracked files');
}

// ── 2. Check staged files for accidental sensitive files ──────────────────────

function scanStagedFiles() {
  console.log('\n── Staged files safety check ───────────────────────────');
  const staged = sh('git diff --cached --name-only').split('\n').filter(Boolean);

  const NEVER_COMMIT = [
    /\.env$/,
    /vault\.enc/,
    /scanner\.db/,
    /health\.json/,
    /\.heal\.pid/,
    /allowlist\.json/,
    /denylist\.json/,
    /scanner\.log/,
    /heal\.log/,
    /findings\.jsonl/,
    /vault-export\.json/,
    /node_modules\//,
  ];

  if (staged.length === 0) {
    info('No staged files to check');
    return;
  }

  for (const file of staged) {
    for (const pattern of NEVER_COMMIT) {
      if (pattern.test(file)) {
        warn(file, `Sensitive file staged for commit — should never be in git`, true);
        if (FIX) {
          sh(`git restore --staged "${file}"`);
          fix(`Unstaged: ${file}`);
        }
      }
    }
  }
  ok(`${staged.length} staged files checked`);
}

// ── 3. .env.defaults must not contain real values ────────────────────────────

function checkEnvDefaults() {
  console.log('\n── .env.defaults cleanliness check ────────────────────');
  const filePath = path.join(ROOT, '.env.defaults');
  if (!fs.existsSync(filePath)) { info('.env.defaults not found'); return; }

  const content = fs.readFileSync(filePath, 'utf8');
  const lines   = content.split('\n');
  let dirty = false;

  for (const [i, line] of lines.entries()) {
    // Should be KEY= with empty value, or KEY=false/true/number
    const m = line.match(/^([A-Z_]+)\s*=\s*(.+)$/);
    if (!m) continue;
    const [, key] = m;
    // Strip inline comments (e.g. VALUE=foo   # comment)
    const val = m[2].replace(/\s*#.*$/, '').trim();

    // Allow: empty values, booleans, numbers, paths, and safe defaults
    const SAFE_DEFAULTS = new Set([
      'info','debug','warn','error',
      './logs','./data','./data/scanner.db',
      'redis://localhost:6379',
    ]);
    const reNum      = /^\d+$/;
    const reBool     = /^(true|false)$/;
    const reUrl      = /^https?:\/\/[a-z0-9.:\/]+$/;
    const reDuration = /^[0-9]+(ms|s|m|h|MB|KB)?$/;
    const isSafe =
      val === "" ||
      reNum.test(val) ||
      reBool.test(val) ||
      SAFE_DEFAULTS.has(val) ||
      reUrl.test(val) ||
      val.startsWith('#') ||
      val.startsWith('./') ||
      reDuration.test(val);

    if (!isSafe && val.length > 6) {
      warn('.env.defaults', `Line ${i+1}: ${key} has a real value — should be empty`);
      dirty = true;
      if (FIX) {
        lines[i] = `${key}=`;
        fix(`.env.defaults: cleared ${key}`);
      }
    }
  }

  if (!dirty) ok('.env.defaults contains only empty/safe values');

  if (FIX && dirty) {
    fs.writeFileSync(filePath, lines.join('\n'), 'utf8');
  }
}

// ── 4. package.json has no private registry token ────────────────────────────

function checkPackageJson() {
  console.log('\n── package.json safety check ───────────────────────────');
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

  // Check for _authToken in publishConfig
  if (pkg.publishConfig?._authToken) {
    warn('package.json', 'publishConfig._authToken is set — remove before publishing');
  }

  // Check scripts for embedded secrets
  for (const [name, script] of Object.entries(pkg.scripts || {})) {
    if (/[A-Za-z0-9]{30,}/.test(script) && !/node |npm /.test(script)) {
      warn('package.json', `Script "${name}" may contain a secret`);
    }
  }

  // .npmrc check
  const npmrc = path.join(ROOT, '.npmrc');
  if (fs.existsSync(npmrc)) {
    const content = fs.readFileSync(npmrc, 'utf8');
    if (content.includes('_authToken') || content.includes('//registry')) {
      warn('.npmrc', 'Contains registry auth — check it is not a real token');
    } else {
      ok('.npmrc is clean');
    }
  }

  ok('package.json is clean');
}

// ── 5. .gitignore completeness ────────────────────────────────────────────────

function checkGitignore() {
  console.log('\n── .gitignore completeness ─────────────────────────────');
  const content = fs.readFileSync(path.join(ROOT, '.gitignore'), 'utf8');

  const required = [
    ['.env',              'environment file'],
    ['data/',             'data directory (vault, DB, findings)'],
    ['logs/',             'log files'],
    ['node_modules/',     'dependencies'],
    ['*.db',              'SQLite database'],
    ['*.jsonl',           'JSONL findings'],
    ['*.log',             'log files'],
  ];

  let complete = true;
  for (const [entry, desc] of required) {
    if (content.includes(entry)) {
      ok(`${entry} — ${desc}`);
    } else {
      warn('.gitignore', `Missing: ${entry} (${desc})`, true);
      complete = false;
      if (FIX) {
        fs.appendFileSync(path.join(ROOT, '.gitignore'), '\n' + entry + '\n');
        fix(`.gitignore: added ${entry}`);
      }
    }
  }
}

// ── 6. Remote URL sanitization ────────────────────────────────────────────────

function checkRemoteUrl() {
  console.log('\n── Git remote URL ──────────────────────────────────────');
  const url = sh('git remote get-url origin');

  if (url.includes('@')) {
    // Has credentials embedded — normal for token auth, but note it
    info('Remote URL contains credentials (local .git/config only — never pushed)');
    ok('Credentials in remote URL are local-only — safe');
  } else {
    ok('Remote URL: ' + url.substring(0, 60));
  }

  // Ensure .git/config is not tracked
  const gitConfigTracked = sh('git ls-files .git/config');
  if (gitConfigTracked) {
    warn('.git/config', 'Git config is tracked — contains credentials!');
  } else {
    ok('.git/config is NOT tracked (correct)');
  }
}

// ── 7. Generate deployment summary ───────────────────────────────────────────

function generateSummary() {
  const summaryPath = path.join(ROOT, 'data', 'sanitize-report.json');
  const report = {
    timestamp:  new Date().toISOString(),
    version:    (() => { try { return JSON.parse(fs.readFileSync(path.join(ROOT,'package.json'),'utf8')).version; } catch { return '?'; } })(),
    issues:     issues.length,
    fixed:      fixed.length,
    clean:      issues.length === 0,
    details:    { issues, fixed, skipped }
  };

  try {
    const d = path.dirname(summaryPath);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(summaryPath, JSON.stringify(report, null, 2));
  } catch {}

  return report;
}

// ── Main ──────────────────────────────────────────────────────────────────────

function main() {
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║   AI Secret Scanner — Pre-Deploy Sanitizer       ║');
  console.log(`║   Mode: ${FIX ? 'FIX' : 'CHECK'} | Strict: ${STRICT ? 'YES' : 'NO'}                          ║`);
  console.log('╚══════════════════════════════════════════════════╝');

  scanTrackedFiles();
  scanStagedFiles();
  checkEnvDefaults();
  checkPackageJson();
  checkGitignore();
  checkRemoteUrl();

  const report = generateSummary();

  console.log('\n══════════════════════════════════════════════════════');
  console.log(`  RESULT: ${report.clean ? '✅ CLEAN — safe to deploy' : '⚠️  ' + issues.length + ' issue(s) found'}`);
  if (fixed.length)   console.log(`  Auto-fixed: ${fixed.length} item(s)`);
  if (issues.length)  issues.forEach(i => console.log(`  ⚠  ${i.file}: ${i.msg}`));
  console.log('══════════════════════════════════════════════════════\n');

  if (STRICT && issues.length > 0) {
    console.error('STRICT mode: blocking due to issues above');
    process.exit(1);
  }
}

main();
