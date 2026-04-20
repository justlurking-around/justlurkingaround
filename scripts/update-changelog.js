#!/usr/bin/env node
'use strict';

/**
 * Auto-Changelog Updater
 *
 * Reads the last git commit, analyzes changed files,
 * categorizes them by module, and prepends a new entry
 * to CHANGELOG.md automatically.
 *
 * Called by:
 *   - git post-commit hook (automatic)
 *   - npm run changelog (manual)
 *   - scripts/update-changelog.js [--commit <sha>] [--dry-run]
 *
 * Detection rules:
 *   - Files changed → module category (scanner, validator, db, cli, etc.)
 *   - Commit message prefix → change type (fix, feat, security, perf, chore)
 *   - package.json version bump → version number
 */

const { execSync } = require('child_process');
const fs   = require('path');
const path = require('path');
const fss  = require('fs');

const ROOT      = path.resolve(__dirname, '..');
const CHANGELOG = path.join(ROOT, 'CHANGELOG.md');
let PKG = { version: '0.0.0' };
try { PKG = JSON.parse(fss.readFileSync(path.join(ROOT, 'package.json'), 'utf8')); } catch {}

// ── CLI args ──────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const DRY_RUN    = args.includes('--dry-run');
const TARGET_SHA = (() => {
  const idx = args.indexOf('--commit');
  return idx !== -1 ? args[idx + 1] : null;
})();

// ── Git helpers ───────────────────────────────────────────────────────────────

function git(cmd) {
  try {
    return execSync(`git ${cmd}`, { cwd: ROOT, encoding: 'utf8' }).trim();
  } catch (e) {
    return '';
  }
}

function getLastCommit(sha) {
  const ref = sha || 'HEAD';
  return {
    sha:     git(`rev-parse --short ${ref}`),
    fullSha: git(`rev-parse ${ref}`),
    message: git(`log -1 --pretty=%s ${ref}`),
    body:    git(`log -1 --pretty=%b ${ref}`),
    author:  git(`log -1 --pretty=%an ${ref}`),
    date:    git(`log -1 --pretty=%ai ${ref}`).split(' ')[0],
    files:   git(`diff-tree --no-commit-id -r --name-only ${ref}`).split('\n').filter(Boolean),
  };
}

// ── Change type detection ─────────────────────────────────────────────────────

const TYPE_RULES = [
  { prefix: /^feat/i,                     type: 'Added',   emoji: '✨' },
  { prefix: /^fix|^bug/i,                 type: 'Fixed',   emoji: '🐛' },
  { prefix: /^security|^sec/i,            type: 'Security',emoji: '🔒' },
  { prefix: /^perf/i,                     type: 'Improved',emoji: '⚡' },
  { prefix: /^refactor/i,                 type: 'Changed', emoji: '♻️'  },
  { prefix: /^docs|^readme|^changelog/i,  type: 'Docs',    emoji: '📝' },
  { prefix: /^chore|^build|^ci/i,         type: 'Chore',   emoji: '🔧' },
  { prefix: /^test/i,                     type: 'Tests',   emoji: '🧪' },
  // Version bumps (vX.Y.Z in message)
  { prefix: /^v\d+\.\d+\.\d+/i,           type: 'Release', emoji: '🚀' },
];

function detectType(message) {
  for (const rule of TYPE_RULES) {
    if (rule.prefix.test(message)) return rule;
  }
  return { type: 'Changed', emoji: '🔄' };
}

// ── Module categorization ─────────────────────────────────────────────────────

const MODULE_MAP = [
  { pattern: /^src\/scanner\//,      label: 'Scanner'        },
  { pattern: /^src\/validator\//,    label: 'Validator'      },
  { pattern: /^src\/db\//,           label: 'Database'       },
  { pattern: /^src\/cli\//,          label: 'CLI / Menu'     },
  { pattern: /^src\/worker\//,       label: 'Worker'         },
  { pattern: /^src\/poller\//,       label: 'Poller'         },
  { pattern: /^src\/notifications\//,label: 'Notifications'  },
  { pattern: /^src\/history\//,      label: 'History Scanner'},
  { pattern: /^src\/filters\//,      label: 'Filters'        },
  { pattern: /^src\/queue\//,        label: 'Queue'          },
  { pattern: /^src\/reporter\//,     label: 'Reporter'       },
  { pattern: /^src\/api\//,          label: 'API / Dashboard'},
  { pattern: /^src\/search\//,       label: 'Search Scanner' },
  { pattern: /^src\/utils\//,        label: 'Utilities'      },
  { pattern: /^scripts\//,           label: 'Scripts'        },
  { pattern: /^package.*\.json$/,    label: 'Dependencies'   },
  { pattern: /^\.github\//,          label: 'GitHub Actions' },
  { pattern: /README|CHANGELOG|CONTRIBUTING|SECURITY/, label: 'Documentation' },
  { pattern: /install-termux|start\.sh|update\.sh/,    label: 'Termux / Scripts' },
  { pattern: /\.env|\.npmrc|\.gitignore/,              label: 'Config'           },
];

function categorizeFiles(files) {
  const modules = new Map();
  for (const file of files) {
    let matched = false;
    for (const rule of MODULE_MAP) {
      if (rule.pattern.test(file)) {
        if (!modules.has(rule.label)) modules.set(rule.label, []);
        modules.get(rule.label).push(file);
        matched = true;
        break;
      }
    }
    if (!matched) {
      if (!modules.has('Other')) modules.set('Other', []);
      modules.get('Other').push(file);
    }
  }
  return modules;
}

// ── Keyword extraction from commit message ────────────────────────────────────

function extractKeywords(message, body) {
  const keywords = [];
  const fullText = `${message}\n${body}`.toLowerCase();

  const checks = [
    [/termux|android/,            'Termux/Android'],
    [/sqlite|database|db/,        'Database'],
    [/vault|encrypt/,             'Vault/Encryption'],
    [/smtp|email/,                'SMTP/Email'],
    [/ssh|private.?key/,          'SSH/Private Keys'],
    [/jwt/,                       'JWT'],
    [/kubernetes|k8s/,            'Kubernetes'],
    [/docker/,                    'Docker'],
    [/credential|password/,       'Credentials'],
    [/gist/,                      'Gist Scanner'],
    [/allowlist|denylist/,        'Allowlist/Denylist'],
    [/blame/,                     'Git Blame'],
    [/revocation|revoke/,         'Revocation Guides'],
    [/stream|real.?time/,         'Streaming Validation'],
    [/rate.?limit|maxlistener/,   'Rate Limiting'],
    [/false.?positive|noise/,     'False Positive Reduction'],
    [/entropy/,                   'Entropy Detection'],
    [/notification|discord|slack|telegram/, 'Notifications'],
    [/menu|tui|cli/,              'Interactive Menu'],
    [/pattern|regex/,             'Detection Patterns'],
    [/security|sanitize/,         'Security'],
  ];

  for (const [re, label] of checks) {
    if (re.test(fullText)) keywords.push(label);
  }
  return [...new Set(keywords)].slice(0, 6);
}

// ── Version detection ─────────────────────────────────────────────────────────

function detectVersion(message) {
  // From commit message: "v2.3.0 — ..."
  const mMsg = message.match(/v(\d+\.\d+\.\d+)/);
  if (mMsg) return mMsg[1];
  // From package.json
  return PKG.version || '0.0.0';
}

// ── Entry builder ─────────────────────────────────────────────────────────────

function buildEntry(commit) {
  const typeInfo  = detectType(commit.message);
  const version   = detectVersion(commit.message);
  const modules   = categorizeFiles(commit.files);
  const keywords  = extractKeywords(commit.message, commit.body);
  const dateStr   = commit.date || new Date().toISOString().split('T')[0];

  // Clean commit message (remove version prefix)
  const cleanMsg  = commit.message
    .replace(/^v\d+\.\d+\.\d+\s*[—-]\s*/i, '')
    .replace(/^(feat|fix|security|perf|docs|chore|refactor|test)(\(.+?\))?:\s*/i, '')
    .trim();

  const lines = [
    `## [${version}] — ${dateStr} — ${cleanMsg}`,
    '',
    `**Type:** ${typeInfo.emoji} ${typeInfo.type}  `,
    `**Commit:** \`${commit.sha}\`  `,
    commit.author !== 'AI Scanner Bot' ? `**Author:** ${commit.author}  ` : '',
    keywords.length ? `**Tags:** ${keywords.join(' · ')}` : '',
    '',
  ].filter(l => l !== undefined);

  // Body from commit message (if multiline)
  const bodyLines = commit.body
    .split('\n')
    .map(l => l.trim())
    .filter(l => l.length > 0)
    .slice(0, 20);

  if (bodyLines.length > 0) {
    lines.push('### Details');
    lines.push('');
    for (const line of bodyLines) {
      // Format bullet points
      if (line.startsWith('-') || line.startsWith('*')) {
        lines.push(line);
      } else if (line.match(/^[A-Z\[]/)) {
        lines.push(`- ${line}`);
      } else {
        lines.push(`  ${line}`);
      }
    }
    lines.push('');
  }

  // Changed modules
  if (modules.size > 0) {
    lines.push('### Files Changed');
    lines.push('');
    for (const [module, files] of modules) {
      const fileList = files.slice(0, 4).map(f => `\`${f.split('/').pop()}\``).join(', ');
      const extra = files.length > 4 ? ` +${files.length - 4} more` : '';
      lines.push(`- **${module}**: ${fileList}${extra}`);
    }
    lines.push('');
  }

  lines.push('---');
  lines.push('');

  return lines.join('\n');
}

// ── Check if this commit already has a changelog entry ────────────────────────

function alreadyLogged(sha) {
  if (!fss.existsSync(CHANGELOG)) return false;
  const content = fss.readFileSync(CHANGELOG, 'utf8');
  return content.includes(`\`${sha}\``);
}

// ── Prepend to CHANGELOG.md ───────────────────────────────────────────────────

function prependToChangelog(entry) {
  const header = `# Changelog\n\nAll notable changes are documented here.\n\n`;

  let existing = '';
  if (fss.existsSync(CHANGELOG)) {
    existing = fss.readFileSync(CHANGELOG, 'utf8');
    // Remove the header if present — we'll re-add it
    existing = existing.replace(/^# Changelog\n[\s\S]*?(?=## \[|$)/, '');
  }

  const updated = header + entry + existing;
  fss.writeFileSync(CHANGELOG, updated, 'utf8');
}

// ── Main ──────────────────────────────────────────────────────────────────────

function main() {
  const commit = getLastCommit(TARGET_SHA);

  if (!commit.sha) {
    console.error('[changelog] Could not get commit info');
    process.exit(0); // non-fatal
  }

  // Skip if already logged
  if (alreadyLogged(commit.sha) && !DRY_RUN) {
    console.log(`[changelog] Already logged: ${commit.sha} — skipping`);
    process.exit(0);
  }

  // Skip changelog-only commits to avoid infinite loops
  if (commit.message.toLowerCase().includes('update changelog') &&
      commit.files.every(f => f.includes('CHANGELOG'))) {
    console.log('[changelog] Changelog-only commit — skipping');
    process.exit(0);
  }

  const entry = buildEntry(commit);

  if (DRY_RUN) {
    console.log('=== DRY RUN — would prepend: ===\n');
    console.log(entry);
    return;
  }

  prependToChangelog(entry);
  console.log(`[changelog] Updated for commit ${commit.sha}: ${commit.message.substring(0, 60)}`);
}

main();
