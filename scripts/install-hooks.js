#!/usr/bin/env node
'use strict';

/**
 * Install git hooks for the project.
 * Run once: node scripts/install-hooks.js
 * Also called automatically by: npm run prepare
 */

const fs   = require('fs');
const path = require('path');

const ROOT      = path.resolve(__dirname, '..');
const HOOKS_DIR = path.join(ROOT, '.git', 'hooks');

function write(hookName, content) {
  if (!fs.existsSync(HOOKS_DIR)) {
    console.warn(`[hooks] .git/hooks not found — skipping (not a git repo?)`);
    return false;
  }
  const hookPath = path.join(HOOKS_DIR, hookName);
  fs.writeFileSync(hookPath, content, { encoding: 'utf8', mode: 0o755 });
  console.log(`[hooks] Installed: .git/hooks/${hookName}`);
  return true;
}

// ── post-commit: auto-update CHANGELOG then amend commit ─────────────────────

write('post-commit', `#!/bin/sh
# Auto-update CHANGELOG.md after every commit
# Does not create an extra commit — updates the file only
# (Changelog is committed manually or via pre-push)

node "$(git rev-parse --show-toplevel)/scripts/update-changelog.js"
`);

// ── pre-push: stage CHANGELOG.md if it was updated ───────────────────────────

write('pre-push', `#!/bin/sh
ROOT="$(git rev-parse --show-toplevel)"

# 1. Run sanitizer — block push if real credentials found
echo "[pre-push] Running sanitization check..."
node "$ROOT/scripts/sanitize.js" --strict
SANITIZE_EXIT=$?
if [ $SANITIZE_EXIT -ne 0 ]; then
  echo "[pre-push] BLOCKED: sanitize check failed. Fix issues before pushing."
  exit 1
fi

# 2. Commit auto-updated CHANGELOG.md if modified
if ! git diff --quiet "$ROOT/CHANGELOG.md" 2>/dev/null; then
  echo "[pre-push] Committing auto-updated CHANGELOG.md..."
  git add "$ROOT/CHANGELOG.md"
  git commit --no-verify -m "chore: auto-update CHANGELOG.md [skip hooks]"
fi
`);

// ── commit-msg: enforce format ────────────────────────────────────────────────

write('commit-msg', `#!/bin/sh
# Soft enforce commit message format (warn only, never block)
MSG=$(cat "$1")

# Skip if it's an auto-changelog commit
echo "$MSG" | grep -q "\\[skip hooks\\]" && exit 0

# Check for reasonable message length
if [ \${#MSG} -lt 10 ]; then
  echo "[commit-msg] Warning: commit message is very short"
fi

# Suggest format if no conventional prefix
echo "$MSG" | grep -qE "^(feat|fix|security|perf|docs|chore|refactor|test|v[0-9])" || \
  echo "[commit-msg] Tip: use feat/fix/security/perf/docs prefix for better changelogs"

exit 0
`);

console.log('\n[hooks] All git hooks installed successfully.');
console.log('[hooks] post-commit: auto-updates CHANGELOG.md');
console.log('[hooks] pre-push:    commits updated CHANGELOG.md');
console.log('[hooks] commit-msg:  soft format check (never blocks)');
