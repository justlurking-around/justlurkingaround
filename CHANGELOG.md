# Changelog

All notable changes to AI Secret Scanner are documented here.

---

## [2.1.0] — 2026-04-20 — Security Audit & Bug Fix Release

### 🔒 Security Fixes
- **SECURITY** `validator/index.js` — Telegram validator now sanitizes the bot token before embedding it in a URL to prevent path-injection via crafted secret values
- **SECURITY** `validator/index.js` — Raw secret values (`rawValue`) are no longer included in any log output, error messages, or exception traces; all log paths now use redacted form only
- **SECURITY** `validator/index.js` — `validateStatus: () => true` added to prevent axios from following error status codes as throw; all status codes handled explicitly

### 🐛 Bug Fixes

#### Scanner Engine (`src/scanner/engine.js`)
- **FIX** `_matchPattern` — Regex objects were being reused across calls with the `g` flag, causing `lastIndex` to carry over and silently skip matches on subsequent scans
- **FIX** `_entropyAnalysis` — `tokenRegex` shared across loop iterations caused stale `lastIndex` and missed tokens on lines after the first match
- **FIX** `_scanFile` — Raw content URL incorrectly inherited `baseURL` from the GitHub API client; now always uses absolute URL with `baseURL: ''`
- **FIX** `_getFileTree` — Truncated trees (repos > 100 000 blobs) now detected and warned; previously silently returned partial results
- **FIX** `scannedHashes` moved from module-level to instance-level — module-level Set caused cross-scan dedup contamination in tests and multi-scanner scenarios
- **PERF** `_entropyAnalysis` — Pre-compiled pattern regex array replaces per-token `PATTERNS.some(p => new RegExp(...))` in inner loop (O(n×m) → O(n))

#### Git History Scanner (`src/history/git-history-scanner.js`)
- **FIX** `scannedCommits` / `scannedBlobs` moved from module-level to instance-level Sets
- **FIX** `_extractAddedLines` — `+++` diff file header lines no longer included in scanned text
- **FIX** Per-branch commit cap (`MAX_COMMITS_PER_BRANCH`) was not enforced when GitHub returned more commits than requested
- **FIX** Dangling commit scan now deduplicates SHAs before scanning; previously could re-scan the same commit multiple times from multiple push events
- **PERF** Entropy dedup now uses pre-compiled pattern array (same fix as engine)

#### Database Layer (`src/db/index.js`)
- **FIX** `JsonlDB.upsertRepo` — Appended to repos file on every call, causing unbounded file growth on long-running scans; now compacts on `close()`
- **FIX** `JsonlDB._loadFile` — Bad JSONL lines previously swallowed silently; now counts and logs them as warnings
- **FIX** `PostgresDB` — Pool was never explicitly closed on process exit; now registers `process.once('exit')` shutdown hook
- **FIX** `getRecentFindings` now accepts `filters` object (provider, status, repo) in both backends; previously only supported limit
- **NEW** `getStats()` returns `topProviders` map; was referenced in worker/notifier but never computed

#### Notification System (`src/notifications/index.js`)
- **FIX** Rate limit window reset bug — `_windowStart` was never reset when the window expired, causing the counter to never reset after the first minute
- **FIX** Telegram messages now hard-capped at 4 000 characters; previously messages > 4 096 chars caused Telegram API 400 errors
- **FIX** Discord embed field `value` fields could be empty string, causing Discord API 400 errors; replaced with `'N/A'` fallback
- **FIX** Notification channels were reloaded from `process.env` on every `alert()` call; now cached at construction time
- **NEW** 1-retry with 2-second delay on notification failure before giving up

#### GitHub Client (`src/utils/github-client.js`)
- **FIX** Singleton `_client` was never recreated when `GITHUB_TOKEN` changed at runtime (e.g. after user sets token in interactive menu); now compares token and recreates if changed
- **FIX** Secondary rate limit (abuse detection) on HTTP 403 with `Retry-After` header now correctly retried
- **NEW** `resetClient()` exported for programmatic reset after token changes

#### Validator (`src/validator/index.js`)
- **FIX** Stripe `402 Payment Required` now correctly returns `VALID` (test key hitting live endpoint limit)
- **FIX** Discord validator used `Bot` prefix for all tokens; user tokens (`xoxp-` style, short tokens) now use `Bearer` prefix
- **FIX** AWS validator crashed with unhandled exception if `@aws-sdk/client-sts` not installed; now returns `SKIPPED` with install instructions
- **NEW** HuggingFace validator (`/api/whoami-v2`)
- **NEW** Linear validator (GraphQL `viewer` query)
- **NEW** GitLab validator (`/api/v4/user`)

#### Config Store (`src/cli/config-store.js`)
- **FIX** After saving token/notifications/DB settings in the interactive menu, singletons (GitHub client, notifier, DB) were not reloaded — new settings only took effect after restart
- **NEW** `reloadSingletons()` — resets GitHub client, notifier, and DB after config changes; called automatically by menu on save

### 🆕 New Features
- **NEW** `src/validator/index.js` — HuggingFace, Linear, GitLab validators (3 new providers)
- **NEW** `resetClient()`, `resetDB()`, `resetNotifier()` — hot-reload exports for runtime config changes
- **NEW** `CHANGELOG.md` — this file

---

## [2.0.0] — 2026-04-20 — Day 1–5 Full Build

- Full project scaffold (Phase 1–14)
- Real-time GitHub Events poller with ETag + X-Poll-Interval
- AI repo detector (20+ signals)
- Surface scanner (100+ patterns + entropy)
- Git history deep scan (all branches, diffs, dangling commits)
- Secret pair matcher + context analyzer
- Validation engine (12 providers)
- PostgreSQL + JSONL flat-file database
- Discord / Slack / Telegram / Webhook notifications
- JSON / Markdown / CSV / SARIF reports
- Express REST API + SSE live web dashboard
- GitHub Code Search proactive scanner
- Interactive TUI menu (arrow-key, works on Termux/Android)
- Persistent config store (no `.env` required)
- Full cross-platform support: Linux · macOS · Windows · Android Termux
