# Changelog

All notable changes are documented here.

## [2.2.0] — 2026-04-20 — auto-changelog system + git hooks

**Type:** ✨ Added  
**Commit:** `ad6c226`  



### Details

- Adds scripts/update-changelog.js and scripts/install-hooks.js
- Wires into post-commit and pre-push git hooks

### Files Changed

- **Documentation**: `CHANGELOG.md`
- **Dependencies**: `package.json`
- **Scripts**: `install-hooks.js`, `update-changelog.js`

---
## [2.3.0] — 2026-04-20 — Credential scanning: DB passwords, SMTP, SSH keys, JWT, K8s secrets

**Type:** 🚀 Release  
**Commit:** `41c697e`  

**Tags:** Database · Vault/Encryption · SMTP/Email · SSH/Private Keys · JWT · Kubernetes

### Details

- NEW: src/scanner/credential-patterns.js (24 new patterns)
- Credential types detected:
- Database connections: MySQL, PostgreSQL, MongoDB, Redis, MSSQL
  (full connection strings with embedded credentials)
- SMTP / email: smtp:// URLs, SMTP_PASSWORD env vars, user+pass pairs
- Private keys: RSA, EC, OpenSSH, PKCS#8 (full PEM block detection)
- JWT signing secrets (JWT_SECRET, signing_secret env vars)
- Generic passwords: DB_PASSWORD, ADMIN_PASSWORD, ROOT_PASSWORD
- HTTP Basic Auth headers (base64 encoded)
- .htpasswd credential entries (Apache password files)
- GCP Service Account JSON files (full file detection)
- AWS credentials file format (~/.aws/credentials)
- Docker registry auth tokens (docker config.json)
- Kubernetes Secret manifests (base64 encoded data fields)
- FTP/SFTP connection strings with credentials
- Encryption keys (AES_KEY, ENCRYPTION_KEY, CIPHER_KEY)
- .env SECRET_KEY entries
- NEW: src/validator/credential-validator.js
- Live validators (non-destructive probes only):
- MySQL: createConnection() + immediate disconnect (3-5s timeout)

### Files Changed

- **Dependencies**: `package-lock.json`, `package.json`
- **Scanner**: `credential-patterns.js`, `engine.js`, `revocation-guide.js`
- **Validator**: `credential-validator.js`, `stream-validator.js`

---
## [2.2.3] — 2026-04-20 — Fix wrong-directory user error

### Problem
Running `git pull` or `npm start` from `~` (home) instead of `~/justlurkingaround`
caused two confusing errors:
- `fatal: not a git repository`
- `ENOENT: no such file or directory, open 'package.json'`

### Added
- **`start.sh`** — universal launcher. Resolves its own location automatically.
  Run from any directory: `bash ~/justlurkingaround/start.sh`
- **`update.sh`** — universal updater. Runs `git pull` + `npm install --ignore-scripts`
  from anywhere: `bash ~/justlurkingaround/update.sh`
- **Shell aliases** injected by `install-termux.sh` into `~/.bashrc`:
  - `scanner` → start from anywhere
  - `scanner-update` → pull latest and reinstall
  - `scanner-logs` → follow live log

### Updated
- `install-termux.sh` — adds aliases to `~/.bashrc` (duplicate-safe)
- `README.md` — Termux section rewritten with numbered steps and
  common mistakes table

---

## [2.2.2] — 2026-04-20 — Silence better-sqlite3 binding warning on Termux

### Fixed
- `better-sqlite3` binding error was logged as `WARN` on Termux Android,
  even though `sql.js` fallback worked correctly
- Demoted to `debug` level — silent unless `LOG_LEVEL=debug`
- No functional change — scanning, DB, vault all worked before and after

---

## [2.2.1] — 2026-04-20 — Fix Termux npm install failure (better-sqlite3)

### Problem
`better-sqlite3` requires Android NDK (`android_ndk_path`) for native
compilation. Termux doesn't have it, causing `npm install` to fail entirely.

### Fixed
- `src/db/sqlite.js` — dual-driver architecture:
  - `better-sqlite3` (native C++, fast) — Linux / macOS / Windows
  - `sql.js` (pure WebAssembly, zero compilation) — Termux / Android / CI
  - Auto-detects which driver is available at startup
  - Both implement identical API — transparent to the rest of the app
  - `SqlJsDB` auto-saves to disk every 60s and on process exit
- `package.json` — `better-sqlite3` moved to `optionalDependencies`
  (npm skips it gracefully when native build fails)
- `.npmrc` — `optional=true` ensures optional dep failures are non-fatal
- `install-termux.sh` — uses `npm install --ignore-scripts` to skip
  all native builds; verifies `sql.js` loads correctly

### DB priority chain
```
PostgreSQL (DATABASE_URL set)
  → SQLite via better-sqlite3 (native, desktop)
  → SQLite via sql.js (WASM, Termux/Android/CI)
  → JSONL flat-file (zero deps, always works)
```

---

## [2.2.0] — 2026-04-20 — 6 new features

### Added

**1. Encrypted Secret Vault** (`src/db/vault.js`)
- VALID secrets saved to `data/vault.enc.jsonl`
- AES-256-GCM encryption, PBKDF2 key derivation (100 000 iterations)
- Set `VAULT_PASSWORD` env var to enable encryption
- `vault.save()`, `vault.list(pw)`, `vault.export(pw, path)`
- Menu: Secret Vault → View / Set password / Export to JSON
- Worker automatically saves every VALID finding to vault

**2. SQLite Database** (`src/db/sqlite.js`)
- `better-sqlite3` (native) or `sql.js` (WASM) — auto-selected
- WAL mode for safe concurrent writes
- Replaces JSONL as default local backend
- `SQLITE_PATH` env var overrides file location

**3. GitHub Blame** (`src/scanner/blame.js`)
- Fetches who committed the secret via GitHub GraphQL blame API
- Returns: author name, email, GitHub login, commit SHA, date
- Called only for VALID findings (saves API quota)
- Shown in logs and notification payloads

**4. GitHub Gist Scanner** (`src/scanner/gist-scanner.js`)
- Scans public GitHub Gists for exposed credentials
- Same 100+ patterns + entropy as repo scanner
- Auto-runs every 15 min when GitHub token is configured
- `scanPublicGists(pages)` and `scanUserGists(username)`
- Accessible from menu → Scan GitHub Gists

**5. Allowlist / Denylist** (`src/utils/allowlist.js`)
- `data/allowlist.json` — repos/orgs to always skip
- `data/denylist.json` — repos/orgs to always force-scan
- Worker checks allowlist before queuing every polled event
- Menu: Allowlist / Denylist → Add / Remove / View

**6. Per-provider Revocation Guides** (`src/scanner/revocation-guide.js`)
- Step-by-step instructions for 16 providers: OpenAI, Anthropic,
  GitHub, Stripe, AWS, Slack, SendGrid, Telegram, Discord, NPM,
  Heroku, Mailgun, Shopify, HuggingFace, Linear, GitLab
- Each guide includes severity, impact, action steps, direct URL
- Printed on every VALID finding in logs
- Included in Markdown reports

### Updated
- `package.json` bumped to v2.2.0
- `README.md` fully rewritten — tables, clear sections, Termux instructions

---

## [2.1.4] — 2026-04-20 — Termux-safe log formatter + streaming validation

### Added

**Compact Termux-safe log output** (`src/utils/logger.js`)
- All console lines truncated to terminal width (78 cols on Termux)
- `[Finding]` lines → compact single-row format: `FIND repo | pattern | file STATUS`
- `[Scanner]` findings count → `SCAN repo  N findings` (color-coded)
- `LIVE SECRET` → full-width red banner (never truncated)
- `HIGH-CONF PAIR` → yellow `PAIR` prefix, single line
- Short 4-char level labels: `INFO` `WARN` `ERRO` `DBUG`
- File transport still gets full untruncated output

**Streaming real-time validation** (`src/validator/stream-validator.js`)
- Named-pattern secrets (OpenAI, GitHub, Stripe, etc.) validated
  **immediately** mid-scan — don't wait for repo scan to finish
- 25 providers in `HIGH_VALUE_PATTERNS` set trigger instant validation
- AWS key + secret buffered until both found, then pair-validated
- Entropy-only `unknown` strings batched for end-of-scan
- Max 3 concurrent validations in flight
- On VALID: DB insert + notification + SSE broadcast fire instantly
- Scan continues after VALID hit — finds all secrets in the repo

---

## [2.1.3] — 2026-04-20 — Fix MaxListeners + 500-finding noise flood

### Fixed
- **`MaxListenersExceededWarning`** — previous fix targeted wrong object.
  Root cause: `https.globalAgent` TLSSocket has its own listener count.
  Now sets all three targets:
  `EventEmitter.defaultMaxListeners = 200`,
  `https.globalAgent.setMaxListeners(200)`,
  `http.globalAgent.setMaxListeners(200)`

- **500+ findings on single repos** (e.g. `qingfeng1910/TV-update`)
  - Entropy threshold raised `4.0` → `4.5`
  - `isLikelyNoise()` added: rejects npm `sha512-` hashes, hex checksums,
    UUIDs, long base64 blobs, pure numeric strings
  - `maxFindingsPerRepo: 100` cap — noisy repos log a warning and stop
  - `isNoisyValue()` wired into engine, history scanner, false-positive filter

---

## [2.1.2] — 2026-04-20 — Fix 4 runtime bugs from live scan output

### Fixed
- **Lock file flooding** (`package-lock.json`, `pnpm-lock.yaml`, etc.)
  — added `SKIP_FILENAMES` set with exact basename match (13 lock files)
  — also added minified/bundled/TypeScript declaration file patterns
- **Twilio pair alert spamming 19×** — one alert per unique
  `pairName + filePath` combination per scan (was per-finding)
- **`MaxListenersExceededWarning`** — raised to 30
  _(note: fully fixed in v2.1.3)_
- **Menu wraps back to top** — `loop: false` on all 8 list prompts

---

## [2.1.1] — 2026-04-20 — Termux UI/UX overhaul

### Fixed
- Banner rewritten as ASCII `+===+` box (emoji broke border alignment on Termux fonts)
- Menu choice labels kept ≤ 52 chars (no line wrapping on 80-col terminal)
- Removed inline trailing `chalk.gray()` hints from choice lines (caused overlap)
- All result tables rebuilt with `printTable()` helper (fixed column widths ≤ 78 chars)
- `TERM_WIDTH` auto-detection capped at 78
- Separators consistently 52 chars throughout
- `npm start` now correctly launches the interactive CLI menu
- `reloadSingletons()` called after every config save (no restart needed)

---

## [2.1.0] — 2026-04-20 — Full security audit + bug fix release

### Security Fixes
- Telegram validator: sanitize token before URL embedding (path injection)
- `rawValue` never appears in logs or error messages (redacted only)
- `validateStatus: () => true` — no silent redirect following

### Bug Fixes (18 total across 6 files)
- `scanner/engine`: regex `lastIndex` carry-over (missed matches)
- `scanner/engine`: `tokenRegex` shared across iterations (missed tokens)
- `scanner/engine`: raw file URL inherited wrong `baseURL`
- `scanner/engine`: truncated trees (>100k blobs) silently returned partial
- `scanner/engine`: `scannedHashes` module-level → cross-scan contamination
- `history`: `scannedCommits/Blobs` same module-level bug
- `history`: `+++` diff header lines included in scan text
- `history`: `maxCommitsPerBranch` cap not enforced
- `history`: dangling commits scanned multiple times
- `db/jsonl`: `upsertRepo` appended unboundedly — file growth
- `db/jsonl`: bad JSONL lines silently swallowed
- `db/postgres`: pool never closed on exit
- `db`: `getStats()` missing `topProviders` field
- `notifications`: rate limit window never reset
- `notifications`: Telegram messages >4096 chars → API 400
- `notifications`: Discord empty embed field value → API 400
- `validator`: Stripe 402 treated as INVALID (it means key is valid)
- `validator`: Discord `Bot` prefix used for user tokens

### Added
- HuggingFace, Linear, GitLab validators (3 new providers)
- `resetClient()`, `resetDB()`, `resetNotifier()` — hot-reload after config change
- `reloadSingletons()` in config-store — settings apply without restart

---

## [2.0.0] — 2026-04-20 — Day 1–5 complete build

### Added (full system)
- Real-time GitHub Events poller (ETag + X-Poll-Interval)
- AI repo detector (20+ signals: `.cursorrules`, `CLAUDE.md`, bolt.new, Lovable, v0.dev...)
- Surface scanner: 100+ provider patterns + Shannon entropy ≥ 4.5
- Git history deep scan: all branches, diffs, dangling commits
- Secret pair matcher + context analyzer
- Validation engine: 12 providers
- PostgreSQL + JSONL flat-file database
- Discord / Slack / Telegram / Webhook notifications
- JSON / Markdown / CSV / SARIF reports
- Express REST API + SSE live web dashboard
- GitHub Code Search proactive scanner
- Interactive TUI menu (arrow-key, Termux/Android safe)
- Persistent config store (no `.env` required)
- Full cross-platform: Linux · macOS · Windows · Android Termux
