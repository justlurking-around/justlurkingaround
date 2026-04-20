<p align="center">
  <img src="https://img.shields.io/badge/AI%20Secret%20Scanner-v2.2.0-cyan?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Node.js-%3E%3D16-brightgreen?style=for-the-badge&logo=node.js" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android-lightgrey?style=for-the-badge" />
</p>

<h1 align="center">🔍 AI Secret Scanner</h1>

<p align="center"><strong>Real-time GitHub credential detector for AI-generated repositories</strong></p>
<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#android--termux">Android/Termux</a> ·
  <a href="#features">Features</a> ·
  <a href="#cli-usage">CLI Usage</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

## Why This Exists

AI coding tools — **bolt.new, Cursor, Lovable, v0.dev, Replit Agent** — generate thousands of repos daily. Many commit `.env` files and hardcoded credentials directly to public GitHub because the AI baked secrets into the code and the developer never noticed.

This scanner monitors GitHub in **real-time**, detects those repos, scans them for credentials, and validates which ones are **live and active** — then alerts you immediately.

---

## Features

| Category | What's included |
|----------|----------------|
| **Detection** | 100+ named provider patterns · Shannon entropy ≥ 4.5 · Noise filter (checksums, UUIDs, lock files) |
| **Scanning** | Current HEAD files · All branches · Full git history · Dangling force-pushed commits · GitHub Gists |
| **AI Detection** | 20+ signals: `.cursorrules`, `CLAUDE.md`, bolt.new, Lovable, v0.dev, Replit Agent, Cursor... |
| **Validation** | 15+ live API validators: OpenAI, Anthropic, GitHub, Stripe, Slack, AWS, Telegram, Discord, NPM, HuggingFace, Linear, GitLab... |
| **Streaming** | Named-pattern secrets validated **immediately** mid-scan — don't wait for scan to finish |
| **Vault** | VALID secrets saved encrypted (AES-256-GCM, PBKDF2 key derivation) — never plaintext |
| **Blame** | Who committed it? GitHub blame API shows author name, email, commit SHA, date |
| **Revocation** | Per-provider step-by-step guide: where to go, what to click, what to check |
| **Gist Scanner** | Scans public GitHub Gists — major source of accidental `.env` pastes |
| **Allowlist/Denylist** | Skip known-safe repos/orgs · Force-scan specific repos/orgs |
| **Notifications** | Discord · Slack · Telegram · Generic webhook — instant alert on VALID finds |
| **Reports** | JSON · Markdown · CSV · SARIF (GitHub Advanced Security compatible) |
| **Dashboard** | Web UI at `localhost:3000` — live feed, findings table, on-demand scan |
| **Database** | SQLite (default) · PostgreSQL (production) · JSONL (zero-config fallback) |
| **CLI** | Interactive arrow-key menu · Non-interactive subcommands for scripts/CI |
| **Platforms** | Linux · macOS · Windows Terminal · **Android Termux** (non-root) |

---

## Quick Start

### Requirements
- **Node.js ≥ 16** → [nodejs.org](https://nodejs.org)
- **GitHub Token** → [github.com/settings/tokens](https://github.com/settings/tokens) (scope: `public_repo`)

```bash
git clone https://github.com/justlurking-around/justlurkingaround.git
cd justlurkingaround
npm install
npm start
```

The **first-run wizard** opens automatically. Add your GitHub token and you're running.

---

## Android / Termux

> Works on **non-rooted** Android. Tested on Android 10–14.

### Install Termux

> ⚠️ Get Termux from **F-Droid** — the Play Store version is abandoned and broken.

1. Go to [f-droid.org](https://f-droid.org) → download F-Droid APK → install it
2. Open F-Droid → search **Termux** → install

Or download directly: [github.com/termux/termux-app/releases](https://github.com/termux/termux-app/releases)
→ pick `termux-app_v*.apk` (arm64-v8a for most phones)

### First-time setup (do this once)

```bash
# 1. Update packages and install dependencies
pkg update -y && pkg upgrade -y
pkg install nodejs git -y

# 2. Clone the repo
git clone https://github.com/justlurking-around/justlurkingaround.git

# 3. Go into the folder
cd justlurkingaround

# 4. Run the Termux setup script (handles everything)
bash install-termux.sh

# 5. Reload shell so the shortcuts work
source ~/.bashrc
```

### How to start (after setup)

```bash
# From the project folder:
cd ~/justlurkingaround && npm start

# OR from ANY directory (shortcut added by install-termux.sh):
scanner
```

### How to update

```bash
# From the project folder:
cd ~/justlurkingaround && bash update.sh

# OR from anywhere:
scanner-update
```

### Common mistakes

| Error | Fix |
|-------|-----|
| `fatal: not a git repository` | You're in the wrong folder. Run `cd ~/justlurkingaround` first |
| `Cannot find package.json` | Same — run `cd ~/justlurkingaround` first |
| `npm install` fails with gyp error | Use `bash install-termux.sh` not plain `npm install` |

> **Why `install-termux.sh` and not plain `npm install`?**
> `better-sqlite3` requires Android NDK to compile — Termux doesn't have it.
> The script runs `npm install --ignore-scripts` and the scanner automatically
> uses **sql.js** (pure WebAssembly SQLite — no compilation, works everywhere).

### Termux Tips

| Tip | How |
|-----|-----|
| Arrow keys | Swipe left edge → extra key bar, or Volume Down + W/A/S/D |
| Run in background | `nohup npm start > logs/out.log 2>&1 &` |
| Auto-start on boot | Install **Termux:Boot** from F-Droid (see below) |
| View logs | `tail -f logs/scanner.log` |

### Auto-start on Android boot

```bash
# Install Termux:Boot from F-Droid first, then:
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/scanner.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
cd ~/justlurkingaround
GITHUB_TOKEN=$(cat ~/.scanner-token) npm start >> ~/justlurkingaround/logs/boot.log 2>&1
EOF
chmod +x ~/.termux/boot/scanner.sh
echo "ghp_your_token_here" > ~/.scanner-token && chmod 600 ~/.scanner-token
```

---

## Windows

Use **Windows Terminal** or **PowerShell** — NOT `cmd.exe` or Git Bash (arrow keys break).

```powershell
# Install Node.js from https://nodejs.org (LTS)
# Install Git from https://git-scm.com

git clone https://github.com/justlurking-around/justlurkingaround.git
cd justlurkingaround
npm install
npm start

# If arrow keys show escape codes:
$env:TERM = "xterm"; npm start
```

---

## Linux / macOS

```bash
# Ubuntu/Debian
sudo apt install nodejs npm git -y

# macOS
brew install node

# Clone and run
git clone https://github.com/justlurking-around/justlurkingaround.git
cd justlurkingaround && npm install && npm start
```

---

## Interactive Menu

Run `npm start` to open the arrow-key menu:

```
  +==================================================+
  |   AI Secret Scanner  v2.2.0                      |
  |   Real-time GitHub Credential Detector           |
  +==================================================+

  Token : Set     Config: ~/.config/configstore/...

? Select an option: (Use arrow keys)
>> Start Real-Time Scanner
>> Scan a Repository
>> View Recent Findings
>> Scanner Statistics
── Settings ─────────────────────────────────────────
>> GitHub Token  [SET]
>> Notifications
>> Scanner Settings
>> Database Settings
── Tools ────────────────────────────────────────────
>> Validate a Secret
>> View Leaked Keys
>> Secret Vault          ← encrypted storage for VALID secrets
>> Allowlist / Denylist  ← skip or force-scan specific repos
>> Scan GitHub Gists     ← scan public gists for .env leaks
>> About / Help
─────────────────────────────────────────────────────
   Exit
```

### Menu Screens

| Screen | What you can do |
|--------|----------------|
| **Start Scanner** | Launches background worker — polls every 60s, validates live, alerts on hits |
| **Scan a Repo** | URL → Quick/Deep/Full mode → Table/JSON/Report output |
| **View Findings** | Filter by VALID/all/historical/provider |
| **Statistics** | Repos, findings, live secrets, top providers |
| **GitHub Token** | Add/verify (calls `/user` live)/remove |
| **Notifications** | Discord/Slack/Telegram/Webhook — step-by-step setup + test button |
| **Scanner Settings** | Validation, dashboard port, git depth, log level |
| **Database** | Switch SQLite ↔ PostgreSQL ↔ JSONL; test connection |
| **Validate a Secret** | Manually test any key live against 15 providers |
| **View Leaked Keys** | VALID-only view with revocation instructions |
| **Secret Vault** | View/export AES-256 encrypted VALID secrets |
| **Allowlist/Denylist** | Manage repos/orgs to skip or force-scan |
| **Scan Gists** | Scan recent public Gists for exposed credentials |

---

## CLI Commands

Non-interactive mode for scripts and CI:

```bash
# Install globally (optional)
npm install -g .

# Scan a repository
ai-scanner scan repo https://github.com/owner/repo
ai-scanner scan repo https://github.com/owner/repo --deep      # + git history
ai-scanner scan repo https://github.com/owner/repo --json      # JSON output
ai-scanner scan repo https://github.com/owner/repo --report    # MD + SARIF files

# Start global real-time scanner
ai-scanner scan global
ai-scanner scan global --token ghp_yourtoken

# View findings
ai-scanner findings
ai-scanner findings --valid-only
ai-scanner findings --limit 100
ai-scanner findings --json

# Statistics
ai-scanner stats

# Validate a specific secret
ai-scanner validate "sk-proj-abc123" --provider openai
ai-scanner validate "ghp_abc123"     --provider github
ai-scanner validate "sk_live_abc"    --provider stripe
```

---

## How Scanning Works

```
GitHub Events API (real-time) ──→ Active repo filter
GitHub Code Search (every 30m) ─→ AI repo detection ──→ Priority queue
GitHub Gists (every 15m) ───────────────────────────────────→ ↑

Queue consumer (3 concurrent repos):
  ┌─ Surface scan (HEAD files)
  │   └─ All files except: lock files, test/, node_modules/,
  │      *.min.js, *.d.ts, .env.example ...
  │
  ├─ Deep history scan (if AI repo or has findings)
  │   └─ All branches + diffs + dangling commits (force-push remnants)
  │
  └─ Stream validator (fires per-finding, not end-of-scan):
      ├─ Named provider hit → validate IMMEDIATELY → alert if VALID
      │   └─ Save to vault (encrypted) + get blame + show revocation guide
      └─ Entropy-only hits → batch validate after scan
```

### Streaming Validation

When a **named-pattern secret** (OpenAI key, GitHub PAT, Stripe key, etc.) is found:
1. Validation fires **immediately** — doesn't wait for the full file scan to finish
2. If **VALID**: alert sent, blame fetched, secret encrypted to vault — all in seconds
3. Scan **continues** — doesn't stop, finds all secrets in the repo
4. Each repo processes independently in parallel (3 concurrent)

---

## Secret Vault

VALID secrets are saved encrypted to `./data/vault.enc.jsonl`:

```bash
# Set encryption password (add to .env)
VAULT_PASSWORD=your-strong-password

# View vault in menu: Secret Vault → View entries
# Export to JSON: Secret Vault → Export to JSON file
```

Encryption: **AES-256-GCM** with **PBKDF2** key derivation (100,000 iterations).  
Without `VAULT_PASSWORD`, entries are saved as plaintext JSON — set the password.

---

## Detection Coverage

<details>
<summary><strong>100+ provider patterns — click to expand</strong></summary>

| Category | Providers |
|----------|-----------|
| **Cloud** | AWS (Access Key + Secret + MWS), GCP (API Key, OAuth, Service Account), Azure (Storage, SAS, Connection String), Cloudflare, Heroku, Vercel, Netlify |
| **AI** | OpenAI (sk-proj- + legacy), Anthropic, HuggingFace, Firebase |
| **Payments** | Stripe (live/test/restricted), Braintree, PayPal, Coinbase, Binance, Plaid |
| **Messaging** | Slack (bot/user/workspace/webhook), Discord (bot/webhook), Telegram, Twilio, SendGrid, Mailgun, Mailchimp, Postmark |
| **DevOps** | GitHub (PAT/OAuth/App/Server), GitLab, NPM, PyPI, Docker Hub |
| **Databases** | MongoDB Atlas, PostgreSQL, MySQL, Redis, RabbitMQ (connection strings) |
| **SaaS** | Shopify (4 types), Salesforce, HubSpot, Intercom, Zendesk, Jira, Linear, Airtable, Notion, Figma |
| **Analytics** | Datadog, New Relic, Sentry, Amplitude, Segment, Mixpanel |
| **Auth** | Okta, Auth0 |
| **Storage/CDN** | Dropbox, Box, Cloudinary, Mapbox, Imgur |
| **Search** | Algolia, Elasticsearch |
| **Keys/Certs** | SSH Private Keys (RSA/EC/DSA/OPENSSH), PGP Private Key Blocks |
| **Generic** | JWT secrets, bearer tokens, high-entropy strings (entropy ≥ 4.5) |

</details>

---

## False Positive Reduction

| Layer | What it catches |
|-------|----------------|
| **Path filter** | `test/`, `node_modules/`, `dist/`, `.env.example`, `vendor/` |
| **Lock file filter** | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `composer.lock` + 8 more |
| **Noise filter** | npm `sha512-` integrity hashes, hex checksums (md5/sha1/sha256), UUIDs, raw base64 blobs |
| **Dummy value filter** | `YOUR_API_KEY`, `xxx...`, `<TOKEN>`, `000000...`, repeated chars |
| **Entropy threshold** | 4.5 minimum (was 4.0 — reduced noise significantly) |
| **Pair matching** | AWS key + secret together = higher confidence |
| **Context scoring** | Variable name + file type + assignment analysis |
| **Per-repo cap** | Max 100 findings per repo (prevents noisy repos flooding queue) |

---

## Revocation Guides

When a VALID secret is found, the scanner prints a step-by-step revocation guide:

```
Provider : Stripe
Severity : CRITICAL
Impact   : Financial fraud — unauthorized charges possible
URL      : https://dashboard.stripe.com/apikeys

1. Go to https://dashboard.stripe.com/apikeys
2. Roll (revoke) the leaked key immediately
3. Check recent charges for unauthorized activity
4. Review webhook events for suspicious calls
5. Consider enabling Stripe Radar rules
```

Guides available for: OpenAI, Anthropic, GitHub, Stripe, AWS, Slack, SendGrid, Telegram, Discord, NPM, Heroku, Mailgun, Shopify, HuggingFace, Linear, GitLab.

---

## Database

| Backend | When used | Notes |
|---------|-----------|-------|
| **SQLite** | Default (no config needed) | Fast, zero-config, works on Termux |
| **PostgreSQL** | When `DATABASE_URL` is set | Production, full SQL, best for large scans |
| **JSONL** | Fallback if both unavailable | Always works, even read-only filesystems |

Auto-selection priority: PostgreSQL → SQLite → JSONL

---

## Configuration

All settings via the **interactive menu** (no `.env` editing required).  
Advanced users: copy `.env.defaults` to `.env` and edit.

```bash
# Required
GITHUB_TOKEN=ghp_...

# Vault encryption (highly recommended)
VAULT_PASSWORD=your-strong-password-here

# Database (default: SQLite — no config needed)
DATABASE_URL=postgresql://user:pass@localhost:5432/ai_scanner
SQLITE_PATH=./data/scanner.db
USE_JSONL=false

# Notifications
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=-1001234567890
NOTIFY_WEBHOOK_URL=https://your-server.com/webhook

# Scanner
VALIDATE_SECRETS=true
ENABLE_API=true
API_PORT=3000
MAX_COMMITS_PER_BRANCH=50
MAX_BRANCHES=10
LOG_LEVEL=info
```

Config saved at:
- Linux/macOS: `~/.config/configstore/ai-secret-scanner.json`
- Windows: `%APPDATA%\configstore\ai-secret-scanner.json`
- Android/Termux: `~/.config/configstore/ai-secret-scanner.json`

---

## Reports

Each scanned repo with findings gets reports in `./reports/`:

| Format | File | Use case |
|--------|------|---------|
| JSON | `*.json` | Automation, APIs, further processing |
| Markdown | `*.md` | Human review, GitHub issues, disclosure |
| CSV | `*.csv` | Spreadsheets, SIEM import |
| SARIF | `*.sarif.json` | GitHub Advanced Security, VS Code |

---

## Web Dashboard

Open **http://localhost:3000** while the scanner is running:

- Real-time SSE live feed of findings
- Stats: repos, findings, live secrets
- Filterable findings table
- On-demand scan by URL

---

## Architecture

```
src/
├── cli/           Interactive TUI menu + CLI subcommands + config store
├── poller/        GitHub Events API (ETag, X-Poll-Interval)
├── filters/       Active repo, AI detector, false-positive filter
├── queue/         Priority queue (in-memory or Redis)
├── scanner/       Engine, patterns (100+), pair matcher, context analyzer
│                  + blame (who committed) + gist scanner + revocation guides
├── history/       All-branches + diffs + dangling commit scanner
├── search/        GitHub Code Search proactive discovery
├── validator/     Live API validation (15 providers) + stream validator
├── notifications/ Discord / Slack / Telegram / Webhook
├── reporter/      JSON / Markdown / CSV / SARIF
├── api/           Express REST API + SSE live dashboard
├── db/            SQLite + PostgreSQL + JSONL fallback + encrypted vault
├── worker/        Full orchestration loop
└── utils/         Logger (Termux-safe) + entropy + GitHub client + allowlist
```

---

## Security & Responsible Use

This tool is for **security research and education only**.

- Do **not** access any systems using credentials you discover
- Do **not** store or share credentials that belong to others
- If you find a live secret: notify the repo owner + contact the provider
- See [SECURITY.md](SECURITY.md) for full responsible disclosure policy

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) to add:
- New provider patterns
- New validators
- AI signature signals

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for full version history.

---

## License

MIT © [justlurking-around](https://github.com/justlurking-around)

<p align="center"><sub>Inspired by TruffleHog · Gitleaks · GitGuardian · Neodyme's GitHub secrets research</sub></p>
