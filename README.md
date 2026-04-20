<p align="center">
  <img src="https://img.shields.io/badge/AI%20Secret%20Scanner-v2.0.0-cyan?style=for-the-badge&logo=github" alt="Version"/>
  <img src="https://img.shields.io/badge/Node.js-%3E%3D16-brightgreen?style=for-the-badge&logo=node.js" alt="Node.js"/>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android-lightgrey?style=for-the-badge" alt="Platforms"/>
</p>

<h1 align="center">🔍 AI Secret Scanner</h1>

<p align="center">
  <strong>Real-time GitHub credential detector for AI-generated repositories</strong><br/>
  <sub>Finds leaked API keys, tokens & credentials before attackers do</sub>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-android--termux-installation">Android/Termux</a> ·
  <a href="#-interactive-menu">Interactive Menu</a> ·
  <a href="#-features">Features</a> ·
  <a href="#-configuration">Configuration</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

## Why This Exists

AI coding tools — **bolt.new, Lovable, Cursor, v0.dev, Replit Agent, GitHub Copilot** — generate thousands of repositories every day. Many ship with `.env` files, hardcoded API keys, and database credentials committed to public GitHub because the AI baked secrets directly into the generated code and the developer never noticed.

This scanner monitors GitHub in **real-time**, detects those repositories, and scans them for exposed credentials — with live validation to confirm which ones actually work.

---

## ✨ Features

| | Feature | Details |
|---|---------|---------|
| 📡 | **Real-time polling** | GitHub Events API with ETag caching + server-side rate control |
| 🤖 | **AI repo detection** | 20+ signals: `.cursorrules`, `CLAUDE.md`, bolt.new, Lovable, v0.dev, Replit... |
| 🔍 | **Surface scan** | Current HEAD — all scannable files, false-positive filtered |
| 🕐 | **Deep history scan** | ALL branches + full commit history + force-pushed "deleted" commits |
| 🔑 | **100+ secret patterns** | AWS, OpenAI, Stripe, GitHub, Slack, GCP, Azure, Discord, Telegram + 80 more |
| 📊 | **Entropy analysis** | Shannon entropy ≥ 4.0 catches unlabeled secrets regex misses |
| ✅ | **Live validation** | Tests secrets against real provider APIs |
| 🔗 | **Pair matching** | AWS key+secret together → higher confidence, fewer false positives |
| 🧠 | **Context scoring** | Variable name + file type + assignment analysis |
| 🔎 | **Proactive search** | GitHub Code Search for known secret patterns in recent AI repos |
| 🔔 | **Notifications** | Discord, Slack, Telegram, Generic Webhook |
| 📋 | **Reports** | JSON, Markdown, CSV, SARIF (GitHub Advanced Security compatible) |
| 🖥 | **Web dashboard** | Real-time SSE feed, filterable findings table, on-demand scan |
| 🎮 | **Interactive TUI** | Arrow-key menu — no commands to memorize |
| 📱 | **Cross-platform** | Linux · macOS · Windows · **Android Termux** |

---

## 📸 Interactive Menu

```
  ╔══════════════════════════════════════════════════╗
  ║     🔍  AI Secret Scanner  v2.0.0                ║
  ║     Real-time GitHub Credential Detector         ║
  ╠══════════════════════════════════════════════════╣
  ║  Finds leaked API keys in AI-generated repos     ║
  ║  Works on Linux · macOS · Windows · Termux       ║
  ╚══════════════════════════════════════════════════╝

  Config: ~/.config/configstore/ai-secret-scanner.json
  Status: ● Token Set

? What do you want to do? (Use arrow keys)
❯ ▶  Start Real-Time Scanner         (monitors GitHub Events API)
   🔍 Scan a Specific Repository       (paste any GitHub URL)
   📊 View Recent Findings             (from local database)
   📈 Scanner Statistics               (totals & summary)
  ─── Configuration ──────────────────────────────────
   🔑 GitHub Token Settings           sk-****1234
   🔔 Notification Settings           (Discord/Slack/Telegram)
   ⚙️  Scanner Settings                (depth, validation, API)
   🗄️  Database Settings               (PostgreSQL / JSONL)
  ─── Other ──────────────────────────────────────────
   ✔️  Validate a Secret               (test any key live)
   📋 View Leaked Keys Log             (VALID findings only)
   ℹ️  About & Help                    (version, links, usage)
  ─────────────────────────────────────────────────────
   ✖  Exit
```

---

## 🚀 Quick Start

### Prerequisites
- **Node.js ≥ 16** — [nodejs.org](https://nodejs.org)
- **GitHub Personal Access Token** — [github.com/settings/tokens](https://github.com/settings/tokens)
  - Scope needed: `public_repo` (read-only is enough)

### Install & Run

```bash
# 1. Clone
git clone https://github.com/justlurking-around/justlurkingaround.git
cd justlurkingaround

# 2. Install dependencies
npm install

# 3. Launch interactive menu
npm start
```

The **first-run wizard** will guide you through adding your GitHub token and optional notification channels. No manual config editing required.

---

## 📱 Android / Termux Installation

> Works on **non-rooted** and **rooted** Android devices.
> Tested on Android 10, 11, 12, 13, 14.

### Step 1 — Install Termux

> ⚠️ **Do NOT install Termux from the Google Play Store** — it is outdated and no longer maintained there.

Install from **F-Droid** (recommended):
1. Open your browser and go to **[f-droid.org](https://f-droid.org)**
2. Download and install the F-Droid app
3. Search for **"Termux"** and install it

Or download the APK directly:
- [Termux latest release on GitHub](https://github.com/termux/termux-app/releases/latest)
- Download the `termux-app_v*.apk` (arm64-v8a for most modern Android phones)

### Step 2 — First-time Termux setup

Open the Termux app and run:

```bash
# Update package lists
pkg update -y && pkg upgrade -y

# Install Node.js and git
pkg install nodejs git -y

# Verify installation
node --version   # should show v18+ or higher
npm --version
git --version
```

### Step 3 — Clone and install

```bash
# Clone the repo
git clone https://github.com/justlurking-around/justlurkingaround.git
cd justlurkingaround

# Install dependencies
npm install
```

### Step 4 — Launch

```bash
# Start interactive menu
npm start
```

The **first-run setup wizard** will appear automatically. Use **arrow keys** to navigate and **Enter** to select.

### Termux Tips

| Tip | Detail |
|-----|--------|
| **Keyboard** | Swipe from the left edge to reveal the extra key bar (arrow keys, Tab, Ctrl) |
| **Arrow keys** | Volume Down + W/A/S/D also work as arrow keys on some devices |
| **Background** | Use `nohup npm start &` to keep scanner running when you switch apps |
| **Storage** | Run `termux-setup-storage` to allow Termux to access your Downloads folder |
| **Keep alive** | Install **Termux:Boot** from F-Droid to auto-start the scanner on reboot |

### Auto-start on Android boot (optional)

1. Install **Termux:Boot** from F-Droid
2. Create the boot script:

```bash
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/start-scanner.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
cd ~/justlurkingaround
GITHUB_TOKEN=$(cat ~/.ai-scanner-token) npm start
EOF
chmod +x ~/.termux/boot/start-scanner.sh

# Save your token to a file (safer than hardcoding in the script)
echo "ghp_yourtoken" > ~/.ai-scanner-token
chmod 600 ~/.ai-scanner-token
```

---

## 🖥 Windows Installation

> Use **Windows Terminal** or **PowerShell** — NOT `cmd.exe` or Git Bash (arrow keys won't work correctly there)

### Step 1 — Install Node.js

Download from [nodejs.org](https://nodejs.org) → LTS version → Run the installer

### Step 2 — Install Git

Download from [git-scm.com](https://git-scm.com/download/win) → Run installer

### Step 3 — Clone and run

Open **Windows Terminal** (search for it in Start):

```powershell
# Clone
git clone https://github.com/justlurking-around/justlurkingaround.git
cd justlurkingaround

# Install
npm install

# Run
npm start
```

> **Note:** If arrow keys show escape characters instead of moving the selection, set `TERM=xterm` before running:
> ```powershell
> $env:TERM = "xterm"
> npm start
> ```

---

## 🍎 macOS Installation

```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Node.js
brew install node

# Clone and run
git clone https://github.com/justlurking-around/justlurkingaround.git
cd justlurkingaround
npm install
npm start
```

---

## 🐧 Linux Installation

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install nodejs npm git -y

# Arch Linux
sudo pacman -S nodejs npm git

# Fedora / RHEL
sudo dnf install nodejs npm git -y

# Clone and run
git clone https://github.com/justlurking-around/justlurkingaround.git
cd justlurkingaround
npm install
npm start
```

---

## 🎮 Interactive Menu Guide

Run `npm start` (or `ai-scanner` after global install) to open the interactive menu.

Navigate with **↑ ↓ arrow keys** and press **Enter** to select.

### Menu Options

| Option | What it does |
|--------|-------------|
| **▶ Start Real-Time Scanner** | Launches the background worker — polls GitHub Events every 60s, scans new AI repos, validates secrets, sends notifications |
| **🔍 Scan a Specific Repo** | Paste any GitHub URL — choose Quick/Deep/Full scan mode, output format |
| **📊 View Recent Findings** | Browse findings by status (VALID/all/historical) or filter by provider |
| **📈 Statistics** | Totals: repos scanned, findings, live secrets |
| **🔑 GitHub Token** | Add/verify/remove your GitHub PAT |
| **🔔 Notification Settings** | Configure Discord, Slack, Telegram, or generic webhook — includes setup instructions and a test button |
| **⚙️ Scanner Settings** | Validation toggle, dashboard port, git history depth, log level |
| **🗄️ Database Settings** | Switch between PostgreSQL and JSONL flat-file; test connection |
| **✔️ Validate a Secret** | Manually test any API key against its provider (OpenAI, GitHub, Stripe, etc.) |
| **📋 View Leaked Keys Log** | Shows only VALID (live, confirmed) secrets |
| **ℹ️ About & Help** | Version info, platform support, config file location |

---

## ⌨️ CLI Commands (Non-Interactive / Scripting)

For use in CI/CD, scripts, or when TTY is unavailable:

```bash
# Global install (optional — lets you run ai-scanner from anywhere)
npm install -g .

# Scan a single repo
ai-scanner scan repo https://github.com/owner/repo
ai-scanner scan repo https://github.com/owner/repo --deep          # include git history
ai-scanner scan repo https://github.com/owner/repo --json          # JSON output
ai-scanner scan repo https://github.com/owner/repo --report        # generate MD+SARIF files
ai-scanner scan repo https://github.com/owner/repo --no-validate   # skip live API validation

# Start global real-time scanner
ai-scanner scan global
ai-scanner scan global --token ghp_yourtoken

# View findings
ai-scanner findings
ai-scanner findings --limit 100
ai-scanner findings --valid-only                                    # live secrets only
ai-scanner findings --json

# Database stats
ai-scanner stats

# Validate a specific key
ai-scanner validate "sk-proj-abc123" --provider openai
ai-scanner validate "ghp_abc123"     --provider github
ai-scanner validate "sk_live_abc123" --provider stripe
```

---

## 🔑 GitHub Token Setup

A GitHub Personal Access Token (PAT) dramatically improves scan coverage:

| Mode | Rate limit | Recommended? |
|------|-----------|-------------|
| No token | 60 req/hour | ⚠️ Very slow |
| With token (`public_repo`) | 5,000 req/hour | ✅ Yes |

**How to get one:**
1. Go to [github.com/settings/tokens](https://github.com/settings/tokens)
2. Click **"Generate new token (classic)"**
3. Name it `ai-secret-scanner`
4. Check **`public_repo`** scope (that's all you need)
5. Click **Generate token**
6. Copy it → paste it in the **🔑 GitHub Token Settings** menu (or in `.env`)

---

## 🔔 Notification Setup

Configure alerts in the **🔔 Notification Settings** menu, which walks you through each channel step-by-step. Or set via environment variable:

```bash
# Discord
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...

# Slack
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# Telegram
TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
TELEGRAM_CHAT_ID=-1001234567890

# Generic webhook (receives JSON POST)
NOTIFY_WEBHOOK_URL=https://your-server.com/webhook
```

---

## ⚙️ Configuration

All settings are managed through the **interactive menu** or environment variables. Config is saved persistently at:

| Platform | Config location |
|----------|----------------|
| Linux / macOS | `~/.config/configstore/ai-secret-scanner.json` |
| Windows | `%APPDATA%\configstore\ai-secret-scanner.json` |
| Android (Termux) | `~/.config/configstore/ai-secret-scanner.json` |

Advanced users can also use a `.env` file in the project root:

```bash
cp .env.defaults .env
# Edit .env with your preferred editor
```

Full `.env` reference:

```bash
# Required
GITHUB_TOKEN=ghp_...

# Database (default: JSONL flat-file, no setup needed)
DATABASE_URL=postgresql://user:pass@localhost:5432/ai_scanner

# Notifications
DISCORD_WEBHOOK_URL=
SLACK_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
NOTIFY_WEBHOOK_URL=

# Scanner behavior
VALIDATE_SECRETS=true          # run live API validation
ENABLE_API=true                # web dashboard
API_PORT=3000                  # dashboard port
MAX_COMMITS_PER_BRANCH=50      # git history depth
MAX_BRANCHES=10                # branches per repo

# Logging
LOG_LEVEL=info                 # debug | info | warn | error
LOG_DIR=./logs
```

---

## 🏗 Architecture

```
src/
├── cli/
│   ├── index.js          CLI entry point (interactive + subcommands)
│   ├── menu.js           Interactive TUI — all menu screens
│   ├── ui.js             Styling helpers (chalk, inquirer wrappers)
│   └── config-store.js   Persistent settings store
├── poller/
│   └── events.js         GitHub Events API poller (ETag, X-Poll-Interval)
├── filters/
│   ├── active-repo.js    Activity filter + priority classification
│   ├── ai-detector.js    AI tool signature detection (20+ signals)
│   └── false-positive.js Path/value filters to suppress noise
├── queue/
│   └── index.js          Priority queue (in-memory or Redis)
├── scanner/
│   ├── engine.js         File tree fetcher + orchestration
│   ├── patterns.js       100+ provider regex patterns
│   ├── pair-matcher.js   AWS/Twilio/Stripe credential pair detection
│   └── context-analyzer.js Variable name + file type scoring
├── history/
│   └── git-history-scanner.js  All branches + diffs + dangling commits
├── search/
│   └── github-search.js  GitHub Code Search proactive discovery
├── validator/
│   └── index.js          Live API validation (12+ providers)
├── notifications/
│   └── index.js          Discord / Slack / Telegram / Webhook
├── reporter/
│   └── index.js          JSON / Markdown / CSV / SARIF reports
├── api/
│   └── server.js         Express REST API + SSE live dashboard
├── db/
│   ├── index.js          PostgreSQL + JSONL fallback
│   └── migrate.js        Schema migration script
├── worker/
│   └── index.js          Full orchestration loop
└── utils/
    ├── entropy.js        Shannon entropy calculator
    ├── github-client.js  Axios + rate-limiting + retry
    ├── hash.js           SHA-256 deduplication
    └── logger.js         Winston logger (file + console)
```

---

## 🔍 Detection Coverage

<details>
<summary><strong>Click to expand — 100+ providers covered</strong></summary>

| Category | Providers |
|----------|-----------|
| **Cloud** | AWS (Access Key + Secret + Session + MWS), GCP (API Key, OAuth, Service Account, Private Key), Azure (Storage Key, SAS, Connection String, Client Secret), Cloudflare, Heroku, Vercel, Netlify |
| **AI** | OpenAI (sk-proj- and legacy format), Anthropic |
| **Payments** | Stripe (live/test/restricted keys), Braintree, PayPal, Coinbase, Binance, Plaid |
| **Messaging** | Slack (bot/user/workspace/webhook), Discord (bot + webhook), Telegram bot token, Twilio (SID + token), SendGrid, Mailgun, Mailchimp, Postmark, Mandrill |
| **DevOps** | GitHub (PAT, OAuth, App, Server tokens), NPM, PyPI, Docker Hub |
| **Databases** | MongoDB Atlas, PostgreSQL, MySQL, Redis, RabbitMQ (all as connection strings) |
| **SaaS** | Shopify (4 token types), Salesforce, HubSpot, Intercom, Zendesk, Jira/Atlassian, Linear, Airtable, Notion, Figma |
| **Analytics** | Datadog, New Relic, Sentry (DSN + token), Amplitude, Segment, Mixpanel |
| **Auth** | Okta, Auth0 |
| **Storage/CDN** | Dropbox, Box, Cloudinary, Mapbox (public + secret), Imgur |
| **CMS** | Contentful, Algolia |
| **Keys** | SSH Private Keys (RSA/EC/DSA/OPENSSH), PGP Private Key Blocks |
| **Generic** | JWT secrets, bearer tokens, high-entropy strings (entropy ≥ 4.0), generic `api_key=` assignments |

</details>

---

## 🛡 False Positive Reduction

Multi-layer filtering keeps noise low:

1. **Path filter** — skips `test/`, `__mocks__/`, `fixtures/`, `.env.example`, `node_modules/`, `dist/`, `vendor/`
2. **Dummy value filter** — rejects `YOUR_API_KEY`, `xxx...`, `<TOKEN>`, `000000...`, repeated chars
3. **Context analyzer** — scores variable names (sensitive: `api_key`, `secret`), rejects comments + documentation files
4. **Pair matching** — AWS key ID + secret in same file = higher confidence
5. **Entropy threshold** — Shannon entropy ≥ 4.0 for generic high-entropy strings

---

## 📋 Reports

Each scanned repo with findings gets reports saved to `./reports/`:

| Format | Filename | Best for |
|--------|----------|---------|
| **JSON** | `owner_repo_DATE.json` | Automation, programmatic use |
| **Markdown** | `owner_repo_DATE.md` | Human review, GitHub issues |
| **CSV** | `owner_repo_DATE.csv` | Spreadsheets, SIEM import |
| **SARIF** | `owner_repo_DATE.sarif.json` | GitHub Advanced Security, VS Code |

---

## 🌐 Web Dashboard

When the scanner is running, open **http://localhost:3000**:

- **Live feed** — real-time SSE stream of every finding as it happens
- **Stats card** — repos scanned, total findings, live secrets
- **Findings table** — filterable by provider, validation status, repo name
- **On-demand scan** — paste any GitHub URL to scan immediately from the browser

---

## ⚠️ Responsible Disclosure

This tool is for **security research and education only**.

- Do **not** access systems using credentials you find
- Do **not** store credentials that belong to others  
- If you find a live secret in a public repo:
  1. Notify the repository owner (open a private vulnerability report)
  2. Contact the credential provider (AWS, OpenAI, Stripe, etc.) to revoke it
- See [SECURITY.md](SECURITY.md) for the full policy

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- How to add new secret patterns
- How to add new provider validators
- How to improve AI signature detection
- Code style and PR process

---

## 📄 License

MIT © [justlurking-around](https://github.com/justlurking-around)

---

<p align="center">
  <sub>Inspired by <a href="https://github.com/trufflesecurity/trufflehog">TruffleHog</a>, <a href="https://github.com/gitleaks/gitleaks">Gitleaks</a>, <a href="https://gitguardian.com">GitGuardian</a>, and <a href="https://neodyme.io/en/blog/github_secrets/">Neodyme's GitHub secrets research</a></sub>
</p>
