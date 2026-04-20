# 🔍 AI-Generated GitHub Secret Scanner

> Real-time scanner that monitors GitHub for AI-generated repositories and scans them for exposed secrets — API keys, tokens, credentials — with live validation.

[![Node.js](https://img.shields.io/badge/node-%3E%3D16-brightgreen)](https://nodejs.org) [![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE) [![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Termux-lightgrey)](#installation)

---

## Why This Exists

AI coding tools (bolt.new, Lovable, Cursor, v0.dev, Replit Agent) are generating thousands of repos daily. Many of them ship with `.env` files, hardcoded API keys, and database credentials committed to public GitHub — because the AI generated the code with the credentials already baked in, and the developer never noticed.

This scanner catches them in real-time.

---

## Features

| Feature | Details |
|---------|---------|
| **Real-time polling** | GitHub Events API with ETag + X-Poll-Interval |
| **AI repo detection** | 20+ signals: `.cursorrules`, `CLAUDE.md`, bolt.new, lovable, v0.dev, Replit Agent, Cursor... |
| **Surface scan** | Current HEAD — all scannable files, filtered for false positives |
| **Deep history scan** | ALL branches + full commit history + dangling commits from force-pushes |
| **Secret patterns** | 100+ named patterns + Shannon entropy ≥ 4.0 for unknown secrets |
| **Live validation** | Tests secrets against real provider APIs |
| **Pair matching** | AWS key+secret, Twilio SID+token — reduces false positives |
| **Context scoring** | Variable name + file type + assignment context analysis |
| **Priority queue** | 1/5/10/25 min intervals based on activity |
| **Proactive search** | GitHub Code Search for known secret patterns in recent repos |
| **Notifications** | Discord, Slack, Telegram, Generic Webhook |
| **Reports** | JSON, Markdown, CSV, SARIF (GitHub Advanced Security compatible) |
| **Web dashboard** | Real-time SSE feed, findings table, on-demand scan |
| **REST API** | `/api/stats`, `/api/findings`, `/api/scan`, `/api/live` |
| **Dual database** | PostgreSQL or JSONL flat-file (no setup needed) |
| **Cross-platform** | Linux, macOS, Windows, Termux (Android) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Worker (Orchestrator)                     │
├──────────────┬──────────────┬───────────────┬───────────────┤
│ Events Poller│ Search Scanner│  Queue        │  API Server   │
│ (real-time)  │ (proactive)   │  (priority)   │  (dashboard)  │
└──────┬───────┴──────┬────────┴───────┬───────┴───────┬───────┘
       │              │                │               │
       ▼              ▼                ▼               ▼
┌─────────────────────────────────────────────────────────────┐
│              Scanner Engine (per repo)                       │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐ │
│  │ Surface Scan │  │ History Scan │  │  AI Detector       │ │
│  │ (HEAD files) │  │ (all branches│  │  (20+ signals)     │ │
│  │              │  │  + diffs +   │  │                    │ │
│  │              │  │  dangling)   │  │                    │ │
│  └──────┬───────┘  └──────┬───────┘  └────────────────────┘ │
│         └─────────────────┘                                   │
│                    ▼                                          │
│         ┌──────────────────────┐                            │
│         │  Pattern + Entropy   │ ← 100+ providers            │
│         │  Pair Matcher        │ ← AWS, Twilio, etc.          │
│         │  Context Analyzer    │ ← variable names, file type  │
│         │  False Positive Filter│                            │
│         └──────────┬───────────┘                            │
│                    ▼                                          │
│         ┌──────────────────────┐                            │
│         │  Validation Engine   │ ← live API calls            │
│         │  (12+ providers)     │                            │
│         └──────────┬───────────┘                            │
└────────────────────┼────────────────────────────────────────┘
                     ▼
       ┌─────────────────────────────┐
       │  Database  │  Notifier  │  Reporter  │
       │ (PG/JSONL) │ (Discord/  │ (JSON/MD/  │
       │            │  Slack/TG) │  CSV/SARIF)│
       └─────────────────────────────┘
```

---

## Installation

### Linux / macOS

```bash
git clone https://github.com/justlurking-around/justlurkingaround.git
cd justlurkingaround
npm install
cp .env.defaults .env
# Edit .env — add your GITHUB_TOKEN
npm start
```

### Windows

```powershell
git clone https://github.com/justlurking-around/justlurkingaround.git
cd justlurkingaround
npm install
copy .env.defaults .env
# Edit .env in Notepad — add GITHUB_TOKEN
npm start
```

### Termux (Android)

```bash
pkg update && pkg install nodejs git
git clone https://github.com/justlurking-around/justlurkingaround.git
cd justlurkingaround
npm install
cp .env.defaults .env
nano .env          # add GITHUB_TOKEN
npm start
```

---

## Quick Start

### 1. Get a GitHub Token

Go to https://github.com/settings/tokens → Generate new token (classic)  
Scope needed: `public_repo` (read-only is fine)

### 2. Configure

```bash
cp .env.defaults .env
```

Minimum config in `.env`:
```
GITHUB_TOKEN=ghp_your_token_here
```

### 3. Start

```bash
# Start the worker + dashboard
npm start

# Dashboard: http://localhost:3000
# Logs:      ./logs/scanner.log
# Reports:   ./reports/
```

---

## CLI Usage

```bash
# Install CLI globally
npm install -g .

# Scan a specific repository (deep scan: surface + history)
ai-scanner scan repo https://github.com/owner/repo

# Scan with JSON output
ai-scanner scan repo https://github.com/owner/repo --json

# Start global real-time scanner
ai-scanner scan global

# View recent findings
ai-scanner findings --limit 50

# Only show live validated secrets
ai-scanner findings --valid-only

# Database statistics
ai-scanner stats

# Validate a specific secret manually
ai-scanner validate "sk-proj-abc123" --provider openai
ai-scanner validate "ghp_abc123" --provider github
```

---

## Configuration

All settings via `.env` file:

### Required
| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub PAT with `public_repo` scope |

### Database (optional — JSONL fallback if not set)
| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | PostgreSQL connection string |
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_NAME` | `ai_scanner` | Database name |

### Notifications (optional)
| Variable | Description |
|----------|-------------|
| `DISCORD_WEBHOOK_URL` | Discord channel webhook URL |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token |
| `TELEGRAM_CHAT_ID` | Telegram chat/channel ID |
| `NOTIFY_WEBHOOK_URL` | Generic webhook for any service |

### Scanner Behavior
| Variable | Default | Description |
|----------|---------|-------------|
| `VALIDATE_SECRETS` | `true` | Run live API validation |
| `ENABLE_API` | `true` | Enable web dashboard |
| `API_PORT` | `3000` | Dashboard port |
| `MAX_COMMITS_PER_BRANCH` | `50` | Git history depth |
| `MAX_BRANCHES` | `10` | Branches to scan per repo |
| `LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` |

---

## Detection Providers (100+ patterns)

<details>
<summary>Click to expand full provider list</summary>

| Category | Providers |
|----------|-----------|
| **Cloud** | AWS (Access Key, Secret, Session Token, MWS), GCP (API Key, OAuth, Service Account, Private Key), Azure (Storage, SAS, Connection String, Client Secret), Cloudflare, Heroku, Vercel, Netlify |
| **AI** | OpenAI (sk-proj, sk-..T3BlbkFJ), Anthropic, Firebase |
| **Payments** | Stripe (live/test/restricted), Braintree, PayPal, Coinbase, Binance, Plaid |
| **Messaging** | Slack (bot/user/workspace/webhook), Discord (bot/webhook), Telegram, Twilio, SendGrid, Mailgun, Mailchimp, Postmark, Mandrill, Pushover |
| **DevOps** | GitHub (PAT, OAuth, App, Server tokens), NPM, PyPI, Docker Hub |
| **Databases** | MongoDB (Atlas connection string), PostgreSQL, MySQL, Redis, RabbitMQ |
| **SaaS** | Shopify (4 token types), Salesforce, HubSpot, Intercom, Zendesk, Jira/Atlassian, Linear, Airtable, Notion, Figma |
| **Analytics** | Datadog, New Relic, Sentry (DSN), Amplitude, Segment, Mixpanel |
| **Auth** | Okta, Auth0 |
| **Storage** | Dropbox, Box, Cloudinary, AWS S3 |
| **Maps** | Mapbox, Google Maps |
| **Search** | Algolia, Elasticsearch |
| **CMS** | Contentful |
| **Keys** | SSH Private Keys (RSA/EC/DSA/OPENSSH), PGP Private Key Blocks |
| **Generic** | JWT secrets, high-entropy strings, generic API keys, bearer tokens |

</details>

---

## Deep Scan — What It Covers

Unlike basic scanners that only look at the current HEAD, this tool goes deeper:

1. **All branches** — not just `main`/`master`
2. **Full commit history** — every commit, not just recent
3. **Diff analysis** — scans only *added* lines (what was introduced)
4. **Dangling commits** — commits force-pushed over but still accessible via GitHub's event API
5. **Deleted files** — secrets in files that no longer exist in HEAD

This matches techniques used by TruffleHog v3 and Neodyme's research on hidden GitHub commits.

---

## False Positive Reduction

Multi-layer FP filtering:
1. **Path filter** — skips `test/`, `mock/`, `fixtures/`, `.env.example`, `node_modules/`, `dist/`
2. **Dummy value filter** — skips `YOUR_API_KEY`, `xxx...`, `<TOKEN>`, `0000...`
3. **Context analyzer** — variable name analysis (not a label/comment/description)
4. **Pair matching** — AWS key+secret together = higher confidence
5. **Entropy threshold** — Shannon entropy ≥ 4.0 for generic strings

---

## Reports

Each scanned repo with findings gets reports in `./reports/`:

| Format | File | Use |
|--------|------|-----|
| JSON | `*.json` | Machine-readable, full detail |
| Markdown | `*.md` | Human-readable, GitHub-ready |
| CSV | `*.csv` | Import to spreadsheets/SIEM |
| SARIF | `*.sarif.json` | GitHub Advanced Security, VS Code, CI |

---

## Web Dashboard

Start the scanner and open http://localhost:3000:

- **Live feed** — real-time SSE stream of new findings
- **Stats** — repos scanned, total findings, live secrets
- **Findings table** — filterable by provider, status, repo
- **On-demand scan** — paste any GitHub URL to scan immediately

---

## Responsible Disclosure

This tool is for **security research and education only**.

- Do not use to access systems you don't own
- Do not store credentials you discover
- If you find a live secret in the wild: notify the repo owner and provider
- See [SECURITY.md](SECURITY.md) for full responsible disclosure policy

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — we welcome:
- New provider patterns
- New validators
- AI signature improvements
- Bug fixes

---

## License

MIT © [justlurking-around](https://github.com/justlurking-around)

---

*Inspired by TruffleHog, Gitleaks, GitGuardian, and Neodyme's GitHub secrets research.*
