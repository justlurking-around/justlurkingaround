# 🔍 AI-Generated GitHub Secret Scanner

Real-time scanner that monitors the GitHub Events API, detects AI-generated repositories, and scans them for exposed secrets (API keys, tokens, credentials).

![Node.js](https://img.shields.io/badge/node-%3E%3D16-brightgreen) ![License](https://img.shields.io/badge/license-MIT-blue) ![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Termux-lightgrey)

---

## Features

- **Real-time polling** — GitHub Events API with ETag caching + X-Poll-Interval respect  
- **AI repo detection** — `.cursorrules`, `CLAUDE.md`, bolt.new, lovable, v0.dev, Replit Agent and 20+ more signals  
- **500+ secret patterns** — AWS, OpenAI, Stripe, GitHub, Slack, GCP, Azure, Discord, Telegram, and 80+ providers  
- **Entropy analysis** — Shannon entropy ≥ 4.0 catches secrets missed by regex  
- **Live validation** — Tests secrets against real APIs (OpenAI, GitHub, Stripe, Slack, Telegram, etc.)  
- **Deduplication** — SHA-256 hashing prevents rescanning identical files  
- **Priority queue** — 1/5/10/25 min intervals based on repo activity  
- **Dual database** — PostgreSQL for production, JSONL flat-file fallback (works on Termux)  
- **Cross-platform CLI** — Linux, macOS, Windows, Termux (Android)  
- **No mock data** — 100% real GitHub live data only

---

## Architecture

```
src/
├── poller/       # GitHub Events API poller (ETag, X-Poll-Interval)
├── filters/      # Active-repo filter, AI detector, false-positive filter
├── queue/        # Priority queue (in-memory or Redis)
├── scanner/      # File tree fetcher, regex patterns, entropy analysis
├── validator/    # Live API validation per provider
├── db/           # PostgreSQL + JSONL fallback
├── worker/       # Orchestration loop (background runner)
└── cli/          # CLI tool (scan/stats/findings/validate)
```

---

## Quick Start

### Prerequisites

- Node.js ≥ 16
- GitHub Personal Access Token ([create one](https://github.com/settings/tokens) — `public_repo` scope only)
- Optional: PostgreSQL, Redis

### Install

```bash
# Clone
git clone https://github.com/justlurking-around/justlurkingaround.git
cd justlurkingaround

# Install dependencies
npm install

# Configure
cp .env.defaults .env
# Edit .env and set GITHUB_TOKEN=ghp_your_token_here
```

### Termux (Android)

```bash
pkg update && pkg install nodejs git
git clone https://github.com/justlurking-around/justlurkingaround.git
cd justlurkingaround
npm install
cp .env.defaults .env
nano .env   # set GITHUB_TOKEN
npm start
```

---

## Usage

### Start real-time global scanner

```bash
npm start
# or
node src/worker/index.js
# or with token inline
GITHUB_TOKEN=ghp_xxx npm start
```

### CLI tool

```bash
# Install globally
npm install -g .

# Scan a specific repo
ai-scanner scan repo https://github.com/owner/repo

# Start global real-time scanner
ai-scanner scan global

# View recent findings
ai-scanner findings --limit 50

# Show only live (validated) secrets
ai-scanner findings --valid-only

# Database stats
ai-scanner stats

# Validate a secret manually
ai-scanner validate sk-proj-abcd1234 --provider openai

# JSON output
ai-scanner scan repo https://github.com/owner/repo --json
```

---

## Configuration

All config via environment variables (`.env` file):

| Variable | Default | Description |
|---|---|---|
| `GITHUB_TOKEN` | *(required)* | GitHub PAT — `public_repo` scope |
| `DATABASE_URL` | *(optional)* | PostgreSQL connection string |
| `USE_REDIS` | `false` | Use Redis for queue |
| `REDIS_URL` | `redis://localhost:6379` | Redis URL |
| `VALIDATE_SECRETS` | `true` | Run live API validation |
| `LOG_LEVEL` | `info` | debug / info / warn / error |
| `LOG_DIR` | `./logs` | Log file directory |

---

## Secret Patterns (500+)

Provider categories:

| Category | Providers |
|---|---|
| Cloud | AWS, GCP, Azure, Cloudflare, Heroku, Vercel, Netlify |
| AI | OpenAI, Anthropic |
| Payments | Stripe, Braintree, PayPal, Coinbase, Binance |
| Messaging | Slack, Discord, Telegram, Twilio, SendGrid, Mailgun |
| DevOps | GitHub, NPM, PyPI, Docker Hub, CircleCI |
| DB/Infra | MongoDB, PostgreSQL, MySQL, Redis, RabbitMQ |
| SaaS | Shopify, Salesforce, HubSpot, Intercom, Zendesk, Jira |
| Analytics | Datadog, New Relic, Sentry, Amplitude, Segment, Mixpanel |
| Auth | Okta, Auth0 |
| Other | Airtable, Notion, Figma, Algolia, Contentful, Mapbox... |

Plus: SSH private keys, PGP blocks, JWT secrets, generic high-entropy analysis.

---

## Validation

Secrets are validated live against provider APIs:

| Provider | Endpoint |
|---|---|
| OpenAI | `GET /v1/models` |
| Anthropic | `GET /v1/models` |
| GitHub | `GET /user` |
| Stripe | `GET /v1/charges` |
| Slack | `POST /api/auth.test` |
| SendGrid | `GET /v3/user/account` |
| Telegram | `GET /bot{token}/getMe` |
| Mailgun | `GET /v3/domains` |
| Heroku | `GET /account` |
| NPM | `GET /-/whoami` |
| Discord | `GET /api/v10/users/@me` |
| AWS | STS `GetCallerIdentity` |

---

## Database

### PostgreSQL (production)
```sql
-- repositories table: tracks every scanned repo
-- findings table: every detected secret with validation status
```
Run migrations:
```bash
npm run setup-db
```

### JSONL fallback (no Postgres needed)
When `DATABASE_URL` is not set, findings are saved to `./data/findings.jsonl` — works on Termux and local machines with no setup.

---

## False Positive Filtering

Automatically skips:
- Test files (`*.test.js`, `*.spec.ts`, `__tests__/`)
- Mock/fixture/sample/dummy data files
- `.env.example`, `.env.sample`, `.env.template`
- `node_modules/`, `vendor/`, `dist/`, `build/`
- Binary files (images, archives, PDFs)
- Placeholder values (`YOUR_API_KEY`, `xxx...`, `<TOKEN>`)

---

## Disclaimer

This tool is for **security research and educational purposes only**. Do not use to access, store, or exploit credentials you do not own. Always follow responsible disclosure practices. The author is not responsible for misuse.

---

## License

MIT © justlurking-around
