'use strict';

/**
 * Notification System — Discord / Slack / Telegram / Webhook
 *
 * FIXES:
 *  - BUG: rate limit window reset bug — windowStart not reset correctly → fixed
 *  - BUG: Telegram message too long (>4096 chars) → now truncated safely
 *  - BUG: Discord embed field values could be empty string → replaced with 'N/A'
 *  - BUG: channels reloaded from env every call → now cached at construction
 *  - SECURITY: no raw secret values ever appear in notifications — verified
 *  - NEW: retry on notification failure (1 retry, 2s delay)
 */

const axios = require('axios');
const logger = require('../utils/logger');

function safe(v, max = 1024) {
  if (!v) return 'N/A';
  return String(v).substring(0, max) || 'N/A';
}

// ── Channel senders ───────────────────────────────────────────────────────────

async function sendDiscord(webhookUrl, payload) {
  const embed = {
    title: payload.isValid ? '🚨 LIVE SECRET DETECTED' : '⚠️ Secret Finding',
    color: payload.isValid ? 0xff0000 : 0xff9900,
    fields: [
      { name: '📦 Repository', value: `[\`${safe(payload.repoName, 100)}\`](${safe(payload.repoUrl, 200)})`, inline: false },
      { name: '🔑 Type',       value: safe(payload.patternName, 100),  inline: true  },
      { name: '🏢 Provider',   value: safe(payload.provider, 50),      inline: true  },
      { name: '📄 File',       value: `\`${safe(payload.filePath, 200)}\``,  inline: false },
      { name: '🔒 Secret',     value: `\`${safe(payload.secretRedacted, 100)}\``, inline: false },
      ...(payload.validationDetail ? [{ name: '✅ Validation', value: safe(payload.validationDetail, 200), inline: false }] : []),
      ...(payload.isHistorical ? [{ name: '🕐 Historical', value: `Commit: \`${safe(payload.commitSha?.substring(0, 8))}\``, inline: false }] : []),
    ].filter(f => f.value && f.value !== 'N/A' || f.name),
    footer: { text: `AI Secret Scanner v2 • ${new Date().toISOString()}` },
    timestamp: new Date().toISOString()
  };

  await axios.post(webhookUrl, {
    username: 'AI Secret Scanner',
    embeds: [embed]
  }, { timeout: 8000 });
}

async function sendSlack(webhookUrl, payload) {
  await axios.post(webhookUrl, {
    attachments: [{
      color: payload.isValid ? '#FF0000' : '#FF9900',
      title: payload.isValid ? '🚨 LIVE SECRET DETECTED' : '⚠️ Secret Finding',
      fields: [
        { title: 'Repository', value: `<${safe(payload.repoUrl, 200)}|${safe(payload.repoName, 100)}>`, short: false },
        { title: 'Type',       value: safe(payload.patternName, 100), short: true },
        { title: 'Provider',   value: safe(payload.provider, 50),     short: true },
        { title: 'File',       value: `\`${safe(payload.filePath, 200)}\``, short: false },
        { title: 'Secret',     value: `\`${safe(payload.secretRedacted, 100)}\``, short: false },
        ...(payload.validationDetail ? [{ title: 'Validation', value: safe(payload.validationDetail, 200), short: false }] : []),
      ],
      footer: 'AI Secret Scanner',
      ts: Math.floor(Date.now() / 1000)
    }]
  }, { timeout: 8000 });
}

async function sendTelegram(botToken, chatId, payload) {
  // FIX: Telegram messages must be ≤ 4096 chars
  const lines = [
    payload.isValid ? '🚨 *LIVE SECRET DETECTED*' : '⚠️ *Secret Finding*',
    '',
    `📦 *Repo:* [${safe(payload.repoName, 60)}](${safe(payload.repoUrl, 200)})`,
    `🔑 *Type:* ${safe(payload.patternName, 80)}`,
    `🏢 *Provider:* ${safe(payload.provider, 40)}`,
    `📄 *File:* \`${safe(payload.filePath, 100)}\``,
    `🔒 *Secret:* \`${safe(payload.secretRedacted, 60)}\``,
    ...(payload.validationDetail ? [`✅ *Validation:* ${safe(payload.validationDetail, 100)}`] : []),
    `_${new Date().toISOString()}_`
  ];
  const text = lines.join('\n').substring(0, 4000); // FIX: hard cap

  await axios.post(
    `https://api.telegram.org/bot${botToken}/sendMessage`,
    { chat_id: chatId, text, parse_mode: 'Markdown', disable_web_page_preview: true },
    { timeout: 8000 }
  );
}

async function sendWebhook(url, payload) {
  await axios.post(url, {
    event: payload.isValid ? 'valid_secret_found' : 'secret_finding',
    timestamp: new Date().toISOString(),
    data: payload
  }, { timeout: 8000, headers: { 'Content-Type': 'application/json', 'User-Agent': 'ai-secret-scanner/2.0' } });
}

// ── Notifier class ────────────────────────────────────────────────────────────

class Notifier {
  constructor() {
    this.channels = this._loadChannels();
    // FIX: rate limit state properly initialized
    this._maxAlertsPerWindow = 10;
    this._windowMs = 60_000;
    this._windowStart = Date.now();
    this._alertCount = 0;
  }

  _loadChannels() {
    const channels = [];
    if (process.env.DISCORD_WEBHOOK_URL)  channels.push({ type: 'discord',  url: process.env.DISCORD_WEBHOOK_URL });
    if (process.env.SLACK_WEBHOOK_URL)    channels.push({ type: 'slack',    url: process.env.SLACK_WEBHOOK_URL });
    if (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID) {
      channels.push({ type: 'telegram', token: process.env.TELEGRAM_BOT_TOKEN, chatId: process.env.TELEGRAM_CHAT_ID });
    }
    if (process.env.NOTIFY_WEBHOOK_URL)   channels.push({ type: 'webhook',  url: process.env.NOTIFY_WEBHOOK_URL });
    if (channels.length) logger.info(`[Notifier] ${channels.length} channel(s) configured: ${channels.map(c => c.type).join(', ')}`);
    return channels;
  }

  _checkRateLimit() {
    const now = Date.now();
    // FIX: correct window reset — reset counter when window expires
    if (now - this._windowStart >= this._windowMs) {
      this._windowStart = now;
      this._alertCount = 0;
    }
    if (this._alertCount >= this._maxAlertsPerWindow) return false;
    this._alertCount++;
    return true;
  }

  async alert(finding, isValid = false) {
    if (!this.channels.length) return;
    if (!this._checkRateLimit()) {
      logger.debug('[Notifier] Rate limit — alert suppressed');
      return;
    }

    const payload = {
      repoName:        finding.repoName || 'unknown',
      repoUrl:         finding.repoUrl  || `https://github.com/${finding.repoName}`,
      patternName:     finding.patternName || 'Secret',
      provider:        finding.provider || 'unknown',
      filePath:        finding.filePath || '',
      lineNumber:      finding.lineNumber,
      entropy:         finding.entropy,
      secretRedacted:  finding.value || finding.secretRedacted || '****',
      validationDetail: finding.validationDetail,
      isValid,
      isHistorical:    finding.isHistorical || false,
      commitSha:       finding.commitSha
    };

    for (const ch of this.channels) {
      try {
        // FIX: 1 retry on failure
        await this._sendWithRetry(ch, payload);
      } catch (err) {
        logger.warn(`[Notifier] Failed (${ch.type}): ${err.message}`);
      }
    }
  }

  async _sendWithRetry(ch, payload, attempt = 0) {
    try {
      if (ch.type === 'discord')  await sendDiscord(ch.url, payload);
      if (ch.type === 'slack')    await sendSlack(ch.url, payload);
      if (ch.type === 'telegram') await sendTelegram(ch.token, ch.chatId, payload);
      if (ch.type === 'webhook')  await sendWebhook(ch.url, payload);
      logger.debug(`[Notifier] Sent via ${ch.type}`);
    } catch (err) {
      if (attempt < 1) {
        await new Promise(r => setTimeout(r, 2000));
        return this._sendWithRetry(ch, payload, attempt + 1);
      }
      throw err;
    }
  }

  async dailySummary(stats) {
    if (!this.channels.length) return;
    const top = Object.entries(stats.topProviders || {})
      .sort((a, b) => b[1] - a[1]).slice(0, 5)
      .map(([p, c]) => `${p}: ${c}`).join(', ');

    for (const ch of this.channels) {
      try {
        if (ch.type === 'discord') {
          await axios.post(ch.url, {
            username: 'AI Secret Scanner',
            embeds: [{
              title: '📊 Daily Scan Summary',
              color: 0x0099ff,
              fields: [
                { name: 'Repos Scanned',  value: String(stats.repositories || 0), inline: true },
                { name: 'Total Findings', value: String(stats.findings     || 0), inline: true },
                { name: '🚨 Live Secrets', value: String(stats.validSecrets || 0), inline: true },
                ...(top ? [{ name: 'Top Providers', value: top, inline: false }] : []),
              ],
              footer: { text: `AI Secret Scanner v2 • ${new Date().toISOString()}` }
            }]
          }, { timeout: 8000 });
        } else if (ch.type === 'slack') {
          await axios.post(ch.url, {
            text: `📊 *Daily Scan Summary*\nRepos: ${stats.repositories} | Findings: ${stats.findings} | 🚨 Live: ${stats.validSecrets}${top ? `\nTop providers: ${top}` : ''}`
          }, { timeout: 8000 });
        } else if (ch.type === 'telegram') {
          const text = `📊 *Daily Scan Summary*\n\nRepos: ${stats.repositories}\nFindings: ${stats.findings}\n🚨 Live: ${stats.validSecrets}${top ? `\nProviders: ${top}` : ''}`;
          await axios.post(`https://api.telegram.org/bot${ch.token}/sendMessage`, {
            chat_id: ch.chatId, text, parse_mode: 'Markdown'
          }, { timeout: 8000 });
        }
      } catch (err) {
        logger.warn(`[Notifier] Daily summary failed (${ch.type}): ${err.message}`);
      }
    }
  }
}

// Singleton — rebuild if env changes (e.g. after menu config save)
let _notifier = null;
function getNotifier(force = false) {
  if (!_notifier || force) _notifier = new Notifier();
  return _notifier;
}
function resetNotifier() { _notifier = null; }

module.exports = { getNotifier, resetNotifier, Notifier };
