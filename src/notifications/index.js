'use strict';

/**
 * DAY 3 — Notification System
 *
 * Sends alerts when VALID secrets are found.
 * Supports: Discord, Slack, Telegram, Generic Webhook
 * Configure via environment variables.
 *
 * VALID finding → immediate alert (all configured channels)
 * Daily summary → digest of all findings
 */

const axios = require('axios');
const logger = require('../utils/logger');

// ─── Channel implementations ──────────────────────────────────────────────────

async function sendDiscord(webhookUrl, payload) {
  const embed = {
    title: payload.isValid
      ? '🚨 LIVE SECRET DETECTED'
      : '⚠️ Secret Finding',
    color: payload.isValid ? 0xff0000 : 0xff9900,
    fields: [
      { name: '📦 Repository',  value: `[\`${payload.repoName}\`](${payload.repoUrl})`, inline: false },
      { name: '🔑 Type',        value: payload.patternName, inline: true },
      { name: '🏢 Provider',    value: payload.provider,    inline: true },
      { name: '📄 File',        value: `\`${payload.filePath}\``, inline: false },
      { name: '🔢 Line',        value: String(payload.lineNumber || '?'), inline: true },
      { name: '📊 Entropy',     value: String(payload.entropy || '?'), inline: true },
      { name: '🔒 Secret',      value: `\`${payload.secretRedacted}\``, inline: false },
      ...(payload.validationDetail ? [{ name: '✅ Validation', value: payload.validationDetail, inline: false }] : []),
      ...(payload.isHistorical ? [{ name: '🕐 Historical', value: `Found in git history (commit: \`${payload.commitSha?.substring(0,8)}\`)`, inline: false }] : []),
    ],
    footer: { text: `AI Secret Scanner • ${new Date().toISOString()}` },
    timestamp: new Date().toISOString()
  };

  await axios.post(webhookUrl, {
    username: 'AI Secret Scanner',
    avatar_url: 'https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png',
    embeds: [embed]
  });
}

async function sendSlack(webhookUrl, payload) {
  const color = payload.isValid ? '#FF0000' : '#FF9900';
  const title = payload.isValid ? '🚨 LIVE SECRET DETECTED' : '⚠️ Secret Finding';

  await axios.post(webhookUrl, {
    attachments: [{
      color,
      title,
      fields: [
        { title: 'Repository', value: `<${payload.repoUrl}|${payload.repoName}>`, short: false },
        { title: 'Type', value: payload.patternName, short: true },
        { title: 'Provider', value: payload.provider, short: true },
        { title: 'File', value: `\`${payload.filePath}\``, short: false },
        { title: 'Secret (redacted)', value: `\`${payload.secretRedacted}\``, short: false },
        ...(payload.validationDetail ? [{ title: 'Validation', value: payload.validationDetail, short: false }] : []),
      ],
      footer: 'AI Secret Scanner',
      ts: Math.floor(Date.now() / 1000)
    }]
  });
}

async function sendTelegram(botToken, chatId, payload) {
  const status = payload.isValid ? '🚨 *LIVE SECRET DETECTED*' : '⚠️ *Secret Finding*';
  const text = [
    status,
    '',
    `📦 *Repo:* [${payload.repoName}](${payload.repoUrl})`,
    `🔑 *Type:* ${payload.patternName}`,
    `🏢 *Provider:* ${payload.provider}`,
    `📄 *File:* \`${payload.filePath}\``,
    `🔒 *Secret:* \`${payload.secretRedacted}\``,
    ...(payload.validationDetail ? [`✅ *Validation:* ${payload.validationDetail}`] : []),
    `📊 *Entropy:* ${payload.entropy}`,
    '',
    `_${new Date().toISOString()}_`
  ].join('\n');

  await axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    chat_id: chatId,
    text,
    parse_mode: 'Markdown',
    disable_web_page_preview: true
  });
}

async function sendWebhook(url, payload) {
  await axios.post(url, {
    event: payload.isValid ? 'valid_secret_found' : 'secret_finding',
    timestamp: new Date().toISOString(),
    data: payload
  }, {
    headers: { 'Content-Type': 'application/json', 'User-Agent': 'ai-secret-scanner/1.0' }
  });
}

// ─── Notifier class ───────────────────────────────────────────────────────────

class Notifier {
  constructor() {
    this.channels = this._loadChannels();
    this._alertCount = 0;
    this._rateLimitWindow = 60_000; // max alerts per minute
    this._maxAlertsPerWindow = 10;
    this._windowStart = Date.now();
  }

  _loadChannels() {
    const channels = [];

    if (process.env.DISCORD_WEBHOOK_URL) {
      channels.push({ type: 'discord', url: process.env.DISCORD_WEBHOOK_URL });
      logger.info('[Notifier] Discord webhook configured');
    }
    if (process.env.SLACK_WEBHOOK_URL) {
      channels.push({ type: 'slack', url: process.env.SLACK_WEBHOOK_URL });
      logger.info('[Notifier] Slack webhook configured');
    }
    if (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID) {
      channels.push({
        type: 'telegram',
        token: process.env.TELEGRAM_BOT_TOKEN,
        chatId: process.env.TELEGRAM_CHAT_ID
      });
      logger.info('[Notifier] Telegram bot configured');
    }
    if (process.env.NOTIFY_WEBHOOK_URL) {
      channels.push({ type: 'webhook', url: process.env.NOTIFY_WEBHOOK_URL });
      logger.info('[Notifier] Generic webhook configured');
    }

    if (channels.length === 0) {
      logger.debug('[Notifier] No notification channels configured');
    }

    return channels;
  }

  /**
   * Send a finding alert to all configured channels
   * @param {object} finding - enriched finding object
   * @param {boolean} isValid - whether secret is live/validated
   */
  async alert(finding, isValid = false) {
    if (this.channels.length === 0) return;

    // Rate limiting: don't flood channels
    const now = Date.now();
    if (now - this._windowStart > this._rateLimitWindow) {
      this._windowStart = now;
      this._alertCount = 0;
    }
    if (this._alertCount >= this._maxAlertsPerWindow) {
      logger.debug('[Notifier] Rate limit hit — skipping notification');
      return;
    }
    this._alertCount++;

    const payload = {
      repoName:        finding.repoName || 'unknown',
      repoUrl:         finding.repoUrl || `https://github.com/${finding.repoName}`,
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

    for (const channel of this.channels) {
      try {
        if (channel.type === 'discord') await sendDiscord(channel.url, payload);
        else if (channel.type === 'slack')   await sendSlack(channel.url, payload);
        else if (channel.type === 'telegram') await sendTelegram(channel.token, channel.chatId, payload);
        else if (channel.type === 'webhook') await sendWebhook(channel.url, payload);

        logger.debug(`[Notifier] Alert sent via ${channel.type}`);
      } catch (err) {
        logger.warn(`[Notifier] Failed to send via ${channel.type}: ${err.message}`);
      }
    }
  }

  /**
   * Send a daily summary digest
   * @param {object} stats - { repos, findings, valid, topProviders }
   */
  async dailySummary(stats) {
    if (this.channels.length === 0) return;

    const topProvidersText = Object.entries(stats.topProviders || {})
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([p, c]) => `${p}: ${c}`)
      .join(', ');

    const payload = {
      title: '📊 Daily Scan Summary',
      stats,
      topProvidersText,
      timestamp: new Date().toISOString()
    };

    for (const channel of this.channels) {
      try {
        if (channel.type === 'discord') {
          await axios.post(channel.url, {
            username: 'AI Secret Scanner',
            embeds: [{
              title: '📊 Daily Scan Summary',
              color: 0x0099ff,
              fields: [
                { name: 'Repos Scanned',   value: String(stats.repositories || 0), inline: true },
                { name: 'Total Findings',  value: String(stats.findings || 0),     inline: true },
                { name: '🚨 Live Secrets', value: String(stats.validSecrets || 0), inline: true },
                ...(topProvidersText ? [{ name: 'Top Providers', value: topProvidersText }] : []),
              ],
              footer: { text: `AI Secret Scanner • ${payload.timestamp}` }
            }]
          });
        } else if (channel.type === 'slack') {
          await axios.post(channel.url, {
            text: `📊 *Daily Scan Summary*\nRepos: ${stats.repositories} | Findings: ${stats.findings} | 🚨 Live: ${stats.validSecrets}\n${topProvidersText ? `Top providers: ${topProvidersText}` : ''}`
          });
        } else if (channel.type === 'telegram') {
          await axios.post(`https://api.telegram.org/bot${channel.token}/sendMessage`, {
            chat_id: channel.chatId,
            text: `📊 *Daily Scan Summary*\n\nRepos: ${stats.repositories}\nFindings: ${stats.findings}\n🚨 Live Secrets: ${stats.validSecrets}\n${topProvidersText ? `Top providers: ${topProvidersText}` : ''}`,
            parse_mode: 'Markdown'
          });
        }
      } catch (err) {
        logger.warn(`[Notifier] Daily summary failed via ${channel.type}: ${err.message}`);
      }
    }
  }
}

// Singleton
let _notifier = null;
function getNotifier() {
  if (!_notifier) _notifier = new Notifier();
  return _notifier;
}

module.exports = { getNotifier, Notifier };
