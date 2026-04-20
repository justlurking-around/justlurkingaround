'use strict';

/**
 * Persistent config store for the CLI
 * Saves to ~/.config/ai-secret-scanner/config.json
 * Works on Linux, macOS, Windows, Termux
 */

const _cs = require('configstore');
const Configstore = _cs.default || _cs;
const pkg = require('../../package.json');

const store = new Configstore(pkg.name, {
  githubToken: '',
  discordWebhookUrl: '',
  slackWebhookUrl: '',
  telegramBotToken: '',
  telegramChatId: '',
  notifyWebhookUrl: '',
  validateSecrets: true,
  enableApi: true,
  apiPort: 3000,
  maxCommitsPerBranch: 50,
  maxBranches: 10,
  logLevel: 'info',
  databaseUrl: '',
  onboardingDone: false
});

/**
 * Apply stored config to process.env so the rest of the app picks it up
 */
function applyToEnv() {
  const map = {
    githubToken:          'GITHUB_TOKEN',
    discordWebhookUrl:    'DISCORD_WEBHOOK_URL',
    slackWebhookUrl:      'SLACK_WEBHOOK_URL',
    telegramBotToken:     'TELEGRAM_BOT_TOKEN',
    telegramChatId:       'TELEGRAM_CHAT_ID',
    notifyWebhookUrl:     'NOTIFY_WEBHOOK_URL',
    validateSecrets:      'VALIDATE_SECRETS',
    enableApi:            'ENABLE_API',
    apiPort:              'API_PORT',
    maxCommitsPerBranch:  'MAX_COMMITS_PER_BRANCH',
    maxBranches:          'MAX_BRANCHES',
    logLevel:             'LOG_LEVEL',
    databaseUrl:          'DATABASE_URL',
  };

  for (const [key, envKey] of Object.entries(map)) {
    const val = store.get(key);
    if (val !== undefined && val !== '' && val !== null) {
      process.env[envKey] = String(val);
    }
  }

  // Env vars always override stored config
  // (so .env file / manual env vars still work)
}

/**
 * Call after saving config changes to hot-reload singletons
 * (GitHub client, notifier, DB) so the new settings take effect
 * without restarting the process.
 */
function reloadSingletons() {
  try { require('../utils/github-client').resetClient(); } catch {}
  try { require('../notifications').resetNotifier(); } catch {}
  try { require('../db').resetDB(); } catch {}
}

module.exports = { store, applyToEnv, reloadSingletons };
