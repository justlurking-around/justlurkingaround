'use strict';

/**
 * Interactive Main Menu — Arrow-key navigation
 * Works on Linux · macOS · Windows · Termux (Android)
 */

require('dotenv').config();
const { store, applyToEnv } = require('./config-store');
const { inquirer, banner, section, success, warn, error, info, dim, pause, SEP, DIM } = require('./ui');
const chalk = require('chalk');
const ora   = require('ora');
const path  = require('path');
const fs    = require('fs');

// ── Helpers ───────────────────────────────────────────────────────────────────

function masked(val) {
  if (!val) return chalk.gray('(not set)');
  if (val.length <= 8) return chalk.red('****');
  return chalk.green(val.substring(0, 4) + '****' + val.slice(-4));
}

function yesNo(val) {
  return val ? chalk.green('✔ Yes') : chalk.gray('✖ No');
}

// ── Main Menu ─────────────────────────────────────────────────────────────────

async function mainMenu() {
  applyToEnv();

  // First-run onboarding
  if (!store.get('onboardingDone')) {
    await onboarding();
    store.set('onboardingDone', true);
  }

  while (true) {
    banner();

    const hasToken = !!store.get('githubToken');
    const tokenStatus = hasToken ? chalk.green('● Token Set') : chalk.red('● No Token');

    console.log(chalk.gray(`  Config: ${store.path}`));
    console.log(chalk.gray(`  Status: ${tokenStatus}`));
    console.log('');

    const { choice } = await inquirer.prompt([{
      type: 'list',
      name: 'choice',
      message: chalk.cyan.bold('What do you want to do?'),
      pageSize: 14,
      choices: [
        { name: `${chalk.green('▶')}  Start Real-Time Scanner         ${chalk.gray('(monitors GitHub Events API)')}`, value: 'start' },
        { name: `${chalk.cyan('🔍')} Scan a Specific Repository       ${chalk.gray('(paste any GitHub URL)')}`,        value: 'scan_repo' },
        { name: `${chalk.blue('📊')} View Recent Findings             ${chalk.gray('(from local database)')}`,          value: 'findings' },
        { name: `${chalk.blue('📈')} Scanner Statistics               ${chalk.gray('(totals & summary)')}`,             value: 'stats' },
        new inquirer.Separator(chalk.gray('─── Configuration ─────────────────────────────────')),
        { name: `${chalk.yellow('🔑')} GitHub Token Settings           ${chalk.gray(masked(store.get('githubToken')))}`, value: 'token' },
        { name: `${chalk.magenta('🔔')} Notification Settings           ${chalk.gray('(Discord/Slack/Telegram)')}`,     value: 'notifications' },
        { name: `${chalk.white('⚙️')}  Scanner Settings                ${chalk.gray('(depth, validation, API)')}`,      value: 'settings' },
        { name: `${chalk.cyan('🗄️')}  Database Settings                ${chalk.gray('(PostgreSQL / JSONL)')}`,          value: 'database' },
        new inquirer.Separator(chalk.gray('─── Other ─────────────────────────────────────────')),
        { name: `${chalk.green('✔️')}  Validate a Secret               ${chalk.gray('(test any key live)')}`,           value: 'validate' },
        { name: `${chalk.white('📋')} View Leaked Keys Log             ${chalk.gray('(VALID findings only)')}`,         value: 'leaks' },
        { name: `${chalk.blue('ℹ️')}  About & Help                    ${chalk.gray('(version, links, usage)')}`,        value: 'about' },
        new inquirer.Separator(chalk.gray('───────────────────────────────────────────────────')),
        { name: `${chalk.red('✖')}  Exit`,                                                                              value: 'exit' },
      ]
    }]);

    switch (choice) {
      case 'start':        await menuStart();       break;
      case 'scan_repo':    await menuScanRepo();    break;
      case 'findings':     await menuFindings();    break;
      case 'stats':        await menuStats();       break;
      case 'token':        await menuToken();       break;
      case 'notifications':await menuNotifications();break;
      case 'settings':     await menuSettings();   break;
      case 'database':     await menuDatabase();   break;
      case 'validate':     await menuValidate();   break;
      case 'leaks':        await menuLeaks();       break;
      case 'about':        await menuAbout();       break;
      case 'exit':
        console.log(chalk.cyan('\n  Goodbye! 👋\n'));
        process.exit(0);
    }
  }
}

// ── Onboarding ────────────────────────────────────────────────────────────────

async function onboarding() {
  banner();
  console.log(chalk.cyan.bold('  Welcome to AI Secret Scanner! 🎉'));
  console.log('');
  console.log(chalk.white('  Let\'s get you set up in 60 seconds.'));
  console.log(chalk.gray('  You can change all settings later from the main menu.\n'));

  console.log(chalk.yellow('  Step 1/2 — GitHub Token'));
  console.log(chalk.gray('  Go to: https://github.com/settings/tokens'));
  console.log(chalk.gray('  Generate a new Classic token with public_repo scope.\n'));

  const { token } = await inquirer.prompt([{
    type: 'password',
    name: 'token',
    message: 'Paste your GitHub token (or press Enter to skip):',
    mask: '*',
  }]);

  if (token && token.trim()) {
    store.set('githubToken', token.trim());
    success('GitHub token saved!');
  } else {
    warn('Skipped — you can add a token later from Settings → GitHub Token');
  }

  console.log('');
  console.log(chalk.yellow('  Step 2/2 — Notifications (optional)'));
  const { setupNotif } = await inquirer.prompt([{
    type: 'confirm',
    name: 'setupNotif',
    message: 'Set up Discord/Slack/Telegram notifications now?',
    default: false,
  }]);

  if (setupNotif) await menuNotifications();

  console.log('');
  success('Setup complete! Starting main menu...');
  await new Promise(r => setTimeout(r, 1200));
}

// ── Start Scanner ─────────────────────────────────────────────────────────────

async function menuStart() {
  section('▶  Start Real-Time Scanner');

  const cfg = {
    token:    store.get('githubToken'),
    apiPort:  store.get('apiPort') || 3000,
    validate: store.get('validateSecrets'),
    api:      store.get('enableApi'),
  };

  console.log('');
  console.log(`  GitHub Token   : ${masked(cfg.token)}`);
  console.log(`  Dashboard      : ${cfg.api ? chalk.green(`http://localhost:${cfg.apiPort}`) : chalk.gray('disabled')}`);
  console.log(`  Validation     : ${yesNo(cfg.validate)}`);
  console.log('');

  if (!cfg.token) {
    warn('No GitHub token configured — unauthenticated mode (very slow, 60 req/hr)');
    const { cont } = await inquirer.prompt([{
      type: 'confirm', name: 'cont',
      message: 'Continue without a token?', default: false
    }]);
    if (!cont) return;
  }

  const { confirm } = await inquirer.prompt([{
    type: 'confirm', name: 'confirm',
    message: 'Start scanner now? (runs in foreground, Ctrl+C to stop)',
    default: true
  }]);

  if (!confirm) return;

  applyToEnv();
  console.log('');
  info('Starting worker... Dashboard will be at http://localhost:' + cfg.apiPort);
  console.log(chalk.gray('  Press Ctrl+C to stop.\n'));

  // Hand off to worker
  require('../worker/index');
}

// ── Scan Repo ─────────────────────────────────────────────────────────────────

async function menuScanRepo() {
  section('🔍  Scan a Specific Repository');
  console.log('');

  const { repoUrl } = await inquirer.prompt([{
    type: 'input',
    name: 'repoUrl',
    message: 'Enter GitHub repo URL:',
    validate: v => {
      if (!v.trim()) return 'URL is required';
      if (!v.includes('github.com/')) return 'Must be a GitHub URL (https://github.com/owner/repo)';
      return true;
    }
  }]);

  const { scanMode } = await inquirer.prompt([{
    type: 'list',
    name: 'scanMode',
    message: 'Scan mode:',
    choices: [
      { name: `${chalk.green('Quick')}  — Current HEAD files only         ${chalk.gray('(fast, ~10s)')}`,     value: 'quick' },
      { name: `${chalk.yellow('Deep')}   — All branches + git history      ${chalk.gray('(thorough, ~1min)')}`, value: 'deep' },
      { name: `${chalk.red('Full')}    — Deep + GitHub Code Search        ${chalk.gray('(max coverage)')}`,    value: 'full' },
    ]
  }]);

  const { validate } = await inquirer.prompt([{
    type: 'confirm', name: 'validate',
    message: 'Run live validation against provider APIs?',
    default: store.get('validateSecrets')
  }]);

  const { outputFmt } = await inquirer.prompt([{
    type: 'list',
    name: 'outputFmt',
    message: 'Output format:',
    choices: [
      { name: 'Table (human-readable)',    value: 'table' },
      { name: 'JSON',                      value: 'json'  },
      { name: 'Markdown report + SARIF',   value: 'report'},
    ]
  }]);

  console.log('');
  applyToEnv();
  if (!validate) process.env.VALIDATE_SECRETS = 'false';

  const repoName = repoUrl
    .replace(/https?:\/\/github\.com\//, '')
    .replace(/\.git$/, '').replace(/\/$/, '');

  const spinner = ora({ text: `Scanning ${chalk.cyan(repoName)}...`, color: 'cyan' }).start();

  try {
    const ScannerEngine = require('../scanner/engine');
    const { validateFinding, RESULTS } = require('../validator');
    const GitHistoryScanner = require('../history/git-history-scanner');
    const { annotatePairs } = require('../scanner/pair-matcher');
    const { annotateWithContext } = require('../scanner/context-analyzer');
    const { getDB } = require('../db');
    const { sha256 } = require('../utils/hash');
    const Reporter = require('../reporter');

    const engine = new ScannerEngine();
    spinner.text = 'Scanning HEAD files...';
    let findings = await engine.scanRepo({
      repoName, repoUrl, pushedAt: new Date().toISOString()
    });

    if (scanMode === 'deep' || scanMode === 'full') {
      spinner.text = 'Deep scan: all branches + commit history...';
      const hist = new GitHistoryScanner();
      const histFindings = await hist.deepScan(repoName);
      findings = [
        ...findings.map(f => ({ ...f, repoName })),
        ...histFindings.map(f => ({ ...f, repoName, isHistorical: true }))
      ];
    }

    findings = annotateWithContext(annotatePairs(findings));
    spinner.text = `Validating ${findings.length} findings...`;

    const db = await getDB();
    const results = [];

    for (const f of findings) {
      let validation = { result: 'SKIPPED', detail: 'Validation skipped' };
      if (validate) validation = await validateFinding(f);

      const record = {
        repoName, filePath: f.filePath, patternId: f.patternId,
        patternName: f.patternName, provider: f.provider,
        secretHash: sha256(f.rawValue), value: f.value,
        entropy: f.entropy, lineNumber: f.lineNumber,
        matchContext: f.matchContext,
        validationResult: validation.result,
        validationDetail: validation.detail,
        detectedAt: f.detectedAt,
        isHistorical: f.isHistorical || false
      };
      await db.insertFinding(record);
      results.push({ ...f, ...validation, validationResult: validation.result });
    }

    spinner.stop();

    if (results.length === 0) {
      success(`No secrets found in ${repoName}`);
      await pause();
      return;
    }

    // Output
    if (outputFmt === 'json') {
      console.log(JSON.stringify(results.map(r => ({
        provider: r.provider, patternName: r.patternName,
        filePath: r.filePath, line: r.lineNumber,
        entropy: r.entropy, secret: r.value,
        status: r.validationResult, detail: r.result
      })), null, 2));
    } else if (outputFmt === 'report') {
      const reporter = new Reporter('./reports');
      const paths = await reporter.generateAll({
        repoName, findings: results, scanDate: new Date().toISOString()
      });
      success(`Reports saved:`);
      Object.entries(paths).forEach(([fmt, p]) => dim(`${fmt}: ${p}`));
    } else {
      _printResultsTable(results, repoName);
    }

    const validCount = results.filter(r => r.validationResult === 'VALID').length;
    console.log('');
    if (validCount > 0) {
      console.log(chalk.red.bold(`  🚨  ${validCount} LIVE secret(s) found! Details saved to database.`));
    } else {
      console.log(chalk.yellow(`  ⚠   ${results.length} potential finding(s). None validated as live.`));
    }

  } catch (err) {
    spinner.fail(chalk.red(`Scan failed: ${err.message}`));
    if (process.env.LOG_LEVEL === 'debug') console.error(err.stack);
  }

  console.log('');
  await pause();
}

function _printResultsTable(results, repoName) {
  console.log('');
  console.log(chalk.cyan.bold(`  Results for ${repoName} — ${results.length} findings\n`));
  console.log(
    chalk.bold('  ' +
      'STATUS  '.padEnd(10) +
      'PROVIDER    '.padEnd(14) +
      'PATTERN                  '.padEnd(26) +
      'FILE                          '.padEnd(32) +
      'ENTROPY')
  );
  console.log('  ' + '─'.repeat(90));

  for (const r of results) {
    const statusColor = {
      VALID:   chalk.red.bold, INVALID: chalk.gray,
      ERROR:   chalk.yellow,   SKIPPED: chalk.blue
    }[r.validationResult] || chalk.white;

    const historical = r.isHistorical ? chalk.magenta(' [HIST]') : '';

    console.log('  ' +
      statusColor((r.validationResult || '?').padEnd(10)) +
      chalk.cyan((r.provider || '?').padEnd(14)) +
      chalk.white((r.patternName || '').substring(0,24).padEnd(26)) +
      chalk.gray((r.filePath || '').substring(0,30).padEnd(32)) +
      chalk.yellow(String(r.entropy || '')) +
      historical
    );
  }
}

// ── Findings Viewer ───────────────────────────────────────────────────────────

async function menuFindings() {
  section('📊  Recent Findings');

  const { filter } = await inquirer.prompt([{
    type: 'list',
    name: 'filter',
    message: 'Show findings:',
    choices: [
      { name: `${chalk.red('🚨')} Live (VALID) secrets only`,          value: 'valid'   },
      { name: `${chalk.yellow('⚠')}  All findings (last 50)`,           value: 'all'     },
      { name: `${chalk.blue('📋')} Historical (git history) only`,      value: 'history' },
      { name: `${chalk.cyan('🔍')} Filter by provider`,                 value: 'provider'},
      { name: chalk.gray('← Back'),                                     value: 'back'    },
    ]
  }]);

  if (filter === 'back') return;

  const spinner = ora('Loading findings...').start();
  try {
    const { getDB } = require('../db');
    const db = await getDB();
    let findings = await db.getRecentFindings(200);

    if (filter === 'valid')    findings = findings.filter(f => f.validation_result === 'VALID');
    if (filter === 'history')  findings = findings.filter(f => f.is_historical);

    if (filter === 'provider') {
      spinner.stop();
      const providers = [...new Set(findings.map(f => f.provider).filter(Boolean))];
      if (!providers.length) { warn('No findings yet.'); await pause(); return; }
      const { prov } = await inquirer.prompt([{
        type: 'list', name: 'prov',
        message: 'Select provider:',
        choices: providers.map(p => ({ name: p, value: p }))
      }]);
      findings = findings.filter(f => f.provider === prov);
      spinner.start('Loading...');
    }

    spinner.stop();

    if (!findings.length) {
      warn('No findings match this filter.');
      await pause();
      return;
    }

    console.log('');
    console.log(chalk.cyan.bold(`  ${findings.length} finding(s)\n`));
    console.log(
      chalk.bold('  ' +
        'STATUS    '.padEnd(11) +
        'PROVIDER      '.padEnd(16) +
        'REPO                          '.padEnd(32) +
        'FILE                       '.padEnd(30) +
        'ENTROPY')
    );
    console.log('  ' + '─'.repeat(97));

    for (const f of findings.slice(0, 50)) {
      const status = f.validation_result || '?';
      const statusColor = {
        VALID: chalk.red.bold, INVALID: chalk.gray,
        ERROR: chalk.yellow,   SKIPPED: chalk.blue
      }[status] || chalk.white;

      console.log('  ' +
        statusColor(status.padEnd(11)) +
        chalk.cyan((f.provider || '').padEnd(16)) +
        chalk.white((f.repo_name || '').substring(0,30).padEnd(32)) +
        chalk.gray((f.file_path || '').substring(0,28).padEnd(30)) +
        chalk.yellow(String(f.entropy || ''))
      );
    }

    if (findings.length > 50) {
      dim(`  ...and ${findings.length - 50} more. Use --json flag for full export.`);
    }

  } catch (err) {
    spinner.fail(chalk.red(err.message));
  }

  console.log('');
  await pause();
}

// ── Stats ─────────────────────────────────────────────────────────────────────

async function menuStats() {
  section('📈  Scanner Statistics');
  const spinner = ora('Fetching stats...').start();
  try {
    const { getDB } = require('../db');
    const db = await getDB();
    const stats = await db.getStats();
    spinner.stop();
    console.log('');
    console.log(`  ${chalk.bold('Repositories scanned :')} ${chalk.cyan(stats.repositories)}`);
    console.log(`  ${chalk.bold('Total findings       :')} ${chalk.yellow(stats.findings)}`);
    console.log(`  ${chalk.bold('🚨 Live secrets      :')} ${chalk.red.bold(stats.validSecrets)}`);
    console.log('');
    dim(`  Database: ${process.env.DATABASE_URL ? 'PostgreSQL' : 'JSONL flat-file'}`);
  } catch (err) {
    spinner.fail(chalk.red(err.message));
  }
  console.log('');
  await pause();
}

// ── GitHub Token ──────────────────────────────────────────────────────────────

async function menuToken() {
  while (true) {
    section('🔑  GitHub Token Settings');
    const current = store.get('githubToken');
    console.log('');
    console.log(`  Current token : ${masked(current)}`);
    console.log('');
    console.log(chalk.gray('  Token is stored at: ' + store.path));
    console.log(chalk.gray('  Scopes needed: public_repo (read-only)'));
    console.log(chalk.gray('  Get one at: https://github.com/settings/tokens\n'));

    const { action } = await inquirer.prompt([{
      type: 'list', name: 'action',
      message: 'Token options:',
      choices: [
        { name: `${chalk.green('+')} Add / Update token`,        value: 'set'    },
        { name: `${chalk.blue('?')} Verify current token`,       value: 'verify' },
        { name: `${chalk.red('✖')} Remove token`,               value: 'remove' },
        { name: chalk.gray('← Back'),                            value: 'back'   },
      ]
    }]);

    if (action === 'back') return;

    if (action === 'set') {
      const { token } = await inquirer.prompt([{
        type: 'password', name: 'token',
        message: 'Paste your GitHub Personal Access Token:',
        mask: '*',
        validate: v => v.trim().length > 10 || 'Token looks too short'
      }]);
      store.set('githubToken', token.trim());
      process.env.GITHUB_TOKEN = token.trim();
      success('Token saved!');
    }

    if (action === 'verify') {
      if (!current) { warn('No token set.'); continue; }
      const spinner = ora('Verifying token...').start();
      try {
        const { getClient } = require('../utils/github-client');
        process.env.GITHUB_TOKEN = current;
        const client = require('../utils/github-client').createGitHubClient(current);
        const resp = await client.get('/user');
        spinner.stop();
        success(`Token valid! Logged in as: ${chalk.cyan(resp.data.login)}`);
        dim(`  Rate limit: ${resp.headers['x-ratelimit-remaining']}/${resp.headers['x-ratelimit-limit']} remaining`);
      } catch (err) {
        spinner.fail(chalk.red(`Token invalid: ${err.response?.status === 401 ? 'Unauthorized' : err.message}`));
      }
    }

    if (action === 'remove') {
      const { confirm } = await inquirer.prompt([{
        type: 'confirm', name: 'confirm',
        message: 'Remove the stored GitHub token?', default: false
      }]);
      if (confirm) {
        store.set('githubToken', '');
        process.env.GITHUB_TOKEN = '';
        success('Token removed.');
      }
    }

    await pause();
  }
}

// ── Notifications ─────────────────────────────────────────────────────────────

async function menuNotifications() {
  while (true) {
    section('🔔  Notification Settings');
    console.log('');

    const discord  = store.get('discordWebhookUrl');
    const slack    = store.get('slackWebhookUrl');
    const tgToken  = store.get('telegramBotToken');
    const tgChat   = store.get('telegramChatId');
    const webhook  = store.get('notifyWebhookUrl');

    console.log(`  Discord   : ${masked(discord)}`);
    console.log(`  Slack     : ${masked(slack)}`);
    console.log(`  Telegram  : ${tgToken ? masked(tgToken) + chalk.gray(' / chat: ') + (tgChat || chalk.red('not set')) : chalk.gray('(not set)')}`);
    console.log(`  Webhook   : ${masked(webhook)}`);
    console.log('');

    const { channel } = await inquirer.prompt([{
      type: 'list', name: 'channel',
      message: 'Configure notification channel:',
      choices: [
        { name: `${chalk.magenta('📣')} Discord Webhook`,            value: 'discord'  },
        { name: `${chalk.green('💬')} Slack Webhook`,               value: 'slack'    },
        { name: `${chalk.blue('✈️')}  Telegram Bot`,                value: 'telegram' },
        { name: `${chalk.white('🌐')} Generic Webhook (any URL)`,   value: 'webhook'  },
        { name: `${chalk.yellow('🧪')} Test All Channels`,           value: 'test'     },
        { name: `${chalk.red('✖')}  Clear All Notifications`,      value: 'clear'    },
        { name: chalk.gray('← Back'),                               value: 'back'     },
      ]
    }]);

    if (channel === 'back') return;

    if (channel === 'discord') {
      console.log(chalk.gray('\n  How to get a Discord webhook:'));
      dim('1. Open Discord → right-click a channel → Edit Channel');
      dim('2. Integrations → Webhooks → New Webhook → Copy Webhook URL');
      console.log('');
      const { url } = await inquirer.prompt([{
        type: 'input', name: 'url',
        message: 'Discord Webhook URL (Enter to skip):',
        default: discord || '',
      }]);
      if (url.trim()) { store.set('discordWebhookUrl', url.trim()); success('Discord webhook saved!'); }
    }

    if (channel === 'slack') {
      console.log(chalk.gray('\n  How to get a Slack webhook:'));
      dim('1. Go to https://api.slack.com/messaging/webhooks');
      dim('2. Create app → Activate Incoming Webhooks → Copy URL');
      console.log('');
      const { url } = await inquirer.prompt([{
        type: 'input', name: 'url',
        message: 'Slack Webhook URL (Enter to skip):',
        default: slack || '',
      }]);
      if (url.trim()) { store.set('slackWebhookUrl', url.trim()); success('Slack webhook saved!'); }
    }

    if (channel === 'telegram') {
      console.log(chalk.gray('\n  How to set up Telegram:'));
      dim('1. Message @BotFather → /newbot → get token');
      dim('2. Add bot to group/channel → message it');
      dim('3. Get chat_id via: https://api.telegram.org/bot<TOKEN>/getUpdates');
      console.log('');
      const { tok } = await inquirer.prompt([{
        type: 'password', name: 'tok', mask: '*',
        message: 'Telegram Bot Token (Enter to skip):',
      }]);
      if (tok.trim()) {
        store.set('telegramBotToken', tok.trim());
        const { chatId } = await inquirer.prompt([{
          type: 'input', name: 'chatId',
          message: 'Telegram Chat ID (e.g. -1001234567890):',
          default: tgChat || '',
        }]);
        if (chatId.trim()) store.set('telegramChatId', chatId.trim());
        success('Telegram settings saved!');
      }
    }

    if (channel === 'webhook') {
      const { url } = await inquirer.prompt([{
        type: 'input', name: 'url',
        message: 'Webhook URL (receives JSON POST on each finding):',
        default: webhook || '',
      }]);
      if (url.trim()) { store.set('notifyWebhookUrl', url.trim()); success('Webhook saved!'); }
    }

    if (channel === 'test') {
      applyToEnv();
      const spinner = ora('Sending test alert...').start();
      try {
        const { getNotifier } = require('../notifications');
        const notifier = getNotifier();
        await notifier.alert({
          repoName: 'justlurking-around/test',
          repoUrl: 'https://github.com/justlurking-around/test',
          patternName: 'Test Alert',
          provider: 'test',
          filePath: '.env',
          lineNumber: 1,
          entropy: 4.5,
          value: 'sk-****test****',
          validationDetail: 'This is a test notification'
        }, false);
        spinner.stop();
        success('Test alert sent to all configured channels!');
      } catch (err) {
        spinner.fail(chalk.red(`Test failed: ${err.message}`));
      }
    }

    if (channel === 'clear') {
      const { confirm } = await inquirer.prompt([{
        type: 'confirm', name: 'confirm',
        message: 'Clear ALL notification settings?', default: false
      }]);
      if (confirm) {
        ['discordWebhookUrl','slackWebhookUrl','telegramBotToken','telegramChatId','notifyWebhookUrl']
          .forEach(k => store.set(k, ''));
        success('All notification settings cleared.');
      }
    }

    await pause();
  }
}

// ── Scanner Settings ──────────────────────────────────────────────────────────

async function menuSettings() {
  section('⚙️   Scanner Settings');
  console.log('');

  const current = {
    validateSecrets:     store.get('validateSecrets'),
    enableApi:           store.get('enableApi'),
    apiPort:             store.get('apiPort') || 3000,
    maxCommitsPerBranch: store.get('maxCommitsPerBranch') || 50,
    maxBranches:         store.get('maxBranches') || 10,
    logLevel:            store.get('logLevel') || 'info',
  };

  console.log(`  Validate secrets     : ${yesNo(current.validateSecrets)}`);
  console.log(`  Enable web dashboard : ${yesNo(current.enableApi)}`);
  console.log(`  Dashboard port       : ${chalk.cyan(current.apiPort)}`);
  console.log(`  Max commits/branch   : ${chalk.cyan(current.maxCommitsPerBranch)}`);
  console.log(`  Max branches         : ${chalk.cyan(current.maxBranches)}`);
  console.log(`  Log level            : ${chalk.cyan(current.logLevel)}`);
  console.log('');

  const answers = await inquirer.prompt([
    {
      type: 'confirm', name: 'validateSecrets',
      message: 'Run live API validation when secrets are found?',
      default: current.validateSecrets
    },
    {
      type: 'confirm', name: 'enableApi',
      message: 'Enable web dashboard (http://localhost:PORT)?',
      default: current.enableApi
    },
    {
      type: 'input', name: 'apiPort',
      message: 'Dashboard port:',
      default: String(current.apiPort),
      when: a => a.enableApi,
      validate: v => !isNaN(parseInt(v)) || 'Must be a number'
    },
    {
      type: 'list', name: 'maxCommitsPerBranch',
      message: 'Max commits to scan per branch (git history depth):',
      choices: [
        { name: '20  — Fast',          value: 20  },
        { name: '50  — Balanced',      value: 50  },
        { name: '100 — Thorough',      value: 100 },
        { name: '200 — Deep',          value: 200 },
        { name: '500 — Maximum',       value: 500 },
      ],
      default: [20,50,100,200,500].indexOf(current.maxCommitsPerBranch) || 1
    },
    {
      type: 'list', name: 'maxBranches',
      message: 'Max branches to scan per repo:',
      choices: [
        { name: '5   — Fast',          value: 5   },
        { name: '10  — Balanced',      value: 10  },
        { name: '20  — Thorough',      value: 20  },
        { name: '50  — Maximum',       value: 50  },
      ],
      default: [5,10,20,50].indexOf(current.maxBranches) || 1
    },
    {
      type: 'list', name: 'logLevel',
      message: 'Log level:',
      choices: ['debug','info','warn','error'],
      default: ['debug','info','warn','error'].indexOf(current.logLevel) || 1
    },
  ]);

  Object.entries(answers).forEach(([k, v]) => store.set(k, v));
  applyToEnv();
  success('Settings saved!');
  await pause();
}

// ── Database Settings ─────────────────────────────────────────────────────────

async function menuDatabase() {
  section('🗄️   Database Settings');
  console.log('');

  const current = store.get('databaseUrl');
  console.log(`  Current: ${current ? chalk.green('PostgreSQL') : chalk.cyan('JSONL flat-file (default)')}`);
  if (current) console.log(`  URL: ${masked(current)}`);
  console.log('');
  console.log(chalk.gray('  JSONL (default): Zero config. Saves to ./data/findings.jsonl'));
  console.log(chalk.gray('  PostgreSQL: Full SQL, better for large scans\n'));

  const { dbChoice } = await inquirer.prompt([{
    type: 'list', name: 'dbChoice',
    message: 'Database backend:',
    choices: [
      { name: `${chalk.cyan('📄')} JSONL flat-file ${chalk.gray('(no setup needed, works on Termux)')}`, value: 'jsonl'    },
      { name: `${chalk.green('🐘')} PostgreSQL      ${chalk.gray('(production, requires Postgres)')}`,    value: 'postgres' },
      { name: chalk.gray('← Back'),                                                                      value: 'back'     },
    ]
  }]);

  if (dbChoice === 'back') return;

  if (dbChoice === 'jsonl') {
    store.set('databaseUrl', '');
    process.env.DATABASE_URL = '';
    success('Using JSONL flat-file. Findings saved to ./data/findings.jsonl');
  }

  if (dbChoice === 'postgres') {
    console.log(chalk.gray('\n  Format: postgresql://user:password@host:5432/dbname\n'));
    const { url } = await inquirer.prompt([{
      type: 'input', name: 'url',
      message: 'PostgreSQL connection string:',
      default: current || 'postgresql://postgres:password@localhost:5432/ai_scanner',
    }]);
    if (url.trim()) {
      store.set('databaseUrl', url.trim());
      process.env.DATABASE_URL = url.trim();

      const spinner = ora('Testing connection...').start();
      try {
        const { getDB } = require('../db');
        const db = await getDB();
        const stats = await db.getStats();
        spinner.stop();
        success(`Connected! ${stats.findings} findings in database.`);
      } catch (err) {
        spinner.fail(chalk.red(`Connection failed: ${err.message}`));
        store.set('databaseUrl', '');
      }
    }
  }

  await pause();
}

// ── Validate a Secret ─────────────────────────────────────────────────────────

async function menuValidate() {
  section('✔️   Validate a Secret');
  console.log('');
  console.log(chalk.gray('  Test a known secret against its provider\'s API.\n'));
  console.log(chalk.red('  ⚠  Only test secrets you own. Never store or use secrets you find.\n'));

  const { provider } = await inquirer.prompt([{
    type: 'list', name: 'provider',
    message: 'Select provider:',
    pageSize: 16,
    choices: [
      { name: 'OpenAI',       value: 'openai'    },
      { name: 'Anthropic',    value: 'anthropic' },
      { name: 'GitHub',       value: 'github'    },
      { name: 'Stripe',       value: 'stripe'    },
      { name: 'Slack',        value: 'slack'     },
      { name: 'SendGrid',     value: 'sendgrid'  },
      { name: 'Telegram',     value: 'telegram'  },
      { name: 'Mailgun',      value: 'mailgun'   },
      { name: 'Heroku',       value: 'heroku'    },
      { name: 'NPM',          value: 'npm'       },
      { name: 'Discord',      value: 'discord'   },
      { name: 'AWS',          value: 'aws'       },
      { name: chalk.gray('← Back'), value: 'back' },
    ]
  }]);

  if (provider === 'back') return;

  const { secret } = await inquirer.prompt([{
    type: 'password', name: 'secret', mask: '*',
    message: `Enter the ${provider} secret to test:`,
    validate: v => v.trim().length >= 8 || 'Too short'
  }]);

  let context = {};
  if (provider === 'aws') {
    const { accessKeyId } = await inquirer.prompt([{
      type: 'input', name: 'accessKeyId',
      message: 'AWS Access Key ID (AKIA...):',
    }]);
    context.accessKeyId = accessKeyId.trim();
  }

  const spinner = ora(`Validating against ${provider}...`).start();
  try {
    const { validateFinding, RESULTS } = require('../validator');
    const result = await validateFinding(
      { rawValue: secret.trim(), provider, patternName: 'Manual test' },
      context
    );
    spinner.stop();
    console.log('');
    const color = result.result === RESULTS.VALID ? chalk.red.bold : chalk.green;
    console.log(`  Result  : ${result.result === RESULTS.VALID ? chalk.red.bold('🚨 VALID (live secret!)') : color(result.result)}`);
    console.log(`  Detail  : ${chalk.gray(result.detail)}`);
  } catch (err) {
    spinner.fail(chalk.red(err.message));
  }

  console.log('');
  await pause();
}

// ── Leaked Keys Log ───────────────────────────────────────────────────────────

async function menuLeaks() {
  section('📋  Leaked Keys Log');
  const spinner = ora('Fetching VALID findings...').start();
  try {
    const { getDB } = require('../db');
    const db = await getDB();
    const all = await db.getRecentFindings(500);
    const leaks = all.filter(f => f.validation_result === 'VALID');
    spinner.stop();

    if (!leaks.length) {
      console.log('');
      success('No live secrets found yet. Keep scanning!');
      dim('  Run "Start Real-Time Scanner" or "Scan a Specific Repository"');
      await pause();
      return;
    }

    console.log('');
    console.log(chalk.red.bold(`  🚨  ${leaks.length} live secret(s) found\n`));
    console.log(chalk.bold('  ' +
      'PROVIDER      '.padEnd(16) +
      'PATTERN                    '.padEnd(28) +
      'REPO                          '.padEnd(32) +
      'FILE'
    ));
    console.log('  ' + '─'.repeat(95));

    for (const f of leaks) {
      console.log('  ' +
        chalk.red((f.provider || '').padEnd(16)) +
        chalk.yellow((f.pattern_name || '').substring(0,26).padEnd(28)) +
        chalk.cyan((f.repo_name || '').substring(0,30).padEnd(32)) +
        chalk.gray((f.file_path || '').substring(0, 35))
      );
    }

    console.log('');
    console.log(chalk.red('  ⚠  These are LIVE credentials. Notify the repo owners immediately.'));
    console.log(chalk.gray('  Responsible disclosure: https://github.com/justlurking-around/justlurkingaround/blob/main/SECURITY.md'));

  } catch (err) {
    spinner.fail(chalk.red(err.message));
  }

  console.log('');
  await pause();
}

// ── About ─────────────────────────────────────────────────────────────────────

async function menuAbout() {
  section('ℹ️   About & Help');
  console.log('');
  console.log(chalk.cyan.bold('  AI Secret Scanner v2.0.0'));
  console.log(chalk.gray('  Real-time GitHub Credential Detector'));
  console.log('');
  console.log(chalk.bold('  📦 Repository'));
  console.log(chalk.blue('     https://github.com/justlurking-around/justlurkingaround'));
  console.log('');
  console.log(chalk.bold('  🔍 What it does'));
  dim('  Monitors GitHub Events API in real-time');
  dim('  Detects AI-generated repos (bolt.new, Cursor, Lovable, v0.dev...)');
  dim('  Scans all files + full git history (branches, deleted commits)');
  dim('  Detects secrets with 100+ patterns + Shannon entropy analysis');
  dim('  Validates findings live against provider APIs');
  dim('  Sends alerts via Discord, Slack, Telegram, or webhook');
  console.log('');
  console.log(chalk.bold('  🖥  Platform Support'));
  dim('  Linux (Ubuntu, Arch, Debian, Fedora...)');
  dim('  macOS (Terminal, iTerm2)');
  dim('  Windows (Windows Terminal, PowerShell — NOT cmd.exe or Git Bash)');
  dim('  Android Termux (non-root and root)');
  console.log('');
  console.log(chalk.bold('  ⌨️  CLI Commands (non-interactive)'));
  dim('  ai-scanner scan repo <url>  — scan a single repo');
  dim('  ai-scanner scan global      — start global real-time scanner');
  dim('  ai-scanner findings         — show recent findings');
  dim('  ai-scanner stats            — show database stats');
  dim('  ai-scanner validate <key>   — validate a specific secret');
  console.log('');
  console.log(chalk.bold('  📖 Config file location'));
  const { store } = require('./config-store');
  dim(`  ${store.path}`);
  console.log('');
  console.log(chalk.bold('  🔐 Security Policy'));
  dim('  Only scan repos you own or have permission to test.');
  dim('  See SECURITY.md for responsible disclosure guidelines.');
  console.log('');
  console.log(chalk.bold('  📄 License : MIT'));
  console.log(chalk.bold('  👤 Author  : justlurking-around'));
  console.log('');

  await pause();
}

module.exports = { mainMenu };
