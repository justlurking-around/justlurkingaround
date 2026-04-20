'use strict';

/**
 * Interactive Main Menu
 *
 * Termux-safe design:
 *  - Menu choice names kept ≤ 52 chars (fits 80-col terminal)
 *  - No inline long trailing comments on choice lines
 *  - Table columns sized to ≤ 78 chars total
 *  - Emoji only in safe positions (start of string, not inside padding)
 *  - console.clear() before each menu redraw
 */

require('dotenv').config();
const { store, applyToEnv, reloadSingletons } = require('./config-store');
const {
  inquirer, banner, section, success, warn, error, info,
  dim, pause, printTable, SEP, DIM
} = require('./ui');
const chalk = require('chalk');
const ora   = require('ora');

// ── Helpers ───────────────────────────────────────────────────────────────────

function masked(val) {
  if (!val) return chalk.gray('(not set)');
  const s = String(val);
  if (s.length <= 8) return chalk.red('****');
  return chalk.green(s.substring(0, 4) + '****' + s.slice(-4));
}
function yesNo(val) { return val ? chalk.green('Yes') : chalk.gray('No'); }
function trunc(s, n) { if (!s) return ''; return s.length > n ? s.substring(0, n - 1) + '…' : s; }

// ── Main Menu ─────────────────────────────────────────────────────────────────

async function mainMenu() {
  applyToEnv();
  if (!store.get('onboardingDone')) {
    await onboarding();
    store.set('onboardingDone', true);
  }

  while (true) {
    banner();

    const hasToken = !!store.get('githubToken');
    console.log(chalk.gray(`  Token : ${hasToken ? chalk.green('Set') : chalk.red('Not set')}`));
    console.log(chalk.gray(`  Config: ${trunc(store.path, 50)}`));
    console.log('');

    const { choice } = await inquirer.prompt([{
      type: 'list',
      name: 'choice',
      message: chalk.cyan.bold('Select an option:'),
      pageSize: 16,
      loop: false,      // FIX: no wrap-around to top when reaching bottom
      choices: [
        {
          name: `${chalk.green('>>')} Start Real-Time Scanner`,
          value: 'start'
        },
        {
          name: `${chalk.cyan('>>')} Scan a Repository`,
          value: 'scan_repo'
        },
        {
          name: `${chalk.blue('>>')} View Recent Findings`,
          value: 'findings'
        },
        {
          name: `${chalk.blue('>>')} Scanner Statistics`,
          value: 'stats'
        },
        new inquirer.Separator(chalk.gray('── Settings ─────────────────────────')),
        {
          name: `${chalk.yellow('>>')} GitHub Token  ${chalk.gray('[' + (hasToken ? 'SET' : 'MISSING') + ']')}`,
          value: 'token'
        },
        {
          name: `${chalk.magenta('>>')} Notifications`,
          value: 'notifications'
        },
        {
          name: `${chalk.white('>>')} Scanner Settings`,
          value: 'settings'
        },
        {
          name: `${chalk.cyan('>>')} Database Settings`,
          value: 'database'
        },
        new inquirer.Separator(chalk.gray('── Tools ────────────────────────────')),
        {
          name: `${chalk.green('>>')} Validate a Secret`,
          value: 'validate'
        },
        {
          name: `${chalk.red('>>')} View Leaked Keys`,
          value: 'leaks'
        },
        {
          name: `${chalk.white('>>')} About / Help`,
          value: 'about'
        },
        new inquirer.Separator(chalk.gray('─────────────────────────────────────')),
        {
          name: chalk.red('    Exit'),
          value: 'exit'
        },
      ]
    }]);

    switch (choice) {
      case 'start':        await menuStart();        break;
      case 'scan_repo':    await menuScanRepo();     break;
      case 'findings':     await menuFindings();     break;
      case 'stats':        await menuStats();        break;
      case 'token':        await menuToken();        break;
      case 'notifications':await menuNotifications();break;
      case 'settings':     await menuSettings();     break;
      case 'database':     await menuDatabase();     break;
      case 'validate':     await menuValidate();     break;
      case 'leaks':        await menuLeaks();        break;
      case 'about':        await menuAbout();        break;
      case 'exit':
        console.log(chalk.cyan('\n  Goodbye!\n'));
        process.exit(0);
    }
  }
}

// ── Onboarding ────────────────────────────────────────────────────────────────

async function onboarding() {
  banner();
  console.log(chalk.cyan.bold('  Welcome! Quick setup (takes ~30s)'));
  console.log('');
  console.log(chalk.yellow('  Step 1: GitHub Token'));
  console.log(chalk.gray('  Get one at: github.com/settings/tokens'));
  console.log(chalk.gray('  Scope needed: public_repo'));
  console.log('');

  const { token } = await inquirer.prompt([{
    type: 'password', name: 'token', mask: '*',
    message: 'Paste GitHub token (Enter to skip):',
  }]);

  if (token && token.trim()) {
    store.set('githubToken', token.trim());
    process.env.GITHUB_TOKEN = token.trim();
    reloadSingletons();
    success('Token saved!');
  } else {
    warn('Skipped — add a token later in Settings > GitHub Token');
  }

  console.log('');
  const { setupNotif } = await inquirer.prompt([{
    type: 'confirm', name: 'setupNotif',
    message: 'Configure notifications now? (Discord/Slack/Telegram)',
    default: false,
  }]);

  if (setupNotif) await menuNotifications();

  success('Setup done! Loading menu...');
  await new Promise(r => setTimeout(r, 800));
}

// ── Start Scanner ─────────────────────────────────────────────────────────────

async function menuStart() {
  section('>> Start Real-Time Scanner');
  console.log('');

  const token    = store.get('githubToken');
  const apiPort  = store.get('apiPort') || 3000;
  const validate = store.get('validateSecrets');
  const api      = store.get('enableApi');

  console.log(`  Token      : ${masked(token)}`);
  console.log(`  Dashboard  : ${api ? chalk.green('http://localhost:' + apiPort) : chalk.gray('disabled')}`);
  console.log(`  Validation : ${yesNo(validate)}`);
  console.log('');

  if (!token) {
    warn('No token — unauthenticated mode (60 req/hr, slow)');
    const { cont } = await inquirer.prompt([{
      type: 'confirm', name: 'cont',
      message: 'Continue without a token?', default: false
    }]);
    if (!cont) return;
  }

  const { confirm } = await inquirer.prompt([{
    type: 'confirm', name: 'confirm',
    message: 'Start scanner? (Ctrl+C to stop)',
    default: true
  }]);

  if (!confirm) return;

  applyToEnv();
  console.log('');
  info('Starting... Dashboard: http://localhost:' + apiPort);
  console.log(chalk.gray('  Press Ctrl+C to stop.\n'));
  require('../worker/index');
}

// ── Scan Repo ─────────────────────────────────────────────────────────────────

async function menuScanRepo() {
  section('>> Scan a Repository');
  console.log('');

  const { repoUrl } = await inquirer.prompt([{
    type: 'input', name: 'repoUrl',
    message: 'GitHub repo URL:',
    validate: v => {
      if (!v.trim()) return 'Required';
      if (!v.includes('github.com/')) return 'Must be a GitHub URL';
      return true;
    }
  }]);

  const { scanMode } = await inquirer.prompt([{
    type: 'list', name: 'scanMode',
    message: 'Scan depth:',
    loop: false,
    choices: [
      { name: 'Quick  — HEAD files only (~10s)',       value: 'quick' },
      { name: 'Deep   — All branches + history (~1m)', value: 'deep'  },
      { name: 'Full   — Deep + GitHub Code Search',    value: 'full'  },
    ]
  }]);

  const { validate } = await inquirer.prompt([{
    type: 'confirm', name: 'validate',
    message: 'Run live API validation?',
    default: store.get('validateSecrets')
  }]);

  const { outputFmt } = await inquirer.prompt([{
    type: 'list', name: 'outputFmt',
    message: 'Output format:',
    loop: false,
    choices: [
      { name: 'Table   (default)',             value: 'table'  },
      { name: 'JSON    (machine-readable)',    value: 'json'   },
      { name: 'Report  (MD + CSV + SARIF)',    value: 'report' },
    ]
  }]);

  console.log('');
  applyToEnv();
  if (!validate) process.env.VALIDATE_SECRETS = 'false';

  const repoName = repoUrl
    .replace(/https?:\/\/github\.com\//, '')
    .replace(/\.git$/, '').replace(/\/$/, '');

  const spinner = ora(`Scanning ${repoName}...`).start();

  try {
    const ScannerEngine     = require('../scanner/engine');
    const { validateFinding, RESULTS } = require('../validator');
    const GitHistoryScanner = require('../history/git-history-scanner');
    const { annotatePairs } = require('../scanner/pair-matcher');
    const { annotateWithContext } = require('../scanner/context-analyzer');
    const { getDB }  = require('../db');
    const { sha256 } = require('../utils/hash');
    const Reporter   = require('../reporter');

    const engine = new ScannerEngine();
    spinner.text = 'Scanning HEAD files...';
    let findings = await engine.scanRepo({ repoName, repoUrl, pushedAt: new Date().toISOString() });

    if (scanMode === 'deep' || scanMode === 'full') {
      spinner.text = 'Deep scan: branches + history...';
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
      let validation = { result: 'SKIPPED', detail: '' };
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
      results.push(record);
    }

    spinner.stop();

    if (results.length === 0) {
      console.log('');
      success(`No secrets found in ${repoName}`);
      await pause();
      return;
    }

    if (outputFmt === 'json') {
      console.log(JSON.stringify(results.map(r => ({
        provider: r.provider, pattern: r.patternName,
        file: r.filePath, line: r.lineNumber,
        entropy: r.entropy, status: r.validationResult
      })), null, 2));

    } else if (outputFmt === 'report') {
      const reporter = new Reporter('./reports');
      const paths = await reporter.generateAll({ repoName, findings: results, scanDate: new Date().toISOString() });
      console.log('');
      success('Reports saved:');
      Object.entries(paths).forEach(([fmt, p]) => dim(`${fmt}: ${trunc(p, 55)}`));

    } else {
      // Compact table — 78 cols max
      console.log('');
      console.log(chalk.yellow(`  ${results.length} finding(s) in ${trunc(repoName, 35)}\n`));
      printTable(results, [
        { key: 'validationResult', label: 'STATUS',   width: 9  },
        { key: 'provider',         label: 'PROVIDER', width: 12 },
        { key: 'patternName',      label: 'PATTERN',  width: 22 },
        { key: 'filePath',         label: 'FILE',     width: 24 },
        { key: 'entropy',          label: 'ENT',      width: 5  },
      ]);
    }

    const validCount = results.filter(r => r.validationResult === 'VALID').length;
    console.log('');
    if (validCount > 0) {
      console.log(chalk.red.bold(`  !! ${validCount} LIVE secret(s) confirmed!`));
    } else {
      console.log(chalk.yellow(`  ${results.length} potential finding(s). None validated as live.`));
    }

  } catch (err) {
    spinner.fail(`Error: ${err.message}`);
    if (process.env.LOG_LEVEL === 'debug') console.error(err.stack);
  }

  console.log('');
  await pause();
}

// ── Findings ──────────────────────────────────────────────────────────────────

async function menuFindings() {
  section('>> Recent Findings');
  console.log('');

  const { filter } = await inquirer.prompt([{
    type: 'list', name: 'filter',
    message: 'Show:',
    loop: false,
    choices: [
      { name: 'Live (VALID) only',         value: 'valid'    },
      { name: 'All findings (last 50)',     value: 'all'      },
      { name: 'Historical (git history)',   value: 'history'  },
      { name: 'Filter by provider',         value: 'provider' },
      { name: chalk.gray('<- Back'),         value: 'back'     },
    ]
  }]);

  if (filter === 'back') return;

  const spinner = ora('Loading...').start();
  try {
    const { getDB } = require('../db');
    const db = await getDB();
    let findings = await db.getRecentFindings(200);

    if (filter === 'valid')   findings = findings.filter(f => f.validation_result === 'VALID');
    if (filter === 'history') findings = findings.filter(f => f.is_historical);

    if (filter === 'provider') {
      spinner.stop();
      const providers = [...new Set(findings.map(f => f.provider).filter(Boolean))];
      if (!providers.length) { warn('No findings yet.'); await pause(); return; }
      const { prov } = await inquirer.prompt([{
        type: 'list', name: 'prov',
        message: 'Provider:',
        choices: providers
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
    console.log(chalk.cyan(`  ${findings.length} finding(s)\n`));

    // Table: 9 + 12 + 26 + 22 + 5 = 74 cols + 4 spaces = 78
    printTable(findings.slice(0, 50), [
      { key: 'validation_result', label: 'STATUS',   width: 9  },
      { key: 'provider',          label: 'PROVIDER', width: 12 },
      { key: 'repo_name',         label: 'REPO',     width: 26 },
      { key: 'file_path',         label: 'FILE',     width: 22 },
      { key: 'entropy',           label: 'ENT',      width: 4  },
    ]);

    if (findings.length > 50) {
      dim(`  ...and ${findings.length - 50} more.`);
    }
  } catch (err) {
    spinner.fail(err.message);
  }

  console.log('');
  await pause();
}

// ── Stats ─────────────────────────────────────────────────────────────────────

async function menuStats() {
  section('>> Scanner Statistics');
  const spinner = ora('Loading...').start();
  try {
    const { getDB } = require('../db');
    const db = await getDB();
    const s = await db.getStats();
    spinner.stop();
    console.log('');
    console.log(`  Repos scanned  : ${chalk.cyan(s.repositories)}`);
    console.log(`  Total findings : ${chalk.yellow(s.findings)}`);
    console.log(`  Live secrets   : ${chalk.red.bold(s.validSecrets)}`);
    if (s.topProviders && Object.keys(s.topProviders).length) {
      console.log('');
      console.log(chalk.bold('  Top providers:'));
      Object.entries(s.topProviders).slice(0, 5).forEach(([p, c]) => {
        dim(`  ${p.padEnd(16)} ${c}`);
      });
    }
    console.log('');
    dim(`  DB: ${process.env.DATABASE_URL ? 'PostgreSQL' : 'JSONL flat-file'}`);
  } catch (err) {
    spinner.fail(err.message);
  }
  console.log('');
  await pause();
}

// ── GitHub Token ──────────────────────────────────────────────────────────────

async function menuToken() {
  while (true) {
    section('>> GitHub Token');
    const current = store.get('githubToken');
    console.log('');
    console.log(`  Current : ${masked(current)}`);
    console.log(chalk.gray('  Source  : github.com/settings/tokens'));
    console.log(chalk.gray('  Scope   : public_repo'));
    console.log('');

    const { action } = await inquirer.prompt([{
      type: 'list', name: 'action',
      message: 'Token options:',
      loop: false,
      choices: [
        { name: 'Add / Update token',   value: 'set'    },
        { name: 'Verify current token', value: 'verify' },
        { name: 'Remove token',         value: 'remove' },
        { name: chalk.gray('<- Back'),   value: 'back'   },
      ]
    }]);

    if (action === 'back') return;

    if (action === 'set') {
      const { token } = await inquirer.prompt([{
        type: 'password', name: 'token', mask: '*',
        message: 'Paste GitHub token:',
        validate: v => v.trim().length > 10 || 'Too short'
      }]);
      store.set('githubToken', token.trim());
      process.env.GITHUB_TOKEN = token.trim();
      reloadSingletons();
      success('Token saved and applied!');
    }

    if (action === 'verify') {
      if (!current) { warn('No token set.'); await pause(); continue; }
      const spinner = ora('Verifying...').start();
      try {
        const { createGitHubClient } = require('../utils/github-client');
        const client = createGitHubClient(current);
        const resp = await client.get('/user');
        spinner.stop();
        success(`Valid! User: ${chalk.cyan(resp.data.login)}`);
        dim(`  Rate limit: ${resp.headers['x-ratelimit-remaining']}/${resp.headers['x-ratelimit-limit']}`);
      } catch (err) {
        spinner.fail(`Invalid: ${err.response?.status === 401 ? 'Unauthorized' : err.message}`);
      }
    }

    if (action === 'remove') {
      const { confirm } = await inquirer.prompt([{
        type: 'confirm', name: 'confirm',
        message: 'Remove the stored token?', default: false
      }]);
      if (confirm) {
        store.set('githubToken', '');
        process.env.GITHUB_TOKEN = '';
        reloadSingletons();
        success('Token removed.');
      }
    }

    await pause();
  }
}

// ── Notifications ─────────────────────────────────────────────────────────────

async function menuNotifications() {
  while (true) {
    section('>> Notifications');
    console.log('');
    console.log(`  Discord  : ${masked(store.get('discordWebhookUrl'))}`);
    console.log(`  Slack    : ${masked(store.get('slackWebhookUrl'))}`);
    console.log(`  Telegram : ${store.get('telegramBotToken') ? 'Set' : chalk.gray('Not set')}`);
    console.log(`  Webhook  : ${masked(store.get('notifyWebhookUrl'))}`);
    console.log('');

    const { ch } = await inquirer.prompt([{
      type: 'list', name: 'ch',
      message: 'Configure:',
      loop: false,
      choices: [
        { name: 'Discord Webhook',        value: 'discord'  },
        { name: 'Slack Webhook',          value: 'slack'    },
        { name: 'Telegram Bot',           value: 'telegram' },
        { name: 'Generic Webhook URL',    value: 'webhook'  },
        { name: 'Test All Channels',      value: 'test'     },
        { name: 'Clear All',              value: 'clear'    },
        { name: chalk.gray('<- Back'),     value: 'back'     },
      ]
    }]);

    if (ch === 'back') return;

    if (ch === 'discord') {
      console.log(chalk.gray('\n  Get URL: Discord channel -> Edit -> Integrations -> Webhooks'));
      const { url } = await inquirer.prompt([{
        type: 'input', name: 'url',
        message: 'Discord Webhook URL:',
        default: store.get('discordWebhookUrl') || ''
      }]);
      if (url.trim()) { store.set('discordWebhookUrl', url.trim()); reloadSingletons(); success('Saved!'); }
    }

    if (ch === 'slack') {
      console.log(chalk.gray('\n  Get URL: api.slack.com/messaging/webhooks'));
      const { url } = await inquirer.prompt([{
        type: 'input', name: 'url',
        message: 'Slack Webhook URL:',
        default: store.get('slackWebhookUrl') || ''
      }]);
      if (url.trim()) { store.set('slackWebhookUrl', url.trim()); reloadSingletons(); success('Saved!'); }
    }

    if (ch === 'telegram') {
      console.log(chalk.gray('\n  1. Message @BotFather -> /newbot -> get token'));
      console.log(chalk.gray('  2. Get chat_id: api.telegram.org/bot<TOKEN>/getUpdates'));
      const { tok } = await inquirer.prompt([{
        type: 'password', name: 'tok', mask: '*',
        message: 'Bot Token (Enter to skip):'
      }]);
      if (tok.trim()) {
        store.set('telegramBotToken', tok.trim());
        const { chatId } = await inquirer.prompt([{
          type: 'input', name: 'chatId',
          message: 'Chat ID (e.g. -1001234567890):',
          default: store.get('telegramChatId') || ''
        }]);
        if (chatId.trim()) store.set('telegramChatId', chatId.trim());
        reloadSingletons();
        success('Telegram saved!');
      }
    }

    if (ch === 'webhook') {
      const { url } = await inquirer.prompt([{
        type: 'input', name: 'url',
        message: 'Webhook URL:',
        default: store.get('notifyWebhookUrl') || ''
      }]);
      if (url.trim()) { store.set('notifyWebhookUrl', url.trim()); reloadSingletons(); success('Saved!'); }
    }

    if (ch === 'test') {
      applyToEnv();
      const spinner = ora('Sending test alert...').start();
      try {
        const { getNotifier } = require('../notifications');
        const n = getNotifier(true); // force rebuild with new env
        await n.alert({
          repoName: 'test/repo', repoUrl: 'https://github.com/test/repo',
          patternName: 'Test Alert', provider: 'test',
          filePath: '.env', lineNumber: 1, entropy: 4.5,
          value: 'sk-****test****', validationDetail: 'This is a test'
        }, false);
        spinner.stop();
        success('Test sent to all configured channels!');
      } catch (err) {
        spinner.fail(`Test failed: ${err.message}`);
      }
    }

    if (ch === 'clear') {
      const { confirm } = await inquirer.prompt([{
        type: 'confirm', name: 'confirm',
        message: 'Clear ALL notification settings?', default: false
      }]);
      if (confirm) {
        ['discordWebhookUrl','slackWebhookUrl','telegramBotToken','telegramChatId','notifyWebhookUrl']
          .forEach(k => store.set(k, ''));
        reloadSingletons();
        success('Cleared.');
      }
    }

    await pause();
  }
}

// ── Scanner Settings ──────────────────────────────────────────────────────────

async function menuSettings() {
  section('>> Scanner Settings');
  console.log('');

  const cur = {
    validateSecrets:     store.get('validateSecrets'),
    enableApi:           store.get('enableApi'),
    apiPort:             store.get('apiPort') || 3000,
    maxCommitsPerBranch: store.get('maxCommitsPerBranch') || 50,
    maxBranches:         store.get('maxBranches') || 10,
    logLevel:            store.get('logLevel') || 'info',
  };

  console.log(`  Validate secrets  : ${yesNo(cur.validateSecrets)}`);
  console.log(`  Web dashboard     : ${yesNo(cur.enableApi)} (port ${cur.apiPort})`);
  console.log(`  Commits/branch    : ${cur.maxCommitsPerBranch}`);
  console.log(`  Max branches      : ${cur.maxBranches}`);
  console.log(`  Log level         : ${cur.logLevel}`);
  console.log('');

  const ans = await inquirer.prompt([
    {
      type: 'confirm', name: 'validateSecrets',
      message: 'Run live API validation on findings?',
      default: cur.validateSecrets
    },
    {
      type: 'confirm', name: 'enableApi',
      message: 'Enable web dashboard?',
      default: cur.enableApi
    },
    {
      type: 'input', name: 'apiPort',
      message: 'Dashboard port:',
      default: String(cur.apiPort),
      when: a => a.enableApi,
      validate: v => !isNaN(parseInt(v)) || 'Must be a number'
    },
    {
      type: 'list', name: 'maxCommitsPerBranch',
      message: 'Git history depth (commits/branch):',
      choices: [
        { name: '20  - Fast',    value: 20  },
        { name: '50  - Default', value: 50  },
        { name: '100 - Deep',    value: 100 },
        { name: '200 - Deeper',  value: 200 },
        { name: '500 - Maximum', value: 500 },
      ],
      default: [20,50,100,200,500].indexOf(cur.maxCommitsPerBranch) !== -1
        ? [20,50,100,200,500].indexOf(cur.maxCommitsPerBranch) : 1
    },
    {
      type: 'list', name: 'maxBranches',
      message: 'Max branches to scan:',
      choices: [
        { name: '5   - Fast',    value: 5  },
        { name: '10  - Default', value: 10 },
        { name: '20  - Deep',    value: 20 },
        { name: '50  - Maximum', value: 50 },
      ],
      default: [5,10,20,50].indexOf(cur.maxBranches) !== -1
        ? [5,10,20,50].indexOf(cur.maxBranches) : 1
    },
    {
      type: 'list', name: 'logLevel',
      message: 'Log level:',
      choices: ['debug','info','warn','error'],
      default: ['debug','info','warn','error'].indexOf(cur.logLevel) || 1
    },
  ]);

  Object.entries(ans).forEach(([k, v]) => store.set(k, v));
  applyToEnv();
  reloadSingletons();
  success('Settings saved!');
  await pause();
}

// ── Database ──────────────────────────────────────────────────────────────────

async function menuDatabase() {
  section('>> Database Settings');
  console.log('');

  const cur = store.get('databaseUrl');
  console.log(`  Mode    : ${cur ? chalk.green('PostgreSQL') : chalk.cyan('JSONL (default)')}`);
  if (cur) console.log(`  URL     : ${masked(cur)}`);
  console.log('');
  console.log(chalk.gray('  JSONL   - zero config, saves to ./data/findings.jsonl'));
  console.log(chalk.gray('  Postgres - production, requires pg server'));
  console.log('');

  const { dbChoice } = await inquirer.prompt([{
    type: 'list', name: 'dbChoice',
    message: 'Database:',
    loop: false,
    choices: [
      { name: 'JSONL flat-file  (default, no setup)', value: 'jsonl'    },
      { name: 'PostgreSQL       (production)',         value: 'postgres' },
      { name: chalk.gray('<- Back'),                   value: 'back'     },
    ]
  }]);

  if (dbChoice === 'back') return;

  if (dbChoice === 'jsonl') {
    store.set('databaseUrl', '');
    process.env.DATABASE_URL = '';
    reloadSingletons();
    success('Using JSONL. Findings: ./data/findings.jsonl');
  }

  if (dbChoice === 'postgres') {
    const { url } = await inquirer.prompt([{
      type: 'input', name: 'url',
      message: 'Connection string:',
      default: cur || 'postgresql://postgres:pass@localhost:5432/ai_scanner',
    }]);
    if (url.trim()) {
      store.set('databaseUrl', url.trim());
      process.env.DATABASE_URL = url.trim();
      reloadSingletons();
      const spinner = ora('Testing connection...').start();
      try {
        const { getDB } = require('../db');
        const db = await getDB();
        const s = await db.getStats();
        spinner.stop();
        success(`Connected! ${s.findings} existing findings.`);
      } catch (err) {
        spinner.fail(`Connection failed: ${err.message}`);
        store.set('databaseUrl', '');
        process.env.DATABASE_URL = '';
        reloadSingletons();
      }
    }
  }

  await pause();
}

// ── Validate a Secret ─────────────────────────────────────────────────────────

async function menuValidate() {
  section('>> Validate a Secret');
  console.log('');
  console.log(chalk.gray('  Manually test any key against its provider API.'));
  console.log(chalk.red('  Only test secrets you own.\n'));

  const { provider } = await inquirer.prompt([{
    type: 'list', name: 'provider',
    message: 'Provider:',
    pageSize: 14,
    loop: false,
    choices: [
      'openai','anthropic','github','stripe','slack',
      'sendgrid','telegram','mailgun','heroku','npm',
      'discord','huggingface','linear','gitlab',
      { name: chalk.gray('<- Back'), value: 'back' }
    ]
  }]);

  if (provider === 'back') return;

  const { secret } = await inquirer.prompt([{
    type: 'password', name: 'secret', mask: '*',
    message: `${provider} secret:`,
    validate: v => v.trim().length >= 8 || 'Too short'
  }]);

  let context = {};
  if (provider === 'aws') {
    const { keyId } = await inquirer.prompt([{
      type: 'input', name: 'keyId',
      message: 'AWS Access Key ID (AKIA...):'
    }]);
    context.accessKeyId = keyId.trim();
  }

  const spinner = ora(`Validating with ${provider}...`).start();
  try {
    const { validateFinding, RESULTS } = require('../validator');
    const result = await validateFinding(
      { rawValue: secret.trim(), provider, patternName: 'Manual' },
      context
    );
    spinner.stop();
    console.log('');
    if (result.result === RESULTS.VALID) {
      console.log(chalk.red.bold(`  !! VALID — This is a live credential!`));
    } else {
      console.log(chalk.green(`  Result : ${result.result}`));
    }
    console.log(chalk.gray(`  Detail : ${result.detail}`));
  } catch (err) {
    spinner.fail(err.message);
  }

  console.log('');
  await pause();
}

// ── Leaked Keys ───────────────────────────────────────────────────────────────

async function menuLeaks() {
  section('>> Leaked Keys Log (VALID only)');
  const spinner = ora('Loading...').start();
  try {
    const { getDB } = require('../db');
    const db = await getDB();
    const all = await db.getRecentFindings(500);
    const leaks = all.filter(f => f.validation_result === 'VALID');
    spinner.stop();

    if (!leaks.length) {
      console.log('');
      success('No live secrets found yet.');
      dim('  Run the scanner or scan a specific repo to find some.');
      await pause();
      return;
    }

    console.log('');
    console.log(chalk.red.bold(`  !! ${leaks.length} LIVE secret(s)\n`));

    // Table: 12 + 20 + 26 + 12 = 70 + 3 spaces = 73 cols
    printTable(leaks, [
      { key: 'provider',     label: 'PROVIDER', width: 12 },
      { key: 'pattern_name', label: 'PATTERN',  width: 20 },
      { key: 'repo_name',    label: 'REPO',     width: 26 },
      { key: 'file_path',    label: 'FILE',     width: 18 },
    ]);

    console.log('');
    console.log(chalk.red('  Notify repo owners! See SECURITY.md for guidance.'));
  } catch (err) {
    spinner.fail(err.message);
  }

  console.log('');
  await pause();
}

// ── About ─────────────────────────────────────────────────────────────────────

async function menuAbout() {
  section('>> About & Help');
  console.log('');
  console.log(chalk.cyan.bold('  AI Secret Scanner  v2.1.0'));
  console.log(chalk.gray('  Real-time GitHub Credential Detector'));
  console.log('');

  console.log(chalk.bold('  Repo:'));
  dim('  github.com/justlurking-around/justlurkingaround');
  console.log('');

  console.log(chalk.bold('  What it does:'));
  dim('  - Polls GitHub Events API in real-time');
  dim('  - Detects AI-generated repos (bolt.new, Cursor...)');
  dim('  - Scans files + full git history');
  dim('  - 100+ secret patterns + entropy analysis');
  dim('  - Validates findings via live API calls');
  dim('  - Alerts via Discord/Slack/Telegram/Webhook');
  console.log('');

  console.log(chalk.bold('  Platforms:'));
  dim('  Linux, macOS, Windows Terminal, Android Termux');
  console.log('');

  console.log(chalk.bold('  CLI commands (non-interactive):'));
  dim('  ai-scanner scan repo <url>');
  dim('  ai-scanner scan repo <url> --deep');
  dim('  ai-scanner scan repo <url> --json');
  dim('  ai-scanner scan global');
  dim('  ai-scanner findings');
  dim('  ai-scanner findings --valid-only');
  dim('  ai-scanner stats');
  dim('  ai-scanner validate <key> --provider openai');
  console.log('');

  console.log(chalk.bold('  Config file:'));
  dim(`  ${store.path}`);
  console.log('');

  console.log(chalk.bold('  License: MIT'));
  console.log('');
  await pause();
}

module.exports = { mainMenu };
