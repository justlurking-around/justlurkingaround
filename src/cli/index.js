#!/usr/bin/env node
'use strict';

/**
 * AI Secret Scanner — CLI Entry Point
 *
 * Run with no args  → interactive TUI menu (arrow-key navigation)
 * Run with subcommands → direct non-interactive mode (for scripts/CI)
 *
 * Platform: Linux · macOS · Windows Terminal · Termux (Android)
 */

require('dotenv').config();
const { store, applyToEnv } = require('./config-store');

// Apply saved config before anything else
applyToEnv();

const { Command } = require('commander');
const chalk  = require('chalk');
const ora    = require('ora');
const pkg    = require('../../package.json');

const program = new Command();

program
  .name('ai-scanner')
  .description('AI-Generated GitHub Secret Scanner')
  .version(pkg.version)
  .helpOption('-h, --help', 'Show help')
  // Default: launch interactive menu when no subcommand given
  .action(async () => {
    try {
      const { mainMenu } = require('./menu');
      await mainMenu();
    } catch (err) {
      if (err.message?.includes('TTY') || err.isTtyError) {
        console.error(chalk.red(
          '\n  ⚠  Interactive mode requires a TTY terminal.\n' +
          '  On Termux: run directly in the Termux app terminal.\n' +
          '  On Windows: use Windows Terminal or PowerShell (not cmd.exe or Git Bash).\n' +
          '\n  Use subcommands for non-interactive mode:\n' +
          '    ai-scanner scan repo <url>\n' +
          '    ai-scanner scan global\n' +
          '    ai-scanner stats\n'
        ));
        process.exit(1);
      }
      throw err;
    }
  });

// ── scan ──────────────────────────────────────────────────────────────────────

const scan = program.command('scan').description('Scan commands');

scan
  .command('global')
  .description('Start real-time global scanner (non-interactive)')
  .option('-t, --token <token>', 'GitHub token (overrides stored config)')
  .action((opts) => {
    if (opts.token) { store.set('githubToken', opts.token); applyToEnv(); }
    if (!process.env.GITHUB_TOKEN) {
      console.warn(chalk.yellow('  ⚠  No GitHub token — unauthenticated mode (60 req/hr)'));
    }
    console.log(chalk.cyan('  Starting real-time scanner...\n'));
    require('../worker/index');
  });

scan
  .command('repo <url>')
  .description('Scan a single GitHub repository')
  .option('-t, --token <token>', 'GitHub token')
  .option('--deep',       'Also scan git history (all branches + commits)')
  .option('--no-validate','Skip live secret validation')
  .option('--json',       'Output findings as JSON')
  .option('--report',     'Generate Markdown + SARIF report files')
  .action(async (url, opts) => {
    if (opts.token) { store.set('githubToken', opts.token); applyToEnv(); }
    if (!opts.validate) process.env.VALIDATE_SECRETS = 'false';

    const repoName = url
      .replace(/https?:\/\/github\.com\//, '')
      .replace(/\.git$/, '').replace(/\/$/, '');

    if (!repoName.includes('/')) {
      console.error(chalk.red(`  Invalid URL: ${url}`));
      process.exit(1);
    }

    const spinner = ora(`Scanning ${chalk.cyan(repoName)}...`).start();
    try {
      const ScannerEngine     = require('../scanner/engine');
      const GitHistoryScanner = require('../history/git-history-scanner');
      const { annotatePairs } = require('../scanner/pair-matcher');
      const { annotateWithContext } = require('../scanner/context-analyzer');
      const { validateFinding, RESULTS } = require('../validator');
      const { getDB }     = require('../db');
      const { sha256 }    = require('../utils/hash');
      const Reporter      = require('../reporter');

      const engine = new ScannerEngine();
      let findings = await engine.scanRepo({ repoName, repoUrl: url, pushedAt: new Date().toISOString() });

      if (opts.deep) {
        spinner.text = 'Deep history scan...';
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
        let validation = { result: 'SKIPPED', detail: 'Skipped' };
        if (opts.validate !== false) validation = await validateFinding(f);

        const record = {
          repoName, filePath: f.filePath, patternId: f.patternId,
          patternName: f.patternName, provider: f.provider,
          secretHash: sha256(f.rawValue), value: f.value,
          entropy: f.entropy, lineNumber: f.lineNumber,
          matchContext: f.matchContext,
          validationResult: validation.result,
          validationDetail: validation.detail,
          detectedAt: f.detectedAt, isHistorical: f.isHistorical || false
        };
        await db.insertFinding(record);
        results.push(record);
      }

      spinner.stop();

      if (results.length === 0) {
        console.log(chalk.green(`\n  ✔  No secrets found in ${repoName}\n`));
        process.exit(0);
      }

      if (opts.json) {
        console.log(JSON.stringify(results, null, 2));
      } else if (opts.report) {
        const reporter = new Reporter('./reports');
        const paths = await reporter.generateAll({ repoName, findings: results, scanDate: new Date().toISOString() });
        console.log(chalk.green('\n  Reports generated:'));
        Object.entries(paths).forEach(([fmt, p]) => console.log(chalk.gray(`    ${fmt}: ${p}`)));
      } else {
        console.log(chalk.yellow(`\n  ${results.length} finding(s) in ${repoName}\n`));
        console.log(
          chalk.bold('  ' + 'STATUS    '.padEnd(11) + 'PROVIDER      '.padEnd(16) +
            'PATTERN                    '.padEnd(28) + 'FILE                    '.padEnd(26) + 'ENT.')
        );
        console.log('  ' + '─'.repeat(86));
        for (const r of results) {
          const sc = { VALID: chalk.red.bold, INVALID: chalk.gray, ERROR: chalk.yellow, SKIPPED: chalk.blue }[r.validationResult] || chalk.white;
          console.log('  ' +
            sc((r.validationResult || '?').padEnd(11)) +
            chalk.cyan((r.provider || '').padEnd(16)) +
            chalk.white((r.patternName || '').substring(0,26).padEnd(28)) +
            chalk.gray((r.filePath || '').substring(0,24).padEnd(26)) +
            chalk.yellow(String(r.entropy || '')) +
            (r.isHistorical ? chalk.magenta(' [H]') : '')
          );
        }
      }

      const validCount = results.filter(r => r.validationResult === 'VALID').length;
      if (validCount > 0) console.log(chalk.red.bold(`\n  🚨  ${validCount} LIVE secret(s)!\n`));
      else console.log('');

    } catch (err) {
      spinner.fail(chalk.red(err.message));
      process.exit(1);
    }
  });

// ── stats / findings / validate (non-interactive shortcuts) ──────────────────

program
  .command('stats')
  .description('Show scanner statistics')
  .action(async () => {
    const spinner = ora('Loading stats...').start();
    try {
      const db = await require('../db').getDB();
      const stats = await db.getStats();
      spinner.stop();
      console.log(`\n  Repositories : ${chalk.cyan(stats.repositories)}`);
      console.log(`  Findings     : ${chalk.yellow(stats.findings)}`);
      console.log(`  Live secrets : ${chalk.red.bold(stats.validSecrets)}\n`);
    } catch (err) { spinner.fail(err.message); process.exit(1); }
  });

program
  .command('findings')
  .description('Show recent findings from database')
  .option('-n, --limit <n>', 'Number of results', '25')
  .option('--valid-only', 'Only show live (VALID) secrets')
  .option('--json', 'JSON output')
  .action(async (opts) => {
    const spinner = ora('Loading...').start();
    try {
      const db = await require('../db').getDB();
      let findings = await db.getRecentFindings(parseInt(opts.limit));
      if (opts.validOnly) findings = findings.filter(f => f.validation_result === 'VALID');
      spinner.stop();
      if (opts.json) { console.log(JSON.stringify(findings, null, 2)); return; }
      if (!findings.length) { console.log(chalk.gray('\n  No findings yet.\n')); return; }
      console.log(chalk.cyan.bold(`\n  ${findings.length} findings\n`));
      for (const f of findings) {
        const sc = f.validation_result === 'VALID' ? chalk.red.bold : chalk.gray;
        console.log(`  ${sc((f.validation_result || '?').padEnd(9))} ${chalk.cyan((f.provider||'?').padEnd(14))} ${chalk.white((f.repo_name||'').substring(0,32).padEnd(34))} ${chalk.gray(f.file_path||'')}`);
      }
      console.log('');
    } catch (err) { spinner.fail(err.message); process.exit(1); }
  });

program
  .command('validate <secret>')
  .description('Validate a secret against its provider API')
  .option('-p, --provider <p>', 'Provider name', 'generic')
  .action(async (secret, opts) => {
    const spinner = ora(`Validating with ${opts.provider}...`).start();
    try {
      const { validateFinding, RESULTS } = require('../validator');
      const result = await validateFinding({ rawValue: secret, provider: opts.provider, patternName: 'CLI test' });
      spinner.stop();
      const color = result.result === RESULTS.VALID ? chalk.red.bold : chalk.green;
      console.log(`\n  Result : ${color(result.result)}`);
      console.log(`  Detail : ${chalk.gray(result.detail)}\n`);
    } catch (err) { spinner.fail(err.message); process.exit(1); }
  });

// ── parse ─────────────────────────────────────────────────────────────────────

program.parseAsync(process.argv).catch(err => {
  console.error(chalk.red(`\n  Error: ${err.message}\n`));
  process.exit(1);
});
