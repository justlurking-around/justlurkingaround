#!/usr/bin/env node
'use strict';

/**
 * PHASE 12 — CLI Tool
 *
 * Usage:
 *   ai-scanner scan global          — start real-time scanner
 *   ai-scanner scan repo <url>      — scan a single repo
 *   ai-scanner stats                — show DB stats
 *   ai-scanner findings [--limit N] — show recent findings
 *   ai-scanner validate <secret>    — validate a known secret
 *
 * Works on: Linux, macOS, Windows, Termux (Android)
 */

require('dotenv').config();

const { Command } = require('commander');
const chalk = require('chalk');
const ora = require('ora');

const ScannerEngine   = require('../scanner/engine');
const { validateFinding, RESULTS } = require('../validator');
const { getDB }       = require('../db');
const { sha256 }      = require('../utils/hash');
const logger          = require('../utils/logger');

const program = new Command();

program
  .name('ai-scanner')
  .description('AI-Generated GitHub Secret Scanner — Real-Time')
  .version('1.0.0');

// ── scan ──────────────────────────────────────────────────────────────────────

const scanCmd = program.command('scan');

scanCmd
  .command('global')
  .description('Start real-time global scanner (polls GitHub Events API)')
  .option('-t, --token <token>', 'GitHub token (or set GITHUB_TOKEN env var)')
  .action(async (opts) => {
    if (opts.token) process.env.GITHUB_TOKEN = opts.token;

    console.log(chalk.cyan.bold('\n🔍 AI Secret Scanner — Global Mode\n'));
    console.log(chalk.gray('Polling GitHub Events API for AI-generated repos...\n'));

    // Delegate to worker
    require('../worker/index');
  });

scanCmd
  .command('repo <url>')
  .description('Scan a single GitHub repository')
  .option('-t, --token <token>', 'GitHub token')
  .option('--no-validate', 'Skip secret validation')
  .option('--json', 'Output findings as JSON')
  .action(async (url, opts) => {
    if (opts.token) process.env.GITHUB_TOKEN = opts.token;

    // Normalize URL to owner/repo
    const repoName = url
      .replace(/https?:\/\/github\.com\//, '')
      .replace(/\.git$/, '')
      .replace(/\/$/, '');

    if (!repoName || !repoName.includes('/')) {
      console.error(chalk.red(`Invalid repo URL: ${url}`));
      console.error('Expected format: https://github.com/owner/repo');
      process.exit(1);
    }

    const spinner = ora(`Scanning ${chalk.cyan(repoName)}...`).start();

    try {
      const scanner = new ScannerEngine();
      const db = await getDB();

      const findings = await scanner.scanRepo({
        repoName,
        repoUrl: `https://github.com/${repoName}`,
        pushedAt: new Date().toISOString()
      });

      spinner.stop();

      if (findings.length === 0) {
        console.log(chalk.green(`\n✅ No secrets found in ${repoName}`));
        process.exit(0);
      }

      console.log(chalk.yellow(`\n⚠️  ${findings.length} potential secret(s) found in ${repoName}\n`));

      // Print table
      const rows = [];
      for (const f of findings) {
        let validResult = { result: RESULTS.SKIPPED };
        if (opts.validate !== false) {
          validResult = await validateFinding(f);
        }

        const statusColor = {
          [RESULTS.VALID]:   chalk.red.bold,
          [RESULTS.INVALID]: chalk.gray,
          [RESULTS.ERROR]:   chalk.yellow,
          [RESULTS.SKIPPED]: chalk.blue,
        }[validResult.result] || chalk.white;

        rows.push({
          provider: f.provider,
          pattern:  f.patternName,
          file:     f.filePath,
          line:     f.lineNumber,
          entropy:  f.entropy,
          secret:   f.value,
          status:   statusColor(validResult.result),
          detail:   validResult.detail || ''
        });

        // Persist to DB
        await db.insertFinding({
          repoName,
          filePath:         f.filePath,
          patternId:        f.patternId,
          patternName:      f.patternName,
          provider:         f.provider,
          secretHash:       sha256(f.rawValue),
          value:            f.value,
          entropy:          f.entropy,
          lineNumber:       f.lineNumber,
          matchContext:     f.matchContext,
          validationResult: validResult.result,
          validationDetail: validResult.detail,
          detectedAt:       f.detectedAt
        });
      }

      if (opts.json) {
        console.log(JSON.stringify(rows, null, 2));
      } else {
        printTable(rows);
      }

      const validCount = rows.filter(r => r.status.includes('VALID')).length;
      if (validCount > 0) {
        console.log(chalk.red.bold(`\n🚨 ${validCount} LIVE secret(s) detected!\n`));
      }

    } catch (err) {
      spinner.fail(chalk.red(`Error: ${err.message}`));
      if (process.env.DEBUG) console.error(err.stack);
      process.exit(1);
    }
  });

// ── stats ─────────────────────────────────────────────────────────────────────

program
  .command('stats')
  .description('Show scanner database statistics')
  .action(async () => {
    try {
      const db = await getDB();
      const stats = await db.getStats();
      console.log(chalk.cyan.bold('\n📊 Scanner Stats\n'));
      console.log(`  ${chalk.bold('Repositories scanned:')} ${stats.repositories}`);
      console.log(`  ${chalk.bold('Total findings:')}       ${stats.findings}`);
      console.log(`  ${chalk.bold('Valid live secrets:')}   ${chalk.red.bold(stats.validSecrets)}\n`);
    } catch (err) {
      console.error(chalk.red(`DB error: ${err.message}`));
      process.exit(1);
    }
  });

// ── findings ──────────────────────────────────────────────────────────────────

program
  .command('findings')
  .description('Show recent findings from the database')
  .option('-n, --limit <n>', 'Number of findings to show', '25')
  .option('--valid-only', 'Only show validated live secrets')
  .option('--json', 'Output as JSON')
  .action(async (opts) => {
    try {
      const db = await getDB();
      let findings = await db.getRecentFindings(parseInt(opts.limit));

      if (opts.validOnly) {
        findings = findings.filter(f => f.validation_result === 'VALID');
      }

      if (findings.length === 0) {
        console.log(chalk.gray('\nNo findings yet.\n'));
        return;
      }

      if (opts.json) {
        console.log(JSON.stringify(findings, null, 2));
        return;
      }

      console.log(chalk.cyan.bold(`\n🔍 Recent Findings (${findings.length})\n`));
      for (const f of findings) {
        const statusColor = f.validation_result === 'VALID' ? chalk.red.bold : chalk.gray;
        console.log(
          `  ${chalk.bold(f.provider?.padEnd(12))} ` +
          `${statusColor((f.validation_result || '?').padEnd(8))} ` +
          `${chalk.cyan(f.repo_name?.padEnd(40))} ` +
          `${chalk.gray(f.file_path)}`
        );
      }
      console.log();
    } catch (err) {
      console.error(chalk.red(`Error: ${err.message}`));
      process.exit(1);
    }
  });

// ── validate ──────────────────────────────────────────────────────────────────

program
  .command('validate <secret>')
  .description('Validate a secret against a provider API')
  .option('-p, --provider <provider>', 'Provider name (openai, github, stripe...)', 'generic')
  .action(async (secret, opts) => {
    const spinner = ora(`Validating against ${opts.provider}...`).start();
    try {
      const result = await validateFinding({
        rawValue: secret,
        provider: opts.provider,
        patternName: 'Manual validation'
      });
      spinner.stop();

      const color = result.result === RESULTS.VALID ? chalk.red.bold : chalk.green;
      console.log(`\n  Result: ${color(result.result)}`);
      console.log(`  Detail: ${result.detail}\n`);
    } catch (err) {
      spinner.fail(err.message);
    }
  });

// ── Helpers ───────────────────────────────────────────────────────────────────

function printTable(rows) {
  if (!rows.length) return;
  const cols = ['provider', 'pattern', 'file', 'line', 'entropy', 'secret', 'status'];
  const widths = cols.map(c => Math.max(c.length, ...rows.map(r => String(r[c] || '').length)));

  const header = cols.map((c, i) => c.toUpperCase().padEnd(widths[i])).join('  ');
  const divider = widths.map(w => '─'.repeat(w)).join('  ');

  console.log(chalk.bold('\n  ' + header));
  console.log('  ' + divider);
  for (const row of rows) {
    const line = cols.map((c, i) => String(row[c] || '').padEnd(widths[i])).join('  ');
    console.log('  ' + line);
  }
  console.log();
}

program.parse(process.argv);

if (!process.argv.slice(2).length) {
  program.outputHelp();
}
