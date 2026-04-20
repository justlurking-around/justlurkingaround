'use strict';

/**
 * Interactive TUI helper
 * Works on: Linux, macOS, Windows Terminal, Termux (Android)
 *
 * Wraps inquirer v8 (CommonJS) with consistent styling
 */

const inquirer  = require('inquirer');
const chalk     = require('chalk');

// ── Brand / styling helpers ───────────────────────────────────────────────────

const BRAND = chalk.cyan.bold;
const DIM   = chalk.gray;
const OK    = chalk.green.bold;
const WARN  = chalk.yellow.bold;
const ERR   = chalk.red.bold;
const INFO  = chalk.blue.bold;
const SEP   = chalk.gray('─'.repeat(52));

function banner() {
  console.clear();
  console.log(chalk.cyan.bold(`
  ╔══════════════════════════════════════════════════╗
  ║     🔍  AI Secret Scanner  v2.0.0                ║
  ║     Real-time GitHub Credential Detector         ║
  ╠══════════════════════════════════════════════════╣
  ║  Finds leaked API keys in AI-generated repos     ║
  ║  Works on Linux · macOS · Windows · Termux       ║
  ╚══════════════════════════════════════════════════╝
`));
}

function section(title) {
  console.log('');
  console.log(SEP);
  console.log(BRAND(`  ${title}`));
  console.log(SEP);
}

function success(msg) { console.log(OK(`  ✔  ${msg}`)); }
function warn(msg)    { console.log(WARN(`  ⚠  ${msg}`)); }
function error(msg)   { console.log(ERR(`  ✖  ${msg}`)); }
function info(msg)    { console.log(INFO(`  ℹ  ${msg}`)); }
function dim(msg)     { console.log(DIM(`     ${msg}`)); }

function pause(msg = 'Press Enter to continue...') {
  return inquirer.prompt([{
    type: 'input',
    name: '_',
    message: DIM(msg),
  }]);
}

module.exports = { inquirer, banner, section, success, warn, error, info, dim, pause, SEP, BRAND, DIM, OK, WARN, ERR, INFO };
