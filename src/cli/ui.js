'use strict';

/**
 * TUI helpers — compact, Termux-safe
 *
 * Design rules:
 *  - Max content width: 60 chars (fits 80-col Termux default)
 *  - No emoji in box-drawing lines (width = 2 but font = 1 on some Termux fonts)
 *  - Separator always 52 dashes (matches inner box width)
 *  - Tables ≤ 78 chars total
 */

const inquirer = require('inquirer');
const chalk    = require('chalk');

// Detect terminal width; cap at 78 for safety
const TERM_WIDTH = Math.min(process.stdout.columns || 80, 78);

const SEP   = chalk.gray('─'.repeat(52));
const BRAND = chalk.cyan.bold;
const DIM   = chalk.gray;
const OK    = chalk.green.bold;
const WARN  = chalk.yellow.bold;
const ERR   = chalk.red.bold;
const INFO  = chalk.blue.bold;

function banner() {
  console.clear();
  // Fixed 52-char inner width, no emoji inside box borders
  console.log(chalk.cyan.bold([
    '',
    '  +==================================================+',
    '  |   AI Secret Scanner  v2.1.0                      |',
    '  |   Real-time GitHub Credential Detector           |',
    '  +==================================================+',
    '',
  ].join('\n')));
}

function section(title) {
  console.log('');
  console.log(SEP);
  console.log(BRAND(`  ${title}`));
  console.log(SEP);
}

function success(msg) { console.log(OK(`  [OK] ${msg}`)); }
function warn(msg)    { console.log(WARN(`  [!!] ${msg}`)); }
function error(msg)   { console.log(ERR(`  [X]  ${msg}`)); }
function info(msg)    { console.log(INFO(`  [i]  ${msg}`)); }
function dim(msg)     { console.log(DIM(`       ${msg}`)); }

function pause(msg = 'Press Enter to continue...') {
  return inquirer.prompt([{ type: 'input', name: '_', message: DIM(msg) }]);
}

/**
 * Print a compact table that fits in 78 columns
 * cols: [{key, label, width}]
 */
function printTable(rows, cols) {
  if (!rows || !rows.length) { dim('  No results.'); return; }

  const header = cols.map(c => c.label.padEnd(c.width)).join(' ');
  const divider = cols.map(c => '─'.repeat(c.width)).join(' ');
  console.log(chalk.bold('  ' + header));
  console.log('  ' + divider);
  for (const row of rows) {
    const line = cols.map(c => {
      const val = String(row[c.key] || '');
      return val.length > c.width ? val.substring(0, c.width - 1) + '…' : val.padEnd(c.width);
    }).join(' ');
    console.log('  ' + line);
  }
}

module.exports = {
  inquirer, banner, section, success, warn, error, info, dim, pause,
  printTable, SEP, BRAND, DIM, OK, WARN, ERR, INFO, TERM_WIDTH
};
