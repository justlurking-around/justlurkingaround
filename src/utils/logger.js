'use strict';

/**
 * Logger — Termux-safe console output
 *
 * CHANGES v2.1.4:
 *  - Console lines truncated to terminal width (no wrap/overlap on 80-col Termux)
 *  - Compact timestamp HH:mm:ss only (saves ~12 chars per line)
 *  - Level shown as short 4-char code: INFO WARN ERRO DBUG
 *  - [Finding] lines formatted as compact single-line table rows
 *  - VALID secret lines always printed in full (never truncated — they matter)
 *  - File log still gets full untruncated output
 */

const winston = require('winston');
const path    = require('path');
const fs      = require('fs');
const config  = require('../../config/default');

const logDir = config.logging.dir || './logs';
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

const { combine, timestamp, printf, errors } = winston.format;

// Terminal width — default 78 for Termux safety (no process.stdout.columns in pipes)
const TTY_WIDTH = Math.min(
  (process.stdout.isTTY && process.stdout.columns) ? process.stdout.columns - 1 : 78,
  120  // cap for wide terminals — don't go too wide
);

// Short level labels (4 chars) to save space
const LEVEL_LABEL = {
  error: 'ERRO',
  warn:  'WARN',
  info:  'INFO',
  debug: 'DBUG',
  verbose: 'VERB',
};

// ANSI color codes (short versions — no chalk dependency here)
const C = {
  reset:  '\x1b[0m',
  red:    '\x1b[31m',
  yellow: '\x1b[33m',
  cyan:   '\x1b[36m',
  green:  '\x1b[32m',
  gray:   '\x1b[90m',
  bold:   '\x1b[1m',
  magenta:'\x1b[35m',
};

function colorForLevel(level) {
  switch (level) {
    case 'error': return C.red + C.bold;
    case 'warn':  return C.yellow;
    case 'info':  return C.cyan;
    case 'debug': return C.gray;
    default:      return C.reset;
  }
}

/**
 * Format a [Finding] log line as a compact row:
 *   FIND | provider  | repo/name       | file.ext | STATUS
 */
function formatFindingLine(message, ts) {
  // Pattern: [Finding] owner/repo | PatternName | file.path | STATUS
  const m = message.match(/\[Finding\]\s+(.+?)\s+\|\s+(.+?)\s+\|\s+(.+?)\s+\|\s+(\S+)/);
  if (!m) return null;

  const [, repo, pattern, file, status] = m;
  const statusColor = status === 'VALID' ? C.red + C.bold : C.gray;
  const basename = file.split('/').pop();                 // just filename, not full path
  const shortRepo = repo.length > 22 ? repo.slice(0, 21) + '…' : repo.padEnd(22);
  const shortPat  = pattern.length > 18 ? pattern.slice(0, 17) + '…' : pattern.padEnd(18);
  const shortFile = basename.length > 16 ? basename.slice(0, 15) + '…' : basename.padEnd(16);

  return `${C.gray}${ts}${C.reset} ${C.gray}FIND${C.reset} ${C.cyan}${shortRepo}${C.reset} ${C.gray}|${C.reset} ${shortPat} ${C.gray}|${C.reset} ${C.gray}${shortFile}${C.reset} ${statusColor}${status}${C.reset}`;
}

/**
 * Format a [Scanner] / [Worker] / [History] status line compactly
 */
function formatStatusLine(message, ts, level) {
  const lc = colorForLevel(level);
  const label = LEVEL_LABEL[level] || 'INFO';

  // Prefix shorten map
  const prefixMap = [
    [/^\[Scanner\] Scanning repo: /, `${C.cyan}SCAN${C.reset} `],
    [/^\[Scanner\] (.+?) — (\d+) findings$/, null],  // handled specially below
    [/^\[Worker\] Processing: /, `${C.cyan}PROC${C.reset} `],
    [/^\[History\] Deep scan: /, `${C.magenta}HIST${C.reset} `],
    [/^\[History\] (.+?) complete/, `${C.magenta}HIST${C.reset} `],
    [/^\[Poller\]/, `${C.gray}POLL${C.reset} `],
    [/^\[Queue\]/, `${C.gray}QUEU${C.reset} `],
    [/^\[Validator\]/, `${C.gray}VALD${C.reset} `],
    [/^\[Stats\]/, `${C.green}STAT${C.reset} `],
    [/^\[DB\]/, `${C.gray}DB  ${C.reset} `],
    [/^\[API\]/, `${C.gray}API ${C.reset} `],
    [/^\[Notifier\]/, `${C.gray}NOTF${C.reset} `],
    [/^\[GHClient\]/, `${C.gray}GH  ${C.reset} `],
  ];

  // Special: findings count line
  const scanFindings = message.match(/^\[Scanner\] (.+?) — (\d+) findings?/);
  if (scanFindings) {
    const [, repo, count] = scanFindings;
    const cnt = parseInt(count);
    const cntColor = cnt > 50 ? C.yellow : cnt > 0 ? C.green : C.gray;
    const shortRepo = repo.length > 30 ? repo.slice(0, 29) + '…' : repo;
    return `${C.gray}${ts}${C.reset} SCAN ${C.cyan}${shortRepo}${C.reset} ${cntColor}${count} findings${C.reset}`;
  }

  let msg = message;
  for (const [pattern, replacement] of prefixMap) {
    if (pattern.test(msg)) {
      if (replacement) msg = msg.replace(pattern, '');
      break;
    }
  }

  // Build line
  const prefix = `${C.gray}${ts}${C.reset} ${lc}${label}${C.reset} `;
  const maxMsgLen = TTY_WIDTH - 14; // 8 (ts) + 1 + 4 (label) + 1
  if (msg.length > maxMsgLen) msg = msg.slice(0, maxMsgLen - 1) + '…';
  return prefix + msg;
}

// ── Console transport format ──────────────────────────────────────────────────

const consoleFormat = printf(({ level, message, timestamp: ts, stack }) => {
  const msg = String(message || '');

  // VALID secret — never truncate, always highlight
  if (msg.includes('LIVE SECRET') || msg.includes('!! VALID')) {
    return [
      `${C.red}${C.bold}${'━'.repeat(Math.min(TTY_WIDTH, 60))}${C.reset}`,
      `${C.red}${C.bold}${ts} LIVE SECRET FOUND!${C.reset}`,
      `${C.red}${C.bold}${msg}${C.reset}`,
      `${C.red}${C.bold}${'━'.repeat(Math.min(TTY_WIDTH, 60))}${C.reset}`,
    ].join('\n');
  }

  // HIGH-CONF PAIR — highlight but no truncation
  if (msg.includes('HIGH-CONF PAIR')) {
    const shortMsg = msg.replace('[HIGH-CONF PAIR]', '').trim();
    const maxLen = TTY_WIDTH - 16;
    const display = shortMsg.length > maxLen ? shortMsg.slice(0, maxLen - 1) + '…' : shortMsg;
    return `${C.gray}${ts}${C.reset} ${C.yellow}PAIR${C.reset} ${display}`;
  }

  // [Finding] lines — compact table row
  if (msg.includes('[Finding]')) {
    const formatted = formatFindingLine(msg, ts);
    if (formatted) return formatted;
  }

  // All other lines — compact with prefix shortening + truncation
  return formatStatusLine(msg, ts, level);
});

// ── File transport format (full, untruncated) ─────────────────────────────────

const fileFormat = printf(({ level, message, timestamp: ts, stack, ...meta }) => {
  let msg = `[${ts}] ${level.toUpperCase()}: ${message}`;
  if (stack) msg += `\n${stack}`;
  if (Object.keys(meta).length > 0) {
    try { msg += ` | ${JSON.stringify(meta)}`; } catch {}
  }
  return msg;
});

// ── Winston logger ─────────────────────────────────────────────────────────────

const logger = winston.createLogger({
  level: config.logging.level || 'info',
  transports: [
    new winston.transports.Console({
      format: combine(
        errors({ stack: true }),
        timestamp({ format: 'HH:mm:ss' }),
        consoleFormat
      )
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'scanner.log'),
      maxsize: 10 * 1024 * 1024,
      maxFiles: 5,
      tailable: true,
      format: combine(
        errors({ stack: true }),
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        fileFormat
      )
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'findings.log'),
      level: 'warn',
      maxsize: 50 * 1024 * 1024,
      maxFiles: 10,
      tailable: true,
      format: combine(
        errors({ stack: true }),
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        fileFormat
      )
    }),
  ]
});

module.exports = logger;
