'use strict';

const winston = require('winston');
const path = require('path');
const fs = require('fs');

const config = require('../../config/default');

// Ensure log dir exists
const logDir = config.logging.dir;
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

const { combine, timestamp, printf, colorize, errors } = winston.format;

const logFormat = printf(({ level, message, timestamp, stack, ...meta }) => {
  let msg = `[${timestamp}] ${level.toUpperCase()}: ${message}`;
  if (stack) msg += `\n${stack}`;
  if (Object.keys(meta).length > 0) {
    try { msg += ` | ${JSON.stringify(meta)}`; } catch {}
  }
  return msg;
});

const logger = winston.createLogger({
  level: config.logging.level,
  format: combine(
    errors({ stack: true }),
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    logFormat
  ),
  transports: [
    new winston.transports.Console({
      format: combine(
        colorize({ all: true }),
        errors({ stack: true }),
        timestamp({ format: 'HH:mm:ss' }),
        logFormat
      )
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'scanner.log'),
      maxsize: 10 * 1024 * 1024,  // 10MB
      maxFiles: 5,
      tailable: true
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'findings.log'),
      level: 'warn',
      maxsize: 50 * 1024 * 1024,
      maxFiles: 10,
      tailable: true
    })
  ]
});

module.exports = logger;
