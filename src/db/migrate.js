#!/usr/bin/env node
'use strict';
require('dotenv').config();
const { getDB } = require('./index');
const logger = require('../utils/logger');

(async () => {
  try {
    const db = await getDB();
    logger.info('Database migration complete.');
    await db.close?.();
    process.exit(0);
  } catch (err) {
    logger.error(`Migration failed: ${err.message}`);
    process.exit(1);
  }
})();
