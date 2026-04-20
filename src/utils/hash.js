'use strict';

const crypto = require('crypto');

/**
 * SHA-256 hash of a string — used for deduplication
 */
function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

/**
 * Hash a file by repo + path + content to avoid rescanning identical files
 */
function fileHash(repoFullName, filePath, content) {
  return sha256(`${repoFullName}::${filePath}::${content}`);
}

module.exports = { sha256, fileHash };
