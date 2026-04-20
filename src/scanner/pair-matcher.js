'use strict';

/**
 * DAY 2 — Secret Pair Matcher
 *
 * Real scanners (GitHub, TruffleHog) reduce false positives by requiring
 * BOTH elements of a credential pair to be present together:
 *   - AWS Access Key ID  +  Secret Access Key (same file)
 *   - DB Username        +  Password (same connection string)
 *   - Stripe public key  +  Secret key (same file)
 *   - Twilio SID         +  Auth Token (same file)
 *
 * This module post-processes findings to:
 *  1. Identify paired secrets in the same file
 *  2. Boost confidence when pairs are found together
 *  3. Flag unpaired findings as lower-confidence
 */

const logger = require('../utils/logger');

// Define pairs: if patternIdA and patternIdB appear in the same file,
// mark both as paired (higher confidence)
const PAIRS = [
  { a: 'aws_access_key',  b: 'aws_secret_key',   name: 'AWS Key Pair' },
  { a: 'twilio_sid',      b: 'twilio_token',      name: 'Twilio SID+Token Pair' },
  { a: 'stripe_live_sk',  b: 'stripe_live_pk',    name: 'Stripe Key Pair' },
  { a: 'stripe_test_sk',  b: 'stripe_live_pk',    name: 'Stripe Test+Pub Pair' },
  { a: 'algolia_key',     b: 'algolia_app',        name: 'Algolia App+Key Pair' },
  { a: 'pusher_key',      b: 'pusher_secret',      name: 'Pusher Key+Secret Pair' },
  { a: 'gcp_api_key',     b: 'gcp_service_acct',  name: 'GCP Key+Service Account' },
  // DB pairs: connection strings are self-contained so they're already paired
];

/**
 * Annotate findings with pair information.
 * Findings from the same file that form a known pair get isPaired=true.
 *
 * @param {object[]} findings - raw scanner findings
 * @returns {object[]} annotated findings
 */
function annotatePairs(findings) {
  if (!findings || findings.length === 0) return findings;

  // Group by filePath
  const byFile = {};
  for (const f of findings) {
    const key = `${f.repoName || ''}::${f.filePath}`;
    if (!byFile[key]) byFile[key] = [];
    byFile[key].push(f);
  }

  for (const [fileKey, filefindings] of Object.entries(byFile)) {
    const patternIds = new Set(filefindings.map(f => f.patternId));

    for (const pair of PAIRS) {
      if (patternIds.has(pair.a) && patternIds.has(pair.b)) {
        // Mark all findings in this file that are part of the pair
        for (const f of filefindings) {
          if (f.patternId === pair.a || f.patternId === pair.b) {
            f.isPaired = true;
            f.pairName = pair.name;
            f.confidence = (f.confidence || 50) + 30; // boost confidence
          }
        }
        logger.debug(`[PairMatcher] Found ${pair.name} in ${fileKey}`);
      }
    }
  }

  // Add default confidence to unpaired findings
  for (const f of findings) {
    if (!f.isPaired) {
      f.isPaired = false;
      f.confidence = f.confidence || 50;
    }
    f.confidence = Math.min(f.confidence, 100);
  }

  return findings;
}

/**
 * Filter findings: only keep high-confidence ones
 * Used in strict mode where we want to minimize FPs
 */
function filterHighConfidence(findings, minConfidence = 60) {
  return findings.filter(f => (f.confidence || 50) >= minConfidence);
}

module.exports = { annotatePairs, filterHighConfidence, PAIRS };
