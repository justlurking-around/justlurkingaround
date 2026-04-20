'use strict';

/**
 * PHASE 3 — Active Repo Filter
 *
 * Only allow repos with recent commits.
 * Assign priority based on how recently the repo was pushed to.
 * Ignore repos inactive for months/years.
 */

const logger = require('../utils/logger');

const PRIORITY = {
  VERY_ACTIVE: { label: 'very_active', intervalMs: 60_000 },      // 1 min
  ACTIVE:      { label: 'active',      intervalMs: 300_000 },     // 5 min
  MODERATE:    { label: 'moderate',    intervalMs: 600_000 },     // 10 min
  LOW:         { label: 'low',         intervalMs: 1_500_000 },   // 25 min
};

// Max age to still consider a repo "active" (48 hours)
const MAX_AGE_MS = 48 * 60 * 60 * 1000;

/**
 * Given a repo event, classify it and decide whether to scan.
 * @param {object} repoEvent - normalized event from poller
 * @returns {{ allowed: boolean, priority: object|null, ageMinutes: number }}
 */
function classifyRepo(repoEvent) {
  const pushedAt = repoEvent.pushedAt || repoEvent.createdAt;
  if (!pushedAt) {
    return { allowed: false, priority: null, ageMinutes: Infinity };
  }

  const ageMs = Date.now() - new Date(pushedAt).getTime();
  const ageMinutes = ageMs / 60_000;

  if (ageMs > MAX_AGE_MS) {
    logger.debug(`[ActiveFilter] Skipping stale repo ${repoEvent.repoName} (age: ${Math.round(ageMinutes)} min)`);
    return { allowed: false, priority: null, ageMinutes };
  }

  let priority;
  if (ageMinutes <= 1) {
    priority = PRIORITY.VERY_ACTIVE;
  } else if (ageMinutes <= 5) {
    priority = PRIORITY.ACTIVE;
  } else if (ageMinutes <= 10) {
    priority = PRIORITY.MODERATE;
  } else {
    priority = PRIORITY.LOW;
  }

  return { allowed: true, priority, ageMinutes };
}

module.exports = { classifyRepo, PRIORITY };
