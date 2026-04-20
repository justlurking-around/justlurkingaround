'use strict';

/**
 * PHASE 2 — Real-Time GitHub Events Poller
 *
 * Connects to GET /events (public GitHub event stream)
 * Handles ETag caching and X-Poll-Interval header
 * Emits PushEvent and CreateEvent payloads
 */

const EventEmitter = require('events');
const { getClient } = require('../utils/github-client');
const logger = require('../utils/logger');

class EventsPoller extends EventEmitter {
  constructor(options = {}) {
    super();
    this.client = getClient();
    this.etag = null;
    this.pollInterval = options.pollInterval || 60000; // default 60s
    this.running = false;
    this._timer = null;
    this.seenEventIds = new Set();
    this.maxSeenSize = 5000; // rolling dedup window
  }

  start() {
    if (this.running) return;
    this.running = true;
    logger.info('[Poller] Starting GitHub Events poller...');
    this._poll();
  }

  stop() {
    this.running = false;
    if (this._timer) clearTimeout(this._timer);
    logger.info('[Poller] Stopped.');
  }

  async _poll() {
    if (!this.running) return;
    try {
      await this._fetchEvents();
    } catch (err) {
      logger.error(`[Poller] Poll error: ${err.message}`);
    }
    if (this.running) {
      this._timer = setTimeout(() => this._poll(), this.pollInterval);
    }
  }

  async _fetchEvents() {
    const headers = {};
    if (this.etag) headers['If-None-Match'] = this.etag;

    let response;
    try {
      response = await this.client.get('/events', {
        headers,
        params: { per_page: 100 }
      });
    } catch (err) {
      if (err.response?.status === 304) {
        logger.debug('[Poller] 304 Not Modified — no new events');
        return;
      }
      throw err;
    }

    // Update ETag and poll interval from headers
    if (response.headers['etag']) {
      this.etag = response.headers['etag'];
    }
    const serverPollInterval = response.headers['x-poll-interval'];
    if (serverPollInterval) {
      const parsed = parseInt(serverPollInterval, 10);
      // Guard against NaN — only apply if valid positive integer
      if (!isNaN(parsed) && parsed > 0) {
        const ms = parsed * 1000;
        if (ms !== this.pollInterval) {
          logger.debug(`[Poller] Server requested poll interval: ${serverPollInterval}s`);
          this.pollInterval = ms;
        }
      }
    }

    const events = response.data || [];
    logger.debug(`[Poller] Fetched ${events.length} events`);

    let newCount = 0;
    for (const event of events) {
      if (this.seenEventIds.has(event.id)) continue;

      // Rolling window cleanup
      if (this.seenEventIds.size >= this.maxSeenSize) {
        const iter = this.seenEventIds.values();
        for (let i = 0; i < 500; i++) this.seenEventIds.delete(iter.next().value);
      }
      this.seenEventIds.add(event.id);
      newCount++;

      if (event.type === 'PushEvent' || event.type === 'CreateEvent') {
        this._handleEvent(event);
      }
    }
    if (newCount > 0) {
      logger.info(`[Poller] ${newCount} new events (${events.length} total)`);
    }
  }

  _handleEvent(event) {
    const repo = event.repo;
    if (!repo) return;

    const payload = event.payload || {};
    const createdAt = event.created_at;

    const normalized = {
      eventId: event.id,
      type: event.type,
      repoName: repo.name,           // "owner/repo"
      repoUrl: `https://github.com/${repo.name}`,
      apiUrl: `https://api.github.com/repos/${repo.name}`,
      createdAt,
      pushedAt: createdAt,
      commits: [],
      ref: payload.ref || null
    };

    if (event.type === 'PushEvent') {
      normalized.commits = (payload.commits || []).map(c => ({
        sha: c.sha,
        message: c.message,
        url: c.url
      }));
      normalized.branch = payload.ref?.replace('refs/heads/', '') || 'unknown';
    }

    if (event.type === 'CreateEvent') {
      normalized.refType = payload.ref_type; // branch / tag / repository
      normalized.description = payload.description || '';
    }

    this.emit('repo', normalized);
  }
}

module.exports = EventsPoller;
