'use strict';

/**
 * PHASE 6 — Queue System
 *
 * Priority queue for repos to scan.
 * Uses Redis if configured, falls back to in-memory.
 * Priority levels: very_active > active > moderate > low
 */

const config = require('../../config/default');
const logger = require('../utils/logger');

const PRIORITY_ORDER = ['very_active', 'active', 'moderate', 'low'];

// ─── In-Memory Queue ──────────────────────────────────────────────────────────

class InMemoryQueue {
  constructor() {
    this.queues = {
      very_active: [],
      active:      [],
      moderate:    [],
      low:         []
    };
    this.seen = new Set(); // dedup by repoName
    this.maxSize = config.queue.maxQueueSize;
  }

  async push(item) {
    const priority = item.priority?.label || 'low';
    const key = item.repoName;

    if (this.seen.has(key)) {
      logger.debug(`[Queue] Skipping duplicate: ${key}`);
      return false;
    }

    const total = this._totalSize();
    if (total >= this.maxSize) {
      // Drop lowest priority to make room
      for (const p of [...PRIORITY_ORDER].reverse()) {
        if (this.queues[p].length > 0) {
          const dropped = this.queues[p].pop();
          this.seen.delete(dropped.repoName);
          logger.debug(`[Queue] Dropped low-priority item to make room: ${dropped.repoName}`);
          break;
        }
      }
    }

    this.queues[priority] = this.queues[priority] || [];
    this.queues[priority].push({ ...item, queuedAt: Date.now() });
    this.seen.add(key);
    logger.debug(`[Queue] Enqueued [${priority}] ${key} | size=${this._totalSize()}`);
    return true;
  }

  async pop() {
    for (const priority of PRIORITY_ORDER) {
      if (this.queues[priority].length > 0) {
        const item = this.queues[priority].shift();
        this.seen.delete(item.repoName);
        return item;
      }
    }
    return null;
  }

  async size() {
    return this._totalSize();
  }

  async stats() {
    return Object.fromEntries(
      PRIORITY_ORDER.map(p => [p, this.queues[p].length])
    );
  }

  _totalSize() {
    return PRIORITY_ORDER.reduce((sum, p) => sum + (this.queues[p]?.length || 0), 0);
  }
}

// ─── Redis Queue ──────────────────────────────────────────────────────────────

class RedisQueue {
  constructor() {
    this.redis = null;
    this.prefix = 'ai_scanner:queue:';
    this.seenKey = 'ai_scanner:seen';
  }

  async connect() {
    const Redis = require('ioredis');
    this.redis = new Redis(config.queue.redisUrl);
    logger.info('[Queue] Connected to Redis');
  }

  _key(priority) {
    return `${this.prefix}${priority}`;
  }

  async push(item) {
    const key = item.repoName;
    const already = await this.redis.sismember(this.seenKey, key);
    if (already) return false;

    const priority = item.priority?.label || 'low';
    const score = Date.now();
    const serialized = JSON.stringify({ ...item, queuedAt: score });

    await this.redis.zadd(this._key(priority), score, serialized);
    await this.redis.sadd(this.seenKey, key);
    await this.redis.expire(this.seenKey, 3600); // expire seen set after 1h
    return true;
  }

  async pop() {
    for (const priority of PRIORITY_ORDER) {
      const results = await this.redis.zpopmin(this._key(priority), 1);
      if (results.length >= 1) {
        try {
          const item = JSON.parse(results[0]);
          await this.redis.srem(this.seenKey, item.repoName);
          return item;
        } catch {}
      }
    }
    return null;
  }

  async size() {
    let total = 0;
    for (const p of PRIORITY_ORDER) {
      total += await this.redis.zcard(this._key(p));
    }
    return total;
  }

  async stats() {
    const stats = {};
    for (const p of PRIORITY_ORDER) {
      stats[p] = await this.redis.zcard(this._key(p));
    }
    return stats;
  }
}

// ─── Factory ──────────────────────────────────────────────────────────────────

let _queue = null;

async function getQueue() {
  if (_queue) return _queue;

  if (config.queue.useRedis) {
    try {
      const rq = new RedisQueue();
      await rq.connect();
      _queue = rq;
      return _queue;
    } catch (err) {
      logger.warn(`[Queue] Redis unavailable (${err.message}), falling back to in-memory`);
    }
  }

  _queue = new InMemoryQueue();
  logger.info('[Queue] Using in-memory queue');
  return _queue;
}

module.exports = { getQueue, InMemoryQueue, RedisQueue };
