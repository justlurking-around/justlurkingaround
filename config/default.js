/**
 * Default configuration
 * Override via environment variables or config/local.js
 */
module.exports = {
  github: {
    token: process.env.GITHUB_TOKEN || '',
    apiBase: 'https://api.github.com',
    eventsUrl: 'https://api.github.com/events',
    pollIntervals: {
      veryActive: 60,      // 1 min
      active: 300,         // 5 min
      moderate: 600,       // 10 min
      low: 1500            // 25 min
    },
    maxFileSizeKB: 500,
    maxFilesPerRepo: 200
  },
  scanner: {
    entropyThreshold: 4.0,
    minSecretLength: 16,
    maxSecretLength: 512,
    concurrentRepos: 3,
    concurrentFiles: 5
  },
  queue: {
    useRedis: process.env.USE_REDIS === 'true',
    redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
    maxQueueSize: 1000
  },
  database: {
    connectionString: process.env.DATABASE_URL || '',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432'),
    database: process.env.DB_NAME || 'ai_scanner',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '',
    ssl: process.env.DB_SSL === 'true',
    // Fallback: SQLite-like JSON file if Postgres not configured
    fallbackFile: process.env.DB_FALLBACK_FILE || './data/findings.jsonl'
  },
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    dir: process.env.LOG_DIR || './logs'
  },
  validation: {
    enabled: process.env.VALIDATE_SECRETS !== 'false',
    timeout: 8000,
    maxRetries: 2
  }
};
