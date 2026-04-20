'use strict';

/**
 * Credential Patterns — beyond API keys
 *
 * Detects:
 *  - Database connection strings with credentials (MySQL, Postgres, MongoDB, Redis)
 *  - SMTP / email service credentials
 *  - SSH private keys (RSA, EC, OpenSSH)
 *  - JWT signing secrets
 *  - Generic username:password pairs in config files
 *  - .htpasswd / basic auth credentials
 *  - Private key files (.pem, .p12, .pfx)
 *  - Service account JSON files (GCP)
 *  - AWS credential files (~/.aws/credentials format)
 *  - Docker registry auth
 *  - Kubernetes secret manifests
 *  - Private SSH keys embedded in code
 *
 * IMPORTANT: We detect and report — we do NOT attempt login
 * for personal account credentials (email/social). Only service
 * credentials with dedicated non-destructive test endpoints.
 */

const CREDENTIAL_PATTERNS = [

  // ── Database connection strings ──────────────────────────────────────────
  {
    id: 'db_mysql_conn',
    name: 'MySQL Connection String',
    provider: 'mysql',
    type: 'database',
    canValidate: true,
    regex: /mysql:\/\/([^:]+):([^@]+)@([^/:]+)(?::(\d+))?\/(\S+)/i,
    group: 0,
  },
  {
    id: 'db_postgres_conn',
    name: 'PostgreSQL Connection String',
    provider: 'postgres',
    type: 'database',
    canValidate: true,
    regex: /postgres(?:ql)?:\/\/([^:]+):([^@]+)@([^/:]+)(?::(\d+))?\/(\S+)/i,
    group: 0,
  },
  {
    id: 'db_mongodb_conn',
    name: 'MongoDB Connection String',
    provider: 'mongodb',
    type: 'database',
    canValidate: false, // requires network access to specific host
    regex: /mongodb(?:\+srv)?:\/\/([^:]+):([^@]+)@[^\s"']+/i,
    group: 0,
  },
  {
    id: 'db_redis_conn',
    name: 'Redis Connection String (with password)',
    provider: 'redis',
    type: 'database',
    canValidate: false,
    regex: /redis:\/\/:?([^@\s]{6,})@[^\s"']+/i,
    group: 0,
  },
  {
    id: 'db_mssql_conn',
    name: 'MSSQL Connection String',
    provider: 'mssql',
    type: 'database',
    canValidate: false,
    regex: /(?:Data Source|Server)=[^;]+;.*(?:Password|PWD)=([^;]{6,})/i,
    group: 1,
  },

  // ── SMTP / Email credentials ──────────────────────────────────────────────
  {
    id: 'smtp_credentials',
    name: 'SMTP Credentials',
    provider: 'smtp',
    type: 'email',
    canValidate: true,
    regex: /smtp[s]?:\/\/([^:]+):([^@]+)@([^/:]+)(?::(\d+))?/i,
    group: 0,
  },
  {
    id: 'smtp_password_env',
    name: 'SMTP Password in Config',
    provider: 'smtp',
    type: 'email',
    canValidate: false,
    regex: /(?:SMTP_PASSWORD|MAIL_PASSWORD|EMAIL_PASSWORD|SMTP_PASS)\s*[=:]\s*["']?([^\s"']{8,})["']?/i,
    group: 1,
  },
  {
    id: 'smtp_user_pass_pair',
    name: 'SMTP User + Password Pair',
    provider: 'smtp',
    type: 'email',
    canValidate: false,
    regex: /(?:SMTP_USER|MAIL_USER|EMAIL_USER)\s*[=:]\s*["']?([^@\s"']+@[^@\s"']+)["']?/i,
    group: 1,
    requireContext: /smtp|mail|email/i,
  },

  // ── Private keys / certificates ───────────────────────────────────────────
  {
    id: 'rsa_private_key',
    name: 'RSA Private Key',
    provider: 'ssh',
    type: 'private_key',
    canValidate: false,
    severity: 'CRITICAL',
    regex: /-----BEGIN RSA PRIVATE KEY-----[\s\S]{100,}?-----END RSA PRIVATE KEY-----/,
    group: 0,
  },
  {
    id: 'ec_private_key',
    name: 'EC Private Key',
    provider: 'ssh',
    type: 'private_key',
    canValidate: false,
    severity: 'CRITICAL',
    regex: /-----BEGIN EC PRIVATE KEY-----[\s\S]{50,}?-----END EC PRIVATE KEY-----/,
    group: 0,
  },
  {
    id: 'openssh_private_key',
    name: 'OpenSSH Private Key',
    provider: 'ssh',
    type: 'private_key',
    canValidate: false,
    severity: 'CRITICAL',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]{50,}?-----END OPENSSH PRIVATE KEY-----/,
    group: 0,
  },
  {
    id: 'pkcs8_private_key',
    name: 'PKCS#8 Private Key',
    provider: 'ssl',
    type: 'private_key',
    canValidate: false,
    severity: 'CRITICAL',
    regex: /-----BEGIN PRIVATE KEY-----[\s\S]{50,}?-----END PRIVATE KEY-----/,
    group: 0,
  },

  // ── JWT signing secrets ───────────────────────────────────────────────────
  {
    id: 'jwt_secret_long',
    name: 'JWT Signing Secret',
    provider: 'jwt',
    type: 'auth_secret',
    canValidate: false,
    regex: /(?:jwt[_\-\s]?secret|JWT_SECRET|jwt[_\-\s]?key|signing[_\-\s]?secret)\s*[=:]\s*["']?([A-Za-z0-9_\-./+!@#$%^&*]{16,})["']?/i,
    group: 1,
  },

  // ── Generic username:password in config/env ───────────────────────────────
  {
    id: 'generic_db_password',
    name: 'Database Password',
    provider: 'database',
    type: 'password',
    canValidate: false,
    regex: /(?:DB_PASS(?:WORD)?|DATABASE_PASSWORD|DB_PASSWORD|POSTGRES_PASSWORD|MYSQL_PASSWORD|MONGO_PASSWORD)\s*[=:]\s*["']?([^\s"']{6,})["']?/i,
    group: 1,
  },
  {
    id: 'generic_admin_password',
    name: 'Admin Password in Config',
    provider: 'generic',
    type: 'password',
    canValidate: false,
    regex: /(?:ADMIN_PASSWORD|ROOT_PASSWORD|MASTER_PASSWORD|ADMIN_PASS)\s*[=:]\s*["']?([^\s"']{8,})["']?/i,
    group: 1,
  },
  {
    id: 'basic_auth_header',
    name: 'HTTP Basic Auth Credentials',
    provider: 'http',
    type: 'password',
    canValidate: false,
    regex: /Authorization:\s*Basic\s+([A-Za-z0-9+/]{12,}={0,2})/i,
    group: 1,
  },
  {
    id: 'htpasswd_entry',
    name: '.htpasswd Credential Entry',
    provider: 'apache',
    type: 'password',
    canValidate: false,
    regex: /^([a-zA-Z0-9_\-\.]+):(\$(?:apr)?1\$[^:$\s]{4,}\$[A-Za-z0-9./]{22}|[A-Za-z0-9./]{13})/m,
    group: 0,
  },

  // ── Service account files ─────────────────────────────────────────────────
  {
    id: 'gcp_service_account_json',
    name: 'GCP Service Account JSON',
    provider: 'google',
    type: 'service_account',
    canValidate: false,
    severity: 'CRITICAL',
    regex: /"type"\s*:\s*"service_account"[\s\S]{0,200}"private_key"\s*:/,
    group: 0,
  },
  {
    id: 'aws_credentials_file',
    name: 'AWS Credentials File',
    provider: 'aws',
    type: 'service_account',
    canValidate: false,
    regex: /\[(?:default|[^\]]+)\]\s*\n\s*aws_access_key_id\s*=\s*(AKIA[A-Z0-9]{16})\s*\n\s*aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})/,
    group: 0,
  },

  // ── Docker / Kubernetes ───────────────────────────────────────────────────
  {
    id: 'docker_auth_config',
    name: 'Docker Registry Auth',
    provider: 'docker',
    type: 'service_account',
    canValidate: false,
    regex: /"auth"\s*:\s*"([A-Za-z0-9+/]{20,}={0,2})"/,
    group: 1,
    requireContext: /auths|registry|docker/i,
  },
  {
    id: 'k8s_secret_manifest',
    name: 'Kubernetes Secret (base64)',
    provider: 'kubernetes',
    type: 'service_account',
    canValidate: false,
    regex: /kind:\s*Secret[\s\S]{0,300}data:\s*\n((?:\s+[a-zA-Z0-9_\-]+:\s*[A-Za-z0-9+/=]{16,}\n){1,10})/,
    group: 0,
  },

  // ── FTP / SFTP credentials ────────────────────────────────────────────────
  {
    id: 'ftp_credentials',
    name: 'FTP/SFTP Credentials',
    provider: 'ftp',
    type: 'password',
    canValidate: false,
    regex: /ftp[s]?:\/\/([^:]+):([^@]{6,})@([^\s"'/]+)/i,
    group: 0,
  },

  // ── Credentials in .env format ────────────────────────────────────────────
  {
    id: 'env_secret_key',
    name: 'Secret Key in .env',
    provider: 'generic',
    type: 'secret',
    canValidate: false,
    regex: /^(?:SECRET[_\-]?KEY|APP[_\-]?SECRET|APPLICATION[_\-]?SECRET)\s*=\s*["']?([A-Za-z0-9_\-!@#$%^&*]{16,})["']?$/im,
    group: 1,
  },
  {
    id: 'env_encryption_key',
    name: 'Encryption Key in Config',
    provider: 'generic',
    type: 'secret',
    canValidate: false,
    regex: /(?:ENCRYPTION_KEY|AES_KEY|CRYPTO_KEY|CIPHER_KEY)\s*[=:]\s*["']?([A-Za-z0-9+/=]{16,})["']?/i,
    group: 1,
  },
];

module.exports = { CREDENTIAL_PATTERNS };
