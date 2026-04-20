'use strict';

/**
 * Revocation Guide
 *
 * Per-provider step-by-step instructions for revoking a leaked credential.
 * Shown in reports, notifications, and the CLI "leak keys" view.
 */

const GUIDES = {
  openai: {
    name: 'OpenAI',
    revokeUrl: 'https://platform.openai.com/api-keys',
    steps: [
      '1. Go to https://platform.openai.com/api-keys',
      '2. Find the leaked key and click Delete',
      '3. Generate a new key immediately',
      '4. Update all systems using the old key',
      '5. Check usage logs for unauthorized calls: https://platform.openai.com/usage',
    ],
    severity: 'CRITICAL',
    impact: 'Unauthorized LLM usage — can cost thousands of dollars quickly',
  },

  anthropic: {
    name: 'Anthropic',
    revokeUrl: 'https://console.anthropic.com/settings/keys',
    steps: [
      '1. Go to https://console.anthropic.com/settings/keys',
      '2. Revoke the leaked key',
      '3. Generate a replacement key',
      '4. Review usage logs for anomalies',
    ],
    severity: 'CRITICAL',
    impact: 'Unauthorized Claude API usage',
  },

  github: {
    name: 'GitHub',
    revokeUrl: 'https://github.com/settings/tokens',
    steps: [
      '1. Go to https://github.com/settings/tokens',
      '2. Find and Delete the leaked token',
      '3. Review recent actions on your account',
      '4. Check for unauthorized repo access or forks',
      '5. Enable 2FA if not already: https://github.com/settings/security',
    ],
    severity: 'HIGH',
    impact: 'Full repo access, code theft, secret repo exposure',
  },

  stripe: {
    name: 'Stripe',
    revokeUrl: 'https://dashboard.stripe.com/apikeys',
    steps: [
      '1. Go to https://dashboard.stripe.com/apikeys',
      '2. Roll (revoke) the leaked key immediately',
      '3. Check recent charges for unauthorized activity',
      '4. Review webhook events for suspicious calls',
      '5. Consider enabling Stripe Radar rules',
    ],
    severity: 'CRITICAL',
    impact: 'Financial fraud — unauthorized charges possible',
  },

  aws: {
    name: 'AWS',
    revokeUrl: 'https://console.aws.amazon.com/iam/home#/security_credentials',
    steps: [
      '1. Go to IAM > Security credentials',
      '2. Deactivate (or delete) the leaked access key IMMEDIATELY',
      '3. Run: aws sts get-caller-identity --profile leaked (to check what it can access)',
      '4. Check CloudTrail logs for unauthorized API calls',
      '5. Review all IAM policies attached to this key',
      '6. Consider enabling AWS GuardDuty',
    ],
    severity: 'CRITICAL',
    impact: 'Full cloud infrastructure access — crypto mining, data exfiltration, huge bills',
  },

  slack: {
    name: 'Slack',
    revokeUrl: 'https://api.slack.com/apps',
    steps: [
      '1. Go to https://api.slack.com/apps',
      '2. Find the app with the leaked token',
      '3. Under OAuth & Permissions, regenerate the token',
      '4. Check workspace audit logs for unauthorized messages',
    ],
    severity: 'HIGH',
    impact: 'Workspace message access, DM exposure, channel enumeration',
  },

  sendgrid: {
    name: 'SendGrid / Twilio',
    revokeUrl: 'https://app.sendgrid.com/settings/api_keys',
    steps: [
      '1. Go to https://app.sendgrid.com/settings/api_keys',
      '2. Delete the leaked API key',
      '3. Create a new key with minimum required permissions',
      '4. Check email activity for unauthorized sends',
    ],
    severity: 'HIGH',
    impact: 'Mass email sending — spam abuse, reputation damage',
  },

  telegram: {
    name: 'Telegram',
    revokeUrl: 'https://t.me/BotFather',
    steps: [
      '1. Open @BotFather in Telegram',
      '2. Send /revoke and select the bot',
      '3. Get a new token with /token',
      '4. Update all systems with the new token',
    ],
    severity: 'MEDIUM',
    impact: 'Bot impersonation, unauthorized message sending',
  },

  discord: {
    name: 'Discord',
    revokeUrl: 'https://discord.com/developers/applications',
    steps: [
      '1. Go to https://discord.com/developers/applications',
      '2. Select your app > Bot > Regenerate Token',
      '3. Update all deployments with the new token',
      '4. Review Discord audit log for unauthorized actions',
    ],
    severity: 'HIGH',
    impact: 'Bot hijacking, server message access',
  },

  npm: {
    name: 'NPM',
    revokeUrl: 'https://www.npmjs.com/settings/~/tokens',
    steps: [
      '1. Go to https://www.npmjs.com/settings/~/tokens',
      '2. Delete the leaked token',
      '3. Check npm audit log for unauthorized publishes',
      '4. If packages were published, report to npm security: security@npmjs.com',
    ],
    severity: 'CRITICAL',
    impact: 'Supply chain attack — malicious package publishing',
  },

  heroku: {
    name: 'Heroku',
    revokeUrl: 'https://dashboard.heroku.com/account',
    steps: [
      '1. Go to https://dashboard.heroku.com/account',
      '2. Scroll to API Key > Regenerate',
      '3. Review app config vars for exposed secrets',
      '4. Check recent deploys for unauthorized activity',
    ],
    severity: 'HIGH',
    impact: 'App deployment access, config var exposure',
  },

  mailgun: {
    name: 'Mailgun',
    revokeUrl: 'https://app.mailgun.com/settings/api_security',
    steps: [
      '1. Go to https://app.mailgun.com/settings/api_security',
      '2. Reset the API key',
      '3. Check sending logs for abuse',
    ],
    severity: 'HIGH',
    impact: 'Email spam / phishing abuse',
  },

  shopify: {
    name: 'Shopify',
    revokeUrl: 'https://YOUR-STORE.myshopify.com/admin/apps',
    steps: [
      '1. Go to your Shopify Admin > Apps',
      '2. Find the leaked app token and uninstall or regenerate',
      '3. Review orders and customer data access logs',
    ],
    severity: 'CRITICAL',
    impact: 'Store data access, order manipulation, customer PII',
  },

  huggingface: {
    name: 'HuggingFace',
    revokeUrl: 'https://huggingface.co/settings/tokens',
    steps: [
      '1. Go to https://huggingface.co/settings/tokens',
      '2. Delete the leaked token',
      '3. Create a new token with minimum permissions',
    ],
    severity: 'MEDIUM',
    impact: 'Model access, dataset exposure',
  },

  linear: {
    name: 'Linear',
    revokeUrl: 'https://linear.app/settings/api',
    steps: [
      '1. Go to https://linear.app/settings/api',
      '2. Revoke the leaked API key',
      '3. Review issue and project access logs',
    ],
    severity: 'MEDIUM',
    impact: 'Project management data access',
  },

  gitlab: {
    name: 'GitLab',
    revokeUrl: 'https://gitlab.com/-/user_settings/personal_access_tokens',
    steps: [
      '1. Go to https://gitlab.com/-/user_settings/personal_access_tokens',
      '2. Revoke the leaked token',
      '3. Review audit events for unauthorized access',
    ],
    severity: 'HIGH',
    impact: 'Repository and CI/CD access',
  },

  generic: {
    name: 'Unknown Provider',
    revokeUrl: null,
    steps: [
      '1. Identify the service this credential belongs to',
      '2. Log in to that service and revoke/rotate the credential',
      '3. Check usage/audit logs for unauthorized access',
      '4. Update all systems using the old credential',
    ],
    severity: 'MEDIUM',
    impact: 'Unknown — treat as high severity until confirmed',
  },
};

/**
 * Get revocation guide for a provider
 * @param {string} provider
 * @returns {object} guide
 */
function getRevocationGuide(provider) {
  return GUIDES[provider] || GUIDES.generic;
}

/**
 * Format guide as markdown string
 */
function formatGuideMarkdown(provider, repoName, filePath) {
  const g = getRevocationGuide(provider);
  return [
    `## Revocation Guide — ${g.name}`,
    '',
    `**Severity:** ${g.severity}`,
    `**Impact:** ${g.impact}`,
    `**Leaked in:** \`${repoName}\` → \`${filePath}\``,
    '',
    '### Steps to revoke:',
    ...g.steps,
    '',
    g.revokeUrl ? `**Direct link:** ${g.revokeUrl}` : '',
    '',
    '> Rotate the credential BEFORE removing it from git history.',
    '> Even after removal, GitHub caches may retain the file. Contact GitHub Support to fully purge.',
  ].filter(l => l !== undefined).join('\n');
}

/**
 * Format guide as plain text (for Termux / CLI display)
 */
function formatGuidePlain(provider) {
  const g = getRevocationGuide(provider);
  return [
    `Provider : ${g.name}`,
    `Severity : ${g.severity}`,
    `Impact   : ${g.impact}`,
    `URL      : ${g.revokeUrl || 'See provider docs'}`,
    '',
    ...g.steps,
  ].join('\n');
}

module.exports = { getRevocationGuide, formatGuideMarkdown, formatGuidePlain, GUIDES };
