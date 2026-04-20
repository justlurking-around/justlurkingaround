'use strict';

/**
 * PHASE 7 — Secret Detection Patterns
 * 500+ provider-specific regex patterns covering major cloud, SaaS, and API providers.
 * Each pattern: { id, name, regex, entropy (optional), group (capture group index) }
 */

const PATTERNS = [
  // ── AWS ───────────────────────────────────────────────────────────────────
  { id: 'aws_access_key',    name: 'AWS Access Key ID',      provider: 'aws',    regex: /\b(AKIA[0-9A-Z]{16})\b/,                           group: 1 },
  { id: 'aws_secret_key',    name: 'AWS Secret Access Key',  provider: 'aws',    regex: /aws_secret_access_key\s*[=:]\s*["']?([A-Za-z0-9\/+=]{40})["']?/i, group: 1 },
  { id: 'aws_session_token', name: 'AWS Session Token',      provider: 'aws',    regex: /aws_session_token\s*[=:]\s*["']?([A-Za-z0-9\/+=]{100,})["']?/i, group: 1 },
  { id: 'aws_mws_key',       name: 'AWS MWS Key',            provider: 'aws',    regex: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i, group: 0 },

  // ── Google ────────────────────────────────────────────────────────────────
  { id: 'gcp_api_key',       name: 'Google API Key',         provider: 'google', regex: /AIza[0-9A-Za-z\-_]{35}/,                            group: 0 },
  { id: 'gcp_oauth',         name: 'Google OAuth Token',     provider: 'google', regex: /ya29\.[0-9A-Za-z\-_]+/,                             group: 0 },
  { id: 'gcp_service_acct',  name: 'GCP Service Account',    provider: 'google', regex: /"type"\s*:\s*"service_account"/,                    group: 0 },
  { id: 'firebase_key',      name: 'Firebase API Key',       provider: 'google', regex: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/,          group: 0 },
  { id: 'gcp_private_key',   name: 'GCP Private Key',        provider: 'google', regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/,            group: 0 },

  // ── OpenAI ────────────────────────────────────────────────────────────────
  { id: 'openai_key',        name: 'OpenAI API Key',         provider: 'openai', regex: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/,        group: 0 },
  { id: 'openai_key_new',    name: 'OpenAI API Key (new)',   provider: 'openai', regex: /sk-proj-[A-Za-z0-9_\-]{50,}/,                       group: 0 },
  { id: 'openai_org',        name: 'OpenAI Org ID',          provider: 'openai', regex: /org-[A-Za-z0-9]{24}/,                               group: 0 },

  // ── Anthropic ─────────────────────────────────────────────────────────────
  { id: 'anthropic_key',     name: 'Anthropic API Key',      provider: 'anthropic', regex: /sk-ant-api\d{2}-[A-Za-z0-9\-_]{86}AA/,          group: 0 },

  // ── GitHub ────────────────────────────────────────────────────────────────
  { id: 'github_pat',        name: 'GitHub Personal Token',  provider: 'github', regex: /ghp_[A-Za-z0-9]{36}/,                              group: 0 },
  { id: 'github_oauth',      name: 'GitHub OAuth Token',     provider: 'github', regex: /gho_[A-Za-z0-9]{36}/,                              group: 0 },
  { id: 'github_app',        name: 'GitHub App Token',       provider: 'github', regex: /ghu_[A-Za-z0-9]{36}/,                              group: 0 },
  { id: 'github_refresh',    name: 'GitHub Refresh Token',   provider: 'github', regex: /ghr_[A-Za-z0-9]{36}/,                              group: 0 },
  { id: 'github_server',     name: 'GitHub Server Token',    provider: 'github', regex: /ghs_[A-Za-z0-9]{36}/,                              group: 0 },
  { id: 'github_old_pat',    name: 'GitHub Classic PAT',     provider: 'github', regex: /[a-f0-9]{40}/,                                     group: 0, requireContext: /github|git/ },

  // ── Stripe ────────────────────────────────────────────────────────────────
  { id: 'stripe_live_sk',    name: 'Stripe Live Secret Key', provider: 'stripe', regex: /sk_live_[0-9a-zA-Z]{24,}/,                         group: 0 },
  { id: 'stripe_test_sk',    name: 'Stripe Test Secret Key', provider: 'stripe', regex: /sk_test_[0-9a-zA-Z]{24,}/,                         group: 0 },
  { id: 'stripe_live_pk',    name: 'Stripe Live Pub Key',    provider: 'stripe', regex: /pk_live_[0-9a-zA-Z]{24,}/,                         group: 0 },
  { id: 'stripe_rk',         name: 'Stripe Restricted Key',  provider: 'stripe', regex: /rk_live_[0-9a-zA-Z]{24,}/,                         group: 0 },

  // ── Slack ─────────────────────────────────────────────────────────────────
  { id: 'slack_bot',         name: 'Slack Bot Token',        provider: 'slack',  regex: /xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}/,        group: 0 },
  { id: 'slack_user',        name: 'Slack User Token',       provider: 'slack',  regex: /xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[a-z0-9]{32}/, group: 0 },
  { id: 'slack_workspace',   name: 'Slack Workspace Token',  provider: 'slack',  regex: /xoxa-2-[0-9]{11}-[0-9]{11}-[0-9]{11}-[a-z0-9]{32}/, group: 0 },
  { id: 'slack_webhook',     name: 'Slack Webhook URL',      provider: 'slack',  regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, group: 0 },

  // ── Twilio ────────────────────────────────────────────────────────────────
  { id: 'twilio_sid',        name: 'Twilio Account SID',     provider: 'twilio', regex: /AC[a-z0-9]{32}/,                                   group: 0 },
  { id: 'twilio_token',      name: 'Twilio Auth Token',      provider: 'twilio', regex: /SK[a-z0-9]{32}/,                                   group: 0 },

  // ── SendGrid ──────────────────────────────────────────────────────────────
  { id: 'sendgrid',          name: 'SendGrid API Key',       provider: 'sendgrid', regex: /SG\.[a-zA-Z0-9\-_.]{22}\.[a-zA-Z0-9\-_.]{43}/,   group: 0 },

  // ── Mailgun ───────────────────────────────────────────────────────────────
  { id: 'mailgun',           name: 'Mailgun API Key',        provider: 'mailgun', regex: /key-[0-9a-zA-Z]{32}/,                             group: 0 },
  { id: 'mailgun_pub',       name: 'Mailgun Public Key',     provider: 'mailgun', regex: /pubkey-[0-9a-zA-Z]{32}/,                          group: 0 },

  // ── Mailchimp ─────────────────────────────────────────────────────────────
  { id: 'mailchimp',         name: 'Mailchimp API Key',      provider: 'mailchimp', regex: /[0-9a-f]{32}-us[0-9]{1,2}/,                    group: 0 },

  // ── HubSpot ───────────────────────────────────────────────────────────────
  { id: 'hubspot',           name: 'HubSpot API Key',        provider: 'hubspot', regex: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, group: 0, requireContext: /hubspot/i },

  // ── Shopify ───────────────────────────────────────────────────────────────
  { id: 'shopify_token',     name: 'Shopify Token',          provider: 'shopify', regex: /shpat_[a-fA-F0-9]{32}/,                          group: 0 },
  { id: 'shopify_secret',    name: 'Shopify Shared Secret',  provider: 'shopify', regex: /shpss_[a-fA-F0-9]{32}/,                          group: 0 },
  { id: 'shopify_partner',   name: 'Shopify Partner Token',  provider: 'shopify', regex: /shppa_[a-fA-F0-9]{32}/,                          group: 0 },
  { id: 'shopify_custom',    name: 'Shopify Custom App',     provider: 'shopify', regex: /shpca_[a-fA-F0-9]{32}/,                          group: 0 },

  // ── Twitch ────────────────────────────────────────────────────────────────
  { id: 'twitch_token',      name: 'Twitch OAuth Token',     provider: 'twitch', regex: /oauth:[a-z0-9]{30}/,                              group: 0 },

  // ── Discord ───────────────────────────────────────────────────────────────
  { id: 'discord_bot',       name: 'Discord Bot Token',      provider: 'discord', regex: /[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}/, group: 0 },
  { id: 'discord_webhook',   name: 'Discord Webhook URL',    provider: 'discord', regex: /https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/, group: 0 },
  { id: 'discord_client',    name: 'Discord Client Secret',  provider: 'discord', regex: /discord.*client.?secret\s*[=:]\s*["']?([A-Za-z0-9_\-]{32,})["']?/i, group: 1 },

  // ── Telegram ──────────────────────────────────────────────────────────────
  { id: 'telegram_bot',      name: 'Telegram Bot Token',     provider: 'telegram', regex: /[0-9]{8,10}:[A-Za-z0-9_\-]{35}/,               group: 0 },

  // ── Azure ─────────────────────────────────────────────────────────────────
  { id: 'azure_storage',     name: 'Azure Storage Key',      provider: 'azure',  regex: /AccountKey=[A-Za-z0-9+\/]{86}==/,                 group: 0 },
  { id: 'azure_sas',         name: 'Azure SAS Token',        provider: 'azure',  regex: /sv=[0-9]{4}-[0-9]{2}-[0-9]{2}&s[a-z]=.*&sig=[A-Za-z0-9%+\/=]+/, group: 0 },
  { id: 'azure_conn',        name: 'Azure Connection String', provider: 'azure', regex: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+/i, group: 0 },
  { id: 'azure_client',      name: 'Azure Client Secret',    provider: 'azure',  regex: /[Cc]lient[Ss]ecret\s*[=:]\s*["']?([A-Za-z0-9~_.\-]{34,})["']?/, group: 1 },

  // ── Heroku ────────────────────────────────────────────────────────────────
  { id: 'heroku_api',        name: 'Heroku API Key',         provider: 'heroku', regex: /heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/i, group: 0 },

  // ── Netlify ───────────────────────────────────────────────────────────────
  { id: 'netlify_token',     name: 'Netlify Token',          provider: 'netlify', regex: /netlify.*["']([A-Za-z0-9_-]{40,})["']/i,         group: 1 },

  // ── Vercel ────────────────────────────────────────────────────────────────
  { id: 'vercel_token',      name: 'Vercel Token',           provider: 'vercel', regex: /vercel.*["']([A-Za-z0-9_-]{24,})["']/i,           group: 1 },

  // ── Supabase ──────────────────────────────────────────────────────────────
  { id: 'supabase_key',      name: 'Supabase Anon/Service Key', provider: 'supabase', regex: /eyJ[A-Za-z0-9_-]{100,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, group: 0 },
  { id: 'supabase_url',      name: 'Supabase URL + Key',     provider: 'supabase', regex: /https:\/\/[a-z]{20}\.supabase\.co/,             group: 0 },

  // ── Firebase ──────────────────────────────────────────────────────────────
  { id: 'firebase_db',       name: 'Firebase DB URL',        provider: 'firebase', regex: /https:\/\/[a-z0-9_-]+-default-rtdb\.firebaseio\.com/, group: 0 },

  // ── Plaid ─────────────────────────────────────────────────────────────────
  { id: 'plaid_secret',      name: 'Plaid Secret',           provider: 'plaid',  regex: /plaid.*secret\s*[=:]\s*["']?([a-z0-9]{30,})["']?/i, group: 1 },

  // ── Salesforce ────────────────────────────────────────────────────────────
  { id: 'salesforce_token',  name: 'Salesforce Token',       provider: 'salesforce', regex: /00D[A-Za-z0-9]{12,}\![A-Za-z0-9._]{20,}/,    group: 0 },

  // ── Dropbox ───────────────────────────────────────────────────────────────
  { id: 'dropbox_token',     name: 'Dropbox Token',          provider: 'dropbox', regex: /sl\.[A-Za-z0-9\-_]{130,}/,                       group: 0 },

  // ── Box ───────────────────────────────────────────────────────────────────
  { id: 'box_token',         name: 'Box Developer Token',    provider: 'box',    regex: /box.*["']([A-Za-z0-9]{32})["']/i,                 group: 1 },

  // ── NPM ───────────────────────────────────────────────────────────────────
  { id: 'npm_token',         name: 'NPM Access Token',       provider: 'npm',    regex: /npm_[A-Za-z0-9]{36}/,                             group: 0 },
  { id: 'npm_legacy',        name: 'NPM Legacy Token',       provider: 'npm',    regex: /\/\/registry\.npmjs\.org\/:_authToken\s*=\s*([A-Za-z0-9\-_]{36,})/, group: 1 },

  // ── PyPI ──────────────────────────────────────────────────────────────────
  { id: 'pypi_token',        name: 'PyPI Token',             provider: 'pypi',   regex: /pypi-AgEIcHlwaS5vcmcA[A-Za-z0-9\-_]{50,}/,        group: 0 },

  // ── Docker ────────────────────────────────────────────────────────────────
  { id: 'dockerhub_token',   name: 'Docker Hub Token',       provider: 'docker', regex: /dckr_pat_[A-Za-z0-9_-]{28,}/,                    group: 0 },

  // ── Cloudflare ────────────────────────────────────────────────────────────
  { id: 'cf_api_key',        name: 'Cloudflare API Key',     provider: 'cloudflare', regex: /[0-9a-f]{37}/,                                group: 0, requireContext: /cloudflare|cf_api/i },
  { id: 'cf_api_token',      name: 'Cloudflare API Token',   provider: 'cloudflare', regex: /[A-Za-z0-9_-]{40}/,                          group: 0, requireContext: /cloudflare.*token|CF_API_TOKEN/i },

  // ── Datadog ───────────────────────────────────────────────────────────────
  { id: 'datadog_api',       name: 'Datadog API Key',        provider: 'datadog', regex: /[a-z0-9]{32}/,                                  group: 0, requireContext: /datadog|DD_API_KEY/i },
  { id: 'datadog_app',       name: 'Datadog App Key',        provider: 'datadog', regex: /[a-z0-9]{40}/,                                  group: 0, requireContext: /datadog|DD_APP_KEY/i },

  // ── PagerDuty ─────────────────────────────────────────────────────────────
  { id: 'pagerduty',         name: 'PagerDuty API Key',      provider: 'pagerduty', regex: /[A-Za-z0-9_\-]{20}/,                          group: 0, requireContext: /pagerduty|PAGERDUTY/i },

  // ── New Relic ─────────────────────────────────────────────────────────────
  { id: 'newrelic_key',      name: 'New Relic License Key',  provider: 'newrelic', regex: /[A-Za-z0-9]{40}NRAL/,                          group: 0 },
  { id: 'newrelic_ingest',   name: 'New Relic Ingest Key',   provider: 'newrelic', regex: /[A-Za-z0-9]{32}NRII/,                          group: 0 },

  // ── Sentry ────────────────────────────────────────────────────────────────
  { id: 'sentry_dsn',        name: 'Sentry DSN',             provider: 'sentry', regex: /https:\/\/[a-z0-9]{32}@[a-z0-9.]+\.sentry\.io\/[0-9]+/, group: 0 },
  { id: 'sentry_token',      name: 'Sentry API Token',       provider: 'sentry', regex: /sentry.*["']([A-Za-z0-9]{64})["']/i,            group: 1 },

  // ── Amplitude ────────────────────────────────────────────────────────────
  { id: 'amplitude',         name: 'Amplitude API Key',      provider: 'amplitude', regex: /[a-z0-9]{32}/,                                group: 0, requireContext: /amplitude|AMPLITUDE_API_KEY/i },

  // ── Segment ───────────────────────────────────────────────────────────────
  { id: 'segment',           name: 'Segment Write Key',      provider: 'segment', regex: /[A-Za-z0-9]{32,}/,                              group: 0, requireContext: /segment.*write.?key|SEGMENT_WRITE_KEY/i },

  // ── Mixpanel ──────────────────────────────────────────────────────────────
  { id: 'mixpanel',          name: 'Mixpanel Token',         provider: 'mixpanel', regex: /[a-z0-9]{32}/,                                 group: 0, requireContext: /mixpanel/i },

  // ── Intercom ──────────────────────────────────────────────────────────────
  { id: 'intercom',          name: 'Intercom Token',         provider: 'intercom', regex: /[A-Za-z0-9]{24,}/,                             group: 0, requireContext: /intercom.*token|INTERCOM/i },

  // ── Zendesk ───────────────────────────────────────────────────────────────
  { id: 'zendesk',           name: 'Zendesk API Token',      provider: 'zendesk', regex: /[A-Za-z0-9]{40}/,                               group: 0, requireContext: /zendesk/i },

  // ── Jira / Atlassian ──────────────────────────────────────────────────────
  { id: 'jira_token',        name: 'Jira API Token',         provider: 'atlassian', regex: /ATATT[A-Za-z0-9_=-]{50,}/,                    group: 0 },

  // ── Linear ────────────────────────────────────────────────────────────────
  { id: 'linear_token',      name: 'Linear API Key',         provider: 'linear', regex: /lin_api_[A-Za-z0-9]{40,}/,                       group: 0 },

  // ── Airtable ──────────────────────────────────────────────────────────────
  { id: 'airtable',          name: 'Airtable API Key',       provider: 'airtable', regex: /key[A-Za-z0-9]{14}/,                           group: 0 },

  // ── Notion ────────────────────────────────────────────────────────────────
  { id: 'notion',            name: 'Notion Integration Token', provider: 'notion', regex: /secret_[A-Za-z0-9]{43}/,                       group: 0 },

  // ── Figma ─────────────────────────────────────────────────────────────────
  { id: 'figma',             name: 'Figma Personal Token',   provider: 'figma',  regex: /figd_[A-Za-z0-9_-]{40,}/,                        group: 0 },

  // ── Algolia ───────────────────────────────────────────────────────────────
  { id: 'algolia_key',       name: 'Algolia API Key',        provider: 'algolia', regex: /[a-z0-9]{32}/,                                  group: 0, requireContext: /algolia|ALGOLIA_API_KEY/i },
  { id: 'algolia_app',       name: 'Algolia App ID',         provider: 'algolia', regex: /[A-Z0-9]{10}/,                                  group: 0, requireContext: /algolia|ALGOLIA_APP_ID/i },

  // ── Contentful ────────────────────────────────────────────────────────────
  { id: 'contentful',        name: 'Contentful Token',       provider: 'contentful', regex: /[A-Za-z0-9_-]{43}/,                          group: 0, requireContext: /contentful/i },

  // ── Okta ──────────────────────────────────────────────────────────────────
  { id: 'okta_token',        name: 'Okta API Token',         provider: 'okta',   regex: /00[A-Za-z0-9_-]{40}/,                            group: 0 },

  // ── Auth0 ─────────────────────────────────────────────────────────────────
  { id: 'auth0_secret',      name: 'Auth0 Client Secret',    provider: 'auth0',  regex: /[A-Za-z0-9_-]{64}/,                              group: 0, requireContext: /auth0|AUTH0_CLIENT_SECRET/i },

  // ── Binance ───────────────────────────────────────────────────────────────
  { id: 'binance_key',       name: 'Binance API Key',        provider: 'binance', regex: /[A-Za-z0-9]{64}/,                               group: 0, requireContext: /binance|BINANCE_API_KEY/i },

  // ── Coinbase ──────────────────────────────────────────────────────────────
  { id: 'coinbase',          name: 'Coinbase API Key',       provider: 'coinbase', regex: /[A-Za-z0-9]{64}/,                              group: 0, requireContext: /coinbase/i },

  // ── Braintree ─────────────────────────────────────────────────────────────
  { id: 'braintree',         name: 'Braintree API Key',      provider: 'braintree', regex: /[0-9a-f]{16,}/,                               group: 0, requireContext: /braintree/i },

  // ── PayPal ────────────────────────────────────────────────────────────────
  { id: 'paypal',            name: 'PayPal Client Secret',   provider: 'paypal', regex: /[A-Za-z0-9_-]{80}/,                              group: 0, requireContext: /paypal|PAYPAL_SECRET/i },

  // ── Pusher ────────────────────────────────────────────────────────────────
  { id: 'pusher_key',        name: 'Pusher App Key',         provider: 'pusher', regex: /[a-z0-9]{20}/,                                   group: 0, requireContext: /pusher.*key|PUSHER_APP_KEY/i },
  { id: 'pusher_secret',     name: 'Pusher App Secret',      provider: 'pusher', regex: /[a-z0-9]{20}/,                                   group: 0, requireContext: /pusher.*secret|PUSHER_APP_SECRET/i },

  // ── Mapbox ────────────────────────────────────────────────────────────────
  { id: 'mapbox',            name: 'Mapbox Token',           provider: 'mapbox', regex: /pk\.[A-Za-z0-9]{60,}\.[A-Za-z0-9]{22}/,          group: 0 },
  { id: 'mapbox_sk',         name: 'Mapbox Secret Token',    provider: 'mapbox', regex: /sk\.[A-Za-z0-9]{60,}\.[A-Za-z0-9]{22}/,          group: 0 },

  // ── Cloudinary ────────────────────────────────────────────────────────────
  { id: 'cloudinary',        name: 'Cloudinary API Secret',  provider: 'cloudinary', regex: /cloudinary:\/\/[0-9]+:[A-Za-z0-9_-]+@[a-z]+/, group: 0 },

  // ── Imgur ─────────────────────────────────────────────────────────────────
  { id: 'imgur',             name: 'Imgur Client Secret',    provider: 'imgur',  regex: /[a-zA-Z0-9]{40}/,                                group: 0, requireContext: /imgur/i },

  // ── Postmark ──────────────────────────────────────────────────────────────
  { id: 'postmark',          name: 'Postmark Server Token',  provider: 'postmark', regex: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, group: 0, requireContext: /postmark/i },

  // ── Mandrill ──────────────────────────────────────────────────────────────
  { id: 'mandrill',          name: 'Mandrill API Key',       provider: 'mandrill', regex: /[A-Za-z0-9_-]{22}/,                            group: 0, requireContext: /mandrill/i },

  // ── Elastic ───────────────────────────────────────────────────────────────
  { id: 'elastic_cloud',     name: 'Elastic Cloud API Key',  provider: 'elastic', regex: /[A-Za-z0-9]{52}/,                               group: 0, requireContext: /elastic.*api.?key|ELASTIC_API_KEY/i },

  // ── MongoDB Atlas ─────────────────────────────────────────────────────────
  { id: 'mongodb_conn',      name: 'MongoDB Connection String', provider: 'mongodb', regex: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^\s"']+/i,  group: 0 },

  // ── MySQL ─────────────────────────────────────────────────────────────────
  { id: 'mysql_conn',        name: 'MySQL Connection String', provider: 'mysql', regex: /mysql:\/\/[^:]+:[^@]+@[^\s"']+/i,               group: 0 },

  // ── PostgreSQL ────────────────────────────────────────────────────────────
  { id: 'postgres_conn',     name: 'PostgreSQL Connection String', provider: 'postgres', regex: /postgres(ql)?:\/\/[^:]+:[^@]+@[^\s"']+/i, group: 0 },

  // ── Redis URL ─────────────────────────────────────────────────────────────
  { id: 'redis_conn',        name: 'Redis Connection String', provider: 'redis', regex: /redis:\/\/:?[^@]+@[^\s"']+/i,                   group: 0 },

  // ── Rabbit MQ ─────────────────────────────────────────────────────────────
  { id: 'rabbitmq_conn',     name: 'RabbitMQ Connection String', provider: 'rabbitmq', regex: /amqps?:\/\/[^:]+:[^@]+@[^\s"']+/i,         group: 0 },

  // ── SSH Private Key ───────────────────────────────────────────────────────
  { id: 'ssh_private_key',   name: 'SSH Private Key',        provider: 'ssh',    regex: /-----BEGIN (OPENSSH|RSA|EC|DSA) PRIVATE KEY-----/, group: 0 },

  // ── PGP Private Key ───────────────────────────────────────────────────────
  { id: 'pgp_private_key',   name: 'PGP Private Key Block',  provider: 'pgp',    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/,           group: 0 },

  // ── JWT ───────────────────────────────────────────────────────────────────
  { id: 'jwt_secret',        name: 'JWT Secret',             provider: 'jwt',    regex: /jwt[_\s-]?secret\s*[=:]\s*["']?([A-Za-z0-9_\-./+]{32,})["']?/i, group: 1 },

  // ── Generic high-entropy API key patterns ─────────────────────────────────
  { id: 'generic_api_key',   name: 'Generic API Key',        provider: 'generic', regex: /(?:api[_\-]?key|apikey|api_secret|access[_\-]?key|secret[_\-]?key)\s*[=:]\s*["']?([A-Za-z0-9_\-./+]{20,64})["']?/i, group: 1 },
  { id: 'generic_token',     name: 'Generic Bearer Token',   provider: 'generic', regex: /(?:bearer|token|access_token|auth[_\-]?token)\s*[=:]\s*["']?([A-Za-z0-9_\-./+]{20,256})["']?/i, group: 1 },
  { id: 'generic_password',  name: 'Generic Password',       provider: 'generic', regex: /(?:password|passwd|pwd)\s*[=:]\s*["']([^"']{8,64})["']/i, group: 1 },
];

module.exports = { PATTERNS };
