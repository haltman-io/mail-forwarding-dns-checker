const dotenv = require('dotenv');
const net = require('node:net');

dotenv.config();

function requireEnv(name) {
  const value = process.env[name];
  if (value === undefined) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function toInt(value, name) {
  const num = parseInt(value, 10);
  if (Number.isNaN(num)) {
    throw new Error(`Invalid integer for ${name}`);
  }
  return num;
}

function toBool(value, defaultValue) {
  if (value === undefined) return defaultValue;
  if (value === 'true' || value === '1') return true;
  if (value === 'false' || value === '0') return false;
  return defaultValue;
}

const dnsServers = process.env.DNS_SERVERS
  ? process.env.DNS_SERVERS.split(',').map((s) => s.trim()).filter(Boolean)
  : [];

const invalidServers = dnsServers.filter((server) => net.isIP(server) === 0);
if (invalidServers.length > 0) {
  throw new Error(`Invalid DNS_SERVERS entries (must be IPs): ${invalidServers.join(', ')}`);
}

const uiCnameAuthorizedIps = process.env.UI_CNAME_AUTHORIZED_IPS
  ? process.env.UI_CNAME_AUTHORIZED_IPS.split(',').map((ip) => ip.trim()).filter(Boolean)
  : [];
const invalidUiCnameAuthorizedIps = uiCnameAuthorizedIps.filter((ip) => net.isIP(ip) === 0);
if (invalidUiCnameAuthorizedIps.length > 0) {
  throw new Error(
    `Invalid UI_CNAME_AUTHORIZED_IPS entries (must be IPs): ${invalidUiCnameAuthorizedIps.join(', ')}`
  );
}

const dbPoolConnectionLimit = Math.max(
  1,
  toInt(process.env.DB_POOL_CONNECTION_LIMIT || '10', 'DB_POOL_CONNECTION_LIMIT')
);
const dbPoolAcquireTimeoutMs = Math.max(
  1000,
  toInt(process.env.DB_POOL_ACQUIRE_TIMEOUT_MS || '15000', 'DB_POOL_ACQUIRE_TIMEOUT_MS')
);
const dbPoolConnectTimeoutMs = Math.max(
  500,
  toInt(process.env.DB_POOL_CONNECT_TIMEOUT_MS || '10000', 'DB_POOL_CONNECT_TIMEOUT_MS')
);
const dbQueryRetryCount = Math.max(
  0,
  toInt(process.env.DB_QUERY_RETRY_COUNT || '2', 'DB_QUERY_RETRY_COUNT')
);
const dbQueryRetryDelayMs = Math.max(
  0,
  toInt(process.env.DB_QUERY_RETRY_DELAY_MS || '300', 'DB_QUERY_RETRY_DELAY_MS')
);
const maxActiveJobsRequested = toInt(
  process.env.MAX_ACTIVE_JOBS || String(dbPoolConnectionLimit),
  'MAX_ACTIVE_JOBS'
);
const maxActiveJobs = Math.max(1, Math.min(maxActiveJobsRequested, dbPoolConnectionLimit));
const resumeStartupJitterMs = Math.max(
  0,
  toInt(process.env.RESUME_STARTUP_JITTER_MS || '5000', 'RESUME_STARTUP_JITTER_MS')
);

const config = {
  HOST: process.env.HOST || '0.0.0.0',
  PORT: toInt(requireEnv('PORT'), 'PORT'),
  DB_HOST: requireEnv('DB_HOST'),
  DB_USER: requireEnv('DB_USER'),
  DB_PASS: requireEnv('DB_PASS'),
  DB_NAME: requireEnv('DB_NAME'),
  DB_PORT: toInt(requireEnv('DB_PORT'), 'DB_PORT'),
  DB_POOL_CONNECTION_LIMIT: dbPoolConnectionLimit,
  DB_POOL_ACQUIRE_TIMEOUT_MS: dbPoolAcquireTimeoutMs,
  DB_POOL_CONNECT_TIMEOUT_MS: dbPoolConnectTimeoutMs,
  DB_QUERY_RETRY_COUNT: dbQueryRetryCount,
  DB_QUERY_RETRY_DELAY_MS: dbQueryRetryDelayMs,

  ADMIN_EMAIL_TO: requireEnv('ADMIN_EMAIL_TO'),
  SMTP_HOST: requireEnv('SMTP_HOST'),
  SMTP_PORT: toInt(requireEnv('SMTP_PORT'), 'SMTP_PORT'),
  SMTP_SECURE: toBool(process.env.SMTP_SECURE, false),
  SMTP_USER: requireEnv('SMTP_USER'),
  SMTP_PASS: requireEnv('SMTP_PASS'),
  SMTP_FROM: requireEnv('SMTP_FROM'),

  DNS_SERVERS: dnsServers,
  DNS_POLL_INTERVAL_SECONDS: toInt(requireEnv('DNS_POLL_INTERVAL_SECONDS'), 'DNS_POLL_INTERVAL_SECONDS'),
  DNS_JOB_MAX_AGE_HOURS: toInt(process.env.DNS_JOB_MAX_AGE_HOURS || '24', 'DNS_JOB_MAX_AGE_HOURS'),
  DNS_TIMEOUT_MS: toInt(requireEnv('DNS_TIMEOUT_MS'), 'DNS_TIMEOUT_MS'),
  DNS_MAX_RECORDS: toInt(process.env.DNS_MAX_RECORDS || '20', 'DNS_MAX_RECORDS'),
  DNS_MAX_TXT_RECORDS: toInt(process.env.DNS_MAX_TXT_RECORDS || '50', 'DNS_MAX_TXT_RECORDS'),
  DNS_MAX_TXT_LENGTH: toInt(process.env.DNS_MAX_TXT_LENGTH || '512', 'DNS_MAX_TXT_LENGTH'),
  DNS_MAX_HOST_LENGTH: toInt(process.env.DNS_MAX_HOST_LENGTH || '253', 'DNS_MAX_HOST_LENGTH'),
  CHECKDNS_MIN_INTERVAL_SECONDS: toInt(
    process.env.CHECKDNS_MIN_INTERVAL_SECONDS || process.env.DNS_POLL_INTERVAL_SECONDS || '300',
    'CHECKDNS_MIN_INTERVAL_SECONDS'
  ),

  MAX_ACTIVE_JOBS: maxActiveJobs,
  MAX_ACTIVE_JOBS_REQUESTED: maxActiveJobsRequested,
  RESUME_STARTUP_JITTER_MS: resumeStartupJitterMs,
  TARGET_COOLDOWN_SECONDS: toInt(process.env.TARGET_COOLDOWN_SECONDS || '60', 'TARGET_COOLDOWN_SECONDS'),
  RESULT_JSON_MAX_BYTES: toInt(process.env.RESULT_JSON_MAX_BYTES || '20000', 'RESULT_JSON_MAX_BYTES'),
  EMAIL_BODY_MAX_LENGTH: toInt(process.env.EMAIL_BODY_MAX_LENGTH || '8000', 'EMAIL_BODY_MAX_LENGTH'),
  CHECKDNS_TOKEN: process.env.CHECKDNS_TOKEN ? process.env.CHECKDNS_TOKEN.trim() : '',

  UI_CNAME_EXPECTED: (process.env.UI_CNAME_EXPECTED || 'forward.haltman.io').toLowerCase(),
  UI_CNAME_AUTHORIZED_IPS: uiCnameAuthorizedIps,
  UI_CNAME_MAX_CHAIN_DEPTH: Math.max(
    1,
    toInt(process.env.UI_CNAME_MAX_CHAIN_DEPTH || '10', 'UI_CNAME_MAX_CHAIN_DEPTH')
  ),
  EMAIL_MX_EXPECTED_HOST: (process.env.EMAIL_MX_EXPECTED_HOST || 'mail.abin.lat').toLowerCase(),
  EMAIL_MX_EXPECTED_PRIORITY: toInt(process.env.EMAIL_MX_EXPECTED_PRIORITY || '10', 'EMAIL_MX_EXPECTED_PRIORITY'),
  EMAIL_DKIM_SELECTOR: (process.env.EMAIL_DKIM_SELECTOR || 's1').toLowerCase(),
  EMAIL_DKIM_CNAME_EXPECTED: (
    process.env.EMAIL_DKIM_CNAME_EXPECTED || 's1._domainkey.dkim.abin.lat'
  ).toLowerCase(),
  EMAIL_SPF_EXPECTED: process.env.EMAIL_SPF_EXPECTED || 'v=spf1 mx -all',
  EMAIL_DMARC_EXPECTED: process.env.EMAIL_DMARC_EXPECTED || 'v=DMARC1; p=none'
};

module.exports = config;
