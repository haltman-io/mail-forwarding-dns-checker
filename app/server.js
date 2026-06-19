const express = require('express');
const config = require('./config');
const requestRoutes = require('./routes/request');
const checkdnsRoutes = require('./routes/checkdns');
const recheckdnsRoutes = require('./routes/recheckdns');
const jobs = require('./jobs/runner');
const recheckJobs = require('./jobs/rechecker');
const { log } = require('./util/time');
const { sanitizeForLogAndEmail } = require('./util/sanitize');
const { getDnsResolverSummary } = require('./dns/checker');
var cors = require('cors')


const app = express();

app.use(cors());

app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 60;
const rateLimitMap = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap.entries()) {
    if (now - entry.lastSeen > RATE_LIMIT_WINDOW_MS * 10) {
      rateLimitMap.delete(ip);
    }
  }
}, RATE_LIMIT_WINDOW_MS * 5);

app.use((req, res, next) => {
  if (req.method === 'POST' && req.path.startsWith('/request/')) {
    if (!req.is('application/json')) {
      return res.status(415).json({ error: 'unsupported_media_type' });
    }
  }
  return next();
});

app.use((req, res, next) => {
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS, lastSeen: now };

  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + RATE_LIMIT_WINDOW_MS;
  }

  entry.count += 1;
  entry.lastSeen = now;
  rateLimitMap.set(ip, entry);

  if (entry.count > RATE_LIMIT_MAX) {
    return res.status(429).json({ error: 'rate_limited', message: 'Too many requests' });
  }

  return next();
});

app.use(requestRoutes);
app.use(checkdnsRoutes);
app.use(recheckdnsRoutes);

// ── Health check ────────────────────────────────────────────
app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok', uptime: process.uptime() });
});

app.use((err, req, res, next) => {
  const status = err.status || (err.type === 'entity.parse.failed' ? 400 : 500);
  const isClientError = status >= 400 && status < 500;
  const message = err.type === 'entity.parse.failed'
    ? 'invalid_json'
    : isClientError
      ? sanitizeForLogAndEmail(err.message, 500)
      : 'internal_error';

  log(`Error ${status}: ${err.message}`);
  return res.status(status).json({ error: message });
});

const server = app.listen(config.PORT, config.HOST, () => {
  log(`Server listening on ${config.HOST}:${config.PORT}`);
  if (config.MAX_ACTIVE_JOBS !== config.MAX_ACTIVE_JOBS_REQUESTED) {
    log(
      `MAX_ACTIVE_JOBS reduced from ${config.MAX_ACTIVE_JOBS_REQUESTED} to ${config.MAX_ACTIVE_JOBS} to match DB pool limit`
    );
  }
  log(
    `DB pool configured: connection_limit=${config.DB_POOL_CONNECTION_LIMIT}, acquire_timeout_ms=${config.DB_POOL_ACQUIRE_TIMEOUT_MS}, connect_timeout_ms=${config.DB_POOL_CONNECT_TIMEOUT_MS}`
  );
  log(
    `DB query retry configured: retry_count=${config.DB_QUERY_RETRY_COUNT}, retry_delay_ms=${config.DB_QUERY_RETRY_DELAY_MS}`
  );
  const resolverSummary = getDnsResolverSummary();
  log(
    `DNS resolver configured: source=${resolverSummary.source}, servers=${resolverSummary.servers.join(',')}`
  );
  log(
    `DNS polling configured: poll_interval_seconds=${config.DNS_POLL_INTERVAL_SECONDS}, timeout_ms=${config.DNS_TIMEOUT_MS}, status_log_interval_seconds=${config.DNS_STATUS_LOG_INTERVAL_SECONDS}`
  );
  jobs.startStatusReporter();
  jobs.resumePending().catch((err) => {
    log(`Failed to resume jobs: ${err.message}`);
  });
  recheckJobs.start();
});

// ── Graceful shutdown ───────────────────────────────────────
const { pool } = require('./db');

function shutdown(signal) {
  log(`Received ${signal}, shutting down gracefully…`);
  recheckJobs.stop();
  server.close(() => log('HTTP server closed'));
  pool.end().then(() => {
    log('DB pool closed');
    process.exit(0);
  }).catch((err) => {
    log(`Error closing DB pool: ${err.message}`);
    process.exit(1);
  });
  // Force exit after 10 s
  setTimeout(() => {
    log('Forced exit after timeout');
    process.exit(1);
  }, 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
