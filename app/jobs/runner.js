const config = require('../config');
const db = require('../db');
const { checkByType } = require('../dns/checker');
const mailer = require('../mailer');
const { now, addSeconds, log } = require('../util/time');
const { buildResultPayload } = require('../util/result');
const { sanitizeForLogAndEmail } = require('../util/sanitize');
const { markDomainAsActive } = require('../util/domain-activation');

const jobs = new Map();
const queue = [];
const queuedKeys = new Set();

function getKey(type, target) {
  return `${type}:${target}`;
}

function canStartJob() {
  return jobs.size < config.MAX_ACTIVE_JOBS;
}

function stopJob(key) {
  const state = jobs.get(key);
  if (!state) return;
  clearInterval(state.intervalId);
  jobs.delete(key);
  log(`Job stopped for ${key}`);
  drainQueue();
}

function enqueue(row, options = {}) {
  const key = getKey(row.type, row.target);
  if (jobs.has(key) || queuedKeys.has(key)) return;
  const initialDelayMs = Math.max(0, Number(options.initialDelayMs) || 0);
  queuedKeys.add(key);
  queue.push({ id: row.id, type: row.type, target: row.target, initialDelayMs });
  log(`Job queued for ${key}`);
}

function drainQueue() {
  while (canStartJob() && queue.length > 0) {
    const row = queue.shift();
    const key = getKey(row.type, row.target);
    queuedKeys.delete(key);
    startJob(row, { initialDelayMs: row.initialDelayMs });
  }
}

async function updateStatus(row, status, failReason, lastResult) {
  const nowDate = now();
  const sets = ['status = ?', 'updated_at = NOW()'];
  const params = [status];

  if (status === 'ACTIVE') {
    sets.push('activated_at = ?');
    params.push(nowDate);
  }

  if (status === 'FAILED' || status === 'EXPIRED') {
    sets.push('fail_reason = ?');
    params.push(failReason || null);
  }

  params.push(row.id);

  const result = await db.query(
    `UPDATE dns_requests SET ${sets.join(', ')} WHERE id = ? AND status = 'PENDING'`,
    params
  );

  if (!result || result.affectedRows === 0) {
    log(`Status update skipped for ${row.type} ${row.target} (already changed)`);
    return false;
  }

  log(`Status updated for ${row.type} ${row.target}: ${status}`);

  let lastResultParsed = lastResult || null;
  if (!lastResultParsed && row.last_check_result_json) {
    try {
      lastResultParsed = JSON.parse(row.last_check_result_json);
    } catch (err) {
      log(`Failed to parse last_check_result_json for ${row.type} ${row.target}: ${err.message}`);
    }
  }

  try {
    await mailer.sendStatusChange({
      id: row.id,
      type: row.type,
      target: row.target,
      status,
      expires_at: row.expires_at,
      fail_reason: failReason || null,
      last_result: lastResultParsed
    });
  } catch (err) {
    log(`Failed to send status email for ${row.type} ${row.target}: ${err.message}`);
  }

  if (status === 'ACTIVE') {
    await markDomainAsActive(row.target);
  }

  return true;
}

async function runCheck(requestId, key) {
  const state = jobs.get(key);
  if (!state || state.running) return;
  state.running = true;

  try {
    const rows = await db.query('SELECT * FROM dns_requests WHERE id = ?', [requestId]);
    if (rows.length === 0) {
      stopJob(key);
      return;
    }

    const row = rows[0];
    if (row.status !== 'PENDING') {
      stopJob(key);
      return;
    }

    const nowDate = now();
    if (row.expires_at && nowDate >= row.expires_at) {
      await updateStatus(row, 'EXPIRED', 'Request expired');
      stopJob(key);
      return;
    }

    const check = await checkByType(row.type, row.target);
    const nextCheckAt = addSeconds(nowDate, config.DNS_POLL_INTERVAL_SECONDS);
    const { payload, json } = buildResultPayload(check, nowDate, nextCheckAt);

    const updateResult = await db.query(
      "UPDATE dns_requests SET last_checked_at = ?, next_check_at = ?, last_check_result_json = ?, updated_at = NOW() WHERE id = ? AND status = 'PENDING'",
      [nowDate, nextCheckAt, json, row.id]
    );

    if (!updateResult || updateResult.affectedRows === 0) {
      stopJob(key);
      return;
    }

    log(`DNS check completed for ${key} (ok=${check.ok})`);

    if (check.ok) {
      await updateStatus(row, 'ACTIVE', null, payload);
      stopJob(key);
    }
  } catch (err) {
    log(`DNS check error for ${key}: ${err.message}`);
    try {
      const reason = sanitizeForLogAndEmail(`Transient DNS error: ${err.message}`, 500);
      await db.query('UPDATE dns_requests SET fail_reason = ?, updated_at = NOW() WHERE id = ?', [
        reason,
        requestId
      ]);
    } catch (updateErr) {
      log(`Failed to update fail_reason for ${key}: ${updateErr.message}`);
    }
  } finally {
    state.running = false;
  }
}

function startJob(row, options = {}) {
  const key = getKey(row.type, row.target);
  if (jobs.has(key)) return;

  const intervalMs = config.DNS_POLL_INTERVAL_SECONDS * 1000;
  const initialDelayMs = Math.max(0, Number(options.initialDelayMs) || 0);
  const state = {
    running: false,
    intervalId: null
  };

  const tick = () => runCheck(row.id, key);
  const runTickWithLog = (label) => {
    tick().catch((err) => log(`${label} for ${key}: ${err.message}`));
  };

  state.intervalId = setInterval(() => {
    runTickWithLog('Job tick failed');
  }, intervalMs);

  jobs.set(key, state);
  log(`Job started for ${key}`);

  if (initialDelayMs > 0) {
    setTimeout(() => {
      runTickWithLog('Initial delayed check failed');
    }, initialDelayMs).unref();
  } else {
    runTickWithLog('Immediate check failed');
  }
}

function startForRequest(row, options = {}) {
  const key = getKey(row.type, row.target);
  if (jobs.has(key)) return;

  if (!canStartJob()) {
    enqueue(row, options);
    return;
  }

  startJob(row, options);
}

async function resumePending() {
  const rows = await db.query(
    "SELECT * FROM dns_requests WHERE status = 'PENDING' AND expires_at > NOW()"
  );

  const intervalMs = config.DNS_POLL_INTERVAL_SECONDS * 1000;
  const jitterCapMs = Math.max(
    0,
    Math.min(config.RESUME_STARTUP_JITTER_MS, Math.max(intervalMs - 100, 0))
  );

  for (const row of rows) {
    const initialDelayMs = jitterCapMs > 0 ? Math.floor(Math.random() * (jitterCapMs + 1)) : 0;
    startForRequest(row, { initialDelayMs });
  }

  drainQueue();
  log(`Resumed ${rows.length} pending DNS jobs`);
}

function getJobStats() {
  return {
    active: jobs.size,
    queued: queue.length,
    max: config.MAX_ACTIVE_JOBS
  };
}

module.exports = {
  startForRequest,
  resumePending,
  getJobStats
};
