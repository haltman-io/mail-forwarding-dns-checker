const config = require('../config');
const db = require('../db');
const { checkByType, describeCheckResult } = require('../dns/checker');
const mailer = require('../mailer');
const { buildResultPayload } = require('../util/result');
const { sanitizeForLogAndEmail } = require('../util/sanitize');
const { now, addSeconds, log } = require('../util/time');
const { getApprovalColumn, normalizeApprovalType } = require('../util/domain-approval');
const { nextRecheckAt } = require('../util/domain-rechecks');

let intervalId = null;
let running = false;
let forcedRunning = false;
let lastSummarySentAtMs = 0;

function toCount(value) {
  if (typeof value === 'bigint') return Number(value);
  const num = Number(value);
  return Number.isFinite(num) ? num : 0;
}

function dateOrNull(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

function parseJsonOrNull(value) {
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch (_err) {
    return null;
  }
}

function isMissingSchemaError(err) {
  return (
    err &&
    (err.code === 'ER_NO_SUCH_TABLE' ||
      err.code === 'ER_BAD_FIELD_ERROR' ||
      err.errno === 1146 ||
      err.errno === 1054)
  );
}

function statusForFailures(failures) {
  if (failures >= config.DNS_RECHECK_FAILURE_THRESHOLD) return 'INVALID';
  if (failures === 1) return 'WARNING';
  return 'DEGRADED';
}

function getApprovalValue(row, type) {
  const approvalColumn = getApprovalColumn(type);
  return Number(row[approvalColumn]) === 1 ? 1 : 0;
}

function getLastValidResult(row) {
  return parseJsonOrNull(row.last_valid_result_json) || parseJsonOrNull(row.last_check_result_json);
}

function buildErrorCheck(row, err) {
  const message = sanitizeForLogAndEmail(err && err.message ? err.message : 'DNS recheck failed', 500);
  return {
    ok: false,
    missing: [
      {
        key: 'DNS_QUERY',
        type: 'DNS',
        name: row.domain_name,
        expected: `${row.type} DNS requirements`,
        found: [],
        ok: false,
        error: message
      }
    ],
    snapshot: {
      error: message,
      error_code: err && err.code ? String(err.code) : 'ERROR'
    }
  };
}

function summarizeFailure(check, checkError) {
  if (checkError) {
    return sanitizeForLogAndEmail(`DNS recheck error: ${checkError.message}`, 500);
  }

  const missing = Array.isArray(check && check.missing) ? check.missing : [];
  const failedKeys = missing
    .filter((item) => item && !item.ok)
    .map((item) => item.key || item.type || 'UNKNOWN')
    .filter(Boolean);

  if (failedKeys.length === 0) return 'DNS requirements are not satisfied';
  return sanitizeForLogAndEmail(`Failed DNS requirements: ${failedKeys.join(', ')}`, 500);
}

function shouldSendFailureAlert(row, nextStatus, nextFailures, thresholdReached, checkedAt) {
  if (!config.DNS_RECHECK_ALERTS_ENABLED) return false;
  if (thresholdReached) {
    return row.status !== 'INVALID' || row.alert_status !== 'DISABLED' || getApprovalValue(row, row.type) === 1;
  }
  if (nextFailures === 1) return true;
  if (row.status !== nextStatus) return true;

  const nextAlertAt = dateOrNull(row.next_alert_at);
  return Boolean(nextAlertAt && checkedAt >= nextAlertAt);
}

function buildAlertDetails(row, eventType, payload, previousValidResult, checkedAt, nextCheckAt, nextFailures, approvalValue) {
  const remainingFailures = Math.max(config.DNS_RECHECK_FAILURE_THRESHOLD - nextFailures, 0);
  const disableAt = remainingFailures === 0
    ? checkedAt
    : addSeconds(checkedAt, remainingFailures * config.DNS_RECHECK_FAILED_INTERVAL_SECONDS);

  return {
    eventType,
    domain: row.domain_name,
    type: row.type,
    active: Number(row.active) === 1,
    approvalColumn: getApprovalColumn(row.type),
    approvalValue,
    currentResult: payload,
    previousValidResult,
    consecutiveFailures: nextFailures,
    threshold: config.DNS_RECHECK_FAILURE_THRESHOLD,
    remainingFailures,
    checkedAt,
    nextCheckAt,
    disableAt
  };
}

async function markAlertSent(recheckId, sentAt, nextAlertAt) {
  await db.query(
    `UPDATE domain_dns_rechecks
     SET last_alert_sent_at = ?,
         next_alert_at = ?,
         updated_at = NOW()
     WHERE id = ?`,
    [sentAt, nextAlertAt, recheckId]
  );
}

async function sendFailureAlert(row, nextStatus, nextFailures, thresholdReached, payload, previousValidResult, checkedAt, nextCheckAt) {
  const eventType = thresholdReached
    ? 'RECHECK_INVALID_DISABLED'
    : nextFailures === 1
      ? 'RECHECK_WARNING'
      : 'RECHECK_DEGRADED';
  const approvalValue = thresholdReached ? 0 : getApprovalValue(row, row.type);
  const details = buildAlertDetails(
    row,
    eventType,
    payload,
    previousValidResult,
    checkedAt,
    nextCheckAt,
    nextFailures,
    approvalValue
  );

  if (eventType === 'RECHECK_INVALID_DISABLED') {
    await mailer.sendRecheckDisabled(details);
    await markAlertSent(row.id, checkedAt, null);
    return;
  }

  if (eventType === 'RECHECK_WARNING') {
    await mailer.sendRecheckWarning(details);
  } else {
    await mailer.sendRecheckDegraded(details);
  }

  await markAlertSent(
    row.id,
    checkedAt,
    addSeconds(checkedAt, config.DNS_RECHECK_ALERT_FOLLOWUP_INTERVAL_SECONDS)
  );
}

async function sendRecoveryAlert(row, payload, previousValidResult, checkedAt, nextCheckAt) {
  if (!config.DNS_RECHECK_ALERTS_ENABLED) return;

  const details = buildAlertDetails(
    row,
    'RECHECK_RECOVERED',
    payload,
    previousValidResult,
    checkedAt,
    nextCheckAt,
    0,
    1
  );

  await mailer.sendRecheckRecovered(details);
}

async function updateApprovalFlag(row, value) {
  const approvalColumn = getApprovalColumn(row.type);
  await db.query(`UPDATE domain SET ${approvalColumn} = ? WHERE id = ?`, [value ? 1 : 0, row.domain_id]);
}

async function handleSuccessfulRecheck(row, check, checkedAt) {
  const nextIntervalSeconds = Number(row.active) === 1
    ? config.DNS_RECHECK_STABLE_INTERVAL_SECONDS
    : config.DNS_RECHECK_INACTIVE_INTERVAL_SECONDS;
  const nextCheckAt = nextRecheckAt(nextIntervalSeconds, checkedAt);
  const { payload, json } = buildResultPayload(check, checkedAt, nextCheckAt);
  const previousValidResult = getLastValidResult(row);
  const wasFailing =
    row.status !== 'OK' ||
    toCount(row.consecutive_failures) > 0 ||
    row.alert_status === 'OPEN' ||
    row.alert_status === 'DISABLED';

  await updateApprovalFlag(row, 1);
  await db.query(
    `UPDATE domain_dns_rechecks
     SET status = 'OK',
         consecutive_failures = 0,
         last_checked_at = ?,
         next_check_at = ?,
         last_ok_at = ?,
         last_check_result_json = ?,
         last_valid_result_json = ?,
         last_error = NULL,
         alert_status = 'NONE',
         alert_opened_at = NULL,
         next_alert_at = NULL,
         alert_sequence_count = 0,
         first_invalid_result_json = NULL,
         last_invalid_result_json = NULL,
         updated_at = NOW()
     WHERE id = ?`,
    [checkedAt, nextCheckAt, checkedAt, json, json, row.id]
  );

  log(`Stable DNS recheck OK for ${row.type}:${row.domain_name} (${describeCheckResult(check)})`);

  if (wasFailing) {
    try {
      await sendRecoveryAlert(row, payload, previousValidResult, checkedAt, nextCheckAt);
    } catch (err) {
      log(`Failed to send DNS recheck recovery email for ${row.type} ${row.domain_name}: ${err.message}`);
    }
  }

  return {
    domain: row.domain_name,
    type: row.type,
    ok: true,
    status: 'OK',
    consecutiveFailures: 0,
    approvalColumn: getApprovalColumn(row.type),
    approvalValue: 1,
    nextCheckAt,
    error: null
  };
}

async function handleFailedRecheck(row, check, checkError, checkedAt) {
  const previousFailures = toCount(row.consecutive_failures);
  const nextFailures = previousFailures + 1;
  const nextStatus = statusForFailures(nextFailures);
  const nextCheckAt = nextRecheckAt(config.DNS_RECHECK_FAILED_INTERVAL_SECONDS, checkedAt);
  const { payload, json } = buildResultPayload(check, checkedAt, nextCheckAt);
  const previousValidResult = getLastValidResult(row);
  const failureReason = summarizeFailure(check, checkError);
  const approvalCurrentlyEnabled = getApprovalValue(row, row.type) === 1;
  const thresholdReached = nextFailures >= config.DNS_RECHECK_FAILURE_THRESHOLD;
  const disableNow = thresholdReached && approvalCurrentlyEnabled;
  const alertStatus = thresholdReached ? 'DISABLED' : 'OPEN';
  const existingNextAlertAt = dateOrNull(row.next_alert_at);
  const storedNextAlertAt = alertStatus === 'OPEN'
    ? existingNextAlertAt || addSeconds(checkedAt, config.DNS_RECHECK_ALERT_FOLLOWUP_INTERVAL_SECONDS)
    : null;

  if (disableNow) {
    await updateApprovalFlag(row, 0);
  }

  await db.query(
    `UPDATE domain_dns_rechecks
     SET status = ?,
         consecutive_failures = ?,
         last_checked_at = ?,
         next_check_at = ?,
         last_check_result_json = ?,
         last_error = ?,
         alert_status = ?,
         alert_opened_at = COALESCE(alert_opened_at, ?),
         next_alert_at = ?,
         alert_sequence_count = ?,
         first_invalid_result_json = COALESCE(first_invalid_result_json, ?),
         last_invalid_result_json = ?,
         updated_at = NOW()
     WHERE id = ?`,
    [
      nextStatus,
      nextFailures,
      checkedAt,
      nextCheckAt,
      json,
      failureReason,
      alertStatus,
      checkedAt,
      storedNextAlertAt,
      nextFailures,
      json,
      json,
      row.id
    ]
  );

  log(
    `Stable DNS recheck failed for ${row.type}:${row.domain_name} status=${nextStatus} failures=${nextFailures}/${config.DNS_RECHECK_FAILURE_THRESHOLD} (${failureReason})`
  );

  if (shouldSendFailureAlert(row, nextStatus, nextFailures, thresholdReached, checkedAt)) {
    try {
      await sendFailureAlert(
        row,
        nextStatus,
        nextFailures,
        thresholdReached,
        payload,
        previousValidResult,
        checkedAt,
        nextCheckAt
      );
    } catch (err) {
      log(`Failed to send DNS recheck alert for ${row.type} ${row.domain_name}: ${err.message}`);
    }
  }

  return {
    domain: row.domain_name,
    type: row.type,
    ok: false,
    status: nextStatus,
    consecutiveFailures: nextFailures,
    approvalColumn: getApprovalColumn(row.type),
    approvalValue: thresholdReached ? 0 : getApprovalValue(row, row.type),
    nextCheckAt,
    error: failureReason
  };
}

async function processRecheck(row) {
  row.type = normalizeApprovalType(row.type);
  const checkedAt = now();
  let check;
  let checkError = null;

  try {
    check = await checkByType(row.type, row.domain_name);
  } catch (err) {
    checkError = err;
    check = buildErrorCheck(row, err);
  }

  if (check.ok) {
    return handleSuccessfulRecheck(row, check, checkedAt);
  }

  return handleFailedRecheck(row, check, checkError, checkedAt);
}

async function getDueRows() {
  return db.query(
    `SELECT
       r.*,
       d.id AS domain_id,
       d.name AS domain_name,
       d.active,
       d.active_mx,
       d.active_ui
     FROM domain_dns_rechecks r
     JOIN domain d ON d.id = r.domain_id
     WHERE r.next_check_at <= NOW()
     ORDER BY r.next_check_at ASC
     LIMIT ?`,
    [config.DNS_RECHECK_BATCH_SIZE]
  );
}

async function getRecheckRowsForForce(target = null) {
  const params = [];
  const where = [];

  if (target) {
    where.push('d.name = ?');
    params.push(target);
  }

  const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';
  return db.query(
    `SELECT
       r.*,
       d.id AS domain_id,
       d.name AS domain_name,
       d.active,
       d.active_mx,
       d.active_ui
     FROM domain_dns_rechecks r
     JOIN domain d ON d.id = r.domain_id
     ${whereSql}
     ORDER BY d.name ASC, r.type ASC`,
    params
  );
}

function emptyDomainSummary() {
  return {
    totalDomains: 0,
    adminEnabled: 0,
    adminDisabled: 0,
    emailValid: 0,
    emailInvalid: 0,
    uiValid: 0,
    uiInvalid: 0,
    bothValid: 0,
    bothInvalid: 0,
    domains: []
  };
}

async function getDomainSummary(target = null) {
  const params = [];
  const where = [];

  if (target) {
    where.push('d.name = ?');
    params.push(target);
  }

  const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';
  const rows = await db.query(
    `SELECT
       d.name,
       d.active,
       d.active_mx,
       d.active_ui,
       r.type,
       r.status,
       r.consecutive_failures,
       r.next_check_at,
       r.last_error
     FROM domain d
     LEFT JOIN domain_dns_rechecks r ON r.domain_id = d.id
     ${whereSql}
     ORDER BY d.name ASC, r.type ASC`,
    params
  );

  const byDomain = new Map();
  for (const row of rows) {
    if (!byDomain.has(row.name)) {
      const active = Number(row.active) === 1;
      const activeMx = Number(row.active_mx) === 1;
      const activeUi = Number(row.active_ui) === 1;
      byDomain.set(row.name, {
        name: row.name,
        active,
        activeMx,
        activeUi,
        emailValid: active && activeMx,
        uiValid: active && activeUi,
        rechecks: {}
      });
    }

    if (row.type) {
      byDomain.get(row.name).rechecks[row.type] = {
        status: row.status,
        consecutiveFailures: toCount(row.consecutive_failures),
        nextCheckAt: row.next_check_at,
        lastError: row.last_error || null
      };
    }
  }

  const summary = emptyDomainSummary();
  summary.domains = Array.from(byDomain.values());
  summary.totalDomains = summary.domains.length;

  for (const domain of summary.domains) {
    if (domain.active) summary.adminEnabled += 1;
    else summary.adminDisabled += 1;

    if (domain.emailValid) summary.emailValid += 1;
    else summary.emailInvalid += 1;

    if (domain.uiValid) summary.uiValid += 1;
    else summary.uiInvalid += 1;

    if (domain.emailValid && domain.uiValid) summary.bothValid += 1;
    if (!domain.emailValid && !domain.uiValid) summary.bothInvalid += 1;
  }

  return summary;
}

function buildForceScope(scope, target) {
  return {
    scope,
    target: target || null,
    label: scope === 'TARGET' ? `target ${target}` : 'all domains'
  };
}

async function runForcedRechecks(scopeDetails) {
  if (running || forcedRunning) {
    const err = new Error('DNS recheck worker is already running');
    err.code = 'DNS_RECHECK_BUSY';
    err.status = 409;
    throw err;
  }

  forcedRunning = true;
  const startedAt = now();
  try {
    const rows = await getRecheckRowsForForce(scopeDetails.target);
    const initialSummary = await getDomainSummary(scopeDetails.target);

    try {
      await mailer.sendForcedRecheckStarted({
        ...scopeDetails,
        startedAt,
        domainCount: initialSummary.totalDomains,
        recheckCount: rows.length
      });
    } catch (err) {
      log(`Failed to send forced DNS recheck start email: ${err.message}`);
    }

    const results = [];
    for (const row of rows) {
      try {
        const result = await processRecheck(row);
        results.push(result);
      } catch (err) {
        const message = sanitizeForLogAndEmail(err.message, 500);
        results.push({
          domain: row.domain_name,
          type: row.type,
          ok: false,
          status: 'ERROR',
          consecutiveFailures: toCount(row.consecutive_failures),
          approvalColumn: getApprovalColumn(row.type),
          approvalValue: getApprovalValue(row, row.type),
          nextCheckAt: row.next_check_at,
          error: message
        });
        log(`Forced DNS recheck failed for ${row.type}:${row.domain_name}: ${message}`, {
          code: err.code || 'ERROR',
          stack: err.stack
        });
      }
    }

    const completedAt = now();
    const finalSummary = await getDomainSummary(scopeDetails.target);
    const completedDetails = {
      ...scopeDetails,
      startedAt,
      completedAt,
      durationSeconds: Math.max(0, Math.round((completedAt.getTime() - startedAt.getTime()) / 1000)),
      processedRechecks: results.length,
      successfulRechecks: results.filter((result) => result && result.ok).length,
      failedRechecks: results.filter((result) => result && result.ok === false).length,
      results,
      summary: finalSummary
    };

    try {
      await mailer.sendForcedRecheckCompleted(completedDetails);
    } catch (err) {
      log(`Failed to send forced DNS recheck completion email: ${err.message}`);
    }

    return completedDetails;
  } finally {
    forcedRunning = false;
  }
}

async function forceRecheckAll() {
  return runForcedRechecks(buildForceScope('ALL', null));
}

async function forceRecheckTarget(target) {
  return runForcedRechecks(buildForceScope('TARGET', target));
}

async function sendPeriodicSummaryIfDue() {
  if (!config.DNS_RECHECK_ALERTS_ENABLED) return;
  if (config.DNS_RECHECK_ALERT_SUMMARY_INTERVAL_SECONDS <= 0) return;

  const nowMs = Date.now();
  const intervalMs = config.DNS_RECHECK_ALERT_SUMMARY_INTERVAL_SECONDS * 1000;
  if (lastSummarySentAtMs > 0 && nowMs - lastSummarySentAtMs < intervalMs) return;

  const incidents = await db.query(
    `SELECT
       r.id,
       r.type,
       r.status,
       r.consecutive_failures,
       r.next_check_at,
       r.last_error,
       r.alert_status,
       d.name AS domain_name,
       d.active,
       d.active_mx,
       d.active_ui
     FROM domain_dns_rechecks r
     JOIN domain d ON d.id = r.domain_id
     WHERE r.alert_status IN ('OPEN', 'DISABLED')
     ORDER BY r.updated_at DESC
     LIMIT 20`
  );

  if (incidents.length === 0) return;

  await mailer.sendRecheckPeriodicSummary({
    generatedAt: now(),
    incidents: incidents.map((incident) => ({
      domain: incident.domain_name,
      type: incident.type,
      status: incident.status,
      alertStatus: incident.alert_status,
      active: Number(incident.active) === 1,
      approvalColumn: getApprovalColumn(incident.type),
      approvalValue: getApprovalValue(incident, incident.type),
      consecutiveFailures: toCount(incident.consecutive_failures),
      threshold: config.DNS_RECHECK_FAILURE_THRESHOLD,
      nextCheckAt: incident.next_check_at,
      lastError: incident.last_error
    }))
  });

  lastSummarySentAtMs = nowMs;
}

async function processDueRechecks() {
  if (!config.DNS_RECHECK_ENABLED) return;

  let rows;
  try {
    rows = await getDueRows();
  } catch (err) {
    if (isMissingSchemaError(err)) {
      log(
        `Stable DNS recheck worker disabled because the schema is missing: ${err.message}. Apply sql/schema.sql, then restart the service.`
      );
      stop();
      return;
    }

    throw err;
  }

  for (const row of rows) {
    try {
      await processRecheck(row);
    } catch (err) {
      log(`Stable DNS recheck processing failed for row ${row.id}: ${err.message}`, {
        code: err.code || 'ERROR',
        stack: err.stack
      });
    }
  }

  try {
    await sendPeriodicSummaryIfDue();
  } catch (err) {
    log(`DNS recheck periodic summary failed: ${err.message}`);
  }
}

function start() {
  if (!config.DNS_RECHECK_ENABLED) {
    log('Stable DNS recheck worker disabled by DNS_RECHECK_ENABLED=false');
    return;
  }

  if (intervalId) return;

  const intervalMs = config.DNS_RECHECK_WORKER_INTERVAL_SECONDS * 1000;
  intervalId = setInterval(() => {
    if (running || forcedRunning) return;
    running = true;
    processDueRechecks()
      .catch((err) => {
        log(`Stable DNS recheck worker tick failed: ${err.message}`, {
          code: err.code || 'ERROR',
          stack: err.stack
        });
      })
      .finally(() => {
        running = false;
      });
  }, intervalMs);
  intervalId.unref();

  log(
    `Stable DNS recheck worker enabled every ${config.DNS_RECHECK_WORKER_INTERVAL_SECONDS}s stable_interval=${config.DNS_RECHECK_STABLE_INTERVAL_SECONDS}s failed_interval=${config.DNS_RECHECK_FAILED_INTERVAL_SECONDS}s inactive_interval=${config.DNS_RECHECK_INACTIVE_INTERVAL_SECONDS}s failure_threshold=${config.DNS_RECHECK_FAILURE_THRESHOLD}`
  );

  running = true;
  processDueRechecks()
    .catch((err) => {
      log(`Initial stable DNS recheck worker tick failed: ${err.message}`);
    })
    .finally(() => {
      running = false;
    });
}

function stop() {
  if (!intervalId) return;
  clearInterval(intervalId);
  intervalId = null;
}

module.exports = {
  start,
  stop,
  processDueRechecks,
  forceRecheckAll,
  forceRecheckTarget,
  getDomainSummary
};
