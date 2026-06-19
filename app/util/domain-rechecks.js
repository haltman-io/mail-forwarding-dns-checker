const db = require('../db');
const config = require('../config');
const { now, addSeconds, log } = require('./time');
const { normalizeApprovalType } = require('./domain-approval');
const { safeJsonStringify } = require('./sanitize');

function secondsWithJitter(baseSeconds) {
  const base = Math.max(1, Number(baseSeconds) || 1);
  const jitterPercent = Math.max(0, Number(config.DNS_RECHECK_JITTER_PERCENT) || 0);
  if (jitterPercent === 0) return base;

  const maxOffset = Math.floor((base * jitterPercent) / 100);
  if (maxOffset <= 0) return base;

  const offset = Math.floor(Math.random() * (maxOffset * 2 + 1)) - maxOffset;
  return Math.max(1, base + offset);
}

function nextRecheckAt(baseSeconds, baseDate = now()) {
  return addSeconds(baseDate, secondsWithJitter(baseSeconds));
}

function resultJsonForStorage(result) {
  if (!result) return null;
  if (typeof result === 'string') return result;

  try {
    return JSON.stringify(result);
  } catch (_err) {
    return safeJsonStringify(result, config.RESULT_JSON_MAX_BYTES);
  }
}

async function scheduleRecheckAfterApproval(domainId, type, lastResult) {
  if (!config.DNS_RECHECK_ENABLED) return;

  const normalizedType = normalizeApprovalType(type);
  const scheduledAt = now();
  const nextCheckAt = nextRecheckAt(config.DNS_RECHECK_STABLE_INTERVAL_SECONDS, scheduledAt);
  const lastResultJson = resultJsonForStorage(lastResult);

  await db.query(
    `INSERT INTO domain_dns_rechecks (
       domain_id,
       type,
       status,
       consecutive_failures,
       next_check_at,
       last_ok_at,
       last_check_result_json,
       last_valid_result_json,
       alert_status,
       alert_sequence_count
     )
     VALUES (?, ?, 'OK', 0, ?, ?, ?, ?, 'NONE', 0)
     ON DUPLICATE KEY UPDATE
       status = 'OK',
       consecutive_failures = 0,
       next_check_at = VALUES(next_check_at),
       last_ok_at = VALUES(last_ok_at),
       last_check_result_json = COALESCE(VALUES(last_check_result_json), last_check_result_json),
       last_valid_result_json = COALESCE(VALUES(last_valid_result_json), last_valid_result_json),
       last_error = NULL,
       alert_status = 'NONE',
       alert_opened_at = NULL,
       next_alert_at = NULL,
       alert_sequence_count = 0,
       first_invalid_result_json = NULL,
       last_invalid_result_json = NULL`,
    [domainId, normalizedType, nextCheckAt, scheduledAt, lastResultJson, lastResultJson]
  );

  log(`Domain DNS recheck scheduled: ${normalizedType} domain_id=${domainId}`);
}

module.exports = {
  nextRecheckAt,
  resultJsonForStorage,
  scheduleRecheckAfterApproval,
  secondsWithJitter
};
