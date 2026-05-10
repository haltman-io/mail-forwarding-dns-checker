const express = require('express');
const db = require('../db');
const config = require('../config');
const { log, now, addHours, addSeconds } = require('../util/time');
const { extractTargetFromBody } = require('../util/validators');
const { checkByType, describeCheckResult } = require('../dns/checker');
const jobs = require('../jobs/runner');
const mailer = require('../mailer');
const { buildResultPayload } = require('../util/result');
const { markDomainAsActive } = require('../util/domain-activation');
const { sanitizeForLogAndEmail } = require('../util/sanitize');

const router = express.Router();

async function insertRequest(type, target) {
  const expiresAt = addHours(now(), config.DNS_JOB_MAX_AGE_HOURS);
  const result = await db.query(
    'INSERT INTO dns_requests (target, type, status, expires_at) VALUES (?, ?, ?, ?)',
    [target, type, 'PENDING', expiresAt]
  );

  return {
    id: typeof result.insertId === 'bigint' ? Number(result.insertId) : result.insertId,
    target,
    type,
    status: 'PENDING',
    expires_at: expiresAt
  };
}

async function refreshExistingRequest(type, target) {
  const expiresAt = addHours(now(), config.DNS_JOB_MAX_AGE_HOURS);
  await db.query(
    `UPDATE dns_requests
     SET status = ?,
         expires_at = ?,
         activated_at = NULL,
         fail_reason = NULL,
         last_checked_at = NULL,
         next_check_at = NULL,
         last_check_result_json = NULL,
         updated_at = NOW()
     WHERE target = ? AND type = ?`,
    ['PENDING', expiresAt, target, type]
  );

  const rows = await db.query(
    'SELECT * FROM dns_requests WHERE target = ? AND type = ? LIMIT 1',
    [target, type]
  );

  if (rows.length === 0) {
    const err = new Error(`Failed to reload refreshed request for ${type} ${target}`);
    err.code = 'REQUEST_REFRESH_MISSING';
    throw err;
  }

  return rows[0];
}

async function createOrRefreshRequest(type, target) {
  try {
    return {
      row: await insertRequest(type, target),
      created: true
    };
  } catch (err) {
    if (!err || err.code !== 'ER_DUP_ENTRY') {
      throw err;
    }

    return {
      row: await refreshExistingRequest(type, target),
      created: false
    };
  }
}

async function runImmediateCheck(row) {
  const nowDate = now();
  const nextCheckAt = addSeconds(nowDate, config.DNS_POLL_INTERVAL_SECONDS);

  const check = await checkByType(row.type, row.target);

  const { payload, json } = buildResultPayload(check, nowDate, nextCheckAt);

  await db.query(
    'UPDATE dns_requests SET last_checked_at = ?, next_check_at = ?, last_check_result_json = ?, updated_at = NOW() WHERE id = ?',
    [nowDate, nextCheckAt, json, row.id]
  );

  log(`Immediate DNS check completed for ${row.type}:${row.target} (${describeCheckResult(check)})`);

  if (check.ok) {
    const result = await db.query(
      "UPDATE dns_requests SET status = ?, activated_at = ?, updated_at = NOW() WHERE id = ? AND status = 'PENDING'",
      ['ACTIVE', nowDate, row.id]
    );
    const statusActivated = Boolean(result && result.affectedRows > 0);

    if (statusActivated) {
      log(`Status updated for ${row.type} ${row.target}: ACTIVE`);
    }

    try {
      await mailer.sendStatusChange({
        id: row.id,
        type: row.type,
        target: row.target,
        status: 'ACTIVE',
        expires_at: row.expires_at,
        last_result: payload
      });
    } catch (err) {
      log(`Failed to send ACTIVE email for ${row.type} ${row.target}: ${err.message}`);
    }

    if (statusActivated) {
      await markDomainAsActive(row.target);
    }
  }

  return { ok: check.ok };
}

async function handleRequest(type, req, res, next) {
  try {
    const target = extractTargetFromBody(req.body);

    const { row, created } = await createOrRefreshRequest(type, target);

    log(`Request ${created ? 'created' : 'refreshed'} for ${type} ${target} (id=${row.id})`);

    mailer.sendRequestCreated(row).catch((err) => {
      log(`Failed to send request email for ${type} ${target}: ${err.message}`);
    });

    let immediateResult = null;
    try {
      immediateResult = await runImmediateCheck(row);
    } catch (err) {
      log(`Immediate DNS check failed for ${type} ${target}: ${err.message}`, {
        code: err.code || 'ERROR',
        stack: err.stack
      });
      try {
        const reason = sanitizeForLogAndEmail(`Immediate DNS error: ${err.message}`, 500);
        await db.query('UPDATE dns_requests SET fail_reason = ?, updated_at = NOW() WHERE id = ?', [
          reason,
          row.id
        ]);
      } catch (updateErr) {
        log(`Failed to update immediate fail_reason for ${type} ${target}: ${updateErr.message}`);
      }
    }

    const responseId = typeof row.id === 'bigint' ? Number(row.id) : row.id;

    if (immediateResult && immediateResult.ok) {
      return res.status(200).json({
        id: responseId,
        target: row.target,
        type: row.type,
        status: 'ACTIVE',
        expires_at: row.expires_at
      });
    }

    jobs.startForRequest(row);

    return res.status(202).json({
      id: responseId,
      target: row.target,
      type: row.type,
      status: 'PENDING',
      expires_at: row.expires_at
    });
  } catch (err) {
    return next(err);
  }
}

router.post('/request/ui', (req, res, next) => handleRequest('UI', req, res, next));
router.post('/request/email', (req, res, next) => handleRequest('EMAIL', req, res, next));

module.exports = router;
