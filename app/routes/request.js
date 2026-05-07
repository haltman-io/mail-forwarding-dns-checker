const express = require('express');
const db = require('../db');
const config = require('../config');
const { log, now, addHours, addSeconds } = require('../util/time');
const { extractTargetFromBody } = require('../util/validators');
const { checkByType } = require('../dns/checker');
const jobs = require('../jobs/runner');
const mailer = require('../mailer');
const { buildResultPayload } = require('../util/result');
const { markDomainAsActive } = require('../util/domain-activation');

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

async function enforceCooldown(target, type) {
  if (config.TARGET_COOLDOWN_SECONDS <= 0) return;
  const rows = await db.query(
    'SELECT created_at FROM dns_requests WHERE target = ? AND type = ? ORDER BY created_at DESC LIMIT 1',
    [target, type]
  );

  if (rows.length === 0) return;
  const lastCreated = rows[0].created_at ? new Date(rows[0].created_at).getTime() : 0;
  const nowMs = Date.now();
  if (nowMs - lastCreated < config.TARGET_COOLDOWN_SECONDS * 1000) {
    const err = new Error('target is in cooldown window');
    err.status = 429;
    throw err;
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

    const stats = jobs.getJobStats();
    if (stats.active >= stats.max) {
      return res.status(503).json({ error: 'server_busy', message: 'Too many active jobs' });
    }

    await enforceCooldown(target, type);

    let row;
    try {
      row = await insertRequest(type, target);
    } catch (err) {
      if (err && err.code === 'ER_DUP_ENTRY') {
        err.status = 409;
        err.expose = true;
        err.message = `Duplicate request for ${type} ${target}`;
      }
      throw err;
    }

    log(`Request created for ${type} ${target} (id=${row.id})`);

    mailer.sendRequestCreated(row).catch((err) => {
      log(`Failed to send request email for ${type} ${target}: ${err.message}`);
    });

    let immediateResult = null;
    try {
      immediateResult = await runImmediateCheck(row);
    } catch (err) {
      log(`Immediate DNS check failed for ${type} ${target}: ${err.message}`);
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
