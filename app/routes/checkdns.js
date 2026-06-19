const express = require('express');
const db = require('../db');
const config = require('../config');
const { normalizeTarget } = require('../util/domain');
const { toIso, log, now, addSeconds } = require('../util/time');
const { checkByType, describeCheckResult } = require('../dns/checker');
const { buildResultPayload } = require('../util/result');
const mailer = require('../mailer');
const {
  markDomainApprovalActive,
  markDomainApprovalInactive
} = require('../util/domain-activation');

const router = express.Router();
const readOnlyChecks = new Map();

function minDate(dates) {
  const filtered = dates.filter(Boolean).map((d) => new Date(d));
  if (filtered.length === 0) return null;
  return new Date(Math.min(...filtered.map((d) => d.getTime())));
}

function maxDate(dates) {
  const filtered = dates.filter(Boolean).map((d) => new Date(d));
  if (filtered.length === 0) return null;
  return new Date(Math.max(...filtered.map((d) => d.getTime())));
}

function missingNameForKey(key, target) {
  const normalizedKey = typeof key === 'string' ? key.toUpperCase() : '';
  if (normalizedKey === 'DMARC') return `_dmarc.${target}`;
  if (normalizedKey === 'DKIM') return `${config.EMAIL_DKIM_SELECTOR}._domainkey.${target}`;
  return target;
}

function missingTypeForKey(key) {
  const normalizedKey = typeof key === 'string' ? key.toUpperCase() : '';
  if (normalizedKey === 'SPF' || normalizedKey === 'DMARC') return 'TXT';
  if (normalizedKey === 'MX') return 'MX';
  if (normalizedKey === 'CNAME' || normalizedKey === 'DKIM') return 'CNAME';
  return normalizedKey || 'UNKNOWN';
}

function withMissingNames(missing, target) {
  if (!Array.isArray(missing)) return missing;
  return missing.map((item) => {
    if (!item || typeof item !== 'object') return item;
    return {
      ...item,
      name: item.name || missingNameForKey(item.key, target),
      type: missingTypeForKey(item.key)
    };
  });
}

function fallbackMissing(type, target) {
  const normalizedType = typeof type === 'string' ? type.toUpperCase() : '';
  const expectedCnameIps = Array.isArray(config.UI_CNAME_AUTHORIZED_IPS)
    ? config.UI_CNAME_AUTHORIZED_IPS
    : [];
  if (normalizedType === 'UI') {
    return [
      {
        key: 'CNAME',
        type: 'CNAME',
        name: target,
        expected: config.UI_CNAME_EXPECTED,
        found: [],
        ok: false,
        expected_ips: expectedCnameIps.length > 0 ? expectedCnameIps : undefined
      }
    ];
  }

  if (normalizedType === 'EMAIL') {
    return [
      {
        key: 'MX',
        type: 'MX',
        name: target,
        expected: { host: config.EMAIL_MX_EXPECTED_HOST, priority: config.EMAIL_MX_EXPECTED_PRIORITY },
        found: [],
        ok: false
      },
      {
        key: 'SPF',
        type: 'TXT',
        name: target,
        expected: config.EMAIL_SPF_EXPECTED,
        found: [],
        ok: false
      },
      {
        key: 'DMARC',
        type: 'TXT',
        name: `_dmarc.${target}`,
        expected: config.EMAIL_DMARC_EXPECTED,
        found: [],
        ok: false
      },
      {
        key: 'DKIM',
        type: 'CNAME',
        name: `${config.EMAIL_DKIM_SELECTOR}._domainkey.${target}`,
        expected: config.EMAIL_DKIM_CNAME_EXPECTED,
        found: [],
        ok: false
      }
    ];
  }

  return [];
}

function canRunReadOnlyCheck(
  type,
  target,
  lastCheckedAt,
  minIntervalSeconds = config.CHECKDNS_MIN_INTERVAL_SECONDS
) {
  const nowMs = Date.now();
  const minIntervalMs = minIntervalSeconds * 1000;
  if (lastCheckedAt && nowMs - lastCheckedAt.getTime() < minIntervalMs) {
    return false;
  }

  const key = `${type}:${target}`;
  const lastRun = readOnlyChecks.get(key);
  if (lastRun && nowMs - lastRun < minIntervalMs) {
    return false;
  }

  readOnlyChecks.set(key, nowMs);

  if (readOnlyChecks.size > 10000) {
    for (const [mapKey, ts] of readOnlyChecks.entries()) {
      if (nowMs - ts > minIntervalMs * 2) {
        readOnlyChecks.delete(mapKey);
      }
    }
  }

  return true;
}

function orderedMissingKeys(type) {
  const normalizedType = typeof type === 'string' ? type.toUpperCase() : '';
  if (normalizedType === 'UI') return ['CNAME'];
  if (normalizedType === 'EMAIL') return ['MX', 'SPF', 'DMARC', 'DKIM'];
  return [];
}

function ensureUnifiedMissing(type, missing, target) {
  const base = withMissingNames(missing, target);
  const fallbackByKey = new Map(
    fallbackMissing(type, target).map((item) => [String(item.key).toUpperCase(), item])
  );
  const foundByKey = new Map();

  if (Array.isArray(base)) {
    for (const item of base) {
      if (!item || typeof item !== 'object') continue;
      const normalizedKey = typeof item.key === 'string' ? item.key.toUpperCase() : '';
      if (!normalizedKey) continue;
      foundByKey.set(normalizedKey, item);
    }
  }

  return orderedMissingKeys(type).map(
    (key) => foundByKey.get(key) || fallbackByKey.get(key)
  );
}

function getStoredMissingForRow(row, rowType, target) {
  if (!row || !row.last_check_result_json) return null;

  try {
    const parsed = JSON.parse(row.last_check_result_json);
    if (parsed && parsed.missing) {
      return ensureUnifiedMissing(rowType, parsed.missing, target);
    }
  } catch (err) {
    log(`Failed to parse last_check_result_json for ${rowType} ${target}: ${err.message}`);
  }

  return null;
}

function dateOrNull(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

function shouldRefreshRow(row, rowType, target, hasStoredMissing) {
  if (!row || row.status !== 'PENDING') return false;

  const lastCheckedAt = dateOrNull(row.last_checked_at);
  const nextCheckAt = dateOrNull(row.next_check_at);
  const nowDate = now();

  if (hasStoredMissing && nextCheckAt && nowDate >= nextCheckAt) {
    return canRunReadOnlyCheck(
      rowType,
      target,
      lastCheckedAt,
      config.DNS_POLL_INTERVAL_SECONDS
    );
  }

  if (hasStoredMissing && !nextCheckAt) {
    return canRunReadOnlyCheck(rowType, target, lastCheckedAt);
  }

  if (!hasStoredMissing) {
    return canRunReadOnlyCheck(rowType, target, lastCheckedAt);
  }

  return false;
}

async function sendActiveNotification(row, rowType, payload) {
  try {
    await mailer.sendStatusChange({
      id: row.id,
      type: rowType,
      target: row.target,
      status: 'ACTIVE',
      expires_at: row.expires_at,
      last_result: payload
    });
  } catch (err) {
    log(`Failed to send ACTIVE email for ${rowType} ${row.target}: ${err.message}`);
  }
}

async function persistCheckResult(row, rowType, check) {
  const checkedAt = now();
  const nextCheckAt = addSeconds(checkedAt, config.DNS_POLL_INTERVAL_SECONDS);
  const { payload, json } = buildResultPayload(check, checkedAt, nextCheckAt);

  const updateResult = await db.query(
    "UPDATE dns_requests SET last_checked_at = ?, next_check_at = ?, last_check_result_json = ?, updated_at = NOW() WHERE id = ? AND status = 'PENDING'",
    [checkedAt, nextCheckAt, json, row.id]
  );

  if (!updateResult || updateResult.affectedRows === 0) {
    const refreshedRows = await db.query('SELECT * FROM dns_requests WHERE id = ?', [row.id]);
    if (refreshedRows.length > 0) {
      Object.assign(row, refreshedRows[0]);
    }
    return payload;
  }

  row.last_checked_at = checkedAt;
  row.next_check_at = nextCheckAt;
  row.last_check_result_json = json;

  if (check.ok) {
    const statusResult = await db.query(
      "UPDATE dns_requests SET status = ?, activated_at = ?, updated_at = NOW() WHERE id = ? AND status = 'PENDING'",
      ['ACTIVE', checkedAt, row.id]
    );

    if (statusResult && statusResult.affectedRows > 0) {
      row.status = 'ACTIVE';
      row.activated_at = checkedAt;
      log(`Status updated for ${rowType} ${row.target}: ACTIVE`);
      await sendActiveNotification(row, rowType, payload);
      await markDomainApprovalActive(row.target, rowType, { lastResult: payload });
    } else {
      const refreshedRows = await db.query('SELECT * FROM dns_requests WHERE id = ?', [row.id]);
      if (refreshedRows.length > 0) {
        Object.assign(row, refreshedRows[0]);
      }
    }
  } else {
    await markDomainApprovalInactive(row.target, rowType);
  }

  return payload;
}

async function getMissingForRow(row, target) {
  if (!row) return null;
  const rowType = typeof row.type === 'string' ? row.type.toUpperCase() : '';
  const storedMissing = getStoredMissingForRow(row, rowType, target);
  const hasStoredMissing = storedMissing !== null;

  if (!shouldRefreshRow(row, rowType, target, hasStoredMissing)) {
    return storedMissing || fallbackMissing(rowType, target);
  }

  try {
    const check = await checkByType(rowType, target);
    await persistCheckResult(row, rowType, check);
    log(`Read-only DNS check completed for ${rowType}:${target} (${describeCheckResult(check)})`);
    return ensureUnifiedMissing(rowType, check.missing, target);
  } catch (err) {
    log(`Read-only DNS check failed for ${rowType} ${target}: ${err.message}`, {
      code: err.code || 'ERROR',
      dns: err.dns || null,
      stack: err.stack
    });
    return storedMissing || fallbackMissing(rowType, target);
  }
}

function overallStatusForRows(rows) {
  const statuses = rows.map((row) => row && row.status).filter(Boolean);
  if (statuses.length === 0) return 'NONE';
  if (statuses.includes('PENDING')) return 'PENDING';
  if (statuses.includes('FAILED')) return 'FAILED';
  if (statuses.includes('EXPIRED')) return 'EXPIRED';
  if (statuses.every((status) => status === 'ACTIVE')) return 'ACTIVE';
  return statuses[0];
}

function buildRowResponse(row, missing) {
  if (!row) return null;
  return {
    status: row.status,
    id: typeof row.id === 'bigint' ? Number(row.id) : row.id,
    created_at: toIso(row.created_at),
    expires_at: toIso(row.expires_at),
    last_checked_at: toIso(row.last_checked_at),
    next_check_at: toIso(row.next_check_at),
    missing
  };
}

router.get('/api/checkdns/:target', async (req, res, next) => {
  try {
    if (config.CHECKDNS_TOKEN) {
      const token = req.get('x-api-key') || '';
      if (token !== config.CHECKDNS_TOKEN) {
        return res.status(401).json({ error: 'unauthorized' });
      }
    }

    let normalized;
    try {
      normalized = normalizeTarget(req.params.target);
    } catch (err) {
      err.status = 400;
      throw err;
    }

    const rows = await db.query('SELECT * FROM dns_requests WHERE target = ?', [normalized]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'not_found', target: normalized });
    }

    const uiRow = rows.find((row) => row.type === 'UI') || null;
    const emailRow = rows.find((row) => row.type === 'EMAIL') || null;
    if (!uiRow && !emailRow) {
      return res.status(404).json({ error: 'not_found', target: normalized });
    }
    const uiMissing = await getMissingForRow(uiRow, normalized);
    const emailMissing = await getMissingForRow(emailRow, normalized);

    const scopedRows = [uiRow, emailRow].filter(Boolean);
    const overallStatus = overallStatusForRows(scopedRows);
    const expiresAtMin = minDate(scopedRows.map((row) => row.expires_at));
    const lastCheckedMax = maxDate(scopedRows.map((row) => row.last_checked_at));
    const nextCheckMin = minDate(scopedRows.map((row) => row.next_check_at));

    return res.status(200).json({
      target: normalized,
      normalized_target: normalized,
      summary: {
        has_ui: Boolean(uiRow),
        has_email: Boolean(emailRow),
        overall_status: overallStatus,
        expires_at_min: toIso(expiresAtMin),
        last_checked_at_max: toIso(lastCheckedMax),
        next_check_at_min: toIso(nextCheckMin)
      },
      ui: buildRowResponse(uiRow, uiMissing),
      email: buildRowResponse(emailRow, emailMissing)
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
