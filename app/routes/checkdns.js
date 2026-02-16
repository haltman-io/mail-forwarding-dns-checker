const express = require('express');
const db = require('../db');
const config = require('../config');
const { normalizeTarget } = require('../util/domain');
const { toIso, log } = require('../util/time');
const { checkEmail } = require('../dns/checker');

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

function fallbackMissing(target) {
  const expectedCnameIps = Array.isArray(config.UI_CNAME_AUTHORIZED_IPS)
    ? config.UI_CNAME_AUTHORIZED_IPS
    : [];
  return [
    {
      key: 'CNAME',
      type: 'CNAME',
      name: target,
      expected: config.UI_CNAME_EXPECTED,
      found: [],
      ok: false,
      expected_ips: expectedCnameIps.length > 0 ? expectedCnameIps : undefined
    },
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

function canRunReadOnlyCheck(type, target, lastCheckedAt) {
  const nowMs = Date.now();
  const minIntervalMs = config.CHECKDNS_MIN_INTERVAL_SECONDS * 1000;
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

function ensureUnifiedMissing(missing, target) {
  const base = withMissingNames(missing, target);
  const fallbackByKey = new Map(fallbackMissing(target).map((item) => [String(item.key).toUpperCase(), item]));
  const foundByKey = new Map();

  if (Array.isArray(base)) {
    for (const item of base) {
      if (!item || typeof item !== 'object') continue;
      const normalizedKey = typeof item.key === 'string' ? item.key.toUpperCase() : '';
      if (!normalizedKey) continue;
      foundByKey.set(normalizedKey, item);
    }
  }

  return ['CNAME', 'MX', 'SPF', 'DMARC', 'DKIM'].map(
    (key) => foundByKey.get(key) || fallbackByKey.get(key)
  );
}

async function getMissingForRow(row, target) {
  if (!row) return null;
  if (row.last_check_result_json) {
    try {
      const parsed = JSON.parse(row.last_check_result_json);
      if (parsed && parsed.missing) return ensureUnifiedMissing(parsed.missing, target);
    } catch (err) {
      log(`Failed to parse last_check_result_json for EMAIL ${target}: ${err.message}`);
    }
  }

  const lastCheckedAt = row.last_checked_at ? new Date(row.last_checked_at) : null;
  if (!canRunReadOnlyCheck('EMAIL', target, lastCheckedAt)) {
    return fallbackMissing(target);
  }
  try {
    const check = await checkEmail(target);
    return ensureUnifiedMissing(check.missing, target);
  } catch (err) {
    log(`Read-only DNS check failed for EMAIL ${target}: ${err.message}`);
    return fallbackMissing(target);
  }
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

    const emailRow = rows.find((row) => row.type === 'EMAIL') || rows.find((row) => row.type === 'UI') || null;
    const emailMissing = await getMissingForRow(emailRow, normalized);

    const overallStatus = emailRow ? emailRow.status : 'NONE';
    const scopedRows = emailRow ? [emailRow] : [];
    const expiresAtMin = minDate(scopedRows.map((row) => row.expires_at));
    const lastCheckedMax = maxDate(scopedRows.map((row) => row.last_checked_at));
    const nextCheckMin = minDate(scopedRows.map((row) => row.next_check_at));

    return res.status(200).json({
      target: normalized,
      normalized_target: normalized,
      summary: {
        has_ui: false,
        has_email: Boolean(emailRow),
        overall_status: overallStatus,
        expires_at_min: toIso(expiresAtMin),
        last_checked_at_max: toIso(lastCheckedMax),
        next_check_at_min: toIso(nextCheckMin)
      },
      ui: null,
      email: buildRowResponse(emailRow, emailMissing)
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
