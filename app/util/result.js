const config = require('../config');
const { byteLength } = require('./sanitize');

function summarizeSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== 'object') return snapshot;
  const summary = { truncated: true, counts: {} };

  if (Array.isArray(snapshot.cname)) {
    summary.counts.cname = snapshot.cname_count || snapshot.cname.length;
  }
  if (Array.isArray(snapshot.mx)) {
    summary.counts.mx = snapshot.mx_count || snapshot.mx.length;
  }
  if (Array.isArray(snapshot.txt_apex)) {
    summary.counts.txt_apex = snapshot.txt_apex_count || snapshot.txt_apex.length;
  }
  if (Array.isArray(snapshot.txt_dmarc)) {
    summary.counts.txt_dmarc = snapshot.txt_dmarc_count || snapshot.txt_dmarc.length;
  }
  if (Array.isArray(snapshot.dkim_cname)) {
    summary.counts.dkim_cname = snapshot.dkim_cname_count || snapshot.dkim_cname.length;
  }

  return summary;
}

function summarizeMissing(missing) {
  if (!Array.isArray(missing)) return missing;
  return missing.map((item) => {
    if (!item || typeof item !== 'object') return item;
    return {
      key: item.key,
      type: item.type,
      name: item.name,
      expected: item.expected,
      ok: item.ok,
      found: Array.isArray(item.found) ? item.found.slice(0, 3) : [],
      found_truncated: Array.isArray(item.found) && item.found.length > 3
    };
  });
}

function ensureResultSize(payload) {
  let json = JSON.stringify(payload);
  if (byteLength(json) <= config.RESULT_JSON_MAX_BYTES) {
    return { payload, json };
  }

  const trimmed = {
    ...payload,
    truncated: true,
    dns_snapshot: summarizeSnapshot(payload.dns_snapshot),
    missing: summarizeMissing(payload.missing)
  };

  json = JSON.stringify(trimmed);
  if (byteLength(json) <= config.RESULT_JSON_MAX_BYTES) {
    return { payload: trimmed, json };
  }

  const minimal = {
    ...trimmed,
    dns_snapshot: { truncated: true, note: 'snapshot omitted' },
    missing: Array.isArray(trimmed.missing)
      ? trimmed.missing.map((item) => ({
          key: item.key,
          type: item.type,
          name: item.name,
          expected: item.expected,
          ok: item.ok,
          found: [],
          found_truncated: true
        }))
      : []
  };

  json = JSON.stringify(minimal);
  return { payload: minimal, json };
}

function buildResultPayload(check, checkedAt, nextCheckAt) {
  const payload = {
    dns_snapshot: check.snapshot,
    missing: check.missing,
    ok: check.ok,
    checked_at: checkedAt.toISOString(),
    next_check_at: nextCheckAt.toISOString()
  };

  return ensureResultSize(payload);
}

module.exports = {
  buildResultPayload
};
