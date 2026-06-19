const express = require('express');
const config = require('../config');
const recheckJobs = require('../jobs/rechecker');
const { normalizeTarget } = require('../util/domain');
const { toIso } = require('../util/time');

const router = express.Router();

function getAuthToken(req) {
  const apiKey = req.get('x-api-key');
  if (apiKey) return apiKey;

  const authorization = req.get('authorization') || '';
  const bearerPrefix = 'Bearer ';
  if (authorization.startsWith(bearerPrefix)) {
    return authorization.slice(bearerPrefix.length).trim();
  }

  return '';
}

function requireCheckdnsToken(req, res, next) {
  if (!config.CHECKDNS_TOKEN) {
    return res.status(503).json({ error: 'checkdns_token_not_configured' });
  }

  if (getAuthToken(req) !== config.CHECKDNS_TOKEN) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  return next();
}

function buildForceResponse(result) {
  return {
    status: 'completed',
    scope: result.scope,
    target: result.target,
    started_at: toIso(result.startedAt),
    completed_at: toIso(result.completedAt),
    duration_seconds: result.durationSeconds,
    processed_rechecks: result.processedRechecks,
    successful_rechecks: result.successfulRechecks,
    failed_rechecks: result.failedRechecks,
    summary: result.summary,
    results: result.results
  };
}

router.post('/api/recheckdns/all', requireCheckdnsToken, async (_req, res, next) => {
  try {
    const result = await recheckJobs.forceRecheckAll();
    return res.status(200).json(buildForceResponse(result));
  } catch (err) {
    return next(err);
  }
});

router.post('/api/recheckdns/:target', requireCheckdnsToken, async (req, res, next) => {
  try {
    let normalized;
    try {
      normalized = normalizeTarget(req.params.target);
    } catch (err) {
      err.status = 400;
      throw err;
    }

    const initialSummary = await recheckJobs.getDomainSummary(normalized);
    if (initialSummary.totalDomains === 0) {
      return res.status(404).json({ error: 'not_found', target: normalized });
    }

    const result = await recheckJobs.forceRecheckTarget(normalized);
    return res.status(200).json(buildForceResponse(result));
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
