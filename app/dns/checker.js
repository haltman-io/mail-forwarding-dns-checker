const dns = require('node:dns');
const crypto = require('node:crypto');
const config = require('../config');
const { sanitizeDnsText, sanitizeDnsHost, capArray } = require('../util/sanitize');

const dnsPromises = dns.promises;

if (config.DNS_SERVERS && config.DNS_SERVERS.length > 0) {
  dns.setServers(config.DNS_SERVERS);
}

function normalizeHost(host) {
  if (!host) return host;
  return host.toLowerCase().replace(/\.$/, '');
}

function withTimeout(promise, timeoutMs, label) {
  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const err = new Error(`DNS timeout after ${timeoutMs}ms${label ? ` (${label})` : ''}`);
      err.code = 'ETIMEDOUT';
      reject(err);
    }, timeoutMs);
  });

  return Promise.race([promise, timeoutPromise]).finally(() => clearTimeout(timer));
}

function isNotFoundError(err) {
  return err && (err.code === 'ENODATA' || err.code === 'ENOTFOUND' || err.code === 'NXDOMAIN');
}

function normalizeIp(ip) {
  if (!ip) return ip;
  return String(ip).trim().toLowerCase();
}

function normalizeSpfRecord(value) {
  if (typeof value !== 'string') return '';
  return value.trim().replace(/\s+/g, ' ').toLowerCase();
}

function isAllMechanism(token) {
  return /^[+?~-]?all$/i.test(token || '');
}

function getExpectedSpfMinimumTokens(expectedSpf) {
  const normalized = normalizeSpfRecord(expectedSpf);
  const tokens = normalized.split(' ').filter(Boolean);
  if (tokens.length === 0 || tokens[0] !== 'v=spf1') return [];

  const contentTokens = tokens.slice(1);
  if (contentTokens.length === 0) return [];

  const withoutPolicyAtEnd = isAllMechanism(contentTokens[contentTokens.length - 1])
    ? contentTokens.slice(0, -1)
    : contentTokens;

  return withoutPolicyAtEnd.filter((token) => !isAllMechanism(token));
}

function isSpfRecordValidWithMinimum(record, requiredTokens) {
  const normalized = normalizeSpfRecord(record);
  const tokens = normalized.split(' ').filter(Boolean);

  if (tokens.length < 2 || tokens[0] !== 'v=spf1') return false;
  if (!isAllMechanism(tokens[tokens.length - 1])) return false;

  const mechanisms = tokens.slice(1, -1).filter((token) => !isAllMechanism(token));
  if (mechanisms.length === 0) return false;

  const mechanismSet = new Set(mechanisms);
  return requiredTokens.every((token) => mechanismSet.has(token));
}

function isSpfSatisfied(records, expectedSpf) {
  const requiredTokens = getExpectedSpfMinimumTokens(expectedSpf);
  return records.some((record) => isSpfRecordValidWithMinimum(record, requiredTokens));
}

function hashValues(values) {
  const hash = crypto.createHash('sha256');
  for (const value of values) {
    hash.update(String(value));
    hash.update('\n');
  }
  return hash.digest('hex');
}

async function resolveCnameSafe(target) {
  try {
    const records = await withTimeout(dnsPromises.resolveCname(target), config.DNS_TIMEOUT_MS, 'CNAME');
    return records.map(normalizeHost);
  } catch (err) {
    if (isNotFoundError(err)) return [];
    throw err;
  }
}

async function resolveMxSafe(target) {
  try {
    const records = await withTimeout(dnsPromises.resolveMx(target), config.DNS_TIMEOUT_MS, 'MX');
    return records.map((rec) => ({
      exchange: normalizeHost(rec.exchange),
      priority: rec.priority
    }));
  } catch (err) {
    if (isNotFoundError(err)) return [];
    throw err;
  }
}

async function resolveTxtSafe(target) {
  try {
    const records = await withTimeout(dnsPromises.resolveTxt(target), config.DNS_TIMEOUT_MS, 'TXT');
    return records.map((chunks) => chunks.join(''));
  } catch (err) {
    if (isNotFoundError(err)) return [];
    throw err;
  }
}

async function resolveA4Safe(target) {
  try {
    const records = await withTimeout(dnsPromises.resolve4(target), config.DNS_TIMEOUT_MS, 'A');
    return records.map(normalizeIp);
  } catch (err) {
    if (isNotFoundError(err)) return [];
    throw err;
  }
}

async function resolveA6Safe(target) {
  try {
    const records = await withTimeout(dnsPromises.resolve6(target), config.DNS_TIMEOUT_MS, 'AAAA');
    return records.map(normalizeIp);
  } catch (err) {
    if (isNotFoundError(err)) return [];
    throw err;
  }
}

async function resolveCnameChainToAuthorizedIp(startHost, authorizedIps, maxDepth) {
  const normalizedAuthorizedIps = new Set(
    (authorizedIps || []).map(normalizeIp).filter(Boolean)
  );
  const start = normalizeHost(startHost);
  const visited = new Set();
  let depth = 0;
  let currentHosts = start ? [start] : [];
  let sawCname = false;
  let loopDetected = false;

  const chain = [];
  const resolvedIps = new Set();

  while (currentHosts.length > 0 && depth < maxDepth) {
    const nextHosts = [];

    for (const rawHost of currentHosts) {
      const host = normalizeHost(rawHost);
      if (!host) continue;

      if (visited.has(host)) {
        loopDetected = true;
        continue;
      }

      visited.add(host);
      chain.push(host);

      const cnameRecords = await resolveCnameSafe(host);
      if (cnameRecords.length > 0) {
        sawCname = true;
        for (const cname of cnameRecords) {
          const normalized = normalizeHost(cname);
          if (normalized) nextHosts.push(normalized);
        }
        continue;
      }

      const aRecords = await resolveA4Safe(host);
      const aaaaRecords = await resolveA6Safe(host);
      const ips = [...aRecords, ...aaaaRecords].map(normalizeIp).filter(Boolean);

      for (const ip of ips) {
        resolvedIps.add(ip);
        if (sawCname && normalizedAuthorizedIps.has(ip)) {
          return {
            ok: true,
            chain,
            resolvedIps: Array.from(resolvedIps),
            reason: 'authorized_ip_match',
            reachedMaxDepth: false,
            loopDetected
          };
        }
      }
    }

    if (nextHosts.length === 0) break;
    currentHosts = Array.from(new Set(nextHosts));
    depth += 1;
  }

  const reachedMaxDepth = currentHosts.length > 0 && depth >= maxDepth;
  let reason = 'authorized_ip_not_found';
  if (!sawCname) reason = 'no_cname_record';
  else if (reachedMaxDepth) reason = 'max_chain_depth_reached';
  else if (loopDetected) reason = 'cname_loop_detected';

  return {
    ok: false,
    chain,
    resolvedIps: Array.from(resolvedIps),
    reason,
    reachedMaxDepth,
    loopDetected
  };
}

function capAndSanitizeHosts(rawHosts) {
  const normalized = rawHosts.map(normalizeHost);
  const capped = capArray(normalized, config.DNS_MAX_RECORDS);
  let valueTruncated = false;

  const sanitized = capped.values.map((host) => {
    const result = sanitizeDnsHost(host, config.DNS_MAX_HOST_LENGTH);
    if (result.truncated) valueTruncated = true;
    return result.value;
  });

  return {
    values: sanitized,
    total: capped.total,
    truncated: capped.truncated,
    valueTruncated,
    hash: capped.truncated || valueTruncated ? hashValues(normalized) : null
  };
}

function capAndSanitizeMx(rawMx) {
  const capped = capArray(rawMx, config.DNS_MAX_RECORDS);
  let valueTruncated = false;

  const sanitized = capped.values.map((rec) => {
    const result = sanitizeDnsHost(rec.exchange, config.DNS_MAX_HOST_LENGTH);
    if (result.truncated) valueTruncated = true;
    return {
      exchange: result.value,
      priority: rec.priority
    };
  });

  return {
    values: sanitized,
    total: capped.total,
    truncated: capped.truncated,
    valueTruncated,
    hash: capped.truncated || valueTruncated ? hashValues(rawMx.map((rec) => rec.exchange)) : null
  };
}

function capAndSanitizeTxt(rawTxt) {
  const capped = capArray(rawTxt, config.DNS_MAX_TXT_RECORDS);
  let valueTruncated = false;

  const sanitized = capped.values.map((txt) => {
    const result = sanitizeDnsText(txt, config.DNS_MAX_TXT_LENGTH);
    if (result.truncated) valueTruncated = true;
    return result.value;
  });

  return {
    values: sanitized,
    total: capped.total,
    truncated: capped.truncated,
    valueTruncated,
    hash: capped.truncated || valueTruncated ? hashValues(rawTxt) : null
  };
}

async function checkUi(target) {
  return checkEmail(target);
}

async function checkEmail(target) {
  const apexName = normalizeHost(target);
  const dkimSelector = normalizeHost(config.EMAIL_DKIM_SELECTOR);
  const dkimName = `${dkimSelector}._domainkey.${apexName}`;
  const dmarcName = `_dmarc.${apexName}`;
  const expectedCname = normalizeHost(config.UI_CNAME_EXPECTED);
  const expectedDkimCname = normalizeHost(config.EMAIL_DKIM_CNAME_EXPECTED);
  const authorizedCnameIps = (config.UI_CNAME_AUTHORIZED_IPS || []).map(normalizeIp).filter(Boolean);
  const expectedMxHost = normalizeHost(config.EMAIL_MX_EXPECTED_HOST);
  const expectedMxPriority = config.EMAIL_MX_EXPECTED_PRIORITY;
  const expectedSpf = config.EMAIL_SPF_EXPECTED;
  const expectedDmarc = config.EMAIL_DMARC_EXPECTED;

  const cnameRecords = await resolveCnameSafe(apexName);
  const dkimCnameRecords = await resolveCnameSafe(dkimName);
  const mxRecords = await resolveMxSafe(apexName);
  const txtApex = await resolveTxtSafe(apexName);
  const txtDmarc = await resolveTxtSafe(dmarcName);

  const directCnameOk = cnameRecords.some((record) => normalizeHost(record) === expectedCname);
  const cnameChainResolution = authorizedCnameIps.length > 0
    ? await resolveCnameChainToAuthorizedIp(apexName, authorizedCnameIps, config.UI_CNAME_MAX_CHAIN_DEPTH)
    : null;
  const cnameOk = cnameChainResolution ? cnameChainResolution.ok : directCnameOk;
  const mxOk = mxRecords.some(
    (rec) => rec.exchange === expectedMxHost && rec.priority === expectedMxPriority
  );
  const spfOk = isSpfSatisfied(txtApex, expectedSpf);
  const dmarcOk = txtDmarc.includes(expectedDmarc);
  const dkimOk = dkimCnameRecords.some((record) => normalizeHost(record) === expectedDkimCname);

  const cnameMeta = capAndSanitizeHosts(cnameRecords);
  const dkimCnameMeta = capAndSanitizeHosts(dkimCnameRecords);
  const mxMeta = capAndSanitizeMx(mxRecords);
  const txtApexMeta = capAndSanitizeTxt(txtApex);
  const txtDmarcMeta = capAndSanitizeTxt(txtDmarc);

  const cnameTruncated = cnameMeta.truncated || cnameMeta.valueTruncated;
  const dkimCnameTruncated = dkimCnameMeta.truncated || dkimCnameMeta.valueTruncated;
  const mxTruncated = mxMeta.truncated || mxMeta.valueTruncated;
  const spfTruncated = txtApexMeta.truncated || txtApexMeta.valueTruncated;
  const dmarcTruncated = txtDmarcMeta.truncated || txtDmarcMeta.valueTruncated;

  const missing = [
    {
      key: 'CNAME',
      type: 'CNAME',
      name: apexName,
      expected: expectedCname,
      found: cnameMeta.values,
      ok: cnameOk,
      found_truncated: cnameTruncated,
      expected_ips: authorizedCnameIps.length > 0 ? authorizedCnameIps : undefined
    },
    {
      key: 'MX',
      type: 'MX',
      name: apexName,
      expected: { host: expectedMxHost, priority: expectedMxPriority },
      found: mxMeta.values,
      ok: mxOk,
      found_truncated: mxTruncated
    },
    {
      key: 'SPF',
      type: 'TXT',
      name: apexName,
      expected: expectedSpf,
      found: txtApexMeta.values,
      ok: spfOk,
      found_truncated: spfTruncated
    },
    {
      key: 'DMARC',
      type: 'TXT',
      name: dmarcName,
      expected: expectedDmarc,
      found: txtDmarcMeta.values,
      ok: dmarcOk,
      found_truncated: dmarcTruncated
    },
    {
      key: 'DKIM',
      type: 'CNAME',
      name: dkimName,
      expected: expectedDkimCname,
      found: dkimCnameMeta.values,
      ok: dkimOk,
      found_truncated: dkimCnameTruncated
    }
  ];

  const snapshot = {
    cname_validation_mode: cnameChainResolution ? 'authorized_ip_chain' : 'expected_cname',
    cname: cnameMeta.values,
    cname_count: cnameMeta.total,
    cname_truncated: cnameTruncated,
    mx: mxMeta.values,
    mx_count: mxMeta.total,
    mx_truncated: mxTruncated,
    txt_apex: txtApexMeta.values,
    txt_apex_count: txtApexMeta.total,
    txt_apex_truncated: spfTruncated,
    txt_dmarc: txtDmarcMeta.values,
    txt_dmarc_count: txtDmarcMeta.total,
    txt_dmarc_truncated: dmarcTruncated,
    dkim_cname: dkimCnameMeta.values,
    dkim_cname_count: dkimCnameMeta.total,
    dkim_cname_truncated: dkimCnameTruncated
  };

  if (authorizedCnameIps.length > 0) {
    const authorizedIpsMeta = capAndSanitizeHosts(authorizedCnameIps);
    snapshot.cname_authorized_ips = authorizedIpsMeta.values;
    snapshot.cname_authorized_ips_count = authorizedIpsMeta.total;
    snapshot.cname_authorized_ips_truncated = authorizedIpsMeta.truncated || authorizedIpsMeta.valueTruncated;
  }

  if (cnameChainResolution) {
    const chainMeta = capAndSanitizeHosts(cnameChainResolution.chain || []);
    const resolvedIpsMeta = capAndSanitizeHosts(cnameChainResolution.resolvedIps || []);
    snapshot.cname_chain = chainMeta.values;
    snapshot.cname_chain_count = chainMeta.total;
    snapshot.cname_chain_truncated = chainMeta.truncated || chainMeta.valueTruncated;
    snapshot.cname_chain_reason = cnameChainResolution.reason;
    snapshot.cname_chain_max_depth = config.UI_CNAME_MAX_CHAIN_DEPTH;
    snapshot.cname_chain_reached_max_depth = Boolean(cnameChainResolution.reachedMaxDepth);
    snapshot.cname_chain_loop_detected = Boolean(cnameChainResolution.loopDetected);
    snapshot.cname_chain_resolved_ips = resolvedIpsMeta.values;
    snapshot.cname_chain_resolved_ips_count = resolvedIpsMeta.total;
    snapshot.cname_chain_resolved_ips_truncated =
      resolvedIpsMeta.truncated || resolvedIpsMeta.valueTruncated;
  }

  if (cnameMeta.hash) snapshot.cname_hash = cnameMeta.hash;
  if (dkimCnameMeta.hash) snapshot.dkim_cname_hash = dkimCnameMeta.hash;
  if (mxMeta.hash) snapshot.mx_hash = mxMeta.hash;
  if (txtApexMeta.hash) snapshot.txt_apex_hash = txtApexMeta.hash;
  if (txtDmarcMeta.hash) snapshot.txt_dmarc_hash = txtDmarcMeta.hash;

  return {
    ok: cnameOk && mxOk && spfOk && dmarcOk && dkimOk,
    missing,
    snapshot
  };
}

module.exports = {
  checkUi,
  checkEmail
};
