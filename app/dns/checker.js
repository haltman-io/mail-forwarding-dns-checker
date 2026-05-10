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

function getSystemDnsServers() {
  try {
    return dns.getServers();
  } catch (_err) {
    return [];
  }
}

function getDnsResolverSummary() {
  const configuredServers = Array.isArray(config.DNS_SERVERS)
    ? config.DNS_SERVERS.filter(Boolean)
    : [];
  if (configuredServers.length > 0) {
    return {
      source: 'configured',
      servers: configuredServers
    };
  }

  const systemServers = getSystemDnsServers();
  return {
    source: 'system',
    servers: systemServers.length > 0 ? systemServers : ['system-default']
  };
}

function createResolverForServer(server) {
  const resolver = new dns.promises.Resolver();
  resolver.setServers([server]);
  return resolver;
}

function getDnsQueryTargets() {
  const summary = getDnsResolverSummary();
  if (summary.source === 'configured') {
    return summary.servers.map((server) => ({
      label: server,
      resolver: createResolverForServer(server)
    }));
  }

  return [
    {
      label: summary.servers.join(','),
      resolver: dnsPromises
    }
  ];
}

function errorForDiagnostics(err) {
  return {
    code: err && err.code ? String(err.code) : 'ERROR',
    message: err && err.message ? String(err.message).slice(0, 300) : 'Unknown DNS error'
  };
}

function appendDnsQuery(collector, recordType, name, queryResults) {
  if (!collector) return;

  collector.push({
    type: recordType,
    name,
    results: queryResults.map((result) => {
      if (result.ok) {
        return {
          server: result.server,
          ok: true,
          found_count: result.records.length,
          not_found: Boolean(result.notFound)
        };
      }

      return {
        server: result.server,
        ok: false,
        found_count: 0,
        error: result.error
      };
    })
  });
}

async function resolveRecordsSafe(recordType, target, queryFn, normalizeRecord, recordKey, collector) {
  const queryTargets = getDnsQueryTargets();
  const queryResults = await Promise.all(
    queryTargets.map(async ({ label, resolver }) => {
      try {
        const rawRecords = await withTimeout(
          queryFn(resolver, target),
          config.DNS_TIMEOUT_MS,
          `${recordType} ${target} via ${label}`
        );

        const records = rawRecords.map(normalizeRecord).filter(Boolean);
        return {
          server: label,
          ok: true,
          notFound: false,
          records
        };
      } catch (err) {
        if (isNotFoundError(err)) {
          return {
            server: label,
            ok: true,
            notFound: true,
            records: []
          };
        }

        return {
          server: label,
          ok: false,
          records: [],
          error: errorForDiagnostics(err)
        };
      }
    })
  );

  appendDnsQuery(collector, recordType, target, queryResults);

  const hasUsableAnswer = queryResults.some((result) => result.ok);
  if (!hasUsableAnswer) {
    const details = queryResults
      .map((result) => `${result.server}:${result.error ? result.error.code : 'ERROR'}`)
      .join(', ');
    const err = new Error(`DNS ${recordType} lookup failed for ${target} via ${details}`);
    err.code = 'DNS_QUERY_FAILED';
    err.dns = {
      type: recordType,
      name: target,
      results: queryResults
    };
    throw err;
  }

  const seen = new Set();
  const merged = [];
  for (const result of queryResults) {
    if (!result.ok) continue;
    for (const record of result.records) {
      const key = recordKey(record);
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(record);
    }
  }

  return merged;
}

function normalizeIp(ip) {
  if (!ip) return ip;
  return String(ip).trim().toLowerCase();
}

function normalizeSpfRecord(value) {
  if (typeof value !== 'string') return '';
  return value.trim().replace(/\s+/g, ' ').toLowerCase();
}

function normalizeDmarcRecord(value) {
  if (typeof value !== 'string') return '';
  return value.trim().replace(/\s+/g, ' ').toLowerCase();
}

function isExactSpfMatch(records, expectedSpf) {
  const expected = normalizeSpfRecord(expectedSpf);
  if (!expected) return false;
  return records.some((record) => normalizeSpfRecord(record) === expected);
}

function isExactDmarcMatch(records, expectedDmarc) {
  const expected = normalizeDmarcRecord(expectedDmarc);
  if (!expected) return false;
  return records.some((record) => normalizeDmarcRecord(record) === expected);
}

function hashValues(values) {
  const hash = crypto.createHash('sha256');
  for (const value of values) {
    hash.update(String(value));
    hash.update('\n');
  }
  return hash.digest('hex');
}

async function resolveCnameSafe(target, collector) {
  return resolveRecordsSafe(
    'CNAME',
    target,
    (resolver, name) => resolver.resolveCname(name),
    normalizeHost,
    (record) => record,
    collector
  );
}

async function resolveMxSafe(target, collector) {
  return resolveRecordsSafe(
    'MX',
    target,
    (resolver, name) => resolver.resolveMx(name),
    (rec) => ({
      exchange: normalizeHost(rec.exchange),
      priority: rec.priority
    }),
    (record) => `${record.exchange}|${record.priority}`,
    collector
  );
}

async function resolveTxtSafe(target, collector) {
  return resolveRecordsSafe(
    'TXT',
    target,
    (resolver, name) => resolver.resolveTxt(name),
    (chunks) => chunks.join(''),
    (record) => record,
    collector
  );
}

async function resolveA4Safe(target, collector) {
  return resolveRecordsSafe(
    'A',
    target,
    (resolver, name) => resolver.resolve4(name),
    normalizeIp,
    (record) => record,
    collector
  );
}

async function resolveA6Safe(target, collector) {
  return resolveRecordsSafe(
    'AAAA',
    target,
    (resolver, name) => resolver.resolve6(name),
    normalizeIp,
    (record) => record,
    collector
  );
}

async function resolveCnameChainToAuthorizedIp(startHost, authorizedIps, maxDepth, collector) {
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

      const cnameRecords = await resolveCnameSafe(host, collector);
      if (cnameRecords.length > 0) {
        sawCname = true;
        for (const cname of cnameRecords) {
          const normalized = normalizeHost(cname);
          if (normalized) nextHosts.push(normalized);
        }
        continue;
      }

      const aRecords = await resolveA4Safe(host, collector);
      const aaaaRecords = await resolveA6Safe(host, collector);
      const ips = [...aRecords, ...aaaaRecords].map(normalizeIp).filter(Boolean);

      for (const ip of ips) {
        resolvedIps.add(ip);
        if (normalizedAuthorizedIps.has(ip)) {
          return {
            ok: true,
            chain,
            resolvedIps: Array.from(resolvedIps),
            reason: sawCname ? 'authorized_ip_match' : 'direct_ip_match',
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
  if (reachedMaxDepth) reason = 'max_chain_depth_reached';
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

function addResolverSnapshot(snapshot, queries) {
  const resolverSummary = getDnsResolverSummary();
  snapshot.dns_server_source = resolverSummary.source;
  snapshot.dns_servers = resolverSummary.servers;
  snapshot.dns_queries = queries;
  snapshot.dns_query_error_count = queries.reduce(
    (total, query) => total + query.results.filter((result) => !result.ok).length,
    0
  );
}

function formatFoundValue(item) {
  if (!item || !Array.isArray(item.found) || item.found.length === 0) return '-';

  const values = item.found.slice(0, 3).map((value) => {
    if (value && typeof value === 'object') {
      if (value.exchange) return `${value.exchange}:${value.priority}`;
      return JSON.stringify(value);
    }
    return String(value);
  });

  const suffix = item.found.length > values.length ? `,+${item.found.length - values.length}` : '';
  return `${values.join(',')}${suffix}`;
}

function describeCheckResult(check) {
  const missing = Array.isArray(check && check.missing) ? check.missing : [];
  const snapshot = check && check.snapshot && typeof check.snapshot === 'object' ? check.snapshot : {};
  const servers = Array.isArray(snapshot.dns_servers) && snapshot.dns_servers.length > 0
    ? snapshot.dns_servers.join(',')
    : 'unknown';
  const pending = missing.filter((item) => !item.ok).map((item) => item.key).join(',') || '-';
  const found = missing.map((item) => {
    const status = item.ok ? 'ok' : 'pending';
    return `${item.key}:${status}:found=${formatFoundValue(item)}`;
  }).join(' | ');
  const queryErrors = Array.isArray(snapshot.dns_queries)
    ? snapshot.dns_queries.flatMap((query) =>
        query.results
          .filter((result) => !result.ok)
          .map((result) => `${query.type} ${query.name} via ${result.server}=${result.error.code}`)
      )
    : [];
  const errorSummary = queryErrors.length > 0
    ? ` dns_errors=${queryErrors.slice(0, 4).join(';')}${queryErrors.length > 4 ? ';...' : ''}`
    : '';

  return `ok=${Boolean(check && check.ok)} dns_servers=${servers} pending=${pending} found=[${found}]${errorSummary}`;
}

async function checkUi(target) {
  const apexName = normalizeHost(target);
  const expectedCname = normalizeHost(config.UI_CNAME_EXPECTED);
  const authorizedCnameIps = (config.UI_CNAME_AUTHORIZED_IPS || []).map(normalizeIp).filter(Boolean);
  const dnsQueries = [];

  const cnameRecords = await resolveCnameSafe(apexName, dnsQueries);
  const directCnameOk = cnameRecords.some((record) => normalizeHost(record) === expectedCname);
  const cnameChainResolution = authorizedCnameIps.length > 0
    ? await resolveCnameChainToAuthorizedIp(
        apexName,
        authorizedCnameIps,
        config.UI_CNAME_MAX_CHAIN_DEPTH,
        dnsQueries
      )
    : null;
  const cnameOk = directCnameOk || (cnameChainResolution ? cnameChainResolution.ok : false);

  const cnameMeta = capAndSanitizeHosts(cnameRecords);
  const cnameTruncated = cnameMeta.truncated || cnameMeta.valueTruncated;

  const missing = [
    {
      key: 'CNAME',
      type: 'CNAME',
      name: apexName,
      expected: expectedCname,
      found: cnameMeta.values,
      ok: cnameOk,
      found_truncated: cnameTruncated,
      expected_ips: authorizedCnameIps.length > 0 ? authorizedCnameIps : undefined,
      found_ips: cnameChainResolution ? cnameChainResolution.resolvedIps || [] : undefined,
      chain_reason: cnameChainResolution ? cnameChainResolution.reason : undefined
    }
  ];

  const snapshot = {
    cname_validation_mode: cnameChainResolution ? 'expected_cname_or_authorized_ip_chain' : 'expected_cname',
    cname: cnameMeta.values,
    cname_count: cnameMeta.total,
    cname_truncated: cnameTruncated
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
  addResolverSnapshot(snapshot, dnsQueries);

  return {
    ok: cnameOk,
    missing,
    snapshot
  };
}

async function checkEmail(target) {
  const apexName = normalizeHost(target);
  const dkimSelector = normalizeHost(config.EMAIL_DKIM_SELECTOR);
  const dkimName = `${dkimSelector}._domainkey.${apexName}`;
  const dmarcName = `_dmarc.${apexName}`;
  const expectedDkimCname = normalizeHost(config.EMAIL_DKIM_CNAME_EXPECTED);
  const expectedMxHost = normalizeHost(config.EMAIL_MX_EXPECTED_HOST);
  const expectedMxPriority = config.EMAIL_MX_EXPECTED_PRIORITY;
  const expectedSpf = config.EMAIL_SPF_EXPECTED;
  const expectedDmarc = config.EMAIL_DMARC_EXPECTED;
  const dnsQueries = [];

  const [dkimCnameRecords, mxRecords, txtApex, txtDmarc] = await Promise.all([
    resolveCnameSafe(dkimName, dnsQueries),
    resolveMxSafe(apexName, dnsQueries),
    resolveTxtSafe(apexName, dnsQueries),
    resolveTxtSafe(dmarcName, dnsQueries)
  ]);

  const mxOk = mxRecords.some(
    (rec) => rec.exchange === expectedMxHost && rec.priority === expectedMxPriority
  );
  const spfOk = isExactSpfMatch(txtApex, expectedSpf);
  const dmarcOk = isExactDmarcMatch(txtDmarc, expectedDmarc);
  const dkimOk = dkimCnameRecords.some((record) => normalizeHost(record) === expectedDkimCname);

  const dkimCnameMeta = capAndSanitizeHosts(dkimCnameRecords);
  const mxMeta = capAndSanitizeMx(mxRecords);
  const txtApexMeta = capAndSanitizeTxt(txtApex);
  const txtDmarcMeta = capAndSanitizeTxt(txtDmarc);

  const dkimCnameTruncated = dkimCnameMeta.truncated || dkimCnameMeta.valueTruncated;
  const mxTruncated = mxMeta.truncated || mxMeta.valueTruncated;
  const spfTruncated = txtApexMeta.truncated || txtApexMeta.valueTruncated;
  const dmarcTruncated = txtDmarcMeta.truncated || txtDmarcMeta.valueTruncated;

  const missing = [
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

  if (dkimCnameMeta.hash) snapshot.dkim_cname_hash = dkimCnameMeta.hash;
  if (mxMeta.hash) snapshot.mx_hash = mxMeta.hash;
  if (txtApexMeta.hash) snapshot.txt_apex_hash = txtApexMeta.hash;
  if (txtDmarcMeta.hash) snapshot.txt_dmarc_hash = txtDmarcMeta.hash;
  addResolverSnapshot(snapshot, dnsQueries);

  return {
    ok: mxOk && spfOk && dmarcOk && dkimOk,
    missing,
    snapshot
  };
}

async function checkByType(type, target) {
  if (type === 'UI') return checkUi(target);
  if (type === 'EMAIL') return checkEmail(target);

  const err = new Error(`Unsupported DNS check type: ${type}`);
  err.code = 'UNSUPPORTED_DNS_CHECK_TYPE';
  throw err;
}

module.exports = {
  checkByType,
  checkUi,
  checkEmail,
  describeCheckResult,
  getDnsResolverSummary
};
