const nodemailer = require('nodemailer');
const config = require('./config');
const { toIso, now } = require('./util/time');
const { sanitizeForLogAndEmail, sanitizeHeaderValue, safeJsonStringify } = require('./util/sanitize');

const transporter = nodemailer.createTransport({
  host: config.SMTP_HOST,
  port: config.SMTP_PORT,
  secure: config.SMTP_SECURE,
  auth: {
    user: config.SMTP_USER,
    pass: config.SMTP_PASS
  }
});

function sanitizeEmailBody(text, maxLen) {
  let value = text === undefined || text === null ? '' : String(text);
  value = value.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  value = value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
  if (value.length > maxLen) {
    value = `${value.slice(0, maxLen)}...`;
  }
  return value;
}

async function sendAdminMail(subject, text) {
  return transporter.sendMail({
    from: sanitizeHeaderValue(config.SMTP_FROM),
    to: sanitizeHeaderValue(config.ADMIN_EMAIL_TO),
    subject: sanitizeHeaderValue(subject),
    text: sanitizeEmailBody(text, config.EMAIL_BODY_MAX_LENGTH)
  });
}

function buildUiCriteriaText() {
  const authorizedCnameIps = Array.isArray(config.UI_CNAME_AUTHORIZED_IPS)
    ? config.UI_CNAME_AUTHORIZED_IPS.filter(Boolean)
    : [];
  const cnameRule = authorizedCnameIps.length > 0
    ? `- CNAME must include ${sanitizeForLogAndEmail(config.UI_CNAME_EXPECTED, 200)} or resolve to authorized IP(s): ${sanitizeForLogAndEmail(authorizedCnameIps.join(', '), 500)}`
    : `- CNAME must include: ${sanitizeForLogAndEmail(config.UI_CNAME_EXPECTED, 200)}`;

  return [
    'UI DNS requirements:',
    cnameRule
  ].join('\n');
}

function buildEmailCriteriaText() {
  return [
    'Email forwarding DNS requirements:',
    `- MX must include: ${sanitizeForLogAndEmail(config.EMAIL_MX_EXPECTED_HOST, 200)} priority ${sanitizeForLogAndEmail(config.EMAIL_MX_EXPECTED_PRIORITY, 50)}`,
    `- SPF TXT must exactly match: ${sanitizeForLogAndEmail(config.EMAIL_SPF_EXPECTED, 200)}`,
    `- DMARC TXT must exactly match: ${sanitizeForLogAndEmail(config.EMAIL_DMARC_EXPECTED, 200)}`,
    `- DKIM CNAME ${sanitizeForLogAndEmail(config.EMAIL_DKIM_SELECTOR, 100)}._domainkey.<target> must include: ${sanitizeForLogAndEmail(config.EMAIL_DKIM_CNAME_EXPECTED, 255)}`
  ].join('\n');
}

function buildCriteriaText(type) {
  if (type === 'UI') return buildUiCriteriaText();

  return [
    buildEmailCriteriaText()
  ].join('\n');
}

function pluralize(count, singular, plural = `${singular}s`) {
  return count === 1 ? singular : plural;
}

function formatRelativeTime(targetDate, baseDate = now()) {
  if (!targetDate) return 'unknown';

  const target = new Date(targetDate);
  const base = new Date(baseDate);
  if (Number.isNaN(target.getTime()) || Number.isNaN(base.getTime())) return 'unknown';

  const diffMs = target.getTime() - base.getTime();
  const absSeconds = Math.max(0, Math.round(Math.abs(diffMs) / 1000));
  const direction = diffMs >= 0 ? 'in' : '';
  const suffix = diffMs >= 0 ? '' : ' ago';

  if (absSeconds < 60) return `${direction} less than 1 minute${suffix}`.trim();

  const absMinutes = Math.round(absSeconds / 60);
  if (absMinutes < 60) {
    return `${direction} ${absMinutes} ${pluralize(absMinutes, 'minute')}${suffix}`.trim();
  }

  const absHours = Math.round(absMinutes / 60);
  if (absHours < 24) {
    return `${direction} ${absHours} ${pluralize(absHours, 'hour')}${suffix}`.trim();
  }

  const absDays = Math.round(absHours / 24);
  return `${direction} ${absDays} ${pluralize(absDays, 'day')}${suffix}`.trim();
}

function missingByKey(result) {
  const map = new Map();
  const missing = result && Array.isArray(result.missing) ? result.missing : [];
  for (const item of missing) {
    if (!item || typeof item !== 'object') continue;
    const key = item.key || `${item.type || 'DNS'}:${item.name || ''}`;
    map.set(String(key).toUpperCase(), item);
  }
  return map;
}

function buildChangedRecordsText(details) {
  const currentMissing = details.currentResult && Array.isArray(details.currentResult.missing)
    ? details.currentResult.missing
    : [];
  const previousByKey = missingByKey(details.previousValidResult);
  const failedItems = currentMissing.filter((item) => item && !item.ok);
  const maxItems = config.DNS_RECHECK_ALERT_MAX_DIFF_ITEMS;
  const lines = [];

  if (failedItems.length === 0) {
    return ['- No failing DNS item was reported.'];
  }

  for (const item of failedItems.slice(0, maxItems)) {
    const key = String(item.key || item.type || 'DNS').toUpperCase();
    const previous = previousByKey.get(key);
    lines.push(`- ${sanitizeForLogAndEmail(key, 100)} ${sanitizeForLogAndEmail(item.name || '', 255)}`.trim());
    lines.push(`  Previously valid: ${safeJsonStringify(previous ? previous.found : null, 1000)}`);
    lines.push(`  Current found: ${safeJsonStringify(item.found || [], 1000)}`);
    lines.push(`  Required: ${safeJsonStringify(item.expected, 1000)}`);
  }

  if (failedItems.length > maxItems) {
    lines.push(`- ${failedItems.length - maxItems} additional failing item(s) omitted.`);
  }

  return lines;
}

function buildCurrentRecordsText(details) {
  const currentMissing = details.currentResult && Array.isArray(details.currentResult.missing)
    ? details.currentResult.missing
    : [];
  const maxItems = config.DNS_RECHECK_ALERT_MAX_DIFF_ITEMS;
  const lines = [];

  if (currentMissing.length === 0) {
    return ['- No DNS item details were reported.'];
  }

  for (const item of currentMissing.slice(0, maxItems)) {
    const key = String(item.key || item.type || 'DNS').toUpperCase();
    lines.push(`- ${sanitizeForLogAndEmail(key, 100)} ${sanitizeForLogAndEmail(item.name || '', 255)}`.trim());
    lines.push(`  Status: ${item.ok ? 'valid' : 'invalid'}`);
    lines.push(`  Current found: ${safeJsonStringify(item.found || [], 1000)}`);
    lines.push(`  Required: ${safeJsonStringify(item.expected, 1000)}`);
  }

  if (currentMissing.length > maxItems) {
    lines.push(`- ${currentMissing.length - maxItems} additional item(s) omitted.`);
  }

  return lines;
}

function currentServiceState(details) {
  if (details.approvalValue === 0) return 'DNS approval disabled';
  if (!details.active) return 'admin-disabled, DNS approval still recorded';
  return 'still enabled';
}

function actionTextForType(type) {
  if (type === 'UI') {
    return 'Restore the CNAME record or an accepted CNAME chain before the disable threshold is reached.';
  }

  return 'Restore the MX, SPF, DMARC, and DKIM DNS records above before the disable threshold is reached.';
}

function buildRecheckEventBody(details, intro) {
  const isRecovered = details.eventType === 'RECHECK_RECOVERED';
  const timingLines = [
    `Current check time: ${sanitizeForLogAndEmail(toIso(details.checkedAt), 50)}`,
    `Next recheck: ${sanitizeForLogAndEmail(toIso(details.nextCheckAt), 50)} (${formatRelativeTime(details.nextCheckAt, details.checkedAt)})`
  ];

  if (!isRecovered) {
    timingLines.push(
      `Disablement if still invalid: ${sanitizeForLogAndEmail(toIso(details.disableAt), 50)} (${formatRelativeTime(details.disableAt, details.checkedAt)})`
    );
  }

  const lines = [
    intro,
    '',
    `Event: ${sanitizeForLogAndEmail(details.eventType, 100)}`,
    `Domain: ${sanitizeForLogAndEmail(details.domain, 255)}`,
    `Validation type: ${sanitizeForLogAndEmail(details.type, 50)}`,
    `Current service state: ${currentServiceState(details)}`,
    `Admin gate: active=${details.active ? 1 : 0}`,
    `DNS approval gate: ${sanitizeForLogAndEmail(details.approvalColumn, 50)}=${details.approvalValue ? 1 : 0}`,
    '',
    'Failure counter:',
    `Failed rechecks in this alert sequence: ${sanitizeForLogAndEmail(details.consecutiveFailures, 50)}`,
    `Disable threshold: ${sanitizeForLogAndEmail(details.threshold, 50)}`,
    `Remaining failed rechecks before disablement: ${sanitizeForLogAndEmail(details.remainingFailures, 50)}`,
    '',
    'Timing:',
    ...timingLines,
    '',
    isRecovered ? 'Current valid DNS:' : 'What changed:',
    ...(isRecovered ? buildCurrentRecordsText(details) : buildChangedRecordsText(details)),
    '',
    'Action required:',
    isRecovered ? 'No action required.' : actionTextForType(details.type)
  ];

  if (config.DNS_RECHECK_ALERT_INCLUDE_RAW_JSON) {
    lines.push('', 'Raw current result:', safeJsonStringify(details.currentResult, 4000));
  }

  return lines.join('\n');
}

async function sendRecheckWarning(details) {
  const subject = `[DNS][WARNING] ${sanitizeForLogAndEmail(details.type, 50)} ${sanitizeForLogAndEmail(details.domain, 100)} changed and may become disabled`;
  return sendAdminMail(
    subject,
    buildRecheckEventBody(details, 'Stable DNS recheck detected that previously valid DNS no longer passes.')
  );
}

async function sendRecheckDegraded(details) {
  const remaining = details.remainingFailures;
  const subject = `[DNS][DEGRADED] ${sanitizeForLogAndEmail(details.type, 50)} ${sanitizeForLogAndEmail(details.domain, 100)} still invalid, ${remaining} ${pluralize(remaining, 'recheck')} left before disablement`;
  return sendAdminMail(
    subject,
    buildRecheckEventBody(details, 'Stable DNS recheck is still failing and disablement is approaching.')
  );
}

async function sendRecheckDisabled(details) {
  const subject = `[DNS][DISABLED] ${sanitizeForLogAndEmail(details.type, 50)} ${sanitizeForLogAndEmail(details.domain, 100)} disabled after repeated invalid DNS`;
  return sendAdminMail(
    subject,
    buildRecheckEventBody(details, 'Stable DNS recheck reached the failure threshold and disabled the matching DNS approval gate.')
  );
}

async function sendRecheckRecovered(details) {
  const subject = `[DNS][RECOVERED] ${sanitizeForLogAndEmail(details.type, 50)} ${sanitizeForLogAndEmail(details.domain, 100)} DNS is valid again`;
  return sendAdminMail(
    subject,
    buildRecheckEventBody(details, 'Stable DNS recheck recovered. The matching DNS approval gate is enabled again.')
  );
}

async function sendRecheckPeriodicSummary(details) {
  const incidents = Array.isArray(details.incidents) ? details.incidents : [];
  const lines = [
    'DNS recheck incidents are still open.',
    '',
    `Event: RECHECK_PERIODIC_SUMMARY`,
    `Generated at: ${sanitizeForLogAndEmail(toIso(details.generatedAt), 50)}`,
    `Incident count: ${incidents.length}`,
    ''
  ];

  for (const incident of incidents) {
    lines.push(
      `- ${sanitizeForLogAndEmail(incident.type, 50)} ${sanitizeForLogAndEmail(incident.domain, 255)} status=${sanitizeForLogAndEmail(incident.status, 50)} alert=${sanitizeForLogAndEmail(incident.alertStatus, 50)} active=${incident.active ? 1 : 0} ${sanitizeForLogAndEmail(incident.approvalColumn, 50)}=${incident.approvalValue ? 1 : 0} failures=${sanitizeForLogAndEmail(incident.consecutiveFailures, 50)}/${sanitizeForLogAndEmail(incident.threshold, 50)} next=${sanitizeForLogAndEmail(toIso(incident.nextCheckAt), 50)} error=${sanitizeForLogAndEmail(incident.lastError || '-', 300)}`
    );
  }

  const subject = `[DNS][SUMMARY] ${incidents.length} DNS recheck ${pluralize(incidents.length, 'incident')} still open`;
  return sendAdminMail(subject, lines.join('\n'));
}

function forcedScopeText(details) {
  if (details.scope === 'TARGET') {
    return `domain ${sanitizeForLogAndEmail(details.target, 255)}`;
  }

  return 'all domains';
}

function recheckStatusText(rechecks) {
  if (!rechecks || typeof rechecks !== 'object') return '-';

  const parts = [];
  for (const type of ['EMAIL', 'UI']) {
    const item = rechecks[type];
    if (!item) continue;
    parts.push(
      `${type}=${sanitizeForLogAndEmail(item.status, 50)}(${sanitizeForLogAndEmail(item.consecutiveFailures, 50)})`
    );
  }

  return parts.length > 0 ? parts.join(' ') : '-';
}

function buildForcedDomainList(summary) {
  const domains = summary && Array.isArray(summary.domains) ? summary.domains : [];
  if (domains.length === 0) return ['- No domains found in this scope.'];

  return domains.map((domain) => {
    const emailState = domain.emailValid ? 'valid' : 'invalid';
    const uiState = domain.uiValid ? 'valid' : 'invalid';
    return [
      `- ${sanitizeForLogAndEmail(domain.name, 255)}`,
      `active=${domain.active ? 1 : 0}`,
      `active_mx=${domain.activeMx ? 1 : 0}`,
      `active_ui=${domain.activeUi ? 1 : 0}`,
      `EMAIL=${emailState}`,
      `UI=${uiState}`,
      `rechecks=${recheckStatusText(domain.rechecks)}`
    ].join(' ');
  });
}

function buildForcedSummaryCounts(summary) {
  const value = summary || {};
  return [
    `Total domains: ${sanitizeForLogAndEmail(value.totalDomains || 0, 50)}`,
    `Admin enabled: ${sanitizeForLogAndEmail(value.adminEnabled || 0, 50)}`,
    `Admin disabled: ${sanitizeForLogAndEmail(value.adminDisabled || 0, 50)}`,
    `EMAIL valid: ${sanitizeForLogAndEmail(value.emailValid || 0, 50)}`,
    `EMAIL invalid: ${sanitizeForLogAndEmail(value.emailInvalid || 0, 50)}`,
    `UI valid: ${sanitizeForLogAndEmail(value.uiValid || 0, 50)}`,
    `UI invalid: ${sanitizeForLogAndEmail(value.uiInvalid || 0, 50)}`,
    `Both valid: ${sanitizeForLogAndEmail(value.bothValid || 0, 50)}`,
    `Both invalid: ${sanitizeForLogAndEmail(value.bothInvalid || 0, 50)}`
  ];
}

async function sendForcedRecheckStarted(details) {
  const lines = [
    'An administrator forced a stable DNS recheck.',
    '',
    'Event: FORCED_RECHECK_STARTED',
    `Scope: ${forcedScopeText(details)}`,
    `Started at: ${sanitizeForLogAndEmail(toIso(details.startedAt), 50)}`,
    `Domains in scope: ${sanitizeForLogAndEmail(details.domainCount, 50)}`,
    `Recheck rows in scope: ${sanitizeForLogAndEmail(details.recheckCount, 50)}`,
    '',
    'The normal stable recheck rules will be used. Existing warning, degraded, disabled, and recovered emails may be sent during this forced run.'
  ];

  const subject = `[DNS][FORCED][STARTED] Recheck ${forcedScopeText(details)}`;
  return sendAdminMail(subject, lines.join('\n'));
}

async function sendForcedRecheckCompleted(details) {
  const lines = [
    'A forced stable DNS recheck completed.',
    '',
    'Event: FORCED_RECHECK_COMPLETED',
    `Scope: ${forcedScopeText(details)}`,
    `Started at: ${sanitizeForLogAndEmail(toIso(details.startedAt), 50)}`,
    `Completed at: ${sanitizeForLogAndEmail(toIso(details.completedAt), 50)}`,
    `Duration: ${sanitizeForLogAndEmail(details.durationSeconds, 50)} seconds`,
    `Processed rechecks: ${sanitizeForLogAndEmail(details.processedRechecks, 50)}`,
    `Successful rechecks: ${sanitizeForLogAndEmail(details.successfulRechecks, 50)}`,
    `Failed rechecks: ${sanitizeForLogAndEmail(details.failedRechecks, 50)}`,
    '',
    'Current domain summary:',
    ...buildForcedSummaryCounts(details.summary),
    '',
    'Current domains:',
    ...buildForcedDomainList(details.summary)
  ];

  const subject = `[DNS][FORCED][COMPLETED] Recheck ${forcedScopeText(details)}: ${sanitizeForLogAndEmail(details.summary ? details.summary.emailValid : 0, 50)} EMAIL valid, ${sanitizeForLogAndEmail(details.summary ? details.summary.uiValid : 0, 50)} UI valid`;
  return sendAdminMail(subject, lines.join('\n'));
}

async function sendRequestCreated(details) {
  const lines = [
    'New DNS validation request received.',
    '',
    `type: ${sanitizeForLogAndEmail(details.type, 100)}`,
    `target: ${sanitizeForLogAndEmail(details.target, 255)}`,
    `request_id: ${sanitizeForLogAndEmail(details.id, 50)}`,
    `status: ${sanitizeForLogAndEmail(details.status, 50)}`,
    `timestamp: ${sanitizeForLogAndEmail(toIso(now()), 50)}`,
    `expires_at: ${sanitizeForLogAndEmail(toIso(details.expires_at), 50)}`,
    '',
    buildCriteriaText(details.type)
  ];

  const subject = `[DNS] Request created: ${sanitizeForLogAndEmail(details.type, 50)} ${sanitizeForLogAndEmail(details.target, 100)}`;
  return sendAdminMail(subject, lines.join('\n'));
}

async function sendStatusChange(details) {
  const lines = [
    'DNS validation status changed.',
    '',
    `type: ${sanitizeForLogAndEmail(details.type, 100)}`,
    `target: ${sanitizeForLogAndEmail(details.target, 255)}`,
    `request_id: ${sanitizeForLogAndEmail(details.id, 50)}`,
    `status: ${sanitizeForLogAndEmail(details.status, 50)}`,
    `timestamp: ${sanitizeForLogAndEmail(toIso(now()), 50)}`,
    `expires_at: ${sanitizeForLogAndEmail(toIso(details.expires_at), 50)}`
  ];

  if (details.fail_reason) {
    lines.push(`fail_reason: ${sanitizeForLogAndEmail(details.fail_reason, 500)}`);
  }

  if (details.last_result) {
    lines.push('', 'dns_snapshot:', safeJsonStringify(details.last_result.dns_snapshot, 4000));
    lines.push('', 'missing:', safeJsonStringify(details.last_result.missing, 4000));
  }

  const subject = `[DNS] Status ${sanitizeForLogAndEmail(details.status, 50)}: ${sanitizeForLogAndEmail(details.type, 50)} ${sanitizeForLogAndEmail(details.target, 100)}`;
  return sendAdminMail(subject, lines.join('\n'));
}

module.exports = {
  sendRequestCreated,
  sendStatusChange,
  sendRecheckWarning,
  sendRecheckDegraded,
  sendRecheckDisabled,
  sendRecheckRecovered,
  sendRecheckPeriodicSummary,
  sendForcedRecheckStarted,
  sendForcedRecheckCompleted
};
