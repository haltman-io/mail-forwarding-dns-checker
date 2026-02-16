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

function buildCriteriaText() {
  const authorizedCnameIps = Array.isArray(config.UI_CNAME_AUTHORIZED_IPS)
    ? config.UI_CNAME_AUTHORIZED_IPS.filter(Boolean)
    : [];
  const cnameRule = authorizedCnameIps.length > 0
    ? `- CNAME chain must resolve to authorized IP(s): ${sanitizeForLogAndEmail(authorizedCnameIps.join(', '), 500)}`
    : `- CNAME must include: ${sanitizeForLogAndEmail(config.UI_CNAME_EXPECTED, 200)}`;

  return [
    'Email forwarding DNS requirements:',
    cnameRule,
    `- MX must include: ${sanitizeForLogAndEmail(config.EMAIL_MX_EXPECTED_HOST, 200)} priority ${sanitizeForLogAndEmail(config.EMAIL_MX_EXPECTED_PRIORITY, 50)}`,
    `- SPF TXT must include: ${sanitizeForLogAndEmail(config.EMAIL_SPF_EXPECTED, 200)}`,
    `- DMARC TXT must include: ${sanitizeForLogAndEmail(config.EMAIL_DMARC_EXPECTED, 200)}`,
    `- DKIM CNAME ${sanitizeForLogAndEmail(config.EMAIL_DKIM_SELECTOR, 100)}._domainkey.<target> must include: ${sanitizeForLogAndEmail(config.EMAIL_DKIM_CNAME_EXPECTED, 255)}`
  ].join('\n');
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
    buildCriteriaText()
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
  sendStatusChange
};
