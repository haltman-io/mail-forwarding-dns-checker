const db = require('../db');
const config = require('../config');
const { log } = require('./time');
const { getApprovalColumn, normalizeApprovalType } = require('./domain-approval');
const { scheduleRecheckAfterApproval } = require('./domain-rechecks');

async function markDomainApprovalActive(target, type, options = {}) {
  try {
    const normalizedType = normalizeApprovalType(type);
    const approvalColumn = getApprovalColumn(type);
    const initialActive = config.DOMAIN_AUTO_APPROVE_ACTIVE ? 1 : 0;
    const activeMx = approvalColumn === 'active_mx' ? 1 : 0;
    const activeUi = approvalColumn === 'active_ui' ? 1 : 0;

    await db.query(
      `INSERT INTO domain (name, active, active_mx, active_ui)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE ${approvalColumn} = VALUES(${approvalColumn})`,
      [target, initialActive, activeMx, activeUi]
    );
    log(`Domain DNS approval updated: ${normalizedType} ${target} (${approvalColumn}=1)`);

    if (config.DNS_RECHECK_ENABLED) {
      try {
        const rows = await db.query('SELECT id FROM domain WHERE name = ? LIMIT 1', [target]);
        if (rows.length > 0) {
          await scheduleRecheckAfterApproval(rows[0].id, normalizedType, options.lastResult || null);
        }
      } catch (err) {
        log(`Failed to schedule domain DNS recheck ${normalizedType} ${target}: ${err.message}`);
      }
    }
  } catch (err) {
    log(`Failed to update domain DNS approval ${type} ${target}: ${err.message}`);
  }
}

async function markDomainApprovalInactive(target, type) {
  try {
    const normalizedType = normalizeApprovalType(type);
    const approvalColumn = getApprovalColumn(type);
    const result = await db.query(
      `UPDATE domain SET ${approvalColumn} = ? WHERE name = ?`,
      [0, target]
    );

    if (result && result.affectedRows > 0) {
      log(`Domain DNS approval updated: ${normalizedType} ${target} (${approvalColumn}=0)`);
    }
  } catch (err) {
    log(`Failed to disable domain DNS approval ${type} ${target}: ${err.message}`);
  }
}

module.exports = {
  getApprovalColumn,
  markDomainApprovalActive,
  markDomainApprovalInactive
};
