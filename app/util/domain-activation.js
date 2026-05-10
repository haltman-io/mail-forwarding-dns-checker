const db = require('../db');
const { log } = require('./time');

async function markDomainAsActive(target) {
  try {
    await db.query(
      'INSERT INTO domain (name, active) VALUES (?, ?) ON DUPLICATE KEY UPDATE active = VALUES(active)',
      [target, 1]
    );
    log(`Domain marked as active: ${target}`);
  } catch (err) {
    log(`Failed to mark domain active ${target}: ${err.message}`);
  }
}

module.exports = {
  markDomainAsActive
};
