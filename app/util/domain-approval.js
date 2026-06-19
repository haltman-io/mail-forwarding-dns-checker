function normalizeApprovalType(type) {
  const normalizedType = typeof type === 'string' ? type.toUpperCase() : '';
  if (normalizedType === 'EMAIL' || normalizedType === 'UI') return normalizedType;

  const err = new Error(`Unsupported domain approval type: ${type}`);
  err.code = 'UNSUPPORTED_DOMAIN_APPROVAL_TYPE';
  throw err;
}

function getApprovalColumn(type) {
  const normalizedType = normalizeApprovalType(type);
  if (normalizedType === 'EMAIL') return 'active_mx';
  return 'active_ui';
}

module.exports = {
  normalizeApprovalType,
  getApprovalColumn
};
