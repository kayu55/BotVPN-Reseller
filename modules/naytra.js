/**
 * naytra.js (proxy)
 * Semua operasi VPN EDU DIRECT diteruskan ke API BotVPN.
 */
const api = require('./api-client');

async function getEduProducts() {
  const body = await api.eduProducts();
  return body.data;
}

async function getEduAccounts() {
  const body = await api.eduAccounts();
  return body.data;
}

async function getEduRenewable() {
  const body = await api.eduRenewable();
  return body.data;
}

async function trialEdu(data) {
  const body = await api.eduTrial(data);
  return body.data;
}

async function orderEdu(data) {
  const body = await api.eduOrder(data);
  return body.data;
}

async function orderEduVerified(data) {
  const body = await api.eduOrder(data);
  // API mengembalikan { recovered, raw }
  const d = body.data;
  if (d && d.raw !== undefined) return d;
  return { recovered: false, raw: d };
}

async function renewEdu(data) {
  const body = await api.eduRenew(data);
  return body.data;
}

function isEduSuccess(raw) {
  if (!raw || typeof raw !== 'object') return false;
  if (raw.status === 'success' || raw.status === true || raw.success === true) return true;
  if (!raw.error && raw.username) return true;
  const inner = raw.data;
  if (inner && typeof inner === 'object') return isEduSuccess(inner);
  return false;
}

function handleApiError(error) {
  if (!error) return 'Terjadi kesalahan tidak diketahui.';
  return error.message || 'Terjadi kesalahan saat menghubungi server. Silakan coba lagi.';
}

module.exports = {
  getEduProducts,
  orderEdu,
  orderEduVerified,
  trialEdu,
  getEduAccounts,
  getEduRenewable,
  renewEdu,
  isEduSuccess,
  handleApiError
};
