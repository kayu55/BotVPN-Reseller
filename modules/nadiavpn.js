/**
 * nadiavpn.js (proxy)
 * Semua operasi VPN CloudFront (API) diteruskan ke API BotVPN.
 */
const dns = require('dns');
const axios = require('axios');
const api = require('./api-client');

async function getServers(force = false) {
  const body = await api.vpncfServers(force);
  return body.data;
}

async function createTrial(serverId, protocol) {
  const body = await api.vpncfTrial({ server_id: serverId, protocol });
  return body.data;
}

async function createVpnVerified(opts) {
  const body = await api.vpncfCreate(opts);
  return body.data;
}

async function renewVpn(accountId, duration, type) {
  const body = await api.vpncfRenew({ account_id: accountId, duration, type });
  return body.data;
}

async function migrateVpn(accountId, newServerId) {
  const body = await api.vpncfMigrate({ account_id: accountId, new_server_id: newServerId });
  return body.data;
}

async function deleteAccount(accountId) {
  const body = await api.vpncfDelete({ account_id: accountId });
  return body.data;
}

async function getAccounts() {
  const body = await api.vpncfAccounts();
  return body.data;
}

async function getAccountDetails(accountId) {
  const body = await api.vpncfAccountDetails(accountId);
  return body.data;
}

async function syncAccount(accountId) {
  const body = await api.vpncfAccountSync(accountId);
  return body.data;
}

async function getBalance() {
  return { balance: 0, reseller_name: '-', email: '-' };
}

const _ispCache = new Map();

async function detectIsp(server) {
  if (!server) return '';
  const host = server.cloudfront_domain || server.domain || '';
  if (!host) return '';
  if (_ispCache.has(host)) return _ispCache.get(host);
  try {
    const { address } = await dns.promises.lookup(host, { family: 4 });
    const res = await axios.get(`http://ip-api.com/json/${address}?fields=status,isp,org`, { timeout: 8000 });
    const isp = res.data && res.data.status === 'success' ? (res.data.isp || res.data.org || '') : '';
    _ispCache.set(host, isp);
    return isp;
  } catch (e) {
    return '';
  }
}

function handleApiError(error) {
  if (!error) return 'Terjadi kesalahan tidak diketahui.';
  return error.message || 'Terjadi kesalahan saat menghubungi server VPN. Silakan coba lagi.';
}

function adminErrorDetail(error) {
  return handleApiError(error);
}

module.exports = {
  getBalance,
  getServers,
  createTrial,
  createVpnVerified,
  renewVpn,
  migrateVpn,
  getAccounts,
  getAccountDetails,
  syncAccount,
  deleteAccount,
  detectIsp,
  handleApiError,
  adminErrorDetail
};
