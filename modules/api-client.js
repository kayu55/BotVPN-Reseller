/**
 * api-client.js
 * ------------------------------------------------------------------
 * Klien HTTP untuk API reseller BotVPN (server utama).
 * Semua operasi panel (create/renew/delete/lock/unlock/... ) diambil
 * dari server utama lewat HTTP, sehingga bot ini tidak memegang
 * kredensial panel sama sekali.
 */

const axios = require('axios');
const fs = require('fs');
const path = require('path');

let _config = null;

function loadConfig() {
  if (_config) return _config;
  let vars = {};
  try {
    vars = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '.vars.json'), 'utf8'));
  } catch (e) {
    vars = {};
  }
  _config = {
    baseURL: vars.API_BASE_URL || 'https://api.rajaserver.web.id/api/v1',
    apiKey: vars.API_KEY || ''
  };
  return _config;
}

let _client = null;

function getClient() {
  if (_client) return _client;
  const { baseURL, apiKey } = loadConfig();
  if (!apiKey) {
    throw new Error('API_KEY belum dikonfigurasi di .vars.json');
  }
  _client = axios.create({
    baseURL,
    timeout: 130000,
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      Accept: 'application/json'
    }
  });
  return _client;
}

async function request(method, url, data, config = {}) {
  const client = getClient();
  try {
    const res = await client.request({ method, url, data, ...config });
    return res.data;
  } catch (error) {
    const status = error.response && error.response.status;
    const body = error.response && error.response.data;
    let message = (body && body.message) || error.message;
    const code = (body && body.code) || 'API_ERROR';
    if (status === 401) message = 'API Key tidak valid';
    else if (status === 403) message = 'Akun reseller tidak aktif / akses ditolak';
    else if (status === 402) message = message || 'Saldo reseller (upstream) tidak cukup';
    else if (status === 429) message = 'Terlalu banyak request, coba lagi nanti';
    else if (status === 502 || status === 503 || status === 530) message = 'API BotVPN tidak dapat diakses (server/tunnel sedang offline)';
    else if (status === undefined) message = 'Tidak dapat terhubung ke API BotVPN';
    const err = new Error(message);
    err.apiStatus = status;
    err.apiCode = code;
    err.apiBody = body;
    if (body && body.uncertain) err.uncertain = true;
    if (code === 'ORDER_FAILED') err.notCreated = true;
    throw err;
  }
}

const api = {
  request,
  getServerList: () => request('get', '/servers'),
  getProducts: () => request('get', '/products'),
  getBalance: () => request('get', '/balance'),
  getMe: () => request('get', '/me'),

  operation: (payload) => request('post', '/operations', payload),

  createAccount: (payload, idempotencyKey) => {
    const headers = {};
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    return request('post', '/operations', { action: 'create', ...payload }, { headers });
  },
  renewAccount: (payload, idempotencyKey) => {
    const headers = {};
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    return request('post', '/operations', { action: 'renew', ...payload }, { headers });
  },

  // EDU Direct
  eduProducts: () => request('get', '/edu/products'),
  eduAccounts: () => request('get', '/edu/accounts'),
  eduRenewable: () => request('get', '/edu/renewable'),
  eduTrial: (payload) => request('post', '/edu/trial', payload),
  eduOrder: (payload) => request('post', '/edu/order', payload),
  eduRenew: (payload) => request('post', '/edu/renew', payload),

  // VPN CloudFront API
  vpncfServers: (force) => request('get', '/vpncf/servers' + (force ? '?force=1' : '')),
  vpncfAccounts: () => request('get', '/vpncf/accounts'),
  vpncfAccountDetails: (accountId) => request('post', '/vpncf/account/details', { account_id: accountId }),
  vpncfAccountSync: (accountId) => request('post', '/vpncf/account/sync', { account_id: accountId }),
  vpncfCreate: (payload) => request('post', '/vpncf/create', payload),
  vpncfTrial: (payload) => request('post', '/vpncf/trial', payload),
  vpncfRenew: (payload) => request('post', '/vpncf/renew', payload),
  vpncfMigrate: (payload) => request('post', '/vpncf/migrate', payload),
  vpncfDelete: (payload) => request('post', '/vpncf/delete', payload)
};

module.exports = api;
