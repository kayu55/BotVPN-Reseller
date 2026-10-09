/**
 * del.js (proxy)
 * Operasi DELETE + pengecekan akun diteruskan ke API BotVPN.
 */
const { opMessage, opData } = require('./_op');
const store = require('./server-store');

async function delssh(username, password, exp, iplimit, server_id) {
  return opMessage({ action: 'delete', protocol: 'ssh', server_id, username });
}
async function delvmess(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'delete', protocol: 'vmess', server_id, username });
}
async function delvless(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'delete', protocol: 'vless', server_id, username });
}
async function deltrojan(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'delete', protocol: 'trojan', server_id, username });
}

async function cekByDomain(domain, username, type) {
  const server = await store.getByDomain(domain);
  if (!server) return null;
  const data = await opData({ action: 'cek', protocol: type, server_id: server.id, username });
  // API membungkus hasil: { success, data: {...} } -> ambil bagian dalam
  if (data && data.data !== undefined) return data.data;
  return data;
}

async function checkAccountExpiry(domain, auth, username, type) {
  try {
    const data = await cekByDomain(domain, username, type);
    if (data && data.expired) return data.expired;
  } catch (e) {
    // diabaikan, caller menangani null
  }
  return null;
}

async function checkAccountFull(domain, auth, username, type) {
  try {
    return await cekByDomain(domain, username, type);
  } catch (e) {
    return null;
  }
}

module.exports = { deltrojan, delvless, delvmess, delssh, checkAccountExpiry, checkAccountFull };
