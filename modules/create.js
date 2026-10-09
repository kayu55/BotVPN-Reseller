/**
 * create.js (proxy)
 * Operasi CREATE diteruskan ke API BotVPN. Tidak ada akses panel langsung.
 */
const { opMessage } = require('./_op');

async function createssh(username, password, exp, iplimit, server_id) {
  return opMessage({ action: 'create', protocol: 'ssh', server_id, username, password, duration: exp, iplimit });
}
async function createvmess(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'create', protocol: 'vmess', server_id, username, duration: exp, quota, iplimit: limitip });
}
async function createvless(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'create', protocol: 'vless', server_id, username, duration: exp, quota, iplimit: limitip });
}
async function createtrojan(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'create', protocol: 'trojan', server_id, username, duration: exp, quota, iplimit: limitip });
}

module.exports = { createssh, createvmess, createvless, createtrojan };
