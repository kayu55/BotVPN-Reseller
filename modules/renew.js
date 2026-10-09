/**
 * renew.js (proxy)
 * Operasi RENEW diteruskan ke API BotVPN.
 */
const { opMessage } = require('./_op');

async function renewssh(username, exp, limitip, server_id) {
  return opMessage({ action: 'renew', protocol: 'ssh', server_id, username, duration: exp, iplimit: limitip });
}
async function renewvmess(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'renew', protocol: 'vmess', server_id, username, duration: exp, quota, iplimit: limitip });
}
async function renewvless(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'renew', protocol: 'vless', server_id, username, duration: exp, quota, iplimit: limitip });
}
async function renewtrojan(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'renew', protocol: 'trojan', server_id, username, duration: exp, quota, iplimit: limitip });
}

module.exports = { renewssh, renewvmess, renewvless, renewtrojan };
