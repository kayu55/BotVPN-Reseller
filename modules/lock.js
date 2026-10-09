/**
 * lock.js (proxy)
 * Operasi LOCK diteruskan ke API BotVPN.
 */
const { opMessage } = require('./_op');

async function lockssh(username, password, exp, iplimit, server_id) {
  return opMessage({ action: 'lock', protocol: 'ssh', server_id, username });
}
async function lockvmess(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'lock', protocol: 'vmess', server_id, username });
}
async function lockvless(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'lock', protocol: 'vless', server_id, username });
}
async function locktrojan(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'lock', protocol: 'trojan', server_id, username });
}

module.exports = { locktrojan, lockvless, lockvmess, lockssh };
