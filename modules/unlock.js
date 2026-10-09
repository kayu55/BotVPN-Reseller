/**
 * unlock.js (proxy)
 * Operasi UNLOCK diteruskan ke API BotVPN.
 */
const { opMessage } = require('./_op');

async function unlockssh(username, password, exp, iplimit, server_id) {
  return opMessage({ action: 'unlock', protocol: 'ssh', server_id, username });
}
async function unlockvmess(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'unlock', protocol: 'vmess', server_id, username });
}
async function unlockvless(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'unlock', protocol: 'vless', server_id, username });
}
async function unlocktrojan(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'unlock', protocol: 'trojan', server_id, username });
}

module.exports = { unlocktrojan, unlockvless, unlockvmess, unlockssh };
