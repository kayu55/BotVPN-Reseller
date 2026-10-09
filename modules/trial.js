/**
 * trial.js (proxy)
 * Operasi TRIAL diteruskan ke API BotVPN.
 */
const { opMessage } = require('./_op');

async function trialssh(username, password, exp, iplimit, server_id) {
  return opMessage({ action: 'trial', protocol: 'ssh', server_id, username });
}
async function trialvmess(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'trial', protocol: 'vmess', server_id, username });
}
async function trialvless(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'trial', protocol: 'vless', server_id, username });
}
async function trialtrojan(username, exp, quota, limitip, server_id) {
  return opMessage({ action: 'trial', protocol: 'trojan', server_id, username });
}

module.exports = { trialssh, trialvmess, trialvless, trialtrojan };
