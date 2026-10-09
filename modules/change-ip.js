/**
 * change-ip.js (proxy)
 * Operasi GANTI LIMIT IP diteruskan ke API BotVPN.
 */
const { opMessage } = require('./_op');

async function changelimipsshvpn(username, password, exp, iplimit, server_id, domainOverride) {
  return opMessage({ action: 'changelimip', protocol: 'ssh', server_id, username, target_ip: iplimit });
}
async function changelimipvmess(username, exp, quota, iplimit, server_id, domainOverride) {
  return opMessage({ action: 'changelimip', protocol: 'vmess', server_id, username, target_ip: iplimit });
}
async function changelimipvless(username, exp, quota, iplimit, server_id, domainOverride) {
  return opMessage({ action: 'changelimip', protocol: 'vless', server_id, username, target_ip: iplimit });
}
async function changelimiptrojan(username, exp, quota, iplimit, server_id, domainOverride) {
  return opMessage({ action: 'changelimip', protocol: 'trojan', server_id, username, target_ip: iplimit });
}

module.exports = { changelimiptrojan, changelimipvless, changelimipvmess, changelimipsshvpn };
