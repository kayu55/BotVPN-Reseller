/**
 * sshcf.js (proxy)
 * Operasi VPN CloudFront PRIVATE diteruskan ke API BotVPN.
 * (Protocol: sshcf / vmesscf / vlesscf / trojancf)
 */
const { opMessage } = require('./_op');

async function createsshcf(username, password, exp, iplimit, server_id, cfDomainOverride) {
  return opMessage({ action: 'create', protocol: 'sshcf', server_id, username, password, duration: exp, iplimit, cf_domain: cfDomainOverride });
}
async function createcfvmess(username, exp, quota, iplimit, server_id, cfDomainOverride) {
  return opMessage({ action: 'create', protocol: 'vmesscf', server_id, username, duration: exp, quota, iplimit, cf_domain: cfDomainOverride });
}
async function createcfvless(username, exp, quota, iplimit, server_id, cfDomainOverride) {
  return opMessage({ action: 'create', protocol: 'vlesscf', server_id, username, duration: exp, quota, iplimit, cf_domain: cfDomainOverride });
}
async function createcftrojan(username, exp, quota, iplimit, server_id, cfDomainOverride) {
  return opMessage({ action: 'create', protocol: 'trojancf', server_id, username, duration: exp, quota, iplimit, cf_domain: cfDomainOverride });
}

async function renewsshcf(username, exp, server_id) {
  return opMessage({ action: 'renew', protocol: 'sshcf', server_id, username, duration: exp });
}
async function renewcfvmess(username, exp, server_id) {
  return opMessage({ action: 'renew', protocol: 'vmesscf', server_id, username, duration: exp });
}
async function renewcfvless(username, exp, server_id) {
  return opMessage({ action: 'renew', protocol: 'vlesscf', server_id, username, duration: exp });
}
async function renewcftrojan(username, exp, server_id) {
  return opMessage({ action: 'renew', protocol: 'trojancf', server_id, username, duration: exp });
}

async function delsshcf(username, server_id) {
  return opMessage({ action: 'delete', protocol: 'sshcf', server_id, username });
}
async function delcfvmess(username, server_id) {
  return opMessage({ action: 'delete', protocol: 'vmesscf', server_id, username });
}
async function delcfvless(username, server_id) {
  return opMessage({ action: 'delete', protocol: 'vlesscf', server_id, username });
}
async function delcftrojan(username, server_id) {
  return opMessage({ action: 'delete', protocol: 'trojancf', server_id, username });
}

async function trialsshcf(username, server_id) {
  return opMessage({ action: 'trial', protocol: 'sshcf', server_id, username });
}
async function trialcfvmess(username, server_id) {
  return opMessage({ action: 'trial', protocol: 'vmesscf', server_id, username });
}
async function trialcfvless(username, server_id) {
  return opMessage({ action: 'trial', protocol: 'vlesscf', server_id, username });
}
async function trialcftrojan(username, server_id) {
  return opMessage({ action: 'trial', protocol: 'trojancf', server_id, username });
}

module.exports = {
  createsshcf, renewsshcf, delsshcf, trialsshcf,
  createcfvmess, createcfvless, createcftrojan,
  trialcfvmess, trialcfvless, trialcftrojan,
  renewcfvmess, renewcfvless, renewcftrojan,
  delcfvmess, delcfvless, delcftrojan
};
