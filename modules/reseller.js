const fs = require('fs');
const path = require('path');
const fsPromises = require('fs/promises');

const resselFilePath = path.join(__dirname, '..', 'ressel.db');

let resellerCache = null;
let cacheTime = 0;
const CACHE_TTL = 30000;

function loadResellerList() {
  if (!fs.existsSync(resselFilePath)) return [];
  return fs.readFileSync(resselFilePath, 'utf8').split('\n').map(l => l.trim()).filter(Boolean);
}

function getResellerList() {
  const now = Date.now();
  if (!resellerCache || now - cacheTime > CACHE_TTL) {
    resellerCache = new Set(loadResellerList());
    cacheTime = now;
  }
  return resellerCache;
}

function invalidateResellerCache() {
  resellerCache = null;
  cacheTime = 0;
}

/**
 * Check if a user is reseller by id.
 * @param {number|string} userId
 * @returns {Promise<boolean>}
 */
function isUserReseller(userId) {
  return getResellerList().has(String(userId));
}


/**
 * Add a reseller id to ressel.db (id as string/number)
 * creates file if not exist
 * @param {string|number} id
 */
function addReseller(id) {
  const line = `${String(id)}\n`;
  fs.appendFileSync(resselFilePath, line, { encoding: 'utf8' });
  invalidateResellerCache();
}

/**
 * Remove reseller id from file
 * @param {string|number} id
 */
function removeReseller(id) {
  if (!fs.existsSync(resselFilePath)) return false;
  const content = fs.readFileSync(resselFilePath, 'utf8');
  const lines = content.split('\n').map(l => l.trim()).filter(Boolean);
  const filtered = lines.filter(l => l !== String(id));
  fs.writeFileSync(resselFilePath, filtered.join('\n') + (filtered.length ? '\n' : ''), 'utf8');
  invalidateResellerCache();
  return true;
}

/**
 * Read all reseller ids (sync)
 * @returns {string[]}
 */
function listResellersSync() {
  if (!fs.existsSync(resselFilePath)) return [];
  const content = fs.readFileSync(resselFilePath, 'utf8');
  return content.split('\n').map(l => l.trim()).filter(Boolean);
}

module.exports = { resselFilePath, isUserReseller, addReseller, removeReseller, listResellersSync };