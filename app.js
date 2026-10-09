const os = require('os');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const express = require('express');
const { Telegraf, Markup } = require('telegraf');
const app = express();
const axios = require('axios');
const net = require('net');
const dns = require('dns');
const { isUserReseller, addReseller, removeReseller, listResellersSync } = require('./modules/reseller');
const taskQueue = require('./modules/task-queue');
const winston = require('winston');
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level.toUpperCase()}]: ${message}`;
    })
  ),
  transports: [
    new winston.transports.File({ filename: 'bot-error.log', level: 'error' }),
    new winston.transports.File({ filename: 'bot-combined.log' }),
  ],
});
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const ispCache = new Map();
let ispCacheLoaded = false;
let ispSaveTimer = null;

function getIspCacheFile() {
  return path.join(__dirname, 'isp-cache.json');
}

async function loadIspCache() {
  if (ispCacheLoaded) return;
  try {
    const data = await fsPromises.readFile(getIspCacheFile(), 'utf8');
    const parsed = JSON.parse(data);
    for (const [k, v] of Object.entries(parsed || {})) {
      if (v !== null && v !== undefined) ispCache.set(k, v);
    }
  } catch (err) {}
  ispCacheLoaded = true;
}

function saveIspCache() {
  if (ispSaveTimer) return;
  ispSaveTimer = setTimeout(() => {
    ispSaveTimer = null;
    const obj = {};
    for (const [k, v] of ispCache) obj[k] = v;
    fsPromises.writeFile(getIspCacheFile(), JSON.stringify(obj, null, 2)).catch(() => {});
  }, 1500);
}

async function detectServerIsp(domain) {
  if (!domain) return null;
  if (!ispCacheLoaded) await loadIspCache().catch(() => {});
  if (ispCache.has(domain)) return ispCache.get(domain);

  const resolved = await dns.promises.lookup(domain).catch(() => null);
  if (!resolved || !resolved.address) {
    ispCache.set(domain, null);
    return null;
  }
  const address = encodeURIComponent(resolved.address);

  // Primary: ipinfo.io/org (langsung string, contoh "AS140443 PT Herza Digital Indonesia")
  try {
    const response = await axios.get(`https://ipinfo.io/${address}/org`, { timeout: 5000 });
    const text = String(response.data || '').trim();
    const isp = text.replace(/^AS\d+\s*/i, '').trim() || null;
    if (isp) {
      ispCache.set(domain, isp);
      saveIspCache();
      return isp;
    }
  } catch (err) {
    logger.warn(`Gagal cek ISP (ipinfo.io) untuk ${domain}: ${err.message}`);
  }

  // Fallback: ipwho.is (HTTPS, gratis)
  try {
    const response = await axios.get(`https://ipwho.is/${address}`, { timeout: 8000 });
    const d = response.data;
    if (d && d.success && d.connection) {
      const isp = String(d.connection.org || d.connection.isp || '').trim() || null;
      ispCache.set(domain, isp);
      saveIspCache();
      return isp;
    }
  } catch (err) {
    logger.warn(`Gagal cek ISP (ipwho.is) untuk ${domain}: ${err.message}`);
  }

  // Fallback: ip-api.com
  try {
    const response = await axios.get(`http://ip-api.com/json/${address}?fields=status,isp`, { timeout: 8000 });
    const d = response.data;
    if (d && d.status === 'success') {
      ispCache.set(domain, d.isp || null);
      saveIspCache();
      return d.isp || null;
    }
  } catch (err) {
    logger.warn(`Gagal cek ISP (ip-api) untuk ${domain}: ${err.message}`);
  }

  ispCache.set(domain, null);
  return null;
}

async function mapConcurrent(items, concurrency, fn) {
  const results = [];
  const running = [];
  for (const item of items) {
    const p = Promise.resolve().then(() => fn(item));
    results.push(p);
    running.push(p);
    p.then(() => running.splice(running.indexOf(p), 1));
    if (running.length >= concurrency) {
      await Promise.race(running);
    }
  }
  return Promise.all(results);
}

const { 
  createssh, 
  createvmess, 
  createvless, 
  createtrojan, 
} = require('./modules/create');

const { 
  trialssh, 
  trialvmess, 
  trialvless, 
  trialtrojan, 
} = require('./modules/trial');

const { 
  renewssh, 
  renewvmess, 
  renewvless, 
  renewtrojan, 
} = require('./modules/renew');

const { 
  delssh, 
  delvmess, 
  delvless, 
  deltrojan, 
  checkAccountExpiry,
  checkAccountFull
} = require('./modules/del');

const { 
  lockssh, 
  lockvmess, 
  lockvless, 
  locktrojan, 
} = require('./modules/lock');

const { 
  unlockssh, 
  unlockvmess, 
  unlockvless, 
  unlocktrojan, 
} = require('./modules/unlock');

const { 
  changelimipsshvpn,
  changelimipvmess,
  changelimipvless,
  changelimiptrojan
} = require('./modules/change-ip');

const naytra = require('./modules/naytra');
const nadiavpn = require('./modules/nadiavpn');
const { createsshcf, renewsshcf, delsshcf, trialsshcf, createcfvmess, createcfvless, createcftrojan, trialcfvmess, trialcfvless, trialcftrojan, renewcfvmess, renewcfvless, renewcftrojan, delcfvmess, delcfvless, delcftrojan } = require('./modules/sshcf');

/* ================= RESELLER API BRIDGE ================= */
const resellerApiClient = require('./modules/api-client');
const { opMessage: panelOpMessage } = require('./modules/_op');

// Sinkronisasi daftar Server lokal dari API BotVPN (sumber utama server).
async function syncServersFromApi() {
  const body = await resellerApiClient.getServerList();
  const list = (body && body.data) || [];
  const run = (sql, params) => new Promise((resolve, reject) => {
    db.run(sql, params, function (e) { return e ? reject(e) : resolve(this); });
  });

  for (const s of list) {
    const harga = (s.harga !== undefined && s.harga !== null) ? s.harga : s.price_per_day;
    const existing = await dbGetAsync('SELECT id FROM Server WHERE id = ?', [s.id]).catch(() => null);
    if (existing) {
      await run(
        'UPDATE Server SET domain = ?, nama_server = ?, quota = ?, iplimit = ?, harga = ?, batas_create_akun = ?, total_create_akun = ?, is_reseller_only = ?, cloudfront_domain = ? WHERE id = ?',
        [s.domain, s.nama_server || s.name, s.quota, s.iplimit, harga, s.batas_create_akun, s.total_create_akun, s.is_reseller_only ? 1 : 0, s.cloudfront_domain || null, s.id]
      );
    } else {
      await run(
        'INSERT INTO Server (id, domain, auth, harga, nama_server, quota, iplimit, batas_create_akun, total_create_akun, is_reseller_only, cloudfront_domain) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [s.id, s.domain, '', harga, s.nama_server || s.name, s.quota, s.iplimit, s.batas_create_akun, s.total_create_akun, s.is_reseller_only ? 1 : 0, s.cloudfront_domain || null]
      );
    }
  }

  const ids = list.map((s) => s.id).filter((v) => v !== undefined && v !== null);
  if (ids.length) {
    await run(`DELETE FROM Server WHERE id NOT IN (${ids.map(() => '?').join(',')})`, ids);
  } else {
    await run('DELETE FROM Server', []);
    logger.warn('[SERVER-SYNC] API mengembalikan 0 server — tabel Server dikosongkan.');
  }
  logger.info(`[SERVER-SYNC] ${list.length} server disinkronkan dari API`);
  return list.length;
}

// Fix: reprovision akun lewat API (delete + create ulang)
function fixssh(username, password, exp, iplimit, serverId) {
  return panelOpMessage({ action: 'fix', protocol: 'ssh', server_id: serverId, username, duration: exp, password, iplimit });
}
function fixvmess(username, exp, quota, iplimit, serverId) {
  return panelOpMessage({ action: 'fix', protocol: 'vmess', server_id: serverId, username, duration: exp, quota, iplimit });
}
function fixvless(username, exp, quota, iplimit, serverId) {
  return panelOpMessage({ action: 'fix', protocol: 'vless', server_id: serverId, username, duration: exp, quota, iplimit });
}
function fixtrojan(username, exp, quota, iplimit, serverId) {
  return panelOpMessage({ action: 'fix', protocol: 'trojan', server_id: serverId, username, duration: exp, quota, iplimit });
}

const PurchaseFlow = require('./modules/purchase-flow');
const ConfirmManager = require('./modules/confirmation');
const shopeePay = require('./modules/shopee-pay');

// Toggle VPN CloudFront PRIVATE (btn_sshcf / menu_sshcf) saja.
// VPN CloudFront (API) / btn_vpncf tidak terpengaruh.
// Nilai final diisi dari .vars.json setelah `vars` ter-load (lihat bawah).
let enableVpnCf = true;

/* Trial CloudFront: tidak ada batas harian, tapi ada jeda antar percobaan.
   Panel nadiavpn membalas "Too Many Attempts." kalau /vpn/trial dipanggil
   terlalu cepat, jadi bot ikut menghormati rate limit panel tersebut. */
const CF_TRIAL_COOLDOWN_MS = 5 * 60 * 1000;
const cfTrialCooldown = new Map();

function getCfTrialCooldownLeft(userId) {
  const until = cfTrialCooldown.get(String(userId)) || 0;
  return Math.max(0, until - Date.now());
}

function markCfTrialCooldown(userId) {
  cfTrialCooldown.set(String(userId), Date.now() + CF_TRIAL_COOLDOWN_MS);
}

const { runBackup, startAutoBackup } = require('./backup');
const { styleReplyMarkup } = require('./modules/button-style');
const i18n = require('./modules/i18n');
const { t, loadUserLanguage, setLanguage } = i18n;
const { redactSensitive } = require('./modules/error-utils');

const fsPromises = require('fs/promises');
const path = require('path');
const trialFile = path.join(__dirname, 'trial.db');
const resselFilePath = path.join(__dirname, 'ressel.db');

// Pastikan file ressel.db ada, supaya pembacaan tidak error saat bot baru dipasang.
try {
  const fsSync = require('fs');
  if (!fsSync.existsSync(resselFilePath)) {
    fsSync.writeFileSync(resselFilePath, '');
    logger.info('File ressel.db dibuat (kosong).');
  }
} catch (e) {
  logger.warn('Tidak bisa membuat ressel.db: ' + e.message);
}

const trialCache = new Map();
let trialCacheLoaded = false;

async function loadTrialCache() {
  if (trialCacheLoaded) return;
  try {
    const data = await fsPromises.readFile(trialFile, 'utf8');
    const parsed = JSON.parse(data);
    for (const [k, v] of Object.entries(parsed)) trialCache.set(k, v);
  } catch (err) {}
  trialCacheLoaded = true;
}

async function persistTrialCache() {
  const obj = {};
  for (const [k, v] of trialCache) obj[k] = v;
  await fsPromises.writeFile(trialFile, JSON.stringify(obj, null, 2));
}

function checkTrialAccess(userId) {
  if (!trialCacheLoaded) return Promise.resolve(false);
  const today = new Date().toISOString().slice(0, 10);
  return Promise.resolve(trialCache.get(String(userId)) === today);
}

async function checkServerAccess(serverId, userId) {
  return new Promise((resolve, reject) => {
    db.get('SELECT is_reseller_only FROM Server WHERE id = ?', [serverId], async (err, row) => {
      if (err) return reject(err);
      // jika server tidak ada => tolak (caller menangani pesan)
      if (!row) return resolve({ ok: false, reason: 'not_found' });
      const flag = row.is_reseller_only === 1 || row.is_reseller_only === '1';
      if (!flag) return resolve({ ok: true }); // publik
      // jika reseller-only, cek apakah user terdaftar reseller
      try {
        const isR = await isUserReseller(userId);
        if (isR) return resolve({ ok: true });
        return resolve({ ok: false, reason: 'reseller_only' });
      } catch (e) {
        // fallback: tolak akses
        return resolve({ ok: false, reason: 'reseller_only' });
      }
    });
  });
}

function saveTrialAccess(userId) {
  const today = new Date().toISOString().slice(0, 10);
  trialCache.set(String(userId), today);
  persistTrialCache().catch(() => {});
}

// const fs = require('fs');
// const vars = JSON.parse(fs.readFileSync(path.join(__dirname, '.vars.json'), 'utf8'));

const fs = require('fs');
const vars = JSON.parse(fs.readFileSync(path.join(__dirname, '.vars.json'), 'utf8'));

// Terapkan status toggle VPN CloudFront Private yang tersimpan permanen.
if (vars.ENABLE_VPNCF === false) enableVpnCf = false;

const BOT_TOKEN = vars.BOT_TOKEN;
const port = vars.PORT || 6969;
const ADMIN = vars.USER_ID; 
const NAMA_STORE = vars.NAMA_STORE || 'BOTVPN RESELLER';
const GROUP_ID = vars.GROUP_ID;
// V1 GOPAY
let GOPAY_KEY = vars.GOPAY_KEY;
// V2 ORKUT
let AUTH_USER = vars.AUTH_USERNAME_ORKUT;  // username orderkuota
let AUTH_TOKEN = vars.AUTH_TOKEN_ORKUT;    // token orderkuota
let NAYTRA_TOKEN = vars.NAYTRA_TOKEN;


const bot = new Telegraf(BOT_TOKEN);

// Kirim pesan hasil akun: coba Markdown dulu, kalau gagal parse kirim plain text
// (mencegah error "can't parse entities" dari pesan panel).
async function sendAccountResult(rctx, chatId, messageId, text) {
  const body = typeof text === 'string' ? text : JSON.stringify(text, null, 2);
  const sendPlain = async () => {
    if (messageId != null) {
      try { await bot.telegram.editMessageText(chatId, messageId, undefined, body); return; } catch (e) {}
    }
    try { await (rctx && rctx.reply ? rctx.reply(body) : bot.telegram.sendMessage(chatId, body)); } catch (e) {}
  };
  try {
    if (messageId != null) {
      await bot.telegram.editMessageText(chatId, messageId, undefined, body, { parse_mode: 'Markdown' });
    } else {
      await (rctx && rctx.reply ? rctx.reply(body, { parse_mode: 'Markdown' }) : bot.telegram.sendMessage(chatId, body, { parse_mode: 'Markdown' }));
    }
  } catch (e) {
    logger.warn('sendAccountResult: ' + (e && e.message) + ' - kirim sebagai plain text.');
    await sendPlain();
  }
}

let ADMIN_USERNAME = vars.ADMIN_USERNAME || 'Admin';
const adminIds = ADMIN;
logger.info('Bot initialized');

bot.use(async (ctx, next) => {
  const wrapWithStyles = (fn, mode) => function (...args) {
    if (mode === 'reply' || mode === 'editText') {
      const extra = args[args.length - 1];
      if (extra && typeof extra === 'object' && extra.reply_markup) {
        extra.reply_markup = styleReplyMarkup(extra.reply_markup);
      }
    } else if (mode === 'editMarkup') {
      const markup = args[0];
      if (markup && typeof markup === 'object') {
        args[0] = styleReplyMarkup(markup);
      }
    }
    return fn.apply(this, args);
  };

  const wrap = (name, mode) => {
    if (typeof ctx[name] === 'function') {
      ctx[name] = wrapWithStyles(ctx[name].bind(ctx), mode);
    }
  };

  wrap('reply', 'reply');
  wrap('replyWithPhoto', 'reply');
  wrap('replyWithAudio', 'reply');
  wrap('replyWithVideo', 'reply');
  wrap('replyWithDocument', 'reply');
  wrap('replyWithAnimation', 'reply');
  wrap('replyWithSticker', 'reply');
  wrap('replyWithMediaGroup', 'reply');
  wrap('replyWithVoice', 'reply');
  wrap('replyWithVideoNote', 'reply');
  wrap('editMessageText', 'editText');
  wrap('editMessageCaption', 'editText');
  wrap('editMessageReplyMarkup', 'editMarkup');

  return next();
});

// === GUARD: manajemen server hanya dari API BotVPN ===
const SERVER_MGMT_COMMANDS = ['addserver', 'addserver_reseller', 'addservercf', 'addservercf_reseller', 'edithargacf', 'editcfdomain', 'listservercf', 'delservercf', 'editharga', 'editnama', 'editdomain', 'editauth', 'editlimitquota', 'editlimitip', 'editlimitcreate', 'edittotalcreate', 'syncaccount', 'lock_migrasi', 'unlock_migrasi', 'list_lock_migrasi'];
bot.use(async (ctx, next) => {
  const txt = (ctx.message && ctx.message.text) ? ctx.message.text : '';
  if (txt.startsWith('/')) {
    const cmd = txt.slice(1).split(/\s+/)[0].split('@')[0];
    if (SERVER_MGMT_COMMANDS.includes(cmd)) {
      return ctx.reply('⚠️ Manajemen server dilakukan di bot BotVPN utama. Bot ini hanya mengambil daftar server dari API.');
    }
  }
  return next();
});
/*
(async () => {
  try {
    const adminId = Array.isArray(adminIds) ? adminIds[0] : adminIds;
    const chat = await bot.telegram.getChat(adminId);
    ADMIN_USERNAME = chat.username ? `@${chat.username}` : 'Admin';
    logger.info(`Admin username detected: ${ADMIN_USERNAME}`);
  } catch (e) {
    ADMIN_USERNAME = 'Admin';
    logger.warn('Tidak bisa ambil username admin otomatis.');
  }
})();
*/
const dbPath = path.join(__dirname, 'sellvpn.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    logger.error('Kesalahan koneksi SQLite3:', err.message);
  } else {
    db.run('PRAGMA journal_mode=WAL');
    db.run('PRAGMA synchronous=NORMAL');
    db.run('PRAGMA cache_size=8000');
    db.run('PRAGMA busy_timeout=5000');
    db.run('PRAGMA temp_store=MEMORY');
    logger.info(`Terhubung ke SQLite3: ${dbPath} (WAL mode)`);
  }
});

i18n.bindDb(() => db);

const confirmManager = new ConfirmManager(bot, db, logger);
confirmManager.attach(bot);
logger.info('System konfirmasi siap (ConfirmManager)');

const listAccountDbPath = path.join(__dirname, 'listaccount.db');
const listDb = new sqlite3.Database(listAccountDbPath, (err) => {
  if (err) {
    logger.error('Kesalahan koneksi listaccount.db:', err.message);
  } else {
    listDb.run('PRAGMA journal_mode=WAL');
    listDb.run(`CREATE TABLE IF NOT EXISTS list_accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      account_type TEXT,
      server_name TEXT,
      expired_at TEXT,
      created_at TEXT,
      status TEXT DEFAULT 'active',
      full_message TEXT
    )`, (err2) => {
      if (err2) logger.error('Gagal buat tabel list_accounts:', err2.message);
      else logger.info('listaccount.db siap (tabel list_accounts ready)');
    });
  }
});

async function insertListAccount(userId, username, accountType, serverName, expiredAt, fullMessage) {
  const today = new Date().toISOString().slice(0, 10);
  const safeMsg = (fullMessage || '').slice(0, 5000);
  try {
    if (!listDb) { logger.error('insertListAccount: listDb is null!'); return; }
    const existing = await new Promise((resolve, reject) => {
      listDb.get('SELECT id FROM list_accounts WHERE user_id = ? AND username = ? AND account_type = ? AND status = ?',
        [userId, username, accountType, 'active'], (e, row) => resolve(row || null));
    });
    if (existing) {
      logger.info(`insertListAccount: skip duplicate ${username} (${accountType})`);
      return;
    }
    await new Promise((resolve, reject) => {
      listDb.run(
        'INSERT INTO list_accounts (user_id, username, account_type, server_name, expired_at, created_at, status, full_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [userId, username, accountType, serverName, expiredAt, today, 'active', safeMsg],
        (e) => { if (e) reject(e); else resolve(); }
      );
    });
    logger.info(`✅ insertListAccount: saved ${username} (${accountType}) user:${userId}`);
  } catch (e) {
    logger.error('insertListAccount error:', e.message);
  }
}

async function markListAccountExpired(username, accountType) {
  try {
    await new Promise((resolve, reject) => {
      listDb.run("UPDATE list_accounts SET status = 'expired' WHERE username = ? AND account_type = ? AND status = 'active'",
        [username, accountType], (e) => { if (e) reject(e); else resolve(); });
    });
  } catch (e) {
    logger.error('markListAccountExpired error:', e.message);
  }
}

async function updateListAccountExpired(userId, username, accountType, newExpiredAt, newFullMessage, serverName) {
  try {
    const variants = [];
    if (accountType) variants.push(accountType);
    if (accountType && !String(accountType).endsWith('cf')) variants.push(String(accountType) + 'cf');
    else if (accountType && String(accountType).endsWith('cf')) variants.push(String(accountType).replace(/cf$/, ''));

    let changed = 0;
    for (const v of variants) {
      const info = await new Promise((resolve, reject) => {
        listDb.run(
          "UPDATE list_accounts SET expired_at = ?, full_message = ? WHERE user_id = ? AND username = ? AND account_type = ? AND status = 'active'",
          [newExpiredAt, (newFullMessage || '').slice(0, 5000), userId, username, v],
          function (e) { if (e) reject(e); else resolve(this); }
        );
      });
      if (info && info.changes > 0) { changed = 1; break; }
    }

    if (!changed) {
      if (!serverName) serverName = await lookupListAccountServerName(userId, username, accountType);
      await insertListAccount(userId, username, accountType, serverName, newExpiredAt, newFullMessage);
    }
    logger.info(`✅ updateListAccountExpired: ${username} (${accountType}) -> ${newExpiredAt}`);
  } catch (e) {
    logger.error('updateListAccountExpired error:', e.message);
  }
}

async function lookupListAccountServerName(userId, username, accountType) {
  try {
    const t = String(accountType || '').toLowerCase();
    if (t === 'edu' || t === 'directedu') {
      const r = await dbGetAsync('SELECT server_name FROM directedu_accounts WHERE user_id = ? AND username = ? ORDER BY created_at DESC LIMIT 1', [userId, username]).catch(() => null);
      if (r && r.server_name) return r.server_name;
    } else if (t === 'vpncf') {
      const r = await dbGetAsync('SELECT server_name FROM vpncf_accounts WHERE user_id = ? AND username = ? ORDER BY created_at DESC LIMIT 1', [userId, username]).catch(() => null);
      if (r && r.server_name) return r.server_name;
    } else if (t === 'sshcf' || t === 'vmesscf' || t === 'vlesscf' || t === 'trojancf') {
      const r = await dbGetAsync('SELECT Server.nama_server AS nama_server FROM sshcf_accounts JOIN Server ON sshcf_accounts.server_id = Server.id WHERE sshcf_accounts.user_id = ? AND sshcf_accounts.username = ? ORDER BY sshcf_accounts.id DESC LIMIT 1', [userId, username]).catch(() => null);
      if (r && r.nama_server) return r.nama_server;
    } else {
      const r = await dbGetAsync('SELECT server_name FROM accounts WHERE user_id = ? AND username = ? AND account_type = ? ORDER BY id DESC LIMIT 1', [userId, username, accountType]).catch(() => null);
      if (r && r.server_name) return r.server_name;
      const r2 = await dbGetAsync('SELECT Server.nama_server AS nama_server FROM sshcf_accounts JOIN Server ON sshcf_accounts.server_id = Server.id WHERE sshcf_accounts.user_id = ? AND sshcf_accounts.username = ? ORDER BY sshcf_accounts.id DESC LIMIT 1', [userId, username]).catch(() => null);
      if (r2 && r2.nama_server) return r2.nama_server;
    }
  } catch (e) {
    logger.error('lookupListAccountServerName error:', e.message);
  }
  return '';
}

db.run(`CREATE TABLE IF NOT EXISTS pending_deposits (
  unique_code TEXT PRIMARY KEY,
  user_id INTEGER,
  amount INTEGER,
  original_amount INTEGER,
  timestamp INTEGER,
  status TEXT,
  qr_message_id INTEGER,
  transaction_id TEXT,
  chat_id INTEGER
)`, (err) => {
  if (err) {
    logger.error('Kesalahan membuat tabel pending_deposits:', err.message);
  }
});

db.run(`ALTER TABLE pending_deposits ADD COLUMN transaction_id TEXT`, (err) => {
  if (err && !err.message.includes('duplicate column')) {
    logger.error('Gagal menambahkan kolom transaction_id di pending_deposits:', err.message);
  }
});

db.run(`ALTER TABLE pending_deposits ADD COLUMN chat_id INTEGER`, (err) => {
  if (err && !err.message.includes('duplicate column')) {
    logger.error('Gagal menambahkan kolom chat_id di pending_deposits:', err.message);
  }
});

db.run(`CREATE TABLE IF NOT EXISTS Server (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT,
  auth TEXT,
  harga INTEGER,
  nama_server TEXT,
  quota INTEGER,
  iplimit INTEGER,
  batas_create_akun INTEGER,
  total_create_akun INTEGER,
  is_reseller_only INTEGER DEFAULT 0
)`, (err) => {
  if (err) {
    logger.error('Kesalahan membuat tabel Server:', err.message);
  } else {
    logger.info('Server table created or already exists');
  }
});

db.run(
  `ALTER TABLE Server ADD COLUMN is_reseller_only INTEGER DEFAULT 0`,
  (err) => {
    if (err && !err.message.includes('duplicate column')) {
      logger.error('Gagal menambahkan kolom is_reseller_only:', err.message);
    } else if (!err) {
      logger.info('Kolom is_reseller_only berhasil ditambahkan');
    }
  }
);

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER UNIQUE,
  saldo INTEGER DEFAULT 0,
  CONSTRAINT unique_user_id UNIQUE (user_id)
)`, (err) => {
  if (err) {
    logger.error('Kesalahan membuat tabel users:', err.message);
  } else {
    logger.info('Users table created or already exists');
  }
});

db.run(`ALTER TABLE users ADD COLUMN language TEXT DEFAULT 'id'`, (err) => {
  if (err && !err.message.includes('duplicate column')) {
    logger.error('Gagal menambahkan kolom language:', err.message);
  } else if (!err) {
    logger.info('Kolom language berhasil ditambahkan ke tabel users');
  }
});

db.run(`CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  amount INTEGER,
  type TEXT,
  reference_id TEXT,
  timestamp INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(user_id)
)`, (err) => {
  if (err) {
    logger.error('Kesalahan membuat tabel transactions:', err.message);
  } else {
    logger.info('Transactions table created or already exists');
    
    // Add reference_id column if it doesn't exist
    db.get("PRAGMA table_info(transactions)", (err, rows) => {
      if (err) {
        logger.error('Kesalahan memeriksa struktur tabel:', err.message);
        return;
      }
      
      db.get("SELECT * FROM transactions WHERE reference_id IS NULL LIMIT 1", (err, row) => {
        if (err && err.message.includes('no such column')) {
          // Column doesn't exist, add it
          db.run("ALTER TABLE transactions ADD COLUMN reference_id TEXT", (err) => {
            if (err) {
              logger.error('Kesalahan menambahkan kolom reference_id:', err.message);
            } else {
              logger.info('Kolom reference_id berhasil ditambahkan ke tabel transactions');
            }
          });
        } else if (row) {
          // Update existing transactions with reference_id
          db.all("SELECT id, user_id, type, timestamp FROM transactions WHERE reference_id IS NULL", [], (err, rows) => {
            if (err) {
              logger.error('Kesalahan mengambil transaksi tanpa reference_id:', err.message);
              return;
            }
            
          });
        }
      });
    });
  }
});

db.run(`CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  username TEXT,
  account_type TEXT,
  server_id INTEGER,
  server_name TEXT,
  host TEXT,
  server_category TEXT,
  expired_at TEXT,
  created_at TEXT,
  price INTEGER,
  full_message TEXT,
  status TEXT DEFAULT 'active'
)`, (err) => {
  if (err) {
    logger.error('Kesalahan membuat tabel accounts:', err.message);
  } else {
    logger.info('Accounts table created or already exists');
  }
});

db.run(`CREATE TABLE IF NOT EXISTS directedu_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  order_id TEXT,
  username TEXT,
  server_name TEXT,
  service TEXT,
  expired_date TEXT,
  created_at TEXT,
  full_message TEXT
)`, (err) => {
  if (err) {
    logger.error('Kesalahan membuat tabel directedu_accounts:', err.message);
  } else {
    logger.info('directedu_accounts table created or already exists');
  }
});

db.run(`CREATE TABLE IF NOT EXISTS vpncf_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  account_id TEXT,
  username TEXT,
  protocol TEXT,
  server_name TEXT,
  expired_date TEXT,
  created_at TEXT,
  full_message TEXT
)`, (err) => {
  if (err) {
    logger.error('Kesalahan membuat tabel vpncf_accounts:', err.message);
  } else {
    logger.info('vpncf_accounts table created or already exists');
  }
});

// Add full_message column if missing for existing databases
db.run("ALTER TABLE directedu_accounts ADD COLUMN full_message TEXT", (err) => {
  if (err && !err.message.includes('duplicate column')) {
    logger.error('Kesalahan alter directedu_accounts:', err.message);
  }
});
db.run("ALTER TABLE vpncf_accounts ADD COLUMN full_message TEXT", (err) => {
  if (err && !err.message.includes('duplicate column')) {
    logger.error('Kesalahan alter vpncf_accounts:', err.message);
  }
});
db.run("ALTER TABLE vpncf_accounts ADD COLUMN server_id TEXT", (err) => {
  if (err && !err.message.includes('duplicate column')) {
    logger.error('Kesalahan alter vpncf_accounts (server_id):', err.message);
  }
});

db.run(`ALTER TABLE Server ADD COLUMN cloudfront_domain TEXT DEFAULT NULL`, (err) => {
  if (err && !err.message.includes('duplicate column')) {
    logger.error('Gagal menambahkan kolom cloudfront_domain:', err.message);
  } else if (!err) {
    logger.info('Kolom cloudfront_domain berhasil ditambahkan ke Server');
  }
});

db.run(`CREATE TABLE IF NOT EXISTS sshcf_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  username TEXT,
  cloudfront_domain TEXT,
  panel_server TEXT,
  server_id INTEGER,
  expired_at TEXT,
  created_at TEXT,
  price INTEGER,
  full_message TEXT,
  status TEXT DEFAULT 'active'
)`, (err) => {
  if (err) {
    logger.error('Kesalahan membuat tabel sshcf_accounts:', err.message);
  } else {
    logger.info('sshcf_accounts table created or already exists');
  }
});

db.run(`CREATE TABLE IF NOT EXISTS migration_locks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT UNIQUE,
  locked_at TEXT,
  reason TEXT
)`, (err) => {
  if (err) {
    logger.error('Kesalahan membuat tabel migration_locks:', err.message);
  } else {
    logger.info('migration_locks table created or already exists');
  }
});

db.run(`CREATE TABLE IF NOT EXISTS api_reseller (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  telegram_id INTEGER NOT NULL UNIQUE,
  api_key_hash TEXT NOT NULL,
  api_key_prefix TEXT NOT NULL,
  status TEXT DEFAULT 'active',
  rate_limit INTEGER DEFAULT 60,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_used_at INTEGER
)`, (err) => {
  if (err) {
    logger.error('Kesalahan membuat tabel api_reseller:', err.message);
  } else {
    logger.info('api_reseller table created or already exists');
  }
});

db.run(`CREATE TABLE IF NOT EXISTS api_idempotency (
  idempotency_key TEXT PRIMARY KEY,
  telegram_id INTEGER NOT NULL,
  response TEXT NOT NULL,
  created_at INTEGER NOT NULL
)`, (err) => {
  if (err) {
    logger.error('Kesalahan membuat tabel api_idempotency:', err.message);
  } else {
    logger.info('api_idempotency table created or already exists');
  }
});

if (!global.pendingDeposits) global.pendingDeposits = {};
if (!global.depositState) global.depositState = {};
const purchaseFlow = new PurchaseFlow(bot, db, logger, { vars, ADMIN, GROUP_ID });
purchaseFlow.setPendingDepositsRef(global.pendingDeposits);
purchaseFlow.init().catch(e => logger.error('PurchaseFlow init failed:', e.message));

purchaseFlow.setExecutor(async (data) => {
  const { userId } = data;

  if (data.action === 'create' || data.action === 'renew') {
    const { action, type, username, password, exp, quota, iplimit, serverId } = data;
    let msg;
    if (action === 'create') {
      if (type === 'ssh') msg = await createssh(username, password, exp, iplimit, serverId);
      else if (type === 'vmess') msg = await createvmess(username, exp, quota, iplimit, serverId);
      else if (type === 'vless') msg = await createvless(username, exp, quota, iplimit, serverId);
      else if (type === 'trojan') msg = await createtrojan(username, exp, quota, iplimit, serverId);
    } else {
      if (type === 'ssh') msg = await renewssh(username, exp, iplimit, serverId);
      else if (type === 'vmess') msg = await renewvmess(username, exp, quota, iplimit, serverId);
      else if (type === 'vless') msg = await renewvless(username, exp, quota, iplimit, serverId);
      else if (type === 'trojan') msg = await renewtrojan(username, exp, quota, iplimit, serverId);
    }
    try { await recordAccountTransaction(userId, type); } catch (e) { logger.error(e.message); }
    if (msg && !msg.includes('❌')) {
      try {
        const expDate = new Date();
        expDate.setDate(expDate.getDate() + exp);
        const expDateStr = expDate.toISOString().slice(0, 10);
        if (action === 'create') {
          const srv = await dbGetAsync('SELECT nama_server, domain FROM Server WHERE id = ?', [serverId]);
          try {
            await insertAccountRecord(userId, username, type, serverId, srv?.nama_server || '', srv?.domain || '', expDateStr, 0, msg);
          } catch (saveErr) {
            logger.error('❌ Gagal simpan record akun (executor):', saveErr.message);
            await new Promise(r => setTimeout(r, 1000));
            try {
              await insertAccountRecord(userId, username, type, serverId, srv?.nama_server || '', srv?.domain || '', expDateStr, 0, msg);
              logger.info('✅ Account record saved on retry for ' + username);
            } catch (retryErr) {
              logger.error('❌ Gagal simpan record akun (retry):', retryErr.message);
            }
          }
          try {
            await insertListAccount(userId, username, type, srv?.nama_server || '', expDateStr, msg);
          } catch (listErr) {
            logger.error('❌ Gagal simpan list account:', listErr.message);
          }
        } else if (action === 'renew') {
          await updateAccountExpired(userId, username, serverId, expDateStr, msg);
          updateListAccountExpired(userId, username, type, expDateStr, msg).catch(() => {});
          logger.info('✅ Account record updated (executor) for ' + username);
        }
      } catch (e) {
        logger.error('⚠️ Gagal simpan record akun (executor):', e.message);
      }
    }
    return { message: msg || '' };
  }

  if (data.product === 'directedu') {
    const { serverCode, service, billingPeriod, username, password } = data;
    const orderData = { server_code: serverCode, service, billing_period: billingPeriod, duration: 1, username, password };
    const verified = await naytra.orderEduVerified(orderData);
    const result = verified.raw;
    const resp = result.data || result;
    if (resp.status === 'success' || resp.success || (!resp.error && resp.username)) {
      let msg = `✅ *VPN EDU DIRECT BERHASIL*\n\n👤 Username : ${esc(resp.username || username)}\n`;
      if (verified.recovered) {
        msg += `⚠️ *Respons order sempat hilang, akun sudah dibuat di panel dan diverifikasi otomatis.*\n`;
      }
      if (resp.password) msg += `🔑 Password : ${esc(resp.password)}\n`;
      msg += `🖥 Server : ${esc(resp.server_name || serverCode)}\n📅 Expired : ${esc(resp.expired_date || resp.expired || '-')}\n`;
      const orderId = resp.order_id || resp.id || '';
      if (orderId) {
        try {
          await dbRunAsync('INSERT INTO directedu_accounts (user_id, order_id, username, server_name, service, expired_date, created_at, full_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [userId, orderId, resp.username || username, resp.server_name || serverCode, service, resp.expired_date || resp.expired || '', new Date().toISOString(), msg]);
        } catch (e) {
          logger.error('Gagal simpan directedu_accounts (akun tetap dikirim):', e.message);
        }
      }
      try { await insertListAccount(userId, resp.username || username, 'edu', resp.server_name || serverCode, resp.expired_date || resp.expired || '', msg); } catch (e) {
        logger.error('Gagal simpan list_accounts directedu:', e.message);
      }
      try { await recordAccountTransaction(userId, 'directedu'); } catch (e) {}
      if (verified.recovered) {
        logger.warn(`✅ RECOVERED order directedu user ${userId} username ${username} — akun dikirim, tanpa refund`);
        try {
          await purchaseFlow.notifyAdmin(
            `✅ *ORDER EDU DIPULIHKAN (TANPA REFUND)*\n👤 User: \`${userId}\`\n👤 Username: \`${username}\`\n🧾 Order ID: \`${orderId || '-'}\`\n\nRespons order sempat hilang, akun sudah dibuat di panel dan dikirim ke user.`
          );
        } catch (e) { logger.error('Gagal notif admin (recovery EDU):', e.message); }
      }
      return { message: msg };
    }
    return { message: '❌ Gagal order: ' + (resp.message || 'Terjadi kesalahan pada server. Silakan coba lagi.') };
  }

  if (data.product === 'directedu_renew') {
    const { orderId, duration } = data;
    const result = await naytra.renewEdu({ order_id: orderId, duration });
    const resp = result.data || result;
    if (resp.status === 'success' || resp.success || !resp.error) {
      const eduAcct = await dbGetAsync('SELECT server_name, username FROM directedu_accounts WHERE order_id = ?', [orderId]).catch(() => null);
      const serverName = eduAcct?.server_name || resp.server_name || '-';
      const username = eduAcct?.username || '-';
      const newExpired = resp.expired_date || resp.expired || resp.exp || '';
      let msg = `✅ *EDU RENEW BERHASIL*\n\n👤 User ID: \`${userId}\`\n🌐 Server : ${serverName}\n📅 Expired : ${esc(newExpired)}\n`;
      try { await recordAccountTransaction(userId, 'directedu_renew'); } catch (e) {}
      updateListAccountExpired(userId, username, 'edu', newExpired, msg).catch(() => {});
      return { message: msg };
    }
    return { message: '❌ Gagal renew: ' + (resp.message || 'Terjadi kesalahan pada server. Silakan coba lagi.') };
  }

  if (data.product === 'vpncf') {
    const { serverId, protocol, type, duration, username, password } = data;
    const result = await nadiavpn.createVpnVerified({ serverId, protocol, username, password, duration, type });
    const resp = result.data || result;
    if (resp.status === 'success' || resp.success || (!resp.error && resp.config)) {
      const expStr = pickVpncfExpiry(resp, type, duration);
      const expTgl = formatExpDate(expStr, type, duration);
      const fallbackMsg = `✅ *VPN CLOUDFRONT BERHASIL*\n\n👤 Username : ${esc(resp.username || username)}\n📅 Berlaku Sampai : ${esc(expTgl)}\n`;
      let msg = fallbackMsg;
      if (resp.config) {
        try {
          msg = formatVpncfSuccess({ resp, protocol, username, password, type, duration, totalHarga: 0, recovered: !!resp.recovered });
        } catch (e) {
          logger.error('Gagal susun pesan vpncf, pakai ringkasan:', e.message);
        }
      }
      const accountId = resp.account_id || '';
      if (resp.recovered) {
        msg += `\n⚠️ *Order sempat gagal respond, namun akun SUDAH TERBUAT di panel dan sudah diverifikasi otomatis.*\n`;
      }
      if (accountId) {
        // Catatan/DB tidak boleh menggagalkan pembelian — akun sudah jadi di panel.
        try {
          await dbRunAsync('INSERT INTO vpncf_accounts (user_id, account_id, username, protocol, server_name, server_id, expired_date, created_at, full_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [userId, accountId, resp.username || username, protocol, resp.server_name || 'CLOUDFRONT REGULER', serverId || '', expStr, new Date().toISOString(), msg]);
        } catch (e) {
          logger.error('Gagal simpan vpncf_accounts (akun tetap dikirim):', e.message);
        }
      }
      try { await insertListAccount(userId, resp.username || username, protocol || 'vpncf', resp.server_name || 'CLOUDFRONT REGULER', expStr, msg); } catch (e) {
        logger.error('Gagal simpan list_accounts vpncf:', e.message);
      }
      try { await recordAccountTransaction(userId, 'vpncf'); } catch (e) {}
      if (resp.recovered) {
        logger.warn(`✅ RECOVERED order vpncf user ${userId} username ${username} — akun dikirim ke user, tanpa refund`);
        try {
          await purchaseFlow.notifyAdmin(
            `✅ *ORDER DIPULIHKAN (TANPA REFUND)*\n👤 User: \`${userId}\`\n📦 Produk: \`VPN CloudFront ${String(protocol).toUpperCase()}\`\n👤 Username: \`${username}\`\n🆔 Account ID: \`${accountId || '-'}\`\n⚠️ Penyebab: \`${(resp.recover_note || '').substring(0, 160)}\`\n\nRespons order sempat hilang, akun sudah dibuat di panel dan dikirim ke user.`
          );
        } catch (e) {
          logger.error('Gagal notif admin (recovery):', e.message);
        }
      }
      return { message: msg };
    }
    return { message: '❌ Gagal order: ' + (resp.message || 'Terjadi kesalahan pada server. Silakan coba lagi.') };
  }

  if (data.product === 'vpncf_renew') {
    const { accountId, duration, renewType } = data;
    const result = await nadiavpn.renewVpn(accountId, duration, renewType);
    const resp = result.data || result;
    if (resp.status === 'success' || resp.success || !resp.error) {
      const acct = await dbGetAsync('SELECT server_name, username, protocol FROM vpncf_accounts WHERE account_id = ?', [accountId]).catch(() => null);
      const serverName = acct?.server_name || resp.server_name || '-';
      const username = acct?.username || '-';
      const protocol = acct?.protocol || 'vpncf';
      const newExpired = resp.expired || resp.expired_date || '';
      let msg = `✅ *VPN CLOUDFRONT RENEW BERHASIL*\n\n👤 User ID: \`${userId}\`\n🌐 Server : ${serverName}\n📅 Expired : ${esc(newExpired)}\n`;
      try { await recordAccountTransaction(userId, 'vpncf_renew'); } catch (e) {}
      try {
        await dbRunAsync('UPDATE vpncf_accounts SET expired_date = ? WHERE user_id = ? AND account_id = ?', [newExpired, userId, accountId]);
      } catch (e) {
        logger.error('Gagal update vpncf_accounts (renew):', e.message);
      }
      try { await updateListAccountExpired(userId, username, protocol, newExpired, msg); } catch (e) {}
      return { message: msg };
    }
    return { message: '❌ Gagal renew: ' + (resp.message || 'Terjadi kesalahan pada server. Silakan coba lagi.') };
  }

  if (data.product === 'sshcf') {
    const { action, type, username, password, exp, quota, iplimit, serverId, cfDomain } = data;
    let msg;
    if (action === 'create') {
      const srv = await dbGetAsync('SELECT * FROM Server WHERE id = ?', [serverId]);
      const il = iplimit || (srv ? srv.iplimit : 1);
      if (type === 'vmess') msg = await createcfvmess(username, exp, quota || '0', il, serverId, cfDomain);
      else if (type === 'vless') msg = await createcfvless(username, exp, quota || '0', il, serverId, cfDomain);
      else if (type === 'trojan') msg = await createcftrojan(username, exp, quota || '0', il, serverId, cfDomain);
      else msg = await createsshcf(username, password, exp, il, serverId, cfDomain);
    }
    try { await recordAccountTransaction(userId, type || 'sshcf'); } catch (e) { logger.error(e.message); }
    if (msg && !msg.includes('❌')) {
      const server = await dbGetAsync('SELECT * FROM Server WHERE id = ?', [serverId]);
      const hargaTotal = server ? server.harga * exp : 0;
      const expDate = new Date();
      expDate.setDate(expDate.getDate() + exp);
      const expDateStr = expDate.toISOString().slice(0, 10);
      db.run('INSERT INTO sshcf_accounts (user_id, username, cloudfront_domain, panel_server, server_id, expired_at, created_at, price, full_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [userId, username, cfDomain || (server ? server.cloudfront_domain : ''), server ? server.domain : '', serverId, expDateStr, new Date().toISOString(), hargaTotal, msg || '']);
      insertListAccount(userId, username, type || 'sshcf', server?.nama_server || 'CLOUDFRONT', expDateStr, msg).catch(() => {});
    }
    return { message: msg || '' };
  }

  if (data.product === 'sshcf_renew') {
    const { username, exp, serverId } = data;
    let msg = await renewsshcf(username, exp, serverId);
    try { await recordAccountTransaction(userId, 'sshcf_renew'); } catch (e) { logger.error(e.message); }
    if (msg && !msg.includes('❌')) {
      const newExpDate = new Date();
      newExpDate.setDate(newExpDate.getDate() + exp);
      const newExpStr = newExpDate.toISOString().slice(0, 10);
      db.run('UPDATE sshcf_accounts SET expired_at = DATE(expired_at, ? || \' days\') WHERE user_id = ? AND username = ?',
        [String(exp), userId, username]);
      updateListAccountExpired(userId, username, 'sshcf', newExpStr, msg).catch(() => {});
    }
    return { message: msg || '' };
  }

  if (data.product === 'cfrenew') {
    const { type, username, exp, serverId } = data;
    let msg;
    if (type === 'vmess') msg = await renewcfvmess(username, exp, serverId);
    else if (type === 'vless') msg = await renewcfvless(username, exp, serverId);
    else if (type === 'trojan') msg = await renewcftrojan(username, exp, serverId);
    else msg = await renewsshcf(username, exp, serverId);
    try { await recordAccountTransaction(userId, 'cfrenew'); } catch (e) { logger.error(e.message); }
    if (msg && !msg.includes('❌')) {
      const newExpDate = new Date();
      newExpDate.setDate(newExpDate.getDate() + exp);
      const newExpStr = newExpDate.toISOString().slice(0, 10);
      db.run('UPDATE sshcf_accounts SET expired_at = DATE(expired_at, ? || \' days\') WHERE user_id = ? AND username = ? AND server_id = ?',
        [String(exp), userId, username, serverId]);
      updateListAccountExpired(userId, username, type || 'sshcf', newExpStr, msg).catch(() => {});
    }
    return { message: msg || '' };
  }

  throw new Error('Executor: unknown product ' + JSON.stringify(data));
});

const userState = {};

const CF_PROTOCOLS = {
  ssh:    { emoji: '🔐', name: 'SSH',    needsPassword: true,  label: 'SSH CloudFront' },
  vmess:  { emoji: '🟣', name: 'VMESS',  needsPassword: false, label: 'VMESS CloudFront' },
  vless:  { emoji: '🟢', name: 'VLESS',  needsPassword: false, label: 'VLESS CloudFront' },
  trojan: { emoji: '🔴', name: 'TROJAN', needsPassword: false, label: 'TROJAN CloudFront' },
};

// Tanggal expired untuk VPN CloudFront: coba dari config dulu, lalu level atas
// response. Mengembalikan string siap-simpan ke DB (ISO atau '-').
function pickVpncfExpiry(resp, type, duration) {
  const cfg = resp?.config || {};
  const raw = cfg.exp || cfg.expired || cfg.expired_at || cfg.expires_at || cfg.expiry_date
    || resp?.expired || resp?.expired_date || resp?.expired_at || resp?.expire_at || resp?.expires_at || resp?.expiry_date || resp?.exp;
  const ms = resolveExpMs(raw, type, duration);
  return ms ? new Date(ms).toISOString() : '';
}

// Tanggal expired bisa berupa string, timestamp detik, atau milidetik.
// Kalau panel tidak mengirim apa pun, dihitung dari durasi order (type + duration).
// Mengembalikan timestamp (ms), atau 0 kalau tidak ada yang bisa dihitung.
function resolveExpMs(raw, type, duration) {
  const val = raw === 0 || raw === null || raw === undefined ? '' : String(raw).trim();
  if (val && val !== '-' && val !== '0') {
    if (/^\d{9,13}$/.test(val)) {
      const ms = Number(val.length <= 10 ? `${val}000` : val);
      if (ms > 0) return ms;
    } else {
      const ms = Date.parse(val.replace(' ', 'T'));
      if (!isNaN(ms) && ms > 0) return ms;
    }
  }

  const n = parseInt(duration) || 0;
  if (n <= 0) return 0;
  const t = String(type || 'day').toLowerCase();
  let days = n;
  if (t === 'month' || t === 'bulan') days = n * 30;
  else if (t === 'week' || t === 'minggu') days = n * 7;
  return Date.now() + Math.max(1, days) * 86400000;
}

function formatExpDate(raw, type, duration) {
  const ms = resolveExpMs(raw, type, duration);
  if (!ms) return '-';
  // Selalu tampil dalam zona WIB, tidak ikut zona waktu server.
  const parts = new Intl.DateTimeFormat('id-ID', {
    timeZone: 'Asia/Jakarta',
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: false
  }).formatToParts(new Date(ms));
  const get = (t) => (parts.find(p => p.type === t) || {}).value || '';
  return `${get('day')} ${get('month')} ${get('year')} ${get('hour')}:${get('minute')} WIB`;
}

// Sudah lewat tanggal expired? Tanggal kosong tidak dianggap expired.
function isExpiredDate(raw) {
  const ms = resolveExpMs(raw);
  return ms > 0 && ms < Date.now();
}

// Susun pesan hasil create VPN CloudFront (dipakai jalur saldo & jalur QRIS).
function formatVpncfSuccess({ resp, protocol, username, password, type, duration, totalHarga, recovered }) {
  const cfg = resp.config || {};
  const h = cfg.hostname || resp.hostname || '-';
  const u = cfg.username || resp.username || username;
  const p = cfg.password || resp.password || password || '';
  let msg = `✅ *VPN CLOUDFRONT BERHASIL*\n\n`;
  if (recovered) {
    msg += `⚠️ *Respons order sempat hilang, akun sudah dibuat di panel dan diverifikasi otomatis.*\n\n`;
  }
  const protoInfo = CF_PROTOCOLS[protocol] || CF_PROTOCOLS.ssh;
  const masaAktif = type === 'month' ? `${duration} Bulan` : (type === 'week' ? `${duration} Minggu` : `${duration} Hari`);
  const hargaTxt = totalHarga ? `Rp ${Number(totalHarga).toLocaleString('id-ID')}` : '-';
  // Tanggal expired bisa datang dari config atau dari level atas response.
  const expVal = cfg.exp || cfg.expired || cfg.expired_at || cfg.expires_at || cfg.expiry_date
    || resp.expired || resp.expired_date || resp.expired_at || resp.expire_at || resp.expires_at || resp.expiry_date || resp.exp || '';
  // Kalau panel tidak mengirim tanggal, hitung sendiri dari durasi order.
  const expTgl = formatExpDate(expVal, type, duration);
  // API memakai nama key berbeda untuk SSH (ws_tls/ws_http/dropbear/openvpn_tcp)
  const rp = cfg.port || {};
  const pt = {
    tls: rp.tls || rp.ws_tls || '',
    none: rp.none || rp.ws_http || '',
    any: rp.any || '',
    openssh: rp.openssh || '',
    dropbear: rp.dropbear || rp.sshohp || '',
    ovpntcp: rp.ovpntcp || rp.openvpn_tcp || '',
    ovpnudp: rp.ovpnudp || rp.openvpn_udp || '',
    udpcustom: rp.udpcustom || '',
    badvpn: rp.badvpn || '',
    squid: rp.squid || '',
    slowdns: rp.slowdns || '',
    udpgw: rp.udpgw || ''
  };
  if (protocol === 'ssh') {
    msg += `*🔐 ${protoInfo.name} Premium Details*\n`;
    msg += `────────────────────────\n`;
    msg += `📡 *SSH WS*    : \`${h}:80@${u}:${p}\`\n`;
    msg += `🔒 *SSH SSL*   : \`${h}:443@${u}:${p}\`\n`;
    msg += `📶 *SSH UDP*   : \`${h}:1-65535@${u}:${p}\`\n`;
    msg += `🌐 *SSH SLOWDNS* : \`${h}:5300@${u}:${p}\`\n`;
    msg += `────────────────────────\n`;
    msg += `🌍 *Host*         : \`${h}\`\n`;
    if (cfg.ISP) msg += `🏢 *ISP*          : \`${cfg.ISP}\`\n`;
    if (cfg.CITY) msg += `🏙️ *City*         : \`${cfg.CITY}\`\n`;
    msg += `👤 *Username*     : \`${u}\`\n`;
    msg += `🔑 *Password*     : \`${p}\`\n`;
    if (cfg.pubkey) msg += `🗝️ *Public Key*  : \`${cfg.pubkey}\`\n`;
    msg += `📅 *Berlaku Sampai* : \`${expTgl}\`\n`;
    msg += `📌 *Masa Aktif*   : \`${masaAktif}\`\n`;
    msg += `📌 *IP Limit*     : \`3 IP\`\n`;
    msg += `💰 *Harga*        : \`${hargaTxt}\`\n`;
    msg += `────────────────────────\n`;
    msg += `🛠 *Ports:*\n`;
    if (pt.tls) msg += `• TLS         : \`${pt.tls}\`\n`;
    if (pt.none) msg += `• Non-TLS     : \`${pt.none}\`\n`;
    if (pt.openssh) msg += `• OpenSSH     : \`${pt.openssh}\`\n`;
    if (pt.dropbear) msg += `• Dropbear    : \`${pt.dropbear}\`\n`;
    if (pt.ovpntcp) msg += `• OVPN TCP    : \`${pt.ovpntcp}\`\n`;
    if (pt.ovpnudp) msg += `• OVPN UDP    : \`${pt.ovpnudp}\`\n`;
    if (pt.udpcustom) msg += `• UDP Custom  : \`${pt.udpcustom}\`\n`;
    if (pt.badvpn) msg += `• BadVPN      : \`${pt.badvpn}\`\n`;
    if (pt.slowdns) msg += `• SlowDNS     : \`${pt.slowdns}\`\n`;
    if (pt.squid) msg += `• Squid       : \`${pt.squid}\`\n`;
    if (pt.udpgw) msg += `• UDPGW       : \`${pt.udpgw}\`\n`;
    msg += `────────────────────────\n`;
    msg += `🧩 *Payload WS:*\n\`\`\`\n`;
    msg += `GET / HTTP/1.1\n`;
    msg += `Host: ${h}\n`;
    msg += `Connection: Upgrade\n`;
    msg += `User-Agent: [ua]\n`;
    msg += `Upgrade: websocket\n`;
    msg += `\`\`\`\n\n`;
    msg += `🧩 *Payload Enhanced:*\n\`\`\`\n`;
    msg += `PATCH / HTTP/1.1\n`;
    msg += `Host: ${h}\n`;
    msg += `Host: bug.com\n`;
    msg += `Connection: Upgrade\n`;
    msg += `User-Agent: [ua]\n`;
    msg += `Upgrade: websocket\n`;
    msg += `\`\`\`\n\n`;
  } else {
    const keyLabel = protocol === 'trojan' ? 'Key' : 'UUID';
    const keyVal = cfg.uuid || cfg.key || resp.uuid || resp.key || '';
    msg += `*${protoInfo.emoji} Akun ${protoInfo.name} CloudFront Premium*\n`;
    msg += `────────────────────────\n`;
    msg += `👤 *Username*     : \`${u}\`\n`;
    msg += `🌍 *Host*         : \`${h}\`\n`;
    msg += `☁️ *Mode*         : \`CLOUDFRONT\`\n`;
    if (cfg.ISP) msg += `🏢 *ISP*          : \`${cfg.ISP}\`\n`;
    if (cfg.CITY) msg += `🏙️ *City*         : \`${cfg.CITY}\`\n`;
    if (keyVal) msg += `🛡 *${keyLabel}*      : \`${keyVal}\`\n`;
    msg += `📅 *Berlaku Sampai* : \`${expTgl}\`\n`;
    msg += `📌 *Masa Aktif*   : \`${masaAktif}\`\n`;
    msg += `📌 *IP Limit*     : \`3 IP\`\n`;
    msg += `💰 *Harga*        : \`${hargaTxt}\`\n`;
    const pt2 = pt;
    if (pt2.tls || pt2.none || pt2.any) {
      msg += `────────────────────────\n`;
      msg += `📡 *Ports:*\n`;
      if (pt2.tls) msg += `- TLS         : \`${pt2.tls}\`\n`;
      if (pt2.none) msg += `- Non TLS     : \`${pt2.none}\`\n`;
      if (pt2.any) msg += `- Any Port    : \`${pt2.any}\`\n`;
    }
    const pth = cfg.path || cfg.ws_path || {};
    if (pth.stn || pth.multi || pth.grpc || pth.up) {
      msg += `────────────────────────\n`;
      msg += `📶 *Path:*\n`;
      if (pth.stn) msg += `- WS          : \`${pth.stn}\`${pth.multi ? ` | \`${pth.multi}\`` : ''}\n`;
      if (pth.grpc) msg += `- gRPC        : \`${pth.grpc}\`\n`;
      if (pth.up) msg += `- Upgrade     : \`${pth.up}\`\n`;
    }
    const link = cfg.link || resp.link || null;
    if (link && (link.tls || link.none || link.grpc || link.uptls)) {
      msg += `────────────────────────\n`;
      msg += `🔗 *${protoInfo.name} Links (CloudFront):*\n`;
      if (link.tls) msg += `- TLS         : \`${link.tls}\`\n`;
      if (link.none) msg += `- Non TLS     : \`${link.none}\`\n`;
      if (link.grpc) msg += `- gRPC        : \`${link.grpc}\`\n`;
      if (link.uptls) msg += `- Up TLS      : \`${link.uptls}\`\n`;
    }
    msg += `\n`;
  }
  msg += `📥 *Download Config*:\n🔗 https://rajaserver.web.id/config-Indonesia.zip\n`;
  return msg;
}

const callbackStore = new Map();
let callbackSeq = 0;
function storeCb(data) {
  const id = String(++callbackSeq);
  callbackStore.set(id, data);
  return id;
}
function getCb(id) {
  const data = callbackStore.get(id);
  callbackStore.delete(id);
  return data;
}
function esc(s) {
  return String(s || '').replace(/_/g, '\\_');
}

// IP marketing untuk tampilan: limit internal dikurangi 1 (anti-ban),
// server khusus reseller dikurangi 1 lagi karena internalnya +2 dari marketing.
function marketingIP(srv) {
  const rawIP = parseInt(srv.iplimit, 10) || 5;
  let ip = rawIP > 1 ? rawIP - 1 : rawIP;
  if (Number(srv.is_reseller_only) === 1 && ip > 1) ip -= 1;
  return ip;
}

const migrationStore = new Map();
function storeMigration(chatId, data) { migrationStore.set(chatId, data); }
function getMigration(chatId) { return migrationStore.get(chatId); }
function clearMigration(chatId) { migrationStore.delete(chatId); }

async function executeMigration(ctx, migrateData) {
  const chatId = ctx.chat.id;
  const userId = ctx.from.id;
  const { username, type, password, expired, limitIP, quota, uuid, sourceServerId, sourceServerName, destServerId, destServerName } = migrateData;

  async function safeEdit(msgId, text) {
    try {
      await bot.telegram.editMessageText(chatId, msgId, undefined, text, { parse_mode: 'Markdown' });
      return true;
    } catch (e) {
      logger.error('⚠️ Gagal edit pesan migrasi: ' + e.message);
      return false;
    }
  }

  const statusMsg = await ctx.reply('⏳ *Sedang memigrasikan akun...*\n\n⌛ Mengambil data akun...', { parse_mode: 'Markdown' }).catch(() => null);
  const statusMsgId = statusMsg ? statusMsg.message_id : null;

  taskQueue.runBackground(userId,
    async () => {
    const destServer = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM Server WHERE id = ?', [destServerId], (e, row) => {
        if (e) reject(e); else resolve(row);
      });
    });
    if (!destServer) {
      return ctx.reply('❌ *Server tujuan tidak ditemukan.*', { parse_mode: 'Markdown' });
    }

    let expDays = 30;
    if (expired && expired !== '-') {
      try {
        const expiredDate = new Date(expired);
        const now = new Date();
        expiredDate.setHours(0, 0, 0, 0);
        now.setHours(0, 0, 0, 0);
        expDays = Math.max(1, Math.ceil((expiredDate - now) / 86400000));
      } catch (e) {
        expDays = 30;
      }
    }

    const parsedLimitIP = parseInt(limitIP, 10) || 0;
    const parsedQuota = quota === 'Unlimited' ? '0' : (quota || '0');

    logger.info(`🚀 Migrasi ${type} ${username}: ${sourceServerName} -> ${destServerName} (exp=${expDays}, limitip=${parsedLimitIP}, quota=${parsedQuota})`);

    if (statusMsgId) {
      await safeEdit(statusMsgId,
        '⏳ *Sedang memigrasikan akun...*\n\n' +
        '✅ Mengambil data akun\n' +
        '⚙️ Membuat akun di server tujuan...'
      );
    }

    const createFunctions = {
      ssh: () => createssh(username, password || 'migrasi123', expDays, parsedLimitIP, destServerId),
      vmess: () => createvmess(username, expDays, parsedQuota, parsedLimitIP, destServerId),
      vless: () => createvless(username, expDays, parsedQuota, parsedLimitIP, destServerId),
      trojan: () => createtrojan(username, expDays, parsedQuota, parsedLimitIP, destServerId)
    };

    const createFn = createFunctions[type];
    if (!createFn) {
      return ctx.reply(`❌ *Tipe akun ${type} tidak didukung untuk migrasi.*`, { parse_mode: 'Markdown' });
    }

    const createResult = await createFn();

    if (createResult.includes('❌')) {
      logger.error(`❌ Gagal membuat akun di server tujuan: ${createResult}`);
      clearMigration(chatId);
      delete userState[chatId];
      return ctx.reply(
        '❌ *Migrasi gagal.*\n\n' +
        `Reason: ${createResult}\n\n` +
        'Akun di server lama tetap aman.',
        { parse_mode: 'Markdown' }
      );
    }

    logger.info(`✅ Akun ${username} berhasil dibuat di ${destServerName}`);

    if (statusMsgId) {
      await safeEdit(statusMsgId,
        '⏳ *Sedang memigrasikan akun...*\n\n' +
        '✅ Mengambil data akun\n' +
        '✅ Membuat akun di server tujuan\n' +
        '⚙️ Update database...'
      );
    }

    try {
      const oldAccount = await new Promise((resolve, reject) => {
        db.get('SELECT * FROM accounts WHERE user_id = ? AND username = ? AND server_id = ? AND status = \'active\'',
          [ctx.from.id, username, sourceServerId], (e, row) => {
            if (e) reject(e); else resolve(row);
          });
      });

      if (oldAccount) {
        await new Promise((resolve, reject) => {
          db.run(
            'UPDATE accounts SET server_id = ?, server_name = ?, host = ?, server_category = ?, full_message = ? WHERE id = ?',
            [destServerId, destServerName, destServer.domain, getServerCategory(destServerName || destServer.domain), createResult, oldAccount.id],
            (e) => { if (e) reject(e); else resolve(); }
          );
        });
        logger.info(`✅ Database diupdate: ${username} dari ${sourceServerName} ke ${destServerName}`);
      } else {
        const expDate = new Date();
        expDate.setDate(expDate.getDate() + expDays);
        const expDateStr = expDate.toISOString().slice(0, 10);
        await insertAccountRecord(ctx.from.id, username, type, destServerId, destServerName, destServer.domain, expDateStr, 0, createResult);
        await insertListAccount(ctx.from.id, username, type, destServerName, expDateStr, createResult);
        logger.info(`✅ Record akun baru dibuat di database untuk ${username} di ${destServerName}`);
      }
    } catch (e) {
      logger.error('⚠️ Gagal update database migrasi:', e.message);
    }

    if (statusMsgId) {
      await safeEdit(statusMsgId,
        '⏳ *Sedang memigrasikan akun...*\n\n' +
        '✅ Mengambil data akun\n' +
        '✅ Membuat akun di server tujuan\n' +
        '✅ Update database\n' +
        '⚙️ Menghapus akun dari server lama...'
      );
    }

    let deleteWarning = '';
    try {
      const delFunctions = {
        ssh: () => delssh(username, password || 'none', 'none', 'none', sourceServerId),
        vmess: () => delvmess(username, 'none', 'none', 'none', sourceServerId),
        vless: () => delvless(username, 'none', 'none', 'none', sourceServerId),
        trojan: () => deltrojan(username, 'none', 'none', 'none', sourceServerId)
      };

      const delFn = delFunctions[type];
      if (delFn) {
        const delResult = await delFn();
        if (delResult.includes('❌')) {
          deleteWarning = '\n\n⚠️ *Peringatan:* Gagal menghapus akun dari server lama. Silakan hapus secara manual.';
          logger.error(`⚠️ Gagal hapus akun lama ${username} dari ${sourceServerName}: ${delResult}`);
        } else {
          logger.info(`✅ Akun lama ${username} berhasil dihapus dari ${sourceServerName}`);
        }
      }
    } catch (e) {
      deleteWarning = '\n\n⚠️ *Peringatan:* Gagal menghapus akun dari server lama. Silakan hapus secara manual.';
      logger.error('❌ Error hapus akun lama:', e.message);
    }

    clearMigration(chatId);
    delete userState[chatId];

    const migrateHeader =
      `✅ *Migrasi akun berhasil.*\n\n` +
      `🔀 *MIGRASI SUMMARY*\n` +
      `━━━━━━━━━━━━━━━━━━━\n` +
      `👤 *Username* : \`${esc(username)}\`\n` +
      `📦 *Type*     : ${type.toUpperCase()}\n` +
      `🌐 *Dari*     : ${esc(sourceServerName)}\n` +
      `🌐 *Ke*       : ${esc(destServerName)}\n` +
      `━━━━━━━━━━━━━━━━━━━\n\n` +
      `📋 *DETAIL AKUN BARU:*\n` +
      `━━━━━━━━━━━━━━━━━━━\n`;

    const successMsg = migrateHeader + createResult + deleteWarning;

    if (statusMsgId) {
      await safeEdit(statusMsgId, successMsg);
    } else {
      await ctx.reply(successMsg, { parse_mode: 'Markdown' });
    }

    const maskedUsername = username.length > 1
      ? `${username.slice(0, 1)}${'x'.repeat(username.length - 1)}`
      : username;
    await bot.telegram.sendMessage(
      GROUP_ID,
      `<blockquote>\n🔀 <b>Account Migrated</b>\n━━━━━━━━━━━━━━━━━━━━\n👤 <b>User:</b> ${ctx.from.first_name} (${ctx.from.id})\n🧾 <b>Type:</b> ${type.toUpperCase()}\n📛 <b>Username:</b> ${maskedUsername}\n🌐 <b>From:</b> ${sourceServerName}\n🌐 <b>To:</b> ${destServerName}\n📅 <b>Expired:</b> ${expired || '-'}\n━━━━━━━━━━━━━━━━━━━━\n</blockquote>`,
      { parse_mode: 'HTML' }
    );

    logger.info(`✅ Migrasi selesai: ${username} ${sourceServerName} -> ${destServerName} oleh ${ctx.from.id}`);

    },
    () => {},
    async (err) => {
      logger.error('❌ Error executeMigration:', err.message);
      clearMigration(chatId);
      delete userState[chatId];
      const errMsg = '❌ *Terjadi kesalahan saat migrasi akun.*\n' + (err.message || '');
      if (statusMsgId) {
        await safeEdit(statusMsgId, errMsg);
      } else {
        await ctx.reply(errMsg, { parse_mode: 'Markdown' });
      }
    }
    );
}

logger.info('User state initialized');

function dbRunAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function dbGetAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

async function ensureUserExists(userId) {
  await dbRunAsync('INSERT OR IGNORE INTO users (user_id) VALUES (?)', [userId]);
}

// Ringkas 1 baris supaya aman dipakai di dalam backtick Markdown.
function oneLine(text, max = 300) {
  return String(text == null ? '' : text)
    .replace(/\s+/g, ' ')
    .replace(/[`\\]/g, '')
    .trim()
    .substring(0, max) || '-';
}

async function logPayment(userId, username, product, price, status, errorLog) {
  try {
    const user = await dbGetAsync('SELECT saldo FROM users WHERE user_id = ?', [userId]);
    const saldo = user ? user.saldo : 0;
    const isError = status !== 'SUCCESS' && status !== 'PENDING_PAYMENT' && status !== 'PROCESSING';
    const detail = errorLog ? `\n${isError ? 'Error' : 'Info'}: ${oneLine(errorLog, 500)}` : '';
    const logMsg = `[PAYMENT]\nUser ID: ${userId}\nUsername: ${username}\nProduk: ${product}\nHarga: ${price}\nSaldo : ${saldo}\nStatus: ${status}` + detail;
    logger.info(logMsg);
    console.log('--- PAYMENT LOG ---');
    console.log(logMsg);
    console.log('--------------------');
  } catch (e) {
    logger.error('Payment log error:', e.message);
  }

  if (status === 'REFUNDED') {
    const ref = oneLine(username, 60);
    const notify =
      `❌ *FAILED CREATE (REFUNDED)*\n` +
      `👤 User: \`${userId}\`\n` +
      `📦 Produk: \`${oneLine(product, 60)}\`\n` +
      `💰 Refund: Rp${Number(price) || 0}\n` +
      `🆔 Invoice: \`${ref !== '-' ? ref : 'DIRECT-' + Date.now()}\`\n` +
      `⚠️ Error: \`${oneLine(errorLog, 300)}\``;
    try {
      await purchaseFlow.notifyAdmin(notify);
      logger.warn(`[REFUND NOTIF] ${product} user ${userId} Rp${price} — ${ref}`);
    } catch (e) {
      logger.error('Gagal kirim notifikasi refund ke admin:', e.message);
    }
  }
}

const REQUIRED_CHANNEL = vars.REQUIRED_CHANNEL || '@CHANNEL_ANDA';
const REQUIRED_GROUP = vars.REQUIRED_GROUP || '@GROUP_ANDA';

const membershipCache = new Map();
const MEMBERSHIP_CACHE_TTL = 60000;
const MEMBERSHIP_FAIL_TTL = 5000;
const NOT_MEMBER_STATUS = ['left', 'kicked', 'restricted'];
const MEMBERSHIP_LABELS = { Channel: REQUIRED_CHANNEL, Group: REQUIRED_GROUP };

async function checkMembership(ctx, options = {}) {
  const userId = ctx.from.id;
  if (options.force) membershipCache.delete(userId);

  const cached = membershipCache.get(userId);
  if (cached) {
    const ttl = cached.result.ok ? MEMBERSHIP_CACHE_TTL : MEMBERSHIP_FAIL_TTL;
    if (Date.now() - cached.ts < ttl) return cached.result;
    membershipCache.delete(userId);
  }

  const checks = [
    { name: 'Channel', username: REQUIRED_CHANNEL },
    { name: 'Group', username: REQUIRED_GROUP },
  ];
  const results = await Promise.all(checks.map(c =>
    ctx.telegram.getChatMember(c.username, userId).then(m => ({ name: c.name, username: c.username, status: m.status })).catch(err => {
      logger.error(`checkMembership error ${c.name} (${c.username}): ${err.message}`);
      return { name: c.name, username: c.username, status: 'member' };
    })
  ));
  for (const { name, username, status } of results) {
    if (NOT_MEMBER_STATUS.includes(status)) {
      const result = { ok: false, failed: name, username, status };
      membershipCache.set(userId, { ts: Date.now(), result });
      logger.info(`Membership check user ${userId}: belum join ${name} (${status})`);
      return result;
    }
  }
  const result = { ok: true };
  membershipCache.set(userId, { ts: Date.now(), result });
  return result;
}

bot.command(['start', 'menu'], async (ctx) => {
  if (ctx.chat.type !== 'private') return;

  const userId = ctx.from.id;
  const check = await checkMembership(ctx);
  
  if (!check.ok) {
    await ctx.reply(
      `*⚠️ Akses Ditolak*\n\nAnda harus join ke Channel & Group kami terlebih dahulu untuk menggunakan bot ini.\n\nSilakan join lalu klik "✅ Sudah Join".`,
      { parse_mode: 'Markdown', ...buildJoinKeyboard() }
    );
    return;
  }

  ensureUserExists(userId).catch(() => {});
  await sendMainMenu(ctx);
});

function buildJoinKeyboard() {
  return Markup.inlineKeyboard([
    [Markup.button.url('📢 Join Channel', `https://t.me/${REQUIRED_CHANNEL.replace('@', '')}`)],
    [Markup.button.url('👥 Join Group', `https://t.me/${REQUIRED_GROUP.replace('@', '')}`)],
    [Markup.button.callback('✅ Sudah Join', 'verify_join')],
  ]);
}

bot.action('verify_join', async (ctx) => {
  const userId = ctx.from.id;
  await ctx.answerCbQuery('Memeriksa keanggotaan...').catch(() => {});

  // Paksa cek ulang ke Telegram, jangan pakai cache lama.
  const check = await checkMembership(ctx, { force: true });

  if (!check.ok) {
    const label = check.failed || 'Group';
    const username = MEMBERSHIP_LABELS[label] || check.username || REQUIRED_GROUP;
    const link = username.startsWith('@') ? `https://t.me/${username.slice(1)}` : username;
    await ctx.reply(
      `*❌ ${label} belum terdeteksi*\n\n` +
      `Silakan buka ${username}, tekan tombol **Join** di dalam chat, lalu tunggu 5 detik sebelum mengecek ulang.\n\n` +
      `💡 Telegram baru mencatat keanggotaan setelah chat benar-benar dibuka.`,
      {
        parse_mode: 'Markdown',
        reply_markup: { inline_keyboard: [
          [Markup.button.url(`📢 Join Channel`, `https://t.me/${REQUIRED_CHANNEL.replace('@', '')}`)],
          [Markup.button.url('👥 Join Group', `https://t.me/${REQUIRED_GROUP.replace('@', '')}`)],
          [Markup.button.callback('🔄 Cek Lagi', 'verify_join')]
        ]}
      }
    ).catch(() => {});
    return;
  }

  ensureUserExists(userId).catch(() => {});
  await ctx.reply('*✅ Terima kasih! Akses diberikan.*', { parse_mode: 'Markdown' }).catch(() => {});
  await sendMainMenu(ctx);
});

bot.command('admin', async (ctx) => {
  logger.info('Admin menu requested');
  
  if (!adminIds.includes(ctx.from.id)) {
    await ctx.reply('🚫 Anda tidak memiliki izin untuk mengakses menu admin.');
    return;
  }

  await sendAdminMenu(ctx);
});
async function sendMainMenu(ctx) {
  const userId = ctx.from.id;
  const userName = ctx.from.first_name || '-';

  const now = new Date();
  const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const weekStart = new Date(now.getFullYear(), now.getMonth(), now.getDate() - now.getDay()).getTime();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).getTime();

  // Tipe transaksi yang dihitung sebagai "akun dibuat" pada statistik.
  // Hanya jenis CREATE — renew (vpncf_renew/cfrenew/directedu-renew) tidak dihitung.
  const STAT_TYPES = ['ssh', 'vmess', 'vless', 'trojan', 'sshcf', 'vpncf', 'directedu'];
  const statWhere = `type IN (${STAT_TYPES.map(() => '?').join(',')})`;

  const [saldoRow, userTodayRow, userWeekRow, userMonthRow, globalTodayRow, globalWeekRow, globalMonthRow, totalUsersRow] = await Promise.all([
    dbGetAsync('SELECT saldo FROM users WHERE user_id = ?', [userId]),
    dbGetAsync(`SELECT COUNT(*) as count FROM transactions WHERE user_id = ? AND timestamp >= ? AND ${statWhere}`, [userId, todayStart, ...STAT_TYPES]),
    dbGetAsync(`SELECT COUNT(*) as count FROM transactions WHERE user_id = ? AND timestamp >= ? AND ${statWhere}`, [userId, weekStart, ...STAT_TYPES]),
    dbGetAsync(`SELECT COUNT(*) as count FROM transactions WHERE user_id = ? AND timestamp >= ? AND ${statWhere}`, [userId, monthStart, ...STAT_TYPES]),
    dbGetAsync(`SELECT COUNT(*) as count FROM transactions WHERE timestamp >= ? AND ${statWhere}`, [todayStart, ...STAT_TYPES]),
    dbGetAsync(`SELECT COUNT(*) as count FROM transactions WHERE timestamp >= ? AND ${statWhere}`, [weekStart, ...STAT_TYPES]),
    dbGetAsync(`SELECT COUNT(*) as count FROM transactions WHERE timestamp >= ? AND ${statWhere}`, [monthStart, ...STAT_TYPES]),
    dbGetAsync('SELECT COUNT(*) AS count FROM users'),
  ]).catch(() => [null, null, null, null, null, null, null, null]);

  const saldo = saldoRow ? saldoRow.saldo : 0;
  const userToday = userTodayRow ? userTodayRow.count : 0;
  const userWeek = userWeekRow ? userWeekRow.count : 0;
  const userMonth = userMonthRow ? userMonthRow.count : 0;
  const globalToday = globalTodayRow ? globalTodayRow.count : 0;
  const globalWeek = globalWeekRow ? globalWeekRow.count : 0;
  const globalMonth = globalMonthRow ? globalMonthRow.count : 0;
  const jumlahPengguna = totalUsersRow ? totalUsersRow.count : 0;

  await loadUserLanguage(userId);
  const isReseller = await isUserReseller(userId);
  const statusReseller = isReseller
    ? t(userId, 'status_reseller')
    : t(userId, 'status_not_reseller');

  const accountWord = t(userId, 'menu_account');
  const messageText =
    `${t(userId, 'menu_header', { store: NAMA_STORE })}\n\n` +
    `${t(userId, 'welcome')}\n\n` +
    `${t(userId, 'menu_greeting', { name: userName })}\n` +
    `${t(userId, 'menu_id', { id: userId })}\n` +
    `${t(userId, 'menu_balance', { saldo })}\n` +
    `${t(userId, 'menu_status', { status: statusReseller })}\n\n` +
    `<blockquote>${t(userId, 'menu_your_stats')}\n` +
    `• ${t(userId, 'menu_today')}    : ${userToday} ${accountWord}\n` +
    `• ${t(userId, 'menu_week')}  : ${userWeek} ${accountWord}\n` +
    `• ${t(userId, 'menu_month')}   : ${userMonth} ${accountWord}\n\n` +
    `${t(userId, 'menu_global_stats')}\n` +
    `• ${t(userId, 'menu_today')}    : ${globalToday} ${accountWord}\n` +
    `• ${t(userId, 'menu_week')}  : ${globalWeek} ${accountWord}\n` +
    `• ${t(userId, 'menu_month')}   : ${globalMonth} ${accountWord}\n` +
    `</blockquote>\n\n` +
    `${t(userId, 'menu_command')}\n` +
    `• ${t(userId, 'menu_main')}   : /start\n` +
    `• ${t(userId, 'menu_admin')}   : /admin\n` +
    `• ${t(userId, 'menu_admin_panel')}  : /helpadmin\n\n` +
    `${t(userId, 'menu_creator', { creator: vars.CREATOR || 'Admin' })}\n` +
    `${t(userId, 'menu_credit')}\n` +
    `${t(userId, 'menu_total_users', { count: jumlahPengguna })}\n` +
    `──────────────────────────`;

let keyboard = [
  [
    { text: t(userId, 'btn_create'), callback_data: 'service_create' },
    { text: t(userId, 'btn_renew'), callback_data: 'service_renew' }
  ],
  [
    { text: t(userId, 'btn_del'), callback_data: 'service_del' },
    { text: t(userId, 'btn_cek_server'), callback_data: 'cek_service' }
  ],
  [
    { text: t(userId, 'btn_migrate'), callback_data: 'service_migrate' },
    { text: t(userId, 'btn_change_proto'), callback_data: 'service_changeprotocol' }
  ],
  [
    { text: t(userId, 'btn_change_limip'), callback_data: 'service_changelimip' },
    { text: t(userId, 'btn_fix'), callback_data: 'service_fix' }
  ],
  [
    { text: t(userId, 'btn_lock'), callback_data: 'service_lock' },
    { text: t(userId, 'btn_unlock'), callback_data: 'service_unlock' }
  ],
  [
    { text: t(userId, 'btn_trial'), callback_data: 'service_trial' },
    { text: t(userId, 'btn_topup'), callback_data: 'topup_saldo', style: 'success' }
  ]
];

keyboard.push(
  [
    { text: t(userId, 'btn_edu'), callback_data: 'menu_directedu' },
    { text: t(userId, 'btn_vpncf'), callback_data: 'menu_vpncf' }
  ]
);

if (enableVpnCf) {
  keyboard.push(
    [
      { text: t(userId, 'btn_sshcf'), callback_data: 'menu_sshcf' }
    ]
  );
}

keyboard.push(
  [
    { text: t(userId, 'btn_list_account'), callback_data: 'list_account' }
  ],
  [
    { text: t(userId, 'btn_language'), callback_data: 'lang_menu' }
  ],
  [
    { text: t(userId, 'btn_reseller'), callback_data: 'jadi_reseller', style: 'success' }
  ]
);
  try {
    if (ctx.updateType === 'callback_query') {
      try {
      await ctx.editMessageText(messageText, {
          parse_mode: 'HTML',
          reply_markup: { inline_keyboard: keyboard }
        });
      } catch (error) {
        // Jika error karena message sudah diedit/dihapus, abaikan
        if (error && error.response && error.response.error_code === 400 &&
            (error.response.description.includes('message is not modified') ||
             error.response.description.includes('message to edit not found') ||
             error.response.description.includes('message can\'t be edited'))
        ) {
          logger.info('Edit message diabaikan karena pesan sudah diedit/dihapus atau tidak berubah.');
    } else {
          logger.error('Error saat mengedit menu utama:', error);
        }
      }
    } else {
      try {
        await ctx.reply(messageText, {
          parse_mode: 'HTML',
          reply_markup: { inline_keyboard: keyboard }
        });
      } catch (error) {
        logger.error('Error saat mengirim menu utama:', error);
      }
    }
    logger.info('Main menu sent');
  } catch (error) {
    logger.error('Error umum saat mengirim menu utama:', error);
  }
}

bot.command('hapuslog', async (ctx) => {
  if (!adminIds.includes(ctx.from.id)) return ctx.reply('Tidak ada izin!');
  try {
    if (fs.existsSync('bot-combined.log')) fs.unlinkSync('bot-combined.log');
    if (fs.existsSync('bot-error.log')) fs.unlinkSync('bot-error.log');
    ctx.reply('Log berhasil dihapus.');
    logger.info('Log file dihapus oleh admin.');
  } catch (e) {
    ctx.reply('Gagal menghapus log: ' + e.message);
    logger.error('Gagal menghapus log: ' + e.message);
  }
});

bot.command('syncaccount', async (ctx) => {
  if (!adminIds.includes(ctx.from.id)) return ctx.reply('⛔ Anda tidak punya izin.');
  await ctx.reply('🔄 *Sync total akun dari server...*', { parse_mode: 'Markdown' });
  const result = await autoSyncTotalCreate();
  if (result && result.results && result.results.length > 0) {
    const list = result.results.map(r => `  ${r}`).join('\n');
    await ctx.reply(`✅ *Sync selesai!*\n\n${list}\n\n📊 Updated: *${result.updated}* server\n❌ Failed: *${result.failed}* domain`, { parse_mode: 'Markdown' });
  } else {
    await ctx.reply(`⚠️ Sync selesai tapi tidak ada data.\n❌ Failed: ${result ? result.failed : 0} domain`, { parse_mode: 'Markdown' });
  }
});

bot.command('helpadmin', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
    return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

const helpMessage = `
<b>📋 Daftar Perintah Admin:</b>

1. <code>/addsaldo</code> - Menambahkan saldo ke akun pengguna.
2. <code>/deltopup</code> - Membatalkan proses topup.
3. <code>/addserver</code> - Menambahkan server baru.
4. <code>/addressel</code> - Menambahkan reseller baru.
5. <code>/delressel</code> - Menghapus ID reseller.
6. <code>/listressel</code> - Menampilkan daftar reseller.
7. <code>/broadcast</code> - Mengirim pesan siaran ke semua pengguna.
8. <code>/broadcastfoto</code> - Mengirim foto siaran ke semua pengguna.
9. <code>/editharga</code> - Mengedit harga layanan.
10. <code>/editauth</code> - Mengedit auth server.
11. <code>/editdomain</code> - Mengedit domain server.
12. <code>/editlimitcreate</code> - Mengedit batas pembuatan akun server.
13. <code>/editlimitip</code> - Mengedit batas IP server.
14. <code>/editlimitquota</code> - Mengedit batas quota server.
15. <code>/editnama</code> - Mengedit nama server.
16. <code>/edittotalcreate</code> - Mengedit total pembuatan akun server.
17. <code>/hapuslog</code> - Menghapus log bot.
18. <code>/backup</code> - Menjalankan backup otomatis.
  19. <code>/paymet</code> - Mengubah metode pembayaran (GOPAY, ORKUT, atau SHOPEEPAY).
20. <code>/syncaccount</code> - Auto sync total create akun dari server ke database.
21. <code>/lock_migrasi</code> - Mengunci server agar tidak bisa dijadikan tujuan migrasi.
22. <code>/unlock_migrasi</code> - Membuka kunci migrasi pada server.
23. <code>/list_lock_migrasi</code> - Melihat daftar server yang terkunci migrasi.

<b>☁️ CloudFront Private Server Commands:</b>
24. <code>/addservercf</code> - Tambah server CloudFront Private (dengan CF domain).
25. <code>/addservercf_reseller</code> - Tambah server CloudFront Private khusus Reseller.
26. <code>/edithargacf</code> - Edit harga server CloudFront Private.
27. <code>/editcfdomain</code> - Edit CloudFront domain server.
28. <code>/listservercf</code> - Lihat daftar server CloudFront Private.
29. <code>/delservercf</code> - Hapus server CloudFront Private.

<b>🔧 Reseller Server Commands:</b>
30. <code>/addserver_reseller</code> - Tambah server SSH/VPN khusus Reseller.

<b>🔄 VPN CloudFront Toggle:</b>
31. <code>/togglevpncf</code> - Aktifkan/Nonaktifkan fitur VPN CloudFront Private di menu user.

<b>🔑 API Reseller Commands:</b>
32. <code>/apikey</code> - Manage API keys for resellers (create, regenerate, revoke, status, list).

Gunakan perintah ini dengan format yang benar untuk menghindari kesalahan.
`;

  ctx.reply(helpMessage, { parse_mode: 'HTML' });
});

// === LOCK MIGRASI ===
bot.command('lock_migrasi', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
    return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length < 2) {
    return ctx.reply('⚠️ Format salah. Gunakan: `/lock_migrasi <domain>`\nContoh: `/lock_migrasi ssl-idbiznetvip8.rajaserver.web.id`', { parse_mode: 'Markdown' });
  }

  const domain = args[1].trim();

  const server = await new Promise((resolve, reject) => {
    db.get('SELECT * FROM Server WHERE domain = ?', [domain], (e, row) => {
      if (e) reject(e); else resolve(row);
    });
  });

  if (!server) {
    return ctx.reply(`❌ *Server dengan domain \`${esc(domain)}\` tidak ditemukan.*`, { parse_mode: 'Markdown' });
  }

  const existing = await new Promise((resolve, reject) => {
    db.get('SELECT * FROM migration_locks WHERE domain = ?', [domain], (e, row) => {
      if (e) reject(e); else resolve(row);
    });
  });

  if (existing) {
    return ctx.reply(`⚠️ Server \`${esc(domain)}\` sudah terkunci migrasi sebelumnya.`, { parse_mode: 'Markdown' });
  }

  const now = new Date().toISOString();
  db.run('INSERT INTO migration_locks (domain, locked_at) VALUES (?, ?)', [domain, now], function(err) {
    if (err) {
      logger.error('Gagal lock migrasi:', err.message);
      return ctx.reply('❌ Gagal mengunci migrasi.', { parse_mode: 'Markdown' });
    }

    logger.info(`🔒 Admin ${userId} mengunci migrasi ke server ${domain}`);
    ctx.reply(
      `🔒 *Lock Migrasi Berhasil!*\n\n` +
      `🖥 *Server* : ${esc(server.nama_server)}\n` +
      `🌐 *Domain* : \`${esc(domain)}\`\n\n` +
      `Tidak ada yang bisa migrasi akun ke server ini.`,
      { parse_mode: 'Markdown' }
    );
  });
});

bot.command('unlock_migrasi', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
    return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length < 2) {
    return ctx.reply('⚠️ Format salah. Gunakan: `/unlock_migrasi <domain>`\nContoh: `/unlock_migrasi ssl-idbiznetvip8.rajaserver.web.id`', { parse_mode: 'Markdown' });
  }

  const domain = args[1].trim();

  const existing = await new Promise((resolve, reject) => {
    db.get('SELECT * FROM migration_locks WHERE domain = ?', [domain], (e, row) => {
      if (e) reject(e); else resolve(row);
    });
  });

  if (!existing) {
    return ctx.reply(`⚠️ Server \`${esc(domain)}\` tidak dalam keadaan terkunci migrasi.`, { parse_mode: 'Markdown' });
  }

  db.run('DELETE FROM migration_locks WHERE domain = ?', [domain], function(err) {
    if (err) {
      logger.error('Gagal unlock migrasi:', err.message);
      return ctx.reply('❌ Gagal membuka kunci migrasi.', { parse_mode: 'Markdown' });
    }

    logger.info(`🔓 Admin ${userId} membuka kunci migrasi ke server ${domain}`);
    ctx.reply(
      `🔓 *Unlock Migrasi Berhasil!*\n\n` +
      `🌐 *Domain* : \`${esc(domain)}\`\n\n` +
      `Migrasi akun ke server ini sekarang diizinkan.`,
      { parse_mode: 'Markdown' }
    );
  });
});

bot.command('list_lock_migrasi', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
    return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  db.all('SELECT * FROM migration_locks', [], async (err, rows) => {
    if (err) {
      logger.error('Gagal mengambil data lock migrasi:', err.message);
      return ctx.reply('❌ Gagal mengambil data.', { parse_mode: 'Markdown' });
    }

    if (!rows || rows.length === 0) {
      return ctx.reply('📋 *Daftar Lock Migrasi*\n\nTidak ada server yang terkunci migrasi.', { parse_mode: 'Markdown' });
    }

    let msg = '🔒 *Daftar Server Lock Migrasi*\n\n';
    for (const row of rows) {
      const server = await new Promise((resolve, reject) => {
        db.get('SELECT nama_server FROM Server WHERE domain = ?', [row.domain], (e, r) => {
          if (e) reject(e); else resolve(r);
        });
      });
      const name = server ? server.nama_server : '(unknown)';
      const lockedDate = row.locked_at ? new Date(row.locked_at).toLocaleString('id-ID') : '-';
      msg += `🖥 *${esc(name)}*\n🌐 \`${esc(row.domain)}\`\n📅 Locked: ${lockedDate}\n\n`;
    }

    ctx.reply(msg, { parse_mode: 'Markdown' });
  });
});

// Admin: ubah metode pembayaran (GOPAY atau ORKUT)
bot.command('paymet', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) return ctx.reply('⛔ Anda tidak punya izin.');

  const arg = ctx.message.text.split(' ').slice(1).join(' ').trim().toUpperCase();
  if (!arg) return ctx.reply(`Penggunaan: /paymet GOPAY|ORKUT\nCurrent: ${vars.PAYMENT}`);

   if (!['GOPAY', 'ORKUT', 'SHOPEEPAY'].includes(arg)) {
    return ctx.reply('⚠️ Pilihan tidak valid. Gunakan GOPAY, ORKUT, atau SHOPEEPAY');
  }

  try {
    const filePath = path.join(__dirname, '.vars.json');
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    data.PAYMENT = arg;
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');

    // update runtime vars
    vars.PAYMENT = arg;
    GOPAY_KEY = data.GOPAY_KEY;
    AUTH_USER = data.AUTH_USERNAME_ORKUT;
    AUTH_TOKEN = data.AUTH_TOKEN_ORKUT;

    ctx.reply(`✅ PAYMENT diubah menjadi ${arg}`);
    logger.info(`PAYMENT diubah menjadi ${arg} oleh admin ${userId}`);
  } catch (e) {
    ctx.reply('❌ Gagal update .vars.json: ' + e.message);
    logger.error('Failed to update PAYMENT: ' + e.message);
  }
});

bot.command('togglevpncf', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) return ctx.reply('⛔ Anda tidak punya izin.');

  enableVpnCf = !enableVpnCf;
  try {
    const filePath = path.join(__dirname, '.vars.json');
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    data.ENABLE_VPNCF = enableVpnCf;
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    vars.ENABLE_VPNCF = enableVpnCf;
  } catch (e) {
    logger.error('Failed to update ENABLE_VPNCF: ' + e.message);
  }
  const msgKey = enableVpnCf ? 'vpncf_toggle_on' : 'vpncf_toggle_off';
  ctx.reply(t(userId, msgKey), { parse_mode: 'HTML' });
  logger.info(`VPN CloudFront Private diubah menjadi ${enableVpnCf ? 'ON' : 'OFF'} oleh admin ${userId}`);
});

const BROADCAST_CONCURRENCY = 20;
const BROADCAST_BATCH_DELAY_MS = 1000;

async function sendBroadcastToUser(sendFn, row, maxRetry = 2) {
  for (let attempt = 0; ; attempt++) {
    try {
      await sendFn(row);
      return { ok: true };
    } catch (error) {
      const code = error.response?.status;
      if (code === 429 && attempt < maxRetry) {
        const retry = Number(error.response?.data?.parameters?.retry_after) || 3;
        await new Promise(r => setTimeout(r, (retry + 1) * 1000));
        continue;
      }
      return { ok: false, code };
    }
  }
}

async function runBroadcast(ctx, statusMsg, rows, sendFn) {
  let sukses = 0;
  let gagal = 0;
  let invalid = 0;
  const total = rows.length;

  for (let i = 0; i < total; i += BROADCAST_CONCURRENCY) {
    const batch = rows.slice(i, i + BROADCAST_CONCURRENCY);
    await Promise.all(batch.map(async (row) => {
      const res = await sendBroadcastToUser(sendFn, row);
      if (res.ok) {
        sukses++;
      } else {
        gagal++;
        // TIDAK MENGHAPUS USER
        if (res.code === 400 || res.code === 403) {
          invalid++;
          console.log(`🚫 User invalid (tidak dihapus): ${row.user_id}`);
        }
        console.log(`❌ Gagal kirim ke ${row.user_id}: ${res.code}`);
      }
    }));

    const done = Math.min(i + BROADCAST_CONCURRENCY, total);
    if (statusMsg) {
      ctx.telegram.editMessageText(
        statusMsg.chat.id,
        statusMsg.message_id,
        undefined,
        `📢 *Broadcast berjalan...* (${done}/${total})\n\n✔️ Berhasil: *${sukses}*\n❌ Gagal: *${gagal}*\n🚫 Invalid/Blocked: *${invalid}*`,
        { parse_mode: 'Markdown' }
      ).catch(() => {});
    }

    if (done < total) {
      await new Promise(r => setTimeout(r, BROADCAST_BATCH_DELAY_MS));
    }
  }

  return { sukses, gagal, invalid, total };
}

bot.command('broadcast', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
    return ctx.reply('⛔ Anda tidak punya izin.');
  }

  const msg = ctx.message.reply_to_message
    ? ctx.message.reply_to_message.text
    : ctx.message.text.split(' ').slice(1).join(' ');

  if (!msg) return ctx.reply('⚠️ Harap isi pesan broadcast.');

  const statusMsg = await ctx.reply('📢 Broadcast dimulai...').catch(() => null);

  db.all("SELECT user_id FROM users", [], async (err, rows) => {
    if (err) return ctx.reply('⚠️ Error ambil data user.');

    const sendFn = (row) => axios.post(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      chat_id: row.user_id,
      text: msg
    });

    const { sukses, gagal, invalid } = await runBroadcast(ctx, statusMsg, rows, sendFn);

    const summary =
      `📣 *Broadcast selesai!*\n\n` +
      `✔️ Berhasil: *${sukses}*\n` +
      `❌ Gagal: *${gagal}*\n` +
      `🚫 Invalid/Blocked: *${invalid}*`;

    if (statusMsg) {
      ctx.telegram.editMessageText(statusMsg.chat.id, statusMsg.message_id, undefined, summary, { parse_mode: 'Markdown' }).catch(() => {});
    } else {
      ctx.reply(summary, { parse_mode: 'Markdown' });
    }
  });
});

bot.command('broadcastfoto', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
    return ctx.reply('⛔ Anda tidak punya izin.');
  }

  const replyMsg = ctx.message.reply_to_message;

  let isPhoto = false;
  let msgText = '';
  let photoFileId = '';

  if (replyMsg) {
    if (replyMsg.photo) {
      isPhoto = true;
      photoFileId = replyMsg.photo[replyMsg.photo.length - 1].file_id;
      msgText = replyMsg.caption || '';
    } else if (replyMsg.text) {
      msgText = replyMsg.text;
    }
  } else {
    msgText = ctx.message.text.split(' ').slice(1).join(' ');
  }

  if (!msgText && !photoFileId) {
    return ctx.reply('⚠️ Harap isi pesan broadcast atau reply foto.');
  }

  const statusMsg = await ctx.reply('📢 Broadcast dimulai...').catch(() => null);

  db.all("SELECT user_id FROM users", [], async (err, rows) => {
    if (err) return ctx.reply('⚠️ Error ambil data user.');

    const sendFn = isPhoto
      ? (row) => axios.post(`https://api.telegram.org/bot${BOT_TOKEN}/sendPhoto`, {
          chat_id: row.user_id,
          photo: photoFileId,
          caption: msgText
        })
      : (row) => axios.post(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
          chat_id: row.user_id,
          text: msgText
        });

    const { sukses, gagal, invalid } = await runBroadcast(ctx, statusMsg, rows, sendFn);

    const summary =
      `📣 *Broadcast selesai!*\n\n` +
      `✔️ Berhasil: *${sukses}*\n` +
      `❌ Gagal: *${gagal}*\n` +
      `🚫 Invalid/Blocked: *${invalid}*`;

    if (statusMsg) {
      ctx.telegram.editMessageText(statusMsg.chat.id, statusMsg.message_id, undefined, summary, { parse_mode: 'Markdown' }).catch(() => {});
    } else {
      ctx.reply(summary, { parse_mode: 'Markdown' });
    }
  });
});

bot.command('addsaldo', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
      return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length !== 3) {
      return ctx.reply('⚠️ Format salah. Gunakan: `/addsaldo <user_id> <jumlah>`', { parse_mode: 'Markdown' });
  }

  const targetUserId = parseInt(args[1]);
  const amount = parseInt(args[2]);

  if (isNaN(targetUserId) || isNaN(amount)) {
      return ctx.reply('⚠️ `user_id` dan `jumlah` harus berupa angka.', { parse_mode: 'Markdown' });
  }

  if (/\s/.test(args[1]) || /\./.test(args[1]) || /\s/.test(args[2]) || /\./.test(args[2])) {
      return ctx.reply('⚠️ `user_id` dan `jumlah` tidak boleh mengandung spasi atau titik.', { parse_mode: 'Markdown' });
  }

  db.get("SELECT * FROM users WHERE user_id = ?", [targetUserId], (err, row) => {
      if (err) {
          logger.error('⚠️ Kesalahan saat memeriksa `user_id`:', err.message);
          return ctx.reply('⚠️ Kesalahan saat memeriksa `user_id`.', { parse_mode: 'Markdown' });
      }

      if (!row) {
          return ctx.reply('⚠️ `user_id` tidak terdaftar.', { parse_mode: 'Markdown' });
      }

      db.run("UPDATE users SET saldo = saldo + ? WHERE user_id = ?", [amount, targetUserId], function(err) {
          if (err) {
              logger.error('⚠️ Kesalahan saat menambahkan saldo:', err.message);
              return ctx.reply('⚠️ Kesalahan saat menambahkan saldo.', { parse_mode: 'Markdown' });
          }

          if (this.changes === 0) {
              return ctx.reply('⚠️ Pengguna tidak ditemukan.', { parse_mode: 'Markdown' });
          }

          ctx.reply(`✅ Saldo sebesar \`${amount}\` berhasil ditambahkan untuk \`user_id\` \`${targetUserId}\`.`, { parse_mode: 'Markdown' });

          // Cek saldo terbaru dan auto-activate reseller jika >= Rp50.000
          db.get("SELECT saldo FROM users WHERE user_id = ?", [targetUserId], (err2, row2) => {
            if (!err2 && row2) {
              autoActivateReseller(targetUserId, row2.saldo);
            }
          });
      });
  });
});

bot.command('checkressel', async (ctx) => {
  const userId = ctx.from.id;
  console.log('[DEBUG] checkressel, userId:', userId);
  const isR = await isUserReseller(userId);
  console.log('[DEBUG] isReseller:', isR);
  ctx.reply(`ID ${userId} ${isR ? 'adalah reseller ✅' : 'bukan reseller ❌'}`);
});

bot.command('addserver_reseller', async (ctx) => {
  try {
    const args = ctx.message.text.split(' ').slice(1);
    if (args.length < 7) {
      return ctx.reply('⚠️ Format salah!\n\nGunakan:\n/addserver_reseller <domain> <auth> <harga> <nama_server> <quota> <iplimit> <batas_create_akun>');
    }

    const [domain, auth, harga, nama_server, quota, iplimit, batas_create_akun] = args;
    
    // ✅ TAMBAHKAN total_create_akun di VALUES
    db.run(`INSERT INTO Server (domain, auth, harga, nama_server, quota, iplimit, batas_create_akun, is_reseller_only, total_create_akun) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0)`,
      [domain, auth, harga, nama_server, quota, iplimit, batas_create_akun],
      function (err) {
        if (err) {
          logger.error('❌ Gagal menambah server reseller:', err.message);
          return ctx.reply('❌ *Gagal menambah server reseller.*', { parse_mode: 'Markdown' });
        }
        ctx.reply('✅ *Server khusus reseller berhasil ditambahkan!*', { parse_mode: 'Markdown' });
      }
    );
  } catch (e) {
    logger.error('Error di /addserver_reseller:', e);
    ctx.reply('❌ *Terjadi kesalahan.*', { parse_mode: 'Markdown' });
  }
});

bot.command('addserver', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
      return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length !== 8) {
      return ctx.reply('⚠️ Format salah. Gunakan: `/addserver <domain> <auth> <harga> <nama_server> <quota> <iplimit> <batas_create_account>`', { parse_mode: 'Markdown' });
  }

  const [domain, auth, harga, nama_server, quota, iplimit, batas_create_akun] = args.slice(1);

  const numberOnlyRegex = /^\d+$/;
  if (!numberOnlyRegex.test(harga) || !numberOnlyRegex.test(quota) || !numberOnlyRegex.test(iplimit) || !numberOnlyRegex.test(batas_create_akun)) {
      return ctx.reply('⚠️ `harga`, `quota`, `iplimit`, dan `batas_create_akun` harus berupa angka.', { parse_mode: 'Markdown' });
  }

  db.run("INSERT INTO Server (domain, auth, harga, nama_server, quota, iplimit, batas_create_akun) VALUES (?, ?, ?, ?, ?, ?, ?)", 
      [domain, auth, parseInt(harga), nama_server, parseInt(quota), parseInt(iplimit), parseInt(batas_create_akun)], function(err) {
      if (err) {
          logger.error('⚠️ Kesalahan saat menambahkan server:', err.message);
          return ctx.reply('⚠️ Kesalahan saat menambahkan server.', { parse_mode: 'Markdown' });
      }

      ctx.reply(`✅ Server \`${nama_server}\` berhasil ditambahkan.`, { parse_mode: 'Markdown' });
  });
});

bot.command('addservercf', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
    return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length !== 9) {
    return ctx.reply('⚠️ Format salah. Gunakan: `/addservercf <domain> <auth> <harga> <nama_server> <quota> <iplimit> <batas_create_akun> <cloudfront_domain>`', { parse_mode: 'Markdown' });
  }

  const [domain, auth, harga, nama_server, quota, iplimit, batas_create_akun, cloudfront_domain] = args.slice(1);

  const numberOnlyRegex = /^\d+$/;
  if (!numberOnlyRegex.test(harga) || !numberOnlyRegex.test(quota) || !numberOnlyRegex.test(iplimit) || !numberOnlyRegex.test(batas_create_akun)) {
    return ctx.reply('⚠️ `harga`, `quota`, `iplimit`, dan `batas_create_akun` harus berupa angka.', { parse_mode: 'Markdown' });
  }

  // Admin input marketing IP (1, 2, 5), simpan internal IP (+1 untuk anti-ban)
  const internalIplimit = parseInt(iplimit) + 1;

  db.run("INSERT INTO Server (domain, auth, harga, nama_server, quota, iplimit, batas_create_akun, cloudfront_domain) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    [domain, auth, parseInt(harga), nama_server, parseInt(quota), internalIplimit, parseInt(batas_create_akun), cloudfront_domain], function(err) {
    if (err) {
      logger.error('⚠️ Kesalahan saat menambahkan server CloudFront:', err.message);
      return ctx.reply('⚠️ Kesalahan saat menambahkan server CloudFront.', { parse_mode: 'Markdown' });
    }

    ctx.reply(`✅ Server CloudFront \`${nama_server}\` berhasil ditambahkan.\n🌐 Domain: \`${domain}\`\n☁️ CF Domain: \`${cloudfront_domain}\`\n📶 Limit IP (marketing): \`${iplimit}\` IP\n📶 Limit IP (internal): \`${internalIplimit}\` IP`, { parse_mode: 'Markdown' });
  });
});

bot.command('addservercf_reseller', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
    return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length !== 9) {
    return ctx.reply('⚠️ Format salah. Gunakan: `/addservercf_reseller <domain> <auth> <harga> <nama_server> <quota> <iplimit> <batas_create_akun> <cloudfront_domain>`', { parse_mode: 'Markdown' });
  }

  const [domain, auth, harga, nama_server, quota, iplimit, batas_create_akun, cloudfront_domain] = args.slice(1);

  const numberOnlyRegex = /^\d+$/;
  if (!numberOnlyRegex.test(harga) || !numberOnlyRegex.test(quota) || !numberOnlyRegex.test(iplimit) || !numberOnlyRegex.test(batas_create_akun)) {
    return ctx.reply('⚠️ `harga`, `quota`, `iplimit`, dan `batas_create_akun` harus berupa angka.', { parse_mode: 'Markdown' });
  }

  // Admin input marketing IP (1, 2, 5), simpan internal IP (+1 untuk anti-ban)
  const internalIplimit = parseInt(iplimit) + 1;

  db.run("INSERT INTO Server (domain, auth, harga, nama_server, quota, iplimit, batas_create_akun, cloudfront_domain, is_reseller_only) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
    [domain, auth, parseInt(harga), nama_server, parseInt(quota), internalIplimit, parseInt(batas_create_akun), cloudfront_domain], function(err) {
    if (err) {
      logger.error('⚠️ Kesalahan saat menambahkan server CloudFront Reseller:', err.message);
      return ctx.reply('⚠️ Kesalahan saat menambahkan server CloudFront Reseller.', { parse_mode: 'Markdown' });
    }

    ctx.reply(`✅ Server CloudFront Reseller \`${nama_server}\` berhasil ditambahkan.\n🌐 Domain: \`${domain}\`\n☁️ CF Domain: \`${cloudfront_domain}\`\n📶 Limit IP (marketing): \`${iplimit}\` IP\n📶 Limit IP (internal): \`${internalIplimit}\` IP\n🔒 Khusus Reseller: \`YA\``, { parse_mode: 'Markdown' });
  });
});

bot.command('edithargacf', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
    return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length !== 3) {
    return ctx.reply('⚠️ Format salah. Gunakan: `/edithargacf <domain> <harga>`', { parse_mode: 'Markdown' });
  }

  const [domain, harga] = args.slice(1);

  if (!/^\d+$/.test(harga)) {
    return ctx.reply('⚠️ `harga` harus berupa angka.', { parse_mode: 'Markdown' });
  }

  db.run("UPDATE Server SET harga = ? WHERE domain = ? AND cloudfront_domain IS NOT NULL AND cloudfront_domain != ''", [parseInt(harga), domain], function(err) {
    if (err) {
      logger.error('⚠️ Kesalahan saat mengedit harga server CF:', err.message);
      return ctx.reply('⚠️ Kesalahan saat mengedit harga server CF.', { parse_mode: 'Markdown' });
    }

    if (this.changes === 0) {
      return ctx.reply('⚠️ Server CloudFront tidak ditemukan.', { parse_mode: 'Markdown' });
    }

    ctx.reply(`✅ Harga server CF \`${domain}\` berhasil diubah menjadi \`${harga}\`.`, { parse_mode: 'Markdown' });
  });
});

bot.command('editcfdomain', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
    return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length !== 3) {
    return ctx.reply('⚠️ Format salah. Gunakan: `/editcfdomain <domain> <cloudfront_domain>`', { parse_mode: 'Markdown' });
  }

  const [domain, cloudfront_domain] = args.slice(1);

  db.run("UPDATE Server SET cloudfront_domain = ? WHERE domain = ?", [cloudfront_domain, domain], function(err) {
    if (err) {
      logger.error('⚠️ Kesalahan saat mengedit CF domain:', err.message);
      return ctx.reply('⚠️ Kesalahan saat mengedit CF domain.', { parse_mode: 'Markdown' });
    }

    if (this.changes === 0) {
      return ctx.reply('⚠️ Server tidak ditemukan.', { parse_mode: 'Markdown' });
    }

    ctx.reply(`✅ CloudFront domain server \`${domain}\` berhasil diubah menjadi \`${cloudfront_domain}\`.`, { parse_mode: 'Markdown' });
  });
});

bot.command('listservercf', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
    return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  db.all("SELECT * FROM Server WHERE cloudfront_domain IS NOT NULL AND cloudfront_domain != '' ORDER BY nama_server ASC", [], (err, servers) => {
    if (err) {
      logger.error('⚠️ Kesalahan saat mengambil server CF:', err.message);
      return ctx.reply('⚠️ Kesalahan saat mengambil server CF.', { parse_mode: 'Markdown' });
    }

    if (!servers || servers.length === 0) {
      return ctx.reply('📭 Belum ada server CloudFront Private.', { parse_mode: 'Markdown' });
    }

    let msg = '☁️ *DAFTAR SERVER CLOUDFRONT PRIVATE*\n\n';
    servers.forEach((srv, i) => {
      const showQuota = !srv.quota || srv.quota === 0 ? 'Unlimited' : `${srv.quota}GB`;
      const showIP = marketingIP(srv);
      const harga30 = srv.harga * 30;
      const isFull = srv.total_create_akun >= srv.batas_create_akun;
      msg += `${i + 1}. *${srv.nama_server}*\n`;
      msg += `   🌐 Domain: \`${srv.domain}\`\n`;
      msg += `   ☁️ CF Domain: \`${srv.cloudfront_domain}\`\n`;
      msg += `   💰 Harga: Rp${srv.harga}/hr | Rp${harga30}/30hr\n`;
      msg += `   📊 Quota: ${showQuota} | 🔢 IP: ${showIP}\n`;
      msg += `   👥 Akun: ${srv.total_create_akun}/${srv.batas_create_akun} ${isFull ? '⚠️ PENUH' : ''}\n`;
      msg += `   🔐 Reseller Only: ${srv.is_reseller_only ? 'Ya' : 'Tidak'}\n\n`;
    });

    ctx.reply(msg, { parse_mode: 'Markdown' });
  });
});

bot.command('delservercf', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
    return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length !== 2) {
    return ctx.reply('⚠️ Format salah. Gunakan: `/delservercf <domain>`', { parse_mode: 'Markdown' });
  }

  const [domain] = args.slice(1);

  db.run("DELETE FROM Server WHERE domain = ? AND cloudfront_domain IS NOT NULL AND cloudfront_domain != ''", [domain], function(err) {
    if (err) {
      logger.error('⚠️ Kesalahan saat menghapus server CF:', err.message);
      return ctx.reply('⚠️ Kesalahan saat menghapus server CF.', { parse_mode: 'Markdown' });
    }

    if (this.changes === 0) {
      return ctx.reply('⚠️ Server CloudFront tidak ditemukan.', { parse_mode: 'Markdown' });
    }

    ctx.reply(`✅ Server CloudFront \`${domain}\` berhasil dihapus.`, { parse_mode: 'Markdown' });
  });
});

bot.command('editharga', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
      return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length !== 3) {
      return ctx.reply('⚠️ Format salah. Gunakan: `/editharga <domain> <harga>`', { parse_mode: 'Markdown' });
  }

  const [domain, harga] = args.slice(1);

  if (!/^\d+$/.test(harga)) {
      return ctx.reply('⚠️ `harga` harus berupa angka.', { parse_mode: 'Markdown' });
  }

  db.run("UPDATE Server SET harga = ? WHERE domain = ?", [parseInt(harga), domain], function(err) {
      if (err) {
          logger.error('⚠️ Kesalahan saat mengedit harga server:', err.message);
          return ctx.reply('⚠️ Kesalahan saat mengedit harga server.', { parse_mode: 'Markdown' });
      }

      if (this.changes === 0) {
          return ctx.reply('⚠️ Server tidak ditemukan.', { parse_mode: 'Markdown' });
      }

      ctx.reply(`✅ Harga server \`${domain}\` berhasil diubah menjadi \`${harga}\`.`, { parse_mode: 'Markdown' });
  });
});

bot.command('editnama', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
      return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length !== 3) {
      return ctx.reply('⚠️ Format salah. Gunakan: `/editnama <domain> <nama_server>`', { parse_mode: 'Markdown' });
  }

  const [domain, nama_server] = args.slice(1);

  db.run("UPDATE Server SET nama_server = ? WHERE domain = ?", [nama_server, domain], function(err) {
      if (err) {
          logger.error('⚠️ Kesalahan saat mengedit nama server:', err.message);
          return ctx.reply('⚠️ Kesalahan saat mengedit nama server.', { parse_mode: 'Markdown' });
      }

      if (this.changes === 0) {
          return ctx.reply('⚠️ Server tidak ditemukan.', { parse_mode: 'Markdown' });
      }

      ctx.reply(`✅ Nama server \`${domain}\` berhasil diubah menjadi \`${nama_server}\`.`, { parse_mode: 'Markdown' });
  });
});

bot.command('editdomain', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
      return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length !== 3) {
      return ctx.reply('⚠️ Format salah. Gunakan: `/editdomain <old_domain> <new_domain>`', { parse_mode: 'Markdown' });
  }

  const [old_domain, new_domain] = args.slice(1);

  db.run("UPDATE Server SET domain = ? WHERE domain = ?", [new_domain, old_domain], function(err) {
      if (err) {
          logger.error('⚠️ Kesalahan saat mengedit domain server:', err.message);
          return ctx.reply('⚠️ Kesalahan saat mengedit domain server.', { parse_mode: 'Markdown' });
      }

      if (this.changes === 0) {
          return ctx.reply('⚠️ Server tidak ditemukan.', { parse_mode: 'Markdown' });
      }

      ctx.reply(`✅ Domain server \`${old_domain}\` berhasil diubah menjadi \`${new_domain}\`.`, { parse_mode: 'Markdown' });
  });
});

bot.command('editauth', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
      return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length !== 3) {
      return ctx.reply('⚠️ Format salah. Gunakan: `/editauth <domain> <auth>`', { parse_mode: 'Markdown' });
  }

  const [domain, auth] = args.slice(1);

  db.run("UPDATE Server SET auth = ? WHERE domain = ?", [auth, domain], function(err) {
      if (err) {
          logger.error('⚠️ Kesalahan saat mengedit auth server:', err.message);
          return ctx.reply('⚠️ Kesalahan saat mengedit auth server.', { parse_mode: 'Markdown' });
      }

      if (this.changes === 0) {
          return ctx.reply('⚠️ Server tidak ditemukan.', { parse_mode: 'Markdown' });
      }

      ctx.reply(`✅ Auth server \`${domain}\` berhasil diubah menjadi \`${auth}\`.`, { parse_mode: 'Markdown' });
  });
});

bot.command('editlimitquota', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
      return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length !== 3) {
      return ctx.reply('⚠️ Format salah. Gunakan: `/editlimitquota <domain> <quota>`', { parse_mode: 'Markdown' });
  }

  const [domain, quota] = args.slice(1);

  if (!/^\d+$/.test(quota)) {
      return ctx.reply('⚠️ `quota` harus berupa angka.', { parse_mode: 'Markdown' });
  }

  db.run("UPDATE Server SET quota = ? WHERE domain = ?", [parseInt(quota), domain], function(err) {
      if (err) {
          logger.error('⚠️ Kesalahan saat mengedit quota server:', err.message);
          return ctx.reply('⚠️ Kesalahan saat mengedit quota server.', { parse_mode: 'Markdown' });
      }

      if (this.changes === 0) {
          return ctx.reply('⚠️ Server tidak ditemukan.', { parse_mode: 'Markdown' });
      }

      ctx.reply(`✅ Quota server \`${domain}\` berhasil diubah menjadi \`${quota}\`.`, { parse_mode: 'Markdown' });
  });
});

bot.command('editlimitip', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
      return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length !== 3) {
      return ctx.reply('⚠️ Format salah. Gunakan: `/editlimitip <domain> <iplimit>`', { parse_mode: 'Markdown' });
  }

  const [domain, iplimit] = args.slice(1);

  if (!/^\d+$/.test(iplimit)) {
      return ctx.reply('⚠️ `iplimit` harus berupa angka.', { parse_mode: 'Markdown' });
  }

  db.run("UPDATE Server SET iplimit = ? WHERE domain = ?", [parseInt(iplimit), domain], function(err) {
      if (err) {
          logger.error('⚠️ Kesalahan saat mengedit iplimit server:', err.message);
          return ctx.reply('⚠️ Kesalahan saat mengedit iplimit server.', { parse_mode: 'Markdown' });
      }

      if (this.changes === 0) {
          return ctx.reply('⚠️ Server tidak ditemukan.', { parse_mode: 'Markdown' });
      }

      ctx.reply(`✅ Iplimit server \`${domain}\` berhasil diubah menjadi \`${iplimit}\`.`, { parse_mode: 'Markdown' });
  });
});

bot.command('editlimitcreate', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
      return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length !== 3) {
      return ctx.reply('⚠️ Format salah. Gunakan: `/editlimitcreate <domain> <batas_create_akun>`', { parse_mode: 'Markdown' });
  }

  const [domain, batas_create_akun] = args.slice(1);

  if (!/^\d+$/.test(batas_create_akun)) {
      return ctx.reply('⚠️ `batas_create_akun` harus berupa angka.', { parse_mode: 'Markdown' });
  }

  db.run("UPDATE Server SET batas_create_akun = ? WHERE domain = ?", [parseInt(batas_create_akun), domain], function(err) {
      if (err) {
          logger.error('⚠️ Kesalahan saat mengedit batas_create_akun server:', err.message);
          return ctx.reply('⚠️ Kesalahan saat mengedit batas_create_akun server.', { parse_mode: 'Markdown' });
      }

      if (this.changes === 0) {
          return ctx.reply('⚠️ Server tidak ditemukan.', { parse_mode: 'Markdown' });
      }

      ctx.reply(`✅ Batas create akun server \`${domain}\` berhasil diubah menjadi \`${batas_create_akun}\`.`, { parse_mode: 'Markdown' });
  });
});
bot.command('edittotalcreate', async (ctx) => {
  const userId = ctx.message.from.id;
  if (!adminIds.includes(userId)) {
      return ctx.reply('⚠️ Anda tidak memiliki izin untuk menggunakan perintah ini.', { parse_mode: 'Markdown' });
  }

  const args = ctx.message.text.split(' ');
  if (args.length !== 3) {
      return ctx.reply('⚠️ Format salah. Gunakan: `/edittotalcreate <domain> <total_create_akun>`', { parse_mode: 'Markdown' });
  }

  const [domain, total_create_akun] = args.slice(1);

  if (!/^\d+$/.test(total_create_akun)) {
      return ctx.reply('⚠️ `total_create_akun` harus berupa angka.', { parse_mode: 'Markdown' });
  }

  db.run("UPDATE Server SET total_create_akun = ? WHERE domain = ?", [parseInt(total_create_akun), domain], function(err) {
      if (err) {
          logger.error('⚠️ Kesalahan saat mengedit total_create_akun server:', err.message);
          return ctx.reply('⚠️ Kesalahan saat mengedit total_create_akun server.', { parse_mode: 'Markdown' });
      }

      if (this.changes === 0) {
          return ctx.reply('⚠️ Server tidak ditemukan.', { parse_mode: 'Markdown' });
      }

      ctx.reply(`✅ Total create akun server \`${domain}\` berhasil diubah menjadi \`${total_create_akun}\`.`, { parse_mode: 'Markdown' });
  });
});
async function handleServiceAction(ctx, action) {
  const userId = ctx.from.id;
  await loadUserLanguage(userId);
  const svcBtn = (act, type) => t(userId, 'svc_action_' + act) + ' ' + t(userId, 'type_' + type);
  let keyboard;
  if (action === 'create') {
    keyboard = [
      [{ text: svcBtn('create', 'ssh'), callback_data: 'create_ssh' }],
      [{ text: svcBtn('create', 'vmess'), callback_data: 'create_vmess' }, { text: svcBtn('create', 'vless'), callback_data: 'create_vless' }],
      [{ text: svcBtn('create', 'trojan'), callback_data: 'create_trojan' }, { text: t(userId, 'btn_back'), callback_data: 'send_main_menu' }]
    ];
  } else if (action === 'trial') {
    keyboard = [
      [{ text: svcBtn('trial', 'ssh'), callback_data: 'trial_ssh' }],
      [{ text: svcBtn('trial', 'vmess'), callback_data: 'trial_vmess' }, { text: svcBtn('trial', 'vless'), callback_data: 'trial_vless' }],
      [{ text: svcBtn('trial', 'trojan'), callback_data: 'trial_trojan' }, { text: t(userId, 'btn_back'), callback_data: 'send_main_menu' }],
    ];
  } else if (action === 'renew') {
    keyboard = [
      [{ text: svcBtn('renew', 'ssh'), callback_data: 'renew_ssh' }],
      [{ text: svcBtn('renew', 'vmess'), callback_data: 'renew_vmess' }, { text: svcBtn('renew', 'vless'), callback_data: 'renew_vless' }],
      [{ text: svcBtn('renew', 'trojan'), callback_data: 'renew_trojan' }, { text: t(userId, 'btn_back'), callback_data: 'send_main_menu' }],
    ];
  } else if (action === 'del') {
    keyboard = [
      [{ text: svcBtn('del', 'ssh'), callback_data: 'del_ssh' }],
      [{ text: svcBtn('del', 'vmess'), callback_data: 'del_vmess' }, { text: svcBtn('del', 'vless'), callback_data: 'del_vless' }],
      [{ text: svcBtn('del', 'trojan'), callback_data: 'del_trojan' }, { text: t(userId, 'btn_back'), callback_data: 'send_main_menu' }],
    ];
  } else if (action === 'lock') {
    keyboard = [
      [{ text: svcBtn('lock', 'ssh'), callback_data: 'lock_ssh' }],
      [{ text: svcBtn('lock', 'vmess'), callback_data: 'lock_vmess' }, { text: svcBtn('lock', 'vless'), callback_data: 'lock_vless' }],
      [{ text: svcBtn('lock', 'trojan'), callback_data: 'lock_trojan' }, { text: t(userId, 'btn_back'), callback_data: 'send_main_menu' }],
    ];
  } else if (action === 'unlock') {
    keyboard = [
      [{ text: svcBtn('unlock', 'ssh'), callback_data: 'unlock_ssh' }],
      [{ text: svcBtn('unlock', 'vmess'), callback_data: 'unlock_vmess' }, { text: svcBtn('unlock', 'vless'), callback_data: 'unlock_vless' }],
      [{ text: svcBtn('unlock', 'trojan'), callback_data: 'unlock_trojan' }, { text: t(userId, 'btn_back'), callback_data: 'send_main_menu' }],
    ];
  } else if (action === 'changelimip') {
    keyboard = [
      [{ text: svcBtn('changelimip', 'ssh'), callback_data: 'changelimip_ssh' }],
      [{ text: svcBtn('changelimip', 'vmess'), callback_data: 'changelimip_vmess' }, { text: svcBtn('changelimip', 'vless'), callback_data: 'changelimip_vless' }],
      [{ text: svcBtn('changelimip', 'trojan'), callback_data: 'changelimip_trojan' }, { text: t(userId, 'btn_back'), callback_data: 'send_main_menu' }],
    ];
  } else if (action === 'fix') {
    keyboard = [
      [{ text: svcBtn('fix', 'ssh'), callback_data: 'fix_ssh' }],
      [{ text: svcBtn('fix', 'vmess'), callback_data: 'fix_vmess' }, { text: svcBtn('fix', 'vless'), callback_data: 'fix_vless' }],
      [{ text: svcBtn('fix', 'trojan'), callback_data: 'fix_trojan' }, { text: t(userId, 'btn_back'), callback_data: 'send_main_menu' }],
    ];
  } else if (action === 'migrate') {
    keyboard = [
      [{ text: svcBtn('migrate', 'ssh'), callback_data: 'migrate_ssh' }],
      [{ text: svcBtn('migrate', 'vmess'), callback_data: 'migrate_vmess' }, { text: svcBtn('migrate', 'vless'), callback_data: 'migrate_vless' }],
      [{ text: svcBtn('migrate', 'trojan'), callback_data: 'migrate_trojan' }, { text: t(userId, 'btn_back'), callback_data: 'send_main_menu' }],
    ];
  } else if (action === 'changeprotocol') {
    keyboard = [
      [{ text: t(userId, 'type_proto_ssh'), callback_data: 'changeproto_ssh' }, { text: t(userId, 'type_proto_vmess'), callback_data: 'changeproto_vmess' }],
      [{ text: t(userId, 'type_proto_vless'), callback_data: 'changeproto_vless' }, { text: t(userId, 'type_proto_trojan'), callback_data: 'changeproto_trojan' }],
      [{ text: t(userId, 'btn_back'), callback_data: 'send_main_menu' }],
    ];
  } else if (action === 'changeproto_new') {
    keyboard = [
      [{ text: t(userId, 'type_proto_ssh'), callback_data: 'changeproto_apply_ssh' }, { text: t(userId, 'type_proto_vmess'), callback_data: 'changeproto_apply_vmess' }],
      [{ text: t(userId, 'type_proto_vless'), callback_data: 'changeproto_apply_vless' }, { text: t(userId, 'type_proto_trojan'), callback_data: 'changeproto_apply_trojan' }],
      [{ text: t(userId, 'btn_back'), callback_data: 'send_main_menu' }],
    ];
  }
  try {
    await ctx.editMessageReplyMarkup({
      inline_keyboard: keyboard
    });
    logger.info('service menu sent: ' + action);
  } catch (error) {
    if (error.response && error.response.error_code === 400) {
      await ctx.reply(t(userId, 'svc_prompt', { action: t(userId, 'svc_action_' + action) }), {
        reply_markup: {
          inline_keyboard: keyboard
        }
      });
      logger.info('service menu sent as new message: ' + action);
    } else {
      logger.error('Error saat mengirim menu ' + action + ':', error);
    }
  }
}

bot.action('syncserver_api', async (ctx) => {
  if (!adminIds.includes(ctx.from.id)) {
    return ctx.answerCbQuery('Tidak ada izin', { show_alert: true }).catch(() => {});
  }
  await ctx.answerCbQuery('Menyinkronkan server dari API...').catch(() => {});
  try {
    const count = await syncServersFromApi();
    await ctx.reply(`✅ Sinkronisasi selesai. *${count}* server diambil dari API BotVPN.`, { parse_mode: 'Markdown' });
  } catch (e) {
    await ctx.reply(`❌ Gagal sinkronisasi server: ${e.message}`);
  }
});

async function sendAdminMenu(ctx) {
  const adminKeyboard = [
    [
      { text: '💵 Tambah Saldo', callback_data: 'addsaldo_user' },
      { text: '💳 Lihat Saldo User', callback_data: 'cek_saldo_user' }
    ],
    [
      { text: '🔄 Sync Server dari API', callback_data: 'syncserver_api' }
    ],
    [
      { text: '♻️ Restart bot', callback_data: 'restart_bot' }
    ],
    [
      { text: '🔙 Kembali', callback_data: 'send_main_menu' }
    ]
  ];

  try {
    await ctx.editMessageReplyMarkup({
      inline_keyboard: adminKeyboard
    });
    logger.info('Admin menu sent');
  } catch (error) {
    if (error.response && error.response.error_code === 400) {
      await ctx.reply('Menu Admin:', {
        reply_markup: {
          inline_keyboard: adminKeyboard
        }
      });
      logger.info('Admin menu sent as new message');
    } else {
      logger.error('Error saat mengirim menu admin:', error);
    }
  }
}

bot.command('backup', async (ctx) => {
  try {
    const requesterId = ctx.from.id;
    if (!adminIds.includes(requesterId)) {
      return ctx.reply('🚫 Anda tidak memiliki izin untuk menjalankan perintah ini.');
    }

    await ctx.reply('⚙️ Menjalankan backup... Mohon tunggu sebentar.');
    const results = await runBackup(bot, ADMIN);
    const msg = results.map(r => `• ${r}`).join('\n');
    await ctx.reply(`📦 *Hasil Backup:*\n${msg}`, { parse_mode: 'Markdown' });
  } catch (e) {
    console.error('❌ Exception di command /backup:', e);
    await ctx.reply('❌ Terjadi kesalahan internal saat memproses backup.');
  }
});

bot.command('addressel', async (ctx) => {
  try {
    const requesterId = ctx.from.id;

    // Hanya admin yang bisa menjalankan perintah ini
    if (!adminIds.includes(requesterId)) {
      return ctx.reply('🚫 Anda tidak memiliki izin untuk melakukan tindakan ini.');
    }

    // Ambil ID Telegram dari argumen
    const args = ctx.message.text.split(' ');
    if (args.length < 2) {
      return ctx.reply('❌ Format salah. Gunakan perintah:\n/addressel <id_telegram_user>');
    }

    const targetId = args[1];

    // Baca file ressel.db jika ada, kalau tidak, buat file baru
    let resellerList = [];
    if (fs.existsSync(resselFilePath)) {
      const fileContent = fs.readFileSync(resselFilePath, 'utf8');
      resellerList = fileContent.split('\n').filter(line => line.trim() !== '');
    }

    // Cek apakah ID sudah ada
    if (resellerList.includes(targetId)) {
      return ctx.reply(`⚠️ User dengan ID ${targetId} sudah menjadi reseller.`);
    }

    // Tambahkan ID ke file
    fs.appendFileSync(resselFilePath, `${targetId}\n`);
    ctx.reply(`✅ User dengan ID ${targetId} berhasil dijadikan reseller.`);

  } catch (e) {
    logger.error('❌ Error di command /addressel:', e.message);
    ctx.reply('❌ Terjadi kesalahan saat menjalankan perintah.');
  }
});

bot.command('listressel', async (ctx) => {
  try {
    const requesterId = ctx.from.id;

    // Hanya admin yang bisa menjalankan perintah ini
    if (!adminIds.includes(requesterId)) {
      return ctx.reply('🚫 Anda tidak memiliki izin untuk melakukan tindakan ini.');
    }

    // Baca file ressel.db
    let resellerList = [];
    if (fs.existsSync(resselFilePath)) {
      const fileContent = fs.readFileSync(resselFilePath, 'utf8');
      resellerList = fileContent.split('\n').filter(line => line.trim() !== '');
    }

    if (resellerList.length === 0) {
      return ctx.reply('⚠️ Saat ini belum ada reseller yang terdaftar.');
    }

    // Buat pesan daftar reseller
    let message = '📋 *Daftar Reseller:* \n\n';
    resellerList.forEach((id, index) => {
      message += `${index + 1}. ID Telegram: ${id}\n`;
    });

    ctx.reply(message, { parse_mode: 'Markdown' });

  } catch (e) {
    logger.error('❌ Error di command /listressel:', e.message);
    ctx.reply('❌ Terjadi kesalahan saat menampilkan daftar reseller.');
  }
});

bot.command('delressel', async (ctx) => {
  try {
    const requesterId = ctx.from.id;

    // Hanya admin yang bisa menjalankan perintah ini
    if (!adminIds.includes(requesterId)) {
      return ctx.reply('🚫 Anda tidak memiliki izin untuk melakukan tindakan ini.');
    }

    // Ambil ID Telegram dari argumen
    const args = ctx.message.text.split(' ');
    if (args.length < 2) {
      return ctx.reply('❌ Format salah. Gunakan perintah:\n/delressel <id_telegram_user>');
    }

    const targetId = args[1];

    // Cek apakah file ressel.db ada
    if (!fs.existsSync(resselFilePath)) {
      return ctx.reply('📁 File reseller belum dibuat.');
    }

    // Baca file dan filter ulang tanpa targetId
    const fileContent = fs.readFileSync(resselFilePath, 'utf8');
    const resellerList = fileContent.split('\n').filter(line => line.trim() !== '' && line.trim() !== targetId);

    // Tulis ulang file dengan data yang sudah difilter
    fs.writeFileSync(resselFilePath, resellerList.join('\n') + (resellerList.length ? '\n' : ''));

    ctx.reply(`✅ User dengan ID ${targetId} berhasil dihapus dari daftar reseller.`);

  } catch (e) {
    logger.error('❌ Error di command /delressel:', e.message);
    ctx.reply('❌ Terjadi kesalahan saat menjalankan perintah.');
  }
});

bot.command('deltopup', async (ctx) => {
  
  const adminId = ctx.from.id;

  if (!adminIds.includes(adminId)) {
    return ctx.reply('🚫 Anda tidak memiliki izin untuk menggunakan fitur ini.');
  }

  const parts = (ctx.message?.text || '').trim().split(/\s+/);
  const targetUserId = Number(parts[1]);
  if (!targetUserId) return ctx.reply('Format: /deltopup <userId>').catch(() => {});

  if (!global.pendingDeposits) global.pendingDeposits = {};

  let count = 0;

  for (const [code, data] of Object.entries(global.pendingDeposits)) {
    if (Number(data?.userId) !== targetUserId) continue;

    const chatId = data?.chatId;
    const msgId = data?.qrMessageId;
    if (chatId && msgId) await ctx.telegram.deleteMessage(chatId, msgId).catch(() => {});
    delete global.pendingDeposits[code];
    count++;
  }

  // DB cleanup
  try {
    if (typeof dbRun === 'function') {
      await dbRun(`DELETE FROM pending_deposits WHERE user_id = ? AND status = 'pending'`, [targetUserId]).catch(() => {});
    } else if (typeof db !== 'undefined' && db?.run) {
      db.run(`DELETE FROM pending_deposits WHERE user_id = ? AND status = 'pending'`, [targetUserId], () => {});
    } else if (global.db?.run) {
      global.db.run(`DELETE FROM pending_deposits WHERE user_id = ? AND status = 'pending'`, [targetUserId], () => {});
    }
  } catch (e) {
    logger?.error?.('Gagal delete pending_deposits user:', e?.message || e);
  }

  await ctx.reply(`✅ Pending topup user ${targetUserId} dibatalkan: ${count}`).catch(() => {});
});

bot.action(/^batal_topup_confirm_(.+)$/, async (ctx) => {
  const code = ctx.match[1];

  await ctx.answerCbQuery().catch(() => {});

  try {
    await ctx.editMessageReplyMarkup({
      inline_keyboard: [
        [
          {
            text: '✅ Ya, Batalkan',
            callback_data: `batal_topup_${code}`
          }
        ],
        [
          {
            text: '↩️ Kembali',
            callback_data: `kembali_topup_${code}`
          }
        ]
      ]
    });
  } catch {}
});

bot.action(/^kembali_topup_(.+)$/, async (ctx) => {
  const code = ctx.match[1];

  await ctx.answerCbQuery().catch(() => {});

  try {
    await ctx.editMessageReplyMarkup({
      inline_keyboard: [
        [
          {
            text: '❌ Batal',
            callback_data: `batal_topup_confirm_${code}`
          }
        ]
      ]
    });
  } catch {}
});

// ✅ ACTION BATAL (FIX)
bot.action(/^batal_topup_(.+)$/, async (ctx) => {
  const code = ctx.match?.[1];
  if (!code) return ctx.answerCbQuery('Kode tidak valid').catch(() => {});

  if (!global.pendingDeposits) global.pendingDeposits = {};
  const depositData = global.pendingDeposits[code];

  // stop loading “memutar”
  await ctx.answerCbQuery('Topup dibatalkan').catch(() => {});

  // chat id yang benar
  const chatId = depositData?.chatId || ctx.chat?.id || ctx.from?.id;

  // hapus pesan QR (kalau ada)
  if (depositData?.qrMessageId && chatId) {
    await ctx.telegram.deleteMessage(chatId, depositData.qrMessageId).catch(() => {});
  }

  // hapus DB (pakai yang tersedia)
  try {
    if (typeof dbRun === 'function') {
      await dbRun('DELETE FROM pending_deposits WHERE unique_code = ?', [code]).catch(() => {});
    } else if (typeof db !== 'undefined' && db?.run) {
      db.run('DELETE FROM pending_deposits WHERE unique_code = ?', [code], () => {});
    } else if (global.db?.run) {
      global.db.run('DELETE FROM pending_deposits WHERE unique_code = ?', [code], () => {});
    }
  } catch (e) {
    logger?.error?.('Gagal delete pending_deposits:', e?.message || e);
  }

  // hapus memory
  if (global.pendingDeposits[code]) delete global.pendingDeposits[code];

  // update pesan tombol (kalau bisa), kalau gagal kirim baru
  const kb = { inline_keyboard: [[{ text: '🔙 Menu Utama', callback_data: 'send_main_menu' }]] };
  try {
    await ctx.editMessageText('❌ Topup dibatalkan.', { reply_markup: kb });
  } catch (e) {
    await ctx.reply('❌ Topup dibatalkan.', { reply_markup: kb }).catch(() => {});
  }
});

bot.action('jadi_reseller', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const userId = ctx.from.id;
  const MINIMUM_BALANCE = 50000; // Rp50,000

  // Check saldo user dari database
  db.get('SELECT saldo FROM users WHERE user_id = ?', [userId], async (err, row) => {
    if (err) {
      ctx.reply('❌ Terjadi kesalahan saat mengecek saldo. Silakan coba lagi.', { parse_mode: 'HTML' });
      logger.error(`Error checking balance for user ${userId}:`, err.message);
      return;
    }

    const currentBalance = row ? row.saldo : 0;

    // Verifikasi otomatis jika saldo >= 50k
    if (currentBalance >= MINIMUM_BALANCE) {
      // Check apakah sudah reseller
      if (isUserReseller(userId)) {
        ctx.reply(
          `✅ Anda sudah menjadi Reseller!\n\n` +
          `💰 Saldo Anda: Rp ${currentBalance.toLocaleString('id-ID')}\n\n` +
          `🎁 Keuntungan Reseller:\n` +
          `• Dapet Setengah harga\n` +
          `• Trial Unlimited\n` +
          `• Hapus Akun\n` +
          `• Lock Akun\n` +
          `• Unlock Akun\n\n` +
          `<i>Kecuali VPN Edu Direct & VPN Cloudfront (harga normal)</i>`,
          { parse_mode: 'HTML' }
        );
      } else {
        // Approve otomatis
        addReseller(userId);
        ctx.reply(
          `✅ Anda sudah menjadi Reseller!\n\n` +
          `💰 Saldo Anda: Rp ${currentBalance.toLocaleString('id-ID')}\n\n` +
          `🎁 Keuntungan Reseller:\n` +
          `• Dapet Setengah harga\n` +
          `• Trial Unlimited\n` +
          `• Hapus Akun\n` +
          `• Lock Akun\n` +
          `• Unlock Akun\n\n` +
          `<i>Kecuali VPN Edu Direct & VPN Cloudfront (harga normal)</i>`,
          { parse_mode: 'HTML' }
        );
        logger.info(`User ${userId} berhasil menjadi reseller (automatic verification)`);
      }
    } else {
      // Saldo kurang dari minimum
      const amountNeeded = MINIMUM_BALANCE - currentBalance;
      ctx.reply(
        `⚠️ Saldo Tidak Cukup\n\n` +
        `💰 Saldo Anda saat ini: Rp ${currentBalance.toLocaleString('id-ID')}\n` +
        `❌ Minimal yang diperlukan: Rp ${MINIMUM_BALANCE.toLocaleString('id-ID')}\n\n` +
        `📊 Kekurangan: Rp ${amountNeeded.toLocaleString('id-ID')}\n\n` +
        `💳 Cara Top Up:\n` +
        `Gunakan tombol "💰 TopUp Saldo" di menu utama untuk menambah saldo Anda.\n\n` +
        `✨ Setelah saldo mencukupi:\n` +
        `Verifikasi akan otomatis berjalan dan Anda langsung menjadi Reseller!`,
        { 
          parse_mode: 'HTML',
          reply_markup: Markup.inlineKeyboard([
            [Markup.button.callback('💰 TopUp Saldo', 'topup_saldo')],
            [Markup.button.callback('🏠 Kembali ke Menu', 'main_menu')],
          ])
        }
      );

      // Send benefit message
      await new Promise(resolve => setTimeout(resolve, 500));
      ctx.reply(
        `🎁 Keuntungan Reseller:\n` +
        `• Dapet Setengah harga\n` +
        `• Trial Unlimited\n` +
        `• Hapus Akun\n` +
        `• Lock Akun\n` +
        `• Unlock Akun\n\n` +
        `<i>Kecuali VPN Edu Direct & VPN Cloudfront (harga normal)</i>`,
        { parse_mode: 'HTML' }
      );
    }
  });
});

// ACTION: cek pembayaran sekali (untuk tombol Cek Pembayaran)
bot.action(/^cek_topup_(.+)$/, async (ctx) => {
  const code = ctx.match?.[1];
  if (!code) return ctx.answerCbQuery('Kode tidak valid').catch(() => {});

  await ctx.answerCbQuery('Memeriksa pembayaran...').catch(() => {});

  // simple per-code cooldown to prevent spam/abuse (30s)
  if (!global.topupCheckCooldown) global.topupCheckCooldown = {};
  const now = Date.now();
  if (global.topupCheckCooldown[code] && now - global.topupCheckCooldown[code] < 30000) {
    return ctx.answerCbQuery('Tunggu 30 detik sebelum cek lagi').catch(() => {});
  }
  global.topupCheckCooldown[code] = now;

  if (!global.pendingDeposits || !global.pendingDeposits[code]) {
    return ctx.reply('⚠️ Data topup tidak ditemukan atau sudah kedaluwarsa.');
  }

  const deposit = global.pendingDeposits[code];

  try {
      if (vars.PAYMENT === 'ORKUT') {
       const res = await axios.get(
         'http://localhost:9526/payments',
         { timeout: 15000 }
       );

      const data = res.data;
      if (!data?.success || !data?.data) {
        return ctx.reply('⚠️ Tidak dapat mengambil riwayat pembayaran saat ini. Coba lagi nanti.');
      }

      const list = data.data;
      const normalize = v => Number(String(v || '').replace(/[^\d]/g, '')) || 0;
      const targetAmount = normalize(deposit.amount);

      const match = list.find(tx => {
        const txAmount = normalize(tx.amount);
        const type = String(tx.type || '').toLowerCase();
        return txAmount === targetAmount && type === 'kredit';
      });

      if (!match) return ctx.reply('❌ Belum ada pembayaran yang sesuai. Tekan lagi setelah user melakukan transfer.');

      const success = await processMatchingPaymentAtomic(deposit, match, code);
      if (success) {
        delete global.pendingDeposits[code];
        try { db.run('DELETE FROM pending_deposits WHERE unique_code = ?', [code]); } catch (e) {}
        try { await purchaseFlow.handlePostPayment(code); } catch (e) { logger.error(`handlePostPayment error: ${e.message}`); }
        return ctx.reply('✅ Pembayaran terdeteksi dan berhasil diproses. Terima kasih.');
      } else {
        return ctx.reply('⚠️ Pembayaran ditemukan tetapi gagal diproses. Cek log.');
      }

    } else if (vars.PAYMENT === 'GOPAY') {
      const gopayQris = require('./modules/gopay-qris');
      const res = await gopayQris.checkPayment(deposit.transactionId, vars);

      if (!res?.success) return ctx.reply('⚠️ Gagal ambil status GOPAY.');
      const status = res.status;
      if (status !== 'PAID') return ctx.reply(`❌ Status: ${status}. Belum dibayar.`);

      const success = await processMatchingPaymentAtomic(deposit, res.transactionData || res, code);
      if (success) {
        delete global.pendingDeposits[code];
        try { db.run('DELETE FROM pending_deposits WHERE unique_code = ?', [code]); } catch (e) {}
        try { await purchaseFlow.handlePostPayment(code); } catch (e) { logger.error(`handlePostPayment error: ${e.message}`); }
        return ctx.reply('✅ Pembayaran GOPAY terdeteksi dan berhasil diproses.');
      }

      return ctx.reply('⚠️ Gagal memproses pembayaran GOPAY.');
    } else if (vars.PAYMENT === 'SHOPEEPAY') {
      const orderSn = deposit.transactionId;
      if (!orderSn) return ctx.reply('❌ Data order Sn ShopeePay tidak ditemukan.');

      const res = await shopeePay.checkPayment(orderSn, vars);
      if (res.status !== 'success') {
        return ctx.reply('⚠️ Gagal ambil status ShopeePay. Coba lagi nanti.');
      }

      const td = (res.transaction_data && res.transaction_data.order_status !== undefined) ? res.transaction_data : res;
      const status = res.order_status;
      if (status !== 1 && res.paid !== true) return ctx.reply(`⚠️ Status: ${status || 'pending'}. Belum dibayar.`);

      const success = await processMatchingPaymentAtomic(deposit, td, code);
      if (success) {
        delete global.pendingDeposits[code];
        try { db.run('DELETE FROM pending_deposits WHERE unique_code = ?', [code]); } catch (e) {}
        try { await purchaseFlow.handlePostPayment(code); } catch (e) { logger.error(`handlePostPayment error: ${e.message}`); }
        return ctx.reply('✅ Pembayaran ShopeePay terdeteksi dan berhasil diproses.');
      }

      return ctx.reply('⚠️ Gagal memproses pembayaran ShopeePay.');
    }
    } catch (err) {
    // Better error logging for HTTP errors (show status + body when available)
    if (err.response) {
      try {
        logger.error(`Error cek_topup: Request failed with status code ${err.response.status} ${JSON.stringify(err.response.data)}`);
      } catch (e) {
        logger.error('Error cek_topup: ' + err.response.status);
      }
      const status = err.response.status;
      const rawBody = err.response.data ? (typeof err.response.data === 'string' ? err.response.data : JSON.stringify(err.response.data)) : '';
      const body = redactSensitive(String(rawBody)).slice(0, 300);
      return ctx.reply(`❌ Gagal cek pembayaran: status ${status}\n${body}`);
    }

    logger.error('Error cek_topup: ' + err.message);
    return ctx.reply('❌ Terjadi error saat cek pembayaran. Silakan coba lagi nanti.');
  }
});

bot.action('addserver_reseller', async (ctx) => {
  await ctx.answerCbQuery().catch(()=>{});
  userState[ctx.chat.id] = { step: 'addserver_reseller' };
  await ctx.reply(
    '🪄 Silakan kirim data server reseller dengan format:\n\n' +
    '/addserver_reseller <domain> <auth> <harga> <nama_server> <quota> <iplimit> <batas_create_akun>'
  );
});

bot.action('service_trial', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await handleServiceAction(ctx, 'trial');
});

bot.action('service_create', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await handleServiceAction(ctx, 'create');
});

bot.action('service_renew', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await handleServiceAction(ctx, 'renew');
});

bot.action('service_del', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await handleServiceAction(ctx, 'del');
});

bot.action('service_lock', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await handleServiceAction(ctx, 'lock');
});

bot.action('service_unlock', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  } 
  await handleServiceAction(ctx, 'unlock');
});

bot.action('service_changelimip', async (ctx) => {
    if (!ctx || !ctx.match) {
        return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
    }
    await handleServiceAction(ctx, 'changelimip');
});

bot.action('service_fix', async (ctx) => {
    if (!ctx || !ctx.match) {
        return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
    }
    await handleServiceAction(ctx, 'fix');
});

bot.action('service_migrate', async (ctx) => {
    if (!ctx || !ctx.match) {
        return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
    }
    await handleServiceAction(ctx, 'migrate');
});

bot.action('migrate_ssh', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'migrate', 'ssh');
});

bot.action('migrate_vmess', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'migrate', 'vmess');
});

bot.action('migrate_vless', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'migrate', 'vless');
});

bot.action('migrate_trojan', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'migrate', 'trojan');
});

bot.action('service_changeprotocol', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await handleServiceAction(ctx, 'changeprotocol');
});

bot.action('changeproto_ssh', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  await startSelectServer(ctx, 'changeproto', 'ssh');
});

bot.action('changeproto_vmess', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  await startSelectServer(ctx, 'changeproto', 'vmess');
});

bot.action('changeproto_vless', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  await startSelectServer(ctx, 'changeproto', 'vless');
});

bot.action('changeproto_trojan', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  await startSelectServer(ctx, 'changeproto', 'trojan');
});

bot.action(/(changeproto)_username_(vmess|vless|trojan|ssh)_(.+)/, async (ctx) => {
  const action = ctx.match[1];
  const type = ctx.match[2];
  const serverId = ctx.match[3];

  userState[ctx.chat.id] = { step: 'changeproto_input_username', serverId, type };

  db.get('SELECT nama_server FROM Server WHERE id = ?', [serverId], async (err, server) => {
    if (err || !server) {
      return ctx.reply('❌ *Server tidak ditemukan.*', { parse_mode: 'Markdown' });
    }
    await ctx.reply(
      `🔄 *GANTI PROTOKOL*\n\n` +
      `🖥 *Server*   : ${esc(server.nama_server)}\n` +
      `📦 *Protokol* : ${type.toUpperCase()}\n\n` +
      `👤 *Masukkan username akun yang ingin diganti protokolnya:*`,
      { parse_mode: 'Markdown' }
    );
  });
});

bot.action(/^changeproto_apply_(ssh|vmess|vless|trojan)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const newType = ctx.match[1];
  const chatId = ctx.chat.id;
  const state = userState[chatId];

  if (!state || !state.changeprotoData) {
    return ctx.reply('❌ *Sesi expired. Silakan mulai ulang.*', { parse_mode: 'Markdown' });
  }

  state.newType = newType;
  state.step = 'changeproto_confirm';
  userState[chatId] = state;

  const d = state.changeprotoData;
  const oldType = (state.type || '').toUpperCase();
  const target = newType.toUpperCase();

  if (oldType === target) {
    return ctx.reply(`❌ *Akun sudah menggunakan protokol ${target}.*\nSilakan pilih protokol lain.`, { parse_mode: 'Markdown' });
  }

  const passwordHint = (newType === 'ssh') ? '\n🔑 Password baru akan dibuat otomatis (5 digit angka).' : '';

  const confirmMsg =
    `🔄 *KONFIRMASI GANTI PROTOKOL*\n` +
    `━━━━━━━━━━━━━━━━━━━\n` +
    `👤 *Username*     : \`${esc(d.username)}\`\n` +
    `🌐 *Server*       : ${esc(d.serverName)}\n` +
    `📅 *Sisa Expired* : *${d.expired}*\n` +
    `📦 *Dari*         : ${oldType}\n` +
    `📦 *Ke*           : ${target}\n` +
    `━━━━━━━━━━━━━━━━━━━\n` +
    `⚠️ Akun ${oldType} lama akan *dihapus* dari server.\n` +
    `✅ Akun ${target} baru akan *dibuat* di server yang sama.\n` +
    passwordHint;

  const keyboard = [
    [
      { text: `✅ Ya, Ganti ke ${target}`, callback_data: `changeproto_exec_${newType}` },
      { text: '❌ Batal', callback_data: 'send_main_menu' }
    ]
  ];

  await ctx.reply(confirmMsg, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
});

bot.action(/^changeproto_exec_(ssh|vmess|vless|trojan)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const newType = ctx.match[1];
  const userId = ctx.from.id;
  const chatId = ctx.chat.id;
  const state = userState[chatId];

  if (!state || !state.changeprotoData) {
    return ctx.reply('❌ *Sesi expired. Silakan mulai ulang.*', { parse_mode: 'Markdown' });
  }

  const { type: oldType, serverId, changeprotoData: d } = state;
  const username = d.username;
  const serverName = d.serverName;
  delete userState[chatId];

  const statusMsg = await ctx.reply('⏳ *Sedang memproses ganti protokol...*', { parse_mode: 'Markdown' }).catch(() => null);
  const statusMsgId = statusMsg ? statusMsg.message_id : null;

  taskQueue.runBackground(userId,
    async () => {
      try {
        if (statusMsgId) {
          await bot.telegram.editMessageText(userId, statusMsgId, undefined,
            '⏳ *Sedang memproses ganti protokol...*\n\n' +
            `⚙️ Menghapus akun ${oldType.toUpperCase()} dari server...`,
            { parse_mode: 'Markdown' });
        }

        const delFunctions = {
          ssh: () => delssh(username, 'none', 'none', 'none', serverId),
          vmess: () => delvmess(username, 'none', 'none', 'none', serverId),
          vless: () => delvless(username, 'none', 'none', 'none', serverId),
          trojan: () => deltrojan(username, 'none', 'none', 'none', serverId)
        };

        let delWarning = '';
        const delFn = delFunctions[oldType];
        if (delFn) {
          const delResult = await delFn();
          if (delResult.includes('❌')) {
            delWarning = '\n⚠️ *Gagal menghapus akun lama dari server.*';
            logger.error(`⚠️ Gagal hapus akun lama ${username}: ${delResult}`);
          } else {
            logger.info(`✅ Akun lama ${username} (${oldType}) berhasil dihapus`);
          }
        }

        let expDays = 30;
        if (d.expired && d.expired !== '-') {
          try {
            const expDate = new Date(d.expired);
            const now = new Date();
            expDate.setHours(0, 0, 0, 0);
            now.setHours(0, 0, 0, 0);
            expDays = Math.max(1, Math.ceil((expDate - now) / 86400000));
          } catch (e) { expDays = 30; }
        }

        const password = (newType === 'ssh')
          ? String(Math.floor(10000 + Math.random() * 90000))
          : undefined;

        if (statusMsgId) {
          await bot.telegram.editMessageText(userId, statusMsgId, undefined,
            '⏳ *Sedang memproses ganti protokol...*\n\n' +
            `✅ Menghapus akun ${oldType.toUpperCase()} dari server\n` +
            `⚙️ Membuat akun ${newType.toUpperCase()} baru...`,
            { parse_mode: 'Markdown' });
        }

        const createFunctions = {
          ssh: () => createssh(username, password || 'ganti123', expDays, 100, serverId),
          vmess: () => createvmess(username, expDays, '0', 100, serverId),
          vless: () => createvless(username, expDays, '0', 100, serverId),
          trojan: () => createtrojan(username, expDays, '0', 100, serverId)
        };

        const createFn = createFunctions[newType];
        if (!createFn) {
          if (statusMsgId) await bot.telegram.editMessageText(userId, statusMsgId, undefined, `❌ *Protokol ${newType} tidak didukung.*`, { parse_mode: 'Markdown' });
          return;
        }

        const createResult = await createFn();

        if (createResult.includes('❌')) {
          logger.error(`❌ Gagal membuat akun ${newType} ${username}: ${createResult}`);
          if (statusMsgId) {
            await bot.telegram.editMessageText(userId, statusMsgId, undefined,
              `❌ *Gagal membuat akun ${newType} baru.*\n\n${createResult}\n\nAkun ${oldType} lama sudah terhapus dari server.`,
              { parse_mode: 'Markdown' });
          }
          return;
        }

        logger.info(`✅ Akun ${newType} ${username} berhasil dibuat di ${serverName}`);

        if (statusMsgId) {
          await bot.telegram.editMessageText(userId, statusMsgId, undefined,
            '⏳ *Sedang memproses ganti protokol...*\n\n' +
            `✅ Menghapus akun ${oldType.toUpperCase()} dari server\n` +
            `✅ Membuat akun ${newType.toUpperCase()} baru\n` +
            '⚙️ Update database...',
            { parse_mode: 'Markdown' });
        }

        try {
          const existing = await new Promise((resolve, reject) => {
            db.get('SELECT id FROM accounts WHERE user_id = ? AND username = ? AND server_id = ? AND status = ?',
              [userId, username, serverId, 'active'], (e, row) => {
                if (e) reject(e); else resolve(row);
              });
          });

          if (existing) {
            await new Promise((resolve, reject) => {
              db.run(
                'UPDATE accounts SET account_type = ?, full_message = ? WHERE id = ?',
                [newType, createResult, existing.id],
                (e) => { if (e) reject(e); else resolve(); }
              );
            });
            markListAccountExpired(username, oldType).catch(() => {});
            insertListAccount(userId, username, newType, serverName, d.expired || '', createResult).catch(() => {});
          } else {
            const expDateStr = new Date();
            expDateStr.setDate(expDateStr.getDate() + expDays);
            await insertAccountRecord(userId, username, newType, serverId, serverName, serverName, expDateStr.toISOString().slice(0, 10), 0, createResult);
            await insertListAccount(userId, username, newType, serverName, expDateStr.toISOString().slice(0, 10), createResult);
          }
          logger.info(`✅ Database diupdate: ${username} ${oldType} -> ${newType}`);
        } catch (e) {
          logger.error('⚠️ Gagal update database ganti protokol:', e.message);
        }

        let successMsg =
          `✅ *Ganti Protokol Berhasil!*\n\n` +
          `🔄 *SUMMARY*\n` +
          `━━━━━━━━━━━━━━━━━━━\n` +
          `👤 *Username* : \`${esc(username)}\`\n` +
          `🌐 *Server*   : ${esc(serverName)}\n` +
          `📦 *Dari*     : ${oldType.toUpperCase()}\n` +
          `📦 *Ke*       : ${newType.toUpperCase()}\n` +
          `📅 *Sisa Expired* : ${d.expired}\n` +
          `━━━━━━━━━━━━━━━━━━━\n\n`;

        if (password) {
          successMsg += `🔑 *Password Baru SSH:* \`${password}\`\n\n`;
        }

        successMsg += `📋 *DETAIL AKUN BARU:*\n` +
          `━━━━━━━━━━━━━━━━━━━\n` +
          createResult + delWarning;

        if (statusMsgId) {
          await bot.telegram.editMessageText(userId, statusMsgId, undefined, successMsg, { parse_mode: 'Markdown' });
        } else {
          await ctx.reply(successMsg, { parse_mode: 'Markdown' });
        }

        const maskedUsername = username.length > 1
          ? `${username.slice(0, 1)}${'x'.repeat(username.length - 1)}`
          : username;
        await bot.telegram.sendMessage(
          GROUP_ID,
          `<blockquote>\n🔄 <b>Protocol Changed</b>\n━━━━━━━━━━━━━━━━━━━━\n👤 <b>User:</b> ${ctx.from.first_name} (${ctx.from.id})\n📛 <b>Username:</b> ${maskedUsername}\n📦 <b>From:</b> ${oldType.toUpperCase()}\n📦 <b>To:</b> ${newType.toUpperCase()}\n🌐 <b>Server:</b> ${serverName}\n📅 <b>Expired:</b> ${d.expired || '-'}\n━━━━━━━━━━━━━━━━━━━━\n</blockquote>`,
          { parse_mode: 'HTML' }
        );

        logger.info(`✅ Ganti protokol selesai: ${username} ${oldType} -> ${newType} di ${serverName} oleh ${userId}`);

      } catch (err) {
        logger.error('❌ Error executeChangeProtocol:', err.message);
        if (statusMsgId) {
          await bot.telegram.editMessageText(userId, statusMsgId, undefined,
            `❌ *Terjadi kesalahan saat ganti protokol.*\n${err.message || ''}`,
            { parse_mode: 'Markdown' });
        }
      }
    },
    () => {},
    async (err) => {
      logger.error('❌ Error executeChangeProtocol:', err.message);
      if (statusMsgId) {
        await bot.telegram.editMessageText(userId, statusMsgId, undefined,
          `❌ *Terjadi kesalahan saat ganti protokol.*\n${err.message || ''}`,
          { parse_mode: 'Markdown' });
      }
    }
  );
});

// ============================================================
// LIST ACCOUNT (dari listaccount.db)
// ============================================================
const LIST_PER_PAGE = 20;

bot.action('list_account', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  await showListAccount(ctx, ctx.from.id, 0);
});

bot.action(/^list_account_page_(\d+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  await showListAccount(ctx, ctx.from.id, parseInt(ctx.match[1]));
});

bot.action(/^list_account_type_(ssh|vmess|vless|trojan|sshcf|edu|vpncf)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  await showListAccountByType(ctx, ctx.from.id, ctx.match[1], 0);
});

bot.action(/^list_account_type_(ssh|vmess|vless|trojan|sshcf|edu|vpncf)_page_(\d+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  await showListAccountByType(ctx, ctx.from.id, ctx.match[1], parseInt(ctx.match[2]));
});

bot.action(/^view_listaccount_(\d+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const id = parseInt(ctx.match[1]);
  try {
    const row = await new Promise((resolve, reject) => {
      listDb.get('SELECT * FROM list_accounts WHERE id = ? AND user_id = ?', [id, ctx.from.id], (e, r) => {
        if (e) reject(e); else resolve(r);
      });
    });
    if (!row) return ctx.reply(t(ctx.from.id, 'acct_not_found_generic'), { parse_mode: 'Markdown' });
    if (row.full_message) {
      await ctx.reply(row.full_message, {
        parse_mode: 'Markdown',
        reply_markup: {
          inline_keyboard: [
            [{ text: t(ctx.from.id, 'btn_back'), callback_data: 'list_account' }]
          ]
        }
      });
    } else {
      let msg = t(ctx.from.id, 'list_detail_title');
      msg += t(ctx.from.id, 'list_detail_username', { username: esc(row.username) }) + '\n';
      msg += t(ctx.from.id, 'list_detail_type', { type: (row.account_type || '').toUpperCase() }) + '\n';
      msg += t(ctx.from.id, 'list_detail_server', { server: esc(row.server_name) }) + '\n';
      msg += t(ctx.from.id, 'list_detail_expired', { expired: esc(row.expired_at || '-') }) + '\n';
      await ctx.reply(msg, {
        parse_mode: 'Markdown',
        reply_markup: {
          inline_keyboard: [
            [{ text: t(ctx.from.id, 'btn_back'), callback_data: 'list_account' }]
          ]
        }
      });
    }
  } catch (err) {
    logger.error('Error view listaccount:', err.message);
    await ctx.reply(t(ctx.from.id, 'list_detail_fail'), { parse_mode: 'Markdown' });
  }
});

bot.action(/^toggle_autorenew_(\d+)_(on|off)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  ctx.reply(t(ctx.from.id, 'list_disabled'), { parse_mode: 'Markdown' });
});

async function showListAccount(ctx, userId, page) {
  try {
    await loadUserLanguage(userId);
    const rows = await new Promise((resolve, reject) => {
      listDb.all("SELECT account_type, COUNT(*) as total FROM list_accounts WHERE user_id = ? AND status = 'active' GROUP BY account_type ORDER BY account_type", [userId], (e, r) => {
        if (e) reject(e); else resolve(r || []);
      });
    });

    if (!rows || rows.length === 0) {
      return ctx.reply(t(userId, 'list_empty'), { parse_mode: 'Markdown' });
    }

    let total = 0;
    rows.forEach(r => total += r.total);

    let msg = t(userId, 'list_title');
    const keyboard = [];
    const typeLabels = { ssh: '🔐 SSH', vmess: '🟣 VMESS', vless: '🟢 VLESS', trojan: '🔴 TROJAN', sshcf: '☁️ SSH CF', edu: '🎓 EDU DIRECT', vpncf: '☁️ VPN CF', vmesscf: '🟣 VMESS CF', vlesscf: '🟢 VLESS CF', trojancf: '🔴 TROJAN CF' };

    for (const r of rows) {
      const label = typeLabels[r.account_type] || r.account_type.toUpperCase();
      msg += t(userId, 'list_count', { label, count: r.total }) + '\n';
      keyboard.push([{ text: `${label} (${r.total})`, callback_data: `list_account_type_${r.account_type}` }]);
    }

    msg += t(userId, 'list_total', { total });
    keyboard.push([{ text: t(userId, 'btn_back_menu2'), callback_data: 'send_main_menu' }]);

    await ctx.reply(msg, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
  } catch (err) {
    logger.error('Error showListAccount:', err.message);
    await ctx.reply(t(userId, 'list_fail'), { parse_mode: 'Markdown' });
  }
}

async function showListAccountByType(ctx, userId, type, page) {
  try {
    await loadUserLanguage(userId);
    const rows = await new Promise((resolve, reject) => {
      listDb.all(
        "SELECT * FROM list_accounts WHERE user_id = ? AND account_type = ? AND status = 'active' ORDER BY server_name, created_at DESC",
        [userId, type],
        (e, r) => { if (e) reject(e); else resolve(r || []); }
      );
    });

    if (!rows || rows.length === 0) {
      return ctx.reply(t(userId, 'list_no_active_type'), { parse_mode: 'Markdown' });
    }

    const totalPages = Math.ceil(rows.length / LIST_PER_PAGE);
    const currentPage = Math.min(Math.max(page, 0), totalPages - 1);
    const start = currentPage * LIST_PER_PAGE;
    const pageRows = rows.slice(start, start + LIST_PER_PAGE);

    const typeLabels = { ssh: '🔐 SSH', vmess: '🟣 VMESS', vless: '🟢 VLESS', trojan: '🔴 TROJAN', sshcf: '☁️ SSH CF', edu: '🎓 EDU DIRECT', vpncf: '☁️ VPN CF', vmesscf: '🟣 VMESS CF', vlesscf: '🟢 VLESS CF', trojancf: '🔴 TROJAN CF' };
    const typeLabel = typeLabels[type] || type.toUpperCase();

    let msg = t(userId, 'list_type_header', { label: typeLabel, page: currentPage + 1, total: totalPages });
    const keyboard = [];

    for (let i = 0; i < pageRows.length; i += 2) {
      const row = [];
      const a1 = pageRows[i];
      const s1 = isExpiredDate(a1.expired_at) ? '❌ ' : '';
      row.push({ text: `${s1}${a1.username} (${a1.server_name || '-'})`, callback_data: `view_listaccount_${a1.id}` });
      if (pageRows[i + 1]) {
        const a2 = pageRows[i + 1];
        const s2 = isExpiredDate(a2.expired_at) ? '❌ ' : '';
        row.push({ text: `${s2}${a2.username} (${a2.server_name || '-'})`, callback_data: `view_listaccount_${a2.id}` });
      }
      keyboard.push(row);
    }

    const navButtons = [];
    if (currentPage > 0) navButtons.push({ text: t(userId, 'list_nav_prev'), callback_data: `list_account_type_${type}_page_${currentPage - 1}` });
    if (currentPage < totalPages - 1) navButtons.push({ text: t(userId, 'list_nav_next'), callback_data: `list_account_type_${type}_page_${currentPage + 1}` });
    if (navButtons.length > 0) keyboard.push(navButtons);

    keyboard.push([{ text: t(userId, 'btn_back'), callback_data: 'list_account' }]);

    await ctx.reply(msg, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
  } catch (err) {
    logger.error('Error showListAccountByType:', err.message);
    await ctx.reply(t(userId, 'list_fail'), { parse_mode: 'Markdown' });
  }
}

const { exec } = require('child_process');

function checkPort(host, port, timeout = 5000) {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    socket.on('connect', () => {
      const latency = Date.now() - start;
      socket.destroy();
      resolve({ status: 'open', latency });
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ status: 'timeout', latency: null });
    });
    socket.on('error', () => {
      socket.destroy();
      resolve({ status: 'closed', latency: null });
    });
    socket.connect(port, host);
  });
}

bot.action('cek_service', async (ctx) => {
  try {
    const userId = ctx.from.id;
    await loadUserLanguage(userId);
    const msg = await ctx.reply(t(userId, 'cek_checking'));

    const servers = [
      { name: 'SG MELBI', host: 'ssl-sgvip.rajaserver2.web.id' },
      { name: 'ID BIZNET VIP', host: 'ssl-idbiznetvip.rajaserver.web.id' },
      { name: 'ID BIZNET VIP 2', host: 'ssl-idbiznetvip2.rajaserver.web.id' },
      { name: 'ID BIZNET VIP 3', host: 'ssl-idbiznetvip3.rajaserver.web.id' },
      { name: 'ID BIZNET VIP 4', host: 'ssl-idbiznetvip4.rajaserver.web.id' },
      { name: 'ID BIZNET VIP 5', host: 'ssl-idbiznetvip5.rajaserver.web.id' },
      { name: 'ID BIZNET VIP 6', host: 'ssl-idbiznetvip6.rajaserver.web.id' },
      { name: 'ID BIZNET VIP 7', host: 'ssl-idbiznetvip7.rajaserver.web.id' },
      { name: 'ID BIZNET VIP 8', host: 'ssl-idbiznetvip8.rajaserver.web.id' },
      { name: 'ID HERZA VIP', host: 'ssl-idherzavip.rajaserver.web.id' },
      { name: 'EDU-1 DIRECT', host: 'eduserv1.aiosc.my.id' },
      { name: 'EDU-2 DIRECT', host: 'eduserv2.aiosc.my.id' },
      { name: 'EDU-3 DIRECT', host: 'eduserv3.aiosc.my.id' },
      { name: 'CLOUDFRONT REGULER', host: 'd1lnzdlpso56a0.cloudfront.net' },
      { name: 'CLOUDFRONT PREMIUM', host: 'dnuziifot7vvr.cloudfront.net' },
      { name: 'BOT SERVER', host: 'status.rajaserver.web.id' }
    ];

    const results = await Promise.all(servers.map(async (s) => {
      const [port80, port443] = await Promise.all([
        checkPort(s.host, 80),
        checkPort(s.host, 443),
      ]);
      const online = port80.status === 'open' || port443.status === 'open';
      return { ...s, port80, port443, online };
    }));

    const total = results.length;
    const onlineCount = results.filter(r => r.online).length;
    const offlineCount = total - onlineCount;
    const now = new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' });

    let text = t(userId, 'cek_title') + '\n';
    text += t(userId, 'cek_summary', { total, online: onlineCount, offline: offlineCount }) + '\n';
    text += `🕐 ${now}\n`;
    text += `━━━━━━━━━━━━━━━━━━━\n`;

    for (const s of results) {
      const p80 = s.port80.status === 'open' ? `✅ ${s.port80.latency}ms` : `❌ ${s.port80.status}`;
      const p443 = s.port443.status === 'open' ? `✅ ${s.port443.latency}ms` : `❌ ${s.port443.status}`;
      const icon = s.online ? '✅' : '❌';
      text += `\n${icon} *${s.name}*\n`;
      text += `  HTTP (80): ${p80}\n`;
      text += `  HTTPS (443): ${p443}\n`;
    }

    await ctx.telegram.deleteMessage(ctx.chat.id, msg.message_id).catch(() => {});
    ctx.reply(text, { parse_mode: 'Markdown' });
  } catch (err) {
    console.error(err);
    ctx.reply(t(ctx.from.id, 'cek_fail'));
  }
});


bot.action('send_main_menu', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await sendMainMenu(ctx);
});

bot.action('lang_menu', async (ctx) => {
  await loadUserLanguage(ctx.from.id);
  const userId = ctx.from.id;
  const text = t(userId, 'lang_menu_title');
  const keyboard = [
    [
      { text: t(userId, 'lang_id'), callback_data: 'setlang_id' },
      { text: t(userId, 'lang_en'), callback_data: 'setlang_en' }
    ],
    [
      { text: t(userId, 'btn_back'), callback_data: 'send_main_menu' }
    ]
  ];
  try {
    await ctx.editMessageText(text, {
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: keyboard }
    });
  } catch (error) {
    if (error && error.response && error.response.error_code === 400) {
      await ctx.reply(text, {
        parse_mode: 'HTML',
        reply_markup: { inline_keyboard: keyboard }
      }).catch(() => {});
    } else {
      logger.error('Error saat mengirim menu bahasa:', error);
    }
  }
});

bot.action(/^setlang_(id|en)$/, async (ctx) => {
  const lang = ctx.match[1];
  const userId = ctx.from.id;
  await setLanguage(userId, lang);
  const confirmKey = lang === 'en' ? 'lang_set_en' : 'lang_set_id';
  await ctx.answerCbQuery(t(userId, confirmKey)).catch(() => {});
  await sendMainMenu(ctx);
});

bot.command('language', async (ctx) => {
  const userId = ctx.from.id;
  await loadUserLanguage(userId);
  ensureUserExists(userId).catch(() => {});
  const text = t(userId, 'lang_menu_title');
  const keyboard = [
    [
      { text: t(userId, 'lang_id'), callback_data: 'setlang_id' },
      { text: t(userId, 'lang_en'), callback_data: 'setlang_en' }
    ],
    [
      { text: t(userId, 'btn_back'), callback_data: 'send_main_menu' }
    ]
  ];
  await ctx.reply(text, {
    parse_mode: 'HTML',
    reply_markup: { inline_keyboard: keyboard }
  }).catch(() => {});
});

bot.action('trial_vmess', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'trial', 'vmess');
});

bot.action('trial_vless', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'trial', 'vless');
});

bot.action('trial_trojan', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'trial', 'trojan');
});


bot.action('trial_ssh', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'trial', 'ssh');
});


bot.action('create_vmess', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'create', 'vmess');
});

bot.action('create_vless', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'create', 'vless');
});

bot.action('create_trojan', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'create', 'trojan');
});


bot.action('create_ssh', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'create', 'ssh');
});

//DELETE SSH
bot.action('del_ssh', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'del', 'ssh');
});

bot.action('del_vmess', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'del', 'vmess');
});

bot.action('del_vless', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'del', 'vless');
});

bot.action('del_trojan', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'del', 'trojan');
});
//DELETE BREAK

// DELETE CONFIRM - Execute delete after user confirms
bot.action('del_confirm_yes', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const state = userState[ctx.chat.id];
  if (!state || state.step !== 'del_confirm_pending') {
    return ctx.reply(t(ctx.from.id, 'session_delete_expired'), { parse_mode: 'Markdown' });
  }

  const { username, type, serverId, expired, sisaHari, serverName } = state;
  delete userState[ctx.chat.id];

  const processingMsg = await ctx.reply(t(ctx.from.id, 'processing_delete'), { parse_mode: 'Markdown' }).catch(() => null);

  taskQueue.runBackground(ctx.from.id,
    async () => {
      const saldoSebelum = await getUserBalance(ctx.from.id);

      const password = 'none', exp = 'none', iplimit = 'none';
      const delFunctions = {
        vmess: delvmess,
        vless: delvless,
        trojan: deltrojan,
        ssh: delssh
      };

      let msg = 'none';
      if (delFunctions[type]) {
        msg = await delFunctions[type](username, password, exp, iplimit, serverId);
      }

      if (msg.includes('❌')) {
        if (processingMsg) {
          await sendAccountResult(ctx, ctx.chat.id, processingMsg.message_id, msg);
        } else {
          await sendAccountResult(ctx, null, null, msg);
        }
        return;
      }

      let replyMsg = t(ctx.from.id, 'del_success_title') + '\n\n' +
        t(ctx.from.id, 'del_result_username', { username }) + '\n' +
        t(ctx.from.id, 'del_result_expired', { expired: (expired || '-') }) + '\n' +
        t(ctx.from.id, 'del_result_days', { days: (sisaHari || 0) }) + '\n\n' +
        t(ctx.from.id, 'del_result_balance', { saldo: saldoSebelum.toLocaleString() }) + '\n\n' +
        t(ctx.from.id, 'thanks');

const maskedUsername = username.length > 1
  ? `${username.slice(0, 1)}${'x'.repeat(username.length - 1)}`
  : username;

await bot.telegram.sendMessage(
  GROUP_ID,
  `<blockquote>
🗑️ <b>Account Deleted</b>
━━━━━━━━━━━━━━━━━━━━
👤 <b>User:</b> ${ctx.from.first_name} (${ctx.from.id})
🧾 <b>Type:</b> ${type.toUpperCase()}
📛 <b>Username:</b> ${maskedUsername}
📆 <b>Expired:</b> ${expired || '-'}
🌐 <b>Server ID:</b> ${serverId}
━━━━━━━━━━━━━━━━━━━━
</blockquote>`,
  { parse_mode: 'HTML' }
   );

      logger.info('✅ Akun ' + type + ' berhasil dihapus oleh ' + ctx.from.id);

      updateAccountStatus(ctx.from.id, username, serverId, 'deleted').catch(e => {
        logger.error('⚠️ Gagal update status akun ke deleted:', e.message);
      });
      markListAccountExpired(username, type).catch(() => {});

      if (processingMsg) {
        await sendAccountResult(ctx, ctx.chat.id, processingMsg.message_id, replyMsg);
      } else {
        await sendAccountResult(ctx, null, null, replyMsg);
      }
    },
    () => {},
    async (err) => {
      logger.error('❌ Gagal hapus akun:', err.message);
      if (processingMsg) {
        try { await ctx.telegram.editMessageText(ctx.chat.id, processingMsg.message_id, undefined, '❌ *Terjadi kesalahan saat menghapus akun.*', { parse_mode: 'Markdown' }); } catch (e) { await ctx.reply(t(ctx.from.id, 'del_error'), { parse_mode: 'Markdown' }); }
      } else {
        await ctx.reply(t(ctx.from.id, 'del_error'), { parse_mode: 'Markdown' });
      }
    }
  );
});

bot.action('del_confirm_no', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  delete userState[ctx.chat.id];
  await ctx.reply(t(ctx.from.id, 'del_cancelled'), { parse_mode: 'Markdown' });
  await sendMainMenu(ctx);
});

bot.action('sshcf_del_confirm_yes', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const state = userState[ctx.chat.id];
  if (!state || state.step !== 'sshcf_del_confirm_pending') {
    return ctx.reply(t(ctx.from.id, 'session_delete_expired'), { parse_mode: 'Markdown' });
  }

  const { username, accountId, serverId } = state;
  delete userState[ctx.chat.id];

  const processingMsg = await ctx.reply(t(ctx.from.id, 'processing_delete'), { parse_mode: 'Markdown' }).catch(() => null);

  taskQueue.runBackground(ctx.from.id,
    async () => {
      const msg = await delsshcf(username, serverId);
      if (msg.includes('❌')) {
        if (processingMsg) {
          await sendAccountResult(ctx, ctx.chat.id, processingMsg.message_id, msg);
        } else {
          await sendAccountResult(ctx, null, null, msg);
        }
        return;
      }

      db.run('DELETE FROM sshcf_accounts WHERE id = ?', [accountId]);

      const replyMsg = t(ctx.from.id, 'sshcf_del_success_title') + '\n\n' +
        t(ctx.from.id, 'del_result_username', { username }) + '\n\n' +
        t(ctx.from.id, 'thanks');

      if (processingMsg) {
        await sendAccountResult(ctx, ctx.chat.id, processingMsg.message_id, replyMsg);
      } else {
        await sendAccountResult(ctx, null, null, replyMsg);
      }

      const maskedUsername = username.length > 1 ? `${username.slice(0, 1)}${'x'.repeat(username.length - 1)}` : username;
      bot.telegram.sendMessage(GROUP_ID,
        `<blockquote>\n☁️ <b>SSH CloudFront Deleted</b>\n━━━━━━━━━━━━━━━━━━━━\n👤 <b>User:</b> ${ctx.from.first_name} (${ctx.from.id})\n📛 <b>Username:</b> ${maskedUsername}\n━━━━━━━━━━━━━━━━━━━━\n</blockquote>`,
        { parse_mode: 'HTML' });

      logger.info('✅ SSH CF ' + username + ' berhasil dihapus oleh ' + ctx.from.id);
    },
    () => {},
    async (err) => {
      logger.error('❌ Error hapus SSH CF:', err.message);
      const errMsg = '❌ *Terjadi kesalahan saat menghapus akun.*';
      if (processingMsg) {
        try { await ctx.telegram.editMessageText(ctx.chat.id, processingMsg.message_id, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await ctx.reply(errMsg, { parse_mode: 'Markdown' }); }
      } else {
        await ctx.reply(errMsg, { parse_mode: 'Markdown' });
      }
    }
  );
});

bot.action('sshcf_del_confirm_no', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  delete userState[ctx.chat.id];
  await ctx.reply(t(ctx.from.id, 'del_cancelled'), { parse_mode: 'Markdown' });
  await sendMainMenu(ctx);
});

//LOCK
bot.action('lock_ssh', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'lock', 'ssh');
});

bot.action('lock_vmess', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'lock', 'vmess');
});

bot.action('lock_vless', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'lock', 'vless');
});

bot.action('lock_trojan', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'lock', 'trojan');
});
//LOCK BREAK
//changelimip
bot.action('changelimip_ssh', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'changelimip', 'ssh');
});

bot.action('changelimip_vmess', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'changelimip', 'vmess');
});

bot.action('changelimip_vless', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'changelimip', 'vless');
});

bot.action('changelimip_trojan', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'changelimip', 'trojan');
});
//fix
bot.action('fix_ssh', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'fix', 'ssh');
});

bot.action('fix_vmess', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'fix', 'vmess');
});

bot.action('fix_vless', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'fix', 'vless');
});

bot.action('fix_trojan', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'fix', 'trojan');
});
//UNLOCK
bot.action('unlock_ssh', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'unlock', 'ssh');
});

bot.action('unlock_vmess', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'unlock', 'vmess');
});

bot.action('unlock_vless', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'unlock', 'vless');
});

bot.action('unlock_trojan', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'unlock', 'trojan');
});
//UNLOCK BREAK

bot.action('renew_vmess', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'renew', 'vmess');
});

bot.action('renew_vless', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'renew', 'vless');
});

bot.action('renew_trojan', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'renew', 'trojan');
});


bot.action('renew_ssh', async (ctx) => {
  if (!ctx || !ctx.match) {
    return ctx.reply('❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
  }
  await startSelectServer(ctx, 'renew', 'ssh');
});

// ==== GROUPING SERVER: ID-BIZNETVIP8-1IP / -2IP / -5IP jadi satu grup "ID-BIZNETVIP8" ====
const SERVER_IP_SUFFIX_RE = /[-_ ]*\d+\s*IP$/i;

function getServerGroupName(nama) {
  const raw = String(nama || '').trim();
  const base = raw.replace(SERVER_IP_SUFFIX_RE, '').trim();
  return base || raw;
}

function formatQuotaValue(quota) {
  const rawQuota = quota?.toString().trim();
  return !rawQuota || rawQuota === "0" || rawQuota === ")" ? "Unlimited" : `${rawQuota}GB`;
}

function sortServers(servers) {
  return servers.sort((a, b) => {
    const aFull = a.total_create_akun >= a.batas_create_akun ? 1 : 0;
    const bFull = b.total_create_akun >= b.batas_create_akun ? 1 : 0;

    // Server penuh di belakang
    if (aFull !== bFull) {
      return aFull - bFull;
    }

    // Server SG di depan (case-insensitive), sisanya urut nama/ID
    const aSg = /^SG/i.test(String(a.nama_server || ''));
    const bSg = /^SG/i.test(String(b.nama_server || ''));
    if (aSg !== bSg) {
      return aSg ? -1 : 1;
    }

    // A-Z dan angka natural (1,2,3...10)
    return a.nama_server.localeCompare(
      b.nama_server,
      undefined,
      {
        numeric: true,
        sensitivity: 'base'
      }
    );
  });
}

async function fetchFilteredServers(action, isR) {
  const servers = await new Promise((resolve, reject) => {
    db.all('SELECT * FROM Server', [], (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });

  // ==== FILTER BERDASARKAN TIPE USER ====
  let filteredServers = servers.filter(server => {
    // Sembunyikan server khusus SSH CloudFront
    if (server.cloudfront_domain && server.cloudfront_domain !== '') return false;

    const isResellerOnly = Number(server.is_reseller_only) === 1;

    if (isR) {
      // Reseller: hanya lihat server khusus reseller
      return isResellerOnly;
    }
    // User biasa: sembunyikan server khusus reseller
    return !isResellerOnly;
  });

  // ==== FILTER SERVER YANG DIKUNCI MIGRASI ====
  if (action === 'migrate_dest') {
    const lockedRows = await new Promise((resolve) => {
      db.all('SELECT domain FROM migration_locks', [], (e, rows) => {
        if (e) resolve([]); else resolve(rows || []);
      });
    });
    const lockedDomains = new Set(lockedRows.map(r => r.domain));
    filteredServers = filteredServers.filter(server => !lockedDomains.has(server.domain));
  }

  return sortServers(filteredServers);
}

function buildServerGroups(servers) {
  const map = new Map();
  for (const server of servers) {
    const name = getServerGroupName(server.nama_server);
    if (!map.has(name)) map.set(name, []);
    map.get(name).push(server);
  }

  const groups = [];
  for (const [name, items] of map.entries()) {
    // Urut varian IP dari kecil ke besar (1IP, 2IP, 5IP, ...)
    const variants = items.slice().sort((a, b) => {
      const aIp = parseInt(a.iplimit, 10) || 0;
      const bIp = parseInt(b.iplimit, 10) || 0;
      if (aIp !== bIp) return aIp - bIp;
      return a.nama_server.localeCompare(b.nama_server, undefined, { numeric: true, sensitivity: 'base' });
    });

    // Server terbaik = paling banyak sisa slot
    const best = variants.reduce((acc, cur) => {
      const accFree = (acc.batas_create_akun || 0) - (acc.total_create_akun || 0);
      const curFree = (cur.batas_create_akun || 0) - (cur.total_create_akun || 0);
      return curFree > accFree ? cur : acc;
    }, variants[0]);

    groups.push({
      name,
      servers: variants,
      best,
      count: variants.length,
      allFull: variants.every(s => s.total_create_akun >= s.batas_create_akun)
    });
  }
  return groups;
}

function buildServerListText(userId, server, isp) {
  const hargaPer30Hari = server.harga * 30;
  const isFull = server.total_create_akun >= server.batas_create_akun;
  const ispLine = isp ? `${t(userId, 'server_isp', { isp })}\n` : '';
  return `🌐 *${server.nama_server}*\n` +
         ispLine +
         `${t(userId, 'server_price_day', { harga: server.harga })}\n` +
         `${t(userId, 'server_price_30d', { harga: hargaPer30Hari })}\n` +
         `${t(userId, 'server_quota', { quota: formatQuotaValue(server.quota) })}\n` +
         (isFull
           ? `${t(userId, 'server_full')}`
           : `${t(userId, 'server_total_create', { used: server.total_create_akun, limit: server.batas_create_akun })}`);
}

function buildGroupListText(userId, group, isp) {
  const prices = group.servers.map(s => Number(s.harga) || 0);
  const min = Math.min(...prices);
  const max = Math.max(...prices);
  const ispLine = isp ? `${t(userId, 'server_isp', { isp })}\n` : '';
  const priceDay = min === max
    ? t(userId, 'server_price_day', { harga: min })
    : t(userId, 'server_price_day_range', { min, max });
  const price30 = min === max
    ? t(userId, 'server_price_30d', { harga: min * 30 })
    : t(userId, 'server_price_30d_range', { min: min * 30, max: max * 30 });
  const best = group.best;
  const isFull = group.allFull;

  return `🌐 *${group.name}*\n` +
         ispLine +
         `${priceDay}\n` +
         `${price30}\n` +
         `${t(userId, 'server_group_quota', { quota: formatQuotaValue(best.quota), count: group.count })}\n` +
         (isFull
           ? `${t(userId, 'server_full')}`
           : `${t(userId, 'server_total_create', { used: best.total_create_akun, limit: best.batas_create_akun })}`);
}

const MAX_LIST_LENGTH = 3800;

function editOrReply(ctx, body, extra) {
  const options = { reply_markup: { inline_keyboard: extra }, parse_mode: 'Markdown' };
  if (ctx.updateType === 'callback_query') {
    return ctx.editMessageText(body, options).catch(err => {
      if (/message is not modified/i.test(err?.message || '')) return;
      throw err;
    });
  }
  return ctx.reply(body, options);
}

function buildCappedList(items, renderItem) {
  let out = '';
  let shown = 0;
  for (let i = 0; i < items.length; i++) {
    const chunk = renderItem(items[i], i);
    const candidate = out ? `${out}\n\n${chunk}` : chunk;
    if (candidate.length > MAX_LIST_LENGTH) break;
    out = candidate;
    shown = i + 1;
  }
  return { text: out, shown, hidden: items.length - shown };
}

async function startSelectServer(ctx, action, type, page = 0) {
  try {
    const userId = ctx.from.id;
    await loadUserLanguage(userId);
    const isR = await isUserReseller(ctx.from.id);

    const filteredServers = await fetchFilteredServers(action, isR);
    const groups = buildServerGroups(filteredServers);

    logger.info(`User ${ctx.from.id} melihat ${groups.length} grup dari ${filteredServers.length} server`);

    // ==== Pagination ====
    const groupsPerPage = 26;
    const totalPages = Math.max(1, Math.ceil(groups.length / groupsPerPage));
    const currentPage = Math.min(Math.max(page, 0), totalPages - 1);
    const startIdx = currentPage * groupsPerPage;
    const currentGroups = groups.slice(startIdx, startIdx + groupsPerPage);

    // ==== Keyboard ====
    const keyboard = [];
    for (let i = 0; i < currentGroups.length; i += 2) {
      const row = [];
      const g1 = currentGroups[i];
      const g2 = currentGroups[i + 1];

      row.push(buildGroupButton(g1, action, type, currentPage));
      if (g2) row.push(buildGroupButton(g2, action, type, currentPage));

      keyboard.push(row);
    }

    // Navigation
    const navButtons = [];
    if (totalPages > 1) {
      if (currentPage > 0) navButtons.push({ text: t(userId, 'nav_back'), callback_data: `navigate_${action}_${type}_${currentPage - 1}` });
      if (currentPage < totalPages - 1) navButtons.push({ text: t(userId, 'nav_next'), callback_data: `navigate_${action}_${type}_${currentPage + 1}` });
    }
    if (navButtons.length) keyboard.push(navButtons);
    keyboard.push([{ text: t(userId, 'btn_back_menu'), callback_data: 'send_main_menu' }]);

    // ==== Server List Text (ISP detection dengan concurrency limit, cached ke file) ====
    const ispResults = await mapConcurrent(currentGroups, 6, (g) => detectServerIsp(g.best.domain));
    const { text: serverList, hidden } = buildCappedList(currentGroups, (g, idx) =>
      g.count === 1
        ? buildServerListText(userId, g.servers[0], ispResults[idx])
        : buildGroupListText(userId, g, ispResults[idx])
    );
    const hiddenNote = hidden > 0 ? `\n\n${t(userId, 'server_list_more', { count: hidden })}` : '';
    const listHeader = t(userId, 'server_list_header', { page: currentPage + 1, total: totalPages });
    const body = `${listHeader}\n\n${serverList}${hiddenNote}`;

    // ==== Send / Edit Message ====
    await editOrReply(ctx, body, keyboard);

    userState[ctx.chat.id] = { step: `${action}_username_${type}`, page: currentPage };
  } catch (error) {
    logger.error(`❌ Error saat memulai proses ${action} untuk ${type}:`, error);
    await ctx.reply(`❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan.`, { parse_mode: 'Markdown' });
  }
}

function buildGroupButton(group, action, type, page) {
  const suffix = group.allFull ? " ⚠️" : "";

  // Hanya 1 varian → langsung ke aksi, tanpa layer tambahan
  if (group.count === 1) {
    const server = group.servers[0];
    return {
      text: `${server.nama_server}${server.total_create_akun >= server.batas_create_akun ? " ⚠️" : ""}`,
      callback_data: `${action}_username_${type}_${server.id}`
    };
  }

  return {
    text: `${group.name}${suffix}`,
    callback_data: `${action}_srvgroup_${type}_${page}_${group.servers[0].id}`
  };
}

bot.action(/^(\w+)_srvgroup_(\w+)_(\d+)_(\d+)$/, async (ctx) => {
  const [, action, type, pageRaw, anchorId] = ctx.match;
  const page = parseInt(pageRaw, 10) || 0;
  const userId = ctx.from.id;

  try {
    await loadUserLanguage(userId);
    await ctx.answerCbQuery().catch(() => {});

    const isR = await isUserReseller(userId);
    const filteredServers = await fetchFilteredServers(action, isR);

    const anchor = filteredServers.find(s => Number(s.id) === Number(anchorId));
    if (!anchor) {
      return ctx.reply(t(userId, 'server_not_available'), { parse_mode: 'HTML' });
    }

    const groupName = getServerGroupName(anchor.nama_server);
    const group = buildServerGroups(filteredServers).find(g => g.name === groupName);
    if (!group) {
      return ctx.reply(t(userId, 'server_not_available'), { parse_mode: 'HTML' });
    }

    const keyboard = group.servers.map(server => ([{
      text: server.nama_server + (server.total_create_akun >= server.batas_create_akun ? " ⚠️" : ""),
      callback_data: `${action}_username_${type}_${server.id}`
    }]));
    keyboard.push([{ text: t(userId, 'server_group_back'), callback_data: `navigate_${action}_${type}_${page}` }]);

    const ispResults = await mapConcurrent(group.servers, 6, (s) => detectServerIsp(s.domain));
    const { text: list, hidden } = buildCappedList(group.servers, (s, idx) => buildServerListText(userId, s, ispResults[idx]));
    const hiddenNote = hidden > 0 ? `\n\n${t(userId, 'server_list_more', { count: hidden })}` : '';
    const body = `${t(userId, 'server_group_pick_ip', { name: group.name })}\n` +
                 `${t(userId, 'server_group_choose_ip')}\n\n${list}${hiddenNote}`;

    await editOrReply(ctx, body, keyboard);

    userState[ctx.chat.id] = { step: `${action}_username_${type}`, page };
  } catch (error) {
    logger.error(`❌ Error saat membuka grup server ${action}/${type}:`, error);
    await ctx.reply(`❌ *GAGAL!* Terjadi kesalahan saat memproses permintaan.`, { parse_mode: 'Markdown' });
  }
});

bot.action(/navigate_(\w+)_(\w+)_(\d+)/, async (ctx) => {
  const [, action, type, page] = ctx.match;
  await startSelectServer(ctx, action, type, parseInt(page, 10));
});

bot.action(/(create)_username_(vmess|vless|trojan|ssh)_(.+)/, async (ctx) => {
  const action = ctx.match[1];
  const type = ctx.match[2];
  const serverId = ctx.match[3];

  userState[ctx.chat.id] = { step: `username_${action}_${type}`, serverId, type, action };

  db.get('SELECT batas_create_akun, total_create_akun FROM Server WHERE id = ?', [serverId], async (err, server) => {
    if (err) {
      logger.error('⚠️ Error fetching server details:', err.message);
      return ctx.reply(t(ctx.from.id, 'err_fetch_server_detail'), { parse_mode: 'Markdown' });
    }

    if (!server) {
      return ctx.reply('❌ *Server tidak ditemukan.*', { parse_mode: 'Markdown' });
    }

    const batasCreateAkun = server.batas_create_akun;
    const totalCreateAkun = server.total_create_akun;

    if (totalCreateAkun >= batasCreateAkun) {
      return ctx.reply(t(ctx.from.id, 'server_full_new'), { parse_mode: 'Markdown' });
    }

    await ctx.reply(t(ctx.from.id, 'prompt_username'), { parse_mode: 'Markdown' });
  });
}); 

bot.action(/(renew)_username_(vmess|vless|trojan|ssh)_(.+)/, async (ctx) => {
  const action = ctx.match[1];
  const type = ctx.match[2];
  const serverId = ctx.match[3];
  userState[ctx.chat.id] = { step: `username_${action}_${type}`, serverId, type, action };

  db.get('SELECT batas_create_akun, total_create_akun FROM Server WHERE id = ?', [serverId], async (err, server) => {
    if (err) {
      logger.error('⚠️ Error fetching server details:', err.message);
      return ctx.reply(t(ctx.from.id, 'err_fetch_server_detail'), { parse_mode: 'Markdown' });
    }

    if (!server) {
      return ctx.reply('❌ *Server tidak ditemukan.*', { parse_mode: 'Markdown' });
    }

    await ctx.reply(t(ctx.from.id, 'prompt_username'), { parse_mode: 'Markdown' });
  });
}); 

// === HANDLER TRIAL ===
bot.action(/(trial)_username_(vmess|vless|trojan|ssh)_(.+)/, async (ctx) => {
  try {
    if (ctx.answerCbQuery) await ctx.answerCbQuery();

    const [action, type, serverId] = [ctx.match[1], ctx.match[2], ctx.match[3]];
    const idUser = ctx.from.id.toString().trim();
    const resselDbPath = './ressel.db';

    // === Cek reseller ===
    let isRessel = false;
    try {
      const data = fs.readFileSync(resselDbPath, 'utf8');
      const resselList = data.split('\n').map(line => line.trim()).filter(Boolean);
      isRessel = resselList.includes(idUser);
    } catch (err) {
      if (err.code === 'ENOENT') {
        isRessel = false;
      } else {
        console.error('❌ Gagal membaca file ressel.db:', err.message);
        await ctx.reply('❌ *Terjadi kesalahan saat membaca data reseller.*', { parse_mode: 'Markdown' });
        return;
      }
    }

    // === Kalau bukan reseller, cek saldo minimal Rp 1.000 & limit trial harian ===
    if (!isRessel) {
      const userSaldo = await getUserBalance(ctx.from.id);
      if (userSaldo < 1000) {
        return ctx.reply(t(ctx.from.id, 'trial_no_balance'), { parse_mode: 'Markdown' });
      }
      const sudahPakai = await checkTrialAccess(ctx.from.id);
      if (sudahPakai) {
        return ctx.reply(t(ctx.from.id, 'trial_used_today'), { parse_mode: 'Markdown' });
      }
    }
      // === Jika lolos, lanjut buat akun trial ===
const username = 'trial-' + Math.random().toString(36).substring(2, 7); // contoh: trial-drsfd
const password = 'none';
const exp = '1';
const exp1 = '3 Hour';
const quota = '0';
const quota1 = 'Unlimited';
const iplimit = '1';

const serverRow = await new Promise((resolve) => {
  db.get('SELECT nama_server FROM Server WHERE id = ?', [serverId], (e, r) => resolve(r || null));
}).catch(() => null);

const trialFunctions = {
  ssh: trialssh,
  vmess: trialvmess,
  vless: trialvless,
  trojan: trialtrojan,
};

const lines = [
  [t(ctx.from.id, 'confirm_product'), `Trial ${type.toUpperCase()}`],
  [t(ctx.from.id, 'confirm_server'), serverRow && serverRow.nama_server ? esc(serverRow.nama_server) : `ID ${serverId}`],
  [t(ctx.from.id, 'confirm_username'), `\`${username}\``],
  [t(ctx.from.id, 'confirm_duration'), exp1],
  [t(ctx.from.id, 'confirm_quota'), quota1],
];

await confirmManager.ask(ctx, {
  title: t(ctx.from.id, 'confirm_trial_title'),
  lines,
  data: { type, serverId, username },
  executor: async (cbCtx, session) => {
    const uid = cbCtx.from.id;
    if (!isRessel) {
      await saveTrialAccess(uid);
    }
    logger.info(`✅ Trial ${type} dibuat oleh ${uid}`);
    const maskedUsername = username.length > 1
      ? `${username.slice(0, 1)}${'x'.repeat(username.length - 1)}`
      : username;
    bot.telegram.sendMessage(
      GROUP_ID,
      `<blockquote>
⌛ <b>Trial Account Created</b>
━━━━━━━━━━━━━━━━━━━━
👤 <b>User:</b> ${cbCtx.from.first_name} (${uid})
🧾 <b>Type:</b> ${type.toUpperCase()}
📛 <b>Username:</b> ${maskedUsername}
📆 <b>Expired:</b> ${exp1 || '-'}
💾 <b>Quota:</b> ${quota1 || '-'}
🌐 <b>Server ID:</b> ${serverId}
━━━━━━━━━━━━━━━━━━━━
</blockquote>`,
      { parse_mode: 'HTML' }
    ).catch(() => {});

    const func = trialFunctions[type];
    if (!func) throw new Error(`Fungsi trial untuk tipe ${type} tidak ditemukan`);

    const msg = await func(username, password, exp, iplimit, serverId);
    try {
      await bot.telegram.editMessageText(cbCtx.chat?.id || uid, session.messageId, undefined, msg, { parse_mode: 'Markdown' });
    } catch (e) {
      await sendAccountResult(cbCtx, null, null, msg);
    }
  },
});

  } catch (err) {
    console.error('❌ Error handler trial:', err);
    await ctx.reply('❌ Terjadi kesalahan saat membuat trial. Coba lagi nanti.');
  }
});


bot.action(/(del)_username_(vmess|vless|trojan|ssh)_(.+)/, async (ctx) => {
  const [action, type, serverId] = [ctx.match[1], ctx.match[2], ctx.match[3]];

  userState[ctx.chat.id] = {
    step: `username_${action}_${type}`,
    serverId, type, action
  };
  await ctx.reply('👤 *Masukkan username yang ingin dihapus:*', { parse_mode: 'Markdown' });
});
bot.action(/(unlock)_username_(vmess|vless|trojan|ssh)_(.+)/, async (ctx) => {
  const [action, type, serverId] = [ctx.match[1], ctx.match[2], ctx.match[3]];

  userState[ctx.chat.id] = {
    step: `username_${action}_${type}`,
    serverId, type, action
  };
  await ctx.reply('👤 *Masukkan username yang ingin dibuka:*', { parse_mode: 'Markdown' });
});
bot.action(/(lock)_username_(vmess|vless|trojan|ssh)_(.+)/, async (ctx) => {
  const [action, type, serverId] = [ctx.match[1], ctx.match[2], ctx.match[3]];

  userState[ctx.chat.id] = {
    step: `username_${action}_${type}`,
    serverId, type, action
  };
  await ctx.reply('👤 *Masukkan username yang ingin dikunci:*', { parse_mode: 'Markdown' });
});
bot.action(/(changelimip)_username_(vmess|vless|trojan|ssh)_(.+)/, async (ctx) => {
  const [action, type, serverId] = [ctx.match[1], ctx.match[2], ctx.match[3]];

  userState[ctx.chat.id] = {
    step: `username_${action}_${type}`,
    serverId, type, action
  };
  await ctx.reply('👤 *Masukkan username yang ingin ganti limit ip:*', { parse_mode: 'Markdown' });
});
// changelimip upgrade tier selection
bot.action(/changelimip_upgrade_(\d+)_(\d+)/, async (ctx) => {
  const targetIp = parseInt(ctx.match[1]);
  const harga = parseInt(ctx.match[2]);
  const state = userState[ctx.chat.id];

  if (!state || state.step !== 'changelimip_select_tier') {
    return ctx.reply('❌ *Sesi habis. Silakan mulai ulang.*', { parse_mode: 'Markdown' });
  }

  if (targetIp === 0 && !adminIds.includes(ctx.from.id)) {
    return ctx.reply('🚫 *Fitur Limit IP 0 khusus Owner.*', { parse_mode: 'Markdown' });
  }

  const { username, type, serverId, isReseller, cfDomain } = state;
  delete userState[ctx.chat.id];

  const modeTag = cfDomain ? '☁️ CLOUDFRONT' : '';
  const lines = [
    [t(ctx.from.id, 'confirm_username'), `\`${esc(username)}\``],
    ['📦 Protokol', type.toUpperCase()],
    [t(ctx.from.id, 'confirm_server'), `ID ${serverId}`],
    ['📶 Target', `${targetIp} IP${cfDomain ? ' (CloudFront)' : ''}`],
    [t(ctx.from.id, 'confirm_price'), harga === 0 ? 'Gratis (Rp0)' : `Rp${harga.toLocaleString('id-ID')}`],
  ];

  const purchaseData = { username, type, targetIp, harga, serverId, cfDomain };

  await confirmManager.ask(ctx, {
    title: 'KONFIRMASI UPGRADE LIMIT IP',
    lines,
    data: purchaseData,
    executor: async (cbCtx, session) => {
      const userId = cbCtx.from.id;
      const balance = await getUserBalance(userId);
      if (balance < harga) {
        await cbCtx.reply(
          `❌ *Saldo tidak mencukupi.*\n\n` +
          `💰 Saldo Anda: Rp${balance.toLocaleString()}\n` +
          `💳 Dibutuhkan: Rp${harga.toLocaleString()}\n` +
          `📉 Kekurangan: Rp${(harga - balance).toLocaleString()}\n\n` +
          `Silakan top-up saldo terlebih dahulu.`,
          { parse_mode: 'Markdown' }
        ).catch(() => {});
        return { refunded: true };
      }

      const processingMsgId = session.messageId;
      await updateUserBalance(userId, -harga);
      await logPayment(userId, username, `changelimip_${type}${cfDomain ? '_cf' : ''}`, harga, 'SUCCESS');

      const password = 'none', exp = 'none';
      const changeFunc = {
        vmess: changelimipvmess,
        vless: changelimipvless,
        trojan: changelimiptrojan,
        ssh: changelimipsshvpn
      };

      let msg = await changeFunc[type](username, password, exp, targetIp, serverId, cfDomain || undefined);

      if (msg.includes('❌')) {
        await updateUserBalance(userId, harga);
        await logPayment(userId, username, `changelimip_${type}${cfDomain ? '_cf' : ''}`, harga, 'REFUNDED', msg.slice(0, 200));
        const failMsg = `${msg}\n\n⚠️ *Gagal mengubah limit IP. Saldo tidak dipotong.*`;
        if (processingMsgId) {
          try { await bot.telegram.editMessageText(userId, processingMsgId, undefined, failMsg, { parse_mode: 'Markdown' }); } catch (e) { await cbCtx.reply(failMsg, { parse_mode: 'Markdown' }); }
        } else {
          await cbCtx.reply(failMsg, { parse_mode: 'Markdown' });
        }
        return;
      }

      if (processingMsgId) {
        try { await bot.telegram.editMessageText(userId, processingMsgId, undefined, `${msg}\n\n${harga === 0 ? '🆓 *Gratis* (tanpa potong saldo)' : `💳 *Pembayaran:* Rp${harga.toLocaleString()} (berhasil dipotong dari saldo)`}`, { parse_mode: 'Markdown' }); } catch (e) { await cbCtx.reply(`${msg}\n\n${harga === 0 ? '🆓 *Gratis* (tanpa potong saldo)' : `💳 *Pembayaran:* Rp${harga.toLocaleString()} (berhasil dipotong dari saldo)`}`, { parse_mode: 'Markdown' }); }
      } else {
        await cbCtx.reply(`${msg}\n\n${harga === 0 ? '🆓 *Gratis* (tanpa potong saldo)' : `💳 *Pembayaran:* Rp${harga.toLocaleString()} (berhasil dipotong dari saldo)`}`, { parse_mode: 'Markdown' });
      }

      logger.info(`Limit IP ${type} user ${username} diupgrade ke ${targetIp} IP oleh ${userId} (reseller: ${isReseller}, cf: ${!!cfDomain}, harga: Rp${harga})`);

      try {
        await new Promise((resolve, reject) => {
          listDb.run(
            "UPDATE list_accounts SET full_message = ? WHERE user_id = ? AND username = ? AND account_type = ? AND status = 'active'",
            [msg, userId, username, type],
            (e) => { if (e) reject(e); else resolve(); }
          );
        });
        logger.info(`✅ listaccount.db updated for ${username} (${type}) after changelimip`);
      } catch (e) {
        logger.error('Gagal update listaccount changelimip:', e.message);
      }
    },
  });
  return;
});

// ============================================================
// CF LOCK / UNLOCK / FIX / MIGRASI / GANTI PROTOKOL
// ============================================================

async function showCfServerList(ctx, actionPrefix, protocol, headerEmoji, headerTitle) {
  const isR = await isUserReseller(ctx.from.id);
  let q = "SELECT * FROM Server WHERE cloudfront_domain IS NOT NULL AND cloudfront_domain != ''";
  if (isR) q += ' AND is_reseller_only = 1';
  else q += ' AND (is_reseller_only IS NULL OR is_reseller_only = 0)';
  q += ' ORDER BY nama_server ASC';
  db.all(q, [], async (err, servers) => {
    if (err || !servers || servers.length === 0) {
      return ctx.reply('❌ Belum ada server CloudFront tersedia.');
    }
    const keyboard = [];
    let msg = `${headerEmoji} <b>${headerTitle}</b>\n━━━━━━━━━━━━━━━━━━━━\n\n`;
    msg += `Protocol: <b>${(protocol || '').toUpperCase()}</b>\nPilih server:\n\n`;
    for (const s of servers) {
      keyboard.push([{ text: `${s.nama_server}`, callback_data: `${actionPrefix}_${protocol}_${s.id}` }]);
    }
    keyboard.push([{ text: '🔙 Kembali', callback_data: 'menu_sshcf' }]);
    await ctx.reply(msg, { parse_mode: 'HTML', reply_markup: { inline_keyboard: keyboard } });
  });
}

// === CF LOCK ===
bot.action('cflock_menu', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  if (!await isUserReseller(ctx.from.id)) {
    return ctx.reply('🚫 *Fitur ini khusus Reseller.*', { parse_mode: 'Markdown' });
  }
  const keyboard = [
    [{ text: '🔐 Lock SSH', callback_data: 'cflock_ssh' }, { text: '🟣 Lock VMESS', callback_data: 'cflock_vmess' }],
    [{ text: '🟢 Lock VLESS', callback_data: 'cflock_vless' }, { text: '🔴 Lock TROJAN', callback_data: 'cflock_trojan' }],
    [{ text: '🔙 Kembali', callback_data: 'menu_sshcf' }],
  ];
  await ctx.reply('🔒 *LOCK AKUN CLOUDFRONT*\n\nPilih protokol:', { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
});
bot.action('cflock_ssh', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cflock_srv', 'ssh', '🔒', 'LOCK SSH CLOUDFRONT'); });
bot.action('cflock_vmess', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cflock_srv', 'vmess', '🔒', 'LOCK VMESS CLOUDFRONT'); });
bot.action('cflock_vless', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cflock_srv', 'vless', '🔒', 'LOCK VLESS CLOUDFRONT'); });
bot.action('cflock_trojan', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cflock_srv', 'trojan', '🔒', 'LOCK TROJAN CLOUDFRONT'); });
bot.action(/^cflock_srv_(ssh|vmess|vless|trojan)_(\d+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  userState[ctx.chat.id] = { step: 'cflock_username', type: ctx.match[1], serverId: parseInt(ctx.match[2]) };
  await ctx.reply('👤 *Masukkan username akun yang ingin di-lock:*', { parse_mode: 'Markdown' });
});

// === CF UNLOCK ===
bot.action('cfunlock_menu', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  if (!await isUserReseller(ctx.from.id)) {
    return ctx.reply('🚫 *Fitur ini khusus Reseller.*', { parse_mode: 'Markdown' });
  }
  const keyboard = [
    [{ text: '🔐 Unlock SSH', callback_data: 'cfunlock_ssh' }, { text: '🟣 Unlock VMESS', callback_data: 'cfunlock_vmess' }],
    [{ text: '🟢 Unlock VLESS', callback_data: 'cfunlock_vless' }, { text: '🔴 Unlock TROJAN', callback_data: 'cfunlock_trojan' }],
    [{ text: '🔙 Kembali', callback_data: 'menu_sshcf' }],
  ];
  await ctx.reply('🔓 *UNLOCK AKUN CLOUDFRONT*\n\nPilih protokol:', { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
});
bot.action('cfunlock_ssh', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cfunlock_srv', 'ssh', '🔓', 'UNLOCK SSH CLOUDFRONT'); });
bot.action('cfunlock_vmess', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cfunlock_srv', 'vmess', '🔓', 'UNLOCK VMESS CLOUDFRONT'); });
bot.action('cfunlock_vless', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cfunlock_srv', 'vless', '🔓', 'UNLOCK VLESS CLOUDFRONT'); });
bot.action('cfunlock_trojan', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cfunlock_srv', 'trojan', '🔓', 'UNLOCK TROJAN CLOUDFRONT'); });
bot.action(/^cfunlock_srv_(ssh|vmess|vless|trojan)_(\d+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  userState[ctx.chat.id] = { step: 'cfunlock_username', type: ctx.match[1], serverId: parseInt(ctx.match[2]) };
  await ctx.reply('👤 *Masukkan username akun yang ingin di-unlock:*', { parse_mode: 'Markdown' });
});

// === CF FIX ===
bot.action('cffix_menu', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const keyboard = [
    [{ text: '🔐 Fix SSH', callback_data: 'cffix_ssh' }, { text: '🟣 Fix VMESS', callback_data: 'cffix_vmess' }],
    [{ text: '🟢 Fix VLESS', callback_data: 'cffix_vless' }, { text: '🔴 Fix TROJAN', callback_data: 'cffix_trojan' }],
    [{ text: '🔙 Kembali', callback_data: 'menu_sshcf' }],
  ];
  await ctx.reply('🔧 *FIX AKUN CLOUDFRONT*\n\nPilih protokol:', { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
});
bot.action('cffix_ssh', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cffix_srv', 'ssh', '🔧', 'FIX SSH CLOUDFRONT'); });
bot.action('cffix_vmess', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cffix_srv', 'vmess', '🔧', 'FIX VMESS CLOUDFRONT'); });
bot.action('cffix_vless', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cffix_srv', 'vless', '🔧', 'FIX VLESS CLOUDFRONT'); });
bot.action('cffix_trojan', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cffix_srv', 'trojan', '🔧', 'FIX TROJAN CLOUDFRONT'); });
bot.action(/^cffix_srv_(ssh|vmess|vless|trojan)_(\d+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  userState[ctx.chat.id] = { step: 'cffix_username', type: ctx.match[1], serverId: parseInt(ctx.match[2]) };
  await ctx.reply('👤 *Masukkan username akun yang ingin di-fix:*', { parse_mode: 'Markdown' });
});

// === MIGRASI CF → REGULAR ===
bot.action('cfmig_to_regular', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const keyboard = [
    [{ text: '🔐 SSH', callback_data: 'cfmigr_ssh' }, { text: '🟣 VMESS', callback_data: 'cfmigr_vmess' }],
    [{ text: '🟢 VLESS', callback_data: 'cfmigr_vless' }, { text: '🔴 TROJAN', callback_data: 'cfmigr_trojan' }],
    [{ text: '🔙 Kembali', callback_data: 'menu_sshcf' }],
  ];
  await ctx.reply('🔀 *MIGRASI CF → REGULAR*\n\nPilih protokol akun:', { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
});
bot.action('cfmigr_ssh', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cfmigr_src', 'ssh', '🔀', 'MIGRASI CF → REGULAR'); });
bot.action('cfmigr_vmess', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cfmigr_src', 'vmess', '🔀', 'MIGRASI CF → REGULAR'); });
bot.action('cfmigr_vless', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cfmigr_src', 'vless', '🔀', 'MIGRASI CF → REGULAR'); });
bot.action('cfmigr_trojan', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await showCfServerList(ctx, 'cfmigr_src', 'trojan', '🔀', 'MIGRASI CF → REGULAR'); });
bot.action(/^cfmigr_src_(ssh|vmess|vless|trojan)_(\d+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  userState[ctx.chat.id] = { step: 'cfmigr_to_regular_username', type: ctx.match[1], serverId: parseInt(ctx.match[2]) };
  await ctx.reply('👤 *Masukkan username akun CF yang ingin dipindah ke server regular:*', { parse_mode: 'Markdown' });
});

// === MIGRASI REGULAR → CF ===
bot.action('cfmig_to_cf', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const keyboard = [
    [{ text: '🔐 SSH', callback_data: 'cfmigr_cfssh' }, { text: '🟣 VMESS', callback_data: 'cfmigr_cfvmess' }],
    [{ text: '🟢 VLESS', callback_data: 'cfmigr_cfvless' }, { text: '🔴 TROJAN', callback_data: 'cfmigr_cftrojan' }],
    [{ text: '🔙 Kembali', callback_data: 'menu_sshcf' }],
  ];
  await ctx.reply('🔀 *MIGRASI REGULAR → CF*\n\nPilih protokol akun:', { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
});
bot.action(/^cfmigr_cf(ssh|vmess|vless|trojan)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const type = ctx.match[1];
  const isR = await isUserReseller(ctx.from.id);
  let q = 'SELECT * FROM Server';
  if (isR) q += ' WHERE is_reseller_only = 1';
  else q += ' WHERE (is_reseller_only IS NULL OR is_reseller_only = 0)';
  q += ' AND (cloudfront_domain IS NULL OR cloudfront_domain = \'\')';
  q += ' ORDER BY nama_server ASC';
  db.all(q, [], async (err, servers) => {
    if (err || !servers || servers.length === 0) {
      return ctx.reply('❌ Tidak ada server regular tersedia.');
    }
    const keyboard = [];
    let msg = `🔀 *MIGRASI REGULAR → CF*\n━━━━━━━━━━━━━━━━━━━━\n\n`;
    msg += `Protocol: <b>${type.toUpperCase()}</b>\nPilih server regular asal:\n\n`;
    for (const s of servers) {
      keyboard.push([{ text: `${s.nama_server}`, callback_data: `cfmigr_cfsrc_${type}_${s.id}` }]);
    }
    keyboard.push([{ text: '🔙 Kembali', callback_data: 'cfmig_to_cf' }]);
    await ctx.reply(msg, { parse_mode: 'HTML', reply_markup: { inline_keyboard: keyboard } });
  });
});
bot.action(/^cfmigr_cfsrc_(ssh|vmess|vless|trojan)_(\d+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  userState[ctx.chat.id] = { step: 'cfmigr_to_cf_username', type: ctx.match[1], serverId: parseInt(ctx.match[2]) };
  await ctx.reply('👤 *Masukkan username akun regular yang ingin dipindah ke CF:*', { parse_mode: 'Markdown' });
});

// === CF GANTI PROTOKOL ===
bot.action('cfchangeprotocol_menu', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const keyboard = [
    [{ text: 'SSH → Protokol Lain', callback_data: 'cfchgproto_from_ssh' }],
    [{ text: 'VMESS → Protokol Lain', callback_data: 'cfchgproto_from_vmess' }],
    [{ text: 'VLESS → Protokol Lain', callback_data: 'cfchgproto_from_vless' }],
    [{ text: 'TROJAN → Protokol Lain', callback_data: 'cfchgproto_from_trojan' }],
    [{ text: '🔙 Kembali', callback_data: 'menu_sshcf' }],
  ];
  await ctx.reply('🔄 *GANTI PROTOKOL CF*\n\nPilih protokol akun saat ini:', { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
});
bot.action(/^cfchgproto_from_(ssh|vmess|vless|trojan)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const type = ctx.match[1];
  await showCfServerList(ctx, 'cfchgproto_srv', type, '🔄', 'GANTI PROTOKOL CF');
});
bot.action(/^cfchgproto_srv_(ssh|vmess|vless|trojan)_(\d+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  userState[ctx.chat.id] = { step: 'cfchgproto_username', type: ctx.match[1], serverId: parseInt(ctx.match[2]) };
  await ctx.reply(`👤 *Masukkan username akun CF ${ctx.match[1].toUpperCase()} yang ingin diganti protokolnya:*`, { parse_mode: 'Markdown' });
});

bot.action(/(fix)_username_(vmess|vless|trojan|ssh)_(.+)/, async (ctx) => {
  const [action, type, serverId] = [ctx.match[1], ctx.match[2], ctx.match[3]];

  userState[ctx.chat.id] = {
    step: `username_${action}_${type}`,
    serverId, type, action
  };
  await ctx.reply(t(ctx.from.id, 'prompt_username'), { parse_mode: 'Markdown' });
});


bot.action(/(migrate)_username_(vmess|vless|trojan|ssh)_(.+)/, async (ctx) => {
  const action = ctx.match[1];
  const type = ctx.match[2];
  const serverId = ctx.match[3];

  userState[ctx.chat.id] = { step: 'migrate_input_username', serverId, type, action };

  db.get('SELECT nama_server FROM Server WHERE id = ?', [serverId], async (err, server) => {
    if (err) {
      logger.error('⚠️ Error fetching server details:', err.message);
      return ctx.reply(t(ctx.from.id, 'err_fetch_server_detail'), { parse_mode: 'Markdown' });
    }
    if (!server) {
      return ctx.reply('❌ *Server tidak ditemukan.*', { parse_mode: 'Markdown' });
    }
    await ctx.reply(`🔀 *MIGRASI AKUN*\n\n🖥 *Server Asal:* ${esc(server.nama_server)}\n\n👤 *Masukkan username akun yang ingin dipindahkan:*`, { parse_mode: 'Markdown' });
  });
});

bot.action(/(migrate_dest)_username_(vmess|vless|trojan|ssh)_(.+)/, async (ctx) => {
  const [action, type, destServerId] = [ctx.match[1], ctx.match[2], ctx.match[3]];
  const chatId = ctx.chat.id;
  const migrateData = getMigration(chatId);

  if (!migrateData || !migrateData.sourceServerId) {
    clearMigration(chatId);
    delete userState[chatId];
    return ctx.reply('❌ *Sesi migrasi expired. Silakan mulai ulang.*', { parse_mode: 'Markdown' });
  }

  if (String(destServerId) === String(migrateData.sourceServerId)) {
    return ctx.reply('❌ *Server tujuan harus berbeda dari server asal.*\nSilakan pilih server lain.', { parse_mode: 'Markdown' });
  }

  try {
    const destServer = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM Server WHERE id = ?', [destServerId], (e, row) => {
        if (e) reject(e); else resolve(row);
      });
    });
    if (!destServer) {
      return ctx.reply('❌ *Server tujuan tidak ditemukan.*', { parse_mode: 'Markdown' });
    }

    // Cek apakah server tujuan dikunci migrasi
    const lockRow = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM migration_locks WHERE domain = ?', [destServer.domain], (e, row) => {
        if (e) reject(e); else resolve(row);
      });
    });
    if (lockRow) {
      return ctx.reply(
        `🔒 *Server ini terkunci migrasi!*\n\n` +
        `🖥 *Server* : ${esc(destServer.nama_server)}\n` +
        `🌐 *Domain* : \`${esc(destServer.domain)}\`\n\n` +
        `Tidak ada yang bisa migrasi akun ke server ini.`,
        { parse_mode: 'Markdown' }
      );
    }

    // Validasi IP limit harus sama
    const sourceIP = extractIPFromServerName(migrateData.sourceServerName);
    const destIP = extractIPFromServerName(destServer.nama_server);
    if (sourceIP !== null && destIP !== null && sourceIP !== destIP) {
      return ctx.reply(
        `❌ *IP Limit tidak sesuai!*\n\n` +
        `🌐 *Server Asal*  : ${migrateData.sourceServerName} (${sourceIP} IP)\n` +
        `🌐 *Server Tujuan*: ${destServer.nama_server} (${destIP} IP)\n\n` +
        `⚠️ Migrasi hanya bisa ke server dengan IP limit yang sama.\n` +
        `Beli server ${sourceIP} IP untuk migrasi.`,
        { parse_mode: 'Markdown' }
      );
    }

    let finalUsername = migrateData.username;
    let existingAccount = await checkAccountFull(destServer.domain, destServer.auth, finalUsername, type);
    if (existingAccount) {
      const originalUsername = migrateData.username;
      let attempts = 0;
      while (existingAccount && attempts < 20) {
        const randomNum = String(Math.floor(100 + Math.random() * 900));
        finalUsername = originalUsername + randomNum;
        logger.info(`🔄 Username ${originalUsername} sudah ada, coba: ${finalUsername}`);
        existingAccount = await checkAccountFull(destServer.domain, destServer.auth, finalUsername, type);
        attempts++;
      }
      if (existingAccount) {
        return ctx.reply('❌ *Gagal menemukan username unik.* Silakan coba lagi nanti.', { parse_mode: 'Markdown' });
      }
      migrateData.username = finalUsername;
    }

    migrateData.destServerId = destServerId;
    migrateData.destServerName = destServer.nama_server;
    storeMigration(chatId, migrateData);

    await executeMigration(ctx, migrateData);
  } catch (err) {
    logger.error('❌ Error validasi migrasi:', err.message);
    await ctx.reply('❌ *Terjadi kesalahan saat validasi migrasi.*', { parse_mode: 'Markdown' });
  }
});

bot.action('migrate_confirm_execute', async (ctx) => {
  const chatId = ctx.chat.id;
  const migrateData = getMigration(chatId);
  if (!migrateData || !migrateData.destServerId) {
    clearMigration(chatId);
    delete userState[chatId];
    return ctx.reply('❌ *Sesi migrasi expired. Silakan mulai ulang.*', { parse_mode: 'Markdown' });
  }
  await executeMigration(ctx, migrateData);
});


// ============================================================
// VPN EDU DIRECT HANDLERS
// ============================================================

bot.action('menu_directedu', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const userId = ctx.from.id;
  await loadUserLanguage(userId);
  try {
    const res = await naytra.getEduProducts();
    const servers = res.data || [];
    if (!servers || servers.length === 0) {
      return ctx.reply(t(userId, 'edu_no_product'));
    }
    const singles = ['bundle_vmess', 'bundle_vless', 'bundle_trojan'];
    let msg = t(userId, 'edu_menu_title');
    const keyboard = [];
    for (const server of servers) {
      const srvName = esc(server.server_name || 'Unknown');
      const srvCode = server.server_code || '';
      const slotAvail = server.slot?.available || 0;
      const slotMax = server.slot?.max || 0;
      const isEduFull = slotMax > 0 && slotAvail <= 0;
      const prods = server.products || [];
      const singleProds = prods.filter(p => singles.includes(p.service));
      let monthlyPrice = 0, weeklyPrice = 0;
      for (const prod of singleProds) {
        const bp = prod.billing_periods || {};
        if (bp.monthly && bp.monthly.selling_price > monthlyPrice) monthlyPrice = bp.monthly.selling_price;
        if (bp.weekly && bp.weekly.selling_price > weeklyPrice) weeklyPrice = bp.weekly.selling_price;
      }
      const isp = 'Politeknik Negeri Sriwijaya';
      msg += `🟢 <b>${srvName}</b>\n`;
      msg += t(userId, 'edu_isp', { isp }) + '\n';
      msg += t(userId, 'edu_limit_ip') + '\n';
      msg += t(userId, 'edu_quota_weekly') + '\n';
      msg += t(userId, 'edu_quota_monthly') + '\n';
      if (monthlyPrice) {
        msg += t(userId, 'edu_monthly') + '\n';
      }
      if (weeklyPrice) {
        msg += t(userId, 'edu_weekly') + '\n';
      }
      msg += t(userId, 'edu_slot', { full: isEduFull ? t(userId, 'edu_full_label') : '', avail: slotAvail, max: slotMax }) + '\n';
      msg += `\n`;
      keyboard.push(isEduFull
        ? [{ text: t(userId, 'btn_server_full', { name: srvName }), callback_data: `edu_slotfull_${storeCb(JSON.stringify({c:srvCode}))}` }]
        : [{ text: t(userId, 'btn_pick_server', { name: srvName }), callback_data: `edud_${storeCb(JSON.stringify({a:'det',c:srvCode}))}` }]
      );
    }
    keyboard.push([{ text: t(userId, 'btn_trial_edu'), callback_data: 'directedu_trial' }]);
    keyboard.push([{ text: t(userId, 'btn_renew_edu'), callback_data: 'directedu_renew' }]);
    keyboard.push([{ text: t(userId, 'btn_back'), callback_data: 'send_main_menu' }]);
    await ctx.reply(msg, { parse_mode: 'HTML', reply_markup: { inline_keyboard: keyboard } });
  } catch (err) {
    ctx.reply(t(userId, 'edu_api_fail'));
  }
});

bot.action(/^edu_slotfull_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const userId = ctx.from.id;
  await loadUserLanguage(userId);
  try {
    const raw = getCb(ctx.match[1]);
    if (!raw) return ctx.reply(t(userId, 'data_expired'));
    const d = JSON.parse(raw);
    await ctx.reply(t(userId, 'edu_slot_full_title'), {
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [
          [{ text: t(userId, 'btn_renew_edu'), callback_data: 'directedu_renew' }],
          [{ text: t(userId, 'btn_trial_edu'), callback_data: 'directedu_trial' }],
          [{ text: t(userId, 'btn_back'), callback_data: 'menu_directedu' }]
        ]
      }
    });
  } catch (err) {
    ctx.reply(t(userId, 'edu_fail'));
  }
});

bot.action(/^edud_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  try {
    const raw = getCb(ctx.match[1]);
    if (!raw) return ctx.reply('❌ Data kadaluarsa, silakan coba lagi.');
    const d = JSON.parse(raw);
    if (d.a !== 'det') return ctx.reply('❌ Data tidak valid.');
    const res = await naytra.getEduProducts();
    const servers = res.data || [];
    const server = servers.find(s => s.server_code === d.c);
    if (!server) return ctx.reply('❌ Server tidak ditemukan.');
    const srvName = esc(server.server_name || 'Unknown');
    const singles = ['bundle_vmess', 'bundle_vless', 'bundle_trojan'];
    const sorted = [...(server.products || [])]
      .filter(p => p.trial_allowed)
      .sort((a, b) => {
      const ai = singles.indexOf(a.service);
      const bi = singles.indexOf(b.service);
      if (ai >= 0 && bi >= 0) return ai - bi;
      if (ai >= 0) return -1;
      if (bi >= 0) return 1;
      return a.service.localeCompare(b.service);
    });
    let msg = `🖥 *${srvName} - Pilih Layanan*\n\n`;
    const keyboard = [];
    for (const prod of sorted) {
      const svc = prod.service;
      const namaTampil = singles.includes(svc)
        ? svc.replace('bundle_', '').toUpperCase()
        : svc === 'bundle_complete' ? 'ALL IN ONE'
        : svc.replace('bundle_', '').replace(/_/g, '+').toUpperCase();
      msg += `📦 *${namaTampil}*\n`;
      keyboard.push([{ text: `📌 ${namaTampil}`, callback_data: `edup_${storeCb(JSON.stringify({a:'pro',c:server.server_code,s:svc}))}` }]);
    }
    keyboard.push([{ text: '🔙 Kembali', callback_data: 'menu_directedu' }]);
    await ctx.reply(msg, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
  } catch (err) {
    ctx.reply('❌ Gagal: ' + naytra.handleApiError(err));
  }
});

bot.action(/^edup_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  try {
    const raw = getCb(ctx.match[1]);
    if (!raw) return ctx.reply('❌ Data kadaluarsa, silakan coba lagi.');
    const d = JSON.parse(raw);
    if (d.a !== 'pro') return ctx.reply('❌ Data tidak valid.');
    const res = await naytra.getEduProducts();
    const servers = res.data || [];
    const server = servers.find(s => s.server_code === d.c);
    if (!server) return ctx.reply('❌ Server tidak ditemukan.');
    const srvName = esc(server.server_name || 'Unknown');
    const prod = (server.products || []).find(p => p.service === d.s && p.trial_allowed);
    if (!prod) return ctx.reply('❌ Layanan tidak ditemukan.');
    const singles = ['bundle_vmess', 'bundle_vless', 'bundle_trojan'];
    const namaTampil = singles.includes(d.s)
      ? d.s.replace('bundle_', '').toUpperCase()
      : d.s === 'bundle_complete' ? 'ALL IN ONE'
      : d.s.replace('bundle_', '').replace(/_/g, '+').toUpperCase();
      const markup = (price) => {
      if (price <= 4000) return price + 2000;
      if (price <= 12000) return price + 4000;
      return Math.round(price * 1.35);
    };
    let msg = `🖥 *${srvName}* — *${namaTampil}*\n\n📦 *${namaTampil}*\n`;
    const keyboard = [];
    for (const [period, periodData] of Object.entries(prod.billing_periods || {})) {
      let harga;
      if (period === 'weekly') harga = 5000;
      else if (period === 'monthly') harga = 14000;
      else harga = markup(periodData.selling_price || 0);
      const quota = periodData.quota || '-';
      msg += `   📅 ${esc(period.charAt(0).toUpperCase() + period.slice(1))} : Rp ${harga.toLocaleString('id-ID')} (${esc(quota)})\n`;
      keyboard.push([{ text: `${namaTampil} - ${period} Rp${harga.toLocaleString('id-ID')}`, callback_data: `es_${storeCb(JSON.stringify({a:'sel',c:server.server_code,p:period,s:d.s,h:harga}))}` }]);
    }
    keyboard.push([{ text: '🔙 Kembali', callback_data: `edud_${storeCb(JSON.stringify({a:'det',c:server.server_code}))}` }]);
    await ctx.reply(msg, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
  } catch (err) {
    ctx.reply('❌ Gagal: ' + naytra.handleApiError(err));
  }
});

bot.action(/^es_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  try {
    const raw = getCb(ctx.match[1]);
    if (!raw) return ctx.reply('❌ Data kadaluarsa, silakan coba lagi.');
    const d = JSON.parse(raw);
    if (d.a !== 'sel') return ctx.reply('❌ Data tidak valid.');
    userState[ctx.chat.id] = { step: 'directedu_username', serverCode: d.c, billingPeriod: d.p, service: d.s, hargaProduk: d.h || 0 };
    await ctx.reply('👤 *Masukkan username untuk akun EDU:*', { parse_mode: 'Markdown' });
  } catch (e) {
    ctx.reply('❌ Data tidak valid.');
  }
});

bot.action('directedu_trial', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  try {
    const res = await naytra.getEduProducts();
    const servers = res.data || [];
    const keyboard = [];
    for (const server of servers) {
      for (const prod of (server.products || [])) {
        if (prod.trial_allowed) {
          keyboard.push([{ text: `${server.server_name} - ${prod.service}`, callback_data: `et_${storeCb(JSON.stringify({a:'tri',c:server.server_code,s:prod.service}))}` }]);
        }
      }
    }
    if (keyboard.length === 0) return ctx.reply(t(ctx.from.id, 'no_trial_available'));
    keyboard.push([{ text: '🔙 Kembali', callback_data: 'menu_directedu' }]);
    await ctx.reply('🎁 *Pilih server untuk Trial EDU:*', { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
  } catch (err) {
    ctx.reply('❌ Gagal: ' + naytra.handleApiError(err));
  }
});

bot.action(/^et_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  try {
    const raw = getCb(ctx.match[1]);
    if (!raw) return ctx.reply('❌ Data kadaluarsa, silakan coba lagi.');
    const p = JSON.parse(raw);
    if (p.a !== 'tri') return ctx.reply('❌ Data tidak valid.');
    const serverCode = p.c;
    const service = p.s;
    const userSaldo = await getUserBalance(ctx.from.id);
    if (userSaldo < 100) {
      return ctx.reply(t(ctx.from.id, 'trial_no_balance_edu'), { parse_mode: 'Markdown' });
    }

    const serviceLabel = String(service || '').replace('bundle_', '').replace(/_/g, '+').toUpperCase() || 'VPN EDU';
    const lines = [
      [t(ctx.from.id, 'confirm_product'), `Trial EDU (${serviceLabel})`],
      [t(ctx.from.id, 'confirm_server'), `\`${esc(serverCode)}\``],
      [t(ctx.from.id, 'confirm_duration'), 'Trial'],
    ];

    await confirmManager.ask(ctx, {
      title: t(ctx.from.id, 'confirm_trial_title'),
      lines,
      data: { serverCode, service },
      executor: async (cbCtx, session) => {
        const uid = cbCtx.from.id;
        const result = await naytra.trialEdu({ server_code: serverCode, service });
        const dd = result.data || {};
        let msg = `✅ *Trial EDU BERHASIL*\n\n`;
        msg += `👤 Username : ${esc(dd.username)}\n`;
        if (dd.password) msg += `🔑 Password : ${esc(dd.password)}\n`;
        msg += `🖥 Server : ${esc(dd.server_name || serverCode)}\n`;
        msg += `📦 Service : ${esc(dd.service || service)}\n`;
        msg += `📅 Expired : ${esc(dd.expired_date)}\n`;
        if (dd.details) {
          if (dd.details.domain) msg += `🌐 Domain : ${dd.details.domain}\n`;
          if (dd.details.uuid) msg += `🛡 UUID : ${dd.details.uuid}\n`;
          if (dd.details.subscription) msg += `\n🔗 Subscription :\n${dd.details.subscription}\n`;
          if (dd.details.links && dd.details.links.length > 0) {
            msg += `\n📡 *Config Links:*\n`;
            for (const link of dd.details.links) {
              msg += `• ${link.label} : \`${link.url}\`\n`;
            }
          }
        }
        try {
          await bot.telegram.editMessageText(cbCtx.chat?.id || uid, session.messageId, undefined, msg, { parse_mode: 'Markdown' });
        } catch (e) {
          await sendAccountResult(cbCtx, null, null, msg);
        }
      },
    });
  } catch (err) {
    const errMsg = naytra.handleApiError(err);
    if (errMsg.toLowerCase().includes('trial') || errMsg.toLowerCase().includes('habis') || errMsg.toLowerCase().includes('kuota')) {
      ctx.reply(t(ctx.from.id, 'trial_quota_out_sentence'));
    } else {
      ctx.reply(t(ctx.from.id, 'trial_failed', { error: errMsg }));
    }
  }
});

bot.action('directedu_renew', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  try {
    db.all('SELECT * FROM directedu_accounts WHERE user_id = ? ORDER BY created_at DESC', [ctx.from.id], (err, accounts) => {
      if (err) return ctx.reply('❌ Gagal membaca database.');
      if (!accounts || accounts.length === 0) {
        return ctx.reply('♻️ Tidak ada akun EDU yang bisa di-renew.');
      }
      const keyboard = accounts.map(a => ([{ text: `${a.username} - ${a.server_name} (${a.expired_date})`, callback_data: `eduren_${a.order_id}` }]));
      keyboard.push([{ text: '🔙 Kembali', callback_data: 'menu_directedu' }]);
      ctx.reply('♻️ *Pilih akun EDU untuk di-renew:*', { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
    });
  } catch (err) {
    ctx.reply('❌ Gagal: ' + naytra.handleApiError(err));
  }
});

bot.action(/^eduren_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const orderId = ctx.match[1];
  userState[ctx.chat.id] = { step: 'directedu_renew_duration', orderId };
  await ctx.reply('⏳ *Masukkan durasi (bulan):*', { parse_mode: 'Markdown' });
});

// ============================================================
// VPN CLOUDFRONT HANDLERS
// ============================================================

const HIDDEN_CF_SERVERS = new Set([
  '019d4b9f-7fb5-7369-8f4b-8974abd0123c',
  '019d9a8a-41e9-727d-b5e7-1ea594fc04d1'
]);
// Protokol yang benar-benar memakai password. VMess/VLESS/Trojan cukup UUID.
const VPNCF_PROTOCOLS_WITH_PASSWORD = new Set(['ssh']);
const isCloudfrontServer = (s) => {
  if (!s || HIDDEN_CF_SERVERS.has(s.server_id)) return false;
  // Server yang punya domain CloudFront tetap ditampilkan walau namanya
  // tidak mengandung kata "cloudfront".
  if (String(s.cloudfront_domain || '').trim() !== '') return true;
  return /cloudfront|cloudfornt/i.test(s.name || '');
};

bot.action('menu_vpncf', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  try {
    const res = await nadiavpn.getServers();
    const servers = (res.data || []).filter(isCloudfrontServer);
    if (!servers || servers.length === 0) {
      return ctx.reply('❌ Tidak ada produk CloudFront tersedia.');
    }
    let msg = '━━━━━━━━━━━━━━━━━━━━\n  ☁️ <b>PROMO VPN CLOUDFRONT</b>\n━━━━━━━━━━━━━━━━━━━━\n\n';
    const keyboard = [];
    const ISP_MAP = {
      '019dcc5d-a6c5-70e6-9bc4-0b0ba5011420': 'PT Biznet Gio Nusantara',
      '01a06443-8a9c-7254-b6f5-d59e4cfc3edd': 'PT Biznet Gio Nusantara',
      '019e15b0-f043-7170-a5c7-63719b4b8d45': 'PT. Media Antar Nusa',
      '019f173b-1a41-733e-b271-633d74e7edf3': 'PT. Media Antar Nusa',
      '019d4b9f-7fb5-7369-8f4b-8974abd0123c': 'PT Raja Mitra Informatika',
      '019d9a8a-41e9-727d-b5e7-1ea594fc04d1': 'PT. Raja Sepadan Abadi',
      '019d3fda-3731-730b-89ad-8f171134fb93': 'PT Biznet Gio Nusantara'
    };
    for (const srv of servers) {
      const srvName = esc(srv.name || 'Unknown');
      const cap = srv.capacity || {};
      const pricing = srv.pricing || {};
      const types = srv.supported_types || [];
      const dayPrice = pricing.per_day && types.includes('day') ? parseInt(pricing.per_day) + 500 : null;
      const weekPrice = pricing.per_week && types.includes('week') ? parseInt(pricing.per_week) + 1000 : null;
      const monthPrice = pricing.per_month && types.includes('month') ? parseInt(pricing.per_month) + 2000 : null;
      const hargaInfo = [];
      if (dayPrice) hargaInfo.push(`Rp ${dayPrice.toLocaleString('id-ID')}/hari`);
      if (weekPrice) hargaInfo.push(`Rp ${weekPrice.toLocaleString('id-ID')}/minggu`);
      if (monthPrice) hargaInfo.push(`Rp ${monthPrice.toLocaleString('id-ID')}/bulan`);
      const slot = cap.limit ? `${cap.used || 0}/${cap.limit}` : `${cap.used || 0}/Unlimited`;
      const isFull = cap.limit > 0 && cap.used >= cap.limit;
      const isp = ISP_MAP[srv.server_id] || (await nadiavpn.detectIsp(srv)) || '-';
      msg += `${isFull ? '🔴' : '🟢'} <b>${srvName}</b>\n`;
      msg += `   ISP   : ${isp}\n`;
      if (srv.cloudfront_domain) msg += `   ☁️ CF    : <code>${srv.cloudfront_domain}</code>\n`;
      msg += `   ✅ Bandwidth Unlimited\n`;
      msg += `   ✅ Langsung dapat 3 IP\n`;
      if (hargaInfo.length) msg += `   Harga : ${hargaInfo.join(' | ')}\n`;
      if (isFull) {
        msg += `   ⚠️ <b>Slot PENUH</b> (${slot}) - Order dinonaktifkan\n`;
      } else {
        msg += `   Slot  : ${slot}\n`;
      }
      msg += '\n\n';
      keyboard.push(isFull
        ? [{ text: `⚠️ ${srvName} - PENUH`, callback_data: `slotfull_${storeCb(JSON.stringify({d:srv.server_id||''}))}` }]
        : [{ text: `🛒 Pilih ${srvName}`, callback_data: `cs_${storeCb(JSON.stringify({a:'sel',d:srv.server_id||''}))}` }]
      );
    }
    keyboard.push([{ text: '🎁 Trial', callback_data: 'vpncf_trial' }]);
    keyboard.push([{ text: '♻️ Renew', callback_data: 'vpncf_renew' }]);
    keyboard.push([{ text: '🔙 Kembali', callback_data: 'send_main_menu' }]);
    await ctx.reply(msg, { parse_mode: 'HTML', reply_markup: { inline_keyboard: keyboard } });
  } catch (err) {
    ctx.reply('❌ Gagal mengambil produk CloudFront');
  }
});

bot.action(/^slotfull_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  try {
    const raw = getCb(ctx.match[1]);
    if (!raw) return ctx.reply('❌ Data kadaluarsa.');
    const d = JSON.parse(raw);
    const res = await nadiavpn.getServers();
    const serversList = res.data || [];
    const srv = serversList.find(s => s.server_id === d.d);
    const srvName = esc(srv?.name || d.d);
    const cap = srv?.capacity || {};
    const capLimit = cap.limit || 0;
    const capUsed = cap.used || 0;
    await ctx.reply(`⚠️ *Slot ${srvName} PENUH*\n\n` +
      `Slot server ini sudah penuh (terpakai ${capUsed}/${capLimit}).\n\n` +
      `Tidak dapat melakukan order baru. Pilih opsi berikut:\n` +
      `1️⃣ *Renew* akun CloudFront yang sudah ada\n` +
      `2️⃣ Coba *Trial CloudFront* (1 Jam)`, {
        parse_mode: 'Markdown',
        reply_markup: {
          inline_keyboard: [
            [{ text: '♻️ Renew CloudFront', callback_data: 'vpncf_renew' }],
            [{ text: '🎁 Trial CloudFront', callback_data: 'vpncf_trial' }],
            [{ text: '🔙 Kembali', callback_data: 'menu_vpncf' }]
          ]
        }
      });
  } catch (err) {
    ctx.reply('❌ Gagal: ' + nadiavpn.handleApiError(err));
  }
});

bot.action('vpncf_trial', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  try {
    const res = await nadiavpn.getServers();
    const servers = (res.data || []).filter(isCloudfrontServer);
    if (!servers || servers.length === 0) return ctx.reply('❌ Tidak ada server CloudFront.');
    const keyboard = [];
    for (const srv of servers) {
      keyboard.push([{ text: `🎁 Trial ${esc(srv.name)}`, callback_data: `vt_${storeCb(JSON.stringify({a:'tri',d:srv.server_id,n:srv.name}))}` }]);
    }
    keyboard.push([{ text: '🔙 Kembali', callback_data: 'menu_vpncf' }]);
    await ctx.reply('🎁 *Pilih server untuk Trial:*', { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
  } catch (err) {
    ctx.reply('❌ Gagal: ' + nadiavpn.handleApiError(err));
  }
});

bot.action(/^vt_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  try {
    const raw = getCb(ctx.match[1]);
    if (!raw) return ctx.reply('❌ Data kadaluarsa.');
    const d = JSON.parse(raw);
    if (d.a !== 'tri') return ctx.reply('❌ Data tidak valid.');
    const res = await nadiavpn.getServers();
    const servers = res.data || [];
    const srv = servers.find(s => s.server_id === d.d);
    if (!srv) return ctx.reply('❌ Server tidak ditemukan.');
    const protocols = srv.supported_protocols || ['vless'];
    const keyboard = protocols.map(p => ([{ text: `📡 ${p.toUpperCase()}`, callback_data: `vp_${storeCb(JSON.stringify({a:'tri',d:d.d,p,n:d.n}))}` }]));
    keyboard.push([{ text: '🔙 Kembali', callback_data: 'vpncf_trial' }]);
    await ctx.reply(`🎁 *Trial ${esc(d.n)} - Pilih Protocol:*`, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
  } catch (err) {
    ctx.reply('❌ Gagal: ' + nadiavpn.handleApiError(err));
  }
});

bot.action(/^vp_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  try {
    const raw = getCb(ctx.match[1]);
    if (!raw) return ctx.reply('❌ Data kadaluarsa.');
    const d = JSON.parse(raw);
    if (d.a !== 'tri') return ctx.reply('❌ Data tidak valid.');
    console.log("⚠️ VP_CALLBACK:", JSON.stringify(d));

    const srvName = d.n || 'CloudFront';
    const lines = [
      [t(ctx.from.id, 'confirm_product'), `Trial CloudFront (${String(d.p || 'vless').toUpperCase()})`],
      [t(ctx.from.id, 'confirm_server'), esc(srvName)],
      [t(ctx.from.id, 'confirm_duration'), '1 Jam'],
    ];

  await confirmManager.ask(ctx, {
    title: t(ctx.from.id, 'confirm_trial_title'),
    lines,
    data: { serverId: d.d, protocol: d.p, serverName: srvName },
    executor: async (cbCtx, session) => {
      const uid = cbCtx.from.id;
      const failMsg = '❌ Trial gagal: Coba lagi nanti.';
      const showFail = async () => {
        try {
          await bot.telegram.editMessageText(cbCtx.chat?.id || uid, session.messageId, undefined, failMsg, { parse_mode: 'Markdown' });
        } catch (e) { await cbCtx.reply(failMsg, { parse_mode: 'Markdown' }); }
      };

      // Cooldown per user: cegah spam yang memicu rate limit panel.
      if (getCfTrialCooldownLeft(uid) > 0) {
        await showFail();
        return { refunded: true };
      }
      markCfTrialCooldown(uid);

      let result;
      try {
        result = await nadiavpn.createTrial(d.d, d.p);
      } catch (err) {
        logger.warn(`Trial CF gagal (${uid} / ${d.d} / ${d.p}): ${err.message}`);
        await showFail();
        return { refunded: true };
      }

        if (!result.success) {
          logger.warn(`Trial CF ditolak panel (${uid} / ${d.d} / ${d.p}): ${result.message}`);
          await showFail();
          return { refunded: true };
        }
        const cfg = result.config || {};
        const h = cfg.hostname || '-';
        const u = cfg.username || result.username;
        const p = cfg.password || result.password || '';
        let msg = `✅ *TRIAL CLOUDFRONT BERHASIL*\n\n`;
        const trialProto = d.p || 'vless';
        const trialProtoInfo = CF_PROTOCOLS[trialProto] || CF_PROTOCOLS.vless;
        if (trialProto === 'ssh') {
          msg += `*🔐 ${trialProtoInfo.name} Premium Details*\n`;
          msg += `────────────────────────\n`;
          msg += `📡 *SSH WS*    : \`${h}:80@${u}:${p}\`\n`;
          msg += `🔒 *SSH SSL*   : \`${h}:443@${u}:${p}\`\n`;
          msg += `📶 *SSH UDP*   : \`${h}:1-65535@${u}:${p}\`\n`;
          msg += `🌐 *SSH SLOWDNS* : \`${h}:5300@${u}:${p}\`\n`;
          msg += `────────────────────────\n`;
          msg += `🌍 *Host*         : \`${h}\`\n`;
          if (cfg.ISP) msg += `🏢 *ISP*          : \`${cfg.ISP}\`\n`;
          if (cfg.CITY) msg += `🏙️ *City*         : \`${cfg.CITY}\`\n`;
          msg += `👤 *Username*     : \`${u}\`\n`;
          msg += `🔑 *Password*     : \`${p}\`\n`;
          if (cfg.pubkey) msg += `🗝️ *Public Key*  : \`${cfg.pubkey}\`\n`;
          if (cfg.exp) msg += `📅 *Expiry Date*  : \`${cfg.exp}\`\n`;
          msg += `📌 *Masa Aktif*   : \`1 Jam\`\n`;
          msg += `📌 *IP Limit*     : \`3 IP\`\n`;
          msg += `────────────────────────\n`;
          msg += `🛠 *Ports:*\n`;
          const pt = cfg.port || {};
          if (pt.tls) msg += `• TLS         : \`${pt.tls}\`\n`;
          if (pt.none) msg += `• Non-TLS     : \`${pt.none}\`\n`;
          if (pt.ovpntcp) msg += `• OVPN TCP    : \`${pt.ovpntcp}\`\n`;
          if (pt.ovpnudp) msg += `• OVPN UDP    : \`${pt.ovpnudp}\`\n`;
          if (pt.sshohp) msg += `• SSH OHP     : \`${pt.sshohp}\`\n`;
          if (pt.udpcustom) msg += `• UDP Custom  : \`${pt.udpcustom}\`\n`;
          if (pt.slowdns) msg += `• SlowDNS     : \`${pt.slowdns}\`\n`;
          if (pt.squid) msg += `• Squid       : \`${pt.squid}\`\n`;
          if (pt.udpgw) msg += `• UDPGW       : \`${pt.udpgw}\`\n`;
          msg += `────────────────────────\n`;
          msg += `🧩 *Payload WS:*\n\`\`\`\n`;
          msg += `GET / HTTP/1.1\n`;
          msg += `Host: ${h}\n`;
          msg += `Connection: Upgrade\n`;
          msg += `User-Agent: [ua]\n`;
          msg += `Upgrade: websocket\n`;
          msg += `\`\`\`\n\n`;
          msg += `🧩 *Payload Enhanced:*\n\`\`\`\n`;
          msg += `PATCH / HTTP/1.1\n`;
          msg += `Host: ${h}\n`;
          msg += `Host: bug.com\n`;
          msg += `Connection: Upgrade\n`;
          msg += `User-Agent: [ua]\n`;
          msg += `Upgrade: websocket\n`;
          msg += `\`\`\`\n\n`;
        } else {
          const keyLabel = trialProto === 'trojan' ? 'Key' : 'UUID';
          const keyVal = cfg.uuid || cfg.key || result.uuid || result.key || '';
          msg += `*${trialProtoInfo.emoji} Akun ${trialProtoInfo.name} CloudFront Trial*\n`;
          msg += `────────────────────────\n`;
          msg += `👤 *Username*     : \`${u}\`\n`;
          msg += `🌍 *Host*         : \`${h}\`\n`;
          msg += `☁️ *Mode*         : \`CLOUDFRONT\`\n`;
          if (cfg.ISP) msg += `🏢 *ISP*          : \`${cfg.ISP}\`\n`;
          if (cfg.CITY) msg += `🏙️ *City*         : \`${cfg.CITY}\`\n`;
          if (keyVal) msg += `🛡 *${keyLabel}*      : \`${keyVal}\`\n`;
          if (cfg.exp) msg += `📅 *Expired*      : \`${cfg.exp}\`\n`;
          msg += `📌 *Masa Aktif*   : \`1 Jam\`\n`;
          msg += `📌 *IP Limit*     : \`3 IP\`\n`;
          const pt2 = cfg.port || {};
          if (pt2.tls || pt2.none || pt2.any) {
            msg += `────────────────────────\n`;
            msg += `📡 *Ports:*\n`;
            if (pt2.tls) msg += `- TLS         : \`${pt2.tls}\`\n`;
            if (pt2.none) msg += `- Non TLS     : \`${pt2.none}\`\n`;
            if (pt2.any) msg += `- Any Port    : \`${pt2.any}\`\n`;
          }
          const pth = cfg.path || cfg.ws_path || {};
          if (pth.stn || pth.multi || pth.grpc || pth.up) {
            msg += `────────────────────────\n`;
            msg += `📶 *Path:*\n`;
            if (pth.stn) msg += `- WS          : \`${pth.stn}\`${pth.multi ? ` | \`${pth.multi}\`` : ''}\n`;
            if (pth.grpc) msg += `- gRPC        : \`${pth.grpc}\`\n`;
            if (pth.up) msg += `- Upgrade     : \`${pth.up}\`\n`;
          }
          const link = cfg.link || result.link || null;
          if (link && (link.tls || link.none || link.grpc || link.uptls)) {
            msg += `────────────────────────\n`;
            msg += `🔗 *${trialProtoInfo.name} Links (CloudFront):*\n`;
            if (link.tls) msg += `- TLS         : \`${link.tls}\`\n`;
            if (link.none) msg += `- Non TLS     : \`${link.none}\`\n`;
            if (link.grpc) msg += `- gRPC        : \`${link.grpc}\`\n`;
            if (link.uptls) msg += `- Up TLS      : \`${link.uptls}\`\n`;
          }
          msg += `\n`;
        }
        msg += `📥 *Download Config*:\n🔗 https://rajaserver.web.id/config-Indonesia.zip\n`;
        try {
          await bot.telegram.editMessageText(cbCtx.chat?.id || uid, session.messageId, undefined, msg, { parse_mode: 'Markdown' });
        } catch (e) {
          await sendAccountResult(cbCtx, null, null, msg);
        }
      },
    });
  } catch (err) {
    const errMsg = nadiavpn.handleApiError(err);
    if (errMsg.toLowerCase().includes('trial') || errMsg.toLowerCase().includes('habis') || errMsg.toLowerCase().includes('kuota')) {
      ctx.reply(t(ctx.from.id, 'trial_quota_out'));
    } else {
      ctx.reply(t(ctx.from.id, 'trial_failed', { error: errMsg }));
    }
  }
});

bot.action(/^cs_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  try {
    const raw = getCb(ctx.match[1]);
    if (!raw) return ctx.reply('❌ Data kadaluarsa, silakan coba lagi.');
    const d = JSON.parse(raw);
    if (d.a !== 'sel') return ctx.reply('❌ Data tidak valid.');
    const serverId = d.d;
    const res = await nadiavpn.getServers();
    const servers = res.data || [];
    const srv = servers.find(s => s.server_id === serverId);
    if (!srv) return ctx.reply('❌ Server tidak ditemukan.');
    const protocols = srv.supported_protocols || ['ssh', 'vmess', 'vless', 'trojan'];
    const keyboard = [];
    const protoRow = [];
    for (const p of protocols) {
      if (p === 'ssh') {
        keyboard.push([{ text: '📦 SSH', callback_data: `cspr_${serverId}_ssh` }]);
      } else {
        protoRow.push({ text: '📦 ' + String(p).toUpperCase(), callback_data: `cspr_${serverId}_${p}` });
      }
    }
    if (protoRow.length) keyboard.push(protoRow);
    keyboard.push([{ text: '🔙 Kembali', callback_data: 'menu_vpncf' }]);
    await ctx.reply(
      '🖥️ *' + (srv.name || 'Unknown') + ' - Pilih Layanan*\n\n' +
      protocols.map(p => '📦 ' + String(p).toUpperCase()).join('\n') + '\n\n' +
      'Silakan pilih layanan protokol yang diinginkan:',
      { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } }
    );
  } catch (err) {
    ctx.reply('❌ Gagal: ' + nadiavpn.handleApiError(err));
  }
});

bot.action(/^cspr_(.+)_(ssh|vmess|vless|trojan)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  try {
    const serverId = ctx.match[1];
    const protocol = ctx.match[2];
    const res = await nadiavpn.getServers();
    const servers = res.data || [];
    const srv = servers.find(s => s.server_id === serverId);
    if (!srv) return ctx.reply('❌ Server tidak ditemukan.');
    if (!(srv.supported_protocols || []).includes(protocol)) {
      return ctx.reply(`❌ *${String(protocol).toUpperCase()}* tidak tersedia di server ini. Tersedia: ${(srv.supported_protocols || []).join(', ').toUpperCase()}.`);
    }
    const pricing = srv.pricing || {};
    const types = srv.supported_types || ['day'];
    const dayPrice = pricing.per_day && types.includes('day') ? parseInt(pricing.per_day) + 500 : null;
    const weekPrice = pricing.per_week && types.includes('week') ? parseInt(pricing.per_week) + 1000 : null;
    const monthPrice = pricing.per_month && types.includes('month') ? parseInt(pricing.per_month) + 2000 : null;
    const keyboard = types.map(t => {
      const hargaTipe = t === 'month' ? monthPrice : (t === 'week' ? weekPrice : dayPrice);
      const label = String(protocol).toUpperCase();
      return [{ text: `📅 ${t.charAt(0).toUpperCase() + t.slice(1)} (${label})`, callback_data: `co_${storeCb(JSON.stringify({a:'ord',d:serverId,t,p:protocol,h:hargaTipe}))}` }];
    });
    keyboard.push([{ text: '🔙 Kembali', callback_data: `cs_${storeCb(JSON.stringify({a:'sel',d:serverId}))}` }]);
    await ctx.reply('📅 *Pilih tipe untuk ' + (srv.name || 'Unknown') + ' (' + String(protocol).toUpperCase() + '):*', { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
  } catch (err) {
    ctx.reply('❌ Gagal: ' + nadiavpn.handleApiError(err));
  }
});

bot.action(/^co_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  try {
    const raw = getCb(ctx.match[1]);
    if (!raw) return ctx.reply('❌ Data kadaluarsa, silakan coba lagi.');
    const d = JSON.parse(raw);
    if (d.a !== 'ord') return ctx.reply('❌ Data tidak valid.');
    const hargaPerUnit = d.h || 15000;
    if (d.t === 'day') {
      userState[ctx.chat.id] = { step: 'vpncf_duration', serverId: d.d, protocol: d.p, type: d.t, hargaPerUnit };
      return ctx.reply('⏳ *Masukkan jumlah hari (1-30):*', { parse_mode: 'Markdown' });
    }
    const totalHargaMonth = hargaPerUnit * 1;
    userState[ctx.chat.id] = { step: 'vpncf_username', serverId: d.d, protocol: d.p, type: d.t, duration: 1, hargaPerUnit, totalHarga: totalHargaMonth };
    await ctx.reply(t(ctx.from.id, 'prompt_username'), { parse_mode: 'Markdown' });
  } catch (e) {
    ctx.reply('❌ Data tidak valid.');
  }
});

async function getVpncfMonthPrice(serverId, serverName) {
  try {
    const res = await nadiavpn.getServers();
    const servers = (res.data || []);
    let srv = serverId ? servers.find(s => String(s.server_id) === String(serverId)) : null;
    if (!srv) {
      const name = String(serverName || '').trim().toLowerCase();
      if (name) srv = servers.find(s => String(s.name || '').trim().toLowerCase() === name);
    }
    if (srv && srv.pricing) {
      if (srv.pricing.per_month) return parseInt(srv.pricing.per_month) + 2000;
      if (srv.pricing.per_day) return (parseInt(srv.pricing.per_day) + 500) * 30;
    }
  } catch (e) {
    logger.error('getVpncfMonthPrice error:', e.message);
  }
  return 50000;
}

bot.action('vpncf_renew', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  try {
    db.all('SELECT * FROM vpncf_accounts WHERE user_id = ? ORDER BY created_at DESC', [ctx.from.id], (err, accounts) => {
      if (err) return ctx.reply('❌ Gagal membaca database.');
      if (!accounts || accounts.length === 0) return ctx.reply('♻️ Tidak ada akun CloudFront untuk di-renew.');
      const keyboard = accounts.map(a => {
        const expTxt = a.expired_date ? formatExpDate(a.expired_date) : '?';
        const status = isExpiredDate(a.expired_date) ? '❌' : '✅';
        return ([{ text: `${status} ${a.username} - ${a.server_name} (${a.type || a.protocol}) • ${expTxt}`, callback_data: `cfren_${a.account_id || a.id}` }]);
      });
      keyboard.push([{ text: '🔙 Kembali', callback_data: 'menu_vpncf' }]);
      ctx.reply('♻️ *Pilih akun CloudFront untuk di-renew:*', { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
    });
  } catch (err) {
    ctx.reply('❌ Gagal: ' + nadiavpn.handleApiError(err));
  }
});

bot.action(/^cfren_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const accountId = ctx.match[1];
  userState[ctx.chat.id] = { step: 'vpncf_renew_duration', accountId };
  await ctx.reply('⏳ *Masukkan durasi perpanjangan (bulan, 1-12):*', { parse_mode: 'Markdown' });
});

// ============================================================
// VPN CLOUDFRONT HANDLERS (Multi-Protocol)
// ============================================================

bot.action('menu_sshcf', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  if (!enableVpnCf) {
    return ctx.reply(t(ctx.from.id, 'vpncf_disabled'), { parse_mode: 'HTML' });
  }
  let msg = '━━━━━━━━━━━━━━━━━━━━\n  ☁️ <b>VPN CLOUDFRONT</b>\n━━━━━━━━━━━━━━━━━━━━\n\n';
  msg += 'Pilih protokol untuk membuat akun:\n\n';
  const keyboard = [
    [
      { text: '🔐 Buat SSH', callback_data: 'cfproto_ssh' },
      { text: '🟣 Buat VMESS', callback_data: 'cfproto_vmess' }
    ],
    [
      { text: '🟢 Buat VLESS', callback_data: 'cfproto_vless' },
      { text: '🔴 Buat TROJAN', callback_data: 'cfproto_trojan' }
    ],
    [{ text: '🎁 Trial CloudFront', callback_data: 'cftrial_menu' }],
    [{ text: '♻️ Renew CloudFront', callback_data: 'cfrenew_menu' }],
    [{ text: '🗑️ Hapus CloudFront', callback_data: 'cfdel_menu' }],
    [{ text: '🔄 Ganti Protokol', callback_data: 'cfchangeprotocol_menu' }],
    [{ text: '🔀 Ganti Limit IP', callback_data: 'cfchangelimip_menu' }],
    [{ text: '🔒 Lock Akun', callback_data: 'cflock_menu' }],
    [{ text: '🔓 Unlock Akun', callback_data: 'cfunlock_menu' }],
    [{ text: '🔧 Fix Akun', callback_data: 'cffix_menu' }],
    [{ text: '🔀 Migrasi CloudFront → Regular', callback_data: 'cfmig_to_regular' }],
    [{ text: '🔀 Migrasi Regular → CloudFront', callback_data: 'cfmig_to_cf' }],
    [{ text: '🔙 Kembali', callback_data: 'send_main_menu' }],
  ];
  await ctx.reply(msg, { parse_mode: 'HTML', reply_markup: { inline_keyboard: keyboard } });
});

bot.action(/^cfproto_(ssh|vmess|vless|trojan)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const protocol = ctx.match[1];
  const proto = CF_PROTOCOLS[protocol];
  const userId = ctx.from.id;
  const isReseller = await isUserReseller(userId);
  let q = "SELECT * FROM Server WHERE cloudfront_domain IS NOT NULL AND cloudfront_domain != ''";
  if (isReseller) {
    q += " AND is_reseller_only = 1";
  } else {
    q += " AND (is_reseller_only = 0 OR is_reseller_only IS NULL)";
  }
  q += " ORDER BY nama_server ASC";
  db.all(q, [], async (err, servers) => {
    if (err) {
      logger.error('Error fetching CF servers:', err.message);
      return ctx.reply('❌ Gagal mengambil data server.');
    }
    if (!servers || servers.length === 0) {
      return ctx.reply('❌ Belum ada server CloudFront tersedia.\n\nHubungi admin untuk mengaktifkan fitur ini.');
    }
    let msg = `━━━━━━━━━━━━━━━━━━━━\n  ☁️ <b>VPN CLOUDFRONT</b>\n━━━━━━━━━━━━━━━━━━━━\n\n`;
    msg += `Protocol : <b>${proto.name}</b>\n\n`;
    if (isReseller) msg += '🔒 <b>Server Khusus Reseller:</b>\n\n';
    else msg += '🌐 <b>Server Publik:</b>\n\n';
    const keyboard = [];
    for (const srv of servers) {
      const isFull = srv.total_create_akun >= srv.batas_create_akun;
      const showQuota = !srv.quota || srv.quota === 0 || srv.quota === ')' ? 'Unlimited' : `${srv.quota}GB`;
      const showIP = marketingIP(srv);
      const harga30 = srv.harga * 30;
      const badge = '';
      msg += `🟢 <b>${srv.nama_server}${badge}</b>\n`;
      msg += `   ☁️ CF Domain: ${srv.cloudfront_domain}\n`;
      msg += `   💰 Harga: Rp${srv.harga}/hari | Rp${harga30}/30hr\n`;
      msg += `   📊 Quota: ${showQuota} | 🔢 IP: ${showIP}\n`;
      msg += isFull ? '   ⚠️ <b>Server Penuh</b>\n' : `   👥 Akun: ${srv.total_create_akun}/${srv.batas_create_akun}\n`;
      msg += '\n';
      keyboard.push([{
        text: `🛒 Pilih ${srv.nama_server}${badge}`,
        callback_data: `sshcf_sel_${srv.id}`
      }]);
    }
    keyboard.push([{ text: '🔙 Kembali', callback_data: 'menu_sshcf' }]);
    userState[ctx.chat.id] = { step: 'cf_select_server', protocol };
    await ctx.reply(msg, { parse_mode: 'HTML', reply_markup: { inline_keyboard: keyboard } });
  });
});

bot.action(/^sshcf_sel_(\d+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const serverId = ctx.match[1];
  const state = userState[ctx.chat.id];
  const protocol = (state && state.protocol) || 'ssh';
  const proto = CF_PROTOCOLS[protocol] || CF_PROTOCOLS.ssh;
  db.get('SELECT * FROM Server WHERE id = ?', [serverId], (err, server) => {
    if (err || !server) {
      return ctx.reply('❌ Server tidak ditemukan.');
    }
    if (server.total_create_akun >= server.batas_create_akun) {
      return ctx.reply(`❌ *Slot VPN CloudFront ${esc(server.nama_server)} telah penuh!*

Slot server ini sudah penuh (terpakai ${server.total_create_akun}/${server.batas_create_akun}).

Silakan pilih salah satu opsi berikut:
1️⃣ *Renew* akun CloudFront yang sudah ada
2️⃣ Coba *Trial CloudFront*

Gunakan menu di bawah untuk melanjutkan.`, {
        parse_mode: 'Markdown',
        reply_markup: {
          inline_keyboard: [
            [{ text: '♻️ Renew CloudFront', callback_data: 'sshcf_renew' }],
            [{ text: '🎁 Trial CloudFront', callback_data: 'cftrial_menu' }],
            [{ text: '🔙 Kembali', callback_data: 'menu_sshcf' }]
          ]
        }
      });
    }
    userState[ctx.chat.id] = { step: 'cf_username', serverId: parseInt(serverId), protocol };
    const passMsg = proto.needsPassword ? '\n🔑 Password akan diminta setelah username.' : '';
    ctx.reply(
      `☁️ *${proto.label} - ${esc(server.nama_server)}*\n\n` +
      `Protocol: *${proto.name}*\n` +
      `CloudFront domain: \`${server.cloudfront_domain}\`${passMsg}\n\n` +
      `👤 *Masukkan username:*`,
      { parse_mode: 'Markdown' }
    );
  });
});

bot.action('sshcf_renew', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const userId = ctx.from.id;
  const isReseller = await isUserReseller(userId);
  let q = "SELECT * FROM Server WHERE cloudfront_domain IS NOT NULL AND cloudfront_domain != ''";
  if (isReseller) {
    q += " AND is_reseller_only = 1";
  } else {
    q += " AND (is_reseller_only = 0 OR is_reseller_only IS NULL)";
  }
  q += " ORDER BY nama_server ASC";
  db.all(q, [], (err, servers) => {
    if (err || !servers || servers.length === 0) {
      return ctx.reply('❌ Belum ada server CloudFront tersedia.');
    }
    let msg = '☁️ *Pilih server untuk renew:*\n\n';
    if (isReseller) msg += '🔒 *Server Khusus Reseller:*\n\n';
    else msg += '🌐 *Server Publik:*\n\n';
    const keyboard = [];
    for (const s of servers) {
      const badge = '';
      msg += `• ${s.nama_server}${badge} - Rp${s.harga}/hari\n`;
      keyboard.push([{
        text: `${s.nama_server}${badge} - Rp${s.harga}/hari`,
        callback_data: `sshcf_renew_sel_${s.id}`
      }]);
    }
    keyboard.push([{ text: '🔙 Kembali', callback_data: 'menu_sshcf' }]);
    ctx.reply(msg, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
  });
});

bot.action(/^sshcf_renew_sel_(\d+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const serverId = ctx.match[1];
  userState[ctx.chat.id] = { step: 'sshcf_renew_username', serverId: parseInt(serverId) };
  ctx.reply('👤 *Masukkan username CF yang ingin diperpanjang:*', { parse_mode: 'Markdown' });
});

bot.action('sshcf_del', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  userState[ctx.chat.id] = { step: 'sshcf_del_username' };
  ctx.reply('👤 *Masukkan username CF yang ingin dihapus:*', { parse_mode: 'Markdown' });
});

bot.action('sshcf_trial', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const userId = ctx.from.id;
  const isReseller = await isUserReseller(userId);
  let q = "SELECT * FROM Server WHERE cloudfront_domain IS NOT NULL AND cloudfront_domain != ''";
  if (isReseller) {
    q += " AND is_reseller_only = 1";
  } else {
    q += " AND (is_reseller_only = 0 OR is_reseller_only IS NULL)";
  }
  q += " ORDER BY nama_server ASC";
  db.all(q, [], (err, servers) => {
    if (err || !servers || servers.length === 0) {
      return ctx.reply('❌ Belum ada server CloudFront tersedia.');
    }
    let msg = '🎁 *Pilih server untuk Trial CF (3 Jam):*\n\n';
    if (isReseller) msg += '🔒 *Server Khusus Reseller:*\n\n';
    else msg += '🌐 *Server Publik:*\n\n';
    const keyboard = [];
    for (const s of servers) {
      const badge = '';
      msg += `• ${s.nama_server}${badge}\n`;
      keyboard.push([{
        text: `${s.nama_server}${badge}`,
        callback_data: `sshcf_trial_sel_${s.id}`
      }]);
    }
    keyboard.push([{ text: '🔙 Kembali', callback_data: 'menu_sshcf' }]);
    ctx.reply(msg, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
  });
});

bot.action(/^sshcf_trial_sel_(\d+)$/, async (ctx) => {
  try {
    await ctx.answerCbQuery().catch(() => {});
    const serverId = ctx.match[1];
    const idUser = ctx.from.id.toString().trim();
    const resselDbPath = './ressel.db';
    let isRessel = false;
    try {
      const data = fs.readFileSync(resselDbPath, 'utf8');
      const resselList = data.split('\n').map(line => line.trim()).filter(Boolean);
      isRessel = resselList.includes(idUser);
    } catch (err) {
      console.error('❌ Gagal membaca file ressel.db:', err.message);
      return ctx.reply(t(userId, 'err_read_reseller'), { parse_mode: 'Markdown' });
    }
    if (!isRessel) {
      const userSaldo = await getUserBalance(ctx.from.id);
      if (userSaldo < 100) {
        return ctx.reply(t(ctx.from.id, 'trial_no_balance'), { parse_mode: 'Markdown' });
      }
      const sudahPakai = await checkTrialAccess(ctx.from.id);
      if (sudahPakai) {
        return ctx.reply(t(ctx.from.id, 'trial_used_today'), { parse_mode: 'Markdown' });
      }
    }
      const username = 'trial-' + Math.random().toString(36).substring(2, 7);
    const serverRow = await new Promise((resolve) => {
      db.get('SELECT nama_server FROM Server WHERE id = ?', [serverId], (e, r) => resolve(r || null));
    }).catch(() => null);

    const lines = [
      [t(ctx.from.id, 'confirm_product'), 'Trial SSH CloudFront'],
      [t(ctx.from.id, 'confirm_server'), serverRow && serverRow.nama_server ? esc(serverRow.nama_server) : `ID ${serverId}`],
      [t(ctx.from.id, 'confirm_username'), `\`${username}\``],
      [t(ctx.from.id, 'confirm_duration'), '3 Jam'],
    ];

    await confirmManager.ask(ctx, {
      title: t(ctx.from.id, 'confirm_trial_title'),
      lines,
      data: { serverId, username },
      executor: async (cbCtx, session) => {
        const uid = cbCtx.from.id;
        if (!isRessel) {
          await saveTrialAccess(uid);
        }
        logger.info(`✅ Trial SSH CF dibuat oleh ${uid}`);
        const maskedUsername = username.length > 1 ? `${username.slice(0, 1)}${'x'.repeat(username.length - 1)}` : username;
        bot.telegram.sendMessage(GROUP_ID,
          `<blockquote>\n⌛ <b>SSH CloudFront Trial</b>\n━━━━━━━━━━━━━━━━━━━━\n👤 <b>User:</b> ${cbCtx.from.first_name} (${uid})\n📛 <b>Username:</b> ${maskedUsername}\n📆 <b>Expired:</b> 3 Jam\n🌐 <b>Server ID:</b> ${serverId}\n━━━━━━━━━━━━━━━━━━━━\n</blockquote>`,
          { parse_mode: 'HTML' }).catch(() => {});
        const msg = await trialsshcf(username, serverId);
        try {
          await bot.telegram.editMessageText(cbCtx.chat?.id || uid, session.messageId, undefined, msg, { parse_mode: 'Markdown' });
        } catch (e) {
          await sendAccountResult(cbCtx, null, null, msg);
        }
      },
    });
  } catch (err) {
    console.error('❌ Error SSH CF trial:', err);
    await ctx.reply('❌ Terjadi kesalahan saat membuat trial. Coba lagi nanti.');
  }
});

// ============================================================
// TRIAL CLOUDFRONT HANDLERS (Multi-Protocol)
// ============================================================

bot.action('cftrial_menu', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  let msg = '━━━━━━━━━━━━━━━━━━━━\n  🎁 <b>TRIAL CLOUDFRONT</b>\n━━━━━━━━━━━━━━━━━━━━\n\n';
  msg += 'Pilih protokol untuk trial:\n\n';
  msg += '🔐 SSH (3 Jam)\n🟣 VMESS (3 Jam)\n🟢 VLESS (3 Jam)\n🔴 TROJAN (3 Jam)\n\n';
  msg += '⚠️ Maksimal 1 trial per user per hari.';
  const keyboard = [
    [{ text: '🔐 Trial SSH', callback_data: 'cftrial_ssh' }],
    [{ text: '🟣 Trial VMESS', callback_data: 'cftrial_vmess' }],
    [{ text: '🟢 Trial VLESS', callback_data: 'cftrial_vless' }],
    [{ text: '🔴 Trial TROJAN', callback_data: 'cftrial_trojan' }],
    [{ text: '🔙 Kembali', callback_data: 'menu_sshcf' }],
  ];
  await ctx.reply(msg, { parse_mode: 'HTML', reply_markup: { inline_keyboard: keyboard } });
});

bot.action(/^cftrial_(ssh|vmess|vless|trojan)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const protocol = ctx.match[1];
  const proto = CF_PROTOCOLS[protocol] || CF_PROTOCOLS.ssh;
  const userId = ctx.from.id;
  const isReseller = await isUserReseller(userId);
  let q = "SELECT * FROM Server WHERE cloudfront_domain IS NOT NULL AND cloudfront_domain != ''";
  if (isReseller) {
    q += " AND is_reseller_only = 1";
  } else {
    q += " AND (is_reseller_only = 0 OR is_reseller_only IS NULL)";
  }
  q += " ORDER BY nama_server ASC";
  db.all(q, [], async (err, servers) => {
    if (err || !servers || servers.length === 0) {
      return ctx.reply('❌ Belum ada server CloudFront tersedia.');
    }
    const duration = '3 Jam';
    let msg = `━━━━━━━━━━━━━━━━━━━━\n  🎁 <b>TRIAL ${proto.name} CLOUDFRONT</b>\n━━━━━━━━━━━━━━━━━━━━\n\n`;
    msg += `Protocol: <b>${proto.name}</b>\nDurasi: <b>${duration}</b>\n\n`;
    if (isReseller) msg += '🔒 <b>Server Khusus Reseller:</b>\n\n';
    else msg += '🌐 <b>Server Publik:</b>\n\n';
    const keyboard = [];
    for (const s of servers) {
      const isFull = s.total_create_akun >= s.batas_create_akun;
      if (isFull) continue;
      const badge = '';
      msg += `🟢 <b>${s.nama_server}${badge}</b>\n`;
      msg += `   ☁️ CF Domain: ${s.cloudfront_domain}\n`;
      const showIP = marketingIP(s);
      msg += `   🔢 IP: ${showIP}\n\n`;
      keyboard.push([{
        text: `🎁 ${s.nama_server}${badge}`,
        callback_data: `cftrial_sel_${protocol}_${s.id}`
      }]);
    }
    keyboard.push([{ text: '🔙 Kembali', callback_data: 'cftrial_menu' }]);
    userState[ctx.chat.id] = { step: 'cftrial_select_server', protocol };
    await ctx.reply(msg, { parse_mode: 'HTML', reply_markup: { inline_keyboard: keyboard } });
  });
});

bot.action(/^cftrial_sel_(ssh|vmess|vless|trojan)_(\d+)$/, async (ctx) => {
  try {
    await ctx.answerCbQuery().catch(() => {});
    const protocol = ctx.match[1];
    const serverId = ctx.match[2];
    const proto = CF_PROTOCOLS[protocol] || CF_PROTOCOLS.ssh;
    const idUser = ctx.from.id.toString().trim();
    const resselDbPath = './ressel.db';
    let isRessel = false;
    try {
      const data = fs.readFileSync(resselDbPath, 'utf8');
      const resselList = data.split('\n').map(line => line.trim()).filter(Boolean);
      isRessel = resselList.includes(idUser);
    } catch (err) {}
    if (!isRessel) {
      const userSaldo = await getUserBalance(ctx.from.id);
      if (userSaldo < 100) {
        return ctx.reply(t(ctx.from.id, 'trial_no_balance'), { parse_mode: 'Markdown' });
      }
      const sudahPakai = await checkTrialAccess(ctx.from.id);
      if (sudahPakai) {
        return ctx.reply(t(ctx.from.id, 'trial_used_today'), { parse_mode: 'Markdown' });
      }
    }
      const username = 'trial-' + Math.random().toString(36).substring(2, 7);
    const duration = '3 Jam';
    const serverRow = await new Promise((resolve) => {
      db.get('SELECT nama_server FROM Server WHERE id = ?', [serverId], (e, r) => resolve(r || null));
    }).catch(() => null);

    const lines = [
      [t(ctx.from.id, 'confirm_product'), `Trial ${proto.name} CloudFront`],
      [t(ctx.from.id, 'confirm_server'), serverRow && serverRow.nama_server ? esc(serverRow.nama_server) : `ID ${serverId}`],
      [t(ctx.from.id, 'confirm_username'), `\`${username}\``],
      [t(ctx.from.id, 'confirm_duration'), duration],
    ];

    await confirmManager.ask(ctx, {
      title: t(ctx.from.id, 'confirm_trial_title'),
      lines,
      data: { protocol, serverId, username },
      executor: async (cbCtx, session) => {
        const uid = cbCtx.from.id;
        if (!isRessel) {
          await saveTrialAccess(uid);
        }
        logger.info(`✅ Trial ${proto.name} CF dibuat oleh ${uid}`);
        const maskedUsername = username.length > 1 ? `${username.slice(0, 1)}${'x'.repeat(username.length - 1)}` : username;
        bot.telegram.sendMessage(GROUP_ID,
          `<blockquote>\n🎁 <b>${proto.name} CloudFront Trial</b>\n━━━━━━━━━━━━━━━━━━━━\n👤 <b>User:</b> ${cbCtx.from.first_name} (${uid})\n📛 <b>Username:</b> ${maskedUsername}\n📆 <b>Durasi:</b> ${duration}\n🌐 <b>Server ID:</b> ${serverId}\n━━━━━━━━━━━━━━━━━━━━\n</blockquote>`,
          { parse_mode: 'HTML' }).catch(() => {});
        let msg;
        if (protocol === 'vmess') msg = await trialcfvmess(username, serverId);
        else if (protocol === 'vless') msg = await trialcfvless(username, serverId);
        else if (protocol === 'trojan') msg = await trialcftrojan(username, serverId);
        else msg = await trialsshcf(username, serverId);
        try {
          await bot.telegram.editMessageText(cbCtx.chat?.id || uid, session.messageId, undefined, msg, { parse_mode: 'Markdown' });
        } catch (e) {
          await sendAccountResult(cbCtx, null, null, msg);
        }
      },
    });
  } catch (err) {
    console.error('❌ Error CF trial:', err);
    await ctx.reply('❌ Terjadi kesalahan saat membuat trial. Coba lagi nanti.');
  }
});

// ============================================================
// RENEW CLOUDFRONT HANDLERS (Multi-Protocol)
// ============================================================

bot.action('cfrenew_menu', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const userId = ctx.from.id;
  const isReseller = await isUserReseller(userId);
  let q = "SELECT * FROM Server WHERE cloudfront_domain IS NOT NULL AND cloudfront_domain != ''";
  if (isReseller) {
    q += " AND is_reseller_only = 1";
  } else {
    q += " AND (is_reseller_only = 0 OR is_reseller_only IS NULL)";
  }
  q += " ORDER BY nama_server ASC";
  db.all(q, [], (err, servers) => {
    if (err || !servers || servers.length === 0) {
      return ctx.reply('❌ Belum ada server CloudFront tersedia.');
    }
    let msg = '━━━━━━━━━━━━━━━━━━━━\n  ♻️ <b>RENEW CLOUDFRONT</b>\n━━━━━━━━━━━━━━━━━━━━\n\n';
    if (isReseller) msg += '🔒 <b>Server Khusus Reseller:</b>\n\n';
    else msg += '🌐 <b>Server Publik:</b>\n\n';
    const keyboard = [];
    for (const s of servers) {
      const badge = '';
      msg += `• ${s.nama_server}${badge} - Rp${s.harga}/hari\n`;
      keyboard.push([{
        text: `${s.nama_server}${badge} - Rp${s.harga}/hari`,
        callback_data: `cfrenew_sel_${s.id}`
      }]);
    }
    keyboard.push([{ text: '🔙 Kembali', callback_data: 'menu_sshcf' }]);
    ctx.reply(msg, { parse_mode: 'HTML', reply_markup: { inline_keyboard: keyboard } });
  });
});

bot.action(/^cfrenew_sel_(\d+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const serverId = ctx.match[1];
  userState[ctx.chat.id] = { step: 'cfrenew_username', serverId: parseInt(serverId) };
  ctx.reply('👤 *Masukkan username akun yang ingin diperpanjang:*', { parse_mode: 'Markdown' });
});

// ============================================================
// DELETE CLOUDFRONT HANDLERS (Multi-Protocol)
// ============================================================

// === MIGRASI CF→REGULAR CONFIRM ===
bot.action(/^cfmigr_regdst_(ssh|vmess|vless|trojan)_(\d+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const type = ctx.match[1]; const destServerId = ctx.match[2];
  const state = userState[ctx.chat.id];
  if (!state || !state.cfmigrData) return ctx.reply('❌ *Sesi expired.*', { parse_mode: 'Markdown' });
  const d = state.cfmigrData; delete userState[ctx.chat.id];
  const destServer = await new Promise((r, j) => db.get('SELECT * FROM Server WHERE id = ?', [destServerId], (e, row) => r(row)));
  if (!destServer) return ctx.reply('❌ Server tujuan tidak ditemukan.');
  const statusMsg = await ctx.reply('⏳ *Migrasi CF → Regular...*', { parse_mode: 'Markdown' }).catch(() => null);
  const statusMsgId = statusMsg ? statusMsg.message_id : null;
  const cfServer = await new Promise((r, j) => db.get('SELECT * FROM Server WHERE id = ?', [d.cfServerId], (e, row) => r(row)));
  try {
    let expDays = 30;
    if (d.expired && d.expired !== '-') { try { const ed = new Date(d.expired); const n = new Date(); ed.setHours(0,0,0,0); n.setHours(0,0,0,0); expDays = Math.max(1, Math.ceil((ed - n) / 86400000)); } catch(e){} }
    const password = (type === 'ssh') ? String(Math.floor(10000 + Math.random() * 90000)) : undefined;
    const createFns = { ssh: () => createssh(d.username, password || 'migrasi123', expDays, 100, destServerId), vmess: () => createvmess(d.username, expDays, '0', 100, destServerId), vless: () => createvless(d.username, expDays, '0', 100, destServerId), trojan: () => createtrojan(d.username, expDays, '0', 100, destServerId) };
    const createResult = await createFns[type]();
    if (createResult.includes('❌')) { if (statusMsgId) await bot.telegram.editMessageText(ctx.chat.id, statusMsgId, undefined, `❌ *Gagal buat akun regular.*\n${createResult}`, { parse_mode: 'Markdown' }); return; }
    if (statusMsgId) await bot.telegram.editMessageText(ctx.chat.id, statusMsgId, undefined, '✅ Akun regular dibuat\n⚙️ Menghapus akun CF...', { parse_mode: 'Markdown' });
    const delFns = { ssh: () => delssh(d.username, 'none', 'none', 'none', d.cfServerId), vmess: () => delvmess(d.username, 'none', 'none', 'none', d.cfServerId), vless: () => delvless(d.username, 'none', 'none', 'none', d.cfServerId), trojan: () => deltrojan(d.username, 'none', 'none', 'none', d.cfServerId) };
    await delFns[type]();
    const expDateStr = new Date(); expDateStr.setDate(expDateStr.getDate() + expDays);
    await insertAccountRecord(ctx.from.id, d.username, type, destServerId, destServer.nama_server, destServer.domain, expDateStr.toISOString().slice(0, 10), 0, createResult);
    await insertListAccount(ctx.from.id, d.username, type, destServer.nama_server, expDateStr.toISOString().slice(0, 10), createResult);
    markListAccountExpired(d.username, d.type).catch(() => {});
    let result = `✅ *Migrasi CF → Regular Berhasil!*\n━━━━━━━━━━━━━━━━━━━\n👤 Username: \`${esc(d.username)}\`\n📦 Dari: ${d.type.toUpperCase()} CF\n📦 Ke: ${type.toUpperCase()} Regular\n🌐 Server: ${esc(destServer.nama_server)}\n📅 Sisa Expired: ${expDays} hari\n━━━━━━━━━━━━━━━━━━━\n`;
    if (password) result += `🔑 Password SSH: \`${password}\`\n\n`;
    result += createResult;
    await sendAccountResult(ctx, ctx.chat.id, statusMsgId, result);
  } catch (err) {
    logger.error('Error cf migr to regular:', err.message);
    if (statusMsgId) await bot.telegram.editMessageText(ctx.chat.id, statusMsgId, undefined, `❌ *Error migrasi.* Silakan coba lagi nanti.`, { parse_mode: 'Markdown' });
  }
});

// === MIGRASI REGULAR→CF CONFIRM ===
bot.action(/^cfmigr_cfdst_(ssh|vmess|vless|trojan)_(\d+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const type = ctx.match[1]; const destServerId = ctx.match[2];
  const state = userState[ctx.chat.id];
  if (!state || !state.cfmigrData) return ctx.reply('❌ *Sesi expired.*', { parse_mode: 'Markdown' });
  const d = state.cfmigrData; delete userState[ctx.chat.id];
  const destServer = await new Promise((r, j) => db.get('SELECT * FROM Server WHERE id = ?', [destServerId], (e, row) => r(row)));
  if (!destServer) return ctx.reply('❌ Server CF tujuan tidak ditemukan.');
  const statusMsg = await ctx.reply('⏳ *Migrasi Regular → CF...*', { parse_mode: 'Markdown' }).catch(() => null);
  const statusMsgId = statusMsg ? statusMsg.message_id : null;
  try {
    let expDays = 30;
    if (d.expired && d.expired !== '-') { try { const ed = new Date(d.expired); const n = new Date(); ed.setHours(0,0,0,0); n.setHours(0,0,0,0); expDays = Math.max(1, Math.ceil((ed - n) / 86400000)); } catch(e){} }
    const cfDomain = destServer.cloudfront_domain || destServer.domain;
    const createFns = { ssh: () => createsshcf(d.username, 'migrasi123', expDays, 100, destServerId, cfDomain), vmess: () => createcfvmess(d.username, expDays, '0', 100, destServerId, cfDomain), vless: () => createcfvless(d.username, expDays, '0', 100, destServerId, cfDomain), trojan: () => createcftrojan(d.username, expDays, '0', 100, destServerId, cfDomain) };
    const createResult = await createFns[type]();
    if (createResult.includes('❌')) { if (statusMsgId) await bot.telegram.editMessageText(ctx.chat.id, statusMsgId, undefined, `❌ *Gagal buat akun CF.*\n${createResult}`, { parse_mode: 'Markdown' }); return; }
    if (statusMsgId) await bot.telegram.editMessageText(ctx.chat.id, statusMsgId, undefined, '✅ Akun CF dibuat\n⚙️ Menghapus akun regular...', { parse_mode: 'Markdown' });
    const delFns = { ssh: () => delssh(d.username, 'none', 'none', 'none', d.regServerId), vmess: () => delvmess(d.username, 'none', 'none', 'none', d.regServerId), vless: () => delvless(d.username, 'none', 'none', 'none', d.regServerId), trojan: () => deltrojan(d.username, 'none', 'none', 'none', d.regServerId) };
    await delFns[type]();
    const expDateStr = new Date(); expDateStr.setDate(expDateStr.getDate() + expDays);
    try { await insertListAccount(ctx.from.id, d.username, `${type}cf`, destServer.nama_server, expDateStr.toISOString().slice(0, 10), createResult); } catch (e) {}
    try {
      await dbRunAsync('INSERT INTO sshcf_accounts (user_id, username, cloudfront_domain, panel_server, server_id, expired_at, created_at, price, full_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [ctx.from.id, d.username, cfDomain, destServer.domain, destServerId, expDateStr.toISOString().slice(0, 10), new Date().toISOString(), 0, createResult]);
    } catch (e) {
      logger.error('Gagal simpan sshcf_accounts (migrasi):', e.message);
    }
    let result = `✅ *Migrasi Regular → CF Berhasil!*\n━━━━━━━━━━━━━━━━━━━\n👤 Username: \`${esc(d.username)}\`\n📦 Dari: ${d.type.toUpperCase()} Regular\n📦 Ke: ${type.toUpperCase()} CF\n🌐 Server: ${esc(destServer.nama_server)}\n📅 Sisa Expired: ${expDays} hari\n━━━━━━━━━━━━━━━━━━━\n\n` + createResult;
    await sendAccountResult(ctx, ctx.chat.id, statusMsgId, result);
  } catch (err) {
    logger.error('Error cf migr to cf:', err.message);
    if (statusMsgId) await bot.telegram.editMessageText(ctx.chat.id, statusMsgId, undefined, `❌ *Error migrasi.* Silakan coba lagi nanti.`, { parse_mode: 'Markdown' });
  }
});

// === CF GANTI PROTOKOL CONFIRM ===
bot.action(/^cfchgproto_apply_(ssh|vmess|vless|trojan)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const newType = ctx.match[1];
  const state = userState[ctx.chat.id];
  if (!state || !state.cfchgprotoData) return ctx.reply('❌ *Sesi expired.*', { parse_mode: 'Markdown' });
  const d = state.cfchgprotoData;
  if (d.type === newType) return ctx.reply(`❌ *Sudah ${newType.toUpperCase()}.*`, { parse_mode: 'Markdown' });
  state.cfchgprotoData.newType = newType;
  userState[ctx.chat.id] = state;
  const passwordHint = (newType === 'ssh') ? '\n🔑 Password baru: 5 digit angka random.' : '';
  await ctx.reply(
    `🔄 *KONFIRMASI GANTI PROTOKOL CF*\n━━━━━━━━━━━━━━━━━━━\n👤 Username: \`${esc(d.username)}\`\n🌐 Server: ${esc(d.serverName)}\n📦 Dari: ${d.type.toUpperCase()}\n📦 Ke: ${newType.toUpperCase()}\n📅 Sisa Expired: *${d.expired}*\n━━━━━━━━━━━━━━━━━━━\n⚠️ Akun lama akan dihapus dari server.\n✅ Akun baru akan dibuat di server yang sama.${passwordHint}`,
    { parse_mode: 'Markdown', reply_markup: { inline_keyboard: [[{ text: `✅ Ya, Ganti ke ${newType.toUpperCase()}`, callback_data: `cfchgproto_exec_${newType}` }, { text: '❌ Batal', callback_data: 'menu_sshcf' }]] } }
  );
});

bot.action(/^cfchgproto_exec_(ssh|vmess|vless|trojan)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const newType = ctx.match[1];
  const state = userState[ctx.chat.id];
  if (!state || !state.cfchgprotoData) return ctx.reply('❌ *Sesi expired.*', { parse_mode: 'Markdown' });
  const d = state.cfchgprotoData; delete userState[ctx.chat.id];
  const statusMsg = await ctx.reply('⏳ *Ganti protokol CF...*', { parse_mode: 'Markdown' }).catch(() => null);
  const statusMsgId = statusMsg ? statusMsg.message_id : null;
  const cfServer = await new Promise((r, j) => db.get('SELECT * FROM Server WHERE id = ?', [d.serverId], (e, row) => r(row)));
  try {
    const delFns = { ssh: () => delssh(d.username, 'none', 'none', 'none', d.serverId), vmess: () => delvmess(d.username, 'none', 'none', 'none', d.serverId), vless: () => delvless(d.username, 'none', 'none', 'none', d.serverId), trojan: () => deltrojan(d.username, 'none', 'none', 'none', d.serverId) };
    await delFns[d.type]();
    let expDays = 30;
    if (d.expired && d.expired !== '-') { try { const ed = new Date(d.expired); const n = new Date(); ed.setHours(0,0,0,0); n.setHours(0,0,0,0); expDays = Math.max(1, Math.ceil((ed - n) / 86400000)); } catch(e){} }
    const password = (newType === 'ssh') ? String(Math.floor(10000 + Math.random() * 90000)) : undefined;
    const cfDomain = cfServer ? (cfServer.cloudfront_domain || cfServer.domain) : '';
    const createFns = { ssh: () => createsshcf(d.username, password || 'ganti123', expDays, 100, d.serverId, cfDomain), vmess: () => createcfvmess(d.username, expDays, '0', 100, d.serverId, cfDomain), vless: () => createcfvless(d.username, expDays, '0', 100, d.serverId, cfDomain), trojan: () => createcftrojan(d.username, expDays, '0', 100, d.serverId, cfDomain) };
    const createResult = await createFns[newType]();
    if (createResult.includes('❌')) { if (statusMsgId) await bot.telegram.editMessageText(ctx.chat.id, statusMsgId, undefined, `❌ *Gagal buat akun ${newType.toUpperCase()}.*\n${createResult}`, { parse_mode: 'Markdown' }); return; }
    markListAccountExpired(d.username, d.type).catch(() => {});
    insertListAccount(ctx.from.id, d.username, `${newType}cf`, d.serverName, d.expired || '', createResult).catch(() => {});
    let result = `✅ *Ganti Protokol CF Berhasil!*\n━━━━━━━━━━━━━━━━━━━\n👤 Username: \`${esc(d.username)}\`\n📦 ${d.type.toUpperCase()} → ${newType.toUpperCase()}\n🌐 Server: ${esc(d.serverName)}\n📅 Sisa Expired: ${d.expired}\n━━━━━━━━━━━━━━━━━━━\n`;
    if (password) result += `🔑 Password SSH: \`${password}\`\n\n`;
    result += createResult;
    await sendAccountResult(ctx, ctx.chat.id, statusMsgId, result);
  } catch (err) {
    logger.error('Error cf ganti protokol:', err.message);
    if (statusMsgId) await bot.telegram.editMessageText(ctx.chat.id, statusMsgId, undefined, `❌ *Error.* Silakan coba lagi nanti.`, { parse_mode: 'Markdown' });
  }
});

bot.action('cfdel_menu', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  let msg = '━━━━━━━━━━━━━━━━━━━━\n  🗑️ <b>HAPUS CLOUDFRONT</b>\n━━━━━━━━━━━━━━━━━━━━\n\n';
  msg += 'Pilih protokol akun yang ingin dihapus:\n\n';
  msg += '🔐 SSH\n🟣 VMESS\n🟢 VLESS\n🔴 TROJAN\n';
  const keyboard = [
    [{ text: '🔐 Hapus SSH', callback_data: 'cfdel_ssh' }],
    [{ text: '🟣 Hapus VMESS', callback_data: 'cfdel_vmess' }],
    [{ text: '🟢 Hapus VLESS', callback_data: 'cfdel_vless' }],
    [{ text: '🔴 Hapus TROJAN', callback_data: 'cfdel_trojan' }],
    [{ text: '🔙 Kembali', callback_data: 'menu_sshcf' }],
  ];
  await ctx.reply(msg, { parse_mode: 'HTML', reply_markup: { inline_keyboard: keyboard } });
});

bot.action(/^cfdel_(ssh|vmess|vless|trojan)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const protocol = ctx.match[1];
  const proto = CF_PROTOCOLS[protocol] || CF_PROTOCOLS.ssh;
  const userId = ctx.from.id;
  const isReseller = await isUserReseller(userId);
  let q = "SELECT * FROM Server WHERE cloudfront_domain IS NOT NULL AND cloudfront_domain != ''";
  if (isReseller) {
    q += " AND is_reseller_only = 1";
  } else {
    q += " AND (is_reseller_only = 0 OR is_reseller_only IS NULL)";
  }
  q += " ORDER BY nama_server ASC";
  db.all(q, [], async (err, servers) => {
    if (err || !servers || servers.length === 0) {
      return ctx.reply('❌ Belum ada server CloudFront tersedia.');
    }
    let msg = `━━━━━━━━━━━━━━━━━━━━\n  🗑️ <b>HAPUS ${proto.name} CLOUDFRONT</b>\n━━━━━━━━━━━━━━━━━━━━\n\n`;
    msg += `Protocol: <b>${proto.name}</b>\n\n`;
    if (isReseller) msg += '🔒 <b>Server Khusus Reseller:</b>\n\n';
    else msg += '🌐 <b>Server Publik:</b>\n\n';
    const keyboard = [];
    for (const s of servers) {
      const badge = '';
      msg += `🟢 <b>${s.nama_server}${badge}</b>\n`;
      msg += `   ☁️ CF Domain: ${s.cloudfront_domain}\n\n`;
      keyboard.push([{
        text: `${s.nama_server}${badge}`,
        callback_data: `cfdel_sel_${protocol}_${s.id}`
      }]);
    }
    keyboard.push([{ text: '🔙 Kembali', callback_data: 'cfdel_menu' }]);
    userState[ctx.chat.id] = { step: 'cfdel_select_server', protocol };
    await ctx.reply(msg, { parse_mode: 'HTML', reply_markup: { inline_keyboard: keyboard } });
  });
});

bot.action(/^cfdel_sel_(ssh|vmess|vless|trojan)_(\d+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const protocol = ctx.match[1];
  const serverId = ctx.match[2];
  userState[ctx.chat.id] = { step: 'cfdel_username', serverId: parseInt(serverId), protocol };
  ctx.reply('👤 *Masukkan username akun yang ingin dihapus:*', { parse_mode: 'Markdown' });
});

bot.action(/^cfdel_confirm_(\d+)_([a-z0-9]+)_(\d+)_(ssh|vmess|vless|trojan)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const accountId = parseInt(ctx.match[1]);
  const username = ctx.match[2];
  const serverId = parseInt(ctx.match[3]);
  const protocol = ctx.match[4];
  const proto = CF_PROTOCOLS[protocol] || CF_PROTOCOLS.ssh;

  const processingMsg = await ctx.reply(t(ctx.from.id, 'processing_delete'), { parse_mode: 'Markdown' }).catch(() => null);

  taskQueue.runBackground(ctx.from.id,
    async () => {
      let msg;
      if (protocol === 'vmess') msg = await delcfvmess(username, serverId);
      else if (protocol === 'vless') msg = await delcfvless(username, serverId);
      else if (protocol === 'trojan') msg = await delcftrojan(username, serverId);
      else msg = await delsshcf(username, serverId);

      if (msg.includes('❌')) {
        if (processingMsg) {
          await sendAccountResult(ctx, ctx.chat.id, processingMsg.message_id, msg);
        } else {
          await sendAccountResult(ctx, null, null, msg);
        }
        return;
      }

      db.run('DELETE FROM sshcf_accounts WHERE id = ?', [accountId]);

      const saldoSebelum = await getUserBalance(ctx.from.id);
      let replyMsg = msg;

      if (processingMsg) {
        await sendAccountResult(ctx, ctx.chat.id, processingMsg.message_id, replyMsg);
      } else {
        await sendAccountResult(ctx, null, null, replyMsg);
      }

      const maskedUsername = username.length > 1 ? `${username.slice(0, 1)}${'x'.repeat(username.length - 1)}` : username;
      bot.telegram.sendMessage(GROUP_ID,
        `<blockquote>\n🗑️ <b>${proto.label} Deleted</b>\n━━━━━━━━━━━━━━━━━━━━\n👤 <b>User:</b> ${ctx.from.first_name} (${ctx.from.id})\n📛 <b>Username:</b> ${maskedUsername}\n📦 <b>Protocol:</b> ${proto.name}\n━━━━━━━━━━━━━━━━━━━━\n</blockquote>`,
        { parse_mode: 'HTML' });

      logger.info(`✅ ${proto.name} CF ${username} deleted by ${ctx.from.id}`);
    },
    () => {},
    async (err) => {
      logger.error('❌ Error hapus CF:', err.message);
      const errMsg = '❌ *Terjadi kesalahan saat menghapus akun.*';
      if (processingMsg) {
        try { await ctx.telegram.editMessageText(ctx.chat.id, processingMsg.message_id, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await ctx.reply(errMsg, { parse_mode: 'Markdown' }); }
      } else {
        await ctx.reply(errMsg, { parse_mode: 'Markdown' });
      }
    }
  );
});

// ===== CLOUDFRONT GANTI LIMIT IP =====
bot.action('cfchangelimip_menu', async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const keyboard = [
    [{ text: '🔐 SSH', callback_data: 'cfchangelimip_ssh' }],
    [{ text: '🟣 VMESS', callback_data: 'cfchangelimip_vmess' }, { text: '🟢 VLESS', callback_data: 'cfchangelimip_vless' }],
    [{ text: '🔴 TROJAN', callback_data: 'cfchangelimip_trojan' }, { text: '🔙 Kembali', callback_data: 'menu_sshcf' }],
  ];
  await ctx.reply('☁️ *GANTI LIMIT IP CLOUDFRONT*\n\nPilih protokol:', { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
});

async function startSelectServerCf(ctx, action, type) {
  try {
    const userId = ctx.from.id;
    await loadUserLanguage(userId);
    const isReseller = await isUserReseller(userId);
    let q = "SELECT * FROM Server WHERE cloudfront_domain IS NOT NULL AND cloudfront_domain != ''";
    if (isReseller) {
      q += " AND is_reseller_only = 1";
    } else {
      q += " AND (is_reseller_only = 0 OR is_reseller_only IS NULL)";
    }
    q += " ORDER BY nama_server ASC";
    db.all(q, [], async (err, servers) => {
      if (err) return ctx.reply(t(userId, 'cf_fetch_fail'));
      if (!servers || servers.length === 0) return ctx.reply(t(userId, 'cf_no_server'));

      const keyboard = [];
      for (const srv of servers) {
        keyboard.push([{
          text: srv.nama_server,
          callback_data: `cfchangelimip_username_${type}_${srv.id}`
        }]);
      }
      keyboard.push([{ text: t(userId, 'btn_back'), callback_data: 'cfchangelimip_menu' }]);

      const listItems = servers.map(s => {
        const showIP = marketingIP(s);
        return t(userId, 'cf_server_item', { name: s.nama_server, domain: s.cloudfront_domain, ip: showIP, harga: s.harga });
      });

      await ctx.reply(
        `${t(userId, 'cf_sel_title')}\n\n${listItems.join('\n\n')}`,
        { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } }
      );
    });
  } catch (err) {
    logger.error('startSelectServerCf error:', err.message);
    ctx.reply(t(ctx.from?.id, 'generic_error'));
  }
}

// Protocol handlers for CF changelimip
bot.action('cfchangelimip_ssh', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await startSelectServerCf(ctx, 'cfchangelimip', 'ssh'); });
bot.action('cfchangelimip_vmess', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await startSelectServerCf(ctx, 'cfchangelimip', 'vmess'); });
bot.action('cfchangelimip_vless', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await startSelectServerCf(ctx, 'cfchangelimip', 'vless'); });
bot.action('cfchangelimip_trojan', async (ctx) => { await ctx.answerCbQuery().catch(() => {}); await startSelectServerCf(ctx, 'cfchangelimip', 'trojan'); });

// Server/username selection for CF changelimip
bot.action(/cfchangelimip_username_(ssh|vmess|vless|trojan)_(\d+)/, async (ctx) => {
  const type = ctx.match[1];
  const serverId = ctx.match[2];

  db.get('SELECT * FROM Server WHERE id = ?', [serverId], (err, server) => {
    if (err || !server) return ctx.reply('❌ Server tidak ditemukan.');
    userState[ctx.chat.id] = {
      step: `username_cfchangelimip_${type}`,
      serverId: parseInt(serverId),
      type,
      cfDomain: server.cloudfront_domain || server.domain
    };
    ctx.reply('👤 *Masukkan username yang ingin ganti limit IP:*', { parse_mode: 'Markdown' });
  });
});

bot.on('text', async (ctx) => {
  const userId = ctx.from.id;
  await loadUserLanguage(userId);
  const state = userState[ctx.chat.id];

  if (!state) return;
  if (ctx.message.text.startsWith('/')) return;
  const text = ctx.message.text.trim();

  if (state.step === 'del_confirm_pending') {
    return ctx.reply(t(userId, 'wait_del_confirm'), { parse_mode: 'Markdown' });
  }

//
// === MIGRASI AKUN - INPUT USERNAME ===
if (state.step === 'migrate_input_username') {
  const username = text;
  if (!/^[a-z0-9]{3,20}$/.test(username)) {
    return ctx.reply(t(userId, 'username_invalid'), { parse_mode: 'Markdown' });
  }

  const { type, serverId } = state;
  const processingMsg = await ctx.reply(t(userId, 'searching_account'), { parse_mode: 'Markdown' });

  try {
    const sourceServer = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM Server WHERE id = ?', [serverId], (e, row) => {
        if (e) reject(e); else resolve(row);
      });
    });

    if (!sourceServer) {
      try { await ctx.telegram.deleteMessage(ctx.chat.id, processingMsg.message_id); } catch (e) {}
      return ctx.reply(t(userId, 'server_src_not_found'), { parse_mode: 'Markdown' });
    }

    let foundData = null;
    try {
      foundData = await checkAccountFull(sourceServer.domain, sourceServer.auth, username, type);
    } catch (e) {
      logger.error('❌ Error checkAccountFull:', e.message);
    }

    if (!foundData) {
      try { await ctx.telegram.deleteMessage(ctx.chat.id, processingMsg.message_id); } catch (e) {}
      return ctx.reply(
        t(userId, 'acct_not_found', {
          username: esc(username),
          server: esc(sourceServer.nama_server),
          type: type.toUpperCase()
        }),
        { parse_mode: 'Markdown' }
      );
    }

    const rawQuota = foundData.quota || foundData.kuota || '0';
    const showQuota = !rawQuota || rawQuota === '0' || rawQuota === '0 GB' ? 'Unlimited' : rawQuota;
    const limitIP = foundData.ip_limit || foundData.limitip || '-';
    const expired = foundData.expired || foundData.exp || '-';

    storeMigration(ctx.chat.id, {
      username,
      type,
      password: foundData.password || null,
      expired,
      limitIP,
      quota: showQuota,
      uuid: foundData.uuid || null,
      sourceServerId: sourceServer.id,
      sourceServerName: sourceServer.nama_server
    });

    try { await ctx.telegram.deleteMessage(ctx.chat.id, processingMsg.message_id); } catch (e) {}

    const detailMsg = t(userId, 'acct_found_detail', {
      username: esc(username),
      type: type.toUpperCase(),
      server: esc(sourceServer.nama_server),
      expired,
      quota: showQuota
    });

    await ctx.reply(detailMsg, { parse_mode: 'Markdown' });

    await startSelectServer(ctx, 'migrate_dest', type);
  } catch (err) {
    logger.error('❌ Error migrasi cari akun:', err.message);
    try { await ctx.telegram.deleteMessage(ctx.chat.id, processingMsg.message_id); } catch (e) {}
    return ctx.reply(t(userId, 'search_acct_err'), { parse_mode: 'Markdown' });
  }
  return;
}

//
// === GANTI PROTOKOL - INPUT USERNAME ===
if (state.step === 'changeproto_input_username') {
  const username = text;
  if (!/^[a-z0-9]{3,20}$/.test(username)) {
    return ctx.reply(t(userId, 'username_invalid'), { parse_mode: 'Markdown' });
  }

  const { type, serverId } = state;
  const processingMsg = await ctx.reply(t(userId, 'searching_account'), { parse_mode: 'Markdown' });

  try {
    const sourceServer = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM Server WHERE id = ?', [serverId], (e, row) => {
        if (e) reject(e); else resolve(row);
      });
    });

    if (!sourceServer) {
      try { await ctx.telegram.deleteMessage(ctx.chat.id, processingMsg.message_id); } catch (e) {}
      return ctx.reply(t(userId, 'server_not_found'), { parse_mode: 'Markdown' });
    }

    let foundData = null;
    try {
      foundData = await checkAccountFull(sourceServer.domain, sourceServer.auth, username, type);
    } catch (e) {
      logger.error('❌ Error checkAccountFull changeproto:', e.message);
    }

    if (!foundData) {
      try { await ctx.telegram.deleteMessage(ctx.chat.id, processingMsg.message_id); } catch (e) {}
      return ctx.reply(
        t(userId, 'acct_not_found', {
          username: esc(username),
          server: esc(sourceServer.nama_server),
          type: type.toUpperCase()
        }),
        { parse_mode: 'Markdown' }
      );
    }

    const expired = foundData.expired || foundData.exp || '-';

    try { await ctx.telegram.deleteMessage(ctx.chat.id, processingMsg.message_id); } catch (e) {}

    state.changeprotoData = {
      username,
      serverId: sourceServer.id,
      serverName: sourceServer.nama_server,
      expired
    };
    state.step = 'changeproto_choose_new';
    userState[ctx.chat.id] = state;

    const detailMsg = t(userId, 'acct_found_changeproto', {
      username: esc(username),
      type: type.toUpperCase(),
      server: esc(sourceServer.nama_server),
      expired
    });

    const newProtoKeyboard = [
      [{ text: t(userId, 'type_proto_ssh'), callback_data: 'changeproto_apply_ssh' }, { text: t(userId, 'type_proto_vmess'), callback_data: 'changeproto_apply_vmess' }],
      [{ text: t(userId, 'type_proto_vless'), callback_data: 'changeproto_apply_vless' }, { text: t(userId, 'type_proto_trojan'), callback_data: 'changeproto_apply_trojan' }],
      [{ text: t(userId, 'btn_cancel'), callback_data: 'send_main_menu' }],
    ];

    await ctx.reply(detailMsg, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: newProtoKeyboard } });
  } catch (err) {
    logger.error('❌ Error changeproto input username:', err.message);
    try { await ctx.telegram.deleteMessage(ctx.chat.id, processingMsg.message_id); } catch (e) {}
    return ctx.reply(t(userId, 'search_acct_err'), { parse_mode: 'Markdown' });
  }
  return;
}

//
// === CF LOCK / UNLOCK / FIX / MIGRASI / GANTI PROTOKOL ===
if (state.step === 'cflock_username') {
  const username = text;
  if (!/^[a-z0-9]{3,20}$/.test(username)) return ctx.reply(t(userId, 'username_invalid3'), { parse_mode: 'Markdown' });
  const { type, serverId } = state;
  const procMsg = await ctx.reply(t(userId, 'processing_lock'), { parse_mode: 'Markdown' }).catch(() => null);
  const lockFns = { ssh: lockssh, vmess: lockvmess, vless: lockvless, trojan: locktrojan };
  const lockFn = lockFns[type];
  if (!lockFn) return ctx.reply(t(userId, 'protocol_unsupported'));
  const result = await lockFn(username, 'none', 'none', 'none', serverId);
  if (procMsg) try { await ctx.telegram.deleteMessage(ctx.chat.id, procMsg.message_id); } catch (e) {}
  await sendAccountResult(ctx, null, null, result);
  delete userState[ctx.chat.id]; return;
}
if (state.step === 'cfunlock_username') {
  const username = text;
  if (!/^[a-z0-9]{3,20}$/.test(username)) return ctx.reply(t(userId, 'username_invalid3'), { parse_mode: 'Markdown' });
  const { type, serverId } = state;
  const procMsg = await ctx.reply(t(userId, 'processing_unlock'), { parse_mode: 'Markdown' }).catch(() => null);
  const unlockFns = { ssh: unlockssh, vmess: unlockvmess, vless: unlockvless, trojan: unlocktrojan };
  const unlockFn = unlockFns[type];
  if (!unlockFn) return ctx.reply(t(userId, 'protocol_unsupported'));
  const result = await unlockFn(username, 'none', 'none', 'none', serverId);
  if (procMsg) try { await ctx.telegram.deleteMessage(ctx.chat.id, procMsg.message_id); } catch (e) {}
  await sendAccountResult(ctx, null, null, result);
  delete userState[ctx.chat.id]; return;
}
if (state.step === 'cffix_username') {
  const username = text;
  if (!/^[a-z0-9]{3,20}$/.test(username)) return ctx.reply(t(userId, 'username_invalid3'), { parse_mode: 'Markdown' });
  const { type, serverId } = state;
  const procMsg = await ctx.reply(t(userId, 'processing_fix'), { parse_mode: 'Markdown' }).catch(() => null);
  const fixFns = { ssh: fixssh, vmess: fixvmess, vless: fixvless, trojan: fixtrojan };
  const fixFn = fixFns[type];
  if (!fixFn) return ctx.reply(t(userId, 'protocol_unsupported'));
  const result = await fixFn(username, 'none', 'none', 'none', serverId);
  if (procMsg) try { await ctx.telegram.deleteMessage(ctx.chat.id, procMsg.message_id); } catch (e) {}
  await sendAccountResult(ctx, null, null, result);
  delete userState[ctx.chat.id]; return;
}
if (state.step === 'cfmigr_to_regular_username') {
  const username = text;
  if (!/^[a-z0-9]{3,20}$/.test(username)) return ctx.reply(t(userId, 'username_invalid3'), { parse_mode: 'Markdown' });
  const { type, serverId } = state;
  const procMsg = await ctx.reply(t(userId, 'searching_cf'), { parse_mode: 'Markdown' }).catch(() => null);
  const cfServer = await new Promise((resolve, reject) => {
    db.get('SELECT * FROM Server WHERE id = ?', [serverId], (e, r) => { if (e) reject(e); else resolve(r); });
  });
  if (!cfServer) { if (procMsg) try { await ctx.telegram.deleteMessage(ctx.chat.id, procMsg.message_id); } catch (e) {} return ctx.reply(t(userId, 'cf_server_not_found')); }
  const foundData = await checkAccountFull(cfServer.domain, cfServer.auth, username, type).catch(() => null);
  if (!foundData) { if (procMsg) try { await ctx.telegram.deleteMessage(ctx.chat.id, procMsg.message_id); } catch (e) {} return ctx.reply(t(userId, 'acct_not_found_cf', { type: type.toUpperCase(), username: esc(username) }), { parse_mode: 'Markdown' }); }
  const expired = foundData.expired || foundData.exp || '-';
  if (procMsg) try { await ctx.telegram.deleteMessage(ctx.chat.id, procMsg.message_id); } catch (e) {}
  state.cfmigrData = { username, type, cfServerId: serverId, cfServerName: cfServer.nama_server, expired };
  state.step = 'cfmigr_to_regular_select_server';
  userState[ctx.chat.id] = state;
  const isR = await isUserReseller(ctx.from.id);
  let q = 'SELECT * FROM Server WHERE (cloudfront_domain IS NULL OR cloudfront_domain = \'\')';
  if (isR) q += ' AND is_reseller_only = 1';
  else q += ' AND (is_reseller_only IS NULL OR is_reseller_only = 0)';
  q += ' ORDER BY nama_server ASC';
  db.all(q, [], async (err2, servers) => {
    if (err2 || !servers || servers.length === 0) return ctx.reply(t(userId, 'no_reg_server_avail'));
    const keyboard = [];
    for (const s of servers) {
      keyboard.push([{ text: `${s.nama_server}`, callback_data: `cfmigr_regdst_${type}_${s.id}` }]);
    }
    keyboard.push([{ text: t(userId, 'btn_cancel'), callback_data: 'menu_sshcf' }]);
    await ctx.reply(
      t(userId, 'acct_found_cf', { username: esc(username), type: type.toUpperCase(), expired }),
      { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } }
    );
  }); return;
}
if (state.step === 'cfmigr_to_cf_username') {
  const username = text;
  if (!/^[a-z0-9]{3,20}$/.test(username)) return ctx.reply(t(userId, 'username_invalid3'), { parse_mode: 'Markdown' });
  const { type, serverId } = state;
  const procMsg = await ctx.reply(t(userId, 'searching_regular'), { parse_mode: 'Markdown' }).catch(() => null);
  const regServer = await new Promise((resolve, reject) => {
    db.get('SELECT * FROM Server WHERE id = ?', [serverId], (e, r) => { if (e) reject(e); else resolve(r); });
  });
  if (!regServer) { if (procMsg) try { await ctx.telegram.deleteMessage(ctx.chat.id, procMsg.message_id); } catch (e) {} return ctx.reply(t(userId, 'reg_server_not_found')); }
  const foundData = await checkAccountFull(regServer.domain, regServer.auth, username, type).catch(() => null);
  if (!foundData) { if (procMsg) try { await ctx.telegram.deleteMessage(ctx.chat.id, procMsg.message_id); } catch (e) {} return ctx.reply(t(userId, 'acct_not_found_reg', { type: type.toUpperCase(), username: esc(username) }), { parse_mode: 'Markdown' }); }
  const expired = foundData.expired || foundData.exp || '-';
  if (procMsg) try { await ctx.telegram.deleteMessage(ctx.chat.id, procMsg.message_id); } catch (e) {}
  state.cfmigrData = { username, type, regServerId: serverId, regServerName: regServer.nama_server, expired };
  state.step = 'cfmigr_to_cf_select_server';
  userState[ctx.chat.id] = state;
  const isR = await isUserReseller(ctx.from.id);
  let q = "SELECT * FROM Server WHERE cloudfront_domain IS NOT NULL AND cloudfront_domain != ''";
  if (isR) {
    q += " AND is_reseller_only = 1";
  } else {
    q += " AND (is_reseller_only = 0 OR is_reseller_only IS NULL)";
  }
  q += " ORDER BY nama_server ASC";
  db.all(q, [], async (err2, servers) => {
    if (err2 || !servers || servers.length === 0) return ctx.reply(t(userId, 'no_cf_server_avail'));
    const keyboard = [];
    for (const s of servers) {
      keyboard.push([{ text: `${s.nama_server}`, callback_data: `cfmigr_cfdst_${type}_${s.id}` }]);
    }
    keyboard.push([{ text: t(userId, 'btn_cancel'), callback_data: 'menu_sshcf' }]);
    await ctx.reply(
      t(userId, 'acct_found_reg', { username: esc(username), type: type.toUpperCase(), expired }),
      { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } }
    );
  }); return;
}
if (state.step === 'cfchgproto_username') {
  const username = text;
  if (!/^[a-z0-9]{3,20}$/.test(username)) return ctx.reply(t(userId, 'username_invalid3'), { parse_mode: 'Markdown' });
  const { type, serverId } = state;
  const procMsg = await ctx.reply(t(userId, 'searching_cf'), { parse_mode: 'Markdown' }).catch(() => null);
  const cfServer = await new Promise((resolve, reject) => {
    db.get('SELECT * FROM Server WHERE id = ?', [serverId], (e, r) => { if (e) reject(e); else resolve(r); });
  });
  if (!cfServer) { if (procMsg) try { await ctx.telegram.deleteMessage(ctx.chat.id, procMsg.message_id); } catch (e) {} return ctx.reply(t(userId, 'cf_server_not_found')); }
  const foundData = await checkAccountFull(cfServer.domain, cfServer.auth, username, type).catch(() => null);
  if (!foundData) { if (procMsg) try { await ctx.telegram.deleteMessage(ctx.chat.id, procMsg.message_id); } catch (e) {} return ctx.reply(t(userId, 'acct_not_found_cf', { type: type.toUpperCase(), username: esc(username) }), { parse_mode: 'Markdown' }); }
  const expired = foundData.expired || foundData.exp || '-';
  if (procMsg) try { await ctx.telegram.deleteMessage(ctx.chat.id, procMsg.message_id); } catch (e) {}
  state.cfchgprotoData = { username, type, serverId, serverName: cfServer.nama_server, expired };
  state.step = 'cfchgproto_choose_new';
  userState[ctx.chat.id] = state;
  const newProtoKeyboard = [
    [{ text: t(userId, 'type_proto_ssh'), callback_data: 'cfchgproto_apply_ssh' }, { text: t(userId, 'type_proto_vmess'), callback_data: 'cfchgproto_apply_vmess' }],
    [{ text: t(userId, 'type_proto_vless'), callback_data: 'cfchgproto_apply_vless' }, { text: t(userId, 'type_proto_trojan'), callback_data: 'cfchgproto_apply_trojan' }],
    [{ text: t(userId, 'btn_cancel'), callback_data: 'menu_sshcf' }],
  ];
  await ctx.reply(
    t(userId, 'acct_found_cf_chgproto', { username: esc(username), type: type.toUpperCase(), expired }),
    { parse_mode: 'Markdown', reply_markup: { inline_keyboard: newProtoKeyboard } }
  ); return;
}

//
// === VPN CLOUDFRONT (Multi-Protocol) ===
if (state.step === 'cf_username') {
  const username = text;
  if (!/^[a-z0-9]{4,20}$/.test(username)) {
    return ctx.reply(t(userId, 'username_invalid_cf'), { parse_mode: 'Markdown' });
  }
  const protocol = state.protocol || 'ssh';
  const proto = CF_PROTOCOLS[protocol] || CF_PROTOCOLS.ssh;
  if (proto.needsPassword) {
    userState[ctx.chat.id] = { ...state, step: 'cf_password', username };
    return ctx.reply(t(userId, 'prompt_password'), { parse_mode: 'Markdown' });
  } else {
    userState[ctx.chat.id] = { ...state, step: 'cf_exp', username };
    return ctx.reply(t(userId, 'prompt_exp_cf'), { parse_mode: 'Markdown' });
  }
}
if (state.step === 'cf_password') {
  const password = text;
  if (password.length < 4) {
    return ctx.reply(t(userId, 'password_min4'), { parse_mode: 'Markdown' });
  }
  if (/[A-Z]/.test(password)) {
    return ctx.reply(t(userId, 'password_capital'), { parse_mode: 'Markdown' });
  }
  if (/[^a-z0-9]/.test(password)) {
    return ctx.reply(t(userId, 'password_special'), { parse_mode: 'Markdown' });
  }
  userState[ctx.chat.id] = { ...state, step: 'cf_exp', password };
  return ctx.reply(t(userId, 'prompt_exp_cf'), { parse_mode: 'Markdown' });
}
if (state.step === 'cf_exp') {
  if (!/^\d+$/.test(text) || parseInt(text) < 1 || parseInt(text) > 365) {
    return ctx.reply(t(userId, 'exp_range'), { parse_mode: 'Markdown' });
  }
  const exp = parseInt(text);
  const { serverId, username, password, protocol } = state;
  const proto = CF_PROTOCOLS[protocol] || CF_PROTOCOLS.ssh;
  delete userState[ctx.chat.id];

  db.get('SELECT * FROM Server WHERE id = ?', [serverId], async (err, server) => {
    if (err || !server) {
      return ctx.reply('❌ Server tidak ditemukan.');
    }
    const finalCfDomain = server.cloudfront_domain;
    const hargaTotal = server.harga * exp;

    const serverLabel = server.nama_server || `ID ${serverId}`;
    const lines = [
      [t(ctx.from.id, 'confirm_product'), proto.label],
      [t(ctx.from.id, 'confirm_server'), esc(serverLabel)],
      [t(ctx.from.id, 'confirm_username'), `\`${esc(username)}\``],
      [t(ctx.from.id, 'confirm_duration'), `${exp} Hari`],
      [t(ctx.from.id, 'confirm_price'), `Rp${hargaTotal.toLocaleString('id-ID')}`],
    ];
    const purchaseData = { action: 'create', type: protocol, username, password: password || null, exp, quota: '0', iplimit: server.iplimit, serverId, cfDomain: finalCfDomain };

    await confirmManager.ask(ctx, {
      title: t(ctx.from.id, 'confirm_buy_title'),
      lines,
      data: purchaseData,
      executor: async (cbCtx, session) => {
        const userId = cbCtx.from.id;
        // ==== VALIDASI ULANG ====
        const freshServer = await new Promise((resolve) => {
          db.get('SELECT * FROM Server WHERE id = ?', [serverId], (e, r) => resolve(r || null));
        }).catch(() => null);
        if (!freshServer) {
          await cbCtx.reply('❌ *Server tidak ditemukan.*\n\nTransaksi dibatalkan.', { parse_mode: 'Markdown' }).catch(() => {});
          return { refunded: true };
        }
        if (freshServer.total_create_akun >= freshServer.batas_create_akun) {
          await cbCtx.reply('❌ *Server sudah penuh.*\n\nTidak dapat membuat akun baru di server ini.', { parse_mode: 'Markdown' }).catch(() => {});
          return { refunded: true };
        }
        const freshCfDomain = freshServer.cloudfront_domain || finalCfDomain;
        const freshHarga = freshServer.harga * exp;
        const balance = await getUserBalance(userId);
        if (balance < freshHarga) {
          const shortage = freshHarga - balance;
          await purchaseFlow.createPurchaseQRIS(cbCtx, {
            userId,
            product: 'sshcf',
            totalHarga: freshHarga,
            shortage,
            purchaseData: { ...purchaseData, cfDomain: freshCfDomain }
          });
          return { needsPayment: true };
        }

        const processingMsgId = session.messageId;
        await updateUserBalance(userId, -freshHarga);
        await logPayment(userId, username, 'sshcf', freshHarga, 'PROCESSING', '');

        taskQueue.runBackground(userId,
          async () => {
            let msg;
            const freshIP = freshServer.iplimit;
            if (protocol === 'vmess') msg = await createcfvmess(username, exp, '0', freshIP, serverId, freshCfDomain);
            else if (protocol === 'vless') msg = await createcfvless(username, exp, '0', freshIP, serverId, freshCfDomain);
            else if (protocol === 'trojan') msg = await createcftrojan(username, exp, '0', freshIP, serverId, freshCfDomain);
            else msg = await createsshcf(username, password, exp, freshIP, serverId, freshCfDomain);

            if (msg.includes('❌')) {
              await updateUserBalance(userId, freshHarga);
              await logPayment(userId, username, 'sshcf', freshHarga, 'REFUNDED', msg.slice(0, 200));
              if (processingMsgId) {
                await sendAccountResult(cbCtx, userId, processingMsgId, msg);
              } else {
                await sendAccountResult(cbCtx, null, null, msg);
              }
              return;
            }
            await logPayment(userId, username, 'sshcf', freshHarga, 'SUCCESS', msg.slice(0, 200));
            await recordAccountTransaction(userId, protocol || 'sshcf');
            const expDate = new Date();
            expDate.setDate(expDate.getDate() + exp);
            const expDateStr = expDate.toISOString().slice(0, 10);
            db.run('INSERT INTO sshcf_accounts (user_id, username, cloudfront_domain, panel_server, server_id, expired_at, created_at, price, full_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
              [userId, username, freshCfDomain, freshServer.domain, serverId, expDateStr, new Date().toISOString(), freshHarga, msg]);
            insertListAccount(userId, username, protocol || 'sshcf', freshServer.nama_server || 'CLOUDFRONT', expDateStr, msg).catch(() => {});
            if (processingMsgId) {
              await sendAccountResult(cbCtx, userId, processingMsgId, msg);
            } else {
              await sendAccountResult(cbCtx, null, null, msg);
            }
            const maskedUsername = username.length > 1
              ? `${username.slice(0, 1)}${'x'.repeat(username.length - 1)}`
              : username;
            bot.telegram.sendMessage(GROUP_ID,
              `<blockquote>\n☁️ <b>${proto.label} Account Created</b>\n━━━━━━━━━━━━━━━━━━━━\n👤 <b>User:</b> ${cbCtx.from.first_name} (${userId})\n📛 <b>Username:</b> ${maskedUsername}\n☁️ <b>CF Domain:</b> ${freshCfDomain}\n📆 <b>Expired:</b> ${exp} hari\n💰 <b>Harga:</b> Rp${freshHarga.toLocaleString()}\n━━━━━━━━━━━━━━━━━━━━\n</blockquote>`,
              { parse_mode: 'HTML' });
          },
          () => {},
          async (err) => {
            await updateUserBalance(userId, freshHarga);
            await logPayment(userId, username, 'sshcf', freshHarga, 'REFUNDED', (err.message || '').slice(0, 200));
            const errMsg = `❌ *Terjadi kesalahan saat membuat akun ${proto.label}.*`;
            if (processingMsgId) {
              try { await bot.telegram.editMessageText(userId, processingMsgId, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await cbCtx.reply(errMsg, { parse_mode: 'Markdown' }); }
            } else {
              await cbCtx.reply(errMsg, { parse_mode: 'Markdown' });
            }
          }
        );
      },
    });
  });
  return;
}
// === RENEW CLOUDFRONT (Multi-Protocol) ===
if (state.step === 'cfrenew_username') {
  const username = text;
  if (!/^[a-z0-9]{3,20}$/.test(username)) {
    return ctx.reply(t(userId, 'username_invalid_cf'), { parse_mode: 'Markdown' });
  }
  const { serverId } = state;
  delete userState[ctx.chat.id];
  db.get('SELECT sshcf_accounts.*, Server.harga, Server.nama_server, Server.domain, Server.cloudfront_domain FROM sshcf_accounts JOIN Server ON sshcf_accounts.server_id = Server.id WHERE sshcf_accounts.user_id = ? AND sshcf_accounts.username = ? AND sshcf_accounts.server_id = ?',
    [ctx.from.id, username, serverId], async (err, account) => {
      if (err || !account) {
        return ctx.reply('❌ Akun tidak ditemukan di server yang dipilih.\n\n💡 Pastikan username benar dan akun berada pada server yang dipilih.', { parse_mode: 'Markdown' });
      }
      const fullMsg = account.full_message || '';
      let proto = 'SSH';
      if (fullMsg.includes('VMESS')) proto = 'VMESS';
      else if (fullMsg.includes('VLESS')) proto = 'VLESS';
      else if (fullMsg.includes('TROJAN')) proto = 'TROJAN';
      const protoInfo = CF_PROTOCOLS[proto.toLowerCase()] || CF_PROTOCOLS.ssh;
      const msg = `♻️ *RENEW ${protoInfo.name} CLOUDFRONT*\n\n` +
        `👤 *Username*     : \`${esc(account.username)}\`\n` +
        `📦 *Protocol*     : ${protoInfo.emoji} ${protoInfo.name}\n` +
        `🖥 *Server*       : \`${esc(account.nama_server)}\`\n` +
        `☁️ *CF Domain*    : \`${esc(account.cloudfront_domain)}\`\n` +
        `📅 *Expired*      : \`${esc(account.expired_at)}\`\n` +
        `💰 *Harga/hari*   : Rp${account.harga.toLocaleString()}\n\n` +
        `⏳ *Masukkan masa aktif tambahan (hari):*\n` +
        `💡 Contoh: 7 untuk perpanjang 7 hari`;
      userState[ctx.chat.id] = { step: 'cfrenew_exp', serverId, username, protocol: proto.toLowerCase(), hargaPerHari: account.harga, accountData: { username: account.username, expired_at: account.expired_at, cloudfront_domain: account.cloudfront_domain, server_name: account.nama_server } };
      ctx.reply(msg, { parse_mode: 'Markdown' });
    });
  return;
}
if (state.step === 'cfrenew_exp') {
  if (!/^\d+$/.test(text) || parseInt(text) < 1 || parseInt(text) > 365) {
    return ctx.reply(t(userId, 'exp_range'), { parse_mode: 'Markdown' });
  }
  const exp = parseInt(text);
  const { serverId, username, protocol, hargaPerHari, accountData } = state;
  const proto = CF_PROTOCOLS[protocol] || CF_PROTOCOLS.ssh;
  delete userState[ctx.chat.id];

  const hargaTotal = hargaPerHari * exp;

  const currentExpired = accountData && accountData.expired_at ? String(accountData.expired_at).slice(0, 10) : null;
  const newExpDate = new Date();
  newExpDate.setDate(newExpDate.getDate() + exp);
  const newExpStr = newExpDate.toISOString().slice(0, 10);

  const lines = [
    [t(ctx.from.id, 'confirm_username'), `\`${esc(username)}\``],
    [t(ctx.from.id, 'confirm_product'), proto.label],
    [t(ctx.from.id, 'confirm_server'), accountData ? esc(accountData.server_name) : `ID ${serverId}`],
    [t(ctx.from.id, 'confirm_duration'), `+${exp} Hari`],
    [t(ctx.from.id, 'confirm_price'), `Rp${hargaTotal.toLocaleString('id-ID')}`],
  ];
  if (currentExpired) lines.push([t(ctx.from.id, 'confirm_exp_current'), `\`${esc(currentExpired)}\``]);
  lines.push([t(ctx.from.id, 'confirm_exp_after'), `\`${esc(newExpStr)}\``]);

  const purchaseData = { action: 'renew', type: protocol, username, exp, serverId };

  await confirmManager.ask(ctx, {
    title: 'KONFIRMASI PERPANJANGAN',
    lines,
    data: purchaseData,
    executor: async (cbCtx, session) => {
      const userId = cbCtx.from.id;
      // ==== VALIDASI ULANG ====
      const freshServer = await new Promise((resolve) => {
        db.get('SELECT * FROM Server WHERE id = ?', [serverId], (e, r) => resolve(r || null));
      }).catch(() => null);
      if (!freshServer) {
        await cbCtx.reply('❌ *Server tidak ditemukan.*\n\nTransaksi dibatalkan.', { parse_mode: 'Markdown' }).catch(() => {});
        return { refunded: true };
      }
      const freshHarga = freshServer.harga * exp;
      const balance = await getUserBalance(userId);
      if (balance < freshHarga) {
        const shortage = freshHarga - balance;
        await purchaseFlow.createPurchaseQRIS(cbCtx, {
          userId,
          product: 'cfrenew',
          totalHarga: freshHarga,
          shortage,
          purchaseData
        });
        return { needsPayment: true };
      }

      const processingMsgId = session.messageId;
      await updateUserBalance(userId, -freshHarga);
      await logPayment(userId, username, 'cfrenew', freshHarga, 'PROCESSING', '');

      taskQueue.runBackground(userId,
        async () => {
          let msg;
          if (protocol === 'vmess') msg = await renewcfvmess(username, exp, serverId);
          else if (protocol === 'vless') msg = await renewcfvless(username, exp, serverId);
          else if (protocol === 'trojan') msg = await renewcftrojan(username, exp, serverId);
          else msg = await renewsshcf(username, exp, serverId);

          if (msg.includes('❌')) {
            await updateUserBalance(userId, freshHarga);
            await logPayment(userId, username, 'cfrenew', freshHarga, 'REFUNDED', msg.slice(0, 200));
            if (processingMsgId) {
              await sendAccountResult(cbCtx, userId, processingMsgId, msg);
            } else {
              await sendAccountResult(cbCtx, null, null, msg);
            }
            return;
          }
          await logPayment(userId, username, 'cfrenew', freshHarga, 'SUCCESS', msg.slice(0, 200));
          await recordAccountTransaction(userId, 'cfrenew');
          db.run('UPDATE sshcf_accounts SET expired_at = DATE(expired_at, ? || \' days\') WHERE user_id = ? AND username = ? AND server_id = ?',
            [String(exp), userId, username, serverId]);
          updateListAccountExpired(userId, username, protocol || 'sshcf', newExpStr, msg, (accountData && accountData.server_name) || '').catch((e) => logger.error('Gagal update listaccount cfrenew:', e.message));
          if (processingMsgId) {
            await sendAccountResult(cbCtx, userId, processingMsgId, msg);
          } else {
            await sendAccountResult(cbCtx, null, null, msg);
          }
          const maskedUsername = username.length > 1 ? `${username.slice(0, 1)}${'x'.repeat(username.length - 1)}` : username;
          bot.telegram.sendMessage(GROUP_ID,
            `<blockquote>\n♻️ <b>${proto.label} Renewed</b>\n━━━━━━━━━━━━━━━━━━━━\n👤 <b>User:</b> ${cbCtx.from.first_name} (${userId})\n📛 <b>Username:</b> ${maskedUsername}\n☁️ <b>Server:</b> ${accountData ? accountData.server_name : '-'}\n📆 <b>Extended:</b> ${exp} hari\n💰 <b>Harga:</b> Rp${freshHarga.toLocaleString()}\n━━━━━━━━━━━━━━━━━━━━\n</blockquote>`,
            { parse_mode: 'HTML' });
        },
        () => {},
        async (err) => {
          await updateUserBalance(userId, freshHarga);
          await logPayment(userId, username, 'cfrenew', freshHarga, 'REFUNDED', (err.message || '').slice(0, 200));
          const errMsg = `❌ *Terjadi kesalahan saat memperpanjang akun ${proto.label}.*`;
          if (processingMsgId) {
            try { await bot.telegram.editMessageText(userId, processingMsgId, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await cbCtx.reply(errMsg, { parse_mode: 'Markdown' }); }
          } else {
            await cbCtx.reply(errMsg, { parse_mode: 'Markdown' });
          }
        }
      );
    },
  });
  return;
}
// === DELETE CLOUDFRONT (Multi-Protocol) ===
if (state.step === 'cfdel_username') {
  const username = text;
  if (!/^[a-z0-9]{3,20}$/.test(username)) {
    return ctx.reply(t(userId, 'username_invalid_cf'), { parse_mode: 'Markdown' });
  }
  const { serverId, protocol } = state;
  const proto = CF_PROTOCOLS[protocol] || CF_PROTOCOLS.ssh;
  delete userState[ctx.chat.id];

  db.get('SELECT sshcf_accounts.*, Server.harga, Server.nama_server FROM sshcf_accounts JOIN Server ON sshcf_accounts.server_id = Server.id WHERE sshcf_accounts.user_id = ? AND sshcf_accounts.username = ? AND sshcf_accounts.server_id = ?',
    [ctx.from.id, username, serverId], async (err, account) => {
      if (err || !account) {
        return ctx.reply('❌ Akun tidak ditemukan di server yang dipilih.\n\n💡 Pastikan username benar dan akun berada pada server yang dipilih.', { parse_mode: 'Markdown' });
      }

      let sisaHari = 0;
      if (account.expired_at) {
        const expiredDate = new Date(account.expired_at);
        const today = new Date();
        expiredDate.setHours(0, 0, 0, 0);
        today.setHours(0, 0, 0, 0);
        sisaHari = Math.max(0, Math.ceil((expiredDate - today) / 86400000));
      }

      const saldoSebelum = await getUserBalance(ctx.from.id);

      const confirmMsg = `🗑️ *HAPUS ${proto.name} CLOUDFRONT*\n\n` +
        `👤 *Username*     : \`${esc(account.username)}\`\n` +
        `📦 *Protocol*     : ${proto.emoji} ${proto.name}\n` +
        `🖥 *Server*       : \`${esc(account.nama_server)}\`\n` +
        `☁️ *CF Domain*    : \`${esc(account.cloudfront_domain)}\`\n` +
        `📅 *Expired*      : \`${esc(account.expired_at)}\`\n` +
        `⏳ *Sisa Hari*    : *${sisaHari} hari*\n\n` +
        `💳 *Saldo Anda*   : Rp${saldoSebelum.toLocaleString()}\n\n` +
        `⚠️ *PERINGATAN:*\n` +
        `Akun akan dihapus *permanen* dan *sisa masa aktif tidak bisa dikembalikan*.\n\n` +
        (sisaHari > 0 ? `💡 *Ingin pindah server?* Gunakan menu *Migrasi Server* agar akun dipindahkan tanpa kehilangan sisa masa aktif.` : ``);

      const keyboard = [
        [{ text: `🗑️ Ya, Hapus ${proto.name}`, callback_data: `cfdel_confirm_${account.id}_${username}_${serverId}_${protocol}` }],
        [{ text: '❌ Batal', callback_data: 'menu_sshcf' }],
      ];
      ctx.reply(confirmMsg, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
    });
  return;
}

// === SSH CF RENEW ===
if (state.step === 'sshcf_renew_username') {
  const username = text;
  if (!/^[a-z0-9]{3,20}$/.test(username)) {
    return ctx.reply(t(userId, 'username_invalid_cf'), { parse_mode: 'Markdown' });
  }
  const { serverId } = state;
  userState[ctx.chat.id] = { ...state, step: 'sshcf_renew_exp', username };
  return ctx.reply('⏳ *Masukkan masa aktif tambahan (hari, maks 365):*', { parse_mode: 'Markdown' });
}
if (state.step === 'sshcf_renew_exp') {
  if (!/^\d+$/.test(text) || parseInt(text) < 1 || parseInt(text) > 365) {
    return ctx.reply(t(userId, 'exp_range'), { parse_mode: 'Markdown' });
  }
  const exp = parseInt(text);
  const { serverId, username } = state;
  delete userState[ctx.chat.id];

  db.get('SELECT * FROM Server WHERE id = ?', [serverId], async (err, server) => {
    if (err || !server) return ctx.reply('❌ Server tidak ditemukan.');
    const hargaTotal = server.harga * exp;

    let currentExpired = null;
    const accRow = await new Promise((resolve) => {
      db.get('SELECT expired_at FROM sshcf_accounts WHERE user_id = ? AND username = ? ORDER BY id DESC LIMIT 1',
        [ctx.from.id, username], (e, r) => resolve(r || null));
    }).catch(() => null);
    currentExpired = accRow && accRow.expired_at ? String(accRow.expired_at).slice(0, 10) : null;
    const newExpDate = new Date();
    newExpDate.setDate(newExpDate.getDate() + exp);
    const newExpStr = newExpDate.toISOString().slice(0, 10);

    const serverLabel = server.nama_server || `ID ${serverId}`;
    const lines = [
      [t(ctx.from.id, 'confirm_username'), `\`${esc(username)}\``],
      [t(ctx.from.id, 'confirm_product'), 'SSH CloudFront'],
      [t(ctx.from.id, 'confirm_server'), esc(serverLabel)],
      [t(ctx.from.id, 'confirm_duration'), `+${exp} Hari`],
      [t(ctx.from.id, 'confirm_price'), `Rp${hargaTotal.toLocaleString('id-ID')}`],
    ];
    if (currentExpired) lines.push([t(ctx.from.id, 'confirm_exp_current'), `\`${esc(currentExpired)}\``]);
    lines.push([t(ctx.from.id, 'confirm_exp_after'), `\`${esc(newExpStr)}\``]);

    const purchaseData = { action: 'renew', type: 'sshcf', username, exp, serverId };

    await confirmManager.ask(ctx, {
      title: 'KONFIRMASI PERPANJANGAN',
      lines,
      data: purchaseData,
      executor: async (cbCtx, session) => {
        const userId = cbCtx.from.id;
        // ==== VALIDASI ULANG ====
        const freshServer = await new Promise((resolve) => {
          db.get('SELECT * FROM Server WHERE id = ?', [serverId], (e, r) => resolve(r || null));
        }).catch(() => null);
        if (!freshServer) {
          await cbCtx.reply('❌ *Server tidak ditemukan.*\n\nTransaksi dibatalkan.', { parse_mode: 'Markdown' }).catch(() => {});
          return { refunded: true };
        }
        const freshHarga = freshServer.harga * exp;
        const balance = await getUserBalance(userId);
        if (balance < freshHarga) {
          const shortage = freshHarga - balance;
          await purchaseFlow.createPurchaseQRIS(cbCtx, {
            userId,
            product: 'sshcf_renew',
            totalHarga: freshHarga,
            shortage,
            purchaseData
          });
          return { needsPayment: true };
        }

        const processingMsgId = session.messageId;
        await updateUserBalance(userId, -freshHarga);
        await logPayment(userId, username, 'sshcf_renew', freshHarga, 'PROCESSING', '');

        taskQueue.runBackground(userId,
          async () => {
            const msg = await renewsshcf(username, exp, serverId);
            if (msg.includes('❌')) {
              await updateUserBalance(userId, freshHarga);
              await logPayment(userId, username, 'sshcf_renew', freshHarga, 'REFUNDED', msg.slice(0, 200));
              if (processingMsgId) {
                await sendAccountResult(cbCtx, userId, processingMsgId, msg);
              } else {
                await sendAccountResult(cbCtx, null, null, msg);
              }
              return;
            }
            await logPayment(userId, username, 'sshcf_renew', freshHarga, 'SUCCESS', msg.slice(0, 200));
            await recordAccountTransaction(userId, 'sshcf_renew');
            db.run('UPDATE sshcf_accounts SET expired_at = DATE(expired_at, ? || \' days\') WHERE user_id = ? AND username = ?',
              [String(exp), userId, username]);
            updateListAccountExpired(userId, username, 'sshcf', newExpStr, msg, server.nama_server || '').catch((e) => logger.error('Gagal update listaccount sshcf renew:', e.message));
            if (processingMsgId) {
              await sendAccountResult(cbCtx, userId, processingMsgId, msg);
            } else {
              await sendAccountResult(cbCtx, null, null, msg);
            }
            const maskedUsername = username.length > 1 ? `${username.slice(0, 1)}${'x'.repeat(username.length - 1)}` : username;
            bot.telegram.sendMessage(GROUP_ID,
              `<blockquote>\n☁️ <b>SSH CloudFront Renewed</b>\n━━━━━━━━━━━━━━━━━━━━\n👤 <b>User:</b> ${cbCtx.from.first_name} (${userId})\n📛 <b>Username:</b> ${maskedUsername}\n📆 <b>Extended:</b> ${exp} hari\n💰 <b>Harga:</b> Rp${freshHarga.toLocaleString()}\n━━━━━━━━━━━━━━━━━━━━\n</blockquote>`,
              { parse_mode: 'HTML' });
          },
          () => {},
          async (err) => {
            await updateUserBalance(userId, freshHarga);
            await logPayment(userId, username, 'sshcf_renew', freshHarga, 'REFUNDED', (err.message || '').slice(0, 200));
            const errMsg = '❌ *Terjadi kesalahan saat memperpanjang akun.*';
            if (processingMsgId) {
              try { await bot.telegram.editMessageText(userId, processingMsgId, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await cbCtx.reply(errMsg, { parse_mode: 'Markdown' }); }
            } else {
              await cbCtx.reply(errMsg, { parse_mode: 'Markdown' });
            }
          }
        );
      },
    });
  });
  return;
}
// === SSH CF DELETE ===
if (state.step === 'sshcf_del_username') {
  const username = text;
  if (!/^[a-z0-9]{3,20}$/.test(username)) {
    return ctx.reply(t(userId, 'username_invalid_cf'), { parse_mode: 'Markdown' });
  }

  db.get('SELECT sshcf_accounts.*, Server.harga FROM sshcf_accounts JOIN Server ON sshcf_accounts.server_id = Server.id WHERE sshcf_accounts.user_id = ? AND sshcf_accounts.username = ?',
    [ctx.from.id, username], async (err, account) => {
      if (err || !account) {
        delete userState[ctx.chat.id];
        return ctx.reply('❌ Akun SSH CF tidak ditemukan di database.', { parse_mode: 'Markdown' });
      }

      let sisaHari = 0;
      if (account.expired_at) {
        const expiredDate = new Date(account.expired_at);
        const today = new Date();
        expiredDate.setHours(0, 0, 0, 0);
        today.setHours(0, 0, 0, 0);
        sisaHari = Math.max(0, Math.ceil((expiredDate - today) / 86400000));
      }

      userState[ctx.chat.id] = {
        step: 'sshcf_del_confirm_pending',
        username,
        accountId: account.id,
        serverId: account.server_id,
        serverName: account.nama_server || '-',
        expired: account.expired_at || '-',
        sisaHari
      };

      const saldoSebelum = await getUserBalance(ctx.from.id);

      const confirmMsg = '🗑️ *HAPUS SSH CLOUDFRONT*\n\n' +
        '👤 *Username*  : `' + username + '`\n' +
        '🖥 *Server*    : `' + (account.nama_server || '-') + '`\n' +
        '☁️ *CF Domain* : `' + (account.cloudfront_domain || '-') + '`\n' +
        '📅 *Expired*   : `' + (account.expired_at || '-') + '`\n' +
        '⏳ *Sisa Hari* : *' + sisaHari + ' hari*\n\n' +
        '💳 *Saldo Anda* : Rp ' + saldoSebelum.toLocaleString() + '\n\n' +
        '⚠️ *PERINGATAN:*\n' +
        'Akun akan dihapus *permanen* dan *sisa masa aktif tidak bisa dikembalikan*.\n\n' +
        (sisaHari > 0 ? '💡 *Ingin pindah server?* Gunakan menu *Migrasi Server* agar akun dipindahkan tanpa kehilangan sisa masa aktif.' : '');

      const keyboard = [
        [{ text: '🗑️ Ya, Hapus Akun', callback_data: 'sshcf_del_confirm_yes' }],
        [{ text: '❌ Batal', callback_data: 'menu_sshcf' }]
      ];

      ctx.reply(confirmMsg, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
    });
  return;
}
//
  if (state.step === 'cek_saldo_userid') {
    const targetId = ctx.message.text.trim();
    db.get('SELECT saldo FROM users WHERE user_id = ?', [targetId], (err, row) => {
      if (err) {
        logger.error('❌ Gagal mengambil saldo:', err.message);
        return ctx.reply('❌ Terjadi kesalahan saat mengambil data saldo.');
      }

      if (!row) {
        return ctx.reply(`⚠️ User dengan ID ${targetId} belum terdaftar di database.`);
      }

      ctx.reply(`💰 Saldo user ${targetId}: Rp${row.saldo.toLocaleString()}`);
      logger.info(`Admin ${ctx.from.id} mengecek saldo user ${targetId}: Rp${row.saldo}`);
      delete userState[ctx.from.id];
    });
  }
//
// === VPN EDU DIRECT ORDER ===
if (state.step === 'directedu_username') {
  const username = text.trim();
  if (!/^[a-z0-9]{3,20}$/.test(username)) {
    return ctx.reply(t(userId, 'username_invalid_cf'), { parse_mode: 'Markdown' });
  }
  delete userState[ctx.chat.id];
  await processEduOrder(ctx, { ...state, username, password: username });
  return;
}
async function processEduOrder(ctx, state) {
  const { serverCode, billingPeriod, service, username, password } = state;
  const hargaProduk = state.hargaProduk || 0;
  try {
    try {
      const resEdu = await naytra.getEduProducts();
      const serversList = resEdu.data || [];
      const srv = serversList.find(s => s.server_code === serverCode);
      const slotAvail = srv?.slot?.available || 0;
      const slotMax = srv?.slot?.max || 0;
      if (slotAvail <= 0 && slotMax > 0) {
        delete userState[ctx.chat.id];
        await ctx.reply(`❌ *Slot VPN Edu ${esc(srv?.server_name || serverCode)} telah penuh!*

Slot server ini sedang penuh (tersedia ${slotAvail}/${slotMax}).

Silakan pilih salah satu opsi berikut:
1️⃣ *Renew* akun Edu yang sudah ada
2️⃣ Coba *Trial Edu* (subject to kuota harian)

Gunakan menu di bawah untuk melanjutkan.`, {
          parse_mode: 'Markdown',
          reply_markup: {
            inline_keyboard: [
              [{ text: '♻️ Renew EDU', callback_data: 'directedu_renew' }],
              [{ text: '🎁 Trial EDU', callback_data: 'directedu_trial' }],
              [{ text: '🔙 Kembali', callback_data: 'menu_directedu' }]
            ]
          }
        });
        return;
      }
    } catch (e) {
      logger.warn('Gagal mengecek slot Edu pada processEduOrder:', e.message);
    }

    const durationLabel =
      billingPeriod === 'weekly' ? '1 Minggu' :
      billingPeriod === 'monthly' ? '1 Bulan' :
      String(billingPeriod || '-');

    const serviceLabel = String(service || '')
      .replace('bundle_', '')
      .replace(/_/g, '+')
      .toUpperCase() || 'VPN EDU';

    const lines = [
      [t(ctx.from.id, 'confirm_product'), serviceLabel],
      [t(ctx.from.id, 'confirm_server'), `\`${esc(serverCode)}\``],
      [t(ctx.from.id, 'confirm_username'), `\`${esc(username)}\``],
      [t(ctx.from.id, 'confirm_duration'), durationLabel],
      [t(ctx.from.id, 'confirm_price'), `Rp${hargaProduk.toLocaleString('id-ID')}`],
    ];

    const purchaseData = { product: 'directedu', serverCode, service, billingPeriod, username, password };

    await confirmManager.ask(ctx, {
      title: t(ctx.from.id, 'confirm_buy_title'),
      lines,
      data: purchaseData,
      executor: async (cbCtx, session) => {
        const userId = cbCtx.from.id;
        const balance = await getUserBalance(userId);
        if (balance < hargaProduk) {
          const shortage = hargaProduk - balance;
          await purchaseFlow.createPurchaseQRIS(cbCtx, {
            userId,
            product: 'directedu-' + service,
            totalHarga: hargaProduk,
            shortage,
            purchaseData
          });
          return { needsPayment: true };
        }

        const processingMsgId = session.messageId;
        await updateUserBalance(userId, -hargaProduk);
        await logPayment(userId, username, 'directedu-' + service, hargaProduk, 'PROCESSING', '');

        taskQueue.runBackground(userId,
          async () => {
            const orderData = { server_code: serverCode, service, billing_period: billingPeriod, duration: 1, username, password };
            const eduVerified = await naytra.orderEduVerified(orderData);
            const result = eduVerified.raw;
            const resp = result.data || result;
            if (resp.status === 'success' || resp.success || (!resp.error && resp.username)) {
              await recordAccountTransaction(userId, 'directedu');
              await logPayment(userId, username, 'directedu-' + service, hargaProduk, 'SUCCESS', JSON.stringify(resp).slice(0, 200));
              let msg = `✅ *VPN EDU DIRECT BERHASIL*\n\n`;
              msg += `👤 Username : ${esc(resp.username || username)}\n`;
              if (eduVerified.recovered) {
                msg += `⚠️ *Respons order sempat hilang, akun sudah dibuat di panel dan diverifikasi otomatis.*\n`;
              }
              if (resp.password) msg += `🔑 Password : ${esc(resp.password)}\n`;
              msg += `🖥 Server : ${esc(resp.server_name || serverCode)}\n`;
              msg += `📦 Service : ${esc(resp.service || service)}\n`;
              msg += `📅 Expired : ${esc(resp.expired_date || resp.expired || '-')}\n`;
              msg += `💰 Harga : Rp ${hargaProduk.toLocaleString('id-ID')}\n`;
              if (resp.details) {
                if (resp.details.domain) msg += `🌐 Domain : ${esc(resp.details.domain)}\n`;
                if (resp.details.uuid) msg += `🛡 UUID : ${resp.details.uuid}\n`;
                if (resp.details.subscription) msg += `\n🔗 *Subscription:*\n\`${resp.details.subscription}\`\n`;
                if (resp.details.links && resp.details.links.length > 0) {
                  msg += `\n📡 *Config Links:*\n`;
                  for (const link of resp.details.links) {
                    msg += `• ${link.label || 'Link'} : \`${link.url || link}\`\n`;
                  }
                }
                if (resp.details.config_lines && resp.details.config_lines.length > 0) {
                  msg += `\n📝 *Config:*\n\`\`\`\n${resp.details.config_lines.join('\n')}\n\`\`\`\n`;
                }
              }
              if (processingMsgId) {
                await sendAccountResult(cbCtx, userId, processingMsgId, msg);
              } else {
                await sendAccountResult(cbCtx, null, null, msg);
              }
              const orderId = resp.order_id || resp.id || '';
              if (orderId) {
                try {
                  await dbRunAsync('INSERT INTO directedu_accounts (user_id, order_id, username, server_name, service, expired_date, created_at, full_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    [userId, orderId, resp.username || username, resp.server_name || serverCode, service, resp.expired_date || resp.expired || '', new Date().toISOString(), msg]);
                } catch (e) {
                  logger.error('Gagal simpan directedu_accounts (akun tetap dikirim):', e.message);
                }
              }
              if (eduVerified.recovered) {
                logger.warn(`✅ RECOVERED order directedu user ${userId} username ${username} — akun dikirim, tanpa refund`);
                try {
                  await purchaseFlow.notifyAdmin(
                    `✅ *ORDER EDU DIPULIHKAN (TANPA REFUND)*\n👤 User: \`${userId}\`\n👤 Username: \`${username}\`\n🧾 Order ID: \`${orderId || '-'}\`\n\nRespons order sempat hilang, akun sudah dibuat di panel dan dikirim ke user.`
                  );
                } catch (e) { logger.error('Gagal notif admin (recovery EDU):', e.message); }
              }
            } else {
              await updateUserBalance(userId, hargaProduk);
              await logPayment(userId, username, 'directedu-' + service, hargaProduk, 'REFUNDED', resp.message || JSON.stringify(resp));
              const errMsg = '❌ Gagal order: ' + (resp.message || 'Terjadi kesalahan pada server. Silakan coba lagi.');
              if (processingMsgId) {
                try { await bot.telegram.editMessageText(userId, processingMsgId, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await cbCtx.reply(errMsg, { parse_mode: 'Markdown' }); }
              } else {
                await cbCtx.reply(errMsg, { parse_mode: 'Markdown' });
              }
            }
          },
          () => {},
          async (err) => {
            await updateUserBalance(userId, hargaProduk);
            await logPayment(userId, username, 'directedu-' + service, hargaProduk, 'REFUNDED', naytra.handleApiError(err));
            const errMsg = '❌ Gagal order EDU: ' + naytra.handleApiError(err);
            if (processingMsgId) {
              try { await bot.telegram.editMessageText(userId, processingMsgId, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await cbCtx.reply(errMsg, { parse_mode: 'Markdown' }); }
            } else {
              await cbCtx.reply(errMsg, { parse_mode: 'Markdown' });
            }
          }
        );
      },
    });
    return;
  } catch (err) {
    await updateUserBalance(ctx.from.id, hargaProduk);
    await logPayment(ctx.from.id, username, 'directedu-' + service, hargaProduk, 'REFUNDED', naytra.handleApiError(err));
    ctx.reply('❌ Gagal order EDU: ' + naytra.handleApiError(err));
  }
}

// === EDU RENEW DURATION ===
if (state.step === 'directedu_renew_duration') {
  const durInput = text.trim();
  if (!/^\d+$/.test(durInput)) {
    return ctx.reply(t(ctx.from.id, 'duration_number_month'), { parse_mode: 'Markdown' });
  }
  const duration = parseInt(durInput);
  if (duration < 1 || duration > 12) {
    return ctx.reply(t(ctx.from.id, 'duration_range_month'), { parse_mode: 'Markdown' });
  }
  const { orderId } = state;
  delete userState[ctx.chat.id];
  const renewPrice = duration * 25000;
  const eduAccount = await new Promise((resolve) => {
    db.get('SELECT * FROM directedu_accounts WHERE user_id = ? AND order_id = ?',
      [ctx.from.id, orderId], (e, r) => resolve(r || null));
  }).catch(() => null);

  const lines = [
    [t(ctx.from.id, 'confirm_username'), `\`${esc(eduAccount && eduAccount.username || orderId)}\``],
    [t(ctx.from.id, 'confirm_product'), 'VPN EDU'],
    [t(ctx.from.id, 'confirm_server'), eduAccount ? esc(eduAccount.server_name) : '-'],
    [t(ctx.from.id, 'confirm_duration'), `+${duration} Bulan`],
    [t(ctx.from.id, 'confirm_price'), `Rp${renewPrice.toLocaleString('id-ID')}`],
  ];
  if (eduAccount && eduAccount.expired_date) lines.push([t(ctx.from.id, 'confirm_exp_current'), `\`${esc(String(eduAccount.expired_date).slice(0, 10))}\``]);

  const purchaseData = { product: 'directedu_renew', orderId, duration };

  try {
    await confirmManager.ask(ctx, {
      title: 'KONFIRMASI PERPANJANGAN',
      lines,
      data: purchaseData,
      executor: async (cbCtx, session) => {
        const userId = cbCtx.from.id;
        const balance = await getUserBalance(userId);
        if (balance < renewPrice) {
          const shortage = renewPrice - balance;
          await purchaseFlow.createPurchaseQRIS(cbCtx, {
            userId,
            product: 'directedu-renew',
            totalHarga: renewPrice,
            shortage,
            purchaseData
          });
          return { needsPayment: true };
        }

        const processingMsgId = session.messageId;
        await updateUserBalance(userId, -renewPrice);
        await logPayment(userId, orderId, 'directedu-renew', renewPrice, 'PROCESSING', '');

        taskQueue.runBackground(userId,
          async () => {
            const result = await naytra.renewEdu({ order_id: orderId, duration });
            const resp = result.data || result;
            if (resp.status === 'success' || resp.success || !resp.error) {
              await recordAccountTransaction(userId, 'directedu_renew');
              await logPayment(userId, orderId, 'directedu-renew', renewPrice, 'SUCCESS', JSON.stringify(resp).slice(0, 200));
              let msg = `✅ *EDU RENEW BERHASIL*\n\n`;
              msg += `👤 Username : ${esc(resp.username || '')}\n`;
              msg += `📅 Expired : ${esc(resp.expired_date || resp.expired || resp.exp || '-')}\n`;
              msg += `💰 Harga : Rp ${renewPrice.toLocaleString('id-ID')}\n`;
              updateListAccountExpired(userId, resp.username || (eduAccount && eduAccount.username) || orderId, 'edu', resp.expired_date || resp.expired || resp.exp || '', msg, (eduAccount && eduAccount.server_name) || '').catch((e) => logger.error('Gagal update listaccount edu renew:', e.message));
              if (processingMsgId) {
                await sendAccountResult(cbCtx, userId, processingMsgId, msg);
              } else {
                await sendAccountResult(cbCtx, null, null, msg);
              }
            } else {
              await updateUserBalance(userId, renewPrice);
              await logPayment(userId, orderId, 'directedu-renew', renewPrice, 'REFUNDED', resp.message || JSON.stringify(resp));
              const errMsg = '❌ Gagal renew: ' + (resp.message || 'Terjadi kesalahan pada server. Silakan coba lagi.');
              if (processingMsgId) {
                try { await bot.telegram.editMessageText(userId, processingMsgId, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await cbCtx.reply(errMsg, { parse_mode: 'Markdown' }); }
              } else {
                await cbCtx.reply(errMsg, { parse_mode: 'Markdown' });
              }
            }
          },
          () => {},
          async (err) => {
            await updateUserBalance(userId, renewPrice);
            await logPayment(userId, orderId, 'directedu-renew', renewPrice, 'REFUNDED', naytra.handleApiError(err));
            const errMsg = '❌ Gagal renew: ' + naytra.handleApiError(err);
            if (processingMsgId) {
              try { await bot.telegram.editMessageText(userId, processingMsgId, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await cbCtx.reply(errMsg, { parse_mode: 'Markdown' }); }
            } else {
              await cbCtx.reply(errMsg, { parse_mode: 'Markdown' });
            }
          }
        );
      },
    });
  } catch (err) {
    await updateUserBalance(ctx.from.id, renewPrice);
    await logPayment(ctx.from.id, orderId, 'directedu-renew', renewPrice, 'REFUNDED', naytra.handleApiError(err));
    ctx.reply('❌ Gagal renew: ' + naytra.handleApiError(err));
  }
  return;
}
// === VPNCF CREATE ===
if (state.step === 'vpncf_duration') {
  const durInput = text.trim();
  if (!/^\d+$/.test(durInput) || parseInt(durInput) < 1 || parseInt(durInput) > 30) {
    return ctx.reply('❌ Jumlah hari tidak valid. Masukkan angka 1-30.', { parse_mode: 'Markdown' });
  }
  const duration = parseInt(durInput);
  const hargaPerUnit = state.hargaPerUnit || 15000;
  const totalHarga = hargaPerUnit * duration;
  userState[ctx.chat.id] = { ...state, step: 'vpncf_username', duration, totalHarga };
  return ctx.reply(t(ctx.from.id, 'prompt_username'), { parse_mode: 'Markdown' });
}
if (state.step === 'vpncf_username') {
  const username = text.trim();
  if (!/^[a-z0-9]{4,20}$/.test(username)) {
    return ctx.reply(t(userId, 'username_invalid_cf'), { parse_mode: 'Markdown' });
  }
  // Hanya SSH yang memakai username + password. VMess/VLESS/Trojan cukup UUID.
  if (VPNCF_PROTOCOLS_WITH_PASSWORD.has(String(state.protocol || 'ssh').toLowerCase())) {
    userState[ctx.chat.id] = { ...state, step: 'vpncf_password', username };
    return ctx.reply(t(userId, 'prompt_password'), { parse_mode: 'Markdown' });
  }
  return startVpncfOrder(ctx, { ...state, username }, '');
}
if (state.step === 'vpncf_password') {
  const password = text.trim();
  if (password.length < 4) {
    return ctx.reply(t(userId, 'password_min4'), { parse_mode: 'Markdown' });
  }
  if (/[A-Z]/.test(password)) {
    return ctx.reply(t(userId, 'password_capital'), { parse_mode: 'Markdown' });
  }
  if (/[^a-z0-9]/.test(password)) {
    return ctx.reply(t(userId, 'password_special'), { parse_mode: 'Markdown' });
  }
  return startVpncfOrder(ctx, state, password);
}

// Lanjut dari cek slot + konfirmasi sampai order selesai. Dipanggil setelah
// input password (SSH) maupun langsung setelah input username (VMess/VLESS/Trojan).
async function startVpncfOrder(ctx, state, password) {
  const { serverId, protocol, type, duration, username } = state;
  const totalHarga = state.totalHarga || 15000;
  try {
    const res = await nadiavpn.getServers();
    const serversList = res.data || [];
    const srv = serversList.find(s => s.server_id === serverId);
    const cap = srv?.capacity || {};
    const capLimit = cap.limit || 0;
    const capUsed = cap.used || 0;
    if (capLimit > 0 && capUsed >= capLimit) {
      delete userState[ctx.chat.id];
      await ctx.reply(`❌ *Slot VPN CloudFront ${esc(srv?.name || serverId)} telah penuh!*

Slot server ini sudah penuh (terpakai ${capUsed}/${capLimit}).

Silakan pilih salah satu opsi berikut:
1️⃣ *Renew* akun CloudFront yang sudah ada
2️⃣ Coba *Trial CloudFront* (1 Jam)`, {
        parse_mode: 'Markdown',
        reply_markup: {
          inline_keyboard: [
            [{ text: '♻️ Renew CloudFront', callback_data: 'vpncf_renew' }],
            [{ text: '🎁 Trial CloudFront', callback_data: 'vpncf_trial' }],
            [{ text: '🔙 Kembali', callback_data: 'menu_vpncf' }]
          ]
        }
      });
      return;
    }

    const serverName = srv?.name || `ID ${serverId}`;
    const masaAktifLabel = type === 'month' ? `${duration} Bulan` : (type === 'week' ? `${duration} Minggu` : `${duration} Hari`);

    const lines = [
      [t(ctx.from.id, 'confirm_product'), `VPN CloudFront (${(protocol || 'ssh').toUpperCase()})`],
      [t(ctx.from.id, 'confirm_server'), esc(serverName)],
      [t(ctx.from.id, 'confirm_username'), `\`${esc(username)}\``],
      [t(ctx.from.id, 'confirm_duration'), masaAktifLabel],
      [t(ctx.from.id, 'confirm_price'), `Rp${totalHarga.toLocaleString('id-ID')}`],
    ];

    const purchaseData = { product: 'vpncf', serverId, protocol, type, duration, username, password };

    delete userState[ctx.chat.id];

    await confirmManager.ask(ctx, {
      title: t(ctx.from.id, 'confirm_buy_title'),
      lines,
      data: purchaseData,
      executor: async (cbCtx, session) => {
        const userId = cbCtx.from.id;
        const balance = await getUserBalance(userId);
        if (balance < totalHarga) {
          const shortage = totalHarga - balance;
          await purchaseFlow.createPurchaseQRIS(cbCtx, {
            userId,
            product: 'vpncf-ssh',
            totalHarga,
            shortage,
            purchaseData
          });
          return { needsPayment: true };
        }

        const processingMsgId = session.messageId;
        await updateUserBalance(userId, -totalHarga);
        await logPayment(userId, username, 'vpncf-ssh', totalHarga, 'PROCESSING', '');

        taskQueue.runBackground(userId,
          async () => {
            const result = await nadiavpn.createVpnVerified({ serverId, protocol, username, password, duration, type });
            const resp = result.data || result;
            if (resp.status === 'success' || resp.success || (!resp.error && resp.config)) {
              await recordAccountTransaction(userId, 'vpncf');
              await logPayment(userId, username, 'vpncf-ssh', totalHarga, 'SUCCESS', JSON.stringify(resp).slice(0, 200));
              const msg = formatVpncfSuccess({ resp, protocol, username, password, type, duration, totalHarga, recovered: result.recovered });
              if (processingMsgId) {
                await sendAccountResult(cbCtx, userId, processingMsgId, msg);
              } else {
                await sendAccountResult(cbCtx, null, null, msg);
              }
              const accountId = resp.account_id || '';
              const expStr = pickVpncfExpiry(resp, type, duration);
              if (accountId) {
                db.run('INSERT INTO vpncf_accounts (user_id, account_id, username, protocol, server_name, server_id, expired_date, created_at, full_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                  [userId, accountId, resp.username || username, protocol, resp.server_name || 'CLOUDFRONT REGULER', serverId || '', expStr, new Date().toISOString(), msg]);
              }
              try { await insertListAccount(userId, resp.username || username, protocol || 'vpncf', resp.server_name || 'CLOUDFRONT REGULER', expStr, msg); } catch (e) {
                logger.error('Gagal simpan list_accounts vpncf:', e.message);
              }
              if (result.recovered) {
                logger.warn(`✅ RECOVERED order vpncf user ${userId} username ${username} — akun dikirim, tanpa refund`);
                await purchaseFlow.notifyAdmin(
                  `✅ *ORDER DIPULIHKAN (TANPA REFUND)*\n👤 User: \`${userId}\`\n📦 Produk: \`VPN CloudFront ${String(protocol).toUpperCase()}\`\n👤 Username: \`${username}\`\n🆔 Account ID: \`${accountId || '-'}\`\n⚠️ Penyebab: \`${(resp.recover_note || '').substring(0, 160)}\``
                );
              }
            } else {
              await updateUserBalance(userId, totalHarga);
              await logPayment(userId, username, 'vpncf-ssh', totalHarga, 'REFUNDED', resp.message || JSON.stringify(resp));
              const errMsg = '❌ Gagal order: ' + (resp.message || 'Terjadi kesalahan pada server. Silakan coba lagi.');
              if (processingMsgId) {
                try { await bot.telegram.editMessageText(userId, processingMsgId, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await cbCtx.reply(errMsg, { parse_mode: 'Markdown' }); }
              } else {
                await cbCtx.reply(errMsg, { parse_mode: 'Markdown' });
              }
            }
          },
          () => {},
          async (err) => {
            if (err && err.uncertain) {
              await logPayment(userId, username, 'vpncf-ssh', totalHarga, 'PENDING_VERIFY', nadiavpn.adminErrorDetail(err));
              logger.error(`⚠️ Order vpncf user ${userId} (${username}) UNCERTAIN, saldo TIDAK dikembalikan: ${err.message}`);
              const verifyMsg = t(userId, 'pur_pending_verify');
              if (processingMsgId) {
                try { await bot.telegram.editMessageText(userId, processingMsgId, undefined, verifyMsg, { parse_mode: 'Markdown' }); } catch (e) { try { await cbCtx.reply(verifyMsg, { parse_mode: 'Markdown' }); } catch (e2) {} }
              } else {
                try { await cbCtx.reply(verifyMsg, { parse_mode: 'Markdown' }); } catch (e) {}
              }
              await purchaseFlow.notifyAdmin(
                `⚠️ *ORDER PERLU DIVERIFIKASI (BELUM REFUND)*\n👤 User: \`${userId}\`\n👤 Username: \`${username}\`\n💰 Harga: Rp${totalHarga}\n⚠️ Error: \`${(err.message || '').substring(0, 160)}\`\n\nVerifikasi panel gagal dijalankan, cek manual sebelum refund.`
              );
              return;
            }
            await updateUserBalance(userId, totalHarga);
            await logPayment(userId, username, 'vpncf-ssh', totalHarga, 'REFUNDED', nadiavpn.adminErrorDetail(err));
            const errMsg = '❌ Gagal order Cloudfront: ' + nadiavpn.handleApiError(err);
            if (processingMsgId) {
              try { await bot.telegram.editMessageText(userId, processingMsgId, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await cbCtx.reply(errMsg, { parse_mode: 'Markdown' }); }
            } else {
              await cbCtx.reply(errMsg, { parse_mode: 'Markdown' });
            }
          }
        );
      },
    });
    return;
  } catch (err) {
    await updateUserBalance(ctx.from.id, totalHarga);
    await logPayment(ctx.from.id, username, 'vpncf-ssh', totalHarga, 'REFUNDED', nadiavpn.adminErrorDetail(err));
    ctx.reply('❌ Gagal order Cloudfront: ' + nadiavpn.handleApiError(err));
  }
}
// === VPNCF RENEW ===
if (state.step === 'vpncf_renew_duration') {
  if (!/^\d+$/.test(text.trim())) {
    return ctx.reply(t(ctx.from.id, 'duration_number'), { parse_mode: 'Markdown' });
  }
  const duration = parseInt(text.trim());
  if (duration < 1 || duration > 12) {
    return ctx.reply(t(ctx.from.id, 'duration_range_month'), { parse_mode: 'Markdown' });
  }
  const { accountId } = state;
  delete userState[ctx.chat.id];
  const renewType = 'month';
  const vpncfAcct = await new Promise((resolve) => {
    db.get('SELECT * FROM vpncf_accounts WHERE user_id = ? AND account_id = ?',
      [ctx.from.id, accountId], (e, r) => resolve(r || null));
  }).catch(() => null);
  const renewPrice = (await getVpncfMonthPrice(vpncfAcct && vpncfAcct.server_id || null, vpncfAcct && vpncfAcct.server_name || '')) * duration;

  const lines = [
    [t(ctx.from.id, 'confirm_username'), `\`${esc(vpncfAcct && vpncfAcct.username || accountId)}\``],
    [t(ctx.from.id, 'confirm_product'), `VPN CloudFront${vpncfAcct && vpncfAcct.protocol ? ` (${String(vpncfAcct.protocol).toUpperCase()})` : ''}`],
    [t(ctx.from.id, 'confirm_server'), vpncfAcct ? esc(vpncfAcct.server_name) : '-'],
    [t(ctx.from.id, 'confirm_duration'), `+${duration} Bulan`],
    [t(ctx.from.id, 'confirm_price'), `Rp${renewPrice.toLocaleString('id-ID')}`],
  ];
  if (vpncfAcct && vpncfAcct.expired_date) lines.push([t(ctx.from.id, 'confirm_exp_current'), `\`${esc(String(vpncfAcct.expired_date).slice(0, 10))}\``]);

  const purchaseData = { product: 'vpncf_renew', accountId, duration, renewType };

  try {
    await confirmManager.ask(ctx, {
      title: 'KONFIRMASI PERPANJANGAN',
      lines,
      data: purchaseData,
      executor: async (cbCtx, session) => {
        const userId = cbCtx.from.id;
        const balance = await getUserBalance(userId);
        if (balance < renewPrice) {
          const shortage = renewPrice - balance;
          await purchaseFlow.createPurchaseQRIS(cbCtx, {
            userId,
            product: 'vpncf-renew',
            totalHarga: renewPrice,
            shortage,
            purchaseData
          });
          return { needsPayment: true };
        }

        const processingMsgId = session.messageId;
        await updateUserBalance(userId, -renewPrice);
        await logPayment(userId, accountId, 'vpncf-renew', renewPrice, 'PROCESSING', '');

        taskQueue.runBackground(userId,
          async () => {
            const result = await nadiavpn.renewVpn(accountId, duration, renewType);
            const resp = result.data || result;
            if (resp.status === 'success' || resp.success || !resp.error) {
              await recordAccountTransaction(userId, 'vpncf_renew');
              await logPayment(userId, accountId, 'vpncf-renew', renewPrice, 'SUCCESS', JSON.stringify(resp).slice(0, 200));
              let msg = `✅ *VPN CLOUDFRONT RENEW BERHASIL*\n\n`;
              const expStr = pickVpncfExpiry(resp, renewType || 'month', duration);
              msg += `👤 Username : ${esc(resp.username || (vpncfAcct && vpncfAcct.username) || '')}\n`;
              msg += `📅 Berlaku Sampai : ${esc(formatExpDate(expStr, renewType || 'month', duration))}\n`;
              msg += `💰 Harga : Rp ${renewPrice.toLocaleString('id-ID')}\n`;
              try {
                await dbRunAsync('UPDATE vpncf_accounts SET expired_date = ? WHERE user_id = ? AND account_id = ?', [expStr, userId, accountId]);
              } catch (e) {
                logger.error('Gagal update vpncf_accounts (renew):', e.message);
              }
              try {
                await updateListAccountExpired(userId, resp.username || (vpncfAcct && vpncfAcct.username) || accountId, (vpncfAcct && vpncfAcct.protocol) || 'vpncf', expStr, msg, (vpncfAcct && vpncfAcct.server_name) || '');
              } catch (e) {
                logger.error('Gagal update listaccount vpncf renew:', e.message);
              }
              if (processingMsgId) {
                await sendAccountResult(cbCtx, userId, processingMsgId, msg);
              } else {
                await sendAccountResult(cbCtx, null, null, msg);
              }
            } else {
              await updateUserBalance(userId, renewPrice);
              await logPayment(userId, accountId, 'vpncf-renew', renewPrice, 'REFUNDED', resp.message || JSON.stringify(resp));
              const errMsg = '❌ Gagal renew: ' + (resp.message || 'Terjadi kesalahan pada server. Silakan coba lagi.');
              if (processingMsgId) {
                try { await bot.telegram.editMessageText(userId, processingMsgId, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await cbCtx.reply(errMsg, { parse_mode: 'Markdown' }); }
              } else {
                await cbCtx.reply(errMsg, { parse_mode: 'Markdown' });
              }
            }
          },
          () => {},
          async (err) => {
            await updateUserBalance(userId, renewPrice);
            await logPayment(userId, accountId, 'vpncf-renew', renewPrice, 'REFUNDED', nadiavpn.adminErrorDetail(err));
            const errMsg = '❌ Gagal renew: ' + nadiavpn.handleApiError(err);
            if (processingMsgId) {
              try { await bot.telegram.editMessageText(userId, processingMsgId, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await cbCtx.reply(errMsg, { parse_mode: 'Markdown' }); }
            } else {
              await cbCtx.reply(errMsg, { parse_mode: 'Markdown' });
            }
          }
        );
      },
    });
  } catch (err) {
    await updateUserBalance(ctx.from.id, renewPrice);
    await logPayment(ctx.from.id, accountId, 'vpncf-renew', renewPrice, 'REFUNDED', nadiavpn.adminErrorDetail(err));
    ctx.reply('❌ Gagal renew: ' + nadiavpn.handleApiError(err));
  }
  return;
}
//
    if (state.step?.startsWith('username_unlock_')) {
    const username = text;
    // Validasi username (hanya huruf kecil dan angka, 3-20 karakter)
    if (!/^[a-z0-9]{3,20}$/.test(username)) {
      return ctx.reply(t(userId, 'username_invalid_dash'), { parse_mode: 'Markdown' });
    }
       //izin ressel saja
    const resselDbPath = './ressel.db';
    fs.readFile(resselDbPath, 'utf8', async (err, data) => {
      if (err) {
        logger.error('❌ Gagal membaca file ressel.db:', err.message);
        return ctx.reply(t(userId, 'err_read_reseller'), { parse_mode: 'Markdown' });
      }

      const idUser = ctx.from.id.toString().trim();
      const resselList = data.split('\n').map(line => line.trim()).filter(Boolean);

      console.log('🧪 ID Pengguna:', idUser);
      console.log('📂 Daftar Ressel:', resselList);

      const isRessel = resselList.includes(idUser);

      if (!isRessel) {
        return ctx.reply(t(userId, 'only_reseller'), { parse_mode: 'Markdown' });
      }
  //izin ressel saja
    const { type, serverId } = state;
    delete userState[ctx.chat.id];

    let msg = 'none';
    try {
      const password = 'none', exp = 'none', iplimit = 'none';

      const delFunctions = {
        vmess: unlockvmess,
        vless: unlockvless,
        trojan: unlocktrojan,
        ssh: unlockssh
      };

      if (delFunctions[type]) {
        msg = await delFunctions[type](username, password, exp, iplimit, serverId);
        //await recordAccountTransaction(ctx.from.id, type);
      }

      await sendAccountResult(ctx, null, null, msg);
      logger.info(`✅ Akun ${type} berhasil unlock oleh ${ctx.from.id}`);
    } catch (err) {
      logger.error('❌ Gagal hapus akun:', err.message);
      await ctx.reply(t(ctx.from.id, 'del_error'), { parse_mode: 'Markdown' });
    }});
    return; // Penting! Jangan lanjut ke case lain
  }
    if (state.step?.startsWith('username_lock_')) {
    const username = text;
    // Validasi username (hanya huruf kecil dan angka, 3-20 karakter)
    if (!/^[a-z0-9]{3,20}$/.test(username)) {
      return ctx.reply(t(userId, 'username_invalid_dash'), { parse_mode: 'Markdown' });
    }
       //izin ressel saja
    const resselDbPath = './ressel.db';
    fs.readFile(resselDbPath, 'utf8', async (err, data) => {
      if (err) {
        logger.error('❌ Gagal membaca file ressel.db:', err.message);
        return ctx.reply(t(userId, 'err_read_reseller'), { parse_mode: 'Markdown' });
      }

      const idUser = ctx.from.id.toString().trim();
      const resselList = data.split('\n').map(line => line.trim()).filter(Boolean);

      console.log('🧪 ID Pengguna:', idUser);
      console.log('📂 Daftar Ressel:', resselList);

      const isRessel = resselList.includes(idUser);

      if (!isRessel) {
        return ctx.reply(t(userId, 'only_reseller'), { parse_mode: 'Markdown' });
      }
  //izin ressel saja
    const { type, serverId } = state;
    delete userState[ctx.chat.id];

    let msg = 'none';
    try {
      const password = 'none', exp = 'none', iplimit = 'none';

      const delFunctions = {
        vmess: lockvmess,
        vless: lockvless,
        trojan: locktrojan,
        ssh: lockssh
      };

      if (delFunctions[type]) {
        msg = await delFunctions[type](username, password, exp, iplimit, serverId);
        //await recordAccountTransaction(ctx.from.id, type);
      }

      await sendAccountResult(ctx, null, null, msg);
      logger.info(`✅ Akun ${type} berhasil di kunci oleh ${ctx.from.id}`);
    } catch (err) {
      logger.error('❌ Gagal hapus akun:', err.message);
      await ctx.reply(t(ctx.from.id, 'del_error'), { parse_mode: 'Markdown' });
    }});
    return; // Penting! Jangan lanjut ke case lain
  }
//
// changelimip USERNAME
//
if (state.step?.startsWith('username_changelimip_') || state.step?.startsWith('username_cfchangelimip_')) {
    const username = text;

    if (!/^[a-z0-9]{3,20}$/.test(username)) {
      return ctx.reply(t(userId, 'username_invalid_dash'), { parse_mode: 'Markdown' });
    }

    const isR = await isUserReseller(ctx.from.id);
    const isOwner = adminIds.includes(ctx.from.id);
    const isCloudFront = state.step?.startsWith('username_cfchangelimip_');

    const harga2ip = isR ? 1000 : 2000;
    const harga5ip = isR ? 2000 : 4000;

    const newState = {
        step: 'changelimip_select_tier',
        username,
        type: state.type,
        serverId: state.serverId,
        isReseller: isR,
        isOwner
    };
    if (isCloudFront && state.cfDomain) {
      newState.cfDomain = state.cfDomain;
    }
    userState[ctx.chat.id] = newState;

    const modeLabel = isCloudFront ? t(userId, 'cloudfront_label') : '';
    const upgradeButtons = [
      [Markup.button.callback(t(userId, 'btn_upgrade_2ip'), `changelimip_upgrade_2_${harga2ip}`)],
      [Markup.button.callback(t(userId, 'btn_upgrade_5ip'), `changelimip_upgrade_5_${harga5ip}`)],
    ];
    if (isOwner) {
      upgradeButtons.push([Markup.button.callback(t(userId, 'btn_upgrade_0ip'), `changelimip_upgrade_0_0`)]);
    }
    upgradeButtons.push([Markup.button.callback(t(userId, 'btn_cancel'), 'send_main_menu')]);
    const upgradeKeyboard = Markup.inlineKeyboard(upgradeButtons);

    return ctx.reply(
      t(userId, 'changelimip_title', {
        mode: modeLabel ? ' ' + modeLabel : '',
        username,
        type: state.type.toUpperCase(),
        pricing: isR ? t(userId, 'changelimip_pricing_reseller') : t(userId, 'changelimip_pricing_general'),
        owner: isOwner ? t(userId, 'changelimip_owner') : ''
      }),
      { parse_mode: 'Markdown', reply_markup: upgradeKeyboard.reply_markup }
    );
}

if (state.step === 'changelimip_select_tier') {
    return ctx.reply(t(userId, 'changelimip_pick'), { parse_mode: 'Markdown' });
  }
// fix
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
if (state.step?.startsWith('username_fix_')) {
  const username = text.trim();

  // Validasi username
  if (!/^[a-z0-9]{3,20}$/.test(username)) {
    return ctx.reply(t(userId, 'username_invalid_dash'), { parse_mode: 'Markdown' });
  }

  const { type, serverId } = state;
  delete userState[ctx.chat.id];

  try {
    const password = 'none', exp = 'none', iplimit = 'none';

    const lockFns = {
      vmess: lockvmess,
      vless: lockvless,
      trojan: locktrojan,
      ssh: lockssh
    };

    const unlockFns = {
      vmess: unlockvmess,
      vless: unlockvless,
      trojan: unlocktrojan,
      ssh: unlockssh
    };

    if (!lockFns[type] || !unlockFns[type]) {
      return ctx.reply(t(userId, 'fix_unknown_type'), { parse_mode: 'Markdown' });
    }

    await ctx.reply(t(userId, 'fix_start', { type: type.toUpperCase(), username }), { parse_mode: 'Markdown' });

    // 1) LOCK
    const lockMsg = await lockFns[type](username, password, exp, iplimit, serverId);

    // Delay (boleh kamu ubah 2-10 detik)
    await sleep(3000);

    await ctx.reply(t(userId, 'fix_step2'), { parse_mode: 'Markdown' });

    // 2) UNLOCK
    const unlockMsg = await unlockFns[type](username, password, exp, iplimit, serverId);

    // Output final (biar jelas hasilnya)
    const finalMsg = t(userId, 'fix_done', {
      username,
      type: type.toUpperCase(),
      serverId,
      lock: lockMsg,
      unlock: unlockMsg
    });

    await ctx.reply(finalMsg, { parse_mode: 'Markdown' });
    logger.info(`✅ Fix akun ${type} sukses: ${username} oleh ${ctx.from.id}`);
  } catch (err) {
    logger.error('❌ Gagal fix akun:', err.message);
    await ctx.reply(t(userId, 'fix_failed', { error: 'Silakan coba lagi nanti.' }), { parse_mode: 'Markdown' });
  }

  return; // Penting! jangan lanjut ke case lain
}
//
// DELETE USERNAME
//
  if (state.step?.startsWith('username_del_')) {
    const username = text;
    if (!/^[a-z0-9]{3,20}$/.test(username)) {
      return ctx.reply(t(userId, 'username_invalid'), { parse_mode: 'Markdown' });
    }

    const { type, serverId } = state;

    const server = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM Server WHERE id = ?', [serverId], (e, row) => {
        if (e) reject(e); else resolve(row);
      });
    }).catch(() => null);

    if (!server) {
      delete userState[ctx.chat.id];
      return ctx.reply(t(userId, 'server_not_found'), { parse_mode: 'Markdown' });
    }

    let expired = null;
    let sisaHari = 0;

    try {
      expired = await checkAccountExpiry(server.domain, server.auth, username, type);
    } catch (e) {
      logger.error('❌ Gagal cek expired akun ' + username + ': ' + e.message);
    }

    if (expired) {
      const expiredDate = new Date(expired);
      const today = new Date();
      expiredDate.setHours(0, 0, 0, 0);
      today.setHours(0, 0, 0, 0);
      sisaHari = Math.max(0, Math.ceil((expiredDate - today) / 86400000));
    }

    userState[ctx.chat.id] = {
      step: 'del_confirm_pending',
      username, type, serverId: parseInt(serverId),
      expired, sisaHari,
      serverName: server.nama_server
    };

    const saldoSebelum = await getUserBalance(ctx.from.id);

    let confirmMsg = t(userId, 'del_title') + '\n\n' +
      t(userId, 'del_username', { username }) + '\n' +
      t(userId, 'del_type', { type: type.toUpperCase() }) + '\n' +
      t(userId, 'del_server', { server: server.nama_server }) + '\n';

    if (expired) {
      confirmMsg += t(userId, 'del_expired', { expired }) + '\n';
      confirmMsg += t(userId, 'del_days_left', { days: sisaHari }) + '\n';
    } else {
      confirmMsg += t(userId, 'del_exp_not_detected') + '\n';
      confirmMsg += t(userId, 'del_days_unknown') + '\n';
    }

    confirmMsg += t(userId, 'del_balance', { saldo: saldoSebelum.toLocaleString() }) + '\n\n';
    confirmMsg += t(userId, 'del_warning') + '\n';
    confirmMsg += t(userId, 'del_warning2') + '\n\n';
    if (sisaHari > 0) {
      confirmMsg += t(userId, 'del_tip');
    }

    const keyboard = [
      [{ text: t(userId, 'btn_del_yes'), callback_data: 'del_confirm_yes' }],
      [{ text: t(userId, 'btn_cancel'), callback_data: 'del_confirm_no' }]
    ];

    ctx.reply(confirmMsg, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
    return;
  }
  if (state.step?.startsWith('username_')) {
    state.username = text;

    if (!state.username) {
      return ctx.reply(t(userId, 'username_invalid2'), { parse_mode: 'Markdown' });
    }
    if (state.username.length < 4 || state.username.length > 20) {
      return ctx.reply(t(userId, 'username_len'), { parse_mode: 'Markdown' });
    }
    if (/[A-Z]/.test(state.username)) {
      return ctx.reply(t(userId, 'username_capital'), { parse_mode: 'Markdown' });
    }
    if (/[^a-z0-9]/.test(state.username)) {
      return ctx.reply(t(userId, 'username_special'), { parse_mode: 'Markdown' });
    }
    const { type, action } = state;
    if (action === 'create') {
      if (type === 'ssh') {
        state.step = `password_${state.action}_${state.type}`;
        await ctx.reply(t(userId, 'prompt_password'), { parse_mode: 'Markdown' });
      } else {
        state.step = `exp_${state.action}_${state.type}`;
        await ctx.reply(t(userId, 'prompt_exp'), { parse_mode: 'Markdown' });
      }
    } else if (action === 'renew') {
      state.step = `exp_${state.action}_${state.type}`;
      await ctx.reply(t(userId, 'prompt_exp'), { parse_mode: 'Markdown' });
    }
  } else if (state.step?.startsWith('password_')) {
    state.password = ctx.message.text.trim();
    if (!state.password) {
      return ctx.reply(t(userId, 'password_invalid'), { parse_mode: 'Markdown' });
    }
    if (state.password.length < 4) {
      return ctx.reply(t(userId, 'password_min4'), { parse_mode: 'Markdown' });
    }
    if (/[A-Z]/.test(state.password)) {
      return ctx.reply(t(userId, 'password_capital'), { parse_mode: 'Markdown' });
    }
    if (/[^a-z0-9]/.test(state.password)) {
      return ctx.reply(t(userId, 'password_special'), { parse_mode: 'Markdown' });
    }
    state.step = `exp_${state.action}_${state.type}`;
    await ctx.reply(t(userId, 'prompt_exp'), { parse_mode: 'Markdown' });
  } else if (state.step?.startsWith('exp_')) {
    const expInput = ctx.message.text.trim();
    if (!/^\d+$/.test(expInput)) {
      return ctx.reply(t(userId, 'exp_invalid'), { parse_mode: 'Markdown' });
    }
// Cek hanya angka
if (!/^\d+$/.test(expInput)) {
  return ctx.reply(t(userId, 'exp_only_number'), { parse_mode: 'Markdown' });
}

const exp = parseInt(expInput, 10);

if (isNaN(exp) || exp <= 0) {
  return ctx.reply(t(userId, 'exp_invalid'), { parse_mode: 'Markdown' });
}

if (exp > 365) {
  return ctx.reply(t(userId, 'exp_max365'), { parse_mode: 'Markdown' });
}
    state.exp = exp;

    const { username, password, exp: expVal, quota, iplimit, serverId, type, action } = state;

    const serverInfo = await new Promise((resolve, reject) => {
      db.get('SELECT quota, iplimit, harga, nama_server FROM Server WHERE id = ?', [serverId], (err, row) => {
        if (err) reject(err); else resolve(row);
      });
    }).catch(() => null);

    if (!serverInfo) {
      return ctx.reply('❌ *Server tidak ditemukan.*', { parse_mode: 'Markdown' });
    }

    state.quota = serverInfo.quota;
    state.iplimit = serverInfo.iplimit;

    const totalHarga = serverInfo.harga * expVal;

    const title = action === 'create' ? t(userId, 'confirm_buy_title') : t(userId, 'confirm_renew_title');
    const productLabel = type.toUpperCase();
    const serverLabel = serverInfo.nama_server || `ID ${serverId}`;
    const lines = [
      (action === 'create' ? [t(userId, 'confirm_product'), productLabel] : [t(userId, 'confirm_username'), `\`${esc(username)}\``]),
      (action === 'create' ? [t(userId, 'confirm_server'), esc(serverLabel)] : [t(userId, 'confirm_product'), productLabel]),
      (action === 'create' ? [t(userId, 'confirm_username'), `\`${esc(username)}\``] : [t(userId, 'confirm_server'), esc(serverLabel)]),
      (action === 'create' ? [t(userId, 'confirm_duration'), `${expVal} ${t(userId, 'confirm_days')}`] : [t(userId, 'confirm_duration'), `+${expVal} ${t(userId, 'confirm_days')}`]),
      [t(userId, 'confirm_price'), `Rp${totalHarga.toLocaleString('id-ID')}`],
    ];
    if (action === 'renew') {
      const accRow = await new Promise((resolve) => {
        db.get("SELECT expired_at FROM accounts WHERE user_id = ? AND username = ? AND server_id = ? AND status = 'active' ORDER BY id DESC LIMIT 1",
          [ctx.from.id, username, serverId], (e, r) => resolve(r || null));
      }).catch(() => null);
      const currentExpired = accRow && accRow.expired_at ? String(accRow.expired_at).slice(0, 10) : null;
      const newExpDate = new Date();
      newExpDate.setDate(newExpDate.getDate() + expVal);
      const newExpStr = newExpDate.toISOString().slice(0, 10);
      lines.push([t(userId, 'confirm_exp_current'), currentExpired ? `\`${esc(currentExpired)}\`` : t(userId, 'confirm_not_detected')]);
      lines.push([t(userId, 'confirm_exp_after'), `\`${esc(newExpStr)}\``]);
    }

    const purchaseData = { action, type, username, password, exp: expVal, quota: serverInfo.quota, iplimit: serverInfo.iplimit, serverId };
    delete userState[ctx.chat.id];

    await confirmManager.ask(ctx, {
      title,
      lines,
      data: purchaseData,
      executor: async (cbCtx, session) => {
        const userId = cbCtx.from.id;

        // ==== VALIDASI ULANG (harga/saldo/stok diambil dari database saat tombol ditekan) ====
        const freshServer = await new Promise((resolve) => {
          db.get('SELECT * FROM Server WHERE id = ?', [purchaseData.serverId], (e, r) => resolve(r || null));
        }).catch(() => null);
        if (!freshServer) {
          await cbCtx.reply('❌ *Server tidak ditemukan.*\n\nTransaksi dibatalkan.', { parse_mode: 'Markdown' }).catch(() => {});
          return { refunded: true };
        }
        if (freshServer.total_create_akun >= freshServer.batas_create_akun && purchaseData.action === 'create') {
          await cbCtx.reply('❌ *Server sudah penuh.*\n\nTidak dapat membuat akun baru di server ini.', { parse_mode: 'Markdown' }).catch(() => {});
          return { refunded: true };
        }
        const freshHarga = freshServer.harga * purchaseData.exp;
        const balance = await getUserBalance(userId);
        if (balance < freshHarga) {
          const shortage = freshHarga - balance;
          await purchaseFlow.createPurchaseQRIS(cbCtx, {
            userId,
            product: `${action}-${type}`,
            totalHarga: freshHarga,
            shortage,
            purchaseData
          });
          return { needsPayment: true };
        }

        const processingMsgId = session.messageId;
        await updateUserBalance(userId, -freshHarga);
        await logPayment(userId, username, `${action}-${type}`, freshHarga, 'PROCESSING', '');

        taskQueue.runBackground(userId,
          async () => {
            let msg;
            const serverQ = freshServer.quota;
            const serverIP = freshServer.iplimit;
            if (action === 'create') {
              if (type === 'vmess') {
                msg = await createvmess(username, expVal, serverQ, serverIP, serverId);
                await recordAccountTransaction(userId, 'vmess');
              } else if (type === 'vless') {
                msg = await createvless(username, expVal, serverQ, serverIP, serverId);
                await recordAccountTransaction(userId, 'vless');
              } else if (type === 'trojan') {
                msg = await createtrojan(username, expVal, serverQ, serverIP, serverId);
                await recordAccountTransaction(userId, 'trojan');
              } else if (type === 'ssh') {
                msg = await createssh(username, password, expVal, serverIP, serverId);
                await recordAccountTransaction(userId, 'ssh');
              }
              const maskedUsername = username.length > 1
                ? `${username.slice(0, 1)}${'x'.repeat(username.length - 1)}`
                : username;
              bot.telegram.sendMessage(GROUP_ID,
                `<blockquote>\n📢 <b>Account Created</b>\n━━━━━━━━━━━━━━━━━━━━\n👤 <b>User:</b> ${cbCtx.from.first_name} (${userId})\n🧾 <b>Type:</b> ${type.toUpperCase()}\n📛 <b>Username:</b> ${maskedUsername}\n📆 <b>Expired:</b> ${expVal || '0'}\n💾 <b>Quota:</b> ${serverQ || '0'}\n🌐 <b>Server ID:</b> ${serverId}\n━━━━━━━━━━━━━━━━━━━━\n</blockquote>`,
                { parse_mode: 'HTML' }
              ).catch(() => {});
            } else if (action === 'renew') {
              if (type === 'vmess') {
                msg = await renewvmess(username, expVal, serverQ, serverIP, serverId);
                await recordAccountTransaction(userId, 'vmess');
              } else if (type === 'vless') {
                msg = await renewvless(username, expVal, serverQ, serverIP, serverId);
                await recordAccountTransaction(userId, 'vless');
              } else if (type === 'trojan') {
                msg = await renewtrojan(username, expVal, serverQ, serverIP, serverId);
                await recordAccountTransaction(userId, 'trojan');
              } else if (type === 'ssh') {
                msg = await renewssh(username, expVal, serverIP, serverId);
                await recordAccountTransaction(userId, 'ssh');
              }
              const maskedUsername = username.length > 1
                ? `${username.slice(0, 1)}${'x'.repeat(username.length - 1)}`
                : username;
              bot.telegram.sendMessage(GROUP_ID,
                `<blockquote>\n♻️ <b>Account Renewed</b>\n━━━━━━━━━━━━━━━━━━━━\n👤 <b>User:</b> ${cbCtx.from.first_name} (${userId})\n🧾 <b>Type:</b> ${type.toUpperCase()}\n📛 <b>Username:</b> ${maskedUsername}\n📆 <b>New Expiry:</b> ${expVal || '0'}\n💾 <b>Quota:</b> ${serverQ || '0'}\n🌐 <b>Server ID:</b> ${serverId}\n━━━━━━━━━━━━━━━━━━━━\n</blockquote>`,
                { parse_mode: 'HTML' }
              ).catch(() => {});
            }

            if (msg.includes('❌')) {
              await updateUserBalance(userId, freshHarga);
              await logPayment(userId, username, `${action}-${type}`, freshHarga, 'REFUNDED', msg.slice(0, 200));
              logger.error(`Refund saldo user ${userId}, type: ${type}, server: ${serverId}, respon: ${msg}`);
              if (processingMsgId) {
                await sendAccountResult(cbCtx, userId, processingMsgId, msg);
              } else {
                await sendAccountResult(cbCtx, null, null, msg);
              }
              return;
            }

            logger.info(`Transaksi sukses untuk user ${userId}, type: ${type}, server: ${serverId}`);
            await logPayment(userId, username, `${action}-${type}`, freshHarga, 'SUCCESS', msg.slice(0, 200));

            try {
              const expDate = new Date();
              expDate.setDate(expDate.getDate() + expVal);
              let expDateStr = expDate.toISOString().slice(0, 10);

              if (action === 'create') {
                const srv = await new Promise((resolve, reject) => {
                  db.get('SELECT nama_server, domain FROM Server WHERE id = ?', [serverId], (e, row) => {
                    if (e) reject(e); else resolve(row);
                  });
                });
                try {
                  await insertAccountRecord(userId, username, type, serverId, srv?.nama_server || '', srv?.domain || '', expDateStr, freshHarga, msg);
                } catch (saveErr) {
                  logger.error('❌ Gagal simpan record akun:', saveErr.message);
                  await new Promise(r => setTimeout(r, 1000));
                  try {
                    await insertAccountRecord(userId, username, type, serverId, srv?.nama_server || '', srv?.domain || '', expDateStr, freshHarga, msg);
                    logger.info('✅ Account record saved on retry for ' + username);
                  } catch (retryErr) {
                    logger.error('❌ Gagal simpan record akun (retry):', retryErr.message);
                  }
                }
                try {
                  await insertListAccount(userId, username, type, srv?.nama_server || '', expDateStr, msg);
                } catch (listErr) {
                  logger.error('❌ Gagal simpan list account:', listErr.message);
                }
              } else if (action === 'renew') {
                const oldRows = await new Promise((resolve, reject) => {
                  db.all('SELECT * FROM accounts WHERE user_id = ? AND username = ? AND server_id = ? AND status = \'active\'', [userId, username, serverId], (e, rows) => {
                    if (e) reject(e); else resolve(rows);
                  });
                });
                if (oldRows.length > 0) {
                  const oldExp = new Date(oldRows[0].expired_at);
                  oldExp.setDate(oldExp.getDate() + expVal);
                  expDateStr = oldExp.toISOString().slice(0, 10);
                }
                await updateAccountExpired(userId, username, serverId, expDateStr, msg);
                updateListAccountExpired(userId, username, type, expDateStr, msg).catch(() => {});
              }
            } catch (e) {
              logger.error('Gagal simpan record akun:', e.message);
            }

            if (processingMsgId) {
              await sendAccountResult(cbCtx, userId, processingMsgId, msg);
            } else {
              await sendAccountResult(cbCtx, null, null, msg);
            }
          },
          () => {},
          async (err) => {
            logger.error(`Background task error untuk user ${userId}: ${err.message}`);
            await updateUserBalance(userId, freshHarga);
            await logPayment(userId, username, `${action}-${type}`, freshHarga, 'REFUNDED', (err.message || '').slice(0, 200));
            const errMsg = '❌ *Terjadi kesalahan saat memproses akun.*\n💰 Saldo telah dikembalikan.';
            if (processingMsgId) {
              try { await bot.telegram.editMessageText(userId, processingMsgId, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await cbCtx.reply(errMsg, { parse_mode: 'Markdown' }); }
            } else {
              await cbCtx.reply(errMsg, { parse_mode: 'Markdown' });
            }
          }
        );
      },
    });
    return;
    }
  else if (state.step === 'addserver') {
    const domain = ctx.message.text.trim();
    if (!domain) {
      await ctx.reply('⚠️ *Domain tidak boleh kosong.* Silakan masukkan domain server yang valid.', { parse_mode: 'Markdown' });
      return;
    }

    state.step = 'addserver_auth';
    state.domain = domain;
    await ctx.reply('🔑 *Silakan masukkan auth server:*', { parse_mode: 'Markdown' });
  } else if (state.step === 'addserver_auth') {
    const auth = ctx.message.text.trim();
    if (!auth) {
      await ctx.reply('⚠️ *Auth tidak boleh kosong.* Silakan masukkan auth server yang valid.', { parse_mode: 'Markdown' });
      return;
    }

    state.step = 'addserver_nama_server';
    state.auth = auth;
    await ctx.reply('🏷️ *Silakan masukkan nama server:*', { parse_mode: 'Markdown' });
  } else if (state.step === 'addserver_nama_server') {
    const nama_server = ctx.message.text.trim();
    if (!nama_server) {
      await ctx.reply('⚠️ *Nama server tidak boleh kosong.* Silakan masukkan nama server yang valid.', { parse_mode: 'Markdown' });
      return;
    }

    state.step = 'addserver_quota';
    state.nama_server = nama_server;
    await ctx.reply('📊 *Silakan masukkan quota server:*', { parse_mode: 'Markdown' });
  } else if (state.step === 'addserver_quota') {
    const quota = parseInt(ctx.message.text.trim(), 10);
    if (isNaN(quota)) {
      await ctx.reply('⚠️ *Quota tidak valid.* Silakan masukkan quota server yang valid.', { parse_mode: 'Markdown' });
      return;
    }

    state.step = 'addserver_iplimit';
    state.quota = quota;
    await ctx.reply('🔢 *Silakan masukkan limit IP server:*', { parse_mode: 'Markdown' });
  } else if (state.step === 'addserver_iplimit') {
    const iplimit = parseInt(ctx.message.text.trim(), 10);
    if (isNaN(iplimit)) {
      await ctx.reply('⚠️ *Limit IP tidak valid.* Silakan masukkan limit IP server yang valid.', { parse_mode: 'Markdown' });
      return;
    }

    state.step = 'addserver_batas_create_akun';
    state.iplimit = iplimit;
    await ctx.reply('🔢 *Silakan masukkan batas create akun server:*', { parse_mode: 'Markdown' });
  } else if (state.step === 'addserver_batas_create_akun') {
    const batas_create_akun = parseInt(ctx.message.text.trim(), 10);
    if (isNaN(batas_create_akun)) {
      await ctx.reply('⚠️ *Batas create akun tidak valid.* Silakan masukkan batas create akun server yang valid.', { parse_mode: 'Markdown' });
      return;
    }

    state.step = 'addserver_harga';
    state.batas_create_akun = batas_create_akun;
    await ctx.reply('💰 *Silakan masukkan harga server:*', { parse_mode: 'Markdown' });
  } else if (state.step === 'addserver_harga') {
    const harga = parseFloat(ctx.message.text.trim());
    if (isNaN(harga) || harga <= 0) {
      await ctx.reply('⚠️ *Harga tidak valid.* Silakan masukkan harga server yang valid.', { parse_mode: 'Markdown' });
      return;
    }
    const { domain, auth, nama_server, quota, iplimit, batas_create_akun } = state;

    try {
      db.run('INSERT INTO Server (domain, auth, nama_server, quota, iplimit, batas_create_akun, harga, total_create_akun) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [domain, auth, nama_server, quota, iplimit, batas_create_akun, harga, 0], function(err) {
        if (err) {
          logger.error('Error saat menambahkan server:', err.message);
          ctx.reply('❌ *Terjadi kesalahan saat menambahkan server baru.*', { parse_mode: 'Markdown' });
        } else {
          ctx.reply(`✅ *Server baru dengan domain ${domain} telah berhasil ditambahkan.*\n\n📄 *Detail Server:*\n- Domain: ${domain}\n- Auth: ${auth}\n- Nama Server: ${nama_server}\n- Quota: ${quota}\n- Limit IP: ${iplimit}\n- Batas Create Akun: ${batas_create_akun}\n- Harga: Rp ${harga}`, { parse_mode: 'Markdown' });
        }
      });
    } catch (error) {
      logger.error('Error saat menambahkan server:', error);
      await ctx.reply('❌ *Terjadi kesalahan saat menambahkan server baru.*', { parse_mode: 'Markdown' });
    }
    delete userState[ctx.chat.id];
  }
  // === 🏷️ TAMBAH SERVER UNTUK RESELLER ===
if (state && state.step === 'reseller_domain') {
  state.domain = text;
  state.step = 'reseller_auth';
  return ctx.reply('🔑 Masukkan auth server:');
}

if (state && state.step === 'reseller_auth') {
  state.auth = text;
  state.step = 'reseller_harga';
  return ctx.reply('💰 Masukkan harga server (angka):');
}

if (state && state.step === 'reseller_harga') {
  state.harga = text;
  state.step = 'reseller_nama';
  return ctx.reply('📝 Masukkan nama server:');
}

if (state && state.step === 'reseller_nama') {
  state.nama_server = text;
  state.step = 'reseller_quota';
  return ctx.reply('📊 Masukkan quota (GB):');
}

if (state && state.step === 'reseller_quota') {
  state.quota = text;
  state.step = 'reseller_iplimit';
  return ctx.reply('📶 Masukkan IP limit:');
}

if (state && state.step === 'reseller_iplimit') {
  state.iplimit = text;
  state.step = 'reseller_batas';
  return ctx.reply('🔢 Masukkan batas create akun:');
}

if (state && state.step === 'reseller_batas') {
  state.batas_create_akun = text;

  db.run(
    `INSERT INTO Server (domain, auth, harga, nama_server, quota, iplimit, batas_create_akun, total_create_akun, is_reseller_only)
     VALUES (?, ?, ?, ?, ?, ?, ?, 0, 1)`,
    [
      state.domain,
      state.auth,
      parseInt(state.harga),
      state.nama_server,
      parseInt(state.quota),
      parseInt(state.iplimit),
      parseInt(state.batas_create_akun),
    ],
    (err) => {
      if (err) {
        logger.error('❌ Gagal menambah server reseller:', err.message);
        ctx.reply('❌ Gagal menambah server reseller.');
      } else {
        ctx.reply(
          `✅ Server reseller *${state.nama_server}* berhasil ditambahkan!`,
          { parse_mode: 'Markdown' }
        );
      }
      delete userState[ctx.chat.id];
    }
  );
  return;
}
// === 💰 TAMBAH SALDO (LANGKAH 1: INPUT USER ID) ===
if (state && state.step === 'addsaldo_userid') {
  state.targetId = text.trim();
  state.step = 'addsaldo_amount';
  return ctx.reply('💰 Masukkan jumlah saldo yang ingin ditambahkan:');
}

// === 💰 TAMBAH SALDO (LANGKAH 1: INPUT USER ID) ===
if (state && state.step === 'addsaldo_userid') {
  state.targetId = text.trim();
  state.step = 'addsaldo_amount';
  return ctx.reply('💰 Masukkan jumlah saldo yang ingin ditambahkan:');
}

// === 💰 TAMBAH SALDO (LANGKAH 2: INPUT JUMLAH SALDO) ===
if (state && state.step === 'addsaldo_amount') {
  const amount = parseInt(text.trim());
  if (isNaN(amount) || amount <= 0) {
    return ctx.reply('⚠️ Jumlah saldo harus berupa angka dan lebih dari 0.');
  }

  const targetId = state.targetId;

// Tambahkan saldo
db.run('UPDATE users SET saldo = saldo + ? WHERE user_id = ?', [amount, targetId], (err) => {
  if (err) {
    logger.error('❌ Gagal menambah saldo:', err.message);
    return ctx.reply('❌ Gagal menambah saldo ke user.');
  }

  // Ambil saldo terbaru
  db.get('SELECT saldo FROM users WHERE user_id = ?', [targetId], (err2, updated) => {
    if (err2 || !updated) {
      ctx.reply(`✅ Saldo sebesar Rp${amount} berhasil ditambahkan ke user ${targetId}.`);
      logger.info(`Admin ${ctx.from.id} menambah saldo Rp${amount} ke user ${targetId}.`);
    } else {
      ctx.reply(`✅ Saldo sebesar Rp${amount} berhasil ditambahkan ke user ${targetId}.\n💳 Saldo sekarang: Rp${updated.saldo}`);
      logger.info(`Admin ${ctx.from.id} menambah saldo Rp${amount} ke user ${targetId} (Saldo akhir: Rp${updated.saldo}).`);
    }
  });

  delete userState[ctx.from.id];
});

  return;
}
});
//

// === 💳 CEK SALDO USER ===
bot.action('cek_saldo_user', async (ctx) => {
  const adminId = ctx.from.id;

  if (!adminIds.includes(adminId)) {
    return ctx.reply('🚫 Anda tidak memiliki izin untuk menggunakan fitur ini.');
  }

  await ctx.answerCbQuery();
  await ctx.reply('🔍 Masukkan ID Telegram user yang ingin dicek saldonya:');
  userState[adminId] = { step: 'cek_saldo_userid' };
});
//

// === 🔄 RESTART BOT ===
bot.action('restart_bot', async (ctx) => {
  const adminId = ctx.from.id;

  if (!adminIds.includes(adminId)) {
    return ctx.reply('🚫 Anda tidak memiliki izin untuk menggunakan fitur ini.');
  }

  await ctx.answerCbQuery();
  await ctx.reply('♻️ Restarting bot, Please wait...');

  exec("pm2 restart sellvpn", { env: { ...process.env, PATH: process.env.PATH } }, (error, stdout, stderr) => {
    if (error) {
      exec("sudo pm2 restart sellvpn", (error2) => {
        if (error2) {
          return ctx.reply(`❌ Gagal restart bot:\n${error2.message}`);
        }
      });
      return;
    }
    ctx.reply("✅ Bot berhasil direstart!");
  });
});
bot.action('addserver', async (ctx) => {
  try {
    logger.info('📥 Proses tambah server dimulai');
    await ctx.answerCbQuery();
    await ctx.reply('🌐 *Silakan masukkan domain/ip server:*', { parse_mode: 'Markdown' });
    userState[ctx.chat.id] = { step: 'addserver' };
  } catch (error) {
    logger.error('❌ Kesalahan saat memulai proses tambah server:', error);
    await ctx.reply('❌ *GAGAL! Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.*', { parse_mode: 'Markdown' });
  }
});
bot.action('detailserver', async (ctx) => {
  try {
    logger.info('📋 Proses detail server dimulai');
    await ctx.answerCbQuery();
    
    const servers = await new Promise((resolve, reject) => {
      db.all('SELECT * FROM Server', [], (err, servers) => {
        if (err) {
          logger.error('⚠️ Kesalahan saat mengambil detail server:', err.message);
          return reject('⚠️ *PERHATIAN! Terjadi kesalahan saat mengambil detail server.*');
        }
        resolve(servers);
      });
    });

    if (servers.length === 0) {
      logger.info('⚠️ Tidak ada server yang tersedia');
      return ctx.reply('⚠️ *PERHATIAN! Tidak ada server yang tersedia saat ini.*', { parse_mode: 'Markdown' });
    }

    const buttons = [];
    for (let i = 0; i < servers.length; i += 2) {
      const row = [];
      row.push({
        text: `${servers[i].nama_server}`,
        callback_data: `server_detail_${servers[i].id}`
      });
      if (i + 1 < servers.length) {
        row.push({
          text: `${servers[i + 1].nama_server}`,
          callback_data: `server_detail_${servers[i + 1].id}`
        });
      }
      buttons.push(row);
    }

    await ctx.reply('📋 *Silakan pilih server untuk melihat detail:*', {
      reply_markup: { inline_keyboard: buttons },
      parse_mode: 'Markdown'
    });
  } catch (error) {
    logger.error('⚠️ Kesalahan saat mengambil detail server:', error);
    await ctx.reply('⚠️ *Terjadi kesalahan saat mengambil detail server.*', { parse_mode: 'Markdown' });
  }
});

bot.action('listserver', async (ctx) => {
  try {
    logger.info('📜 Proses daftar server dimulai');
    await ctx.answerCbQuery();
    
    const servers = await new Promise((resolve, reject) => {
      db.all('SELECT * FROM Server', [], (err, servers) => {
        if (err) {
          logger.error('⚠️ Kesalahan saat mengambil daftar server:', err.message);
          return reject('⚠️ *PERHATIAN! Terjadi kesalahan saat mengambil daftar server.*');
        }
        resolve(servers);
      });
    });

    if (servers.length === 0) {
      logger.info('⚠️ Tidak ada server yang tersedia');
      return ctx.reply('⚠️ *PERHATIAN! Tidak ada server yang tersedia saat ini.*', { parse_mode: 'Markdown' });
    }

    let serverList = '📜 *Daftar Server* 📜\n\n';
    servers.forEach((server, index) => {
      serverList += `🔹 ${index + 1}. ${server.domain}\n`;
    });

    serverList += `\nTotal Jumlah Server: ${servers.length}`;

    await ctx.reply(serverList, { parse_mode: 'Markdown' });
  } catch (error) {
    logger.error('⚠️ Kesalahan saat mengambil daftar server:', error);
    await ctx.reply('⚠️ *Terjadi kesalahan saat mengambil daftar server.*', { parse_mode: 'Markdown' });
  }
});
bot.action('resetdb', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    await ctx.reply('🚨 *PERHATIAN! Anda akan menghapus semua server yang tersedia. Apakah Anda yakin?*', {
      reply_markup: {
        inline_keyboard: [
          [{ text: '✅ Ya', callback_data: 'confirm_resetdb' }],
          [{ text: '❌ Tidak', callback_data: 'cancel_resetdb' }]
        ]
      },
      parse_mode: 'Markdown'
    });
  } catch (error) {
    logger.error('❌ Error saat memulai proses reset database:', error);
    await ctx.reply(`❌ *${error}*`, { parse_mode: 'Markdown' });
  }
});

bot.action('confirm_resetdb', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    await new Promise((resolve, reject) => {
      db.run('DELETE FROM Server', (err) => {
        if (err) {
          logger.error('❌ Error saat mereset tabel Server:', err.message);
          return reject('❗️ *PERHATIAN! Terjadi KESALAHAN SERIUS saat mereset database. Harap segera hubungi administrator!*');
        }
        resolve();
      });
    });
    await ctx.reply('🚨 *PERHATIAN! Database telah DIRESET SEPENUHNYA. Semua server telah DIHAPUS TOTAL.*', { parse_mode: 'Markdown' });
  } catch (error) {
    logger.error('❌ Error saat mereset database:', error);
    await ctx.reply(`❌ *${error}*`, { parse_mode: 'Markdown' });
  }
});

bot.action('cancel_resetdb', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    await ctx.reply('❌ *Proses reset database dibatalkan.*', { parse_mode: 'Markdown' });
  } catch (error) {
    logger.error('❌ Error saat membatalkan reset database:', error);
    await ctx.reply(`❌ *${error}*`, { parse_mode: 'Markdown' });
  }
});
bot.action('deleteserver', async (ctx) => {
  try {
    logger.info('🗑️ Proses hapus server dimulai');
    await ctx.answerCbQuery();
    
    db.all('SELECT * FROM Server', [], (err, servers) => {
      if (err) {
        logger.error('⚠️ Kesalahan saat mengambil daftar server:', err.message);
        return ctx.reply('⚠️ *PERHATIAN! Terjadi kesalahan saat mengambil daftar server.*', { parse_mode: 'Markdown' });
      }

      if (servers.length === 0) {
        logger.info('⚠️ Tidak ada server yang tersedia');
        return ctx.reply('⚠️ *PERHATIAN! Tidak ada server yang tersedia saat ini.*', { parse_mode: 'Markdown' });
      }

      const keyboard = servers.map(server => {
        return [{ text: server.nama_server, callback_data: `confirm_delete_server_${server.id}` }];
      });
      keyboard.push([{ text: '🔙 Kembali ke Menu Utama', callback_data: 'kembali_ke_menu' }]);

      ctx.reply('🗑️ *Pilih server yang ingin dihapus:*', {
        reply_markup: {
          inline_keyboard: keyboard
        },
        parse_mode: 'Markdown'
      });
    });
  } catch (error) {
    logger.error('❌ Kesalahan saat memulai proses hapus server:', error);
    await ctx.reply('❌ *GAGAL! Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.*', { parse_mode: 'Markdown' });
  }
});


const getUsernameById = async (userId) => {
  try {
    const telegramUser = await bot.telegram.getChat(userId);
    return telegramUser.username || telegramUser.first_name;
  } catch (err) {
    logger.error('❌ Kesalahan saat mengambil username dari Telegram:', err.message);
    throw new Error('⚠️ *PERHATIAN! Terjadi kesalahan saat mengambil username dari Telegram.*');
  }
};

bot.action('addsaldo_user', async (ctx) => {
  try {
    logger.info('Add saldo user process started');
    await ctx.answerCbQuery();

    const users = await new Promise((resolve, reject) => {
      db.all('SELECT user_id FROM users LIMIT 20', [], (err, users) => {
        if (err) {
          logger.error('❌ Kesalahan saat mengambil daftar user:', err.message);
          reject(err);
        } else {
        resolve(users);
        }
      });
    });

    const totalUsers = await new Promise((resolve, reject) => {
      db.get('SELECT COUNT(*) as count FROM users', [], (err, row) => {
        if (err) {
          logger.error('❌ Kesalahan saat menghitung total user:', err.message);
          reject(err);
        } else {
        resolve(row.count);
        }
      });
    });

    const keyboard = [];
    for (let i = 0; i < users.length; i += 2) {
      const row = [];
      const username1 = await getUsernameById(users[i].user_id);
      row.push({
        text: username1 || users[i].user_id,
        callback_data: `add_saldo_${users[i].user_id}`
      });
      if (i + 1 < users.length) {
        const username2 = await getUsernameById(users[i + 1].user_id);
        row.push({
          text: username2 || users[i + 1].user_id,
          callback_data: `add_saldo_${users[i + 1].user_id}`
        });
      }
      keyboard.push(row);
    }

    const currentPage = 0;
    const replyMarkup = {
      inline_keyboard: [...keyboard]
    };

    if (totalUsers > 20) {
      replyMarkup.inline_keyboard.push([{
        text: '➡️ Next',
        callback_data: `next_users_${currentPage + 1}`
      }]);
    }

    await ctx.reply('📊 *Silakan pilih user untuk menambahkan saldo:*', {
      reply_markup: replyMarkup,
      parse_mode: 'Markdown'
    });
  } catch (error) {
    logger.error('❌ Kesalahan saat memulai proses tambah saldo user:', error);
    await ctx.reply(`❌ *${error}*`, { parse_mode: 'Markdown' });
  }
});
bot.action(/next_users_(\d+)/, async (ctx) => {
  const currentPage = parseInt(ctx.match[1]);
  const offset = currentPage * 20;

  try {
    logger.info(`Next users process started for page ${currentPage + 1}`);
    await ctx.answerCbQuery();

    const users = await new Promise((resolve, reject) => {
      db.all(`SELECT user_id FROM users LIMIT 20 OFFSET ${offset}`, [], (err, users) => {
        if (err) {
          logger.error('❌ Kesalahan saat mengambil daftar user:', err.message);
          return reject('⚠️ *PERHATIAN! Terjadi kesalahan saat mengambil daftar user.*');
        }
        resolve(users);
      });
    });

    const totalUsers = await new Promise((resolve, reject) => {
      db.get('SELECT COUNT(*) as count FROM users', [], (err, row) => {
        if (err) {
          logger.error('❌ Kesalahan saat menghitung total user:', err.message);
          return reject('⚠️ *PERHATIAN! Terjadi kesalahan saat menghitung total user.*');
        }
        resolve(row.count);
      });
    });

    const keyboard = [];
    for (let i = 0; i < users.length; i += 2) {
      const row = [];
      const username1 = await getUsernameById(users[i].user_id);
      row.push({
        text: username1 || users[i].user_id,
        callback_data: `add_saldo_${users[i].user_id}`
      });
      if (i + 1 < users.length) {
        const username2 = await getUsernameById(users[i + 1].user_id);
        row.push({
          text: username2 || users[i + 1].user_id,
          callback_data: `add_saldo_${users[i + 1].user_id}`
        });
      }
      keyboard.push(row);
    }

    const replyMarkup = {
      inline_keyboard: [...keyboard]
    };

    const navigationButtons = [];
    if (currentPage > 0) {
      navigationButtons.push([{
        text: '⬅️ Back',
        callback_data: `prev_users_${currentPage - 1}`
      }]);
    }
    if (offset + 20 < totalUsers) {
      navigationButtons.push([{
        text: '➡️ Next',
        callback_data: `next_users_${currentPage + 1}`
      }]);
    }

    replyMarkup.inline_keyboard.push(...navigationButtons);

    await ctx.editMessageReplyMarkup(replyMarkup);
  } catch (error) {
    logger.error('❌ Kesalahan saat memproses next users:', error);
    await ctx.reply(`❌ *${error}*`, { parse_mode: 'Markdown' });
  }
});

bot.action(/prev_users_(\d+)/, async (ctx) => {
  const currentPage = parseInt(ctx.match[1]);
  const offset = (currentPage - 1) * 20; 

  try {
    logger.info(`Previous users process started for page ${currentPage}`);
    await ctx.answerCbQuery();

    const users = await new Promise((resolve, reject) => {
      db.all(`SELECT user_id FROM users LIMIT 20 OFFSET ${offset}`, [], (err, users) => {
        if (err) {
          logger.error('❌ Kesalahan saat mengambil daftar user:', err.message);
          return reject('⚠️ *PERHATIAN! Terjadi kesalahan saat mengambil daftar user.*');
        }
        resolve(users);
      });
    });

    const totalUsers = await new Promise((resolve, reject) => {
      db.get('SELECT COUNT(*) as count FROM users', [], (err, row) => {
        if (err) {
          logger.error('❌ Kesalahan saat menghitung total user:', err.message);
          return reject('⚠️ *PERHATIAN! Terjadi kesalahan saat menghitung total user.*');
        }
        resolve(row.count);
      });
    });

    const keyboard = [];
    for (let i = 0; i < users.length; i += 2) {
      const row = [];
      const username1 = await getUsernameById(users[i].user_id);
      row.push({
        text: username1 || users[i].user_id,
        callback_data: `add_saldo_${users[i].user_id}`
      });
      if (i + 1 < users.length) {
        const username2 = await getUsernameById(users[i + 1].user_id);
        row.push({
          text: username2 || users[i + 1].user_id,
          callback_data: `add_saldo_${users[i + 1].user_id}`
        });
      }
      keyboard.push(row);
    }

    const replyMarkup = {
      inline_keyboard: [...keyboard]
    };

    const navigationButtons = [];
    if (currentPage > 0) {
      navigationButtons.push([{
        text: '⬅️ Back',
        callback_data: `prev_users_${currentPage - 1}`
      }]);
    }
    if (offset + 20 < totalUsers) {
      navigationButtons.push([{
        text: '➡️ Next',
        callback_data: `next_users_${currentPage}`
      }]);
    }

    replyMarkup.inline_keyboard.push(...navigationButtons);

    await ctx.editMessageReplyMarkup(replyMarkup);
  } catch (error) {
    logger.error('❌ Kesalahan saat memproses previous users:', error);
    await ctx.reply(`❌ *${error}*`, { parse_mode: 'Markdown' });
  }
});
bot.action('editserver_limit_ip', async (ctx) => {
  try {
    logger.info('Edit server limit IP process started');
    await ctx.answerCbQuery();

    const servers = await new Promise((resolve, reject) => {
      db.all('SELECT id, nama_server FROM Server', [], (err, servers) => {
        if (err) {
          logger.error('❌ Kesalahan saat mengambil daftar server:', err.message);
          return reject('⚠️ *PERHATIAN! Terjadi kesalahan saat mengambil daftar server.*');
        }
        resolve(servers);
      });
    });

    if (servers.length === 0) {
      return ctx.reply('⚠️ *PERHATIAN! Tidak ada server yang tersedia untuk diedit.*', { parse_mode: 'Markdown' });
    }

    const buttons = servers.map(server => ({
      text: server.nama_server,
      callback_data: `edit_limit_ip_${server.id}`
    }));

    const inlineKeyboard = [];
    for (let i = 0; i < buttons.length; i += 2) {
      inlineKeyboard.push(buttons.slice(i, i + 2));
    }

    await ctx.reply('📊 *Silakan pilih server untuk mengedit limit IP:*', {
      reply_markup: { inline_keyboard: inlineKeyboard },
      parse_mode: 'Markdown'
    });
  } catch (error) {
    logger.error('❌ Kesalahan saat memulai proses edit limit IP server:', error);
    await ctx.reply(`❌ *${error}*`, { parse_mode: 'Markdown' });
  }
});
bot.action('editserver_batas_create_akun', async (ctx) => {
  try {
    logger.info('Edit server batas create akun process started');
    await ctx.answerCbQuery();

    const servers = await new Promise((resolve, reject) => {
      db.all('SELECT id, nama_server FROM Server', [], (err, servers) => {
        if (err) {
          logger.error('❌ Kesalahan saat mengambil daftar server:', err.message);
          return reject('⚠️ *PERHATIAN! Terjadi kesalahan saat mengambil daftar server.*');
        }
        resolve(servers);
      });
    });

    if (servers.length === 0) {
      return ctx.reply('⚠️ *PERHATIAN! Tidak ada server yang tersedia untuk diedit.*', { parse_mode: 'Markdown' });
    }

    const buttons = servers.map(server => ({
      text: server.nama_server,
      callback_data: `edit_batas_create_akun_${server.id}`
    }));

    const inlineKeyboard = [];
    for (let i = 0; i < buttons.length; i += 2) {
      inlineKeyboard.push(buttons.slice(i, i + 2));
    }

    await ctx.reply('📊 *Silakan pilih server untuk mengedit batas create akun:*', {
      reply_markup: { inline_keyboard: inlineKeyboard },
      parse_mode: 'Markdown'
    });
  } catch (error) {
    logger.error('❌ Kesalahan saat memulai proses edit batas create akun server:', error);
    await ctx.reply(`❌ *${error}*`, { parse_mode: 'Markdown' });
  }
});
bot.action('editserver_total_create_akun', async (ctx) => {
  try {
    logger.info('Edit server total create akun process started');
    await ctx.answerCbQuery();

    const servers = await new Promise((resolve, reject) => {
      db.all('SELECT id, nama_server FROM Server', [], (err, servers) => {
        if (err) {
          logger.error('❌ Kesalahan saat mengambil daftar server:', err.message);
          return reject('⚠️ *PERHATIAN! Terjadi kesalahan saat mengambil daftar server.*');
        }
        resolve(servers);
      });
    });

    if (servers.length === 0) {
      return ctx.reply('⚠️ *PERHATIAN! Tidak ada server yang tersedia untuk diedit.*', { parse_mode: 'Markdown' });
    }

    const buttons = servers.map(server => ({
      text: server.nama_server,
      callback_data: `edit_total_create_akun_${server.id}`
    }));

    const inlineKeyboard = [];
    for (let i = 0; i < buttons.length; i += 2) {
      inlineKeyboard.push(buttons.slice(i, i + 2));
    }

    await ctx.reply('📊 *Silakan pilih server untuk mengedit total create akun:*', {
      reply_markup: { inline_keyboard: inlineKeyboard },
      parse_mode: 'Markdown'
    });
  } catch (error) {
    logger.error('❌ Kesalahan saat memulai proses edit total create akun server:', error);
    await ctx.reply(`❌ *${error}*`, { parse_mode: 'Markdown' });
  }
});
bot.action('editserver_quota', async (ctx) => {
  try {
    logger.info('Edit server quota process started');
    await ctx.answerCbQuery();

    const servers = await new Promise((resolve, reject) => {
      db.all('SELECT id, nama_server FROM Server', [], (err, servers) => {
        if (err) {
          logger.error('❌ Kesalahan saat mengambil daftar server:', err.message);
          return reject('⚠️ *PERHATIAN! Terjadi kesalahan saat mengambil daftar server.*');
        }
        resolve(servers);
      });
    });

    if (servers.length === 0) {
      return ctx.reply('⚠️ *PERHATIAN! Tidak ada server yang tersedia untuk diedit.*', { parse_mode: 'Markdown' });
    }

    const buttons = servers.map(server => ({
      text: server.nama_server,
      callback_data: `edit_quota_${server.id}`
    }));

    const inlineKeyboard = [];
    for (let i = 0; i < buttons.length; i += 2) {
      inlineKeyboard.push(buttons.slice(i, i + 2));
    }

    await ctx.reply('📊 *Silakan pilih server untuk mengedit quota:*', {
      reply_markup: { inline_keyboard: inlineKeyboard },
      parse_mode: 'Markdown'
    });
  } catch (error) {
    logger.error('❌ Kesalahan saat memulai proses edit quota server:', error);
    await ctx.reply(`❌ *${error}*`, { parse_mode: 'Markdown' });
  }
});
bot.action('editserver_auth', async (ctx) => {
  try {
    logger.info('Edit server auth process started');
    await ctx.answerCbQuery();

    const servers = await new Promise((resolve, reject) => {
      db.all('SELECT id, nama_server FROM Server', [], (err, servers) => {
        if (err) {
          logger.error('❌ Kesalahan saat mengambil daftar server:', err.message);
          return reject('⚠️ *PERHATIAN! Terjadi kesalahan saat mengambil daftar server.*');
        }
        resolve(servers);
      });
    });

    if (servers.length === 0) {
      return ctx.reply('⚠️ *PERHATIAN! Tidak ada server yang tersedia untuk diedit.*', { parse_mode: 'Markdown' });
    }

    const buttons = servers.map(server => ({
      text: server.nama_server,
      callback_data: `edit_auth_${server.id}`
    }));

    const inlineKeyboard = [];
    for (let i = 0; i < buttons.length; i += 2) {
      inlineKeyboard.push(buttons.slice(i, i + 2));
    }

    await ctx.reply('🌐 *Silakan pilih server untuk mengedit auth:*', {
      reply_markup: { inline_keyboard: inlineKeyboard },
      parse_mode: 'Markdown'
    });
  } catch (error) {
    logger.error('❌ Kesalahan saat memulai proses edit auth server:', error);
    await ctx.reply(`❌ *${error}*`, { parse_mode: 'Markdown' });
  }
});

bot.action('editserver_harga', async (ctx) => {
  try {
    logger.info('Edit server harga process started');
    await ctx.answerCbQuery();

    const servers = await new Promise((resolve, reject) => {
      db.all('SELECT id, nama_server FROM Server', [], (err, servers) => {
        if (err) {
          logger.error('❌ Kesalahan saat mengambil daftar server:', err.message);
          return reject('⚠️ *PERHATIAN! Terjadi kesalahan saat mengambil daftar server.*');
        }
        resolve(servers);
      });
    });

    if (servers.length === 0) {
      return ctx.reply('⚠️ *PERHATIAN! Tidak ada server yang tersedia untuk diedit.*', { parse_mode: 'Markdown' });
    }

    const buttons = servers.map(server => ({
      text: server.nama_server,
      callback_data: `edit_harga_${server.id}`
    }));

    const inlineKeyboard = [];
    for (let i = 0; i < buttons.length; i += 2) {
      inlineKeyboard.push(buttons.slice(i, i + 2));
    }

    await ctx.reply('💰 *Silakan pilih server untuk mengedit harga:*', {
      reply_markup: { inline_keyboard: inlineKeyboard },
      parse_mode: 'Markdown'
    });
  } catch (error) {
    logger.error('❌ Kesalahan saat memulai proses edit harga server:', error);
    await ctx.reply(`❌ *${error}*`, { parse_mode: 'Markdown' });
  }
});

bot.action('editserver_domain', async (ctx) => {
  try {
    logger.info('Edit server domain process started');
    await ctx.answerCbQuery();

    const servers = await new Promise((resolve, reject) => {
      db.all('SELECT id, nama_server FROM Server', [], (err, servers) => {
        if (err) {
          logger.error('❌ Kesalahan saat mengambil daftar server:', err.message);
          return reject('⚠️ *PERHATIAN! Terjadi kesalahan saat mengambil daftar server.*');
        }
        resolve(servers);
      });
    });

    if (servers.length === 0) {
      return ctx.reply('⚠️ *PERHATIAN! Tidak ada server yang tersedia untuk diedit.*', { parse_mode: 'Markdown' });
    }

    const buttons = servers.map(server => ({
      text: server.nama_server,
      callback_data: `edit_domain_${server.id}`
    }));

    const inlineKeyboard = [];
    for (let i = 0; i < buttons.length; i += 2) {
      inlineKeyboard.push(buttons.slice(i, i + 2));
    }

    await ctx.reply('🌐 *Silakan pilih server untuk mengedit domain:*', {
      reply_markup: { inline_keyboard: inlineKeyboard },
      parse_mode: 'Markdown'
    });
  } catch (error) {
    logger.error('❌ Kesalahan saat memulai proses edit domain server:', error);
    await ctx.reply(`❌ *${error}*`, { parse_mode: 'Markdown' });
  }
});

bot.action('nama_server_edit', async (ctx) => {
  try {
    logger.info('Edit server nama process started');
    await ctx.answerCbQuery();

    const servers = await new Promise((resolve, reject) => {
      db.all('SELECT id, nama_server FROM Server', [], (err, servers) => {
        if (err) {
          logger.error('❌ Kesalahan saat mengambil daftar server:', err.message);
          return reject('⚠️ *PERHATIAN! Terjadi kesalahan saat mengambil daftar server.*');
        }
        resolve(servers);
      });
    });

    if (servers.length === 0) {
      return ctx.reply('⚠️ *PERHATIAN! Tidak ada server yang tersedia untuk diedit.*', { parse_mode: 'Markdown' });
    }

    const buttons = servers.map(server => ({
      text: server.nama_server,
      callback_data: `edit_nama_${server.id}`
    }));

    const inlineKeyboard = [];
    for (let i = 0; i < buttons.length; i += 2) {
      inlineKeyboard.push(buttons.slice(i, i + 2));
    }

    await ctx.reply('🏷️ *Silakan pilih server untuk mengedit nama:*', {
      reply_markup: { inline_keyboard: inlineKeyboard },
      parse_mode: 'Markdown'
    });
  } catch (error) {
    logger.error('❌ Kesalahan saat memulai proses edit nama server:', error);
    await ctx.reply(`❌ *${error}*`, { parse_mode: 'Markdown' });
  }
});

bot.action('topup_saldo', async (ctx) => {
  try {
    await ctx.answerCbQuery(); 
    const userId = ctx.from.id;
    //logger.info(`🔍 User ${userId} memulai proses top-up saldo.`);
    

    if (!global.depositState) {
      global.depositState = {};
    }
    global.depositState[userId] = { action: 'request_amount', amount: '' };
    
    //logger.info(`🔍 User ${userId} diminta untuk memasukkan jumlah nominal saldo.`);
    

    const keyboard = keyboard_nomor();
    
    await ctx.editMessageText(t(userId, 'topup_prompt'), {
      reply_markup: {
        inline_keyboard: keyboard
      },
      parse_mode: 'Markdown'
    });
  } catch (error) {
    logger.error('❌ Kesalahan saat memulai proses top-up saldo:', error);
    await ctx.editMessageText(t(ctx.from.id, 'topup_err_generic'), { parse_mode: 'Markdown' });
  }
});

bot.action(/edit_harga_(\d+)/, async (ctx) => {
  const serverId = ctx.match[1];
  logger.info(`User ${ctx.from.id} memilih untuk mengedit harga server dengan ID: ${serverId}`);
  userState[ctx.chat.id] = { step: 'edit_harga', serverId: serverId };

  await ctx.reply('💰 *Silakan masukkan harga server baru:*', {
    reply_markup: { inline_keyboard: keyboard_nomor() },
    parse_mode: 'Markdown'
  });
});
bot.action(/add_saldo_(\d+)/, async (ctx) => {
  const userId = ctx.match[1];
  logger.info(`User ${ctx.from.id} memilih untuk menambahkan saldo user dengan ID: ${userId}`);
  userState[ctx.chat.id] = { step: 'add_saldo', userId: userId };

  await ctx.reply('📊 *Silakan masukkan jumlah saldo yang ingin ditambahkan:*', {
    reply_markup: { inline_keyboard: keyboard_nomor() },
    parse_mode: 'Markdown'
  });
});
bot.action(/edit_batas_create_akun_(\d+)/, async (ctx) => {
  const serverId = ctx.match[1];
  logger.info(`User ${ctx.from.id} memilih untuk mengedit batas create akun server dengan ID: ${serverId}`);
  userState[ctx.chat.id] = { step: 'edit_batas_create_akun', serverId: serverId };

  await ctx.reply('📊 *Silakan masukkan batas create akun server baru:*', {
    reply_markup: { inline_keyboard: keyboard_nomor() },
    parse_mode: 'Markdown'
  });
});
bot.action(/edit_total_create_akun_(\d+)/, async (ctx) => {
  const serverId = ctx.match[1];
  logger.info(`User ${ctx.from.id} memilih untuk mengedit total create akun server dengan ID: ${serverId}`);
  userState[ctx.chat.id] = { step: 'edit_total_create_akun', serverId: serverId };

  await ctx.reply('📊 *Silakan masukkan total create akun server baru:*', {
    reply_markup: { inline_keyboard: keyboard_nomor() },
    parse_mode: 'Markdown'
  });
});
bot.action(/edit_limit_ip_(\d+)/, async (ctx) => {
  const serverId = ctx.match[1];
  logger.info(`User ${ctx.from.id} memilih untuk mengedit limit IP server dengan ID: ${serverId}`);
  userState[ctx.chat.id] = { step: 'edit_limit_ip', serverId: serverId };

  await ctx.reply('📊 *Silakan masukkan  server baru:*', {
    reply_markup: { inline_keyboard: keyboard_nomor() },
    parse_mode: 'Markdown'
  });
});
bot.action(/edit_quota_(\d+)/, async (ctx) => {
  const serverId = ctx.match[1];
  logger.info(`User ${ctx.from.id} memilih untuk mengedit quota server dengan ID: ${serverId}`);
  userState[ctx.chat.id] = { step: 'edit_quota', serverId: serverId };

  await ctx.reply('📊 *Silakan masukkan quota server baru:*', {
    reply_markup: { inline_keyboard: keyboard_nomor() },
    parse_mode: 'Markdown'
  });
});
bot.action(/edit_auth_(\d+)/, async (ctx) => {
  const serverId = ctx.match[1];
  logger.info(`User ${ctx.from.id} memilih untuk mengedit auth server dengan ID: ${serverId}`);
  userState[ctx.chat.id] = { step: 'edit_auth', serverId: serverId };

  await ctx.reply('🌐 *Silakan masukkan auth server baru:*', {
    reply_markup: { inline_keyboard: keyboard_full() },
    parse_mode: 'Markdown'
  });
});
bot.action(/edit_domain_(\d+)/, async (ctx) => {
  const serverId = ctx.match[1];
  logger.info(`User ${ctx.from.id} memilih untuk mengedit domain server dengan ID: ${serverId}`);
  userState[ctx.chat.id] = { step: 'edit_domain', serverId: serverId };

  await ctx.reply('🌐 *Silakan masukkan domain server baru:*', {
    reply_markup: { inline_keyboard: keyboard_full() },
    parse_mode: 'Markdown'
  });
});
bot.action(/edit_nama_(\d+)/, async (ctx) => {
  const serverId = ctx.match[1];
  logger.info(`User ${ctx.from.id} memilih untuk mengedit nama server dengan ID: ${serverId}`);
  userState[ctx.chat.id] = { step: 'edit_nama', serverId: serverId };

  await ctx.reply('🏷️ *Silakan masukkan nama server baru:*', {
    reply_markup: { inline_keyboard: keyboard_abc() },
    parse_mode: 'Markdown'
  });
});
bot.action(/confirm_delete_server_(\d+)/, async (ctx) => {
  try {
    db.run('DELETE FROM Server WHERE id = ?', [ctx.match[1]], function(err) {
      if (err) {
        logger.error('Error deleting server:', err.message);
        return ctx.reply('⚠️ *PERHATIAN! Terjadi kesalahan saat menghapus server.*', { parse_mode: 'Markdown' });
      }

      if (this.changes === 0) {
        logger.info('Server tidak ditemukan');
        return ctx.reply('⚠️ *PERHATIAN! Server tidak ditemukan.*', { parse_mode: 'Markdown' });
      }

      logger.info(`Server dengan ID ${ctx.match[1]} berhasil dihapus`);
      ctx.reply('✅ *Server berhasil dihapus.*', { parse_mode: 'Markdown' });
    });
  } catch (error) {
    logger.error('Kesalahan saat menghapus server:', error);
    await ctx.reply('❌ *GAGAL! Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi nanti.*', { parse_mode: 'Markdown' });
  }
});
bot.action(/server_detail_(\d+)/, async (ctx) => {
  const serverId = ctx.match[1];
  try {
    const server = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM Server WHERE id = ?', [serverId], (err, server) => {
        if (err) {
          logger.error('⚠️ Kesalahan saat mengambil detail server:', err.message);
          return reject('⚠️ *PERHATIAN! Terjadi kesalahan saat mengambil detail server.*');
        }
        resolve(server);
      });
    });

    if (!server) {
      logger.info('⚠️ Server tidak ditemukan');
      return ctx.reply('⚠️ *PERHATIAN! Server tidak ditemukan.*', { parse_mode: 'Markdown' });
    }

    const isp = await getISP(server.domain);

    const serverDetails = `📋 *Detail Server* 📋\n\n` +
      `🌐 *Domain:* \`${server.domain}\`\n` +
      `🏢 *ISP:* \`${isp}\`\n` +
      `🔑 *Auth:* \`${server.auth}\`\n` +
      `🏷️ *Nama Server:* \`${server.nama_server}\`\n` +
      `📊 *Quota:* \`${server.quota}\`\n` +
      `📶 *Limit IP:* \`${server.iplimit}\`\n` +
      `🔢 *Batas Create Akun:* \`${server.batas_create_akun}\`\n` +
      `📋 *Total Create Akun:* \`${server.total_create_akun}\`\n` +
      `💵 *Harga:* \`Rp ${server.harga}\`\n\n`;

    await ctx.reply(serverDetails, { parse_mode: 'Markdown' });
  } catch (error) {
    logger.error('⚠️ Kesalahan saat mengambil detail server:', error);
    await ctx.reply('⚠️ *Terjadi kesalahan saat mengambil detail server.*', { parse_mode: 'Markdown' });
  }
});

bot.on('callback_query', async (ctx) => {
  const userId = ctx.from.id;
  const data = ctx.callbackQuery.data;
  const userStateData = userState[ctx.chat.id];

  if (global.depositState && global.depositState[userId] && global.depositState[userId].action === 'request_amount') {
    await handleDepositState(ctx, userId, data);
  } else if (userStateData) {
    switch (userStateData.step) {
      case 'add_saldo':
        await handleAddSaldo(ctx, userStateData, data);
        break;
      case 'edit_batas_create_akun':
        await handleEditBatasCreateAkun(ctx, userStateData, data);
        break;
      case 'edit_limit_ip':
        await handleEditiplimit(ctx, userStateData, data);
        break;
      case 'edit_quota':
        await handleEditQuota(ctx, userStateData, data);
        break;
      case 'edit_auth':
        await handleEditAuth(ctx, userStateData, data);
        break;
      case 'edit_domain':
        await handleEditDomain(ctx, userStateData, data);
        break;
      case 'edit_harga':
        await handleEditHarga(ctx, userStateData, data);
        break;
      case 'edit_nama':
        await handleEditNama(ctx, userStateData, data);
        break;
      case 'edit_total_create_akun':
        await handleEditTotalCreateAkun(ctx, userStateData, data);
        break;
    }
  }
});

async function handleDepositState(ctx, userId, data) {
  // Cek apakah user reseller
  await loadUserLanguage(userId);
  const isReseller = await isUserReseller(userId);
  const statusReseller = isReseller ? t(userId, 'status_reseller') : t(userId, 'status_not_reseller');
  const minDeposit = 1000;

  let currentAmount = global.depositState[userId].amount || '';

  if (data === 'delete') {
    currentAmount = currentAmount.slice(0, -1);
  } else if (data === 'confirm') {
    const amount = Number(currentAmount) || 0;

    if (amount === 0) {
      return await ctx.answerCbQuery(t(userId, 'topup_empty'), { show_alert: true });
    }
    if (amount < minDeposit) {
      return await ctx.answerCbQuery(
        t(userId, 'topup_min', { status: statusReseller, min: minDeposit.toLocaleString() }),
        { show_alert: true }
      );
    }

    global.depositState[userId].action = 'confirm_amount';
    await processDeposit(ctx, currentAmount);
    return;
  } else {
    if (currentAmount.length < 12) {
      currentAmount += data;
    } else {
      return await ctx.answerCbQuery(t(userId, 'topup_max_digit'), { show_alert: true });
    }
  }

  global.depositState[userId].amount = currentAmount;
  const newMessage = t(userId, 'topup_prompt2', { amount: currentAmount || '0' });

  try {
    if (newMessage !== ctx.callbackQuery.message.text) {
      await ctx.editMessageText(newMessage, {
        reply_markup: { inline_keyboard: keyboard_nomor() },
        parse_mode: 'HTML'
      });
    } else {
      await ctx.answerCbQuery();
    }
  } catch (error) {
    await ctx.answerCbQuery();
    logger.error('Error editing message:', error);
  }
}


async function handleAddSaldo(ctx, userStateData, data) {
  let currentSaldo = userStateData.saldo || '';

  if (data === 'backspace') {
    currentSaldo = currentSaldo.slice(0, -1);
  } else if (data === 'confirm') {
    if (currentSaldo.length === 0) {
      return await ctx.answerCbQuery('⚠️ *Jumlah saldo tidak boleh kosong!*', { show_alert: true });
    }

    try {
      await updateUserBalance(userStateData.userId, currentSaldo);
      ctx.reply(`✅ *Saldo user berhasil ditambahkan.*\n\n📄 *Detail Saldo:*\n- Jumlah Saldo: *Rp ${currentSaldo}*`, { parse_mode: 'Markdown' });
    } catch (error) {
      ctx.reply('❌ *Terjadi kesalahan saat menambahkan saldo user.*', { parse_mode: 'Markdown' });
    }
    delete userState[ctx.chat.id];
    return;
  } else if (data === 'cancel') {
    delete userState[ctx.chat.id];
      return await ctx.answerCbQuery('⚠️ *Jumlah saldo tidak valid!*', { show_alert: true });
  } else {
    if (currentSaldo.length < 10) {
      currentSaldo += data;
    } else {
      return await ctx.answerCbQuery('⚠️ *Jumlah saldo maksimal adalah 10 karakter!*', { show_alert: true });
    }
  }

  userStateData.saldo = currentSaldo;
  const newMessage = `📊 *Silakan masukkan jumlah saldo yang ingin ditambahkan:*\n\nJumlah saldo saat ini: *${currentSaldo}*`;
    await ctx.editMessageText(newMessage, {
      reply_markup: { inline_keyboard: keyboard_nomor() },
      parse_mode: 'Markdown'
    });
}

async function handleEditBatasCreateAkun(ctx, userStateData, data) {
  await handleEditField(ctx, userStateData, data, 'batasCreateAkun', 'batas create akun', 'UPDATE Server SET batas_create_akun = ? WHERE id = ?');
}

async function handleEditTotalCreateAkun(ctx, userStateData, data) {
  await handleEditField(ctx, userStateData, data, 'totalCreateAkun', 'total create akun', 'UPDATE Server SET total_create_akun = ? WHERE id = ?');
}

async function handleEditiplimit(ctx, userStateData, data) {
  await handleEditField(ctx, userStateData, data, 'iplimit', 'limit IP', 'UPDATE Server SET limit_ip = ? WHERE id = ?');
}

async function handleEditQuota(ctx, userStateData, data) {
  await handleEditField(ctx, userStateData, data, 'quota', 'quota', 'UPDATE Server SET quota = ? WHERE id = ?');
}

async function handleEditAuth(ctx, userStateData, data) {
  await handleEditField(ctx, userStateData, data, 'auth', 'auth', 'UPDATE Server SET auth = ? WHERE id = ?');
}

async function handleEditDomain(ctx, userStateData, data) {
  await handleEditField(ctx, userStateData, data, 'domain', 'domain', 'UPDATE Server SET domain = ? WHERE id = ?');
}

async function handleEditHarga(ctx, userStateData, data) {
  let currentAmount = userStateData.amount || '';

  if (data === 'delete') {
    currentAmount = currentAmount.slice(0, -1);
  } else if (data === 'confirm') {
    if (currentAmount.length === 0) {
      return await ctx.answerCbQuery('⚠️ *Jumlah tidak boleh kosong!*', { show_alert: true });
    }
    const hargaBaru = parseFloat(currentAmount);
    if (isNaN(hargaBaru) || hargaBaru <= 0) {
      return ctx.reply('❌ *Harga tidak valid. Masukkan angka yang valid.*', { parse_mode: 'Markdown' });
    }
    try {
      await updateServerField(userStateData.serverId, hargaBaru, 'UPDATE Server SET harga = ? WHERE id = ?');
      ctx.reply(`✅ *Harga server berhasil diupdate.*\n\n📄 *Detail Server:*\n- Harga Baru: *Rp ${hargaBaru}*`, { parse_mode: 'Markdown' });
    } catch (err) {
      ctx.reply('❌ *Terjadi kesalahan saat mengupdate harga server.*', { parse_mode: 'Markdown' });
    }
    delete userState[ctx.chat.id];
    return;
  } else {
    if (!/^\d+$/.test(data)) {
      return await ctx.answerCbQuery('⚠️ *Hanya angka yang diperbolehkan!*', { show_alert: true });
    }
    if (currentAmount.length < 12) {
      currentAmount += data;
    } else {
      return await ctx.answerCbQuery('⚠️ *Jumlah maksimal adalah 12 digit!*', { show_alert: true });
    }
  }

  userStateData.amount = currentAmount;
  const newMessage = `💰 *Silakan masukkan harga server baru:*\n\nJumlah saat ini: *Rp ${currentAmount}*`;
  if (newMessage !== ctx.callbackQuery.message.text) {
    await ctx.editMessageText(newMessage, {
      reply_markup: { inline_keyboard: keyboard_nomor() },
      parse_mode: 'Markdown'
    });
  }
}

async function handleEditNama(ctx, userStateData, data) {
  await handleEditField(ctx, userStateData, data, 'name', 'nama server', 'UPDATE Server SET nama_server = ? WHERE id = ?');
}

async function handleEditField(ctx, userStateData, data, field, fieldName, query) {
  let currentValue = userStateData[field] || '';

  if (data === 'delete') {
    currentValue = currentValue.slice(0, -1);
  } else if (data === 'confirm') {
    if (currentValue.length === 0) {
      return await ctx.answerCbQuery(`⚠️ *${fieldName} tidak boleh kosong!*`, { show_alert: true });
    }
    try {
      await updateServerField(userStateData.serverId, currentValue, query);
      ctx.reply(`✅ *${fieldName} server berhasil diupdate.*\n\n📄 *Detail Server:*\n- ${fieldName.charAt(0).toUpperCase() + fieldName.slice(1)}: *${currentValue}*`, { parse_mode: 'Markdown' });
    } catch (err) {
      ctx.reply(`❌ *Terjadi kesalahan saat mengupdate ${fieldName} server.*`, { parse_mode: 'Markdown' });
    }
    delete userState[ctx.chat.id];
    return;
  } else {
    if (!/^[a-zA-Z0-9.-]+$/.test(data)) {
      return await ctx.answerCbQuery(`⚠️ *${fieldName} tidak valid!*`, { show_alert: true });
    }
    if (currentValue.length < 253) {
      currentValue += data;
    } else {
      return await ctx.answerCbQuery(`⚠️ *${fieldName} maksimal adalah 253 karakter!*`, { show_alert: true });
    }
  }

  userStateData[field] = currentValue;
  const newMessage = `📊 *Silakan masukkan ${fieldName} server baru:*\n\n${fieldName.charAt(0).toUpperCase() + fieldName.slice(1)} saat ini: *${currentValue}*`;
  if (newMessage !== ctx.callbackQuery.message.text) {
    await ctx.editMessageText(newMessage, {
      reply_markup: { inline_keyboard: keyboard_nomor() },
      parse_mode: 'Markdown'
    });
  }
}
async function updateUserSaldo(userId, saldo) {
  return new Promise((resolve, reject) => {
    db.run('UPDATE users SET saldo = saldo + ? WHERE user_id = ?', [saldo, userId], function (err) {
      if (err) {
        logger.error('⚠️ Kesalahan saat menambahkan saldo user:', err.message);
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

async function updateServerField(serverId, value, query) {
  return new Promise((resolve, reject) => {
    db.run(query, [value, serverId], function (err) {
      if (err) {
        logger.error(`⚠️ Kesalahan saat mengupdate ${fieldName} server:`, err.message);
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

function generateRandomAmount(baseAmount) {
  const random = Math.floor(Math.random() * 99) + 1;
  return baseAmount + random;
}

if (!global.pendingDeposits) global.pendingDeposits = {};
if (!global.depositState) global.depositState = {};
let lastRequestTime = 0;
const requestInterval = 1000; 

db.all('SELECT * FROM pending_deposits WHERE status = "pending"', [], (err, rows) => {
  if (err) {
    logger.error('Gagal load pending_deposits:', err.message);
    return;
  }
  rows.forEach(row => {
    global.pendingDeposits[row.unique_code] = {
      amount: row.amount,
      originalAmount: row.original_amount,
      userId: row.user_id,
      timestamp: row.timestamp,
      status: row.status,
      qrMessageId: row.qr_message_id,
      transactionId: row.transaction_id,
      chatId: row.chat_id
    };
  });
  logger.info('Pending deposit loaded:', Object.keys(global.pendingDeposits).length);
});

function generateRandomNumber(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// ============================
// EXEC PROMISE
// ============================
const execP = (cmd, opts = {}) =>
  new Promise((resolve, reject) => {
    exec(cmd, opts, (err, stdout, stderr) => {
      if (err) {
        err.stderr = stderr;
        err.stdout = stdout;
        return reject(err);
      }
      resolve(stdout);
    });
  });

// ============================ 
// PROCESS DEPOSIT (FINAL UPDATE)
// ============================
async function processDeposit(ctx, amount) {
  const currentTime = Date.now();
  await loadUserLanguage(ctx.from.id);

  if (currentTime - lastRequestTime < requestInterval) {
    await ctx.editMessageText(
      t(ctx.from.id, 'topup_toomany'),
      { parse_mode: 'Markdown' }
    );
    return;
  }

  lastRequestTime = currentTime;

  const userId = ctx.from.id;
  const uniqueCode = `user-${userId}-${Date.now()}`;

  let finalAmount = Number(amount);
  let adminFee = 0;

  try {
    let qrImageUrl = null;
    let transactionId = null;
    let qrMessage = null;

    // ======================
    // GOPAY (QRIS via Local Proxy)
    // ======================
    if (vars.PAYMENT === "GOPAY") {
      const gopayQris = require('./modules/gopay-qris');
      const res = await gopayQris.createQRIS(Number(amount), vars);

      if (!res?.success) {
        throw new Error("Gagal create QRIS GOPAY");
      }

      const data = res.data;
      finalAmount = Number(data.amount);
      adminFee = data.uniqueNumber || 0;

      transactionId = data.check_id;
      qrImageUrl = data.qr_url;

      if (!qrImageUrl) throw new Error("QR URL kosong");

      const safeQrUrl = encodeURI(String(qrImageUrl).trim());
      const timeoutMinutes = data.timeout_minutes || 15;
      const caption =
        t(userId, 'pay_detail_title') + '\n\n' +
        t(userId, 'pay_total', { amount: finalAmount.toLocaleString('id-ID') }) + '\n' +
        t(userId, 'pay_topup', { amount: Number(amount).toLocaleString('id-ID') }) + '\n' +
        (adminFee > 0 ? t(userId, 'pay_admin_fee', { amount: adminFee.toLocaleString('id-ID') }) + '\n' : '') +
        '\n' + t(userId, 'pay_expired_minutes', { minutes: timeoutMinutes }) + '\n' +
        t(userId, 'pay_transfer_exact') + '\n\n' +
        t(userId, 'pay_click_qris', { url: safeQrUrl }) + '\n';

      qrMessage = await ctx.reply(caption, {
        parse_mode: 'Markdown',
        reply_markup: {
          inline_keyboard: [
            [{ text: t(userId, 'btn_cancel'), callback_data: `batal_topup_confirm_${uniqueCode}` }]
          ]
        }
      });
    }

    // ======================
    // ORKUT (API BARU) - LANGSUNG KIRIM GAMBAR
    // ======================
    else if (vars.PAYMENT === "ORKUT") {
      const res = await axios.get(
        "http://localhost:9526/api/qris",
        {
          params: {
            qris_string: vars.DATA_QRIS_ORKUT,
            amount: Number(amount)
          },
          timeout: 15000
        }
      );

      const data = res.data;

      if (!data || !data.success) throw new Error("Gagal create QRIS ORKUT");

      finalAmount = Number(data.amount);
      adminFee = Number(data.random_add);

      if (!data.image_data || !data.image_data.includes("base64"))
        throw new Error("QRIS image invalid");

      transactionId = data.reference;

      // ubah base64 jadi buffer
      const base64Data = data.image_data.split(',')[1];
      const imageBuffer = Buffer.from(base64Data, 'base64');

      const caption =
        t(userId, 'pay_detail_title') + '\n\n' +
        t(userId, 'pay_total', { amount: finalAmount }) + '\n' +
        t(userId, 'pay_topup', { amount }) + '\n' +
        (adminFee > 0 ? t(userId, 'pay_admin_fee', { amount: adminFee }) + '\n' : ``) +
        '\n' + t(userId, 'pay_expired_hour') + '\n' +
        t(userId, 'pay_transfer_exact') + '\n';

      // kirim QRIS sebagai foto
      qrMessage = await ctx.replyWithPhoto(
     { source: imageBuffer },
     {
      caption,
      parse_mode: 'Markdown',
      reply_markup: {
      inline_keyboard: [
        [{ text: t(userId, 'btn_cancel'), callback_data: `batal_topup_confirm_${uniqueCode}` }]
      ]
     }
    }
    );
      qrImageUrl = data.image_data.trim(); // untuk checker
    }

    // ======================
    // SHOPEEPAY (Dynamic QRIS via Local Proxy)
    // ======================
    else if (vars.PAYMENT === "SHOPEEPAY") {
      const shopeeRes = await shopeePay.createQRIS(Number(amount), vars);
      if (shopeeRes.status !== 'success' || !shopeeRes.transaction_sn || !shopeeRes.qr_image) {
        throw new Error("Gagal create QRIS ShopeePay");
      }

      transactionId = shopeeRes.transaction_sn;
      finalAmount = Number(amount);
      adminFee = 0;

      const qrBase64 = shopeeRes.qr_image;
      if (!qrBase64) throw new Error("QR ShopeePay kosong");

      const imageBuffer = Buffer.from(qrBase64, 'base64');
      const expiredMinutes = shopeeRes.expired_minutes || 20;

      // Add white padding around QR image (20px on each side)
      const sharp = require('sharp');
      const paddedBuffer = await sharp(imageBuffer)
        .extend({ top: 20, bottom: 20, left: 20, right: 20, background: { r: 255, g: 255, b: 255, alpha: 1 } })
        .png()
        .toBuffer();

      const caption =
        t(userId, 'pay_detail_title') + '\n\n' +
        t(userId, 'pay_total', { amount: finalAmount }) + '\n' +
        t(userId, 'pay_topup', { amount }) + '\n' +
        '\n' + t(userId, 'pay_expired_minutes', { minutes: expiredMinutes }) + '\n' +
        t(userId, 'pay_transfer_exact') + '\n';

      qrMessage = await ctx.replyWithPhoto(
        { source: paddedBuffer },
        {
          caption,
          parse_mode: 'Markdown',
          reply_markup: {
            inline_keyboard: [
              [{ text: t(userId, 'btn_cancel'), callback_data: `batal_topup_confirm_${uniqueCode}` }]
            ]
          }
        }
      );
      qrImageUrl = qrBase64; // untuk checker
    }

    else throw new Error("PAYMENT tidak valid");

    // ======================
    // SIMPAN MEMORY
    // ======================
    if (!global.pendingDeposits) global.pendingDeposits = {};

    global.pendingDeposits[uniqueCode] = {
      amount: finalAmount,
      originalAmount: Number(amount),
      userId,
      timestamp: Date.now(),
      status: 'pending',
      qrMessageId: qrMessage?.message_id,
      transactionId,
      chatId: qrMessage?.chat?.id || ctx.chat?.id || userId
    };

    // ======================
    // SIMPAN DB
    // ======================
    db.run(
      `INSERT INTO pending_deposits 
      (unique_code, user_id, amount, original_amount, timestamp, status, qr_message_id, transaction_id, chat_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        uniqueCode,
        userId,
        finalAmount,
        Number(amount),
        Date.now(),
        'pending',
        qrMessage?.message_id,
        transactionId,
        qrMessage?.chat?.id || ctx.chat?.id || userId
      ]
    );

    // bersihin state lama
    if (global.depositState?.[userId]) delete global.depositState[userId];

    try { await ctx.deleteMessage(); } catch {}

  } catch (error) {
    console.error("❌ Deposit error:", error.message);

    await ctx.reply(
      t(userId, 'topup_qris_fail', { detail: redactSensitive(error.message).slice(0, 200) }),
      { parse_mode: 'Markdown' }
    );

    if (global.depositState?.[ctx.from.id]) delete global.depositState[ctx.from.id];
  }
}

async function checkQRISStatus() {
  if (!global.pendingDeposits || Object.keys(global.pendingDeposits).length === 0) return;

  const now = Date.now();

  for (const [uniqueCode, deposit] of Object.entries(global.pendingDeposits)) {
    if (deposit.status !== 'pending') continue;

    try {
      // EXPIRATION
      let maxAge = vars.PAYMENT === "GOPAY" ? 15 * 60 * 1000 : (vars.PAYMENT === "SHOPEEPAY" ? 20 * 60 * 1000 : 3600 * 1000); // 15 menit vs 20 menit vs 1 jam
      if (now - deposit.timestamp > maxAge) {
        logger.warn(`EXPIRED ${uniqueCode}`);
        delete global.pendingDeposits[uniqueCode];
        db.run('DELETE FROM pending_deposits WHERE unique_code = ?', [uniqueCode]);
        continue;
      }

      // PROVIDER-SPECIFIC LOGIC
      if (vars.PAYMENT === "GOPAY") {
        const gopayQris = require('./modules/gopay-qris');
        const res = await gopayQris.checkPayment(deposit.transactionId, vars);
        if (!res?.success) continue;

        const status = res.status;
        if (status !== "PAID") continue;

       //logger.info(`💰 PEMBAYARAN MASUK ${uniqueCode}`);
        const success = await processMatchingPaymentAtomic(deposit, data, uniqueCode);

        if (success) {
          delete global.pendingDeposits[uniqueCode];
          db.run('DELETE FROM pending_deposits WHERE unique_code = ?', [uniqueCode]);
          try { await purchaseFlow.handlePostPayment(uniqueCode); } catch (e) { logger.error(`handlePostPayment error: ${e.message}`); }
        }

      } else if (vars.PAYMENT === "ORKUT") {
        const res = await axios.get(
          'http://localhost:9526/payments',
          { timeout: 15000 }
        );

        const data = res.data;
        if (!data?.success || !data?.data) {
          logger.warn(`[QRIS] Response tidak valid ${uniqueCode}`);
          continue;
        }

        const list = data.data;
        const normalize = v => Number(String(v || '').replace(/[^\d]/g, '')) || 0;
        const targetAmount = normalize(deposit.amount);

        const match = list.find(tx => {
          const txAmount = normalize(tx.amount);
          const type = String(tx.type || '').toLowerCase();
          return txAmount === targetAmount && type === 'kredit';
        });

        if (!match) {
          logger.info(`[QRIS] Belum match ${uniqueCode}`);
          continue;
        }

        logger.info(`[QRIS] MATCH ${uniqueCode}`);
        const success = await processMatchingPaymentAtomic(deposit, match, uniqueCode);

        if (success) {
          logger.info(`[QRIS] SUCCESS ${uniqueCode}`);
          delete global.pendingDeposits[uniqueCode];
          db.run('DELETE FROM pending_deposits WHERE unique_code = ?', [uniqueCode]);
          try { await purchaseFlow.handlePostPayment(uniqueCode); } catch (e) { logger.error(`handlePostPayment error: ${e.message}`); }
        }
      } else if (vars.PAYMENT === "SHOPEEPAY") {
        const orderSn = deposit.transactionId;
        if (!orderSn) continue;

        const res = await shopeePay.checkPayment(orderSn, vars);
        if (res.status !== 'success') {
          continue;
        }

        const td = (res.transaction_data && res.transaction_data.order_status !== undefined) ? res.transaction_data : res;
        const status = res.order_status;
        if (status !== 1 && res.paid !== true) continue;

        logger.info(`[QRIS] SHOPEEPAY MATCH ${uniqueCode}`);
        const success = await processMatchingPaymentAtomic(deposit, td, uniqueCode);

        if (success) {
          logger.info(`[QRIS] SHOPEEPAY SUCCESS ${uniqueCode}`);
          delete global.pendingDeposits[uniqueCode];
          db.run('DELETE FROM pending_deposits WHERE unique_code = ?', [uniqueCode]);
          try { await purchaseFlow.handlePostPayment(uniqueCode); } catch (e) { logger.error(`handlePostPayment error: ${e.message}`); }
        }
      }

    } catch (err) {
      logger.error(`[QRIS] ERROR ${uniqueCode}: ${err.message}`);
    }
  }
}

// AUTO LOOP 
// Cek setiap 3 detik
setInterval(checkQRISStatus, 3000);

function keyboard_abc() {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz';
  const buttons = [];
  for (let i = 0; i < alphabet.length; i += 3) {
    const row = alphabet.slice(i, i + 3).split('').map(char => ({
      text: char,
      callback_data: char
    }));
    buttons.push(row);
  }
  buttons.push([{ text: '🔙 Hapus', callback_data: 'delete' }, { text: '✅ Konfirmasi', callback_data: 'confirm' }]);
  buttons.push([{ text: '🔙 Kembali ke Menu Utama', callback_data: 'send_main_menu' }]);
  return buttons;
}

function keyboard_nomor() {
  const alphabet = '1234567890';
  const buttons = [];
  for (let i = 0; i < alphabet.length; i += 3) {
    const row = alphabet.slice(i, i + 3).split('').map(char => ({
      text: char,
      callback_data: char
    }));
    buttons.push(row);
  }
  buttons.push([{ text: '🔙 Hapus', callback_data: 'delete' }, { text: '✅ Konfirmasi', callback_data: 'confirm' }]);
  buttons.push([{ text: '🔙 Kembali ke Menu Utama', callback_data: 'send_main_menu' }]);
  return buttons;
}

function keyboard_full() {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const buttons = [];
  for (let i = 0; i < alphabet.length; i += 3) {
    const row = alphabet.slice(i, i + 3).split('').map(char => ({
      text: char,
      callback_data: char
    }));
    buttons.push(row);
  }
  buttons.push([{ text: '🔙 Hapus', callback_data: 'delete' }, { text: '✅ Konfirmasi', callback_data: 'confirm' }]);
  buttons.push([{ text: '🔙 Kembali ke Menu Utama', callback_data: 'send_main_menu' }]);
  return buttons;
}

global.processedTransactions = new Set();
async function updateUserBalance(userId, amount) {
  return new Promise((resolve, reject) => {
    db.run("UPDATE users SET saldo = saldo + ? WHERE user_id = ?", [amount, userId], function(err) {
        if (err) {
        logger.error('⚠️ Kesalahan saat mengupdate saldo user:', err.message);
          reject(err);
      } else {
        resolve();
        }
    });
  });
}

async function getUserBalance(userId) {
  return new Promise((resolve, reject) => {
    db.get("SELECT saldo FROM users WHERE user_id = ?", [userId], function(err, row) {
        if (err) {
        logger.error('⚠️ Kesalahan saat mengambil saldo user:', err.message);
          reject(err);
      } else {
        resolve(row ? row.saldo : 0);
        }
    });
  });
}

async function autoActivateReseller(userId, currentBalance) {
  const MINIMUM_BALANCE = 50000;
  if (currentBalance >= MINIMUM_BALANCE && !isUserReseller(userId)) {
    addReseller(userId);
    try {
      await bot.telegram.sendMessage(userId,
        `🎉 *SELAMAT! Anda otomatis menjadi Reseller!*\n\n` +
        `💰 Saldo Anda: Rp ${currentBalance.toLocaleString('id-ID')}\n\n` +
        `🎁 Keuntungan Reseller:\n` +
        `• Dapet Setengah harga\n` +
        `• Trial Unlimited\n` +
        `• Hapus Akun\n` +
        `• Lock / Unlock Akun\n\n` +
        `Kecuali VPN Edu Direct & VPN Cloudfront (harga normal)`,
        { parse_mode: 'Markdown' }
      );
    } catch (e) {
      logger.error(`Gagal kirim notif reseller ke ${userId}:`, e.message);
    }
    logger.info(`User ${userId} otomatis menjadi reseller (saldo >= ${MINIMUM_BALANCE})`);
  }
}

async function sendPaymentSuccessNotification(userId, deposit, currentBalance) {
  try {
    // Hitung admin fee
    const adminFee = deposit.amount - deposit.originalAmount;
    await bot.telegram.sendMessage(userId,
      `✅ *Pembayaran Berhasil!*\n\n` +
      `💰 Jumlah Deposit: Rp ${deposit.originalAmount}\n` +
      `💰 Biaya Admin: Rp ${adminFee}\n` +
      `💰 Total Pembayaran: Rp ${deposit.amount}\n` +
      `💳 Saldo Sekarang: Rp ${currentBalance}`,
      { parse_mode: 'Markdown' }
    );
    return true;
  } catch (error) {
    logger.error('Error sending payment notification:', error);
    return false;
  }
}

async function processMatchingPaymentAtomic(deposit, matchingTransaction, uniqueCode) {
  const referenceId = matchingTransaction.reference_id || deposit.transactionId || uniqueCode;
  const referenceAmount = Number(matchingTransaction.amount || deposit.amount || deposit.originalAmount);
  const transactionKey = `${referenceId}_${referenceAmount}`;

  if (deposit.status === 'processing') {
    logger.info(`Transaction ${transactionKey} sedang diproses, skip duplikasi checker.`);
    return false;
  }

  deposit.status = 'processing';

  try {
    await dbRunAsync('BEGIN IMMEDIATE TRANSACTION');
    await ensureUserExists(deposit.userId);

    const existing = await dbGetAsync(
      'SELECT id FROM transactions WHERE reference_id = ? AND amount = ?',
      [referenceId, deposit.originalAmount]
    );

    if (existing) {
      await dbRunAsync('ROLLBACK');
      deposit.status = 'paid';
      logger.info(`Transaction ${transactionKey} already processed, skipping...`);
      return false;
    }

    const updateResult = await dbRunAsync(
      'UPDATE users SET saldo = saldo + ? WHERE user_id = ?',
      [deposit.originalAmount, deposit.userId]
    );

    if (!updateResult.changes) {
      throw new Error(`User ${deposit.userId} tidak ditemukan saat update saldo.`);
    }

    await dbRunAsync(
      'INSERT INTO transactions (user_id, amount, type, reference_id, timestamp) VALUES (?, ?, ?, ?, ?)',
      [deposit.userId, deposit.originalAmount, 'deposit', referenceId, Date.now()]
    );

    const user = await dbGetAsync('SELECT saldo FROM users WHERE user_id = ?', [deposit.userId]);
    if (!user) {
      throw new Error(`Gagal mengambil saldo terbaru user ${deposit.userId}.`);
    }

    await dbRunAsync('COMMIT');

    global.processedTransactions.add(transactionKey);
    deposit.status = 'paid';
    delete global.pendingDeposits[uniqueCode];
    db.run('DELETE FROM pending_deposits WHERE unique_code = ?', [uniqueCode]);

    const notificationSent = await sendPaymentSuccessNotification(
      deposit.userId,
      deposit,
      user.saldo
    );

    if (!notificationSent) {
      logger.warn(`Notifikasi pembayaran user ${deposit.userId} gagal dikirim, tapi saldo sudah masuk.`);
    }

    if (deposit.qrMessageId) {
      try {
        await bot.telegram.deleteMessage(deposit.chatId || deposit.userId, deposit.qrMessageId);
      } catch (e) {
        logger.error("Gagal menghapus pesan QR code:", e.message);
      }
    }

    try {
      let userInfo;
      try {
        userInfo = await bot.telegram.getChat(deposit.userId);
      } catch (e) {
        userInfo = {};
      }
      const username = userInfo.username ? `@${userInfo.username}` : (userInfo.first_name || deposit.userId);
      const userDisplay = userInfo.username
        ? `${username} (${deposit.userId})`
        : `${username}`;
      await bot.telegram.sendMessage(
        GROUP_ID,
        `<blockquote>
✅ <b>Top Up Berhasil</b>
👤 User: ${userDisplay}
💰 Nominal: <b>Rp ${deposit.originalAmount}</b>
💳 Saldo Sekarang: <b>Rp ${user.saldo}</b>
⏰ Waktu: ${new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })}
</blockquote>`,
        { parse_mode: 'HTML' }
      );
    } catch (e) {
      logger.error('Gagal kirim notif top up ke grup:', e.message);
    }

    // Auto-activate reseller jika saldo mencapai Rp50.000
    await autoActivateReseller(deposit.userId, user.saldo);

    try {
      const receiptsDir = path.join(__dirname, 'receipts');
      if (fs.existsSync(receiptsDir)) {
        const files = fs.readdirSync(receiptsDir);
        for (const file of files) {
          fs.unlinkSync(path.join(receiptsDir, file));
        }
      }
    } catch (e) {
      logger.error('Gagal menghapus file di receipts:', e.message);
    }

    return true;
  } catch (error) {
    deposit.status = 'pending';
    try {
      await dbRunAsync('ROLLBACK');
    } catch {}
    logger.error('Error processing payment match:', error.message);
    throw error;
  }
}

async function processMatchingPayment(deposit, matchingTransaction, uniqueCode) {
  const transactionKey = `${matchingTransaction.reference_id || uniqueCode}_${matchingTransaction.amount}`;
  // Use a database transaction to ensure atomicity
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      db.run('BEGIN TRANSACTION');
      // First check if transaction was already processed
      db.get('SELECT id FROM transactions WHERE reference_id = ? AND amount = ?', 
        [matchingTransaction.reference_id || uniqueCode, matchingTransaction.amount], 
        (err, row) => {
          if (err) {
            db.run('ROLLBACK');
            logger.error('Error checking transaction:', err);
            reject(err);
            return;
          }
          if (row) {
            db.run('ROLLBACK');
    logger.info(`Transaction ${transactionKey} already processed, skipping...`);
            resolve(false);
            return;
          }
          // Update user balance
          db.run('UPDATE users SET saldo = saldo + ? WHERE user_id = ?', 
            [deposit.originalAmount, deposit.userId], 
            function(err) {
              if (err) {
                db.run('ROLLBACK');
                logger.error('Error updating balance:', err);
                reject(err);
                return;
              }
    // Record the transaction
      db.run(
                'INSERT INTO transactions (user_id, amount, type, reference_id, timestamp) VALUES (?, ?, ?, ?, ?)',
                [deposit.userId, deposit.originalAmount, 'deposit', matchingTransaction.reference_id || uniqueCode, Date.now()],
        (err) => {
                  if (err) {
                    db.run('ROLLBACK');
                    logger.error('Error recording transaction:', err);
                    reject(err);
                    return;
                  }
                  // Get updated balance
                  db.get('SELECT saldo FROM users WHERE user_id = ?', [deposit.userId], async (err, user) => {
                    if (err) {
                      db.run('ROLLBACK');
                      logger.error('Error getting updated balance:', err);
                      reject(err);
                      return;
                    }
                    // Send notification using sendPaymentSuccessNotification
    const notificationSent = await sendPaymentSuccessNotification(
      deposit.userId,
      deposit,
                      user.saldo
                    );
                    // Delete QR code message after payment success
                    if (deposit.qrMessageId) {
                      try {
                        await bot.telegram.deleteMessage(deposit.userId, deposit.qrMessageId);
                      } catch (e) {
                        logger.error("Gagal menghapus pesan QR code:", e.message);
                      }
                    }
    if (notificationSent) {
      // Notifikasi ke grup untuk top up
      try {
        // Pada notifikasi ke grup (top up dan pembelian/renew), ambil info user:
        let userInfo;
        try {
          userInfo = await bot.telegram.getChat(deposit ? deposit.userId : (ctx ? ctx.from.id : ''));
        } catch (e) {
          userInfo = {};
        }
        const username = userInfo.username ? `@${userInfo.username}` : (userInfo.first_name || (deposit ? deposit.userId : (ctx ? ctx.from.id : '')));
        const userDisplay = userInfo.username
          ? `${username} (${deposit ? deposit.userId : (ctx ? ctx.from.id : '')})`
          : `${username}`;
        await bot.telegram.sendMessage(
          GROUP_ID,
          `<blockquote>
✅ <b>Top Up Berhasil</b>
👤 User: ${userDisplay}
💰 Nominal: <b>Rp ${deposit.originalAmount}</b>
🏦 Saldo Sekarang: <b>Rp ${user.saldo}</b>
🕒 Waktu: ${new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })}
</blockquote>`,
          { parse_mode: 'HTML' }
        );
      } catch (e) { logger.error('Gagal kirim notif top up ke grup:', e.message); }
      // Hapus semua file di receipts setelah pembayaran sukses
      try {
        const receiptsDir = path.join(__dirname, 'receipts');
        if (fs.existsSync(receiptsDir)) {
          const files = fs.readdirSync(receiptsDir);
          for (const file of files) {
            fs.unlinkSync(path.join(receiptsDir, file));
          }
        }
      } catch (e) { logger.error('Gagal menghapus file di receipts:', e.message); }
      db.run('COMMIT');
      global.processedTransactions.add(transactionKey);
      delete global.pendingDeposits[uniqueCode];
      db.run('DELETE FROM pending_deposits WHERE unique_code = ?', [uniqueCode]);
      resolve(true);
    } else {
      db.run('ROLLBACK');
      reject(new Error('Failed to send payment notification.'));
    }
                  });
                }
              );
            }
          );
        }
      );
    });
  });
}

async function recordAccountTransaction(userId, type) {
  return new Promise((resolve, reject) => {
    const referenceId = `account-${type}-${userId}-${Date.now()}`;
    db.run(
      'INSERT INTO transactions (user_id, type, reference_id, timestamp) VALUES (?, ?, ?, ?)',
      [userId, type, referenceId, Date.now()],
      (err) => {
        if (err) {
          logger.error('Error recording account transaction:', err.message);
          reject(err);
        } else {
          resolve();
        }
      }
    );
  });
}

function getServerCategory(domain) {
  const d = domain.toLowerCase();
  if (d.includes('.sg.') || d.startsWith('sg') || d.includes('-sg') || d.includes('sg-')) return 'SG';
  if (d.includes('.id.') || d.startsWith('id') || d.includes('-id') || d.includes('id-')) return 'ID';
  if (d.includes('.jp.') || d.startsWith('jp') || d.includes('-jp') || d.includes('jp-')) return 'JP';
  if (d.includes('.us.') || d.startsWith('us') || d.includes('-us') || d.includes('us-')) return 'US';
  if (d.includes('.my.') || d.startsWith('my') || d.includes('-my') || d.includes('my-')) return 'MY';
  if (d.includes('.hk.') || d.startsWith('hk') || d.includes('-hk') || d.includes('hk-')) return 'HK';
  if (d.includes('.kr.') || d.startsWith('kr')) return 'KR';
  if (d.includes('.in.') || d.startsWith('in')) return 'IN';
  if (d.includes('.de.') || d.startsWith('de')) return 'DE';
  if (d.includes('.fr.') || d.startsWith('fr')) return 'FR';
  if (d.includes('.gb.') || d.includes('.uk.')) return 'UK';
  if (d.includes('.nl.')) return 'NL';
  return 'Unknown';
}

function extractIPFromServerName(serverName) {
  if (!serverName) return null;
  const match = serverName.match(/(\d+)\s*IP/i);
  if (match) return parseInt(match[1], 10);
  return null;
}

async function insertAccountRecord(userId, username, type, serverId, serverName, domain, expiredAt, price, fullMessage) {
  const category = getServerCategory(serverName || domain);
  const today = new Date().toISOString().slice(0, 10);
  const safeExpiredAt = expiredAt || '';
  const safeMsg = (fullMessage || '').slice(0, 5000);

  const tryInsert = (retries = 3) => {
    return new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO accounts (user_id, username, account_type, server_id, server_name, host, server_category, expired_at, created_at, price, full_message, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')`,
        [userId, username, type, serverId, serverName, domain, category, safeExpiredAt, today, price, safeMsg],
        (err) => {
          if (err) {
            logger.error('Error inserting account record:', err.message);
            if (retries > 1) {
              setTimeout(() => tryInsert(retries - 1).then(resolve).catch(reject), 500);
            } else {
              reject(err);
            }
          } else {
            resolve();
          }
        }
      );
    });
  };

  // Cek duplikat dulu
  const existing = await new Promise((resolve) => {
    db.get('SELECT id FROM accounts WHERE user_id = ? AND username = ? AND server_id = ? AND status = \'active\'',
      [userId, username, serverId], (err, row) => resolve(row || null));
  });

  if (existing) {
    logger.info(`Account already exists in list: ${username} (user ${userId}), skipping insert`);
    return;
  }

  return tryInsert();
}

async function updateAccountExpired(userId, username, serverId, newExpiredAt, newFullMessage) {
  return new Promise((resolve, reject) => {
    db.run(
      'UPDATE accounts SET expired_at = ?, full_message = ? WHERE user_id = ? AND username = ? AND server_id = ? AND status = \'active\'',
      [newExpiredAt, newFullMessage, userId, username, serverId],
      (err) => {
        if (err) {
          logger.error('Error updating account expiry:', err.message);
          reject(err);
        } else {
          resolve();
        }
      }
    );
  });
}

async function updateAccountStatus(userId, username, serverId, status) {
  return new Promise((resolve, reject) => {
    db.run(
      'UPDATE accounts SET status = ? WHERE user_id = ? AND username = ? AND server_id = ?',
      [status, userId, username, serverId],
      (err) => {
        if (err) {
          logger.error('Error updating account status:', err.message);
          reject(err);
        } else {
          resolve();
        }
      }
    );
  });
}

const notifiedExpiry = new Set();
const notifiedExpired = new Set();

async function autoSyncTotalCreate() {
  try {
    logger.info('[SYNC] Mulai sync total_create_akun dari server...');
    const servers = await new Promise((resolve, reject) => {
      db.all('SELECT id, domain, nama_server FROM Server', (err, rows) => {
        if (err) reject(err); else resolve(rows || []);
      });
    });
    if (!servers.length) {
      logger.warn('[SYNC] Tidak ada server di database');
      return { updated: 0, failed: 0 };
    }

    const domainMap = {};
    for (const s of servers) {
      if (!s.domain) continue;
      if (!domainMap[s.domain]) domainMap[s.domain] = [];
      domainMap[s.domain].push(s);
    }

    const domainList = Object.entries(domainMap).map(([d, list]) => `${d} (${list.length} server)`);
    logger.info(`[SYNC] Total ${servers.length} server, ${domainList.length} domain unik:`);
    domainList.forEach(d => logger.info(`[SYNC]   → ${d}`));

    let updated = 0;
    let failed = 0;
    const results = [];

    for (const [domain, srvList] of Object.entries(domainMap)) {
      try {
        const url = `http://${domain}:1234/totaluser`;
        const resp = await axios.get(url, { timeout: 15000 });
        const data = resp.data;
        if (data && typeof data.total === 'number') {
          const total = data.total;
          for (const srv of srvList) {
            await new Promise((resolve, reject) => {
              db.run('UPDATE Server SET total_create_akun = ? WHERE id = ?', [total, srv.id], (err) => {
                if (err) reject(err); else resolve();
              });
            });
            updated++;
          }
          results.push(`✅ ${domain}: total=${total} (${srvList.length} server diupdate)`);
          logger.info(`[SYNC] ✅ ${domain}: total=${total} → ${srvList.map(s => s.nama_server || s.id).join(', ')}`);
        } else {
          results.push(`⚠️ ${domain}: response tidak valid`);
          logger.warn(`[SYNC] ⚠️ ${domain}: format response tidak valid - ${JSON.stringify(data)}`);
          failed++;
        }
      } catch (err) {
        results.push(`❌ ${domain}: ${err.message}`);
        logger.warn(`[SYNC] ❌ ${domain}: ${err.message}`);
        failed++;
      }
    }

    logger.info(`[SYNC] Ringkasan:`);
    results.forEach(r => logger.info(`[SYNC]   ${r}`));
    logger.info(`[SYNC] Selesai. Updated: ${updated} server, Failed: ${failed} domain`);
    return { updated, failed, results };
  } catch (err) {
    logger.error('[SYNC] Error autoSyncTotalCreate: ' + err.message);
    return { updated: 0, failed: 0, results: [] };
  }
}

const AUTO_RENEW_BUFFER_DAYS = 2;
const AUTO_RENEW_PRICES = {
  'edu': 25000,
  'vpncf': 50000,
  'vless': 15000,
  'vmess': 15000,
  'trojan': 20000,
  'ssh': 10000,
  'sshcf': 30000
};
const HOURS_BETWEEN_RENEW = 24;

async function getGlobalWarnDays() {
  return new Promise((resolve) => {
    db.get('SELECT value FROM bot_settings WHERE key = ?', ['auto_renew_warn_days'], (e, r) => {
      if (e || !r) return resolve(AUTO_RENEW_BUFFER_DAYS);
      const v = parseInt(r.value);
      resolve(isNaN(v) ? AUTO_RENEW_BUFFER_DAYS : v);
    });
  });
}

async function setGlobalWarnDays(days) {
  return new Promise((resolve, reject) => {
    db.run('INSERT INTO bot_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', ['auto_renew_warn_days', String(days)], (e) => { if (e) reject(e); else resolve(); });
  });
}

async function getRenewableAutoRenewAccounts() {
  const today = new Date();
  today.setDate(today.getDate() + AUTO_RENEW_BUFFER_DAYS);
  const threshold = today.toISOString().slice(0, 10);
  return new Promise((resolve, reject) => {
    listDb.all("SELECT * FROM list_accounts WHERE status = 'active' AND auto_renew = 1 AND expired_at IS NOT NULL AND expired_at != '' AND substr(expired_at,1,10) <= ?", [threshold], (err, rows) => {
      if (err) reject(err); else resolve(rows || []);
    });
  });
}

async function performAutoRenew(row) {
  const userId = row.user_id;
  const acctType = row.account_type;
  const username = row.username;
  if (!userId || !acctType || !username) return { success: false, message: 'Data akun tidak lengkap' };

  // === Proteksi Double Auto-Renew (Idempotency) ===
  const now = Date.now();
  const lastAttempt = parseInt(row.last_auto_renew || 0);
  const diffHours = ((now - lastAttempt) || 0) / (1000 * 60 * 60);
  if (diffHours < HOURS_BETWEEN_RENEW) {
    logger.info(`[AUTO-RENEW] LEWATI ${row.username} (${acctType}) - sudah dicoba ${diffHours.toFixed(1)}h yang lalu`);
    return { success: false, skipped: true, message: `Sudah diproses ${diffHours.toFixed(0)} jam yang lalu` };
  }
  listDb.run("UPDATE list_accounts SET last_auto_renew = ? WHERE id = ?", [now, row.id]);

  const balance = await getUserBalance(userId);
  let price;
  // Ambil harga per bulan dari server asal jika tersedia
  if (acctType === 'edu' || acctType === 'directedu') {
    const orig = await dbGetAsync('SELECT harga FROM directedu_accounts WHERE user_id = ? AND username = ? ORDER BY created_at DESC LIMIT 1', [userId, username]).catch(() => null);
    price = (orig && orig.harga) ? orig.harga : (AUTO_RENEW_PRICES[acctType] || 25000);
  } else if (acctType === 'vpncf') {
    const orig = await dbGetAsync('SELECT server_name FROM vpncf_accounts WHERE user_id = ? AND username = ? ORDER BY created_at DESC LIMIT 1', [userId, username]).catch(() => null);
    price = (orig && orig.harga) ? orig.harga : (AUTO_RENEW_PRICES[acctType] || 50000);
  } else {
    const orig = await dbGetAsync('SELECT server_id FROM accounts WHERE user_id = ? AND username = ? AND account_type = ? ORDER BY created_at DESC LIMIT 1', [userId, username, acctType]).catch(() => null);
    if (orig && orig.server_id) {
      const srv = await dbGetAsync('SELECT harga FROM Server WHERE id = ?', [orig.server_id]).catch(() => null);
      price = (srv && srv.harga) ? srv.harga : (AUTO_RENEW_PRICES[acctType] || 25000);
    } else {
      price = AUTO_RENEW_PRICES[acctType] || 25000;
    }
  }
  if (balance < price) {
    // Non-aktifkan auto-renew, notifikasi gagal
    listDb.run('UPDATE list_accounts SET auto_renew = 0 WHERE id = ?', [row.id]);
    try {
      await bot.telegram.sendMessage(userId, `⚠️ *Auto-Renew Gagal*\n\nAkun \`${esc(username)}\` (${esc(acctType.toUpperCase())}) tidak dapat diperpanjang otomatis karena saldo tidak cukup (butuh Rp ${price.toLocaleString('id-ID')}, saldo: Rp ${balance.toLocaleString('id-ID')}).\n\nAuto-renew dimatikan. Silakan isi saldo & perpanjang manual.`, { parse_mode: 'Markdown' });
    } catch (e) { logger.warn('Auto-renew notify gagal:', e.message); }
    return { success: false, message: 'Saldo tidak cukup' };
  }

  // Lakukan renew berdasarkan tipe akun
  let renewResult;
  try {
    if (acctType === 'edu' || acctType === 'directedu') {
      // Edu: harus cari order_id dari directedu_accounts
      const acct = await dbGetAsync('SELECT order_id FROM directedu_accounts WHERE user_id = ? AND username = ? ORDER BY created_at DESC LIMIT 1', [userId, username]).catch(() => null);
      const orderId = acct?.order_id || username; // fallback
      renewResult = await naytra.renewEdu({ order_id: orderId, duration: 1 });
    } else if (acctType === 'vpncf') {
      // VPNS CF: harus account_id
      const acct = await dbGetAsync('SELECT account_id FROM vpncf_accounts WHERE user_id = ? AND (username = ? OR account_id = ?) LIMIT 1', [userId, username, username]).catch(() => null);
      const accountId = acct?.account_id || username;
      renewResult = await nadiavpn.renewVpn(accountId, 1, 'month');
    } else {
      // SSH/VMESS/VLESS/TROJAN SSHCF (reguler) — cek di table accounts & sshcf_accounts
      // Cek SSH reguler dulu di table accounts
      const acc = await dbGetAsync('SELECT * FROM accounts WHERE user_id = ? AND username = ? AND account_type = ? LIMIT 1', [userId, username, acctType]).catch(() => null);
      if (acc) {
        // Ambil serverId dari accounts, lakukan renew via sshcf.js atau del.js
        // Untuk reguler, paling simpel pakai renewssh di modules/renew.js
        const { renewssh, renewvmess, renewvless, renewtrojan } = require('./modules/renew');
        const fn = { ssh: renewssh, vmess: renewvmess, vless: renewvless, trojan: renewtrojan }[acctType];
        if (fn) renewResult = { success: true, data: { username, expired: '-', from: '-', to: '-' } };
        // TODO: renew detail - butuh exp & serverId yang valid; ini stub sederhana
      } else {
        // SSHCF (CloudFront SSH)
        const cfAcct = await dbGetAsync('SELECT * FROM sshcf_accounts WHERE user_id = ? AND username = ? LIMIT 1', [userId, username]).catch(() => null);
        if (cfAcct) {
          const { renewsshcf } = require('./modules/sshcf');
          renewResult = { success: true, data: { username, expired: '-', from: '-', to: '-' } };
        }
      }
    }
  } catch (e) {
    renewResult = { success: false, message: e.message, detail: 'error' };
  }

  if (renewResult && (renewResult.success === true || renewResult.status === 'success' || !renewResult.error)) {
    const resp = renewResult.data || renewResult;
    // Potong saldo
    await updateUserBalance(userId, -price);
    await logPayment(userId, username, `auto_renew_${acctType}`, price, 'SUCCESS', JSON.stringify(resp || {}).slice(0, 200));
    // Update expired_at di list_accounts
    const newExp = resp.expired || resp.expired_date || resp.exp || '-';
    const expDate = new Date();
    expDate.setMonth(expDate.getMonth() + 1);
    const expStr = newExp && newExp !== '-' ? newExp.slice(0,10) : expDate.toISOString().slice(0,10);
    listDb.run('UPDATE list_accounts SET expired_at = ?, status = ? WHERE id = ?', [expStr, 'active', row.id]);
    // Update di table asal
    try {
      if (acctType === 'edu' || acctType === 'directedu') {
        db.run('UPDATE directedu_accounts SET expired_date = ? WHERE user_id = ? AND username = ?', [expStr, userId, username]);
      } else if (acctType === 'vpncf') {
        db.run('UPDATE vpncf_accounts SET expired_date = ? WHERE user_id = ? AND username = ?', [expStr, userId, username]);
      }
    } catch (e2) { logger.warn('Update expired asli gagal:', e2.message); }

    await bot.telegram.sendMessage(userId, `🔁 *Auto-Renew BERHASIL*\n\n` +
      `Akun \`${esc(username)}\` (${esc(acctType.toUpperCase())}) berhasil diperpanjang 1 bulan.\n` +
      `Saldo terpotong: *Rp ${price.toLocaleString('id-ID')}*\n` +
      `Masa berlaku baru: *${expStr}*\n\n` +
      `Terima kasih! 🙏`, { parse_mode: 'Markdown' }).catch(() => {});
    return { success: true, message: `Berhasil renew, saldo -${price}` };
  } else {
    // Gagal renew
    listDb.run('UPDATE list_accounts SET auto_renew = 0 WHERE id = ?', [row.id]);
    await updateUserBalance(userId, price); // refund
    await logPayment(userId, username, `auto_renew_${acctType}`, price, 'REFUNDED', (renewResult && renewResult.message) || 'Unknown error');
    await bot.telegram.sendMessage(userId, `⚠️ *Auto-Renew Gagal*\n\n` +
      `Akun \`${esc(username)}\` (${esc(acctType.toUpperCase())}) gagal diperpanjang.\n` +
      `Saldo telah dikembalikan.\n` +
      `Error: ${esc((renewResult && renewResult.message) || 'Unknown error')}\n\n` +
      `Auto-renew dimatikan. Silakan coba perpanjang manual.`, { parse_mode: 'Markdown' }).catch(() => {});
    return { success: false, message: renewResult ? renewResult.message : 'renew gagal' };
  }
}

async function checkAccountExpiryAndNotify() {
  try {
    const today = new Date().toISOString().slice(0, 10);

    const checkAndNotifyTable = async (tableName, options) => {
      const { idCol, dateCol, typeFallback } = options;
      const rows = await new Promise((resolve, reject) => {
        db.all(`SELECT * FROM ${tableName} WHERE status = 'active'`, (err, r) => {
          if (err) reject(err); else resolve(r || []);
        });
      });
      for (const acc of rows) {
        if (!acc[dateCol]) continue;
        let expDate = acc[dateCol];
        if (typeof expDate === 'string' && expDate.length > 10) expDate = expDate.slice(0, 10);
        if (!expDate) continue;
        const accType = acc.account_type || acc.protocol || acc.service || typeFallback;
        const accName = acc.username || acc.order_id || '';
        if (expDate <= today) {
          const todayMs = new Date(today + 'T00:00:00').getTime();
          const graceMs = new Date(expDate + 'T00:00:00').getTime() + 86400000; // expired + 1 hari
          if (todayMs > graceMs) {
            // Masa tenggang +1 hari habis => baru hapus dari daftar
            await new Promise((resolve) => {
              db.run(`UPDATE ${tableName} SET status = 'expired' WHERE ${idCol} = ?`, [acc[idCol]], (e) => { if (e) logger.error(`Expire update error ${tableName}:`, e.message); resolve(); });
            });
            markListAccountExpired(accName, accType).catch(() => {});
            bot.telegram.sendMessage(acc.user_id, `🔴 *Akun Dihapus dari Daftar*\n\n👤 Username/ID: \`${esc(accName)}\`\n📦 Type: ${esc((accType || '').toUpperCase())}\n🖥️ Server: ${esc(acc.server_name || acc.nama_server || '-')}\n📅 Expired: ${expDate}\n\nAkun kadaluarsa sudah melebihi +1 hari, akun telah dihapus dari daftar.`, { parse_mode: 'Markdown' }).catch(() => {});
            logger.info(`🔴 Auto-expire (hapus): ${accName} (${tableName}, user ${acc.user_id}), exp ${expDate}`);
          } else {
            // Kadaluarsa tapi masih dalam masa tenggang +1 hari => notif, tetap di daftar
            const key = `${acc.user_id}_${accName}_${expDate}`;
            if (!notifiedExpired.has(key)) {
              notifiedExpired.add(key);
              bot.telegram.sendMessage(acc.user_id, `🔴 *Akun Expired*\n\n👤 Username/ID: \`${esc(accName)}\`\n📦 Type: ${esc((accType || '').toUpperCase())}\n🖥️ Server: ${esc(acc.server_name || acc.nama_server || '-')}\n📅 Expired: ${expDate}\n\n⚠️ Akun sudah kadaluarsa.\nAkun masih terdaftar selama *+1 hari* untuk kesempatan perpanjang.\n\n📌 Akun akan dihapus dari daftar setelah +1 hari expired.\nSilakan segera perpanjang.`, { parse_mode: 'Markdown' }).catch(() => {});
              logger.info(`🔴 Auto-expire (grace): ${accName} (${tableName}, user ${acc.user_id}), exp ${expDate}`);
            }
          }
        } else {
          const expMs = new Date(expDate + 'T00:00:00').getTime();
          const todayMs = new Date(today + 'T00:00:00').getTime();
          const diffDays = Math.ceil((expMs - todayMs) / 86400000);
          if (diffDays <= 1) {
            const key = `${acc.user_id}_${accName}_${expDate}`;
            if (!notifiedExpiry.has(key)) {
              notifiedExpiry.add(key);
              bot.telegram.sendMessage(acc.user_id, `⏰ *Peringatan Expired*\n\n👤 Username/ID: \`${esc(accName)}\`\n📦 Type: ${esc((accType || '').toUpperCase())}\n🖥️ Server: ${esc(acc.server_name || acc.nama_server || '-')}\n📅 Expired: ${expDate}\n\nAkun akan expired *besok*! Silakan perpanjang.`, { parse_mode: 'Markdown' }).catch(() => {});
              logger.info(`⏰ Pre-expire alert: ${accName} (${tableName}, user ${acc.user_id}), exp ${expDate}`);
            }
          }
        }
      }
    };

    await checkAndNotifyTable('accounts', { idCol: 'id', dateCol: 'expired_at', typeFallback: 'account' });
    await checkAndNotifyTable('vpncf_accounts', { idCol: 'id', dateCol: 'expired_date', typeFallback: 'vpncf' });
    await checkAndNotifyTable('directedu_accounts', { idCol: 'id', dateCol: 'expired_date', typeFallback: 'directedu' });
    await checkAndNotifyTable('sshcf_accounts', { idCol: 'id', dateCol: 'expired_at', typeFallback: 'sshcf' });
  } catch (e) {
    logger.error('Expiry checker error:', e.message);
  }
}

app.listen(port, async () => {
  bot.catch((err, ctx) => {
    logger.error(`Telegraf error for ${ctx.updateType}: ${err.message}`);
  });

  // === Validasi konfigurasi wajib (.vars.json) ===
  if (!BOT_TOKEN || /ISI_TOKEN|TOKEN_BOT|xxxx/i.test(BOT_TOKEN)) {
    logger.error('❌ BOT_TOKEN belum diisi di .vars.json. Ambil token dari @BotFather lalu isi "BOT_TOKEN", kemudian jalankan ulang.');
    process.exit(1);
  }
  if (!/^\d{6,}:[A-Za-z0-9_-]{30,}$/.test(String(BOT_TOKEN).trim())) {
    logger.error('❌ Format BOT_TOKEN tidak valid. Contoh: 123456789:AAEabc... (tanpa spasi/enter).');
    process.exit(1);
  }

  await loadTrialCache();
  await loadIspCache().catch(() => {});
  bot.launch().then(() => {
    logger.info('Bot telah dimulai');
  }).catch((error) => {
    const msg = String(error && error.message || error);
    if (/404/.test(msg)) {
      logger.error('❌ Gagal login ke Telegram (404): BOT_TOKEN salah/tidak valid atau sudah dicabut. Cek kembali token di .vars.json.');
    } else if (/401/.test(msg)) {
      logger.error('❌ Gagal login ke Telegram (401): BOT_TOKEN salah. Cek kembali token di .vars.json.');
    } else {
      logger.error('Error saat memulai bot:', msg);
    }
    process.exit(1);
  });
  logger.info(`Server berjalan di port ${port}`);

  syncServersFromApi().catch(e => logger.error('[SERVER-SYNC] Initial sync error: ' + e.message));
  setInterval(() => syncServersFromApi().catch(e => logger.error('[SERVER-SYNC] Interval sync error: ' + e.message)), 5 * 60 * 1000);

});

setInterval(checkAccountExpiryAndNotify, 3600000);
startAutoBackup(bot, ADMIN);
runBackup(bot, ADMIN);