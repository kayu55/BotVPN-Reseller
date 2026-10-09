/**
 * server-store.js
 * Akses tabel Server lokal (mirror dari API BotVPN).
 * Bot ini TIDAK membuat/mengubah server — hanya membaca hasil sinkronisasi.
 */

const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database(path.join(__dirname, '..', 'sellvpn.db'));

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row || null)));
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows || [])));
  });
}

module.exports = {
  db,
  get,
  all,
  getById: (id) => get('SELECT * FROM Server WHERE id = ?', [id]),
  getByDomain: (domain) => get('SELECT * FROM Server WHERE domain = ?', [domain])
};
