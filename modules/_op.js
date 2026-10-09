/**
 * _op.js
 * Helper internal untuk modul proxy panel.
 * Menjalankan operasi lewat API BotVPN dan mengembalikan pesan siap kirim.
 */

const api = require('./api-client');

function extractMessage(body) {
  if (!body) return '❌ Respons kosong dari API.';
  if (body.success === false) {
    return `❌ ${body.message || body.code || 'Operasi gagal.'}`;
  }
  const d = body.data !== undefined ? body.data : body;
  if (d == null) return '❌ Respons tidak valid dari API.';
  if (typeof d === 'string') return d;
  if (d.message) return d.message;
  return '❌ Respons tidak valid dari API.';
}

async function opMessage(payload) {
  try {
    const body = await api.operation(payload);
    return extractMessage(body);
  } catch (e) {
    return `❌ ${e.message}`;
  }
}

async function opData(payload) {
  const body = await api.operation(payload);
  if (body && body.success === false) {
    const err = new Error(body.message || 'Operasi gagal');
    err.apiCode = body.code;
    err.apiBody = body;
    throw err;
  }
  return body ? body.data : null;
}

module.exports = { opMessage, opData, extractMessage };
