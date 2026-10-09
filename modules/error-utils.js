function redactSensitive(input) {
  let s = String(input == null ? '' : input);
  s = s.replace(/(Authorization\s*[:=]\s*)(?:Bearer\s+)?[^\s"']+/gi, '$1***');
  s = s.replace(/(--proxy-user\s+")([^"]*)(")/gi, '$1***$3');
  s = s.replace(/(--proxy-user\s+)([^\s"']+)/gi, '$1***');
  s = s.replace(/(\bBearer\s+)[A-Za-z0-9._\-]+/gi, '$1***');
  s = s.replace(/([?&](?:token|api_key|apikey|key|auth)=)[^&#\s"']+/gi, '$1***');
  s = s.replace(/\b(sk_live|sk_test|sk-)[A-Za-z0-9._\-]+/gi, '$1***');
  return s;
}

function isCommandLeak(input) {
  const s = String(input || '');
  return /Command failed:\s*curl/i.test(s) || /\bcurl\s+-{1,2}[A-Za-z]/.test(s);
}

function safeErrorMessage(error, fallback = 'Terjadi kesalahan. Silakan coba lagi.') {
  if (!error) return fallback;
  const raw = String(error.message || '');
  const code = String(error.code || '');
  const combined = `${code} ${raw}`;
  if (/ENOENT/.test(combined)) return 'Layanan tidak tersedia saat ini.';
  if (/ETIMEDOUT|ETIMEOUT|timed out/i.test(combined)) return 'Koneksi ke server timeout. Silakan coba lagi.';
  if (/ECONNREFUSED|ECONNRESET|ENOTFOUND|EAI_AGAIN|EPIPE/i.test(combined)) return 'Tidak dapat terhubung ke server. Silakan coba lagi.';
  if (/curl|Command failed/i.test(combined)) return fallback;
  return redactSensitive(fallback);
}

module.exports = { redactSensitive, isCommandLeak, safeErrorMessage };
