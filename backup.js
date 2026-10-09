const fs = require('fs');
const path = require('path');

const DB_FILES = ['sellvpn.db', 'ressel.db', 'trial.db', 'listaccount.db'];

async function runBackup(bot, adminId) {
  const results = [];
  for (const file of DB_FILES) {
    const filePath = path.join(__dirname, file);
    if (!fs.existsSync(filePath)) {
      results.push(`File ${file} tidak ditemukan`);
      continue;
    }
    try {
      await bot.telegram.sendDocument(adminId, { source: filePath });
      results.push(`✅ ${file} berhasil dikirim`);
    } catch (err) {
      results.push(`❌ ${file} gagal: ${err.message}`);
    }
  }
  return results;
}

function startAutoBackup(bot, adminId) {
  console.log('[BACKUP] Auto backup scheduler started (every 1 hour)');

  runBackup(bot, adminId).then(results => {
    console.log('[BACKUP INITIAL]', results.join(' | '));
  });

  setInterval(() => {
    runBackup(bot, adminId).then(results => {
      console.log('[BACKUP HOURLY]', results.join(' | '));
    });
  }, 30 * 60 * 1000);
}

module.exports = { runBackup, startAutoBackup };
