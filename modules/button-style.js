function getButtonStyle(text) {
  const t = String(text || '').toLowerCase();
  if (
    t.includes('kembali') ||
    t.includes('batal') ||
    t.includes('back') ||
    t.includes('cancel') ||
    t.includes('hapus') ||
    t.includes('delete') ||
    t.includes('🔙')
  ) {
    return 'danger';
  }
  if (
    t.includes('✅') ||
    t.includes('konfirmasi') ||
    t.includes('confirm') ||
    t.startsWith('ya')
  ) {
    return 'success';
  }
  return 'primary';
}

function styleButton(btn) {
  if (
    btn &&
    typeof btn === 'object' &&
    (btn.callback_data || btn.url || btn.web_app || btn.login_url || btn.switch_inline_query || btn.callback_game || btn.pay)
  ) {
    if (!btn.style) {
      return { ...btn, style: getButtonStyle(btn.text) };
    }
  }
  return btn;
}

function styleKeyboard(keyboard) {
  if (!Array.isArray(keyboard)) return keyboard;
  return keyboard.map((row) => (Array.isArray(row) ? row.map(styleButton) : row));
}

function styleReplyMarkup(replyMarkup) {
  if (!replyMarkup || typeof replyMarkup !== 'object') return replyMarkup;
  if (replyMarkup.reply_markup) {
    return { ...replyMarkup, reply_markup: styleReplyMarkup(replyMarkup.reply_markup) };
  }
  if (replyMarkup.inline_keyboard) {
    return { ...replyMarkup, inline_keyboard: styleKeyboard(replyMarkup.inline_keyboard) };
  }
  if (replyMarkup.keyboard) {
    return { ...replyMarkup, keyboard: styleKeyboard(replyMarkup.keyboard) };
  }
  return replyMarkup;
}

module.exports = { getButtonStyle, styleButton, styleKeyboard, styleReplyMarkup };