const crypto = require('crypto');
const { t, loadUserLanguage } = require('./i18n');

const SESSION_TTL_MS = 5 * 60 * 1000;

class ConfirmManager {
  constructor(bot, db, logger, config = {}) {
    this.bot = bot;
    this.db = db;
    this.logger = logger;
    this.ttlMs = config.ttlMs || SESSION_TTL_MS;
    this.sessions = new Map();
    this._cleanupTimer = setInterval(() => this.cleanExpired(), 60 * 1000);
    if (this._cleanupTimer.unref) this._cleanupTimer.unref();
  }

  cleanExpired() {
    const now = Date.now();
    for (const [id, s] of this.sessions) {
      if (now - s.createdAt > this.ttlMs) {
        this.sessions.delete(id);
      }
    }
  }

  attach(bot) {
    bot.action(/^cfm_yes_(.+)$/, async (ctx) => {
      await ctx.answerCbQuery().catch(() => {});
      await this.handleYes(ctx, ctx.match[1]);
    });
    bot.action(/^cfm_no_(.+)$/, async (ctx) => {
      await ctx.answerCbQuery().catch(() => {});
      await this.handleNo(ctx, ctx.match[1]);
    });
  }

  generateId() {
    return 'CFM-' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  }

  async ask(ctx, opts) {
    const sessionId = this.generateId();
    await loadUserLanguage(ctx.from.id);

    const session = {
      sessionId,
      userId: ctx.from.id,
      chatId: ctx.chat?.id || ctx.from.id,
      title: opts.title || t(ctx.from.id, 'confirm_default_title'),
      lines: opts.lines || [],
      detailLines: opts.detailLines || opts.lines || [],
      price: opts.price || 0,
      data: opts.data || {},
      executor: opts.executor,
      cancelHandler: opts.onCancel || null,
      status: 'PENDING_CONFIRMATION',
      createdAt: Date.now(),
      messageId: null,
    };

    this.sessions.set(sessionId, session);

    const text = this.buildConfirmMessage(session);
    const reply = await ctx.reply(text, {
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [
          [{ text: t(session.userId, 'confirm_btn_yes'), callback_data: `cfm_yes_${sessionId}` }],
          [{ text: t(session.userId, 'confirm_btn_no'), callback_data: `cfm_no_${sessionId}` }],
        ],
      },
    }).catch(() => null);

    if (reply) session.messageId = reply.message_id;
    return session;
  }

  buildConfirmMessage(s) {
    let msg = `━━━━━━━━━━━━━━━━━━\n📋 *${s.title}*\n━━━━━━━━━━━━━━━━━━\n\n`;
    for (const [label, value] of s.lines) {
      msg += `${label} : ${value}\n`;
    }
    msg += `\n━━━━━━━━━━━━━━━━━━\n${t(s.userId, 'confirm_verify')}`;
    return msg;
  }

  buildProcessingMessage(s) {
    let msg = t(s.userId, 'confirm_wait');
    for (const [label, value] of s.detailLines) {
      msg += `${label} : ${value}\n`;
    }
    return msg;
  }

  async handleYes(ctx, sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return ctx.reply(t(ctx.from.id, 'confirm_session_missing'), { parse_mode: 'Markdown' }).catch(() => {});
    }

    await loadUserLanguage(session.userId);

    if (ctx.from.id !== session.userId) {
      return ctx.answerCbQuery ? ctx.answerCbQuery(t(session.userId, 'confirm_not_yours')).catch(() => {}) : null;
    }

    if (Date.now() - session.createdAt > this.ttlMs) {
      this.sessions.delete(sessionId);
      try {
        await this.bot.telegram.editMessageText(session.chatId, session.messageId, undefined,
          t(session.userId, 'confirm_expired'),
          { parse_mode: 'Markdown' });
      } catch (e) {}
      return ctx.reply(t(session.userId, 'confirm_expired'), { parse_mode: 'Markdown' }).catch(() => {});
    }

    if (session.status !== 'PENDING_CONFIRMATION') {
      return ctx.reply(t(session.userId, 'confirm_already'), { parse_mode: 'Markdown' }).catch(() => {});
    }

    session.status = 'PROCESSING';
    session.confirmedAt = Date.now();

    try {
      await this.bot.telegram.editMessageText(session.chatId, session.messageId, undefined, this.buildProcessingMessage(session), { parse_mode: 'Markdown' });
    } catch (e) {}

    try {
      const result = await session.executor(ctx, session);
      if (result && result.needsPayment) {
        session.status = 'CONFIRMED';
      } else if (result && result.refunded) {
        session.status = 'FAILED';
      } else {
        session.status = 'SUCCESS';
      }
    } catch (err) {
      this.logger.error(`ConfirmManager executor error ${sessionId}: ${err.message}`);
      session.status = 'FAILED';
      try {
        await this.bot.telegram.editMessageText(session.chatId, session.messageId, undefined,
          t(session.userId, 'confirm_error'), { parse_mode: 'Markdown' });
      } catch (e) {}
      await ctx.reply(t(session.userId, 'confirm_error2'), { parse_mode: 'Markdown' }).catch(() => {});
    }

    this.sessions.delete(sessionId);
  }

  async handleNo(ctx, sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return ctx.reply(t(ctx.from.id, 'confirm_session_missing'), { parse_mode: 'Markdown' }).catch(() => {});
    }

    await loadUserLanguage(session.userId);

    if (ctx.from.id !== session.userId) {
      return ctx.answerCbQuery ? ctx.answerCbQuery(t(session.userId, 'confirm_not_yours')).catch(() => {}) : null;
    }

    if (session.status !== 'PENDING_CONFIRMATION') {
      return ctx.reply(t(session.userId, 'confirm_already'), { parse_mode: 'Markdown' }).catch(() => {});
    }

    session.status = 'CANCELLED';
    this.sessions.delete(sessionId);

    const cancelText = t(session.userId, 'confirm_cancelled');
    try {
      await this.bot.telegram.editMessageText(session.chatId, session.messageId, undefined, cancelText, { parse_mode: 'Markdown' });
    } catch (e) {
      await ctx.reply(cancelText, { parse_mode: 'Markdown' }).catch(() => {});
    }

    if (session.cancelHandler) {
      try { await session.cancelHandler(ctx, session); } catch (e) { this.logger.error(`ConfirmManager cancel handler error: ${e.message}`); }
    }
  }

  getSession(sessionId) {
    return this.sessions.get(sessionId);
  }

  clearUserSessions(userId) {
    for (const [id, s] of this.sessions) {
      if (s.userId === userId) this.sessions.delete(id);
    }
  }
}

module.exports = ConfirmManager;