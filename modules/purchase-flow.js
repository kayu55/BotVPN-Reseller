const axios = require('axios');
const crypto = require('crypto');
const { t, loadUserLanguage } = require('./i18n');

// Ringkas 1 baris supaya aman dipakai di dalam backtick Markdown.
function oneLine(text, max = 300) {
  return String(text == null ? '' : text)
    .replace(/\s+/g, ' ')
    .replace(/[`\\]/g, '')
    .trim()
    .substring(0, max) || '-';
}

// Bug internal (TypeError, ReferenceError, "is not a function", ...) bukan
// penolakan dari server. Kalau ini terjadi, kita tidak tahu apakah akunnya sudah
// dibuat di panel atau belum — jadi JANGAN refund, eskalasi ke admin.
function isInternalError(error) {
  if (!error) return false;
  if (error.uncertain) return true;
  if (error instanceof TypeError || error instanceof ReferenceError || error instanceof SyntaxError) return true;
  const msg = String(error.message || '');
  return /is not a function|is not defined|Cannot read propert|Cannot convert|Assignment to constant|of undefined|of null/i.test(msg);
}

class PurchaseFlow {
  constructor(bot, db, logger, config) {
    this.bot = bot;
    this.db = db;
    this.logger = logger;
    this.config = config;
    this.executor = null;
    this.pendingCache = new Map();
    this.pendingDepositsRef = null;
  }

  setExecutor(fn) {
    this.executor = fn;
  }

  setPendingDepositsRef(ref) {
    this.pendingDepositsRef = ref;
  }

  async init() {
    await this.dbRunAsync(`
      CREATE TABLE IF NOT EXISTS purchases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_id TEXT UNIQUE NOT NULL,
        invoice_id TEXT,
        user_id INTEGER NOT NULL,
        product TEXT NOT NULL,
        shortage_amount INTEGER DEFAULT 0,
        total_harga INTEGER NOT NULL,
        status TEXT DEFAULT 'PENDING_PAYMENT',
        created_at INTEGER NOT NULL,
        paid_at INTEGER,
        finished_at INTEGER,
        purchase_data TEXT,
        unique_code TEXT UNIQUE,
        error_log TEXT
      )
    `);
    await this.loadPendingPurchases();
  }

  async loadPendingPurchases() {
    try {
      const rows = await this.dbAllAsync(
        "SELECT * FROM purchases WHERE status IN ('PENDING_PAYMENT')"
      );
      for (const row of rows) {
        if (row.unique_code) {
          this.pendingCache.set(row.unique_code, row);
        }
      }
      this.logger.info(`Loaded ${rows.length} pending purchases from DB`);
    } catch (e) {
      this.logger.error(`Failed to load pending purchases: ${e.message}`);
    }
  }

  async initiatePurchase(ctx, { product, totalHarga, purchaseData }) {
    const userId = ctx.from.id;
    const balance = await this.getUserBalance(userId);

    if (balance >= totalHarga) {
      return this.executePurchase(ctx, { userId, product, totalHarga, purchaseData });
    }

    const shortage = totalHarga - balance;
    return this.createPurchaseQRIS(ctx, { userId, product, totalHarga, shortage, purchaseData });
  }

  async executePurchase(ctx, { userId, product, totalHarga, purchaseData }) {
    const transactionId = this.generateId('TRX');
    await loadUserLanguage(userId);

    await this.updateUserBalance(userId, -totalHarga);
    this.logger.info(`Saldo dipotong Rp${totalHarga} dari user ${userId} untuk ${product}`);

    const processingMsg = await ctx.reply(t(userId, 'pur_processing'), { parse_mode: 'Markdown' }).catch(() => null);

    const taskQueue = require('./task-queue');
    taskQueue.runBackground(userId,
      async () => {
        try {
          const result = await this.executor({ ...purchaseData, userId });
          const msg = result && result.message ? result.message : (result || '');
          const failed = msg.includes('❌') || (result && result.error);

          if (failed) {
            throw new Error(typeof msg === 'string' ? msg : (result.error || 'Unknown error'));
          }

          const now = Date.now();
          await this.dbRunAsync(
            `INSERT INTO purchases (transaction_id, user_id, product, total_harga, status, created_at, paid_at, finished_at, purchase_data)
             VALUES (?, ?, ?, ?, 'SUCCESS', ?, ?, ?, ?)`,
            [transactionId, userId, product, totalHarga, now, now, now, JSON.stringify(purchaseData)]
          );
          await this.recordTransaction(userId, product, totalHarga, 'SUCCESS', transactionId);

          if (processingMsg) {
            try { await this.bot.telegram.editMessageText(ctx.chat.id, processingMsg.message_id, undefined, msg, { parse_mode: 'Markdown' }); } catch (e) { await this.bot.telegram.sendMessage(userId, msg, { parse_mode: 'Markdown' }); }
          } else {
            await this.bot.telegram.sendMessage(userId, msg, { parse_mode: 'Markdown' });
          }
        } catch (error) {
          if (isInternalError(error)) {
            await this.recordTransaction(userId, product, totalHarga, 'PENDING_VERIFY', transactionId, error.message);
            this.logger.error(`Purchase UNCERTAIN for user ${userId} (${product}), saldo TIDAK dikembalikan: ${error.message}`);
            await this.notifyAdmin(
              `⚠️ *ORDER PERLU DIVERIFIKASI (BELUM REFUND)*\n👤 User: \`${userId}\`\n📦 Produk: \`${product}\`\n💰 Harga: Rp${totalHarga}\n🆔 Trx: \`${transactionId}\`\n⚠️ Error: \`${(error.message || '').substring(0, 200)}\`\n\nCek panel dulu sebelum refund manual.`
            );
            const verifyMsg = t(userId, 'pur_pending_verify');
            if (processingMsg) {
              try { await this.bot.telegram.editMessageText(ctx.chat.id, processingMsg.message_id, undefined, verifyMsg, { parse_mode: 'Markdown' }); } catch (e) { try { await this.bot.telegram.sendMessage(userId, verifyMsg, { parse_mode: 'Markdown' }); } catch (e2) {} }
            } else {
              try { await this.bot.telegram.sendMessage(userId, verifyMsg, { parse_mode: 'Markdown' }); } catch (e) {}
            }
            return;
          }

          await this.updateUserBalance(userId, totalHarga);
          await this.recordTransaction(userId, product, totalHarga, 'REFUNDED', transactionId, error.message);
          this.logger.error(`Purchase FAILED for user ${userId}, refunded Rp${totalHarga}: ${error.message}`);

          await this.notifyAdmin(
            `❌ *FAILED CREATE (REFUNDED)*\n👤 User: \`${userId}\`\n📦 Produk: \`${oneLine(product, 60)}\`\n💰 Refund: Rp${Number(totalHarga) || 0}\n🆔 Invoice: \`${transactionId}\`\n⚠️ Error: \`${oneLine(error.message, 300)}\``
          );

          const errMsg = t(userId, 'pur_failed_refund');
          if (processingMsg) {
            try { await this.bot.telegram.editMessageText(ctx.chat.id, processingMsg.message_id, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await this.bot.telegram.sendMessage(userId, errMsg, { parse_mode: 'Markdown' }); }
          } else {
            await this.bot.telegram.sendMessage(userId, errMsg, { parse_mode: 'Markdown' });
          }
        }
      },
      () => {},
      async (err) => {
        this.logger.error(`Background task error untuk user ${userId}: ${err.message}`);
        await this.updateUserBalance(userId, totalHarga);
        await this.recordTransaction(userId, product, totalHarga, 'REFUNDED', transactionId, (err.message || '').substring(0, 200));
        await this.notifyAdmin(
          `❌ *FAILED CREATE (REFUNDED)*\n👤 User: \`${userId}\`\n📦 Produk: \`${oneLine(product, 60)}\`\n💰 Refund: Rp${Number(totalHarga) || 0}\n🆔 Invoice: \`${transactionId}\`\n⚠️ Error: \`${oneLine(err && err.message, 300)}\``
        );
        const errMsg = t(userId, 'pur_generic_error_refund');
        if (processingMsg) {
          try { await this.bot.telegram.editMessageText(ctx.chat.id, processingMsg.message_id, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { await this.bot.telegram.sendMessage(userId, errMsg, { parse_mode: 'Markdown' }); }
        } else {
          await this.bot.telegram.sendMessage(userId, errMsg, { parse_mode: 'Markdown' });
        }
      }
    );

    return { success: true, transactionId };
  }

  async createPurchaseQRIS(ctx, { userId, product, totalHarga, shortage, purchaseData }) {
    const transactionId = this.generateId('TRX');
    const invoiceId = this.generateId('INV');
    const uniqueCode = `buy-${userId}-${Date.now()}`;
    const now = Date.now();
    await loadUserLanguage(userId);

    try {
      let qrResult;

      if (this.config.vars.PAYMENT === 'ORKUT') {
        qrResult = await this.generateOrkutQRIS(ctx, shortage, uniqueCode);
      } else if (this.config.vars.PAYMENT === 'GOPAY') {
        qrResult = await this.generateGopayQRIS(ctx, shortage, uniqueCode);
      } else if (this.config.vars.PAYMENT === 'SHOPEEPAY') {
        qrResult = await this.generateShopeePayQRIS(ctx, shortage, uniqueCode);
      } else {
        throw new Error('Konfigurasi PAYMENT tidak valid');
      }

      await this.dbRunAsync(
        `INSERT INTO purchases (transaction_id, invoice_id, user_id, product, shortage_amount, total_harga, status, created_at, purchase_data, unique_code)
         VALUES (?, ?, ?, ?, ?, ?, 'PENDING_PAYMENT', ?, ?, ?)`,
        [transactionId, invoiceId, userId, product, shortage, totalHarga, now, JSON.stringify(purchaseData), uniqueCode]
      );

      await this.recordTransaction(userId, product, totalHarga, 'PENDING_PAYMENT', transactionId);

      this.pendingCache.set(uniqueCode, {
        id: null,
        transaction_id: transactionId,
        invoice_id: invoiceId,
        user_id: userId,
        product,
        shortage_amount: shortage,
        total_harga: totalHarga,
        purchase_data: JSON.stringify(purchaseData),
        unique_code: uniqueCode,
        status: 'PENDING_PAYMENT',
        created_at: now
      });

      const adminFee = qrResult.adminFee || 0;
      const finalAmount = shortage + adminFee;
      const depositInfo = {
        amount: finalAmount,
        originalAmount: shortage,
        userId,
        timestamp: now,
        status: 'pending',
        qrMessageId: qrResult.qrMessageId,
        transactionId: qrResult.transactionId || null,
        chatId: ctx.chat?.id || userId
      };

      if (this.pendingDepositsRef) {
        this.pendingDepositsRef[uniqueCode] = depositInfo;
      }

      try {
        await this.dbRunAsync(
          `INSERT INTO pending_deposits (unique_code, user_id, amount, original_amount, timestamp, status, qr_message_id, transaction_id, chat_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [uniqueCode, userId, finalAmount, shortage, now, 'pending', qrResult.qrMessageId || '', qrResult.transactionId || '', ctx.chat?.id || userId]
        );
      } catch (e) {
        this.logger.error(`Gagal simpan pending_deposit: ${e.message}`);
      }

      return {
        success: true,
        needsPayment: true,
        shortage,
        totalHarga,
        invoiceId,
        transactionId,
        uniqueCode,
        qrMessageId: qrResult.qrMessageId,
        qrImage: qrResult.qrImage,
        paymentMethod: this.config.vars.PAYMENT
      };
    } catch (error) {
      this.logger.error(`Gagal buat QRIS purchase untuk user ${userId}: ${error.message}`);
      return { success: false, error: error.message };
    }
  }

  async handlePostPayment(uniqueCode) {
    let purchase = this.pendingCache.get(uniqueCode);

    if (!purchase) {
      const rows = await this.dbAllAsync(
        "SELECT p.* FROM purchases p WHERE p.unique_code = ? AND p.status IN ('PENDING_PAYMENT','PAID')",
        [uniqueCode]
      );
      if (rows && rows.length > 0) purchase = rows[0];
    }

    if (!purchase) return { type: 'topup' };

    const now = Date.now();
    const purchaseId = purchase.id;
    const userId = purchase.user_id;
    const totalHarga = purchase.total_harga;
    const purchaseData = JSON.parse(purchase.purchase_data || '{}');
    const maxAge = this.config.vars.PAYMENT === 'GOPAY' ? 15 * 60 * 1000 : (this.config.vars.PAYMENT === 'SHOPEEPAY' ? 20 * 60 * 1000 : 60 * 60 * 1000);
    await loadUserLanguage(userId);

    const isExpired = (now - (purchase.created_at || now)) > maxAge;

    if (isExpired) {
      await this.dbRunAsync(
        "UPDATE purchases SET status = 'EXPIRED', paid_at = ?, finished_at = ?, error_log = ? WHERE id = ? AND status IN ('PENDING_PAYMENT','PAID')",
        [now, now, 'Pembayaran diterima setelah invoice expired', purchaseId]
      );
      this.pendingCache.delete(uniqueCode);
      this.logger.info(`Purchase ${purchase.transaction_id} EXPIRED, dana Rp${purchase.shortage_amount} sudah masuk saldo user ${userId}`);

      try {
        await this.bot.telegram.sendMessage(userId,
          t(userId, 'pur_late_title') + '\n\n' +
          t(userId, 'pur_late_body', { invoice: purchase.transaction_id, amount: (purchase.shortage_amount || 0).toLocaleString('id-ID') }),
          { parse_mode: 'Markdown' }
        );
      } catch (e) {
        this.logger.error(`Gagal notifikasi expired ke user ${userId}: ${e.message}`);
      }

      return { type: 'expired', purchase };
    }

    await this.dbRunAsync(
      "UPDATE purchases SET status = 'PAID', paid_at = ? WHERE id = ? AND status = 'PENDING_PAYMENT'",
      [now, purchaseId]
    );

    await this.updateUserBalance(userId, -totalHarga);
    this.logger.info(`Saldo dipotong Rp${totalHarga} dari user ${userId} (pasca-payment) untuk ${purchase.product}`);

    const processingMsg = await this.bot.telegram.sendMessage(userId,
      t(userId, 'pur_payment_received'),
      { parse_mode: 'Markdown' }
    ).catch(() => null);

    const taskQueue = require('./task-queue');
    taskQueue.runBackground(userId,
      async () => {
        const result = await this.executor({ ...purchaseData, userId });
        const msg = result && result.message ? result.message : (result || '');
        const failed = msg.includes('❌') || (result && result.error);

        if (failed) {
          throw new Error(typeof msg === 'string' ? msg.substring(0, 300) : (result.error || 'Gagal membuat akun'));
        }

        await this.dbRunAsync(
          "UPDATE purchases SET status = 'SUCCESS', finished_at = ? WHERE id = ?",
          [now, purchaseId]
        );
        await this.recordTransaction(userId, purchase.product, totalHarga, 'SUCCESS', purchase.transaction_id);

        this.pendingCache.delete(uniqueCode);

        if (processingMsg) {
          try { await this.bot.telegram.editMessageText(processingMsg.chat.id, processingMsg.message_id, undefined, msg, { parse_mode: 'Markdown' }); } catch (e) { try { await this.bot.telegram.sendMessage(userId, msg, { parse_mode: 'Markdown' }); } catch (e2) {} }
        } else {
          try { await this.bot.telegram.sendMessage(userId, msg, { parse_mode: 'Markdown' }); } catch (e) {}
        }

        await this.notifyGroup(
          `✅ <b>Pembelian Berhasil</b>\n👤 User: <code>${userId}</code>\n📦 Produk: <code>${purchase.product}</code>\n💰 Harga: Rp${totalHarga.toLocaleString('id-ID')}\n🆔 Invoice: <code>${purchase.transaction_id}</code>`
        );

        return { type: 'success', purchase, message: msg };
      },
      () => {},
      async (error) => {
        if (isInternalError(error)) {
          await this.dbRunAsync(
            "UPDATE purchases SET status = 'PENDING_VERIFY', finished_at = ?, error_log = ? WHERE id = ?",
            [now, (error.message || '').substring(0, 500), purchaseId]
          );
          this.pendingCache.delete(uniqueCode);
          this.logger.error(`Purchase ${purchase.transaction_id} UNCERTAIN, saldo TIDAK dikembalikan ke user ${userId}: ${error.message}`);

          const verifyMsg = t(userId, 'pur_pending_verify');
          if (processingMsg) {
            try { await this.bot.telegram.editMessageText(processingMsg.chat.id, processingMsg.message_id, undefined, verifyMsg, { parse_mode: 'Markdown' }); } catch (e) { try { await this.bot.telegram.sendMessage(userId, verifyMsg, { parse_mode: 'Markdown' }); } catch (e2) {} }
          } else {
            try { await this.bot.telegram.sendMessage(userId, verifyMsg, { parse_mode: 'Markdown' }); } catch (e) {}
          }

          await this.notifyAdmin(
            `⚠️ *ORDER PERLU DIVERIFIKASI (BELUM REFUND)*\n👤 User: \`${userId}\`\n📦 Produk: \`${purchase.product}\`\n💰 Harga: Rp${totalHarga}\n🆔 Invoice: \`${purchase.transaction_id}\`\n⚠️ Error: \`${(error.message || '').substring(0, 200)}\`\n\nCek panel dulu sebelum refund manual.`
          );

          return { type: 'pending_verify', purchase, error: error.message };
        }

        await this.updateUserBalance(userId, totalHarga);
        await this.dbRunAsync(
          "UPDATE purchases SET status = 'FAILED_CREATE', finished_at = ?, error_log = ? WHERE id = ?",
          [now, (error.message || '').substring(0, 500), purchaseId]
        );

        this.pendingCache.delete(uniqueCode);
        this.logger.error(`Purchase ${purchase.transaction_id} FAILED_CREATE, refunded Rp${totalHarga} ke user ${userId}: ${error.message}`);

        const errMsg = t(userId, 'pur_failed_create', { saldo: totalHarga.toLocaleString('id-ID') });
        if (processingMsg) {
          try { await this.bot.telegram.editMessageText(processingMsg.chat.id, processingMsg.message_id, undefined, errMsg, { parse_mode: 'Markdown' }); } catch (e) { try { await this.bot.telegram.sendMessage(userId, errMsg, { parse_mode: 'Markdown' }); } catch (e2) {} }
        } else {
          try { await this.bot.telegram.sendMessage(userId, errMsg, { parse_mode: 'Markdown' }); } catch (e) {}
        }

        await this.notifyAdmin(
          `❌ *FAILED CREATE (REFUNDED)*\n👤 User: \`${userId}\`\n📦 Produk: \`${purchase.product}\`\n💰 Refund: Rp${totalHarga}\n🆔 Invoice: \`${purchase.transaction_id}\`\n⚠️ Error: \`${(error.message || '').substring(0, 200)}\``
        );

        return { type: 'failed_create', purchase, error: error.message };
      }
    );
  }

  async generateOrkutQRIS(ctx, amount, uniqueCode) {
    const DATA_QRIS_ORKUT = this.config.vars.DATA_QRIS_ORKUT;

    const res = await axios.get('http://localhost:9526/api/qris', {
      params: { qris_string: DATA_QRIS_ORKUT, amount: Number(amount) },
      timeout: 15000
    });

    const data = res.data;
    if (!data || !data.success) throw new Error('Gagal create QRIS ORKUT');

    if (!data.image_data || !data.image_data.includes('base64'))
      throw new Error('QRIS image invalid');

    const base64Data = data.image_data.split(',')[1];
    const imageBuffer = Buffer.from(base64Data, 'base64');
    const adminFee = Number(data.random_add) || 0;

    const caption =
      t(ctx.from.id, 'pay_detail_title') + '\n\n' +
      t(ctx.from.id, 'pay_total', { amount: Number(data.amount).toLocaleString('id-ID') }) + '\n' +
      t(ctx.from.id, 'pay_purchase', { amount: Number(amount).toLocaleString('id-ID') }) + '\n' +
      (adminFee > 0 ? t(ctx.from.id, 'pay_admin_fee', { amount: adminFee.toLocaleString('id-ID') }) + '\n' : '') +
      '\n' + t(ctx.from.id, 'pay_expired_hour') + '\n' +
      t(ctx.from.id, 'pay_transfer_exact') + '\n' +
      t(ctx.from.id, 'pay_invoice', { invoice: uniqueCode });

    const qrMessage = await ctx.replyWithPhoto(
      { source: imageBuffer },
      {
        caption,
        parse_mode: 'Markdown',
        reply_markup: { inline_keyboard: [
          [{ text: t(ctx.from.id, 'btn_cancel'), callback_data: `batal_topup_confirm_${uniqueCode}` }]
        ]}
      }
    );

    return { qrImage: data.image_data.trim(), qrMessageId: qrMessage.message_id, adminFee, transactionId: null };
  }

  async generateGopayQRIS(ctx, amount, uniqueCode) {
    const gopayQris = require('./gopay-qris');
    const res = await gopayQris.createQRIS(Number(amount), this.config.vars);

    if (!res?.success) throw new Error('Gagal create QRIS GOPAY');

    const data = res.data;
    const qrImageUrl = data.qr_url;
    const checkId = data.check_id;
    const checkUrl = data.check_url;
    const timeoutMinutes = data.timeout_minutes || 15;
    if (!qrImageUrl) throw new Error('QR URL kosong');

    const safeQrUrl = encodeURI(String(qrImageUrl).trim());
    const caption =
      t(ctx.from.id, 'pay_detail_title') + '\n\n' +
      t(ctx.from.id, 'pay_total', { amount: Number(data.amount).toLocaleString('id-ID') }) + '\n' +
      t(ctx.from.id, 'pay_purchase', { amount: Number(amount).toLocaleString('id-ID') }) + '\n' +
      (data.uniqueNumber > 0 ? t(ctx.from.id, 'pay_admin_fee', { amount: Number(data.uniqueNumber).toLocaleString('id-ID') }) + '\n' : '') +
      '\n' + t(ctx.from.id, 'pay_expired_minutes', { minutes: timeoutMinutes }) + '\n' +
      t(ctx.from.id, 'pay_transfer_exact') + '\n\n' +
      t(ctx.from.id, 'pay_click_qris', { url: safeQrUrl }) + '\n' +
      t(ctx.from.id, 'pay_invoice', { invoice: uniqueCode });

    const qrMessage = await ctx.reply(caption, {
      parse_mode: 'Markdown',
      reply_markup: { inline_keyboard: [
        [{ text: t(ctx.from.id, 'btn_cancel'), callback_data: `batal_topup_confirm_${uniqueCode}` }]
      ]}
    });

    return { qrImage: qrImageUrl, qrMessageId: qrMessage.message_id, adminFee: data.uniqueNumber || 0, transactionId: checkId, checkUrl };
  }

  async checkGopayStatus(checkId, vars) {
    const gopayQris = require('./gopay-qris');
    const res = await gopayQris.checkPayment(checkId, vars);

    if (!res?.success) {
      return { paid: false, status: null };
    }

    const status = res.status;
    const paid = status === 'PAID';

    return {
      paid,
      status,
      amount: res.transaction?.real_gross_amount || res.transaction?.gross_amount,
      completeTime: res.transaction?.settlement_time,
      transactionId: res.transaction?.id || res.check_id,
      transactionData: res.transaction
    };
  }

  async generateShopeePayQRIS(ctx, amount, uniqueCode) {
    const shopeePay = require('./shopee-pay');
    const sharp = require('sharp');
    const res = await shopeePay.createQRIS(Number(amount), this.config.vars);

    if (res.status !== 'success' || !res.transaction_sn || !res.qr_image) {
      throw new Error('Gagal create QRIS ShopeePay');
    }

    const orderSn = res.transaction_sn;
    const qrBase64 = res.qr_image;
    const expiredMinutes = res.expired_minutes || 20;

    // Add white padding around QR image (20px on each side)
    const imageBuffer = Buffer.from(qrBase64, 'base64');
    const paddedBuffer = await sharp(imageBuffer)
      .extend({ top: 20, bottom: 20, left: 20, right: 20, background: { r: 255, g: 255, b: 255, alpha: 1 } })
      .png()
      .toBuffer();
    const adminFee = 0;

    const caption =
      t(ctx.from.id, 'pay_detail_title') + '\n\n' +
      t(ctx.from.id, 'pay_total', { amount: Number(amount).toLocaleString('id-ID') }) + '\n' +
      (adminFee > 0 ? t(ctx.from.id, 'pay_admin_fee', { amount: adminFee.toLocaleString('id-ID') }) + '\n' : '') +
      '\n' + t(ctx.from.id, 'pay_expired_minutes', { minutes: expiredMinutes }) + '\n' +
      t(ctx.from.id, 'pay_transfer_exact') + '\n' +
      t(ctx.from.id, 'pay_invoice', { invoice: uniqueCode });

    const qrMessage = await ctx.replyWithPhoto(
      { source: paddedBuffer },
      {
        caption,
        parse_mode: 'Markdown',
        reply_markup: { inline_keyboard: [
          [{ text: t(ctx.from.id, 'btn_cancel'), callback_data: `batal_topup_confirm_${uniqueCode}` }]
        ]}
      }
    );

    return { qrImage: qrBase64, qrMessageId: qrMessage.message_id, adminFee, transactionId: orderSn };
  }

  async checkShopeePayStatus(orderSn) {
    const shopeePay = require('./shopee-pay');
    const res = await shopeePay.checkPayment(orderSn, this.config.vars);

    if (res.status !== 'success') {
      return { paid: false, status: null };
    }

    const orderStatus = res.order_status;
    const paid = orderStatus === 1 || res.paid === true;

    const td = (res.transaction_data && res.transaction_data.order_status !== undefined)
      ? res.transaction_data
      : {};

    return {
      paid,
      status: orderStatus,
      amount: td.amount || res.amount,
      completeTime: td.complete_time || res.complete_time,
      transactionId: td.transaction_id || res.transaction_id
    };
  }

  async recordTransaction(userId, product, amount, status, referenceId, errorLog) {
    try {
      await this.dbRunAsync(
        'INSERT INTO transactions (user_id, amount, type, reference_id, timestamp) VALUES (?, ?, ?, ?, ?)',
        [userId, amount || 0, `purchase-${status}`, referenceId || `${product}-${Date.now()}`, Date.now()]
      );
    } catch (e) {
      this.logger.error(`Gagal catat transaksi: ${e.message}`);
    }
  }

  async notifyAdmin(message) {
    try {
      const ids = Array.isArray(this.config.ADMIN) ? this.config.ADMIN : [this.config.ADMIN];
      for (const id of ids) {
        if (id) await this.bot.telegram.sendMessage(id, message, { parse_mode: 'Markdown' }).catch(() => {});
      }
    } catch (e) {
      this.logger.error(`Gagal notifikasi admin: ${e.message}`);
    }
  }

  async notifyGroup(message) {
    try {
      if (this.config.GROUP_ID) {
        await this.bot.telegram.sendMessage(this.config.GROUP_ID, message, { parse_mode: 'HTML' }).catch(() => {});
      }
    } catch (e) {
      this.logger.error(`Gagal notifikasi grup: ${e.message}`);
    }
  }

  generateId(prefix) {
    return `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  }

  dbRunAsync(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function (err) {
        if (err) return reject(err);
        resolve(this);
      });
    });
  }

  dbAllAsync(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) return reject(err);
        resolve(rows || []);
      });
    });
  }

  dbGetAsync(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) return reject(err);
        resolve(row);
      });
    });
  }

  async getUserBalance(userId) {
    const row = await this.dbGetAsync('SELECT saldo FROM users WHERE user_id = ?', [userId]);
    return row ? row.saldo : 0;
  }

  async updateUserBalance(userId, amount) {
    await this.dbRunAsync('UPDATE users SET saldo = saldo + ? WHERE user_id = ?', [amount, userId]);
  }
}

module.exports = PurchaseFlow;
