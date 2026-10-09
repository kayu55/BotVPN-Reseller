const axios = require('axios');

function getBaseUrl(vars) {
  return (vars && vars.GOPAY_QRIS_BASE_URL) || 'http://localhost:2234';
}

async function createQRIS(amount, vars) {
  const base = getBaseUrl(vars);
  const res = await axios.get(
    `${base}/createqris/amount=${encodeURIComponent(Number(amount))}`,
    { timeout: 15000 }
  );
  return res.data;
}

async function checkPayment(checkId, vars) {
  const base = getBaseUrl(vars);
  const res = await axios.get(
    `${base}/cekpembayaran/${encodeURIComponent(String(checkId))}`,
    { timeout: 15000 }
  );
  const data = res.data;
  if (data?.success && data?.transaction) {
    return {
      success: true,
      status: data.status,
      check_id: data.check_id,
      transactionData: data.transaction,
      transaction: data.transaction
    };
  }
  return data;
}

module.exports = { createQRIS, checkPayment, getBaseUrl };