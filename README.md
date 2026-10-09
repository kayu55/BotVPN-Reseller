# BotVPN-Reseller

**Instalasi cepat:** `bash <(curl -fsSL https://github.com/arivpnstores/BotVPN-Reseller/raw/main/start)`

Bot Telegram **reseller** dengan menu & alur **sama seperti BotVPN**, bedanya:

- **Daftar server diambil dari API BotVPN** (bukan dari database sendiri).
- **Semua operasi panel** (buat, perpanjang, hapus, lock, unlock, ganti limit IP,
  trial, fix, cek server, **VPN CloudFront Private**, **VPN CloudFront API**, dan
  **VPN EDU Direct**) dijalankan lewat **API BotVPN** — bot ini **tidak memegang
  kredensial panel** sama sekali.
- **Saldo & akun disimpan lokal** (SQLite) + **TopUp QRIS sendiri** (GOPAY / ORKUT / SHOPEEPAY).

## Arsitektur

```
                      ┌──────────────────────────────┐
   Reseller User ───▶ │   BotVPN-Reseller (bot ini)  │
                      │  • Menu & alur = BotVPN      │
                      │  • Saldo/akun lokal (SQLite) │
                      │  • TopUp QRIS sendiri        │
                      └───────────────┬──────────────┘
                                      │ HTTPS + Bearer API Key
                                      ▼
                      ┌──────────────────────────────┐
                      │   API BotVPN (server utama)  │
                      │   /api/v1/*                  │
                      └───────────────┬──────────────┘
                                      ▼
                         Panel VPN / CloudFront API / Edu Direct API
```

Dua lapis saldo:

1. **Saldo lokal** milik customer reseller (di bot ini). Dipotong saat customer beli.
2. **Saldo reseller di BotVPN** (upstream). Dipotong otomatis oleh API BotVPN saat
   provisioning (`create`/`renew`). Inilah harga modal reseller (diskon reseller 50%,
   kecuali CloudFront/EDU).

## Menyiapkan BotVPN (server utama)

Tambahkan endpoint operasi. File yang sudah disiapkan di folder `BotVPN`:

- `modules/api-operations.js` — dispatcher operasi panel (baru).
- `api-server.js` — route baru:
  - `POST /api/v1/operations`
  - `GET/POST /api/v1/edu/*` (products, accounts, renewable, trial, order, renew)
  - `GET/POST /api/v1/vpncf/*` (servers, accounts, account/details, account/sync,
    create, trial, renew, migrate, delete)
- `modules/api-reseller.js` — `/servers` kini mengembalikan `batas_create_akun`,
  `total_create_akun`, `harga`, `nama_server` (dipakai untuk sinkronisasi).

Langkah di bot BotVPN:

1. Daftarkan Telegram ID reseller sebagai reseller:
   `/addressel <telegram_id>`
2. Beri saldo modal ke reseller:
   `/addsaldo <telegram_id> <nominal>`
3. Buat API key untuk reseller:
   `/apikey create <telegram_id>` → salin `rsl_...`
4. Pastikan API server berjalan (`API_PORT`, default `8788`).

## Menyiapkan BotVPN-Reseller

1. **Install dependency**
   ```bash
   cd BotVPN-Reseller
   npm install
   ```
2. **Konfigurasi `.vars.json`**
   ```json
   {
     "BOT_TOKEN": "TOKEN_BOT_RESELLER_DARI_BOTFATHER",
     "USER_ID": "TELEGRAM_ID_ADMIN",
     "NAMA_STORE": "PT RAJA SERVER PREMIUM",
     "GROUP_ID": "-100xxxxxxxxxx",
     "PORT": "6969",
     "PAYMENT": "SHOPEEPAY",
     "GOPAY_KEY": "",
     "DATA_QRIS_ORKUT": "",
     "AUTH_USERNAME_ORKUT": "",
     "AUTH_TOKEN_ORKUT": "",
     "SHOPEEPAY_BASE_URL": "http://localhost:2007",
     "API_BASE_URL": "https://api.rajaserver.web.id/api/v1",
     "API_KEY": "rsl_xxxxxxxxx",
      "REQUIRED_CHANNEL": "@channel_wajib_join",
      "REQUIRED_GROUP": "@group_wajib_join",
      "ENABLE_VPNCF": true
    }
    ```
`REQUIRED_CHANNEL` / `REQUIRED_GROUP` opsional (untuk gate wajib join).
   `ENABLE_VPNCF` = status fitur **VPN CloudFront Private** (diubah lewat `/togglevpncf`
   dan langsung tersimpan permanen di file ini).

   **Catatan Node.js:** gunakan **Node.js 20 (LTS)**. `sqlite3` 5.1.7 hanya punya
   prebuilt binary sampai Node 20/21; di Node 22+ binding native-nya tidak ditemukan
   (`Could not locate the bindings file`). Kalau terlanjur pakai Node 22, perbaiki dengan:
   ```bash
   apt-get install -y build-essential python3
   cd BotVPN-Reseller && npm rebuild sqlite3 --build-from-source
   ```
3. **Jalankan**
   ```bash
   node app.js
   # production
   pm2 start ecosystem.config.js
   ```

## Fitur (paritas BotVPN)

Buat Akun, Perpanjang, Hapus, Cek Server, Migrasi, Ganti Protokol, Ganti Limit IP,
Fix, Lock, Unlock, Trial, TopUp Saldo, **VPN EDU Direct (API)**, **VPN CloudFront (API)**,
**VPN CloudFront Private**, All List Account, Bahasa/Language, Jadi Reseller.
Menu Admin: Tambah Saldo, Lihat Saldo User, **Sync Server dari API**, Restart bot.

## Cara kerja server (mirror)

Bot ini menyimpan salinan tabel `Server` di `sellvpn.db` yang **disinkronkan otomatis
dari endpoint `GET /servers`**:

- Sekali saat start, lalu setiap **5 menit**.
- Bisa dipaksa manual via menu Admin → **🔄 Sync Server dari API**.
- Command manajemen server (`/addserver`, `/editharga`, dll.) diblokir dan
  diarahkan ke bot BotVPN utama.

## Struktur

```
BotVPN-Reseller/
├── app.js                     # Bot (mirror app.js BotVPN, sudah dipatch)
├── backup.js                  # Auto backup DB ke admin
├── .vars.json                 # Konfigurasi utama
├── modules/
│   ├── api-client.js          # Klien HTTP ke API BotVPN
│   ├── _op.js                 # Helper pemanggil operasi API
│   ├── server-store.js        # Akses tabel Server lokal
│   ├── create.js | renew.js | del.js | lock.js | unlock.js
│   ├── change-ip.js | trial.js | sshcf.js      # Proxy ke API
│   ├── cloudfront.js | edudirect.js            # Proxy ke API
│   ├── purchase-flow.js | confirmation.js | task-queue.js
│   ├── button-style.js | error-utils.js | i18n.js | reseller.js | shopee-pay.js
│   └── ...
├── locales/                   # id.json / en.json
├── ecosystem.config.js        # PM2
└── package.json
```

## Endpoint API yang dipakai

| Endpoint | Method | Kegunaan |
|----------|--------|----------|
| `/me`, `/balance` | GET | Identitas & saldo upstream |
| `/servers` | GET | Sinkronisasi daftar server |
| `/products` | GET | Daftar produk |
| `/operations` | POST | `create`, `renew`, `delete`, `lock`, `unlock`, `changelimip`, `trial`, `fix`, `cek` |
| `/edu/*` | GET/POST | VPN EDU Direct |
| `/vpncf/*` | GET/POST | VPN CloudFront (API) |

## Catatan

- Bot ini **tidak menyediakan API** (bukan server) — API tetap di bot BotVPN utama.
- Perubahan server (tambah/harga/IP limit) dilakukan di BotVPN utama; bot ini
  otomatis mengikuti lewat sinkronisasi.
- `API_KEY` harus milik reseller yang sudah terdaftar (`/addressel`) dan punya saldo
  cukup di BotVPN untuk provisioning.

## Lisensi

MIT
