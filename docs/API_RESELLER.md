# BotVPN Reseller REST API Documentation

## Base URL
```
https://api.rajaserver.web.id/api/v1
```

## Local Development
```
http://127.0.0.1:8788/api/v1
```

---

## Authentication

All API endpoints (except `/health`) require authentication via Bearer token:

```
Authorization: Bearer rsl_xxxxxxxxxxxxxxxxxxxxxxxxx
```

### How it Works

1. **API Key** → maps to **Telegram ID** (stored in database)
2. **Telegram ID** → maps to **BotVPN Reseller** (existing system)
3. **BotVPN Reseller** → uses **existing saldo/balance**

> **Important:** No separate API balance. The API uses the exact same balance as the Telegram bot.

---

## Error Format

All endpoints return consistent error format:

```json
{
  "success": false,
  "code": "ERROR_CODE",
  "message": "Human readable message"
}
```

### Common Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| `INVALID_API_KEY` | 401 | API key tidak valid atau tidak ditemukan |
| `ACCOUNT_SUSPENDED` | 403 | Akun reseller tidak aktif |
| `INSUFFICIENT_BALANCE` | 402 | Saldo tidak cukup untuk transaksi |
| `PRODUCT_NOT_FOUND` | 404 | Produk tidak ditemukan |
| `SERVER_NOT_FOUND` | 404 | Server tidak ditemukan |
| `ACCOUNT_NOT_FOUND` | 404 | Akun tidak ditemukan atau bukan milik Anda |
| `INVALID_REQUEST` | 400 | Request body tidak valid |
| `INVALID_PROTOCOL` | 400 | Protocol tidak didukung |
| `INVALID_ACTION` | 400 | Action operasi tidak dikenal |
| `OPERATION_FAILED` | 400 | Operasi panel gagal |
| `RATE_LIMIT_EXCEEDED` | 429 | Terlalu banyak request |
| `DUPLICATE_REQUEST` | 409 | Request duplikat (idempotency) |
| `UPSTREAM_ERROR` | 502 | Panel upstream (EDU/CloudFront) error |
| `INTERNAL_ERROR` | 500 | Kesalahan internal server |

---

## Rate Limit

Default: **60 requests/minute per API key**

Headers returned:
- `X-RateLimit-Limit`: Limit per menit
- `X-RateLimit-Remaining`: Sisa request
- `X-RateLimit-Reset`: Unix timestamp kapan reset

---

## Request ID

Every request should include (or will be auto-generated):

```
X-Request-ID: req_xxxxxxxxx
```

Returned in response headers for tracing.

---

## Idempotency

For `POST /accounts` and `POST /accounts/{username}/renew`, include:

```
Idempotency-Key: unique-request-id
```

If the same key is sent again, the previous result is returned (no duplicate creation, no double charge).

---

## Supported Protocols

| Protocol | ID | Keterangan |
|----------|----|------------|
| SSH | `ssh` | SSH premium (WS/SSL/UDP/SlowDNS) |
| VMess | `vmess` | VMess WS/GRPC |
| VLESS | `vless` | VLESS |
| Trojan | `trojan` | Trojan |
| SSH CloudFront | `sshcf` | SSH via domain CloudFront private |
| VMess CloudFront | `vmesscf` | VMess via CloudFront private |
| VLESS CloudFront | `vlesscf` | VLESS via CloudFront private |
| Trojan CloudFront | `trojancf` | Trojan via CloudFront private |

> Selain protokol di atas, tersedia **VPN EDU Direct** (`/edu/*`) dan
> **VPN CloudFront API** (`/vpncf/*`) yang menggunakan panel upstream terpisah.

> **Pricing:** `price = server.harga * duration`. Resellers get 50% discount
> (kecuali SSH/VMess/VLESS/Trojan CloudFront = harga normal).

---

## Endpoints

### 1. Health Check (Public)
```
GET /api/v1/health
```

**Response:**
```json
{ "success": true, "status": "ok" }
```

---

### 2. Get Current Reseller Identity
```
GET /api/v1/me
Authorization: Bearer rsl_xxxxxxxxx
```

**Response:**
```json
{
  "success": true,
  "data": { "telegram_id": 123456789, "status": "active" }
}
```

---

### 3. Get Balance
```
GET /api/v1/balance
Authorization: Bearer rsl_xxxxxxxxx
```

**Response:**
```json
{ "success": true, "data": { "balance": 50000, "currency": "IDR" } }
```

> Uses the **exact same balance** as Telegram bot. No separate API balance.

---

### 4. List Products
```
GET /api/v1/products
Authorization: Bearer rsl_xxxxxxxxx
```

**Response:**
```json
{
  "success": true,
  "data": [
    { "id": "ssh", "name": "SSH" },
    { "id": "vmess", "name": "VMess" },
    { "id": "vless", "name": "VLESS" },
    { "id": "trojan", "name": "Trojan" },
    { "id": "sshcf", "name": "SSH CloudFront" },
    { "id": "vmesscf", "name": "VMess CloudFront" },
    { "id": "vlesscf", "name": "VLESS CloudFront" },
    { "id": "trojancf", "name": "Trojan CloudFront" }
  ]
}
```

---

### 5. List Servers
```
GET /api/v1/servers
Authorization: Bearer rsl_xxxxxxxxx
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "name": "ID BiznetVIP1",
      "nama_server": "ID BiznetVIP1",
      "location": "ID",
      "domain": "id-biznetvip1.rajaserver.web.id",
      "cloudfront_domain": "cf-id-biznetvip1.rajaserver.web.id",
      "quota": 100,
      "iplimit": 2,
      "price_per_day": 2000,
      "harga": 2000,
      "batas_create_akun": 100,
      "total_create_akun": 37,
      "status": "online",
      "is_reseller_only": false
    }
  ]
}
```

> Reseller-only servers only shown to resellers.
> `status` = `full` jika `total_create_akun >= batas_create_akun`.

---

### 6. Create Account
```
POST /api/v1/accounts
Authorization: Bearer rsl_xxxxxxxxx
Content-Type: application/json
Idempotency-Key: order-123456 (optional but recommended)
```

**Request Body:**
```json
{
  "protocol": "ssh",
  "server_id": 1,
  "duration": 30,
  "username": "optional_custom_username",
  "password": "optional_custom_password"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `protocol` | ✅ | `ssh`, `vmess`, `vless`, `trojan`, `sshcf`, `vmesscf`, `vlesscf`, `trojancf` |
| `server_id` | ✅ | Server ID from `/servers` |
| `duration` | ✅ | Duration in days (e.g., 30) |
| `username` | ❌ | Auto-generated if not provided |
| `password` | ❌ | Only for SSH/SSH CloudFront; auto-generated if not provided |

> **Note:** `quota` dan `iplimit` otomatis dari default server.

**Success Response (200):**
```json
{
  "success": true,
  "data": {
    "username": "abc123",
    "password": "pass123",
    "protocol": "ssh",
    "server": "ID BiznetVIP1",
    "server_id": 1,
    "duration": 30,
    "expired_at": "2026-10-28T23:59:59+07:00",
    "price": 6000,
    "balance": 44000,
    "message": "✅ *SSH Account Created Successfully!*..."
  }
}
```

---

### 7. Renew Account
```
POST /api/v1/accounts/{username}/renew
Authorization: Bearer rsl_xxxxxxxxx
Content-Type: application/json
Idempotency-Key: renew-123456 (optional but recommended)
```

**Request Body:**
```json
{ "protocol": "ssh", "server_id": 1, "duration": 30 }
```

**Success Response (200):**
```json
{
  "success": true,
  "data": {
    "username": "abc123",
    "protocol": "ssh",
    "server": "ID BiznetVIP1",
    "duration": 30,
    "expired_at": "2026-11-27T23:59:59+07:00",
    "price": 6000,
    "balance": 38000,
    "message": "✅ *Renew SSH Account Success!*..."
  }
}
```

---

### 8. Get Account Detail
```
GET /api/v1/accounts/{username}
Authorization: Bearer rsl_xxxxxxxxx
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "username": "abc123",
    "protocol": "ssh",
    "server": "ID BiznetVIP1",
    "status": "active",
    "expired_at": "2026-10-28T23:59:59+07:00",
    "created_at": "2026-09-28T10:00:00+07:00",
    "price": 6000
  }
}
```

---

### 9. Run Operation (delete / lock / unlock / changelimip / trial / fix / cek)

Endpoint generik untuk operasi panel selain create/renew. Dipakai oleh
bot Reseller.

```
POST /api/v1/operations
Authorization: Bearer rsl_xxxxxxxxx
Content-Type: application/json
```

**Request Body:**
```json
{
  "action": "delete",
  "protocol": "ssh",
  "server_id": 1,
  "username": "abc123",
  "duration": 30,
  "quota": "0",
  "iplimit": 2,
  "target_ip": 2,
  "cf_domain": "cf-xxxx.rajaserver.web.id"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `action` | ✅ | `create`, `renew`, `delete`, `lock`, `unlock`, `changelimip`, `trial`, `fix`, `cek` |
| `protocol` | ✅ | Protocol yang didukung |
| `server_id` | ✅ | Server ID |
| `username` | Tergantung action | Username target |
| `duration` | `create`/`renew`/`fix` | Durasi (hari) |
| `target_ip` | `changelimip` | Limit IP baru |
| `cf_domain` | ❌ | Override domain CloudFront |

> - `create` & `renew` memotong saldo reseller (harga reseller).
> - `delete`, `lock`, `unlock`, `changelimip`, `trial`, `fix` dijalankan di panel (gratis upstream).
> - `cek` mengembalikan data akun bila ada.

**Response (200):**
```json
{
  "success": true,
  "data": {
    "success": true,
    "message": "✅ *Delete SSH Account Success!*...",
    "username": "abc123",
    "protocol": "ssh",
    "expired": null
  }
}
```

Untuk `action: "cek"`:
```json
{
  "success": true,
  "data": {
    "success": true,
    "data": {
      "username": "abc123",
      "protocol": "ssh",
      "expired": "2026-10-28",
      "quota": "Unlimited",
      "iplimit": 2,
      "raw": { "..." : "..." }
    }
  }
}
```

---

### 10. VPN EDU DIRECT (Naytra) — `/edu/*`

| Endpoint | Method | Deskripsi |
|----------|--------|-----------|
| `/edu/products` | GET | Daftar server & produk EDU |
| `/edu/accounts` | GET | Daftar akun EDU |
| `/edu/renewable` | GET | Daftar akun EDU yang bisa di-renew |
| `/edu/trial` | POST | Order trial EDU |
| `/edu/order` | POST | Order akun EDU (dengan verifikasi panel) |
| `/edu/renew` | POST | Renew akun EDU |

**Order EDU — Request:**
```json
{
  "server_code": "polsri",
  "service": "bundle_complete",
  "billing_period": "monthly",
  "duration": 1,
  "username": "myuser",
  "password": "mypass"
}
```

> `order` melakukan verifikasi ke panel: jika respons order ambigu tetapi akun
> sudah dibuat, akun **dipulihkan otomatis** (`recovered: true`) tanpa refund.

**Renew EDU — Request:**
```json
{ "order_id": "ORD-123", "duration": 1 }
```

---

### 11. VPN CLOUDFRONT (NadiaVPN) — `/vpncf/*`

| Endpoint | Method | Deskripsi |
|----------|--------|-----------|
| `/vpncf/servers` | GET | Daftar server CloudFront (`?force=1` untuk bypass cache) |
| `/vpncf/accounts` | GET | Daftar akun CloudFront |
| `/vpncf/account/details` | POST | Detail akun |
| `/vpncf/account/sync` | POST | Sync akun |
| `/vpncf/create` | POST | Order akun CloudFront |
| `/vpncf/trial` | POST | Order trial CloudFront |
| `/vpncf/renew` | POST | Renew akun |
| `/vpncf/migrate` | POST | Pindah server |
| `/vpncf/delete` | POST | Hapus akun |

**Create — Request:**
```json
{
  "server_id": 12,
  "protocol": "vless",
  "username": "myuser",
  "password": "mypass",
  "duration": 1,
  "type": "month"
}
```

**Renew — Request:**
```json
{ "account_id": "acc_123", "duration": 1, "type": "month" }
```

**Migrate — Request:**
```json
{ "account_id": "acc_123", "new_server_id": 15 }
```

**Delete / Details / Sync — Request:**
```json
{ "account_id": "acc_123" }
```

> Respons endpoint `/edu/*` dan `/vpncf/*` membungkus hasil panel upstream
> apa adanya: `{ "success": true, "data": <hasil panel> }`.

---

## ⚠️ Keamanan API Key

> **Penting:** Pembuatan API key **hanya bisa dilakukan melalui admin chat di [t.me/ARI_VPN_STORE](https://t.me/ARI_VPN_STORE)** untuk menjaga keamanan. Bot Reseller tidak menyediakan endpoint publik untuk generate API key.

---

## Admin Commands (Telegram Bot)

Admin can manage API keys via Telegram bot:

```
/apikey create <telegram_id>     - Generate API key for reseller
/apikey regenerate <telegram_id> - Regenerate API key (old becomes invalid)
/apikey revoke <telegram_id>     - Disable API key
/apikey status <telegram_id>     - View API key status
/apikey list                     - List all API keys
```

---

## cURL Examples

### Check Balance
```bash
curl https://api.rajaserver.web.id/api/v1/balance \
  -H "Authorization: Bearer rsl_xxxxxxxxx"
```

### Create SSH Account
```bash
curl -X POST https://api.rajaserver.web.id/api/v1/accounts \
  -H "Authorization: Bearer rsl_xxxxxxxxx" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: order-123456" \
  -d '{ "protocol": "ssh", "server_id": 1, "duration": 30 }'
```

### Create VMess Account
```bash
curl -X POST https://api.rajaserver.web.id/api/v1/accounts \
  -H "Authorization: Bearer rsl_xxxxxxxxx" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: order-123457" \
  -d '{ "protocol": "vmess", "server_id": 1, "duration": 30 }'
```

### Renew Account
```bash
curl -X POST https://api.rajaserver.web.id/api/v1/accounts/abc123/renew \
  -H "Authorization: Bearer rsl_xxxxxxxxx" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: renew-123456" \
  -d '{ "protocol": "ssh", "server_id": 1, "duration": 30 }'
```

### Delete Account
```bash
curl -X POST https://api.rajaserver.web.id/api/v1/operations \
  -H "Authorization: Bearer rsl_xxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{ "action": "delete", "protocol": "ssh", "server_id": 1, "username": "abc123" }'
```

### Get Account Detail
```bash
curl https://api.rajaserver.web.id/api/v1/accounts/abc123 \
  -H "Authorization: Bearer rsl_xxxxxxxxx"
```

### List Servers
```bash
curl https://api.rajaserver.web.id/api/v1/servers \
  -H "Authorization: Bearer rsl_xxxxxxxxx"
```

---

## Cloudflare Tunnel Configuration

Since the VPS is behind NAT, the API runs on localhost and is exposed via Cloudflare Tunnel:

```yaml
tunnel: api-raja
credentials-file: /root/.cloudflared/api-raja.json

ingress:
  - hostname: api.rajaserver.web.id
    service: http://127.0.0.1:8788
  - service: http_status:404
```

**Flow:**
```
Reseller
  ↓
https://api.rajaserver.web.id
  ↓
Cloudflare
  ↓
Cloudflare Tunnel
  ↓
127.0.0.1:8788 (BotVPN Express server)
  ↓
API Reseller Layer → BotVPN Existing Logic
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Reseller Client                          │
│            (BotVPN-Reseller Telegram Bot)                   │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS REST API
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Cloudflare Tunnel                        │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              API Reseller Layer (127.0.0.1:8788)            │
│  ┌─────────────┐ ┌────────────┐ ┌────────────────────────┐  │
│  │ Auth        │ │ Rate Limit │ │ Idempotency            │  │
│  │ (Bearer)    │ │ (60/min)   │ │ (Idempotency-Key)      │  │
│  └─────────────┘ └────────────┘ └────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ /operations  /edu/*  /vpncf/*                        │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   BotVPN Existing Logic                     │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────┐  │
│  │ SSH    │ │ VMess  │ │ VLESS  │ │ Trojan │ │ CloudF   │  │
│  └────────┘ └────────┘ └────────┘ └────────┘ └──────────┘  │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────────────────┐   │
│  │ EDU    │ │ VPNCF  │ │ Balance│ │ Server & Pricing    │   │
│  └────────┘ └────────┘ └────────┘ └────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Principles

1. **NO DUPLICATE BUSINESS LOGIC** - API calls existing BotVPN functions
2. **SHARED BALANCE** - Uses existing `users.saldo` table
3. **TELEGRAM ID MAPPING** - API Key → Telegram ID → Reseller
4. **ATOMIC TRANSACTIONS** - Balance deducted only after successful creation
5. **IDEMPOTENCY** - Safe retries with Idempotency-Key
6. **RATE LIMITING** - Per API key (configurable)
7. **AUDIT LOGGING** - All requests logged (no sensitive data)

---

## Testing Checklist

- [ ] API key valid → returns 200
- [ ] API key invalid → 401 INVALID_API_KEY
- [ ] Telegram ID mapping correct
- [ ] Reseller suspended → 403 ACCOUNT_SUSPENDED
- [ ] Balance reads from existing system
- [ ] Balance decreases after purchase
- [ ] Create/renew uses existing logic
- [ ] Operations (delete/lock/unlock/changelimip/trial/fix/cek) bekerja
- [ ] EDU order/renew/trial bekerja
- [ ] CloudFront create/renew/migrate/delete bekerja
- [ ] Account ownership enforced
- [ ] Reseller A cannot access Reseller B data
- [ ] Balance never negative
- [ ] Failed provisioning → no balance deduction
- [ ] Duplicate request → no double creation
- [ ] Rate limit enforced
- [ ] API key regenerate works
- [ ] Cloudflare Tunnel accessible
- [ ] Health check returns ok
