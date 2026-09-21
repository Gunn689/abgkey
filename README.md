# abgkey

Cloudflare Workers server untuk ABGunnn:
- License key system (auth per user, HWID binding, expiry)
- Feedback auto (PUBG → Telegram)

## Endpoints

| Method | Path | Fungsi |
|---|---|---|
| GET | `/` `/health` | status check |
| POST | `/` `/upload` | terima gambar + caption → Telegram |
| POST | `/auth` | validasi license key |
| POST | `/admin/add` | bikin key baru |
| POST | `/admin/revoke` | hapus key |
| POST | `/admin/reset-hwid` | reset binding HWID |
| POST | `/admin/list` | list semua key |

## Setup

1. buat KV namespace `AUTH_KEYS`
2. bind KV ke Worker: `AUTH_KEYS` → `AUTH_KEYS`
3. env vars (Secret):
   - `BOT_TOKEN` — token Telegram bot
   - `CHAT_ID` — id grup Telegram
   - `ADMIN_TOKEN` — random string
4. deploy
