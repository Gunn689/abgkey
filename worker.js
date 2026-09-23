// language: JavaScript, file: worker.js, runtime: Cloudflare Workers (V8)
// ABGunnn License Server — v1.2
// Case-preserved keys, free format like GitHub

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;

        // HEALTH
        if (request.method === 'GET' && (path === '/' || path === '/health')) {
            return json(200, {
                status: true,
                service: 'ABGunnn License Server',
                runtime: 'cloudflare-workers',
                version: '1.2',
                auth_enabled: Boolean(env.AUTH_KEYS && env.ADMIN_TOKEN),
                key_mode: 'case-sensitive'
            });
        }

        if (request.method === 'POST' && path === '/auth') {
            return handleAuth(request, env);
        }

        if (request.method === 'POST' && path.startsWith('/admin/')) {
            return handleAdmin(request, env, path);
        }

        return json(404, { status: false, error: 'Not found' });
    }
};

// ═══════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════
async function handleAuth(request, env) {
    if (!env.AUTH_KEYS) return json(500, { valid: false, error: 'auth not configured' });

    try {
        const ct = request.headers.get('content-type') || '';
        let key = '', hwid = '', device = '', android = '';

        if (ct.includes('application/x-www-form-urlencoded')) {
            const p = new URLSearchParams(await request.text());
            key     = (p.get('key')     || '').trim();   // no uppercase
            hwid    = (p.get('hwid')    || '').trim();
            device  = (p.get('device')  || '').trim();
            android = (p.get('android') || '').trim();
        } else {
            const j = await request.json();
            key     = String(j.key     || '').trim();
            hwid    = String(j.hwid    || '').trim();
            device  = String(j.device  || '').trim();
            android = String(j.android || '').trim();
        }

        if (!key)  return json(400, { valid: false, error: 'key required' });
        if (!hwid) return json(400, { valid: false, error: 'hwid required' });

        const raw = await env.AUTH_KEYS.get(key);
        if (!raw) return json(200, { valid: false, reason: 'key_not_found' });

        let data;
        try { data = JSON.parse(raw); }
        catch { return json(500, { valid: false, error: 'corrupt key data' }); }

        const now = Date.now();

        if (data.expire && now > data.expire) {
            return json(200, { valid: false, reason: 'expired', expire: data.expire });
        }

        data.hwids = data.hwids || [];
        const maxDevices = data.max || 1;

        if (data.hwids.length === 0) {
            data.hwids.push({ id: hwid, device, android, first_seen: now, last_seen: now });
            await env.AUTH_KEYS.put(key, JSON.stringify(data));
        } else {
            const found = data.hwids.find(h => h.id === hwid);
            if (!found) {
                if (data.hwids.length >= maxDevices) {
                    return json(200, { valid: false, reason: 'hwid_mismatch', max: maxDevices });
                }
                data.hwids.push({ id: hwid, device, android, first_seen: now, last_seen: now });
                await env.AUTH_KEYS.put(key, JSON.stringify(data));
            } else {
                found.last_seen = now;
                if (device)  found.device  = device;
                if (android) found.android = android;
                await env.AUTH_KEYS.put(key, JSON.stringify(data));
            }
        }

        return json(200, {
            valid: true,
            expire: data.expire || 0,
            note: data.note || '',
            hwids_count: data.hwids.length,
            max: maxDevices
        });
    } catch (e) {
        return json(500, { valid: false, error: e.message });
    }
}

// ═══════════════════════════════════════════════════════════
// ADMIN
// ═══════════════════════════════════════════════════════════
function checkAdmin(request, env) {
    const token = request.headers.get('x-admin-token') || '';
    if (!env.ADMIN_TOKEN) return false;
    return token === env.ADMIN_TOKEN;
}

async function handleAdmin(request, env, path) {
    if (!checkAdmin(request, env)) {
        return json(401, { status: false, error: 'unauthorized' });
    }

    try {
        const ct = request.headers.get('content-type') || '';
        let body = {};
        if (ct.includes('application/json')) {
            body = await request.json();
        } else {
            const p = new URLSearchParams(await request.text());
            p.forEach((v, k) => body[k] = v);
        }

        // ADD
        if (path === '/admin/add') {
            let key = String(body.key || '').trim();   // no uppercase, no forced prefix
            if (!key) key = generateKey();

            const days = Number(body.days !== undefined ? body.days : 30);
            const max = Number(body.max || 1);
            const note = String(body.note || '');
            const expire = days > 0 ? Date.now() + (days * 86400000) : 0;

            // check existing
            const existing = await env.AUTH_KEYS.get(key);
            if (existing) {
                return json(409, { status: false, error: 'key already exists', key });
            }

            const data = {
                expire, max, hwids: [], note,
                created: Date.now(),
                updated: Date.now()
            };
            await env.AUTH_KEYS.put(key, JSON.stringify(data));

            return json(200, {
                status: true,
                key,
                expire,
                expire_readable: expire ? new Date(expire).toISOString() : 'never',
                max,
                note
            });
        }

        // UPDATE
        if (path === '/admin/update') {
            const key = String(body.key || '').trim();
            if (!key) return json(400, { status: false, error: 'key required' });

            const raw = await env.AUTH_KEYS.get(key);
            if (!raw) return json(404, { status: false, error: 'key not found' });

            let data;
            try { data = JSON.parse(raw); }
            catch { return json(500, { status: false, error: 'corrupt key data' }); }

            const changes = {};

            if (body.days !== undefined && body.days !== '' && body.days !== null) {
                const days = Number(body.days);
                if (isNaN(days)) return json(400, { status: false, error: 'invalid days' });
                if (days === 0) {
                    data.expire = 0;
                    changes.days = 'lifetime';
                } else {
                    const now = Date.now();
                    const base = (data.expire && data.expire > now) ? data.expire : now;
                    data.expire = base + (days * 86400000);
                    changes.days = days;
                }
            }

            if (body.max !== undefined && body.max !== '' && body.max !== null) {
                const max = Number(body.max);
                if (isNaN(max) || max < 1) return json(400, { status: false, error: 'invalid max' });
                data.max = max;
                changes.max = max;
            }

            if (body.note !== undefined && body.note !== null) {
                data.note = String(body.note);
                changes.note = data.note;
            }

            // TEST ONLY: force expire
            if (body.test_expired === 'true' || body.test_expired === true) {
                data.expire = Date.now() - 86400000;
                changes.test_expired = true;
            }

            data.updated = Date.now();
            await env.AUTH_KEYS.put(key, JSON.stringify(data));

            return json(200, {
                status: true,
                key,
                expire: data.expire,
                expire_readable: data.expire ? new Date(data.expire).toISOString() : 'never',
                max: data.max,
                note: data.note,
                hwids_count: (data.hwids || []).length,
                changes
            });
        }

        // REVOKE
        if (path === '/admin/revoke') {
            const key = String(body.key || '').trim();
            if (!key) return json(400, { status: false, error: 'key required' });
            await env.AUTH_KEYS.delete(key);
            return json(200, { status: true, revoked: key });
        }

        // RESET HWID
        if (path === '/admin/reset-hwid') {
            const key = String(body.key || '').trim();
            if (!key) return json(400, { status: false, error: 'key required' });

            const raw = await env.AUTH_KEYS.get(key);
            if (!raw) return json(404, { status: false, error: 'key not found' });

            const data = JSON.parse(raw);
            data.hwids = [];
            data.updated = Date.now();
            await env.AUTH_KEYS.put(key, JSON.stringify(data));

            return json(200, { status: true, key, hwids_reset: true });
        }

        // LIST
        if (path === '/admin/list') {
            const list = await env.AUTH_KEYS.list({ limit: 1000 });
            const items = [];

            for (const k of list.keys) {
                const raw = await env.AUTH_KEYS.get(k.name);
                let d = {};
                try { d = JSON.parse(raw); } catch {}

                items.push({
                    key: k.name,
                    expire: d.expire || 0,
                    expire_readable: d.expire ? new Date(d.expire).toISOString() : 'never',
                    max: d.max || 1,
                    hwids: d.hwids || [],
                    note: d.note || '',
                    created: d.created || 0,
                    updated: d.updated || 0
                });
            }

            items.sort((a, b) => (b.created || 0) - (a.created || 0));
            return json(200, { status: true, count: items.length, keys: items });
        }

        return json(404, { status: false, error: 'unknown admin path' });
    } catch (e) {
        return json(500, { status: false, error: e.message });
    }
}

// ═══════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════

// auto-generate: random 16 char tanpa prefix
function generateKey() {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let out = '';
    for (let i = 0; i < 16; i++) {
        out += chars[Math.floor(Math.random() * chars.length)];
    }
    return out;
}

function json(code, data) {
    return new Response(JSON.stringify(data), {
        status: code,
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
}
