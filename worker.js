// language: JavaScript, file: worker.js, runtime: Cloudflare Workers (V8)
// ABGunnn Feedback + License Server

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;

        // ============ HEALTH ============
        if (request.method === 'GET' && (path === '/' || path === '/health')) {
            return json(200, {
                status: true,
                service: 'ABGunnn Server',
                runtime: 'cloudflare-workers',
                telegram_configured: Boolean(env.BOT_TOKEN && env.CHAT_ID),
                auth_enabled: Boolean(env.AUTH_KEYS && env.ADMIN_TOKEN)
            });
        }

        // ============ AUTH ============
        if (request.method === 'POST' && path === '/auth') {
            return handleAuth(request, env);
        }

        // ============ ADMIN ============
        if (request.method === 'POST' && path.startsWith('/admin/')) {
            return handleAdmin(request, env, path);
        }

        // ============ UPLOAD (feedback) ============
        if (request.method === 'POST' && (path === '/' || path === '/upload')) {
            return handleUpload(request, env);
        }

        return json(404, { status: false, error: 'Not found' });
    }
};

// ==================== AUTH ====================

async function handleAuth(request, env) {
    if (!env.AUTH_KEYS) {
        return json(500, { valid: false, error: 'auth not configured' });
    }

    try {
        const ct = request.headers.get('content-type') || '';
        let key = '', hwid = '';
        if (ct.includes('application/x-www-form-urlencoded')) {
            const p = new URLSearchParams(await request.text());
            key = (p.get('key') || '').trim().toUpperCase();
            hwid = (p.get('hwid') || '').trim();
        } else {
            const j = await request.json();
            key = String(j.key || '').trim().toUpperCase();
            hwid = String(j.hwid || '').trim();
        }

        if (!key) return json(400, { valid: false, error: 'key required' });
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
            data.hwids.push(hwid);
            await env.AUTH_KEYS.put(key, JSON.stringify(data));
        } else if (!data.hwids.includes(hwid)) {
            if (data.hwids.length >= maxDevices) {
                return json(200, { valid: false, reason: 'hwid_mismatch', max: maxDevices });
            }
            data.hwids.push(hwid);
            await env.AUTH_KEYS.put(key, JSON.stringify(data));
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

// ==================== ADMIN ====================

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
            let key = String(body.key || '').trim().toUpperCase();
            if (!key) key = generateKey();

            const days = Number(body.days || 30);
            const max = Number(body.max || 1);
            const note = String(body.note || '');
            const expire = days > 0 ? Date.now() + (days * 86400000) : 0;

            const data = { expire, max, hwids: [], note, created: Date.now() };
            await env.AUTH_KEYS.put(key, JSON.stringify(data));

            return json(200, {
                status: true, key,
                expire,
                expire_readable: expire ? new Date(expire).toISOString() : 'never',
                max, note
            });
        }

        // REVOKE
        if (path === '/admin/revoke') {
            const key = String(body.key || '').trim().toUpperCase();
            if (!key) return json(400, { status: false, error: 'key required' });
            await env.AUTH_KEYS.delete(key);
            return json(200, { status: true, revoked: key });
        }

        // RESET HWID
        if (path === '/admin/reset-hwid') {
            const key = String(body.key || '').trim().toUpperCase();
            if (!key) return json(400, { status: false, error: 'key required' });
            const raw = await env.AUTH_KEYS.get(key);
            if (!raw) return json(404, { status: false, error: 'key not found' });
            const data = JSON.parse(raw);
            data.hwids = [];
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
                    note: d.note || ''
                });
            }
            return json(200, { status: true, count: items.length, keys: items });
        }

        return json(404, { status: false, error: 'unknown admin path' });
    } catch (e) {
        return json(500, { status: false, error: e.message });
    }
}

function generateKey() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const seg = () => Array.from({ length: 4 }, () =>
        chars[Math.floor(Math.random() * chars.length)]).join('');
    return `ABG-${seg()}-${seg()}-${seg()}`;
}

// ==================== UPLOAD ====================

async function handleUpload(request, env) {
    if (!env.BOT_TOKEN || !env.CHAT_ID) {
        return json(500, { status: false, error: 'BOT_TOKEN or CHAT_ID not configured' });
    }

    try {
        const contentType = request.headers.get('content-type') || '';
        let base64_image = '';
        let caption = '';

        if (contentType.includes('application/x-www-form-urlencoded')) {
            const text = await request.text();
            const params = new URLSearchParams(text);
            base64_image = params.get('base64_image') || '';
            caption = params.get('caption') || '';
        } else {
            base64_image = await request.text();
        }

        if (!base64_image) {
            return json(400, { status: false, error: 'base64_image required' });
        }

        let b64 = base64_image.trim();
        const comma = b64.indexOf(',');
        if (b64.startsWith('data:') && comma !== -1) b64 = b64.slice(comma + 1);
        b64 = b64.replace(/\s+/g, '').replace(/%2B/gi, '+').replace(/%2F/gi, '/').replace(/%3D/gi, '=');

        let imageBytes;
        try {
            const binary = atob(b64);
            imageBytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) imageBytes[i] = binary.charCodeAt(i);
        } catch {
            return json(400, { status: false, error: 'invalid base64' });
        }

        if (imageBytes.length === 0) return json(400, { status: false, error: 'image empty' });
        if (imageBytes.length > 20 * 1024 * 1024) return json(413, { status: false, error: 'image too large' });

        const boundary = '----ABG' + Math.random().toString(16).slice(2);
        const enc = new TextEncoder();
        const parts = [];

        const addField = (n, v) => parts.push(enc.encode(
            `--${boundary}\r\nContent-Disposition: form-data; name="${n}"\r\n\r\n${v}\r\n`
        ));

        addField('chat_id', env.CHAT_ID);
        if (caption) addField('caption', caption);
        addField('parse_mode', 'HTML');

        parts.push(enc.encode(
            `--${boundary}\r\nContent-Disposition: form-data; name="photo"; filename="f.jpg"\r\nContent-Type: image/jpeg\r\n\r\n`
        ));
        parts.push(imageBytes);
        parts.push(enc.encode(`\r\n--${boundary}--\r\n`));

        let totalLen = 0;
        for (const p of parts) totalLen += p.length;
        const body = new Uint8Array(totalLen);
        let offset = 0;
        for (const p of parts) { body.set(p, offset); offset += p.length; }

        const tgRes = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendPhoto`, {
            method: 'POST',
            headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
            body
        });

        const tgJson = await tgRes.json();
        if (!tgJson.ok) return json(502, { status: false, error: tgJson.description || 'telegram_failed' });

        return json(200, {
            status: true,
            telegram_message_id: tgJson.result && tgJson.result.message_id
        });
    } catch (err) {
        return json(500, { status: false, error: err.message || 'server error' });
    }
}

// ==================== HELPERS ====================

function json(code, data) {
    return new Response(JSON.stringify(data), {
        status: code,
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
}
