const { WebSocketServer } = require('ws');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

const online = new Map(); // username -> WebSocket (للمتصلين الآن فقط)

// ---------- تشفير كلمة المرور ----------
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
}

function newSalt() {
  return crypto.randomBytes(16).toString('hex');
}

// ---------- الاتصال بقاعدة البيانات ----------
async function db(method, path, body) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    method,
    headers: {
      apikey: SUPABASE_KEY,
      Authorization: `Bearer ${SUPABASE_KEY}`,
      'Content-Type': 'application/json',
      Prefer: method === 'POST' ? 'return=representation' : 'return=minimal',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`DB ${res.status}: ${await res.text()}`);
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

// ---------- الحسابات ----------
async function createAccount(username, password) {
  const existing = await db('GET', `users?id=eq.${encodeURIComponent(username)}&select=id`);
  if (existing.length > 0) return { ok: false, error: 'اسم المستخدم مستخدم مسبقاً' };
  const salt = newSalt();
  const stored = `${salt}:${hashPassword(password, salt)}`;
  await db('POST', 'users', { id: username, password_hash: stored });
  return { ok: true };
}

async function checkLogin(username, password) {
  const rows = await db('GET', `users?id=eq.${encodeURIComponent(username)}&select=password_hash`);
  if (rows.length === 0) return false;
  const [salt, hash] = rows[0].password_hash.split(':');
  return hashPassword(password, salt) === hash;
}

// ---------- الأذونات ----------
async function listGrants(owner) {
  return db('GET', `grants?owner_id=eq.${encodeURIComponent(owner)}&select=trusted_id,source`);
}

async function addGrant(owner, trusted, source) {
  await db('POST', 'grants', { owner_id: owner, trusted_id: trusted, source });
}

async function removeGrant(owner, trusted, source) {
  await db('DELETE', `grants?owner_id=eq.${encodeURIComponent(owner)}&trusted_id=eq.${encodeURIComponent(trusted)}&source=eq.${encodeURIComponent(source)}`);
}

async function allowed(owner, trusted, source) {
  const rows = await db('GET', `grants?owner_id=eq.${encodeURIComponent(owner)}&trusted_id=eq.${encodeURIComponent(trusted)}&source=eq.${encodeURIComponent(source)}&select=source`);
  return rows.length > 0;
}

// ---------- الخادم ----------
const wss = new WebSocketServer({ port: PORT });

function send(ws, obj) {
  if (ws.readyState === 1) ws.send(JSON.stringify(obj));
}

wss.on('connection', (ws) => {
  let me = null;

  ws.on('message', async (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    try {
      switch (msg.type) {
        case 'signup': {
          const r = await createAccount(String(msg.username), String(msg.password));
          send(ws, { type: 'signup_result', ...r });
          break;
        }

        case 'login': {
          const username = String(msg.username);
          const ok = await checkLogin(username, String(msg.password));
          if (!ok) {
            send(ws, { type: 'login_result', ok: false, error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
            break;
          }
          me = username;
          online.set(me, ws);
          const grants = await listGrants(me);
          send(ws, { type: 'login_result', ok: true, id: me, grants });
          break;
        }

        case 'grant': {
          if (!me) break;
          await addGrant(me, String(msg.trusted), String(msg.source));
          send(ws, { type: 'grants', grants: await listGrants(me) });
          break;
        }

        case 'revoke': {
          if (!me) break;
          await removeGrant(me, String(msg.trusted), String(msg.source));
          send(ws, { type: 'grants', grants: await listGrants(me) });
          break;
        }

        case 'revoke_all': {
          if (!me) break;
          await db('DELETE', `grants?owner_id=eq.${encodeURIComponent(me)}`);
          send(ws, { type: 'grants', grants: [] });
          break;
        }

        case 'signal': {
          if (!me) break;
          const to = String(msg.to);
          const target = online.get(to);
          if (!target || target.readyState !== 1) {
            send(ws, { type: 'error', message: 'الجهاز غير متصل' });
            break;
          }
          target.send(JSON.stringify({ type: 'signal', from: me, data: msg.data }));
          break;
        }
      }
    } catch (e) {
      send(ws, { type: 'error', message: 'خطأ في الخادم: ' + e.message });
    }
  });

  ws.on('close', () => {
    if (me && online.get(me) === ws) online.delete(me);
  });
});

console.log(`Signaling server running on port ${PORT}`);
