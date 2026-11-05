const { WebSocketServer } = require('ws');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

// الأجهزة المتصلة الآن: "اسم_المستخدم/معرّف_الجهاز" -> { ws, user, device }
const online = new Map();

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
}

function newSalt() {
  return crypto.randomBytes(16).toString('hex');
}

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

async function createAccount(username, password) {
  const existing = await db('GET', `users?id=eq.${encodeURIComponent(username)}&select=id`);
  if (existing.length > 0) return { ok: false, error: 'اسم المستخدم مستخدم مسبقاً' };
  const salt = newSalt();
  await db('POST', 'users', { id: username, password_hash: `${salt}:${hashPassword(password, salt)}` });
  return { ok: true };
}

async function checkLogin(username, password) {
  const rows = await db('GET', `users?id=eq.${encodeURIComponent(username)}&select=password_hash`);
  if (rows.length === 0) return false;
  const [salt, hash] = rows[0].password_hash.split(':');
  return hashPassword(password, salt) === hash;
}

// أول جهاز متصل لحساب معيّن (يُستخدم عندما لا يُحدَّد الجهاز)
function firstDeviceOf(user) {
  for (const [, entry] of online) {
    if (entry.user === user && entry.ws.readyState === 1) return entry;
  }
  return null;
}

function send(ws, obj) {
  if (ws.readyState === 1) ws.send(JSON.stringify(obj));
}

const wss = new WebSocketServer({ port: PORT });

wss.on('connection', (ws) => {
  let myKey = null;
  let me = null; // { user, device }

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
          const device = String(msg.device || 'd0');
          me = { user: username, device };
          myKey = `${username}/${device}`;
          online.set(myKey, { ws, user: username, device });
          send(ws, { type: 'login_result', ok: true, id: username, device });
          break;
        }

        case 'signal': {
          if (!me) break;
          const toUser = String(msg.toUser);
          const toDevice = msg.toDevice ? String(msg.toDevice) : '';

          // إن لم يُحدَّد الجهاز، نختار أول جهاز متصل للحساب الهدف
          const target = toDevice
            ? online.get(`${toUser}/${toDevice}`)
            : firstDeviceOf(toUser);

          if (!target || target.ws.readyState !== 1) {
            send(ws, { type: 'error', message: 'لا يوجد جهاز متصل لهذا الحساب' });
            break;
          }

          target.ws.send(JSON.stringify({
            type: 'signal',
            from: me.user,
            fromDevice: me.device,
            data: msg.data,
          }));
          break;
        }
      }
    } catch (e) {
      send(ws, { type: 'error', message: 'خطأ في الخادم: ' + e.message });
    }
  });

  ws.on('close', () => {
    if (myKey && online.get(myKey)?.ws === ws) online.delete(myKey);
  });
});

console.log(`Signaling server running on port ${PORT}`);
