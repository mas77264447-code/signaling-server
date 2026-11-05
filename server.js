const { WebSocketServer } = require('ws');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

// الأجهزة المتصلة الآن: deviceKey -> { ws, user }
// deviceKey = اسم المستخدم + "/" + معرّف الجهاز
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

async function listGrants(owner) {
  return db('GET', `grants?owner_id=eq.${encodeURIComponent(owner)}&select=trusted_id,source`);
}

async function addGrant(owner, trusted, source) {
  await db('POST', 'grants', { owner_id: owner, trusted_id: trusted, source });
}

async function removeGrant(owner, trusted, source) {
  await db('DELETE', `grants?owner_id=eq.${encodeURIComponent(owner)}&trusted_id=eq.${encodeURIComponent(trusted)}&source=eq.${encodeURIComponent(source)}`);
}

// قائمة الأجهزة المتصلة لحساب معيّن
function devicesOf(user) {
  const list = [];
  for (const [key, entry] of online) {
    if (entry.user === user) list.push(entry.device);
  }
  return list;
}

function send(ws, obj) {
  if (ws.readyState === 1) ws.send(JSON.stringify(obj));
}

const wss = new WebSocketServer({ port: PORT });

wss.on('connection', (ws) => {
  let me = null; // { user, device }
  let myKey = null;

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
          const grants = await listGrants(username);
          send(ws, {
            type: 'login_result',
            ok: true,
            id: username,
            device,
            grants,
            devices: devicesOf(username).filter((d) => d !== device),
          });
          break;
        }

        case 'list_devices': {
          if (!me) break;
          // أجهزة الحساب الآخر المتصلة الآن
          const other = String(msg.user);
          const list = [];
          for (const [, entry] of online) {
            if (entry.user === other) list.push(entry.device);
          }
          send(ws, { type: 'devices', user: other, devices: list });
          break;
        }

        case 'grant': {
          if (!me) break;
          await addGrant(me.user, String(msg.trusted), String(msg.source));
          send(ws, { type: 'grants', grants: await listGrants(me.user) });
          break;
        }

        case 'revoke': {
          if (!me) break;
          await removeGrant(me.user, String(msg.trusted), String(msg.source));
          send(ws, { type: 'grants', grants: await listGrants(me.user) });
          break;
        }

        case 'signal': {
          if (!me) break;
          // الهدف: اسم المستخدم + معرّف الجهاز
          const targetKey = `${String(msg.toUser)}/${String(msg.toDevice)}`;
          const target = online.get(targetKey);
          if (!target || target.ws.readyState !== 1) {
            send(ws, { type: 'error', message: 'الجهاز غير متصل' });
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
