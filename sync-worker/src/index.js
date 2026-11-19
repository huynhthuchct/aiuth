const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }
});
const b64 = /^[A-Za-z0-9_-]+$/;
const encode = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const hash = async (value) => encode(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))));
async function equal(a, b) {
  const [x, y] = await Promise.all([hash(a), hash(b)]);
  let difference = 0;
  for (let i = 0; i < x.length; i++) difference |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return difference === 0;
}
const config = (db) => db.prepare('SELECT c.salt, c.auth_hash, k.iv AS key_iv, k.ct AS key_ct FROM config c LEFT JOIN key_wrap k ON k.id = c.id WHERE c.id = 1').first();
const validKeys = (salt, key) => typeof salt === 'string' && b64.test(salt) && salt.length === 22 && typeof key === 'string' && b64.test(key) && key.length === 43;
const validBlob = (blob, max = 700000) => blob && typeof blob.iv === 'string' && b64.test(blob.iv) && blob.iv.length === 16 && typeof blob.ct === 'string' && b64.test(blob.ct) && blob.ct.length >= 22 && blob.ct.length <= max;
async function route(req, env) {
  const db = env.DB;
  const path = new URL(req.url).pathname;
  if (req.method === 'GET' && path === '/') return json({ service: 'aiuth-sync-v1' });
  if (req.method === 'GET' && path === '/api/status') {
    const account = await config(db);
    return json({ service: 'aiuth-sync-v1', registered: !!account, salt: account?.salt ?? null,
      wrappedKey: account?.key_iv ? { iv: account.key_iv, ct: account.key_ct } : null });
  }
  let body;
  if (req.method === 'POST') {
    const text = await req.text();
    if (new TextEncoder().encode(text).length > 800000) return json({ error: 'too_large' }, 413);
    try { body = JSON.parse(text); } catch { return json({ error: 'bad_json' }, 400); }
    if (!body || typeof body !== 'object' || Array.isArray(body)) return json({ error: 'bad_request' }, 400);
  }
  if (req.method === 'POST' && path === '/api/register') {
    if (!env.SETUP_CODE) return json({ error: 'setup_code_missing' }, 503);
    if (typeof body.setupCode !== 'string' || !(await equal(body.setupCode, env.SETUP_CODE))) return json({ error: 'bad_setup_code' }, 403);
    if (typeof body.salt !== 'string' || !b64.test(body.salt) || body.salt.length !== 22 ||
        typeof body.authKey !== 'string' || !b64.test(body.authKey) || body.authKey.length !== 43) return json({ error: 'bad_request' }, 400);
    const result = await db.prepare('INSERT OR IGNORE INTO config (id, salt, auth_hash) VALUES (1, ?, ?)').bind(body.salt, await hash(body.authKey)).run();
    return result.meta.changes === 1 ? json({ ok: true }) : json({ error: 'already_registered' }, 409);
  }
  if (req.method === 'POST' && path === '/api/password/reset') {
    if (!env.SETUP_CODE) return json({ error: 'setup_code_missing' }, 503);
    if (typeof body.setupCode !== 'string' || !(await equal(body.setupCode, env.SETUP_CODE))) return json({ error: 'bad_setup_code' }, 403);
    if (body.confirmReset !== true || !validKeys(body.salt, body.authKey) || !validBlob(body.snapshot)) return json({ error: 'bad_request' }, 400);
    // D1 batch là một transaction: thay mật khẩu và bản local đã mã hoá cùng lúc.
    await db.batch([
      db.prepare('DELETE FROM sessions'),
      db.prepare('DELETE FROM key_wrap'),
      db.prepare('DELETE FROM snapshot'),
      db.prepare('DELETE FROM config'),
      db.prepare('INSERT INTO config (id, salt, auth_hash) VALUES (1, ?, ?)').bind(body.salt, await hash(body.authKey)),
      db.prepare('INSERT INTO snapshot (id, revision, iv, ct) VALUES (1, 1, ?, ?)').bind(body.snapshot.iv, body.snapshot.ct)
    ]);
    return json({ ok: true });
  }
  if (req.method === 'POST' && path === '/api/password/change') {
    const account = await config(db);
    if (!account || !validKeys(body.salt, body.authKey) || !(await equal(await hash(body.authKey), account.auth_hash))) return json({ error: 'bad_credentials' }, 401);
    if (!validKeys(body.salt, body.newAuthKey) || !validBlob(body.wrappedKey, 256)) return json({ error: 'bad_request' }, 400);
    const guard = 'EXISTS (SELECT 1 FROM config WHERE id = 1 AND auth_hash = ?)';
    const result = await db.batch([
      db.prepare('DELETE FROM sessions WHERE ' + guard).bind(account.auth_hash),
      db.prepare('INSERT INTO key_wrap (id, iv, ct) SELECT 1, ?, ? WHERE ' + guard + ' ON CONFLICT(id) DO UPDATE SET iv = excluded.iv, ct = excluded.ct').bind(body.wrappedKey.iv, body.wrappedKey.ct, account.auth_hash),
      db.prepare('UPDATE config SET salt = ?, auth_hash = ? WHERE id = 1 AND auth_hash = ?').bind(body.salt, await hash(body.newAuthKey), account.auth_hash)
    ]);
    return result[2].meta.changes === 1 ? json({ ok: true }) : json({ error: 'account_changed' }, 409);
  }
  if (req.method === 'POST' && path === '/api/login') {
    const account = await config(db);
    if (!account || typeof body.authKey !== 'string' || body.authKey.length !== 43 || !(await equal(await hash(body.authKey), account.auth_hash))) return json({ error: 'bad_credentials' }, 401);
    const token = encode(crypto.getRandomValues(new Uint8Array(32)));
    const result = await db.batch([
      db.prepare('DELETE FROM sessions WHERE expires <= ?').bind(Date.now()),
      db.prepare('INSERT INTO sessions (hash, expires) SELECT ?, ? WHERE EXISTS (SELECT 1 FROM config WHERE id = 1 AND auth_hash = ?)').bind(await hash(token), Date.now() + 15 * 60000, account.auth_hash),
      db.prepare('DELETE FROM sessions WHERE hash NOT IN (SELECT hash FROM sessions ORDER BY expires DESC, rowid DESC LIMIT 10)')
    ]);
    if (result[1].meta.changes !== 1) return json({ error: 'account_changed' }, 409);
    return json({ token });
  }
  const bearer = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.get('authorization') || '');
  if (!bearer) return json({ error: 'unauthorized' }, 401);
  const tokenHash = await hash(bearer[1]);
  const active = () => db.prepare('SELECT 1 AS active FROM sessions WHERE hash = ? AND expires > ?').bind(tokenHash, Date.now()).first();
  if (!(await active())) return json({ error: 'unauthorized' }, 401);
  if (req.method === 'POST' && path === '/api/logout') {
    await db.prepare('DELETE FROM sessions WHERE hash = ?').bind(tokenHash).run();
    return json({ ok: true });
  }
  if (req.method === 'GET' && path === '/api/snapshot') {
    const snapshot = await db.prepare('SELECT revision, iv, ct FROM snapshot WHERE id = 1').first();
    return json(snapshot ? { revision: snapshot.revision, blob: { iv: snapshot.iv, ct: snapshot.ct } } : { revision: 0, blob: null });
  }
  if (req.method === 'POST' && path === '/api/snapshot') {
    if (!Number.isSafeInteger(body.revision) || body.revision < 0 ||
        typeof body.iv !== 'string' || !b64.test(body.iv) || body.iv.length !== 16 ||
        typeof body.ct !== 'string' || !b64.test(body.ct) || body.ct.length < 22 || body.ct.length > 700000) return json({ error: 'bad_request' }, 400);
    const guard = 'EXISTS (SELECT 1 FROM sessions WHERE hash = ? AND expires > ?)';
    const stmt = body.revision === 0
      ? db.prepare('INSERT INTO snapshot (id, revision, iv, ct) SELECT 1, 1, ?, ? WHERE ' + guard + ' ON CONFLICT(id) DO NOTHING').bind(body.iv, body.ct, tokenHash, Date.now())
      : db.prepare('UPDATE snapshot SET revision = revision + 1, iv = ?, ct = ? WHERE id = 1 AND revision = ? AND ' + guard).bind(body.iv, body.ct, body.revision, tokenHash, Date.now());
    const result = await stmt.run();
    if (result.meta.changes !== 1) return json({ error: (await active()) ? 'conflict' : 'unauthorized' }, (await active()) ? 409 : 401);
    return json({ revision: body.revision + 1 });
  }
  return json({ error: 'not_found' }, 404);
}
export default {
  async fetch(req, env) {
    try { return await route(req, env); }
    catch { return json({ error: 'server_error' }, 500); }
  }
};
