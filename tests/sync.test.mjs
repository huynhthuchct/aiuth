import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { runSync, mergeAccounts, deriveSyncKeys, sealSnapshot, openSnapshot, changeSyncPassword, resetSyncPassword } from '../aiuth-sync.mjs';
import worker from '../sync-worker/src/index.js';

const record = (name, id, token = 'test-token') => ({ name, auth: JSON.stringify({ tokens: { account_id: id, access_token: token } }) });
const identify = (auth) => auth.tokens?.account_id || null;
function server() {
  const db = new DatabaseSync(':memory:');
  db.exec(fs.readFileSync(new URL('../sync-worker/schema.sql', import.meta.url), 'utf8'));
  const prepare = (sql) => {
    let args = [];
    return {
      bind(...values) { args = values; return this; },
      async first() { return db.prepare(sql).get(...args) ?? null; },
      async run() { return { meta: { changes: Number(db.prepare(sql).run(...args).changes) } }; }
    };
  };
  const env = { SETUP_CODE: 'test-setup', DB: { prepare, async batch(stmts) {
    db.exec('BEGIN');
    try { const out = []; for (const stmt of stmts) out.push(await stmt.run()); db.exec('COMMIT'); return out; }
    catch (e) { db.exec('ROLLBACK'); throw e; }
  } } };
  return { db, env, request: (url, opts) => worker.fetch(new Request(url, opts), env) };
}

test('merge prefers local identity and preserves differently named or colliding remote accounts', () => {
  const local = [record('same', 'a', 'new-token')];
  const remote = [record('old-alias', 'a', 'old-token'), record('same', 'b'), record('remote', 'c')];
  const merged = mergeAccounts(local, remote, identify);
  assert.equal(merged.length, 3);
  assert.equal(merged.find((r) => identify(JSON.parse(r.auth)) === 'a').auth, local[0].auth);
  assert.match(merged.find((r) => identify(JSON.parse(r.auth)) === 'b').name, /^same-remote-/);
  assert.deepEqual(mergeAccounts(merged, remote, identify), merged, 'repeated sync must not add duplicates');
  assert.equal(new Set(mergeAccounts([record('Alice', 'a')], [record('alice', 'b')], identify, true).map((r) => r.name.toLowerCase())).size, 2);
});
test('remote names and auth data are validated before importing', () => {
  for (const name of ['../escape', '/absolute', 'CON', 'accounts.', 'x/y'])
    assert.throws(() => mergeAccounts([], [record(name, 'a')], identify));
  assert.throws(() => mergeAccounts([], [{ name: 'bad', auth: '{}' }], identify));
});

test('two devices merge both ways, keep local tokens and store only ciphertext', async () => {
  const s = server();
  let local = [record('alpha', 'a')];
  const opts = { url: 'https://sync.example.test', password: 'test-password', setupCode: 'test-setup', identify, request: s.request,
    readLocal: () => local, writeLocal: (merged) => { local = merged; } };
  try {
    await runSync(opts);
    local = [record('beta', 'b')];
    await runSync(opts);
    assert.deepEqual(local.map((r) => r.name), ['alpha', 'beta']);
    local = [record('alpha-renamed', 'a', 'refreshed-local')];
    await runSync(opts);
    assert.equal(local.length, 2);
    assert.ok(local.some((r) => r.name === 'alpha-renamed' && r.auth.includes('refreshed-local')));
    const stored = s.db.prepare('SELECT * FROM snapshot').get();
    assert.ok(!JSON.stringify(stored).includes('refreshed-local'));
    assert.equal(s.db.prepare('SELECT COUNT(*) AS count FROM sessions').get().count, 0, 'temporary login is revoked');
    const before = structuredClone(local);
    await assert.rejects(runSync({ ...opts, password: 'wrong-password' }), /Sai mật khẩu/);
    assert.deepEqual(local, before);
    // Corrupted ciphertext cannot be imported or replaced.
    s.db.prepare("UPDATE snapshot SET ct = 'invalidciphertext'").run();
    await assert.rejects(runSync(opts));
    assert.equal(s.db.prepare('SELECT ct FROM snapshot').get().ct, 'invalidciphertext');
    assert.deepEqual(local, before);
  } finally { s.db.close(); }
});

test('conflict retries pull and preserve the other device before overriding Worker', async () => {
  const s = server();
  let local = [record('local', 'a')];
  let injected = false;
  const request = async (url, opts) => {
    if (!injected && url.endsWith('/snapshot') && opts.method === 'POST') {
      injected = true;
      const { salt } = s.db.prepare('SELECT salt FROM config').get();
      const keys = await deriveSyncKeys('test-password', salt);
      const blob = sealSnapshot([record('other-device', 'b')], keys.encKey);
      assert.equal((await s.request(url, { ...opts, body: JSON.stringify({ revision: 0, ...blob }) })).status, 200);
    }
    return s.request(url, opts);
  };
  try {
    const result = await runSync({ url: 'https://sync.example.test', password: 'test-password', setupCode: 'test-setup', identify, request,
      readLocal: () => local, writeLocal: (merged) => { local = merged; } });
    assert.equal(result.total, 2);
    assert.equal(result.revision, 2);
    const { salt } = s.db.prepare('SELECT salt FROM config').get();
    const { encKey } = await deriveSyncKeys('test-password', salt);
    assert.deepEqual(openSnapshot(s.db.prepare('SELECT iv, ct FROM snapshot').get(), encKey), local);
  } finally { s.db.close(); }
});

function runCli(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [new URL('../aiuth.mjs', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'), ...args], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', (data) => { stdout += data; });
    child.stderr.on('data', (data) => { stderr += data; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}
test('Worker write failure leaves local records unchanged', async () => {
  const s = server();
  let writes = 0;
  try {
    await assert.rejects(runSync({
      url: 'https://sync.example.test', password: 'test-password', setupCode: 'test-setup', identify,
      readLocal: () => [record('local', 'a')], writeLocal: () => { writes++; },
      request: (url, opts) => url.endsWith('/snapshot') && opts.method === 'POST'
        ? Promise.resolve(new Response(JSON.stringify({ error: 'server_error' }), { status: 503 }))
        : s.request(url, opts)
    }), /HTTP 503/);
    assert.equal(writes, 0);
    assert.equal(s.db.prepare('SELECT * FROM snapshot').get(), undefined);
  } finally { s.db.close(); }
});

test('password changes preserve ciphertext, unwrap repeatedly and revoke existing sessions', async () => {
  const s = server();
  let local = [record('worker-account', 'a')];
  const options = { url: 'https://sync.example.test', request: s.request, identify, setupCode: 'test-setup', readLocal: () => local, writeLocal: (records) => { local = records; } };
  try {
    await runSync({ ...options, password: 'old-password' });
    const before = s.db.prepare('SELECT * FROM snapshot').get();
    const originalConfig = s.db.prepare('SELECT * FROM config').get();
    const oldKeys = await deriveSyncKeys('old-password', originalConfig.salt);
    const session = await s.request(options.url + '/api/login', { method: 'POST', body: JSON.stringify({ authKey: oldKeys.authKey }) });
    const { token } = await session.json();
    await assert.rejects(changeSyncPassword({ ...options, oldPassword: 'incorrect-password', password: 'new-password' }), /Sai mật khẩu/);
    assert.deepEqual(s.db.prepare('SELECT * FROM config').get(), originalConfig);
    await changeSyncPassword({ ...options, oldPassword: 'old-password', password: 'new-password' });
    assert.deepEqual(s.db.prepare('SELECT * FROM snapshot').get(), before);
    assert.equal((await s.request(options.url + '/api/snapshot', { headers: { authorization: 'Bearer ' + token } })).status, 401);
    await assert.rejects(runSync({ ...options, password: 'old-password' }), /Sai mật khẩu/);
    local = [];
    await runSync({ ...options, password: 'new-password' });
    assert.equal(local[0].name, 'worker-account');
    await changeSyncPassword({ ...options, oldPassword: 'new-password', password: 'third-password' });
    local = [];
    await runSync({ ...options, password: 'third-password' });
    assert.equal(local[0].name, 'worker-account');
  } finally { s.db.close(); }
});

test('reset validates consent, setup code and local data; replaces Worker atomically', async () => {
  const s = server();
  const options = { url: 'https://sync.example.test', request: s.request, identify, setupCode: 'test-setup' };
  const local = [record('local-account', 'b')];
  try {
    await runSync({ ...options, password: 'old-password', readLocal: () => [record('remote-only', 'a')], writeLocal() {} });
    const before = s.db.prepare('SELECT * FROM snapshot').get();
    const beforeConfig = s.db.prepare('SELECT * FROM config').get();
    const resetOptions = { ...options, password: 'reset-password', confirmReset: true, readLocal: () => local };
    await assert.rejects(resetSyncPassword({ ...resetOptions, confirmReset: false }));
    for (let i = 0; i < 6; i++) await assert.rejects(resetSyncPassword({ ...resetOptions, setupCode: 'wrong-code' }), /Sai mã thiết lập/);
    await assert.rejects(resetSyncPassword({ ...resetOptions, readLocal: () => [record('../bad', 'c')] }));
    assert.deepEqual(s.db.prepare('SELECT * FROM snapshot').get(), before);
    s.db.exec("CREATE TRIGGER fail_reset BEFORE INSERT ON snapshot BEGIN SELECT RAISE(ABORT, 'test failure'); END");
    await assert.rejects(resetSyncPassword(resetOptions), /HTTP 500/);
    assert.deepEqual(s.db.prepare('SELECT * FROM snapshot').get(), before, 'failed reset must restore the prior ciphertext');
    assert.deepEqual(s.db.prepare('SELECT * FROM config').get(), beforeConfig, 'failed reset must keep the old password');
    s.db.exec('DROP TRIGGER fail_reset');
    const result = await resetSyncPassword(resetOptions);
    assert.equal(result.total, 1);
    assert.deepEqual(local, [record('local-account', 'b')]);
    assert.equal(s.db.prepare('SELECT * FROM key_wrap').get(), undefined);
    let pulled;
    await runSync({ ...options, password: 'reset-password', readLocal: () => [], writeLocal: (records) => { pulled = records; } });
    assert.deepEqual(pulled, local, 'remote-only account must be gone after reset');
    await assert.rejects(runSync({ ...options, password: 'old-password', readLocal: () => [], writeLocal() {} }), /Sai mật khẩu/);
  } finally { s.db.close(); }
});

test('CLI sync keeps live auth and backups, imports Worker records and prefers refreshed live tokens', async () => {
  const s = server();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aiuth-sync-test-'));
  const httpServer = http.createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const response = await s.request('http://127.0.0.1' + req.url, { method: req.method, headers: req.headers,
      ...(req.method === 'POST' ? { body: Buffer.concat(chunks) } : {}) });
    res.writeHead(response.status, Object.fromEntries(response.headers)); res.end(await response.text());
  });
  await new Promise((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
  try {
    const url = `http://127.0.0.1:${httpServer.address().port}`;
    await runSync({ url, password: 'test-password', setupCode: 'test-setup', identify, request: fetch,
      readLocal: () => [record('remote', 'b')], writeLocal() {} });
    const stored = record('local', 'a', 'old-local');
    const live = record('local', 'a', 'fresh-live');
    fs.mkdirSync(path.join(dir, 'accounts', 'local', 'backups'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'accounts', 'local', 'auth.json'), stored.auth);
    fs.writeFileSync(path.join(dir, 'accounts', 'local', 'backups', 'old.json'), stored.auth);
    fs.writeFileSync(path.join(dir, 'auth.json'), live.auth);
    const env = { CODEX_HOME: dir, CLAUDE_CONFIG_DIR: path.join(dir, 'claude-empty'), AIUTH_SYNC_PASSWORD: 'test-password', AIUTH_SYNC_URL: url, AIUTH_SYNC_SETUP_CODE: '' };
    const result = await runCli(['sync'], env);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(fs.readFileSync(path.join(dir, 'auth.json'), 'utf8'), live.auth);
    assert.equal(fs.readFileSync(path.join(dir, 'accounts', 'local', 'backups', 'old.json'), 'utf8'), stored.auth);
    assert.equal(fs.readFileSync(path.join(dir, 'accounts', 'remote', 'auth.json'), 'utf8'), record('remote', 'b').auth);
    const { salt } = s.db.prepare('SELECT salt FROM config').get();
    const { encKey } = await deriveSyncKeys('test-password', salt);
    const remote = openSnapshot(s.db.prepare('SELECT iv, ct FROM snapshot').get(), encKey);
    assert.ok(remote.some((r) => r.auth.includes('fresh-live')));
    assert.ok(!result.stdout.includes('fresh-live'));
    const change = await runCli(['sync', 'change-password'], { ...env, AIUTH_SYNC_NEW_PASSWORD: 'new-cli-password' });
    assert.equal(change.code, 0, change.stderr);
    assert.ok(!change.stdout.includes('new-cli-password'));
    const synced = await runCli(['sync'], { ...env, AIUTH_SYNC_PASSWORD: 'new-cli-password' });
    assert.equal(synced.code, 0, synced.stderr);
    const resetEnv = { ...env, AIUTH_SYNC_NEW_PASSWORD: 'reset-cli-password', AIUTH_SYNC_SETUP_CODE: 'test-setup' };
    const beforeReset = s.db.prepare('SELECT * FROM snapshot').get();
    const cancelled = await runCli(['sync', 'reset-password'], resetEnv);
    assert.equal(cancelled.code, 1);
    assert.deepEqual(s.db.prepare('SELECT * FROM snapshot').get(), beforeReset);
    const reset = await runCli(['sync', 'forgot-password', '--confirm-reset'], resetEnv);
    assert.equal(reset.code, 0, reset.stderr);
    assert.equal(fs.readFileSync(path.join(dir, 'auth.json'), 'utf8'), live.auth);
    assert.equal(fs.readFileSync(path.join(dir, 'accounts', 'local', 'backups', 'old.json'), 'utf8'), stored.auth);
    assert.equal((await runCli(['sync'], { ...env, AIUTH_SYNC_PASSWORD: 'reset-cli-password' })).code, 0);
  } finally {
    await new Promise((resolve) => httpServer.close(resolve));
    s.db.close(); fs.rmSync(dir, { recursive: true, force: true });
  }
});
