import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

const CLI = new URL('../aiuth.mjs', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
function run(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

const jwt = (claims) => `h.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.s`;
const codexAuth = (email, token = 't') => JSON.stringify({ auth_mode: 'chatgpt', tokens: { id_token: jwt({ email }), access_token: token, account_id: `acct-${email}` } });
const claudeCred = (token, extra = {}) => JSON.stringify({ claudeAiOauth: { accessToken: token, refreshToken: `r-${token}`, expiresAt: 1, subscriptionType: 'max' }, ...extra });
const claudeCfg = (email, extra = {}) => JSON.stringify({ oauthAccount: { emailAddress: email, accountUuid: `uuid-${email}` }, ...extra });

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aiuth-claude-'));
  const codex = path.join(dir, 'codex');
  const claude = path.join(dir, 'claude');
  fs.mkdirSync(codex);
  fs.mkdirSync(claude);
  const env = { CODEX_HOME: codex, CLAUDE_CONFIG_DIR: claude };
  const cred = path.join(claude, '.credentials.json');
  const cfg = path.join(claude, '.claude.json');
  const auth = path.join(codex, 'auth.json');
  return { dir, env, cred, cfg, auth, codex, claude, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('save stores both Codex and Claude; list shows one table with a provider column', async () => {
  const s = sandbox();
  try {
    fs.writeFileSync(s.auth, codexAuth('me@example.com'));
    fs.writeFileSync(s.cred, claudeCred('c1'));
    fs.writeFileSync(s.cfg, claudeCfg('me@example.com'));
    const saved = await run(['save'], s.env);
    assert.equal(saved.code, 0, saved.stderr);
    assert.match(saved.stdout, /tài khoản codex "me@example.com"/);
    // Cùng email ở hai provider: Claude nhận hậu tố để tên vẫn duy nhất.
    assert.match(saved.stdout, /tài khoản claude "me@example.com-claude"/);
    const list = await run(['list'], s.env);
    assert.equal(list.code, 0, list.stderr);
    assert.match(list.stdout, /PROVIDER/);
    assert.match(list.stdout, /\* +1 codex +me@example\.com /);
    assert.match(list.stdout, /\* +2 claude +me@example\.com-claude /);
    // Lưu lại không tạo bản trùng.
    assert.equal((await run(['save'], s.env)).code, 0);
    assert.equal(fs.readdirSync(path.join(s.codex, 'accounts')).filter((n) => !n.startsWith('.')).length, 2);
    const cur = await run(['current'], s.env);
    assert.match(cur.stdout, /codex +me@example\.com/);
    assert.match(cur.stdout, /claude +me@example\.com-claude/);
  } finally { s.cleanup(); }
});

test('use on a Claude row swaps only Claude and keeps unrelated Claude keys; Codex row swaps only Codex', async () => {
  const s = sandbox();
  try {
    fs.writeFileSync(s.auth, codexAuth('x@codex.com', 'codex-live'));
    fs.writeFileSync(s.cred, claudeCred('a-token', { mcpOAuth: { keep: true } }));
    fs.writeFileSync(s.cfg, claudeCfg('a@claude.com', { theme: 'dark' }));
    assert.equal((await run(['save'], s.env)).code, 0);
    // Đăng nhập tài khoản Claude thứ hai rồi lưu.
    fs.writeFileSync(s.cred, claudeCred('b-token', { mcpOAuth: { keep: true } }));
    fs.writeFileSync(s.cfg, claudeCfg('b@claude.com', { theme: 'dark' }));
    assert.equal((await run(['save'], s.env)).code, 0);
    const list = await run(['list'], s.env);
    const row = (email) => list.stdout.split('\n').find((l) => l.includes(email));
    assert.match(row('b@claude.com'), /^\*/);
    assert.doesNotMatch(row('a@claude.com'), /^\*/);
    const index = row('a@claude.com').trim().split(/\s+/).find((t) => /^\d+$/.test(t));

    const used = await run(['use', index], s.env);
    assert.equal(used.code, 0, used.stderr);
    const cred = JSON.parse(fs.readFileSync(s.cred, 'utf8'));
    const cfg = JSON.parse(fs.readFileSync(s.cfg, 'utf8'));
    assert.equal(cred.claudeAiOauth.accessToken, 'a-token');
    assert.deepEqual(cred.mcpOAuth, { keep: true });
    assert.equal(cfg.oauthAccount.emailAddress, 'a@claude.com');
    assert.equal(cfg.theme, 'dark');
    assert.equal(fs.readFileSync(s.auth, 'utf8'), codexAuth('x@codex.com', 'codex-live'), 'Codex không bị đụng');
    assert.match(used.stdout, /khởi động lại Claude Code/);

    // Dùng lại tài khoản Claude b bằng tên; Codex vẫn nguyên.
    assert.equal((await run(['use', 'b@claude.com'], s.env)).code, 0);
    assert.equal(JSON.parse(fs.readFileSync(s.cred, 'utf8')).claudeAiOauth.accessToken, 'b-token');

    // Codex: thêm tài khoản thứ hai, use sang tài khoản đầu; Claude không đổi.
    fs.writeFileSync(s.auth, codexAuth('y@codex.com', 'codex-2'));
    assert.equal((await run(['save'], s.env)).code, 0);
    const claudeBefore = fs.readFileSync(s.cred, 'utf8');
    const switched = await run(['use', 'x@codex.com', '--no-kill'], s.env);
    assert.equal(switched.code, 0, switched.stderr);
    assert.match(fs.readFileSync(s.auth, 'utf8'), /codex-live/);
    assert.equal(fs.readFileSync(s.cred, 'utf8'), claudeBefore);
  } finally { s.cleanup(); }
});

test('Claude token refresh is kept when switching away, and an unsaved Claude login goes to .unsaved', async () => {
  const s = sandbox();
  try {
    fs.writeFileSync(s.cred, claudeCred('old'));
    fs.writeFileSync(s.cfg, claudeCfg('a@claude.com'));
    assert.equal((await run(['save'], s.env)).code, 0);
    fs.writeFileSync(s.cred, claudeCred('b1'));
    fs.writeFileSync(s.cfg, claudeCfg('b@claude.com'));
    assert.equal((await run(['save'], s.env)).code, 0);
    fs.writeFileSync(s.cred, claudeCred('b2-refreshed'));
    assert.equal((await run(['use', 'a@claude.com'], s.env)).code, 0);
    const saved = JSON.parse(fs.readFileSync(path.join(s.codex, 'accounts', 'b@claude.com', 'auth.json'), 'utf8'));
    assert.equal(saved.claudeAiOauth.accessToken, 'b2-refreshed');

    // Đăng nhập tài khoản chưa lưu rồi use: bản chưa lưu được cất lại.
    fs.writeFileSync(s.cred, claudeCred('c1'));
    fs.writeFileSync(s.cfg, claudeCfg('c@claude.com'));
    assert.equal((await run(['use', 'b@claude.com'], s.env)).code, 0);
    const kept = fs.readdirSync(path.join(s.codex, 'accounts', '.unsaved'));
    assert.equal(kept.length, 1);
    assert.match(kept[0], /^claude-/);
  } finally { s.cleanup(); }
});

test('usage reports Claude rows as unsupported instead of failing', async () => {
  const s = sandbox();
  try {
    fs.writeFileSync(s.cred, claudeCred('a'));
    fs.writeFileSync(s.cfg, claudeCfg('a@claude.com'));
    assert.equal((await run(['save'], s.env)).code, 0);
    const out = await run(['usage'], s.env);
    assert.equal(out.code, 0, out.stderr);
    assert.match(out.stdout, /Claude: chưa hỗ trợ/);
  } finally { s.cleanup(); }
});
