import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { setupCloudflare, findNpx } from '../aiuth-setup.mjs';

const account = 'a'.repeat(32);
const databaseId = '01203641-d0b7-44ee-a8cf-ad1dfa995d59';
const url = 'https://aiuth-sync.example.workers.dev';
function mockRunner({ existing = true, loggedIn = true, fail, invalidList = false, afterLogin = true } = {}) {
  const calls = [];
  let hasDatabase = existing;
  let authenticated = loggedIn;
  const runner = async (args, opts = {}) => {
    calls.push({ args, opts });
    const cmd = args.slice(0, 2).join(' ');
    if (cmd === fail) return { code: 1, output: 'mock cloud failure' };
    if (args[0] === 'whoami') return { code: 0, output: authenticated ? `You are logged in\nAccount ID ${account}` : 'You are not authenticated.' };
    if (args[0] === 'login') { authenticated = afterLogin; return { code: 0, output: '' }; }
    if (cmd === 'd1 list') return { code: 0, output: invalidList ? 'invalid response' : `notice\n${JSON.stringify(hasDatabase ? [{ name: 'aiuth-sync', uuid: databaseId }] : [])}\n` };
    if (cmd === 'd1 create') hasDatabase = true;
    if (args[0] === 'deploy') return { code: 0, output: `Deployed\n${url}\n` };
    return { code: 0, output: 'ok' };
  };
  return { runner, calls };
}
async function fixture(fn) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'aiuth-setup-test-'));
  try { await fn(home); } finally { fs.rmSync(home, { recursive: true, force: true }); }
}

test('fresh setup logs in, creates D1, deploys and stores a private code and URL', async () => fixture(async (home) => {
  const mock = mockRunner({ existing: false, loggedIn: false });
  const logs = [];
  const result = await setupCloudflare({ home, runner: mock.runner, interactive: true, nodeVersion: '22.12.0', log: (line) => logs.push(line) });
  assert.equal(result.url, url);
  assert.ok(mock.calls.some((c) => c.args[0] === 'login' && c.opts.interactive));
  assert.ok(mock.calls.some((c) => c.args[1] === 'create'));
  assert.ok(mock.calls.some((c) => c.args.includes('--file=schema.sql')));
  const secret = mock.calls.find((c) => c.args[0] === 'secret');
  assert.match(secret.opts.input.trim(), /^[A-Za-z0-9_-]{32}$/);
  assert.ok(fs.readFileSync(result.infoPath, 'utf8').includes(secret.opts.input.trim()));
  assert.ok(!logs.join('\n').includes(secret.opts.input.trim()));
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(home, 'aiuth-sync.json'))), { url });
  assert.match(fs.readFileSync(path.join(result.workspace, 'wrangler.toml'), 'utf8'), new RegExp(databaseId));
  if (process.platform !== 'win32') assert.equal(fs.statSync(result.infoPath).mode & 0o777, 0o600);
}));

test('rerunning setup reuses database and setup code, preserving local accounts', async () => fixture(async (home) => {
  const workspace = path.join(home, 'aiuth-worker');
  fs.mkdirSync(workspace);
  const secret = 'a_b-c'.repeat(6);
  fs.writeFileSync(path.join(workspace, 'setup-info.txt'), `Worker: ${url}\nSetup code: ${secret}\n`);
  fs.mkdirSync(path.join(home, 'accounts'));
  fs.writeFileSync(path.join(home, 'auth.json'), 'untouched-live');
  fs.writeFileSync(path.join(home, 'accounts', 'keep'), 'untouched-account');
  const mock = mockRunner();
  await setupCloudflare({ home, runner: mock.runner, nodeVersion: '24.0.0', log() {} });
  assert.ok(!mock.calls.some((c) => c.args.includes('create')));
  assert.equal(mock.calls.find((c) => c.args[0] === 'secret').opts.input, secret + '\n');
  assert.equal(fs.readFileSync(path.join(home, 'auth.json'), 'utf8'), 'untouched-live');
  assert.equal(fs.readFileSync(path.join(home, 'accounts', 'keep'), 'utf8'), 'untouched-account');
}));

test('setup imports the original source setup code without rotating it', async () => fixture(async (home) => {
  const source = path.join(home, 'source');
  fs.cpSync(fileURLToPath(new URL('../sync-worker', import.meta.url)), path.join(source, 'sync-worker'), {
    recursive: true, filter: (file) => !file.includes('.wrangler') && !file.endsWith('setup-info.txt')
  });
  const secret = 'ABCDEF-123456-ABCDEF-123456-ABCDEF-123456';
  fs.writeFileSync(path.join(source, 'sync-worker', 'setup-info.txt'), `Worker: ${url}\nSetup code: ${secret}\n`);
  const mock = mockRunner();
  await setupCloudflare({ home, source, runner: mock.runner, log() {} });
  assert.equal(mock.calls.find((c) => c.args[0] === 'secret').opts.input.trim(), secret);
}));

test('list failures do not create databases; secret failures keep the recovery code and prior config', async () => fixture(async (home) => {
  const configPath = path.join(home, 'aiuth-sync.json');
  const oldConfig = '{"url":"https://previous.example.test"}';
  fs.writeFileSync(configPath, oldConfig);
  const invalid = mockRunner({ invalidList: true });
  await assert.rejects(setupCloudflare({ home, runner: invalid.runner, log() {} }), /danh sách database/);
  assert.ok(!invalid.calls.some((c) => c.args.includes('create')));
  const failed = mockRunner({ fail: 'secret put' });
  await assert.rejects(setupCloudflare({ home, runner: failed.runner, log() {} }), /mã thiết lập/);
  assert.ok(fs.existsSync(path.join(home, 'aiuth-worker', 'setup-info.txt')));
  assert.equal(fs.readFileSync(configPath, 'utf8'), oldConfig);
}));

test('headless auth and unsupported Node stop before provisioning', async () => fixture(async (home) => {
  const mock = mockRunner({ loggedIn: false });
  await assert.rejects(setupCloudflare({ home, runner: mock.runner, interactive: false, log() {} }), /terminal tương tác/);
  assert.equal(mock.calls.length, 1);
  await assert.rejects(setupCloudflare({ home, runner: mock.runner, nodeVersion: '22.11.0', log() {} }), /22.12.0/);
  assert.equal(mock.calls.length, 1);
}));

test('npx runs directly through Node without a command shell', () => {
  const npx = findNpx();
  assert.ok(fs.existsSync(npx));
  const checked = spawnSync(process.execPath, [npx, '--version'], { encoding: 'utf8' });
  assert.equal(checked.status, 0, checked.stderr);
  assert.match(checked.stdout.trim(), /^\d+\./);
});
