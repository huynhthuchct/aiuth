import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const NAME = 'aiuth-sync';
const WRANGLER = 'wrangler@4.165.0';
const read = (file) => fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null;
function write(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, content, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

// Chạy npx bằng Node, không qua shell: hoạt động với đường dẫn Windows có dấu cách.
export function findNpx() {
  const lookup = spawnSync(process.platform === 'win32' ? 'where.exe' : 'which', ['npx'], { encoding: 'utf8', windowsHide: true });
  const candidates = [
    process.env.npm_execpath && path.join(path.dirname(process.env.npm_execpath), 'npx-cli.js'),
    path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npx-cli.js')
  ];
  for (const bin of (lookup.stdout || '').trim().split(/\r?\n/).filter(Boolean)) {
    candidates.push(path.join(path.dirname(bin), 'node_modules/npm/bin/npx-cli.js'));
    try { const real = fs.realpathSync(bin); if (real.endsWith('.js')) candidates.push(real); } catch {}
  }
  const result = candidates.find((file) => file && fs.existsSync(file));
  if (!result) throw new Error('Không tìm thấy npx. Hãy cài Node.js LTS kèm npm rồi chạy lại aiuth sync setup.');
  return result;
}

export function createWranglerRunner(cwd) {
  const npx = findNpx();
  return (args, { input, interactive = false, stream = false } = {}) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [npx, '--yes', WRANGLER, ...args], {
      cwd, shell: false, windowsHide: true,
      env: { ...process.env, NO_COLOR: '1', WRANGLER_SEND_METRICS: 'false' },
      stdio: interactive ? 'inherit' : ['pipe', 'pipe', 'pipe']
    });
    let output = '';
    if (!interactive) {
      const collect = (chunk) => {
        output += chunk;
        if (stream) process.stderr.write(chunk);
      };
      child.stdout.on('data', collect);
      child.stderr.on('data', collect);
      child.stdin.on('error', () => {});
      child.stdin.end(input ?? '');
    }
    child.once('error', reject);
    child.once('close', (code) => resolve({ code, output }));
  });
}

function parseDatabaseList(output) {
  for (let start = output.indexOf('['); start >= 0; start = output.indexOf('[', start + 1)) {
    for (let end = output.lastIndexOf(']'); end > start; end = output.lastIndexOf(']', end - 1)) {
      try { const value = JSON.parse(output.slice(start, end + 1)); if (Array.isArray(value)) return value; } catch {}
    }
  }
  throw new Error('Không đọc được danh sách database Cloudflare. Chưa tạo hoặc thay đổi database.');
}

function setupCodeFor(url, workspace, source) {
  const saved = read(path.join(workspace, 'setup-info.txt'));
  const legacy = read(path.join(source, 'sync-worker/setup-info.txt'));
  for (const text of [saved, legacy]) {
    if (!text) continue;
    const previousUrl = /^(?:Worker|Địa chỉ máy chủ)\s*:\s*(https:\/\/[A-Za-z0-9.-]+\.workers\.dev)\s*$/m.exec(text)?.[1];
    const code = /^(?:Setup code|Mã thiết lập)\s*:\s*([A-Za-z0-9_-]{16,128})\s*$/m.exec(text)?.[1];
    if (previousUrl === url && code) return code;
  }
  return crypto.randomBytes(24).toString('base64url');
}

export async function setupCloudflare({ home, source = ROOT, runner, log = console.log, interactive = process.stdin.isTTY,
  nodeVersion = process.versions.node, accountId = process.env.CLOUDFLARE_ACCOUNT_ID } = {}) {
  log('[1/6] Kiểm tra Node.js và chuẩn bị Worker');
  const [major, minor] = nodeVersion.split('.').map(Number);
  if (major < 22 || (major === 22 && minor < 12)) throw new Error('Cài Cloudflare cần Node.js >= 22.12.0. Hãy cập nhật Node.js LTS rồi chạy lại.');
  if (!home) throw new Error('Thiếu thư mục cấu hình aiuth.');
  const workspace = path.join(home, 'aiuth-worker');
  fs.mkdirSync(workspace, { recursive: true, mode: 0o700 });
  for (const file of ['src/index.js', 'schema.sql']) {
    const template = read(path.join(source, 'sync-worker', file));
    if (!template) throw new Error('Bản aiuth thiếu source Worker. Hãy cài lại phiên bản aiuth mới.');
    write(path.join(workspace, file), template);
  }
  const run = runner || createWranglerRunner(workspace);
  const checked = async (args, opts = {}) => {
    const result = await run(args, opts);
    if (result.code !== 0) {
      const hint = /subdomain/i.test(result.output || '')
        ? ' Hãy tạo tên miền workers.dev tại Cloudflare Dashboard → Workers & Pages rồi chạy lại.' : '';
      throw new Error(`Cloudflare thất bại ở bước ${args.slice(0, 2).join(' ')}.${hint}\n${opts.input ? 'Không cập nhật được mã thiết lập. Mã đã được giữ trong setup-info.txt.' : (result.output || '')}`);
    }
    return result.output || '';
  };
  const config = (dbId) => `name = "${NAME}"\nmain = "src/index.js"\ncompatibility_date = "2025-01-01"\nworkers_dev = true\n${accountId ? `account_id = "${accountId}"\n` : ''}${dbId ? `\n[[d1_databases]]\nbinding = "DB"\ndatabase_name = "${NAME}"\ndatabase_id = "${dbId}"\n` : ''}`;
  write(path.join(workspace, 'wrangler.toml'), config());

  log('[2/6] Kiểm tra đăng nhập Cloudflare');
  let who = await run(['whoami']);
  if (!/You are logged in/i.test(who.output || '')) {
    if (who.code !== 0 && !/not authenticated|not logged in|authentication|unauthorized|login/i.test(who.output || ''))
      throw new Error('Không kiểm tra được đăng nhập Cloudflare. Kiểm tra mạng rồi chạy lại.');
    if (!interactive) throw new Error('Chưa đăng nhập Cloudflare. Chạy aiuth sync setup trong terminal tương tác hoặc đặt CLOUDFLARE_API_TOKEN và CLOUDFLARE_ACCOUNT_ID.');
    log('Trình duyệt sẽ mở. Đăng nhập Cloudflare và bấm Allow.');
    await checked(['login'], { interactive: true });
    who = { code: 0, output: await checked(['whoami']) };
    if (!/You are logged in/i.test(who.output)) throw new Error('Cloudflare chưa xác nhận đăng nhập. Hãy chạy lại setup.');
  }
  if (!accountId) {
    const ids = [...new Set((who.output || '').match(/\b[a-f0-9]{32}\b/gi) || [])];
    if (ids.length !== 1) throw new Error('Có nhiều hoặc không xác định được tài khoản Cloudflare. Đặt CLOUDFLARE_ACCOUNT_ID rồi chạy lại.');
    accountId = ids[0];
  }
  if (!/^[a-f0-9]{32}$/i.test(accountId)) throw new Error('CLOUDFLARE_ACCOUNT_ID không hợp lệ.');
  write(path.join(workspace, 'wrangler.toml'), config());

  log('[3/6] Tìm hoặc tạo database D1');
  let list = parseDatabaseList(await checked(['d1', 'list', '--json']));
  let database = list.find((item) => item.name === NAME);
  if (!database) {
    await checked(['d1', 'create', NAME]);
    list = parseDatabaseList(await checked(['d1', 'list', '--json']));
    database = list.find((item) => item.name === NAME);
  }
  if (!database || !/^[a-f0-9-]{36}$/i.test(database.uuid)) throw new Error('Không xác định được ID database aiuth-sync.');
  write(path.join(workspace, 'wrangler.toml'), config(database.uuid));
  await checked(['d1', 'execute', NAME, '--remote', '--file=schema.sql', '--yes'], { stream: true });

  log('[4/6] Đưa Worker lên Cloudflare');
  const deployed = await checked(['deploy'], { stream: true });
  const url = deployed.match(/https:\/\/aiuth-sync\.[A-Za-z0-9.-]+\.workers\.dev\b/)?.[0];
  if (!url) throw new Error('Deploy đã chạy nhưng không đọc được địa chỉ workers.dev. Kiểm tra output Cloudflare.');

  log('[5/6] Lưu mã thiết lập an toàn');
  const setupCode = setupCodeFor(url, workspace, source);
  const infoPath = path.join(workspace, 'setup-info.txt');
  // Giữ mã trước khi gửi để có thể chạy lại nếu mạng bị ngắt.
  write(infoPath, `AIUTH SYNC\nWorker: ${url}\nSetup code: ${setupCode}\n\nGiữ kín mã này: dùng khi đăng ký hoặc đặt lại mật khẩu đồng bộ.\n`);
  await checked(['secret', 'put', 'SETUP_CODE'], { input: setupCode + '\n' });

  log('[6/6] Lưu cấu hình aiuth');
  write(path.join(home, 'aiuth-sync.json'), JSON.stringify({ url }, null, 2) + '\n');
  log(`Đã cài xong: ${url}\nMã thiết lập: ${infoPath}\nChạy aiuth sync để đồng bộ tài khoản.`);
  return { url, workspace, infoPath, databaseId: database.uuid };
}
