#!/usr/bin/env node
/**
 * aiuth — quản lý nhiều tài khoản cho ~/.codex/auth.json (backup / restore theo tài khoản).
 * Zero-dependency, Node >= 18. Có thể đổi thư mục bằng biến môi trường CODEX_HOME.
 *
 * Cấu trúc lưu trữ:
 *   ~/.codex/auth.json                       <- file live mà Codex đọc
 *   ~/.codex/accounts/<tên>/auth.json        <- bản mới nhất của tài khoản
 *   ~/.codex/accounts/<tên>/backups/<ts>.json
 *   ~/.codex/accounts/.unsaved/<ts>.json     <- auth live bị ghi đè mà chưa thuộc tài khoản nào
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import tls from 'node:tls';
import { spawnSync } from 'node:child_process';
import { runSync, normalizeSyncUrl, validSyncName, mergeAccounts, changeSyncPassword, resetSyncPassword } from './aiuth-sync.mjs';
import { setupCloudflare } from './aiuth-setup.mjs';

const HOME = process.env.CODEX_HOME || path.join(os.homedir(), '.codex');
const AUTH = path.join(HOME, 'auth.json');
const STORE = path.join(HOME, 'accounts');
const UNSAVED = path.join(STORE, '.unsaved');
// Claude Code: token ở <CLAUDE_CONFIG_DIR|~/.claude>/.credentials.json, thông tin tài khoản (email, uuid)
// ở key oauthAccount trong .claude.json (cạnh thư mục đó nếu mặc định là ~/.claude.json).
const CLAUDE_DIR = process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude');
const CLAUDE_CRED = path.join(CLAUDE_DIR, '.credentials.json');
const CLAUDE_CFG = process.env.CLAUDE_CONFIG_DIR ? path.join(CLAUDE_DIR, '.claude.json') : path.join(os.homedir(), '.claude.json');
const MAX_BACKUPS = 20;
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._@+-]*$/;

const die = (msg) => {
  console.error(`Lỗi: ${msg}`);
  process.exit(1);
};

const ensureDir = (dir) => fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

/** Ghi nguyên tử (tmp + rename), quyền 0600. */
function writeFile(file, content) {
  ensureDir(path.dirname(file));
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, content, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function readAuth(file) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
  try {
    return { raw, json: JSON.parse(raw) };
  } catch {
    die(`${file} không phải JSON hợp lệ.`);
  }
}

function jwtPayload(token) {
  try {
    const part = String(token).split('.')[1];
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch {
    return {};
  }
}

/** Một tài khoản lưu là của Claude nếu có claudeAiOauth, ngược lại là Codex. */
const providerOf = (json) => (json?.claudeAiOauth ? 'claude' : 'codex');

/** Danh tính của bản lưu Claude: { claudeAiOauth, oauthAccount }. Fingerprint ổn định dù token xoay vòng. */
function claudeIdentity(json) {
  const a = json.oauthAccount ?? {};
  const email = a.emailAddress ?? null;
  const accountId = a.accountUuid ?? null;
  return {
    provider: 'claude',
    email,
    accountId,
    fingerprint: email || accountId ? `claude:${accountId ?? ''}|${email ?? ''}` : null,
    mode: json.claudeAiOauth.subscriptionType ?? 'oauth',
  };
}

/** Trích danh tính (email, account id, fingerprint) từ nội dung auth.json. */
function identity(json) {
  if (providerOf(json) === 'claude') return claudeIdentity(json);
  const t = json?.tokens ?? {};
  const claims = jwtPayload(t.id_token);
  const email = claims.email ?? null;
  const accountId = t.account_id ?? claims['https://api.openai.com/auth']?.chatgpt_account_id ?? null;
  let fingerprint;
  if (email || accountId) {
    fingerprint = `${accountId ?? ''}|${email ?? ''}`;
  } else if (json?.OPENAI_API_KEY) {
    fingerprint = `key:${crypto.createHash('sha256').update(json.OPENAI_API_KEY).digest('hex').slice(0, 16)}`;
  } else {
    fingerprint = null;
  }
  return { provider: 'codex', email, accountId, fingerprint, mode: json?.auth_mode ?? (json?.OPENAI_API_KEY ? 'apikey' : '?') };
}

/* ───────── auth live của từng provider ───────── */

const PROVIDERS = ['codex', 'claude'];

/** Đọc auth live. Codex: nguyên auth.json. Claude: gộp credentials + oauthAccount thành 1 bản lưu. */
function readLive(provider) {
  if (provider === 'codex') return readAuth(AUTH);
  const cred = readAuth(CLAUDE_CRED)?.json;
  if (!cred?.claudeAiOauth) return null;
  const oauthAccount = readAuth(CLAUDE_CFG)?.json?.oauthAccount;
  const json = { claudeAiOauth: cred.claudeAiOauth, ...(oauthAccount ? { oauthAccount } : {}) };
  return { raw: `${JSON.stringify(json, null, 2)}\n`, json };
}

/** Ghi bản lưu thành auth live. Claude: chỉ thay claudeAiOauth và oauthAccount, giữ nguyên các key khác. */
function writeLive(provider, raw) {
  if (provider === 'codex') return writeFile(AUTH, raw);
  const saved = JSON.parse(raw);
  const cred = readAuth(CLAUDE_CRED)?.json ?? {};
  cred.claudeAiOauth = saved.claudeAiOauth;
  const cfg = readAuth(CLAUDE_CFG)?.json ?? {};
  if (saved.oauthAccount) cfg.oauthAccount = saved.oauthAccount;
  else delete cfg.oauthAccount;
  writeFile(CLAUDE_CRED, `${JSON.stringify(cred, null, 2)}\n`);
  writeFile(CLAUDE_CFG, `${JSON.stringify(cfg, null, 2)}\n`);
}

/** Tên mặc định cho tài khoản mới: email; nếu đã bị tài khoản khác (provider kia) chiếm thì thêm hậu tố provider. */
function defaultName(id, taken = new Set(listAccounts())) {
  const base = id.email;
  if (!base) return null;
  return taken.has(base) ? `${base}-${id.provider}` : base;
}

const checkName = (name) => {
  if (!name) die('Thiếu tên tài khoản.');
  if (!NAME_RE.test(name)) die(`Tên "${name}" không hợp lệ (chỉ dùng chữ, số, . _ @ + -).`);
  return name;
};

/** Nhận tên tài khoản hoặc số thứ tự (theo `aiuth list`). Tên khớp chính xác được ưu tiên. */
function resolveName(arg) {
  if (!arg) die('Thiếu tên hoặc số thứ tự tài khoản.');
  const names = listAccounts();
  if (names.includes(arg)) return arg;
  if (/^\d+$/.test(arg)) {
    const i = Number(arg);
    if (i >= 1 && i <= names.length) return names[i - 1];
    die(`Không có tài khoản số ${arg} (hiện có ${names.length}). Xem: aiuth list`);
  }
  return checkName(arg);
}

const accountDir = (name) => path.join(STORE, name);
const accountAuth = (name) => path.join(accountDir(name), 'auth.json');
const stamp = () => new Date().toISOString().replace(/[:.]/g, '-');

function listAccounts() {
  if (!fs.existsSync(STORE)) return [];
  return fs
    .readdirSync(STORE, { withFileTypes: true })
    .filter((d) => d.isDirectory() && NAME_RE.test(d.name) && fs.existsSync(accountAuth(d.name)))
    .map((d) => d.name)
    .sort();
}

function listBackups(name) {
  const dir = path.join(accountDir(name), 'backups');
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.slice(0, -5))
    .sort();
}

function pruneBackups(name) {
  const ids = listBackups(name);
  for (const id of ids.slice(0, Math.max(0, ids.length - MAX_BACKUPS))) {
    fs.rmSync(path.join(accountDir(name), 'backups', `${id}.json`), { force: true });
  }
}

function snapshot(name, raw) {
  const id = stamp();
  writeFile(path.join(accountDir(name), 'backups', `${id}.json`), raw);
  pruneBackups(name);
  return id;
}

/** Tìm tài khoản đã lưu khớp với auth live. */
function findAccountFor(fingerprint) {
  if (!fingerprint) return null;
  return (
    listAccounts().find((n) => {
      const a = readAuth(accountAuth(n));
      return a && identity(a.json).fingerprint === fingerprint;
    }) ?? null
  );
}

/** Trước khi ghi đè auth live: đồng bộ vào tài khoản của nó + backup, hoặc cất vào .unsaved. */
function preserveLive(provider) {
  const live = readLive(provider);
  if (!live) return null;
  const owner = findAccountFor(identity(live.json).fingerprint);
  if (owner) {
    writeFile(accountAuth(owner), live.raw); // token có thể đã refresh -> cập nhật bản lưu
    snapshot(owner, live.raw);
    return `tài khoản "${owner}"`;
  }
  writeFile(path.join(UNSAVED, `${provider}-${stamp()}.json`), live.raw);
  return `${path.relative(HOME, UNSAVED)}/`;
}

/* ───────────────────────────── commands ───────────────────────────── */

/* ───────── dừng Codex đang chạy (giữ token cũ trong RAM, có thể ghi đè auth.json) ───────── */

const CODEX_CMD_RE = /(^|[\s/])codex(-[\w.-]+)?(\s|$)|@openai\/codex/;

/** Tổ tiên của tiến trình hiện tại (để không tự giết shell/terminal đang chạy aiuth). */
function ancestorsOf(table, pid) {
  const out = new Set();
  for (let p = pid; p && table.has(p) && !out.has(p); p = table.get(p).ppid) out.add(p);
  return out;
}

/**
 * Dừng mọi tiến trình codex và cây con của chúng (MCP server do codex mở).
 * Không dùng `pkill -f mcp`: nó khớp cả MCP server của Claude/IDE và các app khác.
 */
async function stopCodex(flags = {}) {
  if (flags['no-kill']) return;
  if (process.platform === 'win32') return console.log('Windows: hãy tự tắt Codex trước khi chuyển tài khoản.');
  const ps = spawnSync('ps', ['-axo', 'pid=,ppid=,command='], { encoding: 'utf8' });
  if (ps.status !== 0) return console.log('Không đọc được danh sách tiến trình, bỏ qua bước dừng Codex.');
  const table = new Map();
  for (const line of ps.stdout.split('\n')) {
    const m = /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(line);
    if (m) table.set(Number(m[1]), { ppid: Number(m[2]), cmd: m[3] });
  }
  const skip = ancestorsOf(table, process.pid);
  const roots = [...table].filter(([pid, v]) => !skip.has(pid) && CODEX_CMD_RE.test(v.cmd)).map(([pid]) => pid);
  const doomed = new Set(roots);
  for (let grew = true; grew; ) {
    grew = false;
    for (const [pid, v] of table) {
      if (!doomed.has(pid) && !skip.has(pid) && doomed.has(v.ppid)) (doomed.add(pid), (grew = true));
    }
  }
  if (!doomed.size) return;
  const send = (sig) => doomed.forEach((pid) => { try { process.kill(pid, sig); } catch {} });
  send('SIGTERM');
  await new Promise((r) => setTimeout(r, 800));
  const alive = [...doomed].filter((pid) => { try { return process.kill(pid, 0); } catch { return false; } });
  alive.forEach((pid) => { try { process.kill(pid, 'SIGKILL'); } catch {} });
  console.log(`Đã dừng ${doomed.size} tiến trình Codex/MCP con (${roots.length} codex)${alive.length ? `, ép tắt ${alive.length}` : ''}.`);
}

/** Lưu auth live của một provider (đã biết là có đăng nhập). Trả về true nếu đã lưu. */
function saveProvider(provider, nameArg) {
  const live = readLive(provider);
  const id = identity(live.json);
  if (!id.fingerprint && provider === 'claude') {
    console.log(`Bỏ qua Claude: không đọc được tài khoản từ ${CLAUDE_CFG} (thiếu oauthAccount).`);
    return false;
  }
  // Không truyền tên: ưu tiên tài khoản đã lưu của chính danh tính này, rồi mới tới email.
  const name = checkName(nameArg ?? findAccountFor(id.fingerprint) ?? defaultName(id) ?? null);
  const existed = fs.existsSync(accountAuth(name));
  if (existed && identity(readAuth(accountAuth(name)).json).provider !== provider) {
    die(`Tên "${name}" đang là tài khoản ${identity(readAuth(accountAuth(name)).json).provider}. Chọn tên khác: save <tên>`);
  }
  writeFile(accountAuth(name), live.raw);
  snapshot(name, live.raw);
  console.log(`${existed ? 'Cập nhật' : 'Đã lưu'} tài khoản ${provider} "${name}"${id.email ? ` (${id.email})` : ''}`);
  return true;
}

/**
 * save [tên]: lưu cả Codex và Claude đang đăng nhập. Có tên mà cả hai cùng có: Codex lấy "tên",
 * Claude lấy "tên-claude".
 */
function cmdSave([nameArg]) {
  const present = PROVIDERS.filter((p) => readLive(p));
  if (!present.length) die('Chưa đăng nhập Codex lẫn Claude. Hãy chạy "codex login" hoặc "claude" (/login) trước.');
  for (const p of present) {
    const name = nameArg && present.length > 1 && p === 'claude' ? `${nameArg}-claude` : nameArg;
    saveProvider(p, name);
  }
}

async function cmdList(args = []) {
  const { flags } = parseArgs(args);
  const names = listAccounts();
  if (!names.length) return console.log('Chưa có tài khoản nào. Dùng: aiuth save [tên]');
  const lives = Object.fromEntries(PROVIDERS.map((p) => [p, readLive(p)]));
  const rows = names.map((n) => {
    const saved = readAuth(accountAuth(n));
    const id = identity(saved.json);
    const live = lives[id.provider];
    const active = !!live && !!id.fingerprint && identity(live.json).fingerprint === id.fingerprint;
    return { n, id, active, raw: active ? live.raw : saved.raw };
  });
  // --usage: gọi song song, mỗi tài khoản một dòng tóm tắt limit.
  const limits = flags.usage ? await Promise.all(rows.map((r) => fetchUsage(r.raw))) : [];
  const summary = (u) => {
    if (u.error) return paint(31, `${u.error.split(' — ')[0]}`);
    const ws = windowsOf(u.data);
    const txt = ws
      .map((w) => `${w.label.trim()} ${colorLeft(leftOf(w.used), `còn ${leftOf(w.used)}%`)} (reset ${fmtDur(w.resetIn)})`)
      .join(' · ');
    return `${u.data.rate_limit?.limit_reached ? 'CHẠM LIMIT ' : ''}${txt || '-'}`;
  };
  console.log(`  ${'#'.padStart(2)} ${'PROVIDER'.padEnd(8)} ${'TÊN'.padEnd(32)} ${'EMAIL'.padEnd(32)} ${'MODE'.padEnd(9)} ${'BACKUPS'.padEnd(7)}${flags.usage ? ' LIMIT' : ''}`);
  rows.forEach((r, i) => {
    console.log(
      `${r.active ? '*' : ' '} ${String(i + 1).padStart(2)} ${r.id.provider.padEnd(8)} ${r.n.padEnd(32)} ${(r.id.email ?? '-').padEnd(32)} ${r.id.mode.padEnd(9)} ${String(listBackups(r.n).length).padEnd(7)}${flags.usage ? ` ${summary(limits[i])}` : ''}`,
    );
  });
  console.log(`\n* = đang dùng (khớp auth live của provider đó)${flags.usage ? '' : '   |   thêm --usage để xem limit   |   dùng: aiuth use <số hoặc tên>'}`);
}

async function cmdUse(args) {
  const { pos, flags } = parseArgs(args);
  const name = resolveName(pos[0]);
  const target = readAuth(accountAuth(name));
  if (!target) die(`Không có tài khoản "${name}". Xem: aiuth list`);
  const id = identity(target.json);
  if (id.provider === 'codex') await stopCodex(flags);
  const kept = preserveLive(id.provider);
  writeLive(id.provider, target.raw);
  if (kept) console.log(`Đã giữ auth ${id.provider} hiện tại vào ${kept}`);
  console.log(`Đang dùng ${id.provider} "${name}"${id.email ? ` (${id.email})` : ''}`);
  if (id.provider === 'claude') console.log('Hãy khởi động lại Claude Code (bản đang mở giữ token cũ trong bộ nhớ).');
}

/* ───────── helper dùng chung cho send / receive ───────── */

/** Tách cờ (--no-encrypt, --use, --name x) khỏi tham số vị trí. */
function parseArgs(args) {
  const pos = [];
  const flags = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--name' || a === '--port' || a === '--to' || a === '--wait' || a === '--url') flags[a.slice(2)] = args[++i];
    else if (a.startsWith('--')) flags[a.slice(2)] = true;
    else pos.push(a);
  }
  return { pos, flags };
}

function encrypt(plain, pass) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(pass, salt, 32);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return Buffer.concat([salt, iv, c.getAuthTag(), data]);
}

function decrypt(buf, pass) {
  try {
    const salt = buf.subarray(0, 16);
    const iv = buf.subarray(16, 28);
    const tag = buf.subarray(28, 44);
    const key = crypto.scryptSync(pass, salt, 32);
    const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(buf.subarray(44)), d.final()]).toString('utf8');
  } catch {
    die('Sai passphrase hoặc chuỗi bị hỏng/cắt cụt.');
  }
}

/** Lấy nội dung auth của tài khoản: 'main' (mặc định, ưu tiên live nếu cùng tài khoản) hoặc một backup. */
function pickRaw(name, idArg = 'main') {
  if (idArg === 'main') {
    const saved = readAuth(accountAuth(name));
    const live = readLive(providerOf(saved.json));
    return live && identity(live.json).fingerprint === identity(saved.json).fingerprint ? live.raw : saved.raw;
  }
  const ids = listBackups(name);
  const id = idArg === 'latest' ? ids.at(-1) : ids.find((x) => x === idArg || x.startsWith(idArg));
  if (!id) die(`Không tìm thấy backup "${idArg}" của "${name}".`);
  return readAuth(path.join(accountDir(name), 'backups', `${id}.json`)).raw;
}

/** Kiểm tra payload giải mã được, lưu thành tài khoản (backup bản cũ nếu ghi đè). */
async function saveImported(plain, flags) {
  let payload;
  try {
    payload = JSON.parse(plain);
    JSON.parse(payload.auth);
  } catch {
    die('Dữ liệu giải mã không phải auth.json hợp lệ.');
  }
  const id = identity(JSON.parse(payload.auth));
  if (!id.fingerprint) die('auth.json trong chuỗi không có token hay API key.');
  const name = checkName(flags.name ?? payload.name);
  const old = readAuth(accountAuth(name));
  if (old) snapshot(name, old.raw); // giữ bản cũ trước khi ghi đè
  writeFile(accountAuth(name), payload.auth);
  snapshot(name, payload.auth);
  console.log(`Đã nhận tài khoản "${name}"${id.email ? ` (${id.email})` : ''}${old ? ' (ghi đè bản cũ, đã backup)' : ''}`);
  if (flags.use) await cmdUse([name, ...(flags['no-kill'] ? ['--no-kill'] : [])]);
  else console.log(`  Dùng ngay: aiuth use ${name}`);
}

/* ───────── send / receive: chuyển trực tiếp qua LAN, 1 lần, không qua bên thứ ba ───────── */

const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // bỏ I O 0 1 cho dễ đọc
const SEND_TTL_MS = 5 * 60 * 1000;
const MAX_BAD_PROOFS = 3;

const newCode = (len = 8) =>
  Array.from({ length: len }, () => CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)])
    .join('')
    .match(/.{1,4}/g)
    .join('-');
const normCode = (c) => String(c).toUpperCase().replace(/[^A-Z0-9]/g, '');
const proofOf = (code, salt) =>
  crypto.createHmac('sha256', crypto.scryptSync(normCode(code), salt, 32)).update('aiuth-proof').digest('hex');

const lanAddresses = () =>
  Object.values(os.networkInterfaces())
    .flat()
    .filter((i) => i && i.family === 'IPv4' && !i.internal)
    .map((i) => i.address);

/**
 * send <tên> [id] [--port N]: mở server HTTP tạm, phục vụ đúng 1 lần.
 * Máy nhận phải chứng minh biết mã (HMAC) mới nhận được blob; sai quá 3 lần thì đóng.
 * Blob được mã hoá bằng chính mã đó; mã không bao giờ đi qua mạng.
 */
async function cmdSend(args) {
  const { pos, flags } = parseArgs(args);
  const name = resolveName(pos[0]);
  if (!fs.existsSync(accountAuth(name))) die(`Không có tài khoản "${name}".`);
  if (flags.mail) return sendViaMail(name, pos[1], flags);
  const code = newCode();
  const payload = JSON.stringify({ v: 1, name, exportedAt: new Date().toISOString(), auth: pickRaw(name, pos[1]) });
  const blob = encrypt(payload, normCode(code)).toString('base64url');
  const salt = crypto.randomBytes(16);
  const expected = Buffer.from(proofOf(code, salt));
  let bad = 0;

  const server = http.createServer((req, res) => {
    const reply = (status, obj) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(obj));
    };
    if (req.method === 'GET' && req.url === '/hello') return reply(200, { salt: salt.toString('base64url') });
    if (req.method === 'POST' && req.url === '/fetch') {
      let body = '';
      req.on('data', (c) => {
        body += c;
        if (body.length > 1024) req.destroy();
      });
      req.on('end', () => {
        let given = '';
        try {
          given = String(JSON.parse(body).proof ?? '');
        } catch {}
        const got = Buffer.from(given);
        if (got.length === expected.length && crypto.timingSafeEqual(got, expected)) {
          reply(200, { blob });
          console.log('Máy kia đã nhận xong. Đóng server.');
          setTimeout(() => server.close(() => process.exit(0)), 100);
        } else {
          reply(403, { error: 'sai mã' });
          if (++bad >= MAX_BAD_PROOFS) {
            console.error(`Sai mã ${MAX_BAD_PROOFS} lần, đóng server.`);
            setTimeout(() => server.close(() => process.exit(1)), 100);
          }
        }
      });
      return;
    }
    reply(404, { error: 'not found' });
  });

  server.listen(Number(flags.port) || 0, '0.0.0.0', () => {
    const { port } = server.address();
    const ips = lanAddresses();
    const isTailscale = (ip) => {
      const [a, b] = ip.split('.').map(Number);
      return a === 100 && b >= 64 && b <= 127; // CGNAT 100.64.0.0/10 mà Tailscale dùng
    };
    const lan = ips.filter((i) => !isTailscale(i));
    const ts = ips.filter(isTailscale);
    console.log(`Đang chờ máy nhận (tối đa ${SEND_TTL_MS / 60000} phút, phục vụ đúng 1 lần).\n`);
    console.log('Chạy 1 trong các lệnh sau trên máy kia:\n');
    for (const ip of lan) console.log(`  LAN        aiuth receive ${ip}:${port} ${code}`);
    for (const ip of ts) console.log(`  Tailscale  aiuth receive ${ip}:${port} ${code}`);
    if (!ts.length) console.log('  (không thấy IP Tailscale — nếu cần, bật Tailscale rồi chạy lại)');
    if (!ips.length) console.log(`  aiuth receive <ip-máy-này>:${port} ${code}`);
    console.log('\nCtrl+C để huỷ.');
  });
  setTimeout(() => {
    console.error('Hết thời gian chờ, đóng server.');
    process.exit(1);
  }, SEND_TTL_MS).unref();
  await new Promise(() => {}); // giữ tiến trình sống; thoát qua process.exit ở trên
}

/** receive <host:port> <mã> [--name x] [--use] */
async function cmdReceive(args) {
  const { pos, flags } = parseArgs(args);
  if (flags.mail) return receiveViaMail(pos[0], flags);
  const [addr, codeArg] = pos;
  if (!addr || !codeArg) die('Dùng: aiuth receive <host:port> <mã>   (ví dụ: aiuth receive 192.168.1.5:7421 K7P4-QX9M)');
  if (!/^[A-Za-z0-9.-]+:\d{1,5}$/.test(addr)) die(`Địa chỉ "${addr}" không hợp lệ, cần dạng host:port.`);
  const base = `http://${addr}`;
  const call = async (url, init) => {
    try {
      const r = await fetch(url, { ...init, signal: AbortSignal.timeout(10_000) });
      return { status: r.status, body: await r.json().catch(() => ({})) };
    } catch (e) {
      die(`Không kết nối được tới ${addr} (${e.cause?.code ?? e.message}). Cùng mạng chưa? Firewall có chặn không?`);
    }
  };
  const hello = await call(`${base}/hello`);
  if (!hello.body.salt) die('Máy kia không phải aiuth send.');
  const proof = proofOf(codeArg, Buffer.from(hello.body.salt, 'base64url'));
  const res = await call(`${base}/fetch`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ proof }),
  });
  if (res.status === 403) die('Sai mã.');
  if (!res.body.blob) die('Không nhận được dữ liệu (máy gửi có thể đã đóng).');
  const plain = decrypt(Buffer.from(res.body.blob, 'base64url'), normCode(codeArg));
  await saveImported(plain, flags);
}

/* ───────── usage: thống kê limit theo từng tài khoản ───────── */

const USAGE_URL = 'https://chatgpt.com/backend-api/wham/usage';

const fmtDur = (sec) => {
  if (sec == null) return '-';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
};
const fmtWindow = (sec) => (sec % 86400 === 0 ? `${sec / 86400}d` : sec % 3600 === 0 ? `${sec / 3600}h` : `${Math.round(sec / 60)}m`);
// Màu ANSI: chỉ khi in ra terminal và không đặt NO_COLOR.
const useColor = () => process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code, text) => (useColor() ? `\x1b[${code}m${text}\x1b[0m` : text);
/** % còn lại: < 10 đỏ, > 50 xanh, còn lại vàng. */
const colorLeft = (left, text) => paint(left < 10 ? 31 : left > 50 ? 32 : 33, text);
const leftOf = (used) => Math.max(0, Math.min(100, 100 - used));

/** Gọi endpoint usage của Codex bằng token đã lưu. Không refresh token (tránh xoay vòng làm hỏng máy khác). */
async function fetchUsage(raw) {
  const json = JSON.parse(raw);
  if (providerOf(json) === 'claude') return { error: 'Claude: chưa hỗ trợ thống kê limit' };
  const t = json.tokens;
  if (!t?.access_token) return { error: 'tài khoản API key: không có thống kê limit' };
  const headers = { Authorization: `Bearer ${t.access_token}`, 'User-Agent': 'aiuth' };
  if (t.account_id) headers['ChatGPT-Account-Id'] = t.account_id;
  try {
    const r = await fetch(USAGE_URL, { headers, signal: AbortSignal.timeout(15_000) });
    if (r.status === 401 || r.status === 403) {
      return { error: 'token hết hạn — dùng tài khoản này bằng codex một lần để làm mới, rồi chạy lại' };
    }
    if (!r.ok) return { error: `HTTP ${r.status}` };
    return { data: await r.json() };
  } catch (e) {
    return { error: `không kết nối được (${e.cause?.code ?? e.message})` };
  }
}

/** Gom các cửa sổ limit (primary/secondary/code review/additional) thành danh sách phẳng. */
function windowsOf(d) {
  const out = [];
  const add = (label, rl) => {
    for (const key of ['primary_window', 'secondary_window']) {
      const w = rl?.[key];
      if (w) out.push({ label: `${label}${fmtWindow(w.limit_window_seconds)}`, used: w.used_percent, resetIn: w.reset_after_seconds, resetAt: w.reset_at });
    }
  };
  add('', d.rate_limit);
  add('review ', d.code_review_rate_limit);
  const extra = d.additional_rate_limits;
  if (Array.isArray(extra)) extra.forEach((e, i) => add(`${e.limit_name ?? e.name ?? `extra${i + 1}`} `, e.rate_limit ?? e));
  return out;
}

/** usage [tên] [--json]: limit hiện tại của từng tài khoản đã lưu (không cần switch). */
/* ───────── mail: chuyển tài khoản qua hộp thư (SMTP gửi, IMAP nhận), mã hoá đầu-cuối ───────── */

const MAIL_CFG = path.join(HOME, 'aiuth-mail.json');
const GMAIL_APP_PASSWORD_URL = 'https://myaccount.google.com/apppasswords';
const MAIL_CODE_LEN = 12; // dài hơn LAN vì blob nằm lâu trong hộp thư
const MAIL_MAX_AGE_MS = 24 * 3600 * 1000;
const MAIL_PRESETS = {
  'gmail.com': { smtp: 'smtp.gmail.com:465', imap: 'imap.gmail.com:993' },
  'googlemail.com': { smtp: 'smtp.gmail.com:465', imap: 'imap.gmail.com:993' },
  'yahoo.com': { smtp: 'smtp.mail.yahoo.com:465', imap: 'imap.mail.yahoo.com:993' },
  'zoho.com': { smtp: 'smtp.zoho.com:465', imap: 'imap.zoho.com:993' },
};

/** Hỏi một dòng; hidden=true thì không hiện ký tự. */
function ask(question, hidden = false, trim = true) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    if (hidden) rl._writeToOutput = (t) => { if (t.includes(question)) process.stderr.write(t); };
    rl.question(question, (ans) => {
      rl.close();
      if (hidden) process.stderr.write('\n');
      resolve(trim ? ans.trim() : ans);
    });
  });
}

/** Cấu hình mail: biến môi trường ưu tiên, sau đó file aiuth-mail.json (0600). */
function mailConfig() {
  let f = {};
  try {
    f = JSON.parse(fs.readFileSync(MAIL_CFG, 'utf8'));
  } catch {}
  const user = process.env.AIUTH_MAIL_USER ?? f.user;
  const pass = process.env.AIUTH_MAIL_PASS ?? f.pass;
  const preset = MAIL_PRESETS[String(user ?? '').split('@')[1]] ?? {};
  const smtp = process.env.AIUTH_SMTP ?? f.smtp ?? preset.smtp;
  const imap = process.env.AIUTH_IMAP ?? f.imap ?? preset.imap;
  if (!user || !pass || !smtp || !imap) die(`Chưa cấu hình mail. Chạy: aiuth mail setup (Gmail: tạo app password tại ${GMAIL_APP_PASSWORD_URL})`);
  return { user, pass, smtp, imap };
}

/** Bộ đọc socket: until(test) gom dữ liệu tới khi test đúng, rồi xả buffer. */
function reader(sock) {
  let buf = '';
  let wake = null;
  let err = null;
  sock.setEncoding('utf8');
  sock.on('data', (d) => { buf += d; wake?.(); });
  sock.on('error', (e) => { err = e; wake?.(); });
  sock.on('close', () => { err ??= new Error('kết nối bị đóng'); wake?.(); });
  return {
    async until(test) {
      for (;;) {
        if (test(buf)) { const out = buf; buf = ''; return out; }
        if (err) throw err;
        await new Promise((r) => { wake = r; });
      }
    },
  };
}

function tlsConnect(hostPort) {
  const [host, port] = hostPort.split(':');
  return new Promise((resolve, reject) => {
    const s = tls.connect({ host, port: Number(port), servername: host }, () => resolve(s));
    s.setTimeout(30_000, () => s.destroy(new Error('hết thời gian chờ')));
    s.once('error', reject);
  });
}

async function smtpSend(cfg, to, subject, body) {
  const s = await tlsConnect(cfg.smtp);
  const rd = reader(s);
  const lastLine = (b) => /(^|\r\n)\d{3} [^\r\n]*\r\n$/.test(b);
  const expect = async (okRe, what) => {
    const r = await rd.until(lastLine);
    if (!okRe.test(r)) throw new Error(`SMTP ${what}: ${r.trim().split('\r\n').pop()}`);
  };
  try {
    await expect(/^220/, 'chào');
    s.write('EHLO aiuth\r\n'); await expect(/^250/, 'EHLO');
    s.write(`AUTH PLAIN ${Buffer.from(`\0${cfg.user}\0${cfg.pass}`).toString('base64')}\r\n`); await expect(/^235/, 'đăng nhập');
    s.write(`MAIL FROM:<${cfg.user}>\r\n`); await expect(/^250/, 'MAIL FROM');
    s.write(`RCPT TO:<${to}>\r\n`); await expect(/^25[01]/, 'RCPT TO');
    s.write('DATA\r\n'); await expect(/^354/, 'DATA');
    const msg = [
      `From: ${cfg.user}`, `To: ${to}`, `Subject: ${subject}`, `Date: ${new Date().toUTCString()}`,
      `Message-ID: <${crypto.randomUUID()}@aiuth>`, 'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=us-ascii', 'Content-Transfer-Encoding: 7bit', '', body,
    ].join('\r\n');
    s.write(`${msg.replace(/^\./gm, '..')}\r\n.\r\n`); await expect(/^250/, 'gửi thư');
    s.write('QUIT\r\n');
  } finally {
    s.end();
  }
}

/** Tìm thư theo subject, lấy phần thân, đánh dấu xoá. Trả về chuỗi blob hoặc null. */
async function imapTake(cfg, subject) {
  const s = await tlsConnect(cfg.imap);
  const rd = reader(s);
  let n = 0;
  const run = async (cmd) => {
    const tag = `a${++n}`;
    s.write(`${tag} ${cmd}\r\n`);
    const out = await rd.until((b) => new RegExp(`(^|\\r\\n)${tag} (OK|NO|BAD)[^\\r\\n]*\\r\\n$`).test(b));
    if (!new RegExp(`(^|\\r\\n)${tag} OK`).test(out)) throw new Error(`IMAP ${cmd.split(' ')[0]}: ${out.trim().split('\r\n').pop()}`);
    return out;
  };
  const q = (v) => `"${String(v).replace(/(["\\])/g, '\\$1')}"`;
  try {
    await rd.until((b) => /\r\n$/.test(b)); // lời chào
    await run(`LOGIN ${q(cfg.user)} ${q(cfg.pass)}`);
    await run('SELECT INBOX');
    const found = /\* SEARCH([\d ]*)\r\n/.exec(await run(`SEARCH SUBJECT ${q(subject)}`));
    const ids = (found?.[1] ?? '').trim().split(/\s+/).filter(Boolean);
    if (!ids.length) return null;
    const id = ids.at(-1);
    const body = await run(`FETCH ${id} BODY.PEEK[TEXT]`);
    const m = /-----BEGIN AIUTH-----([\s\S]*?)-----END AIUTH-----/.exec(body);
    if (!m) throw new Error('Thư tìm thấy nhưng không có dữ liệu aiuth.');
    await run(`STORE ${ids.join(',')} +FLAGS (\\Deleted)`);
    await run('EXPUNGE');
    return m[1].replace(/\s+/g, '');
  } finally {
    s.write(`a${++n} LOGOUT\r\n`);
    s.end();
  }
}

const mailId = (code) => crypto.scryptSync(normCode(code), 'aiuth-mail-id-v1', 12).toString('hex');

/** send <tên> --mail [--to địa-chỉ]: gửi blob mã hoá vào hộp thư, in mã để nhập ở máy kia. */
async function sendViaMail(name, idArg, flags) {
  const cfg = mailConfig();
  const to = flags.to ?? cfg.user;
  const code = newCode(MAIL_CODE_LEN);
  const payload = JSON.stringify({ v: 1, name, exportedAt: new Date().toISOString(), auth: pickRaw(name, idArg) });
  const blob = encrypt(payload, normCode(code)).toString('base64url');
  const wrapped = blob.match(/.{1,72}/g).join('\r\n');
  const body = `Thu tu dong tu aiuth. Khong tra loi. Du lieu da ma hoa, can ma de mo.\r\n\r\n-----BEGIN AIUTH-----\r\n${wrapped}\r\n-----END AIUTH-----`;
  try {
    await smtpSend(cfg, to, `aiuth:${mailId(code)}`, body);
  } catch (e) {
    die(`Gửi mail thất bại. ${e.message}`);
  }
  console.log(`Đã gửi tới ${to}.\n`);
  console.log('Trên máy kia chạy:');
  console.log(`  aiuth receive --mail ${code}\n`);
  console.log('Mã này chỉ hiện một lần và không nằm trong thư. Thư sẽ bị xoá khỏi INBOX sau khi nhận.');
}

/** receive --mail <mã> [--wait giây] [--name x] [--use]: lấy thư, giải mã, lưu tài khoản. */
async function receiveViaMail(codeArg, flags) {
  if (!codeArg) die('Dùng: aiuth receive --mail <mã>');
  const cfg = mailConfig();
  const subject = `aiuth:${mailId(codeArg)}`;
  const deadline = Date.now() + (Number(flags.wait ?? 60) || 60) * 1000;
  let blob = null;
  for (;;) {
    try {
      blob = await imapTake(cfg, subject);
    } catch (e) {
      die(`Đọc mail thất bại. ${e.message}`);
    }
    if (blob || Date.now() >= deadline) break;
    console.log('Chưa thấy thư, thử lại sau 5 giây...');
    await new Promise((r) => setTimeout(r, 5000));
  }
  if (!blob) die('Không thấy thư. Kiểm tra mã, hoặc tăng --wait <giây>.');
  const plain = decrypt(Buffer.from(blob, 'base64url'), normCode(codeArg));
  const age = Date.now() - Date.parse(JSON.parse(plain).exportedAt);
  if (age > MAIL_MAX_AGE_MS) die('Thư đã quá 24 giờ, từ chối nhận. Hãy gửi lại.');
  await saveImported(plain, flags);
}

/** mail setup: lưu tài khoản mail (mật khẩu ứng dụng) vào aiuth-mail.json, quyền 0600. */
async function cmdMail([sub]) {
  if (sub !== 'setup') die('Dùng: aiuth mail setup');
  if (!process.stdin.isTTY) die('Cần chạy trong terminal tương tác, hoặc đặt AIUTH_MAIL_USER / AIUTH_MAIL_PASS.');
  console.error('Dùng Gmail? Tạo mật khẩu ứng dụng (cần bật xác minh 2 bước) tại:');
  console.error(`  ${GMAIL_APP_PASSWORD_URL}\n`);
  const user = await ask('Địa chỉ email: ');
  const domain = user.split('@')[1];
  const preset = MAIL_PRESETS[domain] ?? {};
  const smtp = (await ask(`SMTP host:port [${preset.smtp ?? 'bắt buộc'}]: `)) || preset.smtp;
  const imap = (await ask(`IMAP host:port [${preset.imap ?? 'bắt buộc'}]: `)) || preset.imap;
  const pass = await ask('Mật khẩu ứng dụng (app password, không phải mật khẩu chính): ', true);
  if (!user || !smtp || !imap || !pass) die('Thiếu thông tin.');
  const cfg = { user, pass, smtp, imap };
  try {
    const s = await tlsConnect(imap);
    s.destroy();
    await imapTake(cfg, 'aiuth:selftest'); // thử đăng nhập IMAP
  } catch (e) {
    die(`Không đăng nhập được: ${e.message || e.code || e.errors?.[0]?.code || "lỗi kết nối"}. Chưa lưu cấu hình.${domain === 'gmail.com' || domain === 'googlemail.com' ? ` Kiểm tra app password: ${GMAIL_APP_PASSWORD_URL}` : ''}`);
  }
  writeFile(MAIL_CFG, `${JSON.stringify(cfg, null, 2)}\n`);
  console.log(`Đã lưu ${MAIL_CFG} (quyền 0600, mật khẩu ứng dụng lưu dạng rõ giống auth.json).`);
}

async function cmdUsage(args) {
  const { pos, flags } = parseArgs(args);
  const names = pos[0] ? [resolveName(pos[0])] : listAccounts();
  if (!names.length) return console.log('Chưa có tài khoản nào. Dùng: aiuth save [tên]');
  for (const n of names) if (!fs.existsSync(accountAuth(n))) die(`Không có tài khoản "${n}".`);
  const all = listAccounts();
  const results = await Promise.all(
    names.map(async (n) => {
      const saved = readAuth(accountAuth(n));
      // Auth live của cùng tài khoản thường mới hơn bản đã lưu (Codex tự refresh token).
      const live = readLive(providerOf(saved.json));
      const useLive = live && identity(saved.json).fingerprint === identity(live.json).fingerprint;
      const res = await fetchUsage(useLive ? live.raw : saved.raw);
      return { name: n, active: useLive, email: identity(saved.json).email, ...res };
    }),
  );

  if (flags.json) {
    console.log(JSON.stringify(results.map((r) => ({ name: r.name, active: r.active, email: r.email, usage: r.data ?? null, error: r.error ?? null })), null, 2));
    return;
  }

  for (const r of results) {
    const head = `${r.active ? '*' : ' '} ${String(all.indexOf(r.name) + 1).padStart(2)}. ${r.name}${r.email && r.email !== r.name ? `  (${r.email})` : ''}`;
    if (r.error) {
      console.log(`${head}\n    ${r.error}\n`);
      continue;
    }
    const d = r.data;
    const status = d.rate_limit?.limit_reached ? '  ĐÃ CHẠM LIMIT' : '';
    console.log(`${head}  [${d.plan_type ?? '?'}]${status}`);
    const ws = windowsOf(d);
    if (!ws.length) console.log('    (không có thông tin cửa sổ limit)');
    for (const w of ws) {
      const left = leftOf(w.used);
      console.log(`    ${w.label.padEnd(10)} ${colorLeft(left, `còn ${String(left).padStart(3)}%`)} · reset sau ${fmtDur(w.resetIn)}`);
    }
    if (d.credits?.has_credits) console.log(`    credits    ${d.credits.unlimited ? 'không giới hạn' : d.credits.balance}`);
    if (d.rate_limit_reached_type) console.log(`    chạm limit loại: ${d.rate_limit_reached_type}`);
    console.log('');
  }
  console.log('* = đang dùng. Số liệu lấy trực tiếp từ OpenAI bằng token đã lưu của từng tài khoản.');
}

/**
 * Thêm tài khoản mới KHÔNG logout (logout thu hồi token cũ phía server).
 * Giữ auth cũ -> gỡ file auth.json (Codex coi như chưa đăng nhập) -> `codex login --device-auth`
 * -> lưu tài khoản mới. Nếu login thất bại/huỷ thì khôi phục auth cũ.
 */
async function cmdAdd(args) { // chỉ Codex; Claude: chạy "claude" rồi /login, sau đó "aiuth save"
  const { pos, flags } = parseArgs(args);
  const nameArg = pos[0];
  if (nameArg) checkName(nameArg);
  await stopCodex(flags);
  const old = readAuth(AUTH);
  if (old) {
    const oldId = identity(old.json);
    const owner = findAccountFor(oldId.fingerprint);
    if (owner) {
      writeFile(accountAuth(owner), old.raw);
      snapshot(owner, old.raw);
    } else {
      const keep = oldId.email;
      if (!keep) die('Auth hiện tại chưa được lưu và không có email. Chạy "save <tên>" trước đã.');
      writeFile(accountAuth(keep), old.raw);
      snapshot(keep, old.raw);
      console.log(`Đã lưu auth hiện tại thành "${keep}"`);
    }
    fs.rmSync(AUTH); // chỉ xoá file cục bộ, không gọi logout
    console.log('Đã gỡ auth.json cục bộ (không logout, token cũ vẫn sống).');
  }

  const r = spawnSync('codex', ['login', '--device-auth'], { stdio: 'inherit' });
  const fresh = readAuth(AUTH);
  const fail = (msg) => {
    if (old) writeFile(AUTH, old.raw);
    die(`${msg}${old ? ' Đã khôi phục auth cũ.' : ''}`);
  };
  if (r.error) fail(`Không chạy được codex: ${r.error.message}.`);
  if (r.status !== 0 || !fresh) fail('Đăng nhập không thành công.');

  const id = identity(fresh.json);
  if (old && id.fingerprint === identity(old.json).fingerprint) {
    fail('Bạn đã đăng nhập lại đúng tài khoản cũ, không có tài khoản mới.');
  }
  const name = checkName(nameArg ?? id.email);
  writeFile(accountAuth(name), fresh.raw);
  snapshot(name, fresh.raw);
  console.log(`Đã thêm tài khoản "${name}"${id.email ? ` (${id.email})` : ''} và đang dùng nó.`);
}

function cmdRemove([nameArg]) {
  const name = resolveName(nameArg);
  if (!fs.existsSync(accountDir(name))) die(`Không có tài khoản "${name}".`);
  fs.rmSync(accountDir(name), { recursive: true });
  console.log(`Đã xoá tài khoản "${name}" cùng các backup của nó (auth.json live không bị đụng).`);
}

async function cmdSync(args) {
  const { pos, flags } = parseArgs(args);
  const configPath = path.join(HOME, 'aiuth-sync.json');
  try {
    for (const flag of Object.keys(flags)) if (!['url', 'confirm-reset'].includes(flag)) throw new Error(`Cờ sync không hợp lệ: --${flag}. Mật khẩu đọc từ terminal hoặc biến môi trường.`);
    const config = readAuth(configPath)?.json || {};
    const setup = pos[0] === 'setup';
    const change = pos[0] === 'change-password';
    const reset = ['reset-password', 'forgot-password'].includes(pos[0]);
    if (flags['confirm-reset'] && !reset) throw new Error('--confirm-reset chỉ dùng cho aiuth sync reset-password.');
    const subcommand = setup || change || reset;
    if (pos.length > (subcommand ? 2 : 1)) throw new Error('Dùng: aiuth sync [setup|change-password|reset-password] [URL].');
    if (setup && !flags.url && !pos[1]) {
      await setupCloudflare({ home: HOME });
      return;
    }
    let url = flags.url || (subcommand ? pos[1] : pos[0]) || process.env.AIUTH_SYNC_URL || config.url;
    if (!url && process.stdin.isTTY) url = await ask('Địa chỉ Worker aiuth (https://...workers.dev): ');
    if (!url) throw new Error('Chưa cấu hình Worker. Dùng: aiuth sync setup <URL>');
    url = normalizeSyncUrl(url);
    if (setup) {
      writeFile(configPath, `${JSON.stringify({ url }, null, 2)}\n`);
      console.log('Đã lưu địa chỉ Worker. Chạy aiuth sync để kéo, gộp và tải dữ liệu lên.');
      return;
    }
    const password = reset ? undefined : process.env.AIUTH_SYNC_PASSWORD ?? (process.stdin.isTTY ? await ask(change ? 'Mật khẩu đồng bộ hiện tại: ' : 'Mật khẩu đồng bộ (ít nhất 8 ký tự): ', true, false) : '');
    const identify = (auth) => identity(auth).fingerprint;
    const readLocal = () => {
      let records = listAccounts().map((name) => ({ name, auth: pickRaw(name) }));
      for (const provider of PROVIDERS) {
        const live = readLive(provider);
        if (!live) continue;
        const id = identity(live.json);
        if (!id.fingerprint) {
          if (provider === 'claude') continue; // chưa đọc được tài khoản Claude: bỏ qua, không chặn sync
          throw new Error('auth.json live không có danh tính hợp lệ.');
        }
        if (!records.some((r) => identify(JSON.parse(r.auth)) === id.fingerprint)) {
          const email = defaultName(id, new Set(records.map((r) => r.name)));
          const name = validSyncName(email) ? email : `current-${crypto.createHash('sha256').update(id.fingerprint).digest('hex').slice(0, 12)}`;
          records = mergeAccounts(records, [{ name, auth: live.raw }], identify);
        }
      }
      return records;
    };
    if (change || reset) {
      let newPassword = process.env.AIUTH_SYNC_NEW_PASSWORD;
      if (newPassword === undefined && process.stdin.isTTY) {
        newPassword = await ask('Mật khẩu đồng bộ mới (ít nhất 8 ký tự): ', true, false);
        if (newPassword !== await ask('Nhập lại mật khẩu mới: ', true, false)) throw new Error('Hai mật khẩu mới không khớp.');
      }
      if (reset) {
        console.error('Reset sẽ xoá bản đồng bộ cũ trên Worker và thay bằng tài khoản local. Mục chỉ có trên Worker sẽ mất. Auth live và backup local được giữ nguyên.');
        const confirmed = flags['confirm-reset'] === true || (process.stdin.isTTY && await ask('Nhập RESET để xác nhận: ') === 'RESET');
        if (!confirmed) throw new Error('Chưa xác nhận reset. Dùng --confirm-reset khi chạy không tương tác.');
        const setupCode = process.env.AIUTH_SYNC_SETUP_CODE ?? (process.stdin.isTTY ? await ask('Mã thiết lập Worker: ', true) : '');
        const result = await resetSyncPassword({ url, setupCode, password: newPassword, confirmReset: true, identify, readLocal });
        console.log(`Đã đặt lại mật khẩu đồng bộ và tải lại ${result.total} tài khoản local lên Worker. Các máy khác cần đăng nhập lại bằng mật khẩu mới.`);
      } else {
        await changeSyncPassword({ url, oldPassword: password, password: newPassword });
        console.log('Đã đổi mật khẩu đồng bộ, giữ nguyên dữ liệu Worker. Các máy khác cần cập nhật aiuth và dùng mật khẩu mới.');
      }
      writeFile(configPath, `${JSON.stringify({ url }, null, 2)}\n`);
      return;
    }
    const result = await runSync({
      url, password, identify, readLocal,
      setupCode: async () => process.env.AIUTH_SYNC_SETUP_CODE ?? (process.stdin.isTTY ? await ask('Mã thiết lập Worker: ', true) : ''),
      writeLocal: (records) => {
        // Tài khoản đã có không bị ghi đè; auth.json live và các backup cũ được giữ nguyên.
        for (const record of records) {
          const dir = accountDir(record.name);
          if (fs.existsSync(dir) && (!fs.lstatSync(dir).isDirectory() || fs.lstatSync(dir).isSymbolicLink())) throw new Error(`Thư mục tài khoản không hợp lệ: ${record.name}`);
          if (fs.existsSync(accountAuth(record.name))) continue;
          writeFile(accountAuth(record.name), record.auth);
          snapshot(record.name, record.auth);
        }
      }
    });
    writeFile(configPath, `${JSON.stringify({ url }, null, 2)}\n`);
    console.log(`Đã đồng bộ: local ${result.local}, Worker ${result.remote}, sau khi gộp ${result.total} tài khoản (revision ${result.revision}).`);
  } catch (e) {
    die(e.message);
  }
}

function cmdCurrent() {
  const present = PROVIDERS.map((p) => [p, readLive(p)]).filter(([, live]) => live);
  if (!present.length) die('Chưa đăng nhập Codex lẫn Claude.');
  for (const [p, live] of present) {
    const id = identity(live.json);
    console.log(`${p.padEnd(7)} ${findAccountFor(id.fingerprint) ?? '(chưa lưu)'}  ${id.email ?? '-'}  [${id.mode}]`);
  }
}

const HELP = `aiuth — quản lý nhiều tài khoản Codex (~/.codex/auth.json) và Claude Code (~/.claude/.credentials.json)

  add [tên]             Thêm tài khoản Codex mới bằng device code, KHÔNG logout tài khoản cũ
                        (Claude: chạy "claude" rồi /login, sau đó "aiuth save")
  save [tên]            Lưu cả Codex và Claude đang đăng nhập (mặc định tên = email)
  list [--usage]        Liệt kê tài khoản Codex + Claude (* = đang dùng); --usage thêm cột limit (chỉ Codex)
  current               Tài khoản đang dùng
  usage [số|tên] [--json]  Thống kê limit (% đã dùng, thời gian reset) của từng tài khoản
  use <số|tên>          Chuyển tài khoản (số thứ tự theo list), chỉ đổi provider của tài khoản đó.
                        Codex: dừng codex + MCP con, giữ auth hiện tại rồi ghi đè. Claude: khởi động lại Claude Code sau khi use
                        (--no-kill: không dừng codex; áp dụng cho use/add/receive --use)
  send <tên>            Chờ 1 máy khác trong LAN nhận trực tiếp (in ra lệnh + mã 8 ký tự)
  send <tên> --mail     Gửi qua hộp thư (mã hoá), in mã 12 ký tự; --to <địa-chỉ> gửi tới mail khác
  receive --mail <mã>   Lấy từ hộp thư rồi giải mã (--wait <giây>, --name, --use)
  mail setup            Lưu tài khoản mail (app password) cho send/receive --mail
  sync setup           Cài Cloudflare: đăng nhập, tạo D1, deploy Worker, lưu mã và URL
  sync setup <URL>     Chỉ kết nối Worker đã có (không deploy)
  sync [--url URL]      Kéo Worker → gộp (local ưu tiên) → ghi bản gộp lên Worker và local
  sync change-password Đổi mật khẩu đồng bộ bằng mật khẩu cũ, giữ dữ liệu Worker
  sync reset-password  Quên mật khẩu: dùng mã thiết lập, thay Worker bằng bản local (cần xác nhận)
                        (alias: sync forgot-password; --confirm-reset khi chạy không tương tác)
  receive <ip:port> <mã>  Nhận tài khoản từ máy đang chạy send (--name, --use)
  remove <tên>          Xoá tài khoản đã lưu và backup của nó

Env: CODEX_HOME (mặc định ~/.codex), CLAUDE_CONFIG_DIR (mặc định ~/.claude)   Giữ tối đa ${MAX_BACKUPS} backup mỗi tài khoản.`;

const COMMANDS = {
  add: cmdAdd,
  save: cmdSave,
  list: cmdList,
  usage: cmdUsage,
  limits: cmdUsage,
  ls: cmdList,
  current: cmdCurrent,
  use: cmdUse,
  send: cmdSend,
  mail: cmdMail,
  sync: cmdSync,
  receive: cmdReceive,
  remove: cmdRemove,
  rm: cmdRemove,
};

const [cmd, ...rest] = process.argv.slice(2);
if (!cmd || cmd === '-h' || cmd === '--help' || cmd === 'help') {
  console.log(HELP);
} else if (COMMANDS[cmd]) {
  await COMMANDS[cmd](rest);
} else {
  die(`Lệnh không hợp lệ: ${cmd}\n\n${HELP}`);
}
