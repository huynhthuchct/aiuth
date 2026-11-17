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
import { spawnSync } from 'node:child_process';

const HOME = process.env.CODEX_HOME || path.join(os.homedir(), '.codex');
const AUTH = path.join(HOME, 'auth.json');
const STORE = path.join(HOME, 'accounts');
const UNSAVED = path.join(STORE, '.unsaved');
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

/** Trích danh tính (email, account id, fingerprint) từ nội dung auth.json. */
function identity(json) {
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
  return { email, accountId, fingerprint, mode: json?.auth_mode ?? (json?.OPENAI_API_KEY ? 'apikey' : '?') };
}

const checkName = (name) => {
  if (!name) die('Thiếu tên tài khoản.');
  if (!NAME_RE.test(name)) die(`Tên "${name}" không hợp lệ (chỉ dùng chữ, số, . _ @ + -).`);
  return name;
};

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
function preserveLive() {
  const live = readAuth(AUTH);
  if (!live) return null;
  const owner = findAccountFor(identity(live.json).fingerprint);
  if (owner) {
    writeFile(accountAuth(owner), live.raw); // token có thể đã refresh -> cập nhật bản lưu
    snapshot(owner, live.raw);
    return `tài khoản "${owner}"`;
  }
  writeFile(path.join(UNSAVED, `${stamp()}.json`), live.raw);
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

function cmdSave([nameArg]) {
  const live = readAuth(AUTH);
  if (!live) die(`Không thấy ${AUTH}. Hãy chạy "codex login" trước.`);
  const id = identity(live.json);
  const name = checkName(nameArg ?? id.email);
  if (!nameArg && !id.email) die('Không đọc được email từ auth.json, hãy truyền tên: save <tên>');
  const existed = fs.existsSync(accountAuth(name));
  writeFile(accountAuth(name), live.raw);
  snapshot(name, live.raw);
  console.log(`${existed ? 'Cập nhật' : 'Đã lưu'} tài khoản "${name}"${id.email ? ` (${id.email})` : ''}`);
}

async function cmdList(args = []) {
  const { flags } = parseArgs(args);
  const names = listAccounts();
  if (!names.length) return console.log('Chưa có tài khoản nào. Dùng: aiuth save [tên]');
  const live = readAuth(AUTH);
  const liveFp = live ? identity(live.json).fingerprint : null;
  const rows = names.map((n) => {
    const saved = readAuth(accountAuth(n));
    const id = identity(saved.json);
    const active = !!liveFp && id.fingerprint === liveFp;
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
  console.log(`  ${'TÊN'.padEnd(32)} ${'EMAIL'.padEnd(32)} ${'MODE'.padEnd(9)} ${'BACKUPS'.padEnd(7)}${flags.usage ? ' LIMIT' : ''}`);
  rows.forEach((r, i) => {
    console.log(
      `${r.active ? '*' : ' '} ${r.n.padEnd(32)} ${(r.id.email ?? '-').padEnd(32)} ${r.id.mode.padEnd(9)} ${String(listBackups(r.n).length).padEnd(7)}${flags.usage ? ` ${summary(limits[i])}` : ''}`,
    );
  });
  console.log(`\n* = đang dùng (khớp ~/.codex/auth.json)${flags.usage ? '' : '   |   thêm --usage để xem limit'}`);
}

async function cmdUse(args) {
  const { pos, flags } = parseArgs(args);
  const name = checkName(pos[0]);
  const target = readAuth(accountAuth(name));
  if (!target) die(`Không có tài khoản "${name}". Xem: aiuth list`);
  await stopCodex(flags);
  const kept = preserveLive();
  writeFile(AUTH, target.raw);
  if (kept) console.log(`Đã giữ auth hiện tại vào ${kept}`);
  console.log(`Đang dùng "${name}"${identity(target.json).email ? ` (${identity(target.json).email})` : ''}`);
}

function cmdBackups([nameArg]) {
  const name = checkName(nameArg);
  if (!fs.existsSync(accountAuth(name))) die(`Không có tài khoản "${name}".`);
  const ids = listBackups(name);
  if (!ids.length) return console.log('(chưa có backup)');
  ids.reverse().forEach((id, i) => console.log(`${i === 0 ? 'latest ' : '       '}${id}`));
}

/* ───────── helper dùng chung cho send / receive ───────── */

/** Tách cờ (--no-encrypt, --use, --name x) khỏi tham số vị trí. */
function parseArgs(args) {
  const pos = [];
  const flags = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--name' || a === '--port') flags[a.slice(2)] = args[++i];
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
    const live = readAuth(AUTH);
    const saved = readAuth(accountAuth(name));
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

const newCode = () => {
  const c = Array.from({ length: 8 }, () => CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)]).join('');
  return `${c.slice(0, 4)}-${c.slice(4)}`;
};
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
  const name = checkName(pos[0]);
  if (!fs.existsSync(accountAuth(name))) die(`Không có tài khoản "${name}".`);
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
async function cmdUsage(args) {
  const { pos, flags } = parseArgs(args);
  const names = pos[0] ? [checkName(pos[0])] : listAccounts();
  if (!names.length) return console.log('Chưa có tài khoản nào. Dùng: aiuth save [tên]');
  for (const n of names) if (!fs.existsSync(accountAuth(n))) die(`Không có tài khoản "${n}".`);
  const live = readAuth(AUTH);
  const liveFp = live ? identity(live.json).fingerprint : null;

  const results = await Promise.all(
    names.map(async (n) => {
      const saved = readAuth(accountAuth(n));
      // Auth live của cùng tài khoản thường mới hơn bản đã lưu (Codex tự refresh token).
      const useLive = live && identity(saved.json).fingerprint === liveFp;
      const res = await fetchUsage(useLive ? live.raw : saved.raw);
      return { name: n, active: useLive, email: identity(saved.json).email, ...res };
    }),
  );

  if (flags.json) {
    console.log(JSON.stringify(results.map((r) => ({ name: r.name, active: r.active, email: r.email, usage: r.data ?? null, error: r.error ?? null })), null, 2));
    return;
  }

  for (const r of results) {
    const head = `${r.active ? '*' : ' '} ${r.name}${r.email && r.email !== r.name ? `  (${r.email})` : ''}`;
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
async function cmdAdd(args) {
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
  const name = checkName(nameArg);
  if (!fs.existsSync(accountDir(name))) die(`Không có tài khoản "${name}".`);
  fs.rmSync(accountDir(name), { recursive: true });
  console.log(`Đã xoá tài khoản "${name}" cùng các backup của nó (auth.json live không bị đụng).`);
}

function cmdCurrent() {
  const live = readAuth(AUTH);
  if (!live) die('Chưa đăng nhập (không có auth.json).');
  const id = identity(live.json);
  const owner = findAccountFor(id.fingerprint);
  console.log(`${owner ?? '(chưa lưu)'}  ${id.email ?? '-'}  [${id.mode}]`);
}

const HELP = `aiuth — quản lý nhiều ~/.codex/auth.json

  add [tên]             Thêm tài khoản mới bằng device code, KHÔNG logout tài khoản cũ
  save [tên]            Lưu auth.json hiện tại thành tài khoản (mặc định tên = email)
  list [--usage]        Liệt kê tài khoản (* = đang dùng); --usage thêm cột limit
  current               Tài khoản đang dùng
  usage [tên] [--json]  Thống kê limit (% đã dùng, thời gian reset) của từng tài khoản
  use <tên>             Chuyển tài khoản: dừng codex + MCP con của nó, giữ auth hiện tại rồi ghi đè
                        (--no-kill: không dừng codex; áp dụng cho use/add/receive --use)
  backups <tên>         Liệt kê backup của tài khoản
  send <tên> [id]       Chờ 1 máy khác trong LAN nhận trực tiếp (in ra lệnh + mã 8 ký tự)
  receive <ip:port> <mã>  Nhận tài khoản từ máy đang chạy send (--name, --use)
  remove <tên>          Xoá tài khoản đã lưu và backup của nó

Env: CODEX_HOME (mặc định ~/.codex)   Giữ tối đa ${MAX_BACKUPS} backup mỗi tài khoản.`;

const COMMANDS = {
  add: cmdAdd,
  save: cmdSave,
  list: cmdList,
  usage: cmdUsage,
  limits: cmdUsage,
  ls: cmdList,
  current: cmdCurrent,
  use: cmdUse,
  backups: cmdBackups,
  send: cmdSend,
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
