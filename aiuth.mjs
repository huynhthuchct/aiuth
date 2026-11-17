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
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { spawnSync } from 'node:child_process';

const HOME = process.env.CODEX_HOME || path.join(os.homedir(), '.codex');
const AUTH = path.join(HOME, 'auth.json');
const STORE = path.join(HOME, 'accounts');
const UNSAVED = path.join(STORE, '.unsaved');
const MAX_BACKUPS = 20;
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._@+-]*$/;

const die = (msg) => {
  console.error(`✗ ${msg}`);
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

function cmdSave([nameArg]) {
  const live = readAuth(AUTH);
  if (!live) die(`Không thấy ${AUTH}. Hãy chạy "codex login" trước.`);
  const id = identity(live.json);
  const name = checkName(nameArg ?? id.email);
  if (!nameArg && !id.email) die('Không đọc được email từ auth.json, hãy truyền tên: save <tên>');
  const existed = fs.existsSync(accountAuth(name));
  writeFile(accountAuth(name), live.raw);
  snapshot(name, live.raw);
  console.log(`✓ ${existed ? 'Cập nhật' : 'Đã lưu'} tài khoản "${name}"${id.email ? ` (${id.email})` : ''}`);
}

function cmdList() {
  const names = listAccounts();
  if (!names.length) return console.log('Chưa có tài khoản nào. Dùng: aiuth save [tên]');
  const live = readAuth(AUTH);
  const liveFp = live ? identity(live.json).fingerprint : null;
  console.log(`  ${'TÊN'.padEnd(32)} ${'EMAIL'.padEnd(32)} MODE      BACKUPS`);
  for (const n of names) {
    const a = readAuth(accountAuth(n));
    const id = identity(a.json);
    const mark = liveFp && id.fingerprint === liveFp ? '*' : ' ';
    console.log(
      `${mark} ${n.padEnd(32)} ${(id.email ?? '-').padEnd(32)} ${id.mode.padEnd(9)} ${listBackups(n).length}`,
    );
  }
  console.log('\n* = đang dùng (khớp ~/.codex/auth.json)');
}

function cmdUse([nameArg]) {
  const name = checkName(nameArg);
  const target = readAuth(accountAuth(name));
  if (!target) die(`Không có tài khoản "${name}". Xem: aiuth list`);
  const kept = preserveLive();
  writeFile(AUTH, target.raw);
  if (kept) console.log(`• Đã giữ auth hiện tại vào ${kept}`);
  console.log(`✓ Đang dùng "${name}"${identity(target.json).email ? ` (${identity(target.json).email})` : ''}`);
}

function cmdBackup([nameArg]) {
  let name = nameArg;
  const live = readAuth(AUTH);
  if (!name) {
    if (!live) die('Không có auth live để suy ra tài khoản.');
    name = findAccountFor(identity(live.json).fingerprint);
    if (!name) die('Auth hiện tại chưa thuộc tài khoản nào. Dùng: aiuth save [tên]');
  }
  checkName(name);
  if (!fs.existsSync(accountAuth(name))) die(`Không có tài khoản "${name}".`);
  // Ưu tiên auth live nếu nó thuộc tài khoản này (token mới nhất), nếu không dùng bản đã lưu.
  const useLive = live && identity(live.json).fingerprint === identity(readAuth(accountAuth(name)).json).fingerprint;
  const raw = useLive ? live.raw : readAuth(accountAuth(name)).raw;
  if (useLive) writeFile(accountAuth(name), raw);
  console.log(`✓ Backup "${name}" → backups/${snapshot(name, raw)}.json`);
}

function cmdBackups([nameArg]) {
  const name = checkName(nameArg);
  if (!fs.existsSync(accountAuth(name))) die(`Không có tài khoản "${name}".`);
  const ids = listBackups(name);
  if (!ids.length) return console.log('(chưa có backup)');
  ids.reverse().forEach((id, i) => console.log(`${i === 0 ? 'latest ' : '       '}${id}`));
}

/* ───────── export / import: chuyển tài khoản giữa các máy bằng một chuỗi ───────── */

const PREFIX = 'aiuth1';

/** Tách cờ (--no-encrypt, --use, --name x) khỏi tham số vị trí. */
function parseArgs(args) {
  const pos = [];
  const flags = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--name') flags.name = args[++i];
    else if (a.startsWith('--')) flags[a.slice(2)] = true;
    else pos.push(a);
  }
  return { pos, flags };
}

/** Hỏi một dòng; hidden=true thì không hiện ký tự (passphrase). */
function ask(question, hidden = false) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    if (hidden) {
      rl._writeToOutput = (s) => {
        if (s.includes(question)) process.stderr.write(s);
      };
    }
    rl.question(question, (ans) => {
      rl.close();
      if (hidden) process.stderr.write('\n');
      resolve(ans);
    });
  });
}

async function getPassphrase(confirm) {
  if (process.env.AIUTH_PASSPHRASE) return process.env.AIUTH_PASSPHRASE;
  if (!process.stdin.isTTY) die('Không có TTY: đặt passphrase qua biến môi trường AIUTH_PASSPHRASE.');
  const p = await ask('Passphrase: ', true);
  if (!p) die('Passphrase không được để trống.');
  if (confirm && (await ask('Nhập lại passphrase: ', true)) !== p) die('Passphrase không khớp.');
  return p;
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

/** export <tên> [id|latest] [--no-encrypt]  → in chuỗi ra stdout (thông báo ra stderr). */
async function cmdExport(args) {
  const { pos, flags } = parseArgs(args);
  const name = checkName(pos[0]);
  if (!fs.existsSync(accountAuth(name))) die(`Không có tài khoản "${name}".`);
  const idArg = pos[1] ?? 'main';
  let raw;
  if (idArg === 'main') {
    // Ưu tiên auth live nếu thuộc tài khoản này (token mới nhất).
    const live = readAuth(AUTH);
    const saved = readAuth(accountAuth(name));
    raw = live && identity(live.json).fingerprint === identity(saved.json).fingerprint ? live.raw : saved.raw;
  } else {
    const ids = listBackups(name);
    const id = idArg === 'latest' ? ids.at(-1) : ids.find((x) => x === idArg || x.startsWith(idArg));
    if (!id) die(`Không tìm thấy backup "${idArg}" của "${name}".`);
    raw = readAuth(path.join(accountDir(name), 'backups', `${id}.json`)).raw;
  }
  const payload = JSON.stringify({ v: 1, name, exportedAt: new Date().toISOString(), auth: raw });
  let out;
  if (flags['no-encrypt']) {
    console.error('⚠ Không mã hoá: chuỗi này chứa token dạng rõ, ai có nó là đăng nhập được.');
    out = `${PREFIX}:p:${Buffer.from(payload).toString('base64url')}`;
  } else {
    out = `${PREFIX}:e:${encrypt(payload, await getPassphrase(true)).toString('base64url')}`;
  }
  console.error(`✓ Export "${name}" — dán chuỗi dưới đây vào máy khác: aiuth import <chuỗi>`);
  console.log(out);
}

/** import [chuỗi|-] [--name x] [--use]  (không có chuỗi: đọc stdin hoặc hỏi). */
async function cmdImport(args) {
  const { pos, flags } = parseArgs(args);
  let text = pos[0];
  if (!text || text === '-') {
    if (process.stdin.isTTY) {
      text = await ask('Dán chuỗi aiuth1:...: ');
    } else {
      const chunks = [];
      for await (const c of process.stdin) chunks.push(c);
      text = Buffer.concat(chunks).toString('utf8');
    }
  }
  const m = /^aiuth1:([ep]):([A-Za-z0-9_-]+)$/.exec(text.trim());
  if (!m) die('Chuỗi không đúng định dạng aiuth1:… (có thể bị cắt khi copy).');
  const buf = Buffer.from(m[2], 'base64url');
  const plain = m[1] === 'p' ? buf.toString('utf8') : decrypt(buf, await getPassphrase(false));
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
  console.log(`✓ Đã import tài khoản "${name}"${id.email ? ` (${id.email})` : ''}${old ? ' (ghi đè bản cũ, đã backup)' : ''}`);
  if (flags.use) cmdUse([name]);
  else console.log(`  Dùng ngay: aiuth use ${name}`);
}

function cmdRestore([nameArg, idArg = 'latest']) {
  const name = checkName(nameArg);
  if (!fs.existsSync(accountAuth(name))) die(`Không có tài khoản "${name}".`);
  const ids = listBackups(name);
  const id = idArg === 'latest' ? ids.at(-1) : ids.find((x) => x === idArg || x.startsWith(idArg));
  if (!id) die(`Không tìm thấy backup "${idArg}" của "${name}". Xem: aiuth backups ${name}`);
  const bk = readAuth(path.join(accountDir(name), 'backups', `${id}.json`));
  const kept = preserveLive();
  writeFile(accountAuth(name), bk.raw);
  writeFile(AUTH, bk.raw);
  if (kept) console.log(`• Đã giữ auth hiện tại vào ${kept}`);
  console.log(`✓ Khôi phục "${name}" từ backup ${id} → ${AUTH}`);
}

/**
 * Thêm tài khoản mới KHÔNG logout (logout thu hồi token cũ phía server).
 * Giữ auth cũ -> gỡ file auth.json (Codex coi như chưa đăng nhập) -> `codex login --device-auth`
 * -> lưu tài khoản mới. Nếu login thất bại/huỷ thì khôi phục auth cũ.
 */
function cmdAdd([nameArg]) {
  if (nameArg) checkName(nameArg);
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
      console.log(`• Đã lưu auth hiện tại thành "${keep}"`);
    }
    fs.rmSync(AUTH); // chỉ xoá file cục bộ, không gọi logout
    console.log('• Đã gỡ auth.json cục bộ (không logout, token cũ vẫn sống).');
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
  console.log(`✓ Đã thêm tài khoản "${name}"${id.email ? ` (${id.email})` : ''} và đang dùng nó.`);
}

function cmdRemove([nameArg]) {
  const name = checkName(nameArg);
  if (!fs.existsSync(accountDir(name))) die(`Không có tài khoản "${name}".`);
  fs.rmSync(accountDir(name), { recursive: true });
  console.log(`✓ Đã xoá tài khoản "${name}" cùng các backup của nó (auth.json live không bị đụng).`);
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
  list                  Liệt kê tài khoản (* = đang dùng)
  current               Tài khoản đang dùng
  use <tên>             Chuyển sang tài khoản (tự giữ auth hiện tại trước khi ghi đè)
  backup [tên]          Tạo bản backup có dấu thời gian (mặc định: tài khoản đang dùng)
  backups <tên>         Liệt kê backup của tài khoản
  restore <tên> [id]    Khôi phục từ backup (id hoặc tiền tố; mặc định latest)
  export <tên> [id]     In ra 1 chuỗi (mã hoá bằng passphrase) để import ở máy khác
                        (--no-encrypt: không mã hoá; AIUTH_PASSPHRASE: passphrase qua env)
  import [chuỗi]        Nhập chuỗi từ export (--name <tên> đổi tên, --use dùng ngay)
  remove <tên>          Xoá tài khoản đã lưu và backup của nó

Env: CODEX_HOME (mặc định ~/.codex)   Giữ tối đa ${MAX_BACKUPS} backup mỗi tài khoản.`;

const COMMANDS = {
  add: cmdAdd,
  save: cmdSave,
  list: cmdList,
  ls: cmdList,
  current: cmdCurrent,
  use: cmdUse,
  switch: cmdUse,
  backup: cmdBackup,
  backups: cmdBackups,
  export: cmdExport,
  import: cmdImport,
  restore: cmdRestore,
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
