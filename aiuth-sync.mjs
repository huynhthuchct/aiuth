import crypto from 'node:crypto';

const ITEM_ID = 'aiuth-accounts-v1';
const KEY_ID = 'aiuth-data-key-v1';
const MAX_BYTES = 500_000;
const namePattern = /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$/;
export function validSyncName(name) {
  return typeof name === 'string' && namePattern.test(name) && !name.endsWith('.') &&
    !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name);
}
export function normalizeSyncUrl(input) {
  const url = new URL(input);
  if (url.username || url.password || url.search || url.hash || !['', '/'].includes(url.pathname))
    throw new Error('Địa chỉ Worker phải là URL gốc, không có thông tin đăng nhập hoặc đường dẫn.');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))
    throw new Error('Worker phải dùng HTTPS (chỉ cho phép HTTP khi thử trên localhost).');
  return url.origin;
}

function validate(records, identify) {
  if (!Array.isArray(records) || records.length > 10000) throw new Error('Danh sách tài khoản đồng bộ không hợp lệ.');
  return records.map((record) => {
    if (!record || !validSyncName(record.name) || typeof record.auth !== 'string') throw new Error('Tên hoặc dữ liệu tài khoản đồng bộ không hợp lệ.');
    let auth;
    try { auth = JSON.parse(record.auth); } catch { throw new Error('Tài khoản đồng bộ chứa auth.json không hợp lệ.'); }
    const id = auth && typeof auth === 'object' && !Array.isArray(auth) ? identify(auth) : null;
    if (typeof id !== 'string' || !id) throw new Error('Tài khoản đồng bộ không có danh tính hợp lệ.');
    return { name: record.name, auth: record.auth, id };
  });
}

// Local thắng khi trùng danh tính. Trùng tên nhưng khác danh tính: giữ cả hai.
export function mergeAccounts(local, remote, identify, caseInsensitive = process.platform === 'win32') {
  const result = [];
  const ids = new Set();
  const names = new Set();
  const canonical = (name) => caseInsensitive ? name.toLowerCase() : name;
  const add = (record) => {
    if (ids.has(record.id)) return;
    let name = record.name;
    if (names.has(canonical(name))) {
      const suffix = crypto.createHash('sha256').update(record.id).digest('hex').slice(0, 10);
      const base = `${name.slice(0, 100)}-remote-${suffix}`;
      name = base;
      for (let i = 2; names.has(canonical(name)); i++) name = `${base}-${i}`;
    }
    ids.add(record.id);
    names.add(canonical(name));
    result.push({ name, auth: record.auth });
  };
  validate(local, identify).forEach(add);
  validate(remote, identify).forEach(add);
  return result.sort((a, b) => a.name.localeCompare(b.name));
}

export async function deriveSyncKeys(password, salt) {
  const master = await new Promise((resolve, reject) => crypto.pbkdf2(password, Buffer.from(salt, 'base64url'), 600000, 32, 'sha256', (e, value) => e ? reject(e) : resolve(value)));
  const sub = (label) => Buffer.from(crypto.hkdfSync('sha256', master, Buffer.alloc(32), label, 32));
  return { authKey: sub('aiuth-auth-v1').toString('base64url'), encKey: sub('aiuth-enc-v1') };
}
function sealJson(value, key, aad) {
  const plain = JSON.stringify(value);
  if (Buffer.byteLength(plain) > MAX_BYTES) throw new Error('Danh sách quá lớn để đồng bộ (tối đa 500 KB).');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return { iv: iv.toString('base64url'), ct: ct.toString('base64url') };
}
function openJson(blob, key, aad) {
  try {
    const ct = Buffer.from(blob.ct, 'base64url');
    if (ct.length < 16 || Buffer.from(blob.iv, 'base64url').length !== 12) throw new Error();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(blob.iv, 'base64url'), { authTagLength: 16 });
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(ct.subarray(-16));
    const data = JSON.parse(Buffer.concat([decipher.update(ct.subarray(0, -16)), decipher.final()]).toString('utf8'));
    return data;
  } catch { throw new Error('Không giải mã được bản đồng bộ; kiểm tra mật khẩu hoặc dữ liệu Worker. Chưa ghi đè dữ liệu.'); }
}
export const sealSnapshot = (accounts, key) => sealJson({ version: 1, accounts }, key, ITEM_ID);
export function openSnapshot(blob, key) {
  const data = openJson(blob, key, ITEM_ID);
  if (data?.version !== 1 || !Array.isArray(data.accounts)) throw new Error('Bản đồng bộ Worker không hợp lệ.');
  return data.accounts;
}
function restoreDataKey(keys, wrappedKey) {
  if (!wrappedKey) return keys;
  const data = openJson(wrappedKey, keys.encKey, KEY_ID);
  if (typeof data?.key !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(data.key)) throw new Error('Khoá dữ liệu đồng bộ không hợp lệ.');
  return { ...keys, encKey: Buffer.from(data.key, 'base64url') };
}

const errors = {
  bad_credentials: 'Sai mật khẩu đồng bộ.', bad_setup_code: 'Sai mã thiết lập Worker.',
  already_registered: 'Worker vừa được đăng ký trên máy khác. Chạy lại aiuth sync.',
  unauthorized: 'Phiên đồng bộ hết hạn. Chạy lại aiuth sync.',
  account_changed: 'Tài khoản vừa thay đổi trên máy khác. Hãy thử lại.',
  not_found: 'Worker chưa hỗ trợ chức năng này. Hãy cập nhật Worker.',
  setup_code_missing: 'Worker chưa có SETUP_CODE.', too_large: 'Dữ liệu vượt giới hạn Worker.'
};
function createApi(url, request) {
  return async (path, body, token) => {
    const response = await request(url + '/api/' + path, {
      method: body === undefined ? 'GET' : 'POST', redirect: 'error', signal: AbortSignal.timeout(20000),
      headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
    const data = await response.json();
    if (!response.ok) throw Object.assign(new Error(errors[data?.error] || `Worker báo lỗi HTTP ${response.status}.`), { status: response.status });
    return data;
  };
}
function checkPassword(password) {
  if (typeof password !== 'string' || password.length < 8) throw new Error('Mật khẩu đồng bộ cần ít nhất 8 ký tự.');
}
async function getSyncState(call) {
  const state = await call('status');
  if (state?.service !== 'aiuth-sync-v1' || typeof state.registered !== 'boolean') throw new Error('Địa chỉ này không phải Worker aiuth.');
  if (state.registered && (typeof state.salt !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(state.salt))) throw new Error('Salt Worker không hợp lệ.');
  return state;
}
export async function runSync({ url, password, setupCode, readLocal, writeLocal, identify, request = fetch }) {
  url = normalizeSyncUrl(url);
  checkPassword(password);
  const call = createApi(url, request);
  const state = await getSyncState(call);
  const salt = state.registered ? state.salt : crypto.randomBytes(16).toString('base64url');
  if (typeof salt !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(salt)) throw new Error('Salt Worker không hợp lệ.');
  let keys = await deriveSyncKeys(password, salt);
  if (!state.registered) {
    const code = typeof setupCode === 'function' ? await setupCode() : setupCode;
    if (!code?.trim()) throw new Error('Worker chưa có tài khoản. Nhập mã thiết lập hoặc đặt AIUTH_SYNC_SETUP_CODE.');
    await call('register', { salt, authKey: keys.authKey, setupCode: code.trim() });
  }
  const { token } = await call('login', { authKey: keys.authKey });
  try {
    keys = restoreDataKey(keys, state.wrappedKey);
    for (let attempt = 0; attempt < 4; attempt++) {
      const snapshot = await call('snapshot', undefined, token);
      if (!Number.isSafeInteger(snapshot.revision) || snapshot.revision < 0 || (snapshot.revision > 0 && !snapshot.blob)) throw new Error('Bản đồng bộ Worker không hợp lệ.');
      const remote = snapshot.blob ? openSnapshot(snapshot.blob, keys.encKey) : [];
      const local = await readLocal();
      const merged = mergeAccounts(local, remote, identify);
      try {
        const saved = await call('snapshot', { revision: snapshot.revision, ...sealSnapshot(merged, keys.encKey) }, token);
        await writeLocal(merged);
        return { local: local.length, remote: remote.length, total: merged.length, revision: saved.revision };
      } catch (e) {
        if (e.status === 409 && attempt < 3) continue;
        throw e;
      }
    }
  } finally { await call('logout', {}, token).catch(() => {}); }
}

export async function changeSyncPassword({ url, oldPassword, password, request = fetch }) {
  url = normalizeSyncUrl(url);
  checkPassword(oldPassword);
  checkPassword(password);
  const call = createApi(url, request);
  const state = await getSyncState(call);
  if (!state.registered) throw new Error('Worker chưa có tài khoản đồng bộ. Chạy aiuth sync trước.');
  const oldKeys = await deriveSyncKeys(oldPassword, state.salt);
  const { token } = await call('login', { authKey: oldKeys.authKey });
  try {
    const dataKeys = restoreDataKey(oldKeys, state.wrappedKey);
    const salt = crypto.randomBytes(16).toString('base64url');
    const keys = await deriveSyncKeys(password, salt);
    const wrappedKey = sealJson({ key: dataKeys.encKey.toString('base64url') }, keys.encKey, KEY_ID);
    await call('password/change', { authKey: oldKeys.authKey, salt, newAuthKey: keys.authKey, wrappedKey });
    return { passwordUpdated: true };
  } finally { await call('logout', {}, token).catch(() => {}); }
}

export async function resetSyncPassword({ url, setupCode, password, confirmReset, readLocal, identify, request = fetch }) {
  url = normalizeSyncUrl(url);
  checkPassword(password);
  if (confirmReset !== true) throw new Error('Reset sẽ xoá bản đồng bộ cũ trên Worker. Cần xác nhận RESET hoặc cờ --confirm-reset.');
  if (typeof setupCode !== 'string' || !setupCode.trim()) throw new Error('Hãy nhập mã thiết lập Worker.');
  const call = createApi(url, request);
  await getSyncState(call);
  // Kiểm tra và mã hoá toàn bộ local trước khi thay đổi Worker.
  const accounts = mergeAccounts(await readLocal(), [], identify);
  const salt = crypto.randomBytes(16).toString('base64url');
  const keys = await deriveSyncKeys(password, salt);
  const snapshot = sealSnapshot(accounts, keys.encKey);
  await call('password/reset', { setupCode: setupCode.trim(), confirmReset: true, salt, authKey: keys.authKey, snapshot });
  return { passwordUpdated: true, total: accounts.length };
}
