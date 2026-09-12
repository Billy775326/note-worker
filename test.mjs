import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import vm from 'node:vm';
import worker from './worker.js';

// Node WebCrypto lacks Workers' MD5 extension; use OpenSSL only for that algorithm.
const nativeDigest = crypto.subtle.digest.bind(crypto.subtle);
crypto.subtle.digest = (algorithm, data) => algorithm === 'MD5'
  ? Promise.resolve(Uint8Array.from(createHash('md5').update(data).digest()).buffer)
  : nativeDigest(algorithm, data);
const password = '测试 password : 12345';
function environment() {
  const store = new Map();
  const salt = 'ab'.repeat(32);
  return {
    login: 'private-notes',
    PASSWORD_SALT: salt,
    PASSWORD_HASH: createHash('md5').update(salt + ':' + password).digest('hex'),
    SESSION_SECRET: 'cd'.repeat(32),
    LOGIN_RATE_LIMITER: { limit: async () => ({ success: true }) },
    CLOUD_EDITOR_KV: { get: async key => store.get(key), put: async (key, value) => store.set(key, value) },
    PROXY_ALLOWED_HOSTS: 'example.com'
  };
}
function request(path, { method = 'GET', body, cookie, headers = {} } = {}) {
  return new Request('https://notes.example' + (path.startsWith('/api/') ? '/private-notes' : '') + path, { method,
    headers: { ...(method === 'POST' ? { Origin: 'https://notes.example', 'X-Requested-With': 'note-editor', 'Content-Type': 'application/json' } : {}), ...(cookie ? { Cookie: cookie } : {}), ...headers },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
}
async function login(env) {
  const res = await worker.fetch(request('/api/login', { method: 'POST', body: { password } }), env);
  assert.equal(res.status, 200);
  assert.match(res.headers.get('Set-Cookie'), /HttpOnly; Secure; SameSite=Strict/);
  return res.headers.get('Set-Cookie').split(';')[0];
}
test('page has no password, legacy header or localStorage credentials; embedded script compiles', async () => {
  const page = await (await worker.fetch(request('/private-notes'), environment())).text();
  assert.doesNotMatch(page, /adminbly|X-Password|localStorage\.setItem\('cloud_editor_auth'/);
  const script = page.match(/<script>([\s\S]*?)<\/script>/)[1];
  new vm.Script(script);
  assert.match(page, /escapeHtml\(trimmed\)/);
});
test('all data and proxy APIs require signed cookies, legacy password cannot bypass', async () => {
  const env = environment();
  for (const path of ['/api/get-data', '/api/session', '/api/proxy?url=https://example.com']) {
    assert.equal((await worker.fetch(request(path, { headers: { 'X-Password': 'legacy-password' } }), env)).status, 401);
  }
  assert.equal((await worker.fetch(request('/api/save-data', { method: 'POST', body: {} }), env)).status, 401);
});
test('wrong password and malformed login rejected without cookies', async () => {
  const env = environment();
  for (const [body, status] of [[{ password: 'wrong' }, 401], [{}, 400], [null, 400]]) {
    const res = await worker.fetch(request('/api/login', { method: 'POST', body }), env);
    assert.equal(res.status, status); assert.equal(res.headers.get('Set-Cookie'), null);
  }
});
test('login verifies salted UTF-8 hash and creates authenticated session', async () => {
  const env = environment(); const cookie = await login(env);
  assert.equal((await worker.fetch(request('/api/session', { cookie }), env)).status, 200);
});
test('tampered, expired and old-secret cookies fail', async () => {
  const env = environment(); const cookie = await login(env);
  const tampered = cookie.slice(0, -1) + (cookie.endsWith('a') ? 'b' : 'a');
  assert.equal((await worker.fetch(request('/api/session', { cookie: tampered }), env)).status, 401);
  const now = Date.now;
  try {
    Date.now = () => now() + 9 * 3600000;
    assert.equal((await worker.fetch(request('/api/session', { cookie }), env)).status, 401);
  } finally { Date.now = now; }
  env.PASSWORD_HASH = '12'.repeat(16);
  assert.equal((await worker.fetch(request('/api/session', { cookie }), env)).status, 401);
});
test('cross-origin and missing CSRF headers rejected', async () => {
  const env = environment();
  for (const headers of [{ Origin: 'https://evil.example' }, { 'X-Requested-With': '' }]) {
    assert.equal((await worker.fetch(request('/api/login', { method: 'POST', body: { password }, headers }), env)).status, 403);
  }
});
test('missing secrets and missing limiter fail closed; rate limit returns 429', async () => {
  const env = environment();
  const req = () => request('/api/login', { method: 'POST', body: { password } });
  assert.equal((await worker.fetch(req(), { login: 'private-notes' })).status, 503);
  env.LOGIN_RATE_LIMITER = undefined;
  assert.equal((await worker.fetch(req(), env)).status, 503);
  env.LOGIN_RATE_LIMITER = { limit: async () => ({ success: false }) };
  assert.equal((await worker.fetch(req(), env)).status, 429);
});
test('save/read roundtrip, invalid schema cannot overwrite data', async () => {
  const env = environment(); const cookie = await login(env);
  const data = { notes: [{ id: 'note1', title: '标题', content: '内容' }], novels: [] };
  assert.equal((await worker.fetch(request('/api/save-data', { method: 'POST', cookie, body: data }), env)).status, 200);
  for (const body of [{}, { notes: [{ id: "' onclick='", title: 'x', content: '' }], novels: [] }]) {
    assert.equal((await worker.fetch(request('/api/save-data', { method: 'POST', cookie, body }), env)).status, 400);
  }
  assert.deepEqual(await (await worker.fetch(request('/api/get-data', { cookie }), env)).json(), data);
});
test('oversized and non-JSON login rejected', async () => {
  const env = environment();
  assert.equal((await worker.fetch(request('/api/login', { method: 'POST', body: { password: 'x'.repeat(5000) } }), env)).status, 413);
  assert.equal((await worker.fetch(request('/api/login', { method: 'POST', body: {}, headers: { 'Content-Type': 'text/plain' } }), env)).status, 415);
});
test('logout clears browser cookie', async () => {
  const res = await worker.fetch(request('/api/logout', { method: 'POST' }), environment());
  assert.equal(res.status, 200); assert.match(res.headers.get('Set-Cookie'), /Max-Age=0/);
});
test('proxy enforces exact domain allowlist and rechecks redirects', async () => {
  const env = environment(); const cookie = await login(env);
  for (const target of ['http://127.0.0.1', 'https://example.com.evil.test', 'file:///etc/passwd', 'https://user:pass@example.com']) {
    assert.equal((await worker.fetch(request('/api/proxy?url=' + encodeURIComponent(target), { cookie }), env)).status, 403);
  }
  const original = globalThis.fetch; let calls = 0;
  try {
    globalThis.fetch = async () => { calls++; return new Response(null, { status: 302, headers: { Location: 'http://127.0.0.1' } }); };
    assert.equal((await worker.fetch(request('/api/proxy?url=https://example.com', { cookie }), env)).status, 403);
    assert.equal(calls, 1);
    globalThis.fetch = async () => new Response('<script>alert(1)</script>', { headers: { 'Content-Type': 'text/html' } });
    const res = await worker.fetch(request('/api/proxy?url=https://example.com', { cookie }), env);
    assert.equal(res.status, 200); assert.match(res.headers.get('Content-Type'), /^text\/plain/);
  } finally { globalThis.fetch = original; }
});


test('public pages never read KV, embed private scripts or reveal entrance', async () => {
  const env = environment();
  env.CLOUD_EDITOR_KV.get = async () => { throw new Error('public must not read KV'); };
  for (const path of ['/', '/wrong', '/login', '/private-notes-extra']) {
    const res = await worker.fetch(new Request('https://notes.example' + path), env);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.doesNotMatch(html, /private-notes|pwd-input|api\/|<script|PASSWORD|SESSION_SECRET/);
  }
  for (const path of ['/api/login', '/wrong/api/get-data']) {
    const res = await worker.fetch(new Request('https://notes.example' + path), env);
    assert.equal(res.status, 404);
  }
  const privatePage = await worker.fetch(request('/private-notes/'), env);
  assert.match(await privatePage.text(), /pwd-input/);
  assert.match(privatePage.headers.get('X-Robots-Tag'), /noindex/);
});

test('plaintext PASSWORD env is ignored; hash mode stays authoritative', async () => {
  const env = environment();
  env.PASSWORD = password;
  env.PASSWORD_HASH = '12'.repeat(16);
  assert.equal((await worker.fetch(request('/api/login', { method: 'POST', body: { password } }), env)).status, 401);
  env.PASSWORD_HASH = 'nothex';
  assert.equal((await worker.fetch(request('/api/login', { method: 'POST', body: { password } }), env)).status, 503);
});

test('save-data snapshots history with dedupe, force flag and version fetch', async () => {
  const env = environment(); const cookie = await login(env);
  const v1 = { notes: [{ id: 'n1', title: '一', content: '第一版' }], novels: [] };
  const v2 = { notes: [{ id: 'n1', title: '二', content: '第二版' }], novels: [] };
  assert.equal((await worker.fetch(request('/api/save-data', { method: 'POST', cookie, body: v1 }), env)).status, 200);
  assert.equal((await worker.fetch(request('/api/save-data', { method: 'POST', cookie, body: v1 }), env)).status, 200);
  const list = async () => (await (await worker.fetch(request('/api/history', { cookie }), env)).json()).items;
  assert.equal((await list()).length, 0);
  assert.equal((await worker.fetch(request('/api/save-data?history=force', { method: 'POST', cookie, body: v2 }), env)).status, 200);
  const items = await list();
  assert.equal(items.length, 1);
  assert.deepEqual(await (await worker.fetch(request('/api/history-item?ts=' + items[0].ts, { cookie }), env)).json(), v1);
  assert.equal((await worker.fetch(request('/api/history-item?ts=999', { cookie }), env)).status, 404);
  assert.equal((await worker.fetch(request('/api/history', {}), env)).status, 401);
});

test('changing login closes old path and invalidates cookies', async () => {
  const env = environment(); const cookie = await login(env);
  env.login = 'changed-entry';
  assert.equal((await worker.fetch(request('/api/session', {cookie}), env)).status, 404);
  const res = await worker.fetch(new Request('https://notes.example/changed-entry/api/session', {headers:{Cookie:cookie}}), env);
  assert.equal(res.status, 401);
  assert.doesNotMatch(await (await worker.fetch(request('/private-notes'), env)).text(), /pwd-input/);
  assert.match(await (await worker.fetch(request('/changed-entry'), env)).text(), /pwd-input/);
  for (const invalid of ['', '/', 'api', 'path/child', '../private']) {
    env.login = invalid;
    assert.doesNotMatch(await (await worker.fetch(request('/'), env)).text(), /pwd-input/);
  }
});
