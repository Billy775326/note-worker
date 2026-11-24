import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import worker from '../worker.js';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const encoder = new TextEncoder();
const hex = bytes => Buffer.from(bytes).toString('hex');
const origin = 'https://notes.example';

async function fixture(initial = { notes: [], novels: [] }) {
  const store = new Map([['user_creative_data', JSON.stringify(initial)]]);
  const writes = [];
  const env = {
    login: 'sample-entry', PASSWORD_HASH: 'test-only-password', PASSWORD_SALT: 'test-only-salt',
    SESSION_SECRET: 'test-only-session-secret', LOGIN_RATE_LIMITER: { limit: async () => ({ success: true }) },
    CLOUD_EDITOR_KV: {
      get: async key => store.get(key) ?? null,
      put: async (key, value) => { writes.push(key); store.set(key, value); }
    }
  };
  // Produce a real signed session using the existing public session contract.
  const material = JSON.stringify([env.SESSION_SECRET, env.PASSWORD_SALT, env.PASSWORD_HASH, '/' + env.login]);
  const key = await crypto.subtle.importKey('raw', await crypto.subtle.digest('SHA-256', encoder.encode(material)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const payload = `${Math.floor(Date.now() / 1000) + 3600}.${'ab'.repeat(32)}`;
  const signature = hex(await crypto.subtle.sign('HMAC', key, encoder.encode(payload)));
  const cookie = `__Host-note_session=${payload}.${signature}`;
  const call = (path = '', method = 'GET', body, headers = {}) => worker.fetch(new Request(origin + '/' + env.login + '/api/notes' + path, {
    method,
    headers: { Cookie: cookie, Origin: origin, 'X-Requested-With': 'note-editor', 'Content-Type': 'application/json', ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  }), env);
  return { env, store, writes, cookie, call };
}

test('create, list, search, detail, patch and delete preserve unrelated data and history', async () => {
  const original = { notes: [{ id: 'old', title: '旧笔记', content: 'keep', custom: 1 }], novels: [{ id: 'novel', title: '故事', type: 'short', content: '保留' }], customRoot: true };
  const { call, store } = await fixture(original);
  const created = await call('', 'POST', { title: ' 新笔记 ', content: '| A | B |\n| --- | --- |', pinned: true });
  assert.equal(created.status, 201);
  const { note } = await created.json();
  assert.match(note.id, /^[a-zA-Z0-9_-]+$/);
  assert.equal(note.title, '新笔记'); assert.equal(note.pinned, true);
  assert.equal(created.headers.get('Location'), '/sample-entry/api/notes/' + note.id);
  assert.equal(typeof note.createdAt, 'number');
  assert.deepEqual((await (await call('/' + note.id)).json()).note, note);
  const listed = await (await call('?q=' + encodeURIComponent('新笔记') + '&limit=1&offset=0')).json();
  assert.equal(listed.total, 1); assert.equal(listed.notes[0].id, note.id);
  assert.equal((await (await call('?q=KEEP')).json()).total, 1);
  assert.equal((await (await call('?offset=100')).json()).notes.length, 0);
  const patched = await call('/' + note.id, 'PATCH', { content: '', pinned: false });
  assert.equal(patched.status, 200);
  const updated = (await patched.json()).note;
  assert.equal(updated.content, ''); assert.equal(updated.pinned, false);
  assert.equal(updated.title, note.title); assert.equal(updated.createdAt, note.createdAt);
  assert.ok(updated.updatedAt >= note.updatedAt);
  const oldPatch = await call('/old', 'PATCH', { title: '改名' });
  assert.equal((await oldPatch.json()).note.custom, 1);
  assert.equal((await call('/' + note.id, 'DELETE')).status, 200);
  assert.equal((await call('/' + note.id)).status, 404);
  assert.equal((await call('/' + note.id, 'DELETE')).status, 404);
  const saved = JSON.parse(store.get('user_creative_data'));
  assert.deepEqual(saved.novels, original.novels); assert.equal(saved.customRoot, true);
  assert.deepEqual(JSON.parse(JSON.parse(store.get('user_creative_history'))[0].data), original);
});

test('write payload validation cannot change the existing document', async () => {
  const { call, store, writes, cookie, env } = await fixture({ notes: [{ id: 'one', title: 'One', content: 'text' }], novels: [] });
  const before = store.get('user_creative_data');
  for (const body of [null, [], {}, { title: '' }, { title: ' ' }, { title: 1 }, { content: null }, { pinned: 'true' }, { id: 'other' }, { updatedAt: 0 }, { extra: 1 }]) {
    assert.equal((await call('/one', 'PATCH', body)).status, 400, JSON.stringify(body));
  }
  assert.equal((await call('', 'POST', { content: 'missing title' })).status, 400);
  assert.equal((await call('', 'POST', { title: 'ok' }, { 'Content-Type': 'text/plain' })).status, 415);
  const invalidJson = await worker.fetch(new Request(origin + '/sample-entry/api/notes', { method: 'POST', headers: { Cookie: cookie, Origin: origin, 'X-Requested-With': 'note-editor', 'Content-Type': 'application/json' }, body: '{' }), env);
  assert.equal(invalidJson.status, 400);
  assert.equal(store.get('user_creative_data'), before); assert.equal(writes.length, 0);
});

test('pagination and methods return explicit errors', async () => {
  const { call } = await fixture();
  for (const query of ['limit=0', 'limit=201', 'offset=-1', 'limit=1.5', 'offset=NaN', 'offset=9007199254740992']) {
    assert.equal((await call('?' + query)).status, 400, query);
  }
  const res = await call('', 'PUT', {});
  assert.equal(res.status, 405); assert.equal(res.headers.get('Allow'), 'GET, POST');
  assert.equal((await call('/invalid/path')).status, 404);
  for (const method of ['GET', 'PATCH', 'DELETE']) assert.equal((await call('/missing', method, method === 'PATCH' ? { title: 'x' } : undefined)).status, 404);
});

test('authentication, private entrance and CSRF headers apply to all CRUD writes', async () => {
  const { call, env } = await fixture();
  for (const method of ['GET', 'POST', 'PATCH', 'DELETE']) {
    assert.equal((await call('', method, method === 'POST' || method === 'PATCH' ? { title: 'x' } : undefined, { Cookie: '' })).status, 401);
  }
  for (const method of ['POST', 'PATCH', 'DELETE']) {
    assert.equal((await call('', method, method !== 'DELETE' ? {} : undefined, { Origin: 'https://other.example' })).status, 403);
    assert.equal((await call('', method, method !== 'DELETE' ? {} : undefined, { 'X-Requested-With': '' })).status, 403);
  }
  assert.equal((await worker.fetch(new Request(origin + '/api/notes'), env)).status, 404);
});

test('corrupt data and storage errors fail without resetting the library', async () => {
  const { call, store, writes, env } = await fixture();
  for (const corrupt of ['{', '{"notes":[],"novels":null}']) {
    store.set('user_creative_data', corrupt);
    assert.equal((await call('', 'POST', { title: 'x' })).status, 500);
    assert.equal(store.get('user_creative_data'), corrupt);
  }
  assert.equal(writes.length, 0);
  env.CLOUD_EDITOR_KV.get = async () => { throw new Error('test failure'); };
  assert.equal((await call()).status, 500);
});

test('failed data writes return errors and old full-library endpoints remain compatible', async () => {
  const { env, cookie, store, call } = await fixture();
  const created = (await (await call('', 'POST', { title: 'test', content: 'body' })).json()).note;
  const req = (method, path, body) => new Request(origin + '/sample-entry/api/' + path, {
    method, headers: { Cookie: cookie, Origin: origin, 'X-Requested-With': 'note-editor', 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const full = await worker.fetch(req('GET', 'get-data'), env);
  assert.equal(full.status, 200);
  const data = await full.json();
  assert.equal(data.notes[0].id, created.id);
  data.notes[0].content = 'legacy save';
  assert.equal((await worker.fetch(req('POST', 'save-data', data), env)).status, 200);
  assert.equal((await (await call('/' + created.id)).json()).note.content, 'legacy save');
  const before = store.get('user_creative_data');
  const put = env.CLOUD_EDITOR_KV.put;
  env.CLOUD_EDITOR_KV.put = async (key, value) => {
    if (key === 'user_creative_data') throw new Error('simulated write failure');
    return put(key, value);
  };
  assert.equal((await call('/' + created.id, 'PATCH', { content: 'must not claim success' })).status, 500);
  assert.equal(store.get('user_creative_data'), before);
});

test('empty KV can create notes; request and document size are bounded', async () => {
  const { call, store, writes } = await fixture();
  store.clear();
  assert.equal((await call('', 'POST', { title: 'first' })).status, 201);
  const before = store.get('user_creative_data'); const count = writes.length;
  assert.equal((await call('', 'POST', { title: 'large', content: 'x'.repeat(20 * 1024 * 1024) })).status, 413);
  assert.equal(store.get('user_creative_data'), before); assert.equal(writes.length, count);
  const huge = { notes: [{ id: 'large', title: 'large', content: 'x'.repeat(20 * 1024 * 1024) }], novels: [] };
  store.set('user_creative_data', JSON.stringify(huge));
  assert.equal((await call('', 'POST', { title: 'another' })).status, 413);
  assert.equal(writes.length, count);
});
