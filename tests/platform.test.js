'use strict';
// Platform tests: request ids, audit log shape (no raw input), rate-limit buckets, API keys, batch, OpenAPI, errors, status.
const test = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const path = require('node:path');
const crypto = require('node:crypto');
const { safeEqual, createKeyStore } = require('../lib/apiKeys');
const { redact } = require('../lib/redact');
const { createLimiter, groupFor } = require('../lib/rateLimit');
const { detectInputType } = require('../lib/audit');

const PORT = process.env.TEST_PORT_PLATFORM || 8093;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = 's3cret-value';
const KEYS = JSON.stringify({ pilotkey: { secretHash: crypto.createHash('sha256').update(SECRET).digest('hex'), tier: 'pilot' } });
let server; let out = '';
const J = { 'content-type': 'application/json' };
const post = (p, b, h = {}) => fetch(BASE + p, { method: 'POST', headers: { ...J, ...h }, body: typeof b === 'string' ? b : JSON.stringify(b) });

test.before(async () => {
  server = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PORT: String(PORT), DISABLE_GEMINI: '1', DISABLE_THREAT_INTEL: '1', DISABLE_CLOUDFLARE_DNS: '1', INGEST_INPROCESS: '0',
      API_KEYS_JSON: KEYS, RL_CHECK_BURST: '6', RL_CHECK_PER_MIN: '1', RL_DOC_BURST: '2', RL_DOC_PER_MIN: '1', GIT_SHA: 'abcdef1234567', AUDIT_HMAC_SECRET: 'test-secret' },
    stdio: ['ignore', 'pipe', 'ignore']
  });
  server.stdout.on('data', d => { out += d; });
  for (let i = 0; i < 80; i++) { try { if ((await fetch(BASE + '/health')).ok) return; } catch { /* retry */ } await new Promise(r => setTimeout(r, 250)); }
  throw new Error('server did not start');
});
test.after(() => { if (server) server.kill(); });

test('unit: safeEqual is correct for equal, different and different-length strings', () => {
  assert.ok(safeEqual('abc', 'abc'));
  assert.ok(!safeEqual('abc', 'abd'));
  assert.ok(!safeEqual('abc', 'abcd'));
});
test('unit: key store auth', () => {
  const ks = createKeyStore(KEYS);
  assert.equal(ks.authenticate(undefined).keyId, null);
  assert.equal(ks.authenticate('pilotkey.' + SECRET).keyId, 'pilotkey');
  assert.equal(ks.authenticate('pilotkey.wrong').ok, false);
  assert.equal(ks.authenticate('nokey.' + SECRET).ok, false);
  assert.equal(ks.authenticate('garbage').ok, false);
});
test('unit: token bucket separates groups and refills', () => {
  let t = 0; const l = createLimiter({ groups: { check: { burst: 2, perMin: 60 }, doc: { burst: 1, perMin: 60 } }, now: () => t });
  assert.ok(l.consume('check', 'a').allowed); assert.ok(l.consume('check', 'a').allowed);
  const d = l.consume('check', 'a'); assert.ok(!d.allowed); assert.ok(d.retryAfterSec >= 1);
  assert.ok(l.consume('doc', 'a').allowed, 'other group unaffected');
  t = 1500; assert.ok(l.consume('check', 'a').allowed, 'refilled');
  assert.equal(groupFor('/api/gemini/advisor'), 'gemini'); assert.equal(groupFor('/api/health'), null);
});
test('unit: redact + detectInputType', () => {
  const r = redact('Call 9876543210 or a@b.com, pay x@okhdfc, PAN ABCDE1234F, Aadhaar 2345 6789 0123, card 4111 1111 1111 1111, your OTP is 482913');
  for (const raw of ['9876543210', 'a@b.com', 'x@okhdfc', 'ABCDE1234F', '2345 6789 0123', '4111 1111 1111 1111', '482913']) assert.ok(!r.includes(raw), raw + ' leaked: ' + r);
  assert.equal(detectInputType('abc@okaxis'), 'upi'); assert.equal(detectInputType('+91 98765 43210'), 'phone');
  assert.equal(detectInputType('https://x.example/p'), 'url'); assert.equal(detectInputType('you won a prize'), 'message');
});

test('requestId: generated, echoed in header and body; inbound id preserved', async () => {
  const r = await post('/api/emergency/digital-arrest-screen', {});
  const j = await r.json();
  assert.match(r.headers.get('x-request-id'), /^[0-9a-f-]{36}$/);
  assert.equal(j.requestId, r.headers.get('x-request-id'));
  assert.match(j.engineVersion, /^1\.0\.0\+abcdef123456$/);
  assert.equal(j.verdict, 'NO_SIGNALS_SELECTED', 'existing shape intact');
  const r2 = await post('/api/emergency/digital-arrest-screen', {}, { 'x-request-id': 'my-trace-id-0001' });
  assert.equal((await r2.json()).requestId, 'my-trace-id-0001');
});

test('audit: one JSON line per check, hashed input, no raw input or IP', async () => {
  const secretText = 'Your SBI KYC expires, share OTP 556677 urgently';
  const before = out.length;
  const r = await post('/api/scam/check', { text: secretText });
  assert.equal(r.status, 200);
  const rid = r.headers.get('x-request-id');
  await new Promise(r2 => setTimeout(r2, 300));
  const lines = out.slice(before).split('\n').filter(l => l.includes('"logType":"safemeai.audit"') && l.includes(rid));
  assert.equal(lines.length, 1);
  const a = JSON.parse(lines[0]);
  for (const k of ['timestamp', 'requestId', 'endpoint', 'apiKeyId', 'clientNetHash', 'inputType', 'inputHash', 'inputLength', 'verdict', 'riskScore', 'engineVersion', 'dataSources', 'latencyMs']) assert.ok(k in a, 'missing ' + k);
  assert.equal(a.apiKeyId, 'anon'); assert.equal(a.endpoint, '/api/scam/check'); assert.equal(a.inputType, 'message');
  assert.equal(a.inputHash, crypto.createHash('sha256').update(secretText).digest('hex'));
  assert.equal(a.inputLength, secretText.length);
  assert.ok('geminiUsed' in a.dataSources && 'threatStoreSnapshotTs' in a.dataSources);
  const blob = lines[0];
  assert.ok(!blob.includes('556677') && !blob.includes('SBI KYC'));
  assert.ok(!/127\.0\.0\.1|::1/.test(blob), 'raw IP in audit line');
  assert.match(a.clientNetHash, /^[0-9a-f]{24}$/);
});

test('error shapes: bad JSON, oversize, 404-safe', async () => {
  const bad = await post('/api/scam/check', '{"text": ');
  assert.equal(bad.status, 400); const bj = await bad.json();
  assert.equal(bj.code, 'BAD_JSON'); assert.equal(bj.error, 'Malformed JSON body'); assert.ok(!/position|token|Unexpected/i.test(JSON.stringify(bj)));
  const big = await post('/api/emergency/digital-arrest-screen', { x: 'a'.repeat(70 * 1024) });
  assert.equal(big.status, 413); const gj = await big.json();
  assert.equal(gj.code, 'PAYLOAD_TOO_LARGE'); assert.match(gj.error, /64 KB/);
});

test('API keys: invalid => 401, valid ok, anonymous ok', async () => {
  const bad = await post('/api/emergency/digital-arrest-screen', {}, { 'x-api-key': 'pilotkey.nope' });
  assert.equal(bad.status, 401); assert.equal((await bad.json()).code, 'INVALID_API_KEY');
  const good = await post('/api/emergency/digital-arrest-screen', {}, { 'x-api-key': 'pilotkey.' + SECRET });
  assert.equal(good.status, 200);
  const anon = await post('/api/emergency/digital-arrest-screen', {});
  assert.equal(anon.status, 200);
});

test('v1 aliases dispatch and OpenAPI is structurally valid', async () => {
  const k = { 'x-api-key': 'pilotkey.' + SECRET };
  const r = await post('/api/v1/check', { input: 'Dear customer your account is blocked, share OTP now' }, k);
  assert.equal(r.status, 200); const j = await r.json(); assert.equal(j.status, 'success'); assert.ok(j.data);
  const m = await post('/api/v1/message/check', { text: 'hello friend' }, k);
  assert.equal(m.status, 200);
  const spec = await (await fetch(BASE + '/api/v1/openapi.json')).json();
  assert.match(spec.openapi, /^3\.0/); assert.ok(spec.info.title && spec.info.version);
  for (const p of ['/api/v1/check', '/api/v1/domain/check', '/api/v1/message/check', '/api/v1/batch']) assert.ok(spec.paths[p].post.responses['200'], p);
  const html = await (await fetch(BASE + '/api/docs')).text();
  assert.ok(html.includes('/api/v1/batch') && !/<script|https?:\/\/cdn/i.test(html));
});

test('batch: limits and per-item results', async () => {
  const k = { 'x-api-key': 'pilotkey.' + SECRET };
  const tooMany = await post('/api/v1/batch', { items: Array.from({ length: 21 }, () => 'hi') }, k);
  assert.equal(tooMany.status, 400);
  assert.equal((await post('/api/v1/batch', { items: [] }, k)).status, 400);
  const r = await post('/api/v1/batch', { items: ['hello there', 'share your OTP immediately or account blocked', 42] }, k);
  assert.equal(r.status, 200); const j = await r.json();
  assert.equal(j.count, 3); assert.equal(j.quotaUnits, 2);
  assert.equal(j.results[0].httpStatus, 200); assert.ok(j.results[1].result);
  assert.equal(j.results[2].httpStatus, 400);
  assert.deepEqual(j.results.map(x => x.index), [0, 1, 2]);
});

test('rate limit: check bucket exhausts with 429 shape; other groups unaffected', async () => {
  // anonymous bucket: burst 6 (earlier anonymous check used 1)
  let last;
  for (let i = 0; i < 12; i++) { last = await post('/api/scam/check', { text: 'hello ' + i }); if (last.status === 429) break; }
  assert.equal(last.status, 429);
  const j = await last.json();
  assert.equal(j.code, 'RATE_LIMITED'); assert.ok(j.retryAfterSec >= 1); assert.ok(j.error);
  assert.ok(Number(last.headers.get('retry-after')) >= 1);
  assert.equal(last.headers.get('x-ratelimit-remaining'), '0');
  assert.equal(last.headers.get('x-ratelimit-group'), 'check');
  const dom = await post('/api/domain/check', {});         // same group => still limited
  assert.equal(dom.status, 429);
  const adv = await post('/api/gemini/advisor', { prompt: 'is this a scam digital arrest' });
  assert.equal(adv.status, 200, 'gemini bucket is separate');
  const ok = await post('/api/emergency/digital-arrest-screen', {});
  assert.equal(ok.status, 200, 'general bucket is separate');
});

test('health endpoints and system status shape', async () => {
  for (const p of ['/health', '/api/health']) { const j = await (await fetch(BASE + p)).json(); assert.equal(j.status, 'ok'); }
  const r = await fetch(BASE + '/api/system/status'); const j = await r.json();
  assert.equal(j.services.cloudRun.live, true);
  for (const k of ['vertexGemini', 'webRisk', 'documentAI', 'bigQuery', 'threatStore', 'auditSink']) assert.ok(j.services[k], k);
  assert.equal(j.services.documentAI.configured, false);
  assert.equal(j.services.auditSink.bigQuery, false);
  assert.equal(typeof j.services.threatStore.ready, 'boolean');
  assert.ok(!/secret|key|token/i.test(Object.keys(j.services.webRisk).join()));
});

test('startup banner is one JSON line without secrets', () => {
  const l = out.split('\n').find(x => x.includes('"message":"startup"'));
  assert.ok(l); const b = JSON.parse(l);
  assert.equal(b.engineVersion, '1.0.0+abcdef123456'); assert.equal(b.vertexLocation, 'asia-south1');
  assert.ok(!l.includes(SECRET) && !l.includes('test-secret'));
});
