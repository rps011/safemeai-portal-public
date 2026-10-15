'use strict';
// Digital Arrest Panic Check must be graded: every additional answer changes the result (regression: any single "yes" used to lock 100%).
const test = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const path = require('node:path');

const PORT = process.env.TEST_PORT_PANIC || 8092;
const BASE = `http://127.0.0.1:${PORT}`;
let server;
const post = async b => (await fetch(`${BASE}/api/emergency/digital-arrest-screen`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })).json();

test.before(async () => {
  server = spawn(process.execPath, ['server.js'], { cwd: path.join(__dirname, '..'), env: { ...process.env, PORT: String(PORT), DISABLE_GEMINI: '1', DISABLE_THREAT_INTEL: '1' }, stdio: 'ignore' });
  for (let i = 0; i < 60; i++) { try { await post({}); return; } catch { await new Promise(r => setTimeout(r, 250)); } }
  throw new Error('server did not start');
});
test.after(() => { if (server) server.kill(); });

test('no answers => low, not a scam verdict', async () => {
  const r = await post({});
  assert.equal(r.verdict, 'NO_SIGNALS_SELECTED'); assert.ok(r.certainty < 20);
});
test('certainty rises with each additional yes', async () => {
  const keys = ['isUniformOrAgency', 'isContrabandOrPMLA', 'isCoerciveSurveillance', 'isMoneyDemand'];
  const seen = [];
  for (let n = 0; n <= 4; n++) {
    const body = {}; keys.slice(0, n).forEach(k => { body[k] = true; });
    seen.push((await post(body)).certainty);
  }
  for (let i = 1; i < seen.length; i++) assert.ok(seen[i] > seen[i - 1], `step ${i} did not increase: ${seen}`);
});
test('every single signal alone is flagged (contraband-only used to be ignored)', async () => {
  for (const k of ['isUniformOrAgency', 'isContrabandOrPMLA', 'isCoerciveSurveillance', 'isMoneyDemand', 'isAskingSensitiveInfo', 'isAppOrVideoMove']) {
    const r = await post({ [k]: true });
    assert.equal(r.verdict, 'SUSPICIOUS_SIGNAL', k); assert.ok(r.certainty >= 50, k);
  }
});
test('money plus another signal is confirmed; 2 non-money signals are likely', async () => {
  assert.equal((await post({ isUniformOrAgency: true, isMoneyDemand: true })).verdict, 'CONFIRMED_DIGITAL_ARREST_CRIME');
  assert.equal((await post({ isUniformOrAgency: true, isCoerciveSurveillance: true })).verdict, 'LIKELY_DIGITAL_ARREST_SCAM');
});
test('new signals (OTP/Aadhaar request, app install / video move) count in the graded logic', async () => {
  const a = await post({ isAskingSensitiveInfo: true });
  assert.equal(a.signalCount, 1); assert.equal(a.verdict, 'SUSPICIOUS_SIGNAL');
  const b = await post({ isAskingSensitiveInfo: true, isAppOrVideoMove: true });
  assert.equal(b.signalCount, 2); assert.equal(b.verdict, 'LIKELY_DIGITAL_ARREST_SCAM'); assert.ok(b.certainty > a.certainty);
  const c = await post({ isAppOrVideoMove: true, isMoneyDemand: true });
  assert.equal(c.verdict, 'CONFIRMED_DIGITAL_ARREST_CRIME');
  const all = await post({ isUniformOrAgency: true, isContrabandOrPMLA: true, isCoerciveSurveillance: true, isMoneyDemand: true, isAskingSensitiveInfo: true, isAppOrVideoMove: true });
  assert.equal(all.signalCount, 6); assert.equal(all.certainty, 100);
});
test('ignores non-boolean junk', async () => {
  const r = await post({ isMoneyDemand: 'yes', isUniformOrAgency: 1 });
  assert.equal(r.verdict, 'NO_SIGNALS_SELECTED');
});
