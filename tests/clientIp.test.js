'use strict';
const test = require('node:test');
const assert = require('node:assert');
process.env.NODE_ENV = 'test';
const { clientIp, isGoogleIp } = require('../lib/clientIp');
const req = (h, ip) => ({ headers: h, ip });

test('behind Firebase Hosting the real visitor comes from Fastly-Client-IP', () => {
  const r = req({ via: '1.1 Firebase Hosting', 'fastly-client-ip': '203.0.113.9', 'x-forwarded-for': '203.0.113.9,66.249.82.70' }, '66.249.82.70');
  assert.equal(clientIp(r), '203.0.113.9');
});
test('a direct caller cannot spoof the header (last hop is not Google)', () => {
  const r = req({ via: '1.1 Firebase Hosting', 'fastly-client-ip': '6.6.6.6', 'x-forwarded-for': '6.6.6.6,198.51.100.7' }, '198.51.100.7');
  assert.equal(clientIp(r), '198.51.100.7');
});
test('without the Via header the header is ignored even from a Google hop', () => {
  const r = req({ 'fastly-client-ip': '6.6.6.6', 'x-forwarded-for': 'x,66.249.82.70' }, '66.249.82.70');
  assert.equal(clientIp(r), '66.249.82.70');
});
test('garbage Fastly-Client-IP is ignored', () => {
  const r = req({ via: '1.1 Firebase Hosting', 'fastly-client-ip': 'not-an-ip', 'x-forwarded-for': 'a,66.249.82.70' }, '66.249.82.70');
  assert.equal(clientIp(r), '66.249.82.70');
});
test('google range check', () => { assert.ok(isGoogleIp('66.249.82.70')); assert.ok(!isGoogleIp('198.51.100.7')); });
