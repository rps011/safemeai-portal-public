'use strict';
/**
 * Regression benchmark: the 119-case bank-UAT corpus (tests/fixtures/benchmark.json) run against the local engines with a
 * mocked, deterministic network. Prints a confusion matrix and asserts the accuracy gates:
 *   - zero scams SAFE/LOW (messages must reach HIGH/CRITICAL; malicious domains must reach HIGH/CRITICAL)
 *   - <= 1 of the genuine messages above LOW
 *   - 0 legitimate domains CRITICAL/HIGH (and none above LOW)
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { createWorld, runDomain, runMessage } = require('./helpers/benchWorld');
const corpus = require('./fixtures/benchmark.json').cases;

const world = createWorld();
const results = [];
test.before(async () => {
  world.install();
  for (const c of corpus) {
    const r = c.kind === 'domain' ? await runDomain(world, c.input) : await runMessage(world, c.input);
    results.push({ ...c, ...r });
  }
});
test.after(() => world.restore());

const bucket = (lvl) => (lvl === 'SAFE' || lvl === 'LOW') ? 'SAFE/LOW' : ((lvl === 'MEDIUM' || lvl === 'MODERATE') ? 'MEDIUM' : 'HIGH/CRIT');

function matrix(kind) {
  const m = { legit: { 'SAFE/LOW': 0, MEDIUM: 0, 'HIGH/CRIT': 0 }, scam: { 'SAFE/LOW': 0, MEDIUM: 0, 'HIGH/CRIT': 0 } };
  for (const r of results.filter(x => x.kind === kind)) m[r.malicious ? 'scam' : 'legit'][bucket(r.level)]++;
  return m;
}

test('corpus has the full 119 cases', () => { assert.equal(corpus.length, 119); });

test('benchmark: confusion matrix + gates', () => {
  const lines = [];
  for (const kind of ['message', 'domain']) {
    const m = matrix(kind);
    lines.push(`\n  ${kind.toUpperCase()}S (rows = truth, cols = verdict)`);
    lines.push('               SAFE/LOW   MEDIUM   HIGH/CRIT');
    for (const row of ['legit', 'scam']) lines.push(`    ${row.padEnd(8)}   ${String(m[row]['SAFE/LOW']).padStart(6)}   ${String(m[row].MEDIUM).padStart(6)}   ${String(m[row]['HIGH/CRIT']).padStart(8)}`);
  }
  console.log(lines.join('\n'));

  const detail = (r) => `${r.level}/${r.score} ${JSON.stringify(r.input.slice(0, 80))} [${r.verdict}]`;
  const scamMsgLow = results.filter(r => r.kind === 'message' && r.malicious && bucket(r.level) !== 'HIGH/CRIT');
  assert.deepEqual(scamMsgLow.map(detail), [], 'every scam message must reach HIGH/CRITICAL');
  const scamDomLow = results.filter(r => r.kind === 'domain' && r.malicious && bucket(r.level) !== 'HIGH/CRIT');
  assert.deepEqual(scamDomLow.map(detail), [], 'every malicious domain must reach HIGH/CRITICAL');
  const genuineMsgHigh = results.filter(r => r.kind === 'message' && !r.malicious && bucket(r.level) !== 'SAFE/LOW');
  assert.ok(genuineMsgHigh.length <= 1, 'at most 1 genuine message above LOW: ' + genuineMsgHigh.map(detail).join(' | '));
  const legitDomHigh = results.filter(r => r.kind === 'domain' && !r.malicious && bucket(r.level) !== 'SAFE/LOW');
  assert.deepEqual(legitDomHigh.map(detail), [], 'legitimate domains must be SAFE/LOW');
});

// Every case is also its own named regression test (so a failure points at the exact corpus entry).
for (const [i, c] of corpus.entries()) {
  test(`benchmark #${String(i).padStart(3, '0')} ${c.kind} ${c.malicious ? 'SCAM ' : 'LEGIT'} ${JSON.stringify(c.input.slice(0, 60))}`, () => {
    const r = results[i];
    assert.ok(r, 'no result');
    if (c.malicious) assert.equal(bucket(r.level), 'HIGH/CRIT', `${r.level}/${r.score} ${r.verdict}`);
    else if (c.kind === 'message') assert.equal(bucket(r.level), 'SAFE/LOW', `${r.level}/${r.score} ${r.verdict} ${JSON.stringify(r.flags)}`);
    else assert.equal(bucket(r.level), 'SAFE/LOW', `${r.level}/${r.score} ${r.verdict}`);
  });
}
