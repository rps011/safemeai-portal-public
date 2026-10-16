#!/usr/bin/env node
/*
 * Held-out evaluation runner for SafeMeAI (black box, HTTP only; imports no engine code).
 *
 *   node tests/eval/run-eval.js --target https://safemeai.in --label live-gemini \
 *        --out tests/eval/results-live.json [--pace 2500] [--docpace 10500]
 *   node tests/eval/run-eval.js --report-only tests/eval/results-live.json [--baseline tests/eval/results-local.json]
 *
 * Phase 1 (collect) stores the raw API responses; phase 2 (report) computes metrics from them and writes them
 * into the same file under "metrics". Re-running phase 2 never calls the network.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const arg = (n, d) => { const i = process.argv.indexOf('--' + n); return i > -1 ? process.argv[i + 1] : d; };
const DATA_FILE = path.join(__dirname, 'fresh.json');
const RES = (() => { try { return JSON.parse(fs.readFileSync(path.join(__dirname, 'resolution.json'), 'utf8')); } catch (_) { return {}; } })();
const ORD = { SAFE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function levelOf(rec) {
  if (rec.level && ORD[rec.level] !== undefined) return rec.level;
  const s = rec.score;
  if (s == null) return null;
  return s >= 80 ? 'CRITICAL' : s >= 60 ? 'HIGH' : s >= 40 ? 'MEDIUM' : s >= 20 ? 'LOW' : 'SAFE';
}
const isFlagged = (r) => r.ok && (r.level === 'HIGH' || r.level === 'CRITICAL');
const ordOf = (r) => (r.ok ? (ORD[r.level] ?? 0) : null);

// ---------------------------------------------------------------- collect
async function post(target, route, body, headers) {
  for (let attempt = 0; attempt < 12; attempt++) {
    const t0 = process.hrtime.bigint();
    let res, txt;
    try {
      res = await fetch(target + route, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
      txt = await res.text();
    } catch (e) { await sleep(3000); continue; }
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    if (res.status === 429) {
      const ra = Number(res.headers.get('retry-after')) || 10;
      await sleep((ra + 1) * 1000);
      continue; // 429 is never a result
    }
    let json = null; try { json = JSON.parse(txt); } catch (_) {}
    return { status: res.status, ms, json, retries: attempt };
  }
  return { status: 0, ms: 0, json: null, retries: 12 };
}

function sliceMsg(d) {
  return { score: d.riskScore, level: d.riskLevel, scamType: d.scamType, engine: d.analysisEngine, headline: d.headline, flags: d.flags, data: d };
}
function sliceDom(d) {
  return { score: d.riskScore, level: d.riskLevel, verdict: d.verdict, headline: d.headline, flags: d.flags, data: d };
}
function sliceDoc(j) {
  const a = j.analysis || {};
  return { score: a.riskScore, level: a.severity, verdict: a.verdict, authenticity: a.authenticityScore, signals: a.signals, data: j };
}

async function collect() {
  const target = arg('target').replace(/\/$/, '');
  const label = arg('label', 'run');
  const out = arg('out');
  const pace = Number(arg('pace', 2500));
  const docpace = Number(arg('docpace', 10500));
  const raw = fs.readFileSync(DATA_FILE);
  const ds = JSON.parse(raw);
  const results = { meta: { label, target, startedAt: new Date().toISOString(), datasetSha256: crypto.createHash('sha256').update(raw).digest('hex'), pace, docpace, note: arg('note', '') }, messages: [], domains: [], documents: [] };

  const checkStream = async () => {
    for (const m of ds.messages) {
      const r = await post(target, '/api/scam/check', { text: m.text }, {});
      const d = r.json && r.json.data;
      results.messages.push({ id: m.id, ms: r.ms, http: r.status, retries: r.retries, ok: !!d, ...(d ? sliceMsg(d) : {}) });
      process.stdout.write(`\rmsg ${results.messages.length}/${ds.messages.length}   `);
      await sleep(pace);
    }
    for (const m of ds.domains) {
      const r = await post(target, '/api/domain/check', { url: m.input }, {});
      const d = r.json && r.json.data;
      results.domains.push({ id: m.id, ms: r.ms, http: r.status, retries: r.retries, ok: !!d, ...(d ? sliceDom(d) : {}) });
      process.stdout.write(`\rdom ${results.domains.length}/${ds.domains.length}   `);
      await sleep(pace);
    }
  };
  const docStream = async () => {
    for (const m of ds.documents) {
      const r = await post(target, '/api/document-ai/analyze', { customText: m.text }, {});
      const j = r.json;
      results.documents.push({ id: m.id, ms: r.ms, http: r.status, retries: r.retries, ok: !!(j && j.analysis), ...(j && j.analysis ? sliceDoc(j) : {}) });
      await sleep(docpace);
    }
  };
  await Promise.all([checkStream(), docStream()]);
  results.meta.finishedAt = new Date().toISOString();
  for (const k of ['messages', 'domains', 'documents']) {
    const order = new Map(ds[k].map((x, i) => [x.id, i]));
    results[k].sort((a, b) => order.get(a.id) - order.get(b.id));
    results[k].forEach((r) => { if (r.ok) r.level = levelOf(r); });
  }
  fs.writeFileSync(out, JSON.stringify(results));
  console.log('\nraw results written to', out);
  return out;
}

// ---------------------------------------------------------------- stats
function wilson(k, n, z = 1.96) {
  if (!n) return [null, null];
  const p = k / n, d = 1 + (z * z) / n;
  const c = (p + (z * z) / (2 * n)) / d;
  const h = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / d;
  return [Math.max(0, c - h), Math.min(1, c + h)];
}
const ratio = (k, n) => ({ k, n, value: n ? k / n : null, ci95: wilson(k, n) });
function pct(arr, p) { if (!arr.length) return null; const s = [...arr].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)]; }

function confusion(cases, pos, flaggedFn) {
  let tp = 0, fp = 0, tn = 0, fn = 0, missedBelowMedium = 0, negMediumPlus = 0, nPos = 0, nNeg = 0, failed = 0;
  for (const c of cases) {
    if (!c.res.ok) { failed++; continue; }
    const f = flaggedFn(c.res), isPos = c.label === pos;
    if (isPos) { nPos++; f ? tp++ : fn++; if (ordOf(c.res) < 2) missedBelowMedium++; }
    else { nNeg++; f ? fp++ : tn++; if (ordOf(c.res) >= 2) negMediumPlus++; }
  }
  const prec = tp + fp ? tp / (tp + fp) : null, rec = nPos ? tp / nPos : null;
  return {
    n: cases.length, failedCalls: failed, tp, fp, tn, fn,
    precision: ratio(tp, tp + fp), recall: ratio(tp, nPos), fpr: ratio(fp, nNeg), missRate: ratio(fn, nPos),
    f1: prec != null && rec != null && prec + rec ? (2 * prec * rec) / (prec + rec) : null,
    accuracy: ratio(tp + tn, tp + tn + fp + fn),
    scamBelowMedium_lossOfFundsMiss: ratio(missedBelowMedium, nPos),
    genuineHighOrCritical_cxIncident: ratio(fp, nNeg),
    genuineMediumOrAbove: ratio(negMediumPlus, nNeg),
  };
}
function breakdown(cases, pos, keyFn, flaggedFn) {
  const g = {};
  for (const c of cases) { const k = keyFn(c); if (k == null) continue; (g[k] = g[k] || []).push(c); }
  const out = {};
  for (const [k, arr] of Object.entries(g)) {
    const p = arr.filter((c) => c.label === pos && c.res.ok), n = arr.filter((c) => c.label !== pos && c.res.ok);
    out[k] = {
      positives: p.length, flaggedPositives: p.filter((c) => flaggedFn(c.res)).length,
      recall: p.length ? ratio(p.filter((c) => flaggedFn(c.res)).length, p.length) : null,
      negatives: n.length, flaggedNegatives: n.filter((c) => flaggedFn(c.res)).length,
      fpr: n.length ? ratio(n.filter((c) => flaggedFn(c.res)).length, n.length) : null,
    };
  }
  return out;
}

// Gemini involvement detection from the engine string (documented in EVALUATION.md after inspecting responses).
function geminiTouched(r) {
  const e = (r.engine || '').toLowerCase();
  if (!e) return false;
  if (/deterministic/.test(e) && !/gemini|ai second opinion applied|escalat|de-?escalat|adjust/.test(e)) return false;
  return /gemini|ai (second|review)|escalat|de-?escalat|adjust/.test(e);
}

function report(file, baselineFile) {
  const res = JSON.parse(fs.readFileSync(file, 'utf8'));
  const ds = JSON.parse(fs.readFileSync(DATA_FILE));
  const base = baselineFile ? JSON.parse(fs.readFileSync(baselineFile, 'utf8')) : null;
  const join = (kind, set) => {
    const byId = new Map(res[kind].map((r) => [r.id, r]));
    return set.map((c) => ({ ...c, res: byId.get(c.id) || { ok: false } }));
  };
  const msgs = join('messages', ds.messages), doms = join('domains', ds.domains), docs = join('documents', ds.documents);
  const flag = isFlagged;
  const M = {};
  M.messages = { overall: confusion(msgs, 'scam', flag), byCategory: breakdown(msgs, 'scam', (c) => c.cat, flag), byLanguage: breakdown(msgs, 'scam', (c) => c.lang, flag), byHard: breakdown(msgs.filter((c) => c.label === 'scam'), 'scam', (c) => (c.hard ? 'hard(no-trigger/non-English/obfuscated)' : 'classic'), flag), tricky: confusion(msgs.filter((c) => c.label === 'scam' || c.tricky), 'scam', flag), byObfuscation: breakdown(msgs.filter((c) => c.label === 'scam'), 'scam', (c) => (c.obf === 'none' ? 'plain' : 'obfuscated:' + c.obf), flag) };
  const exists = (c) => c.label === 'legit' || RES[c.id] === true;
  M.domains = { overall: confusion(doms, 'malicious', flag), byCategory: breakdown(doms, 'malicious', (c) => c.cat, flag),
    maliciousExistingPlusLegit: confusion(doms.filter((c) => exists(c)), 'malicious', flag),
    maliciousNonExistingPlusLegit: confusion(doms.filter((c) => c.label === 'legit' || !exists(c)), 'malicious', flag),
    byTier: breakdown(doms.filter((c) => c.label === 'legit'), 'malicious', (c) => c.cat, flag) };
  M.documents = { overall: confusion(docs, 'forged', flag), byCategory: breakdown(docs, 'forged', (c) => c.cat, flag) };
  M.combinedMessagesAndDomains = confusion([...msgs.map((c) => ({ ...c, label: c.label === 'scam' ? 'P' : 'N' })), ...doms.map((c) => ({ ...c, label: c.label === 'malicious' ? 'P' : 'N' }))], 'P', flag);

  const lat = (arr) => { const v = arr.filter((r) => r.ok).map((r) => r.ms); return { n: v.length, p50: pct(v, 50), p95: pct(v, 95), max: Math.max(...v) }; };
  M.latencyMs = { messages: lat(res.messages), domains: lat(res.domains), documents: lat(res.documents) };
  M.rateLimitRetries = [...res.messages, ...res.domains, ...res.documents].reduce((a, r) => a + (r.retries || 0), 0);
  M.failedCalls = [...res.messages, ...res.domains, ...res.documents].filter((r) => !r.ok).map((r) => r.id);

  // Gemini engine strings seen (messages) and involvement
  const engines = {};
  for (const r of res.messages) if (r.ok) engines[r.engine] = (engines[r.engine] || 0) + 1;
  M.messageEngineStrings = engines;
  const act = (r) => { const m = (r.engine || '').match(/second opinion \((escalated|de-escalated|agrees|not applied)\)/); return m ? m[1] : null; };
  const gem = {};
  for (const c of msgs) {
    if (!c.res.ok) continue;
    const a = act(c.res); if (!a) continue;
    (gem[a] = gem[a] || []).push({ id: c.id, truth: c.label, score: c.res.score, level: c.res.level, flagged: flag(c.res), outcomeCorrect: flag(c.res) === (c.label === 'scam') });
  }
  M.geminiOnMessages = { consultedCases: Object.values(gem).reduce((a, v) => a + v.length, 0), byAction: gem };
  const domG = doms.filter((c) => c.res.ok && (c.res.flags || []).some((x) => /Gemini/i.test(x)));
  M.geminiOnDomains = domG.map((c) => ({ id: c.id, truth: c.label, score: c.res.score, level: c.res.level, flagged: flag(c.res), outcomeCorrect: flag(c.res) === (c.label === 'malicious') }));

  // Ablation vs baseline (local rules-only): per-case outcome changes
  if (base) {
    const bm = new Map([...base.messages, ...base.domains, ...base.documents].map((r) => [r.id, r]));
    const rows = [];
    for (const [kind, set, pos] of [['messages', msgs, 'scam'], ['domains', doms, 'malicious'], ['documents', docs, 'forged']]) {
      for (const c of set) {
        const b = bm.get(c.id); if (!b || !b.ok || !c.res.ok) continue;
        const fa = flag(b), fb = flag(c.res), isPos = c.label === pos;
        if (fa !== fb) rows.push({ id: c.id, kind, truth: c.label, baselineScore: b.score, baselineLevel: b.level, runScore: c.res.score, runLevel: c.res.level, direction: fb ? 'flag-gained' : 'flag-lost', changeWasCorrect: fb === isPos });
      }
    }
    M.vsBaseline = { baselineLabel: base.meta.label, flagChanges: rows, netCorrect: rows.filter((r) => r.changeWasCorrect).length, netWrong: rows.filter((r) => !r.changeWasCorrect).length };
    const mk = (r) => ({ ...r });
    M.baselineMetrics = {
      messages: confusion(join.call(null, 'messages', ds.messages).map((c) => ({ ...c, res: (base.messages.find((x) => x.id === c.id)) || { ok: false } })), 'scam', flag),
      domains: confusion(ds.domains.map((c) => ({ ...c, res: base.domains.find((x) => x.id === c.id) || { ok: false } })), 'malicious', flag),
      documents: confusion(ds.documents.map((c) => ({ ...c, res: base.documents.find((x) => x.id === c.id) || { ok: false } })), 'forged', flag),
    };
  }

  // Every error
  const errors = [];
  const add = (kind, set, pos) => {
    for (const c of set) {
      if (!c.res.ok) { errors.push({ id: c.id, kind, type: 'CALL_FAILED' }); continue; }
      const f = flag(c.res), isPos = c.label === pos;
      if (f !== isPos) errors.push({ id: c.id, kind, type: isPos ? 'MISS (false negative)' : 'FALSE ALARM (false positive)', cat: c.cat, expected: c.label, actualLevel: c.res.level, actualScore: c.res.score, engine: c.res.engine, verdict: c.res.verdict, input: c.text || c.input, topFlags: (c.res.flags || []).slice(0, 4), rootCause: '' });
      else if (isPos && ordOf(c.res) === 2) errors.push({ id: c.id, kind, type: 'WEAK (flagged-not, rated MEDIUM)', cat: c.cat, expected: c.label, actualLevel: c.res.level, actualScore: c.res.score, input: c.text || c.input });
    }
  };
  add('messages', msgs, 'scam'); add('domains', doms, 'malicious'); add('documents', docs, 'forged');
  M.errors = errors;
  res.metrics = M;
  fs.writeFileSync(file, JSON.stringify(res, null, 1));

  const f = (x) => (x == null ? 'n/a' : (100 * x).toFixed(1) + '%');
  const line = (name, c) => console.log(`${name.padEnd(26)} n=${String(c.n).padEnd(4)} TP=${c.tp} FP=${c.fp} TN=${c.tn} FN=${c.fn}  P=${f(c.precision.value)} R=${f(c.recall.value)} [${f(c.recall.ci95[0])}-${f(c.recall.ci95[1])}] FPR=${f(c.fpr.value)} [${f(c.fpr.ci95[0])}-${f(c.fpr.ci95[1])}] F1=${f(c.f1)}  scam<MED=${c.scamBelowMedium_lossOfFundsMiss.k}/${c.scamBelowMedium_lossOfFundsMiss.n}`);
  console.log(`== ${res.meta.label} (${res.meta.target}) dataset ${res.meta.datasetSha256.slice(0, 12)}`);
  line('messages', M.messages.overall); line('domains', M.domains.overall); line('  dom: mal-existing+legit', M.domains.maliciousExistingPlusLegit); line('  dom: mal-NXDOMAIN+legit', M.domains.maliciousNonExistingPlusLegit); line('  msgs: scam+tricky genuine', M.messages.tricky); line('documents', M.documents.overall);
  console.log('latency', JSON.stringify(M.latencyMs), 'retries429', M.rateLimitRetries, 'failed', M.failedCalls.length);
  console.log('errors', errors.filter((e) => !/^WEAK/.test(e.type)).length, '(+ weak', errors.filter((e) => /^WEAK/.test(e.type)).length, ')');
}

(async () => {
  if (arg('report-only')) return report(arg('report-only'), arg('baseline'));
  const out = await collect();
  report(out, arg('baseline'));
})();
