// ========================================================
// SafeMeAI Cyber Defense Platform — Interactive Client Engine
// ========================================================

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initScamChecker();
  initDomainChecker();
  initDigitalArrestPanic();
  initDocumentAILab();
  initGeminiAdvisor();
  initBigQueryMatrix();
  initCitizenReporting();
  // CSP forbids inline handlers: hero links use data-switch-tab instead of onclick.
  document.querySelectorAll('[data-switch-tab]').forEach(a => a.addEventListener('click', () => switchTab(a.dataset.switchTab)));
});

// ========================================================
// 0. SHARED HELPERS (escaping, fail-closed fetch, race control)
// ========================================================
const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };
// Escape ANY server-supplied or user-supplied string before it goes into innerHTML.
function esc(v) {
  return String(v == null ? '' : v).replace(/[&<>"'`]/g, c => ESC_MAP[c]);
}
// Only allow plain http(s) hostnames in links built from server data.
function safeHost(h) {
  return /^[a-z0-9.-]{1,253}$/i.test(String(h || '')) ? String(h) : '';
}

const FAIL_CLOSED = 'Could not verify. Treat this as UNVERIFIED and do not act on it until checked through an official channel.';
const reqSeq = {};   // per-feature sequence number: only the newest request may update the UI

// POST/GET JSON with timeout; throws Error(message) that is safe to show. Resolves null if superseded.
async function api(key, url, { method = 'POST', json, form, timeoutMs = 20000 } = {}) {
  const seq = (reqSeq[key] = (reqSeq[key] || 0) + 1);
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const opts = { method, signal: ac.signal };
    if (json !== undefined) { opts.headers = { 'Content-Type': 'application/json' }; opts.body = JSON.stringify(json); }
    if (form) opts.body = form;
    let resp;
    try { resp = await fetch(url, opts); }
    catch (e) { throw new Error(e.name === 'AbortError' ? 'The request timed out. ' + FAIL_CLOSED : 'Network error. ' + FAIL_CLOSED); }
    let data = null;
    try { data = await resp.json(); } catch (_) { /* non-JSON error page */ }
    if (seq !== reqSeq[key]) return null;                    // stale response
    if (resp.status === 429) throw new Error('Too many requests. Please wait a minute and try again.');
    if (!resp.ok || !data || data.status !== 'success') {
      const why = (data && data.error) ? data.error : `Server error (${resp.status}).`;
      throw new Error(resp.status >= 500 ? `${why} ${FAIL_CLOSED}` : why);
    }
    return data;
  } finally {
    clearTimeout(timer);
  }
}

function setBusy(btn, busy, label) {
  if (!btn) return;
  btn.disabled = busy;
  btn.setAttribute('aria-busy', busy ? 'true' : 'false');
  if (label !== undefined) {
    const span = btn.querySelector('span') || btn;
    if (busy) { btn.dataset.label = span.textContent; span.textContent = label; }
    else if (btn.dataset.label) { span.textContent = btn.dataset.label; }
  }
}

// Visual class for a verdict. Green is reserved for explicitly VERIFIED/safe results; low-score
// but unconfirmed results are amber "UNVERIFIED" and never get a green check.
function classifyVerdict(res, { requireVerified }) {
  const score = Number(res.riskScore);
  const level = String(res.riskLevel || '').toUpperCase();
  if (score >= 80) return { ring: 'critical', badge: 'badge-critical', icon: '🚨', text: res.riskLevel };
  if (score >= 40) return { ring: 'high', badge: 'badge-danger', icon: '⚠️', text: res.riskLevel };
  const green = requireVerified ? res.verified === true : (/^(SAFE|LOW|VERIFIED)$/.test(level) && res.verified !== false);
  if (green) return { ring: 'safe', badge: 'badge-safe', icon: '✅', text: res.verified === true ? 'VERIFIED' : res.riskLevel };
  return { ring: 'unverified', badge: 'badge-unverified', icon: '❓', text: 'UNVERIFIED' };
}

function sourceBadge(grounded) {
  return grounded
    ? '<span class="src-badge src-live" title="Answer produced by Gemini on Vertex AI">Gemini live</span>'
    : '<span class="src-badge src-rules" title="Gemini was not used; deterministic rules produced this result">rules fallback</span>';
}



// ========================================================
// 1. GLOBAL NAVIGATION & TAB SWITCHING
// ========================================================
function initNavigation() {
  const tabs = document.querySelectorAll('.nav-tab');
  const panels = document.querySelectorAll('.tab-content-panel');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetId = tab.dataset.tab;
      switchTab(targetId);
    });
  });
}

window.switchTab = function(targetId) {
  const tabs = document.querySelectorAll('.nav-tab');
  const panels = document.querySelectorAll('.tab-content-panel');

  tabs.forEach(t => {
    if (t.dataset.tab === targetId) {
      t.classList.add('active');
    } else {
      t.classList.remove('active');
    }
  });

  panels.forEach(p => {
    if (p.id === targetId) {
      p.classList.add('active');
    } else {
      p.classList.remove('active');
    }
  });

  // Scroll smoothly to navigation on tab switch if clicked from hero
  const navBar = document.getElementById('main-navigation');
  if (navBar && window.scrollY > 300) {
    navBar.scrollIntoView({ behavior: 'smooth' });
  }
};

// ========================================================
// 2. INTERACTIVE SCAM & MESSAGE CHECKER (CORE TOOL)
// ========================================================
const PRESET_SCAM_SAMPLES = {
  'digital-arrest': `CENTRAL BUREAU OF INVESTIGATION - NEW DELHI
SPECIAL CYBER CRIME CELL - ORDER NO: CBI/CYB/2026/8941
SUBJECT: IMMEDIATE FREEZING ORDER & ARREST WARRANT UNDER PMLA ACT

A DHL courier in your name containing 140g MDMA and 5 fake passports was intercepted at Mumbai Airport.
You are placed under 24-HOUR DIGITAL SURVEILLANCE. Do NOT disconnect your Skype video call.
To verify your liquid assets, immediately transfer INR 4,85,000 to the:
RBI FINANCIAL SAFETY VERIFICATION ESCROW ACCOUNT:
UPI ID: rbi.safecustody99@okhdfcbank
Account: 919876543210 (RBI Secret Verification Cell)

Failure to comply within 2 hours will lead to physical arrest by local police under IPC 420/120B.
Signed, Director General of CBI.`,

  'upi-collect': `Google Pay Alert:
Refund of ₹4,999.00 has been approved from Flipkart for Order #FL88921.
Open Google Pay, accept the Collect Request from 'refund.desk92@icici' and ENTER YOUR UPI PIN to receive ₹4,999 directly into your linked bank account immediately. Valid for 15 minutes only.`,

  'electricity': `Dear Consumer,
Your electricity power will be disconnected at 9:30 PM tonight from the electricity office because your previous month bill was not updated. Please immediately contact our Electricity Officer at +91 98710 99281 or install UrjaBillUpdate.apk to update your bill immediately. - Electricity Dept.`,

  'loan-app': `Congratulations! Instant Loan of INR 50,000 has been approved for you with ZERO paperwork!
Disbursal amount: INR 31,500 (Processing Fee & GST: INR 18,500 deducted upfront).
Repayment due: 7 days.
Download QuickRupeeCash.apk now and grant Contact List, Camera, and Photo Gallery access to receive instant funds in 5 minutes!`,

  'telegram-task': `Part-Time Work From Home Job!
Earn ₹3,000 - ₹5,000 daily from your phone by simply liking YouTube videos and rating hotels on Google Maps. No skills needed. Daily payout via UPI.
Join our official Telegram VIP Channel: @EarnDailyIndiaVIP.
Deposit initial security verification of ₹1,000 to unlock your first batch of tasks.`,

  'authentic-bank': `Dear HDFC Bank Customer,
INR 1,850.00 has been debited from A/C XX4921 on 14-OCT-26 at POS SWIGGY BANGALORE.
Avail Bal: INR 42,310.50.
If not done by you, call 1800 202 6161 or SMS BLOCK to 5676712 immediately. Do not share your OTP with anyone.`
};

function initScamChecker() {
  const inputEl = document.getElementById('checker-input-text');
  const btnRun = document.getElementById('btn-run-check');
  const btnClear = document.getElementById('btn-clear-checker');
  const chips = document.querySelectorAll('.specimen-chip[data-sample]');

  chips.forEach(chip => {
    chip.addEventListener('click', () => {
      const sampleKey = chip.dataset.sample;
      if (PRESET_SCAM_SAMPLES[sampleKey]) {
        inputEl.value = PRESET_SCAM_SAMPLES[sampleKey];
        runScamCheck(PRESET_SCAM_SAMPLES[sampleKey]);
      }
    });
  });

  if (btnRun) {
    btnRun.addEventListener('click', () => {
      const text = (inputEl.value || '').trim();
      if (!text) { showScamNotice('Input required', 'Please paste a suspicious message, SMS, URL, or UPI ID first.'); inputEl.focus(); return; }
      runScamCheck(text);
    });
  }
  if (btnClear) btnClear.addEventListener('click', () => { inputEl.value = ''; reqSeq.scam = (reqSeq.scam || 0) + 1; resetScamVerdict(); });
}

function showScamNotice(headline, desc) {
  const badgeEl = document.getElementById('checker-badge');
  badgeEl.className = 'status-badge badge-unverified';
  badgeEl.textContent = '❓ UNVERIFIED';
  document.getElementById('gauge-ring').className = 'gauge-ring unverified';
  document.getElementById('gauge-score').textContent = '?';
  document.getElementById('verdict-headline').textContent = headline;
  document.getElementById('verdict-desc').textContent = desc;
  document.getElementById('verdict-type-tag').textContent = 'Category: Not assessed';
}

async function runScamCheck(text) {
  const btnRun = document.getElementById('btn-run-check');
  const badgeEl = document.getElementById('checker-badge');
  const ringEl = document.getElementById('gauge-ring');
  const scoreEl = document.getElementById('gauge-score');
  const flagsListEl = document.getElementById('red-flags-list');
  const actionCardEl = document.getElementById('action-steps-card');
  const legalBoxEl = document.getElementById('legal-citation-box');

  setBusy(btnRun, true, 'Analyzing...');
  badgeEl.className = 'status-badge';
  badgeEl.textContent = 'Analyzing...';
  document.getElementById('verdict-headline').textContent = 'Running SafeMeAI Multi-Layer Detection...';
  document.getElementById('verdict-desc').textContent = 'Scanning for scam patterns, link reputation and impersonation signals...';

  try {
    const data = await api('scam', '/api/scam/check', { json: { text }, timeoutMs: 25000 });
    if (!data) return;                       // superseded by a newer click
    const res = data.data;
    const v = classifyVerdict(res, { requireVerified: false });

    scoreEl.textContent = `${Number(res.riskScore) || 0}%`;
    ringEl.className = 'gauge-ring ' + v.ring;
    badgeEl.className = 'status-badge ' + v.badge;
    badgeEl.textContent = `${v.icon} ${v.text}`;

    document.getElementById('verdict-headline').textContent = res.headline || '';
    document.getElementById('verdict-desc').textContent = res.verdictDescription || '';
    document.getElementById('verdict-type-tag').textContent = `Scam Category: ${res.scamType || 'n/a'}`;

    const flags = Array.isArray(res.flags) ? res.flags : [];
    flagsListEl.innerHTML = flags.length
      ? flags.map(f => `<li>⚠️ ${esc(f)}</li>`).join('')
      : `<li class="empty-state">No anomalies found by the automated checks. This is not proof the message is safe.</li>`;

    const advice = Array.isArray(res.actionAdvice) ? res.actionAdvice : [];
    if (advice.length) {
      actionCardEl.innerHTML = `<strong>Safety Recommendations:</strong><ul>${advice.map(a => `<li>${esc(a)}</li>`).join('')}</ul>`;
    }
    legalBoxEl.innerHTML = `<span>⚖️ Legal Protection: <strong>${esc(res.protectionLaw || 'Indian Penal Law')}</strong></span>`;
  } catch (err) {
    showScamNotice('Could not verify', err.message);
    flagsListEl.innerHTML = '<li class="empty-state">No result. Do not assume this message is safe.</li>';
  } finally {
    setBusy(btnRun, false);
  }
}

function resetScamVerdict() {
  document.getElementById('gauge-score').textContent = '0%';
  document.getElementById('gauge-ring').className = 'gauge-ring';
  document.getElementById('checker-badge').className = 'status-badge';
  document.getElementById('checker-badge').textContent = 'Ready for Input';
  document.getElementById('verdict-headline').textContent = 'Waiting for suspicious text...';
  document.getElementById('verdict-desc').textContent = 'Paste your message on the left or select a sample above to verify authenticity instantly.';
  document.getElementById('verdict-type-tag').textContent = 'Category: Standby';
  document.getElementById('red-flags-list').innerHTML = '<li class="empty-state">No anomalies evaluated yet.</li>';
  document.getElementById('action-steps-card').innerHTML = '<p>SafeMeAI will generate step-by-step instructions to protect your funds and personal safety.</p>';
}

// ========================================================
// 2B. DOMAIN & URL FRAUD CHECKER (HCRV ENGINE)
// ========================================================
function initDomainChecker() {
  const inputEl = document.getElementById('domain-input-text');
  const btnRun = document.getElementById('btn-run-domain-check');
  const btnClear = document.getElementById('btn-clear-domain');

  document.querySelectorAll('[data-domain-sample]').forEach(chip => {
    chip.addEventListener('click', () => {
      const d = chip.dataset.domainSample;
      if (d) { inputEl.value = d; runDomainCheck(d); }
    });
  });
  if (btnRun) {
    btnRun.addEventListener('click', () => {
      const text = (inputEl.value || '').trim();
      if (!text) { inputEl.focus(); inputEl.setAttribute('aria-invalid', 'true'); return; }
      inputEl.removeAttribute('aria-invalid');
      runDomainCheck(text);
    });
  }
  if (inputEl) inputEl.addEventListener('keydown', e => { if (e.key === 'Enter') btnRun && btnRun.click(); });
  if (btnClear) btnClear.addEventListener('click', () => { inputEl.value = ''; reqSeq.domain = (reqSeq.domain || 0) + 1; resetDomainVerdict(); });
}

function renderTelemetry(t) {
  const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
  const dns = t.dns, ssl = t.ssl, feed = t.threatFeeds, ml = t.mlDiagnostics, ai = t.agenticAi;

  if (dns) {
    const ips = Array.isArray(dns.ips) ? dns.ips : [];
    set('telemetry-dns-val', dns.resolved
      ? `<span class="badge-safe">✅ ${esc(dns.status)}</span> · ${esc(ips.slice(0, 2).join(', '))}${ips.length > 2 ? ' +' + (ips.length - 2) : ''} <small>(TTL: ${esc(dns.ttl == null ? 'n/a' : dns.ttl)}s${dns.isFastFlux ? ' · ⚠️ Fast-Flux' : ''})</small>`
      : `<span class="badge-crit">⚠️ ${esc(dns.status || 'UNRESOLVED')}</span> · <small>Not resolvable via Google Public DNS</small>`);
  }

  if (ssl) {
    if (ssl.supported && ssl.hasValidSsl) {
      if (ssl.isEV_OV) set('telemetry-ssl-val', `<span class="badge-safe">🏛️ Organisation-validated TLS</span> · <strong>${esc(ssl.subjectOrg)}</strong> <small>(${esc(ssl.issuer)})</small>`);
      else if (ssl.isFreeDV) set('telemetry-ssl-val', `<span class="badge-warn">⚠️ Free DV TLS</span> · ${esc(ssl.issuer)} <small>(${ssl.ageDays != null ? esc(ssl.ageDays) + 'd old' : 'active'}${ssl.isNewlyIssued ? ' · 🚨 Newly issued' : ''})</small>`);
      else set('telemetry-ssl-val', `<span class="badge-warn">Valid TLS</span> · ${esc(ssl.issuer)} <small>(age ${ssl.ageDays != null ? esc(ssl.ageDays) + 'd' : 'n/a'})</small>`);
    } else {
      set('telemetry-ssl-val', `<span class="badge-crit">🚨 ${esc(ssl.error || 'No secure TLS')}</span> · <small>Port 443 check failed</small>`);
    }
  }

  const ageEl = document.getElementById('telemetry-age-val');
  const age = t.domainAge;
  if (ageEl) {
    if (age && age.available && age.ageDays != null) {
      const cls = age.ageDays < 30 ? 'badge-crit' : (age.ageDays < 180 ? 'badge-warn' : 'badge-safe');
      ageEl.innerHTML = `<span class="${cls}">${esc(age.ageDays)} days old</span> · <small>${esc(age.registrar || 'registrar n/a')}</small>`;
    } else if (age && age.notRegistered) {
      ageEl.innerHTML = '<span class="badge-crit">Not registered</span>';
    } else {
      ageEl.innerHTML = `<span class="badge-warn">Unknown</span> · <small>${esc((age && age.error) || 'RDAP lookup unavailable')}</small>`;
    }
  }

  if (feed) {
    const wr = feed.webRisk || {};
    const wrHtml = wr.available
      ? (wr.flagged ? `<span class="badge-crit">🚨 Google Web Risk: ${esc((wr.threatTypes || []).join(', '))}</span>` : '<span class="badge-safe">Web Risk: no match</span>')
      : `<span class="badge-warn">Web Risk not checked</span> <small>(${esc(wr.reason || 'unavailable')})</small>`;
    const opHtml = feed.openPhishMatch
      ? '<span class="badge-crit">🚨 Listed in OpenPhish feed</span>'
      : (feed.feedLive
        ? `<span class="badge-warn">Not in OpenPhish feed</span> <small>(${esc(feed.activeIndicators)} indicators; absence is not proof of safety)</small>`
        : '<span class="badge-warn">OpenPhish feed offline</span>');
    set('telemetry-feed-val', `${opHtml}<br>${wrHtml}`);
  }

  if (ml) {
    const cls = ml.isDGA ? 'badge-crit' : (ml.shannonEntropy > 3.4 ? 'badge-warn' : 'badge-safe');
    set('telemetry-ml-val', `<span class="${cls}">${esc(ml.entropyRating)}</span> · <small>Shannon entropy ${esc(ml.shannonEntropy)}</small>`);
  }

  if (ai) {
    set('telemetry-rationale-val', `
      <div class="ai-head">
        <strong>🧠 ${esc(ai.model)}</strong> ${sourceBadge(ai.grounded === true)}
        <span class="ai-conf">Confidence: ${esc(ai.confidence)}</span>
      </div>
      <div class="ai-body">${esc(ai.rationale)}</div>`);
  }
}

async function runDomainCheck(urlOrDomain) {
  const btnRun = document.getElementById('btn-run-domain-check');
  const badgeEl = document.getElementById('domain-badge');
  const ringEl = document.getElementById('domain-gauge-ring');
  const scoreEl = document.getElementById('domain-gauge-score');
  const headlineEl = document.getElementById('domain-verdict-headline');
  const descEl = document.getElementById('domain-verdict-desc');
  const flagsListEl = document.getElementById('domain-flags-list');
  const actionCardEl = document.getElementById('domain-action-card');
  const realtimeBox = document.getElementById('domain-realtime-box');

  setBusy(btnRun, true, 'Checking...');
  badgeEl.className = 'status-badge';
  badgeEl.textContent = 'Analyzing...';
  headlineEl.textContent = 'Running layered domain verification...';
  descEl.textContent = 'Allow-list + DNS, domain age, Google Web Risk, OpenPhish, TLS and Gemini (escalation only)...';
  if (realtimeBox) realtimeBox.style.display = 'none';

  try {
    const data = await api('domain', '/api/domain/check', { json: { url: urlOrDomain }, timeoutMs: 30000 });
    if (!data) return;
    const res = data.data;
    const v = classifyVerdict(res, { requireVerified: true });

    scoreEl.textContent = `${Number(res.riskScore) || 0}%`;
    ringEl.className = 'gauge-ring ' + v.ring;
    badgeEl.className = 'status-badge ' + v.badge;
    badgeEl.textContent = `${v.icon} ${v.text}`;

    headlineEl.textContent = res.headline || '';
    descEl.textContent = `Target Domain: ${res.domain} (TLD: ${res.tld || 'n/a'})`;
    document.getElementById('domain-verdict-tag').textContent = `Verdict: ${res.verdict}`;

    const flags = Array.isArray(res.flags) ? res.flags : [];
    flagsListEl.innerHTML = flags.length
      ? flags.map(f => `<li>${res.verified ? '✓' : (res.riskScore >= 50 ? '⚠️' : '•')} ${esc(f)}</li>`).join('')
      : `<li class="empty-state">No flags raised. This domain is not confirmed as official.</li>`;

    const host = safeHost(res.officialDomain);
    actionCardEl.innerHTML = `
      <strong>Safety Directive:</strong>
      <p class="mt-s">${esc(res.actionAdvice)}</p>
      ${host ? `<p class="official-link">Official website: <a href="https://${esc(host)}" target="_blank" rel="noopener noreferrer">https://${esc(host)}</a></p>` : ''}`;

    if (res.realtimeTelemetry && realtimeBox) {
      realtimeBox.style.display = 'block';
      renderTelemetry(res.realtimeTelemetry);
    }
  } catch (err) {
    scoreEl.textContent = '?';
    ringEl.className = 'gauge-ring unverified';
    badgeEl.className = 'status-badge badge-unverified';
    badgeEl.textContent = '❓ UNVERIFIED';
    headlineEl.textContent = 'Could not verify this domain';
    descEl.textContent = err.message;
    document.getElementById('domain-verdict-tag').textContent = 'Verdict: UNVERIFIED';
    flagsListEl.innerHTML = '<li class="empty-state">No result. Treat this domain as unverified.</li>';
  } finally {
    setBusy(btnRun, false);
  }
}

function resetDomainVerdict() {
  document.getElementById('domain-gauge-score').textContent = '0%';
  document.getElementById('domain-gauge-ring').className = 'gauge-ring';
  document.getElementById('domain-badge').className = 'status-badge';
  document.getElementById('domain-badge').textContent = 'Ready for Input';
  document.getElementById('domain-verdict-headline').textContent = 'Waiting for URL or Domain...';
  document.getElementById('domain-verdict-desc').textContent = 'Enter any domain or click a preset sample above to evaluate legitimacy.';
  document.getElementById('domain-verdict-tag').textContent = 'Status: Standby';
  document.getElementById('domain-flags-list').innerHTML = '<li class="empty-state">No domain evaluated yet.</li>';
  document.getElementById('domain-action-card').innerHTML = '<p>SafeMeAI will advise whether this domain is safe for credentials, payment transactions, or downloads.</p>';
  const realtimeBox = document.getElementById('domain-realtime-box');
  if (realtimeBox) realtimeBox.style.display = 'none';
}

// ========================================================
// 3. DIGITAL ARREST EMERGENCY RAPID SCREENER
// ========================================================
function initDigitalArrestPanic() {
  document.querySelectorAll('.q-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll(`.q-btn[data-q="${btn.dataset.q}"]`).forEach(b => { b.classList.remove('active'); b.setAttribute('aria-pressed', 'false'); });
      btn.classList.add('active');
      btn.setAttribute('aria-pressed', 'true');
      evaluatePanicRisk();
    });
  });
  const btnEvaluate = document.getElementById('btn-evaluate-panic');
  if (btnEvaluate) btnEvaluate.addEventListener('click', evaluatePanicRisk);
}

async function evaluatePanicRisk() {
  const yes = q => document.querySelector(`.q-btn[data-q="${q}"].active`)?.dataset.val === 'yes';
  const badgeEl = document.getElementById('panic-badge');
  const headlineEl = document.getElementById('panic-headline');
  const summaryEl = document.getElementById('panic-summary');
  const stepsBoxEl = document.getElementById('panic-steps-box');
  try {
    const data = await api('panic', '/api/emergency/digital-arrest-screen', {
      json: { isUniformOrAgency: yes('q1'), isContrabandOrPMLA: yes('q2'), isCoerciveSurveillance: yes('q3'), isMoneyDemand: yes('q4') },
      timeoutMs: 10000
    });
    if (!data) return;
    badgeEl.textContent = `Certainty: ${data.certainty}% (${data.verdict})`;
    headlineEl.textContent = data.headline;
    summaryEl.textContent = data.certainty >= 90
      ? 'CRITICAL ALERT: You are in no legal danger from the police. You are facing an organized criminal extortion attempt.'
      : 'No coercion signals selected. Never transfer funds or share credentials on a call, and if in doubt dial 1930.';
    if (Array.isArray(data.emergencyProtocol)) {
      stepsBoxEl.innerHTML = `<h4>Immediate Emergency Safety Protocol:</h4><ul>${data.emergencyProtocol.map(s => `<li><strong>${esc(s)}</strong></li>`).join('')}</ul>`;
    }
  } catch (err) {
    headlineEl.textContent = 'Could not run the screener';
    summaryEl.textContent = 'If anyone is demanding money or asking you to stay on a video call, hang up and dial 1930 now.';
  }
}

// ========================================================
// 4. DOCUMENT FORENSIC LAB (Document AI only if the server has a processor configured)
// ========================================================
let currentSelectedFile = null;
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;

function initDocumentAILab() {
  const cards = document.querySelectorAll('.specimen-card');
  const btnAnalyzeText = document.getElementById('btn-analyze-doc');
  const customTextArea = document.getElementById('custom-doc-text');
  const dropzone = document.getElementById('doc-dropzone');
  const fileInput = document.getElementById('doc-file-input');
  const fileBar = document.getElementById('file-selected-bar');
  const fileNameEl = document.getElementById('selected-file-name');
  const btnUploadDoc = document.getElementById('btn-upload-file-doc');
  const btnRemoveFile = document.getElementById('btn-remove-file');

  function handleFileSelect(file) {
    if (file.size > MAX_UPLOAD_BYTES) { showDocError('File is larger than 5 MB.'); return; }
    currentSelectedFile = file;
    fileNameEl.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    fileBar.style.display = 'flex';
  }

  if (dropzone && fileInput) {
    dropzone.addEventListener('click', () => fileInput.click());
    dropzone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
    dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('dragover'); });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone.addEventListener('drop', e => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) handleFileSelect(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener('change', e => { if (e.target.files && e.target.files[0]) handleFileSelect(e.target.files[0]); });
  }
  if (btnRemoveFile) {
    btnRemoveFile.addEventListener('click', e => {
      e.stopPropagation();
      currentSelectedFile = null;
      if (fileInput) fileInput.value = '';
      fileBar.style.display = 'none';
    });
  }
  if (btnUploadDoc) {
    btnUploadDoc.addEventListener('click', () => {
      if (!currentSelectedFile) { showDocError('Please select or drop a document file first.'); return; }
      const fd = new FormData();
      fd.append('document', currentSelectedFile);
      renderDocument({ form: fd }, btnUploadDoc);
    });
  }
  cards.forEach(card => {
    card.addEventListener('click', () => {
      cards.forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      renderDocument({ json: { specimenKey: card.dataset.specimen } });
    });
  });
  if (btnAnalyzeText) {
    btnAnalyzeText.addEventListener('click', () => {
      const customText = (customTextArea.value || '').trim();
      if (!customText) { showDocError('Please paste document text or upload a file to inspect.'); return; }
      renderDocument({ json: { customText } }, btnAnalyzeText);
    });
  }
  renderDocument({ json: { specimenKey: 'fake_arrest_warrant' } });
}

function showDocError(msg) {
  document.getElementById('doc-verdict-badge').textContent = 'Could not analyze';
  document.getElementById('doc-raw-text').textContent = msg;
}

async function renderDocument(payload, btn) {
  const verdictBadge = document.getElementById('doc-verdict-badge');
  verdictBadge.className = 'status-pill';
  verdictBadge.textContent = 'Analyzing...';
  setBusy(btn, true);
  try {
    const data = await api('doc', '/api/document-ai/analyze', { ...payload, timeoutMs: 40000 });
    if (!data) return;
    const ana = data.analysis;
    verdictBadge.textContent = ana.verdict;
    verdictBadge.className = `status-pill ${String(ana.severity || '').toLowerCase().replace(/[^a-z]/g, '')}`;
    document.getElementById('doc-auth-score').textContent = `${ana.authenticityScore}/100`;
    document.getElementById('doc-risk-score').textContent = `${ana.riskScore}/100`;
    document.getElementById('doc-raw-text').textContent = data.document.extractedText || 'No text extracted.';
    document.getElementById('doc-findings-list').innerHTML = (ana.findings || []).map(f => {
      const ok = ['PASSED', 'CLEAN', 'NO_MATCH'].includes(f.status);
      return `<div class="finding-row"><span class="finding-status ${ok ? 'passed' : 'failed'}">${esc(f.status)}</span><div><strong>${esc(f.rule)}:</strong> ${esc(f.detail)}</div></div>`;
    }).join('') + `<div class="datasource-note">${esc(data.dataSource === 'demo-simulated' ? 'DEMO SPECIMEN: ' : 'Source: ')}${esc(data.dataSourceNote || data.dataSource)}</div>`;
    document.getElementById('doc-rec-action').textContent = ana.recommendedAction || 'Verify through official banking channels.';
  } catch (err) {
    verdictBadge.className = 'status-pill';
    verdictBadge.textContent = 'Could not analyze';
    document.getElementById('doc-raw-text').textContent = err.message;
  } finally {
    setBusy(btn, false);
  }
}

// ========================================================
// 5. GEMINI FRAUD REASONER
// ========================================================
function initGeminiAdvisor() {
  const inputEl = document.getElementById('gemini-input-field');
  const sendBtn = document.getElementById('btn-send-gemini');
  const submit = () => {
    const text = (inputEl.value || '').trim();
    if (!text || sendBtn.disabled) return;
    inputEl.value = '';
    askGemini(text);
  };
  document.querySelectorAll('.gemini-pill').forEach(pill => pill.addEventListener('click', () => { if (!sendBtn.disabled) askGemini(pill.dataset.prompt); }));
  if (sendBtn) sendBtn.addEventListener('click', submit);
  if (inputEl) inputEl.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
}

function chatMsg(cls, avatar, bodyHtml) {
  const d = document.createElement('div');
  d.className = 'chat-message ' + cls;
  d.innerHTML = `<div class="msg-avatar">${avatar}</div><div class="msg-body">${bodyHtml}</div>`;
  return d;
}

async function askGemini(prompt) {
  const display = document.getElementById('gemini-chat-display');
  const sendBtn = document.getElementById('btn-send-gemini');
  display.appendChild(chatMsg('user', '👤', `<strong>You:</strong><p>${esc(prompt)}</p>`));
  const loading = chatMsg('assistant', '🧠', '<strong>SafeMeAI Advisor:</strong><p>Analyzing...</p>');
  display.appendChild(loading);
  display.scrollTop = display.scrollHeight;
  setBusy(sendBtn, true);
  try {
    const data = await api('advisor', '/api/gemini/advisor', { json: { prompt }, timeoutMs: 30000 });
    if (!data) return;
    const r = data.data;
    const color = r.riskLevel === 'CRITICAL' || r.riskLevel === 'HIGH' ? '#f87171' : (r.riskLevel === 'MEDIUM' ? '#fbbf24' : '#38bdf8');
    const signals = Array.isArray(r.signals) ? r.signals : [];
    loading.innerHTML = `<div class="msg-avatar">🛡️</div><div class="msg-body">
      <strong>${esc(r.model)} ${sourceBadge(r.grounded === true)} · Risk: <span style="color:${color}">${esc(r.riskLevel)}</span></strong>
      <p>${esc(r.reasoning)}</p>
      ${signals.length ? `<div class="adv-signals"><strong>Key Fraud Signals:</strong><ul>${signals.map(s => `<li>${esc(s)}</li>`).join('')}</ul></div>` : ''}
      <div class="adv-action"><strong>Recommended action:</strong> <span class="pre">${esc(r.recommendedAction)}</span></div>
      ${r.grounded ? '' : `<div class="datasource-note">Gemini was not used (${esc(r.fallbackReason || 'unavailable')}). This answer comes from fixed keyword rules.</div>`}
    </div>`;
  } catch (err) {
    loading.querySelector('.msg-body').innerHTML = `<strong>SafeMeAI Advisor:</strong><p>${esc(err.message)}</p>`;
  } finally {
    setBusy(sendBtn, false);
    display.scrollTop = display.scrollHeight;
  }
}

// ========================================================
// 6. THREAT ANALYTICS (demo data unless BigQuery is connected server-side)
// ========================================================
async function initBigQueryMatrix() {
  const threatBars = document.getElementById('threat-bars-container');
  const muleTable = document.getElementById('mule-table-body');
  try {
    const data = await api('bq', '/api/bigquery/analytics', { method: 'GET', timeoutMs: 15000 });
    if (!data) return;
    const note = document.getElementById('bq-source-note');
    if (note) note.textContent = data.dataSourceNote || '';
    if (threatBars && data.topVectors) {
      threatBars.innerHTML = data.topVectors.map(v => {
        const w = Math.max(0, Math.min(100, Number(v.share) || 0));
        return `<div class="threat-bar-item"><div class="bar-meta"><span>${esc(v.vector)}</span><span>${w}% (${esc(v.count)} incidents)</span></div><div class="bar-track"><div class="bar-fill" style="width:${w}%"></div></div></div>`;
      }).join('');
    }
    if (muleTable && data.liveMuleClusters) {
      muleTable.innerHTML = data.liveMuleClusters.map(m => `<tr>
        <td><strong>${esc(m.clusterId)}</strong></td><td>${esc(m.nodes)} Accounts</td><td>${esc(m.volumeINR)}</td>
        <td><span class="risk-pct">${esc(m.riskScore)}%</span></td><td><span class="finding-status failed">${esc(m.status)}</span></td></tr>`).join('');
    }
  } catch (err) {
    const note = document.getElementById('bq-source-note');
    if (note) note.textContent = 'Analytics unavailable: ' + err.message;
  }
}

// ========================================================
// 7. CITIZEN SCAM REPORTER ("FEED SAFEMEAI")
// ========================================================
async function initCitizenReporting() {
  const form = document.getElementById('scam-report-form');
  const successMsg = document.getElementById('report-success-msg');
  loadCitizenReports();
  if (!form) return;
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const btn = document.getElementById('btn-submit-report');
    const val = id => document.getElementById(id).value;
    setBusy(btn, true);
    try {
      const data = await api('report', '/api/scam/report', {
        json: { scamType: val('report-type'), scamTarget: val('report-target'), scamDetails: val('report-details'), reporterName: val('report-name'), reporterPhone: val('report-phone') },
        timeoutMs: 10000
      });
      if (!data) return;
      form.reset();
      successMsg.style.display = 'block';
      setTimeout(() => { successMsg.style.display = 'none'; }, 4000);
      loadCitizenReports();
    } catch (err) {
      successMsg.style.display = 'block';
      successMsg.textContent = err.message;
      setTimeout(() => { successMsg.style.display = 'none'; }, 5000);
    } finally {
      setBusy(btn, false);
    }
  });
}

async function loadCitizenReports() {
  const feedList = document.getElementById('citizen-reports-list');
  if (!feedList) return;
  try {
    const data = await api('reports', '/api/scam/reports', { method: 'GET', timeoutMs: 10000 });
    if (!data || !data.data) return;
    feedList.innerHTML = data.data.map(r => `
      <div class="report-feed-item">
        <div class="feed-item-top"><span class="feed-item-badge">${esc(r.scamType)}</span><span class="feed-item-time">${esc(r.time)}</span></div>
        <div class="feed-item-target">${esc(r.target)}</div>
        <div class="feed-item-desc">${esc(r.details)}</div>
      </div>`).join('');
  } catch (err) {
    feedList.innerHTML = '<div class="datasource-note">Could not load reports.</div>';
  }
}
