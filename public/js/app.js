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
});

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
  const chips = document.querySelectorAll('.specimen-chip');

  // One-click specimen chips
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
      const text = (inputEl.value || "").trim();
      if (!text) {
        alert("Please paste a suspicious message, SMS, URL, or UPI ID first!");
        inputEl.focus();
        return;
      }
      runScamCheck(text);
    });
  }

  if (btnClear) {
    btnClear.addEventListener('click', () => {
      inputEl.value = "";
      resetScamVerdict();
    });
  }
}

async function runScamCheck(text) {
  const badgeEl = document.getElementById('checker-badge');
  const ringEl = document.getElementById('gauge-ring');
  const scoreEl = document.getElementById('gauge-score');
  const headlineEl = document.getElementById('verdict-headline');
  const descEl = document.getElementById('verdict-desc');
  const typeTagEl = document.getElementById('verdict-type-tag');
  const flagsListEl = document.getElementById('red-flags-list');
  const actionCardEl = document.getElementById('action-steps-card');
  const legalBoxEl = document.getElementById('legal-citation-box');

  // Loading state
  badgeEl.className = 'status-badge';
  badgeEl.textContent = 'Analyzing...';
  headlineEl.textContent = 'Running SafeMeAI Multi-Layer Detection...';
  descEl.textContent = 'Scanning for keyword triggers, UPI inversion patterns, coercive legal pressure, and unauthorized accounts...';

  try {
    const response = await fetch('/api/scam/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });

    const data = await response.json();
    if (!data.status || data.status !== 'success') {
      throw new Error(data.error || "Analysis failed");
    }

    const res = data.data;

    // Update gauge
    scoreEl.textContent = `${res.riskScore}%`;
    ringEl.className = 'gauge-ring';
    badgeEl.className = 'status-badge';

    if (res.riskScore >= 80) {
      ringEl.classList.add('critical');
      badgeEl.classList.add('badge-critical');
      badgeEl.textContent = '🚨 ' + res.riskLevel;
    } else if (res.riskScore >= 40) {
      ringEl.classList.add('high');
      badgeEl.classList.add('badge-danger');
      badgeEl.textContent = '⚠️ ' + res.riskLevel;
    } else {
      ringEl.classList.add('safe');
      badgeEl.classList.add('badge-safe');
      badgeEl.textContent = '✅ ' + res.riskLevel;
    }

    headlineEl.textContent = res.headline;
    descEl.textContent = res.verdictDescription;
    typeTagEl.textContent = `Scam Category: ${res.scamType}`;

    // Render flags
    if (res.flags && res.flags.length > 0) {
      flagsListEl.innerHTML = res.flags.map(f => `<li>⚠️ ${f}</li>`).join('');
    } else {
      flagsListEl.innerHTML = `<li class="empty-state">✅ No anomalies detected in message structure.</li>`;
    }

    // Render guidance
    if (res.actionAdvice && res.actionAdvice.length > 0) {
      actionCardEl.innerHTML = `
        <strong>Safety Recommendations:</strong>
        <ul>
          ${res.actionAdvice.map(a => `<li>${a}</li>`).join('')}
        </ul>
      `;
    }

    legalBoxEl.innerHTML = `<span>⚖️ Legal Protection: <strong>${res.protectionLaw || "Indian Penal Law"}</strong></span>`;

  } catch (err) {
    badgeEl.className = 'status-badge badge-danger';
    badgeEl.textContent = 'Notice';
    ringEl.className = 'gauge-ring';
    scoreEl.textContent = '0%';
    headlineEl.textContent = 'Input Required';
    descEl.textContent = err.message || "Please enter a specific message or URL to analyze.";
    flagsListEl.innerHTML = '<li class="empty-state">Select any of the 6 specimen buttons above or paste text from SMS/WhatsApp.</li>';
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
  const chips = document.querySelectorAll('[data-domain-sample]');

  chips.forEach(chip => {
    chip.addEventListener('click', () => {
      const domainSample = chip.dataset.domainSample;
      if (domainSample) {
        inputEl.value = domainSample;
        runDomainCheck(domainSample);
      }
    });
  });

  if (btnRun) {
    btnRun.addEventListener('click', () => {
      const text = (inputEl.value || "").trim();
      if (!text) {
        alert("Please enter a domain or URL first!");
        inputEl.focus();
        return;
      }
      runDomainCheck(text);
    });
  }

  if (btnClear) {
    btnClear.addEventListener('click', () => {
      inputEl.value = "";
      resetDomainVerdict();
    });
  }
}

async function runDomainCheck(urlOrDomain) {
  const badgeEl = document.getElementById('domain-badge');
  const ringEl = document.getElementById('domain-gauge-ring');
  const scoreEl = document.getElementById('domain-gauge-score');
  const headlineEl = document.getElementById('domain-verdict-headline');
  const descEl = document.getElementById('domain-verdict-desc');
  const typeTagEl = document.getElementById('domain-verdict-tag');
  const flagsListEl = document.getElementById('domain-flags-list');
  const actionCardEl = document.getElementById('domain-action-card');

  badgeEl.className = 'status-badge';
  badgeEl.textContent = 'Analyzing...';
  headlineEl.textContent = 'Running HCRV Multi-Vector DNS & Whitelist Check...';
  descEl.textContent = 'Cross-referencing authoritative directories, typosquatting patterns, and TLD reputation...';

  try {
    const response = await fetch('/api/domain/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: urlOrDomain })
    });

    const data = await response.json();
    if (!data.status || data.status !== 'success') {
      throw new Error(data.error || "Domain check failed");
    }

    const res = data.data;

    scoreEl.textContent = `${res.riskScore}%`;
    ringEl.className = 'gauge-ring';
    badgeEl.className = 'status-badge';

    if (res.riskScore >= 80) {
      ringEl.classList.add('critical');
      badgeEl.classList.add('badge-critical');
      badgeEl.textContent = '🚨 ' + res.riskLevel;
    } else if (res.riskScore >= 40) {
      ringEl.classList.add('high');
      badgeEl.classList.add('badge-danger');
      badgeEl.textContent = '⚠️ ' + res.riskLevel;
    } else {
      ringEl.classList.add('safe');
      badgeEl.classList.add('badge-safe');
      badgeEl.textContent = '✅ ' + res.riskLevel;
    }

    headlineEl.textContent = res.headline;
    descEl.textContent = `Target Domain: ${res.domain} (TLD: ${res.tld || "Standard"})`;
    typeTagEl.textContent = `Verdict: ${res.verdict}`;

    if (res.flags && res.flags.length > 0) {
      flagsListEl.innerHTML = res.flags.map(f => `<li>${res.riskScore >= 50 ? '⚠️' : '✓'} ${f}</li>`).join('');
    } else {
      flagsListEl.innerHTML = `<li class="empty-state">✅ Domain adheres to verified safety criteria.</li>`;
    }

    actionCardEl.innerHTML = `
      <strong>Safety Directive:</strong>
      <p style="margin-top: 0.3rem;">${res.actionAdvice}</p>
      ${res.officialDomain ? `<p style="margin-top: 0.4rem; color: #6ee7b7; font-weight: 700;">Official Authorized Website: <a href="https://${res.officialDomain}" target="_blank" style="color: #6ee7b7; text-decoration: underline;">https://${res.officialDomain}</a></p>` : ''}
    `;

    // Render Real-Time Telemetry & Agentic Forensics
    const realtimeBox = document.getElementById('domain-realtime-box');
    const dnsVal = document.getElementById('telemetry-dns-val');
    const sslVal = document.getElementById('telemetry-ssl-val');
    const feedVal = document.getElementById('telemetry-feed-val');
    const mlVal = document.getElementById('telemetry-ml-val');
    const rationaleVal = document.getElementById('telemetry-rationale-val');

    if (res.realtimeTelemetry && realtimeBox) {
      realtimeBox.style.display = 'block';

      // DNS Tile
      if (dnsVal && res.realtimeTelemetry.dns) {
        const dns = res.realtimeTelemetry.dns;
        if (dns.resolved) {
          dnsVal.innerHTML = `<span class="badge-safe">✅ ${dns.status}</span> · ${dns.ips.slice(0, 2).join(', ')}${dns.ips.length > 2 ? ' +' + (dns.ips.length - 2) : ''} <small>(TTL: ${dns.ttl || 60}s${dns.isFastFlux ? ' · ⚠️ Fast-Flux' : ''})</small>`;
        } else {
          dnsVal.innerHTML = `<span class="badge-crit">⚠️ ${dns.status || 'UNRESOLVED'}</span> · <small>Not reachable on Google Public DNS</small>`;
        }
      }

      // SSL Tile
      if (sslVal && res.realtimeTelemetry.ssl) {
        const ssl = res.realtimeTelemetry.ssl;
        if (ssl.supported && ssl.hasValidSsl) {
          if (ssl.isEV_OV) {
            sslVal.innerHTML = `<span class="badge-safe">🏛️ EV/OV Certified</span> · <strong>${ssl.subjectOrg}</strong> <small>(${ssl.issuer})</small>`;
          } else if (ssl.isFreeDV) {
            sslVal.innerHTML = `<span class="badge-warn">⚠️ Free DV TLS</span> · ${ssl.issuer} <small>(${ssl.ageDays !== null ? ssl.ageDays + 'd old' : 'active'}${ssl.isNewlyIssued ? ' · 🚨 Newly Issued' : ''})</small>`;
          } else {
            sslVal.innerHTML = `<span class="badge-safe">✅ Valid TLS</span> · ${ssl.issuer} <small>(Age: ${ssl.ageDays !== null ? ssl.ageDays + 'd' : 'active'})</small>`;
          }
        } else {
          sslVal.innerHTML = `<span class="badge-crit">🚨 ${ssl.error || 'No Secure TLS'}</span> · <small>Port 443 handshake failed</small>`;
        }
      }

      // OpenPhish Feed Tile
      if (feedVal && res.realtimeTelemetry.threatFeeds) {
        const feed = res.realtimeTelemetry.threatFeeds;
        if (feed.openPhishMatch) {
          feedVal.innerHTML = `<span class="badge-crit">🚨 ACTIVE ZERO-DAY THREAT</span> · <small>Flagged in live OpenPhish community stream</small>`;
        } else {
          feedVal.innerHTML = `<span class="badge-safe">✅ Threat Feed Clean</span> · <small>Passed OpenPhish real-time stream (${feed.activeIndicators} active IOCs)</small>`;
        }
      }

      // ML Diagnostics Tile
      if (mlVal && res.realtimeTelemetry.mlDiagnostics) {
        const ml = res.realtimeTelemetry.mlDiagnostics;
        const badgeClass = ml.isDGA ? 'badge-crit' : (ml.shannonEntropy > 3.4 ? 'badge-warn' : 'badge-safe');
        mlVal.innerHTML = `<span class="${badgeClass}">${ml.entropyRating}</span> · <small>Shannon Entropy: ${ml.shannonEntropy}</small>`;
      }

      // Agentic AI Rationale Box
      if (rationaleVal && res.realtimeTelemetry.agenticAi) {
        const ai = res.realtimeTelemetry.agenticAi;
        rationaleVal.innerHTML = `
          <div style="margin-bottom: 0.35rem; display: flex; align-items: center; justify-content: space-between;">
            <strong style="color: #38bdf8;">🧠 ${ai.model}</strong>
            <span style="font-size: 0.72rem; background: rgba(56, 189, 248, 0.15); border: 1px solid rgba(56, 189, 248, 0.3); padding: 0.1rem 0.4rem; border-radius: 4px; color: #7dd3fc;">Confidence: ${ai.confidence}</span>
          </div>
          <div style="color: #cbd5e1; font-size: 0.82rem; line-height: 1.4;">${ai.rationale}</div>
        `;
      }
    }

  } catch (err) {
    headlineEl.textContent = "Domain Evaluation Error";
    descEl.textContent = err.message || "Failed to reach domain verification engine.";
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
  const toggleButtons = document.querySelectorAll('.q-btn');
  const btnEvaluate = document.getElementById('btn-evaluate-panic');

  // Handle toggle selection with immediate real-time feedback
  toggleButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const questionGroup = btn.dataset.q;
      document.querySelectorAll(`.q-btn[data-q="${questionGroup}"]`).forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      evaluatePanicRisk(); // Instant real-time evaluation as soon as user clicks!
    });
  });

  if (btnEvaluate) {
    btnEvaluate.addEventListener('click', evaluatePanicRisk);
  }
}

async function evaluatePanicRisk() {
  const isQ1 = document.querySelector('.q-btn[data-q="q1"].active')?.dataset.val === 'yes';
  const isQ2 = document.querySelector('.q-btn[data-q="q2"].active')?.dataset.val === 'yes';
  const isQ3 = document.querySelector('.q-btn[data-q="q3"].active')?.dataset.val === 'yes';
  const isQ4 = document.querySelector('.q-btn[data-q="q4"].active')?.dataset.val === 'yes';

  const badgeEl = document.getElementById('panic-badge');
  const headlineEl = document.getElementById('panic-headline');
  const summaryEl = document.getElementById('panic-summary');
  const stepsBoxEl = document.getElementById('panic-steps-box');

  try {
    const response = await fetch('/api/emergency/digital-arrest-screen', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        isUniformOrAgency: isQ1,
        isCoerciveSurveillance: isQ3,
        isContrabandOrPMLA: isQ2,
        isMoneyDemand: isQ4
      })
    });

    const data = await response.json();
    if (data.status === 'success') {
      badgeEl.textContent = `Certainty: ${data.certainty}% (${data.verdict})`;
      headlineEl.textContent = data.headline;
      summaryEl.textContent = data.certainty >= 90
        ? "⚠️ CRITICAL ALERT: You are in zero legal danger from the police. You are facing an organized criminal extortion syndicate."
        : "Standard communication. Never transfer funds or share private credentials over video calls.";

      if (data.emergencyProtocol) {
        stepsBoxEl.innerHTML = `
          <h4>Immediate Emergency Safety Protocol:</h4>
          <ul>
            ${data.emergencyProtocol.map(s => `<li><strong>${s}</strong></li>`).join('')}
          </ul>
        `;
      }
    }
  } catch (err) {
    console.error("Panic evaluation failed", err);
  }
}

// ========================================================
// 4. GOOGLE DOCUMENT AI FORENSIC LAB (WITH WORKING FILE UPLOAD)
// ========================================================
let currentSelectedFile = null;

function initDocumentAILab() {
  const cards = document.querySelectorAll('.specimen-card');
  const btnAnalyzeText = document.getElementById('btn-analyze-doc');
  const customTextArea = document.getElementById('custom-doc-text');

  // File upload elements
  const dropzone = document.getElementById('doc-dropzone');
  const fileInput = document.getElementById('doc-file-input');
  const fileBar = document.getElementById('file-selected-bar');
  const fileNameEl = document.getElementById('selected-file-name');
  const btnUploadDoc = document.getElementById('btn-upload-file-doc');
  const btnRemoveFile = document.getElementById('btn-remove-file');

  // Click dropzone to browse
  if (dropzone && fileInput) {
    dropzone.addEventListener('click', () => fileInput.click());

    // Drag and drop handlers
    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));

    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleFileSelect(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleFileSelect(e.target.files[0]);
      }
    });
  }

  function handleFileSelect(file) {
    currentSelectedFile = file;
    fileNameEl.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    fileBar.style.display = 'flex';
  }

  if (btnRemoveFile) {
    btnRemoveFile.addEventListener('click', (e) => {
      e.stopPropagation();
      currentSelectedFile = null;
      if (fileInput) fileInput.value = '';
      fileBar.style.display = 'none';
    });
  }

  if (btnUploadDoc) {
    btnUploadDoc.addEventListener('click', () => {
      if (!currentSelectedFile) {
        alert("Please select or drop a document file first!");
        return;
      }
      uploadAndAnalyzeDocument(currentSelectedFile);
    });
  }

  // Specimen selection
  cards.forEach(card => {
    card.addEventListener('click', () => {
      cards.forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      const specimenKey = card.dataset.specimen;
      analyzeDocument(specimenKey, null);
    });
  });

  if (btnAnalyzeText) {
    btnAnalyzeText.addEventListener('click', () => {
      const customText = (customTextArea.value || "").trim();
      if (!customText) {
        alert("Please paste document clauses or upload a file to inspect!");
        return;
      }
      analyzeDocument(null, customText);
    });
  }

  // Load default specimen on startup
  analyzeDocument('fake_arrest_warrant', null);
}

async function uploadAndAnalyzeDocument(file) {
  const verdictBadge = document.getElementById('doc-verdict-badge');
  const authScore = document.getElementById('doc-auth-score');
  const riskScore = document.getElementById('doc-risk-score');
  const rawText = document.getElementById('doc-raw-text');
  const findingsList = document.getElementById('doc-findings-list');
  const recAction = document.getElementById('doc-rec-action');

  verdictBadge.textContent = "Uploading & Processing via Document AI OCR...";

  const formData = new FormData();
  formData.append('document', file);

  try {
    const response = await fetch('/api/document-ai/analyze', {
      method: 'POST',
      body: formData
    });

    const data = await response.json();
    if (data.status === 'success') {
      const doc = data.document;
      const ana = data.analysis;

      verdictBadge.textContent = ana.verdict;
      verdictBadge.className = `status-pill ${ana.severity.toLowerCase()}`;

      authScore.textContent = `${ana.authenticityScore}/100`;
      riskScore.textContent = `${ana.riskScore}/100`;

      rawText.textContent = doc.extractedText || "No text extracted.";

      if (ana.findings && ana.findings.length > 0) {
        findingsList.innerHTML = ana.findings.map(f => `
          <div class="finding-row">
            <span class="finding-status ${f.status === 'PASSED' || f.status === 'CLEAN' ? 'passed' : 'failed'}">${f.status}</span>
            <div>
              <strong>${f.rule}:</strong> ${f.detail}
            </div>
          </div>
        `).join('');
      }

      recAction.textContent = ana.recommendedAction || "Verify through official banking channels.";
    }
  } catch (err) {
    verdictBadge.textContent = "Upload Failed";
    rawText.textContent = "Error communicating with Document AI OCR pipeline.";
  }
}

async function analyzeDocument(specimenKey, customText) {
  const verdictBadge = document.getElementById('doc-verdict-badge');
  const authScore = document.getElementById('doc-auth-score');
  const riskScore = document.getElementById('doc-risk-score');
  const rawText = document.getElementById('doc-raw-text');
  const findingsList = document.getElementById('doc-findings-list');
  const recAction = document.getElementById('doc-rec-action');

  verdictBadge.textContent = "Analyzing via Document AI...";

  try {
    const response = await fetch('/api/document-ai/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ specimenKey, customText })
    });

    const data = await response.json();
    if (data.status === 'success') {
      const doc = data.document;
      const ana = data.analysis;

      verdictBadge.textContent = ana.verdict;
      verdictBadge.className = `status-pill ${ana.severity.toLowerCase()}`;

      authScore.textContent = `${ana.authenticityScore}/100`;
      riskScore.textContent = `${ana.riskScore}/100`;

      rawText.textContent = doc.extractedText || "No text extracted.";

      if (ana.findings && ana.findings.length > 0) {
        findingsList.innerHTML = ana.findings.map(f => `
          <div class="finding-row">
            <span class="finding-status ${f.status === 'PASSED' || f.status === 'CLEAN' ? 'passed' : 'failed'}">${f.status}</span>
            <div>
              <strong>${f.rule}:</strong> ${f.detail}
            </div>
          </div>
        `).join('');
      }

      recAction.textContent = ana.recommendedAction || "Verify through official banking channels.";
    }
  } catch (err) {
    console.error("Document AI inspection failed", err);
  }
}

// ========================================================
// 5. GEMINI FRAUD REASONER (VERTEX AI CHATBOT)
// ========================================================
function initGeminiAdvisor() {
  const pills = document.querySelectorAll('.gemini-pill');
  const inputEl = document.getElementById('gemini-input-field');
  const sendBtn = document.getElementById('btn-send-gemini');
  const display = document.getElementById('gemini-chat-display');

  pills.forEach(pill => {
    pill.addEventListener('click', () => {
      const prompt = pill.dataset.prompt;
      inputEl.value = prompt;
      askGemini(prompt);
    });
  });

  if (sendBtn) {
    sendBtn.addEventListener('click', () => {
      const text = (inputEl.value || "").trim();
      if (!text) return;
      askGemini(text);
      inputEl.value = "";
    });
  }

  if (inputEl) {
    inputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const text = (inputEl.value || "").trim();
        if (!text) return;
        askGemini(text);
        inputEl.value = "";
      }
    });
  }
}

async function askGemini(prompt) {
  const display = document.getElementById('gemini-chat-display');

  // Add User Message
  const userMsg = document.createElement('div');
  userMsg.className = 'chat-message user';
  userMsg.innerHTML = `
    <div class="msg-avatar">👤</div>
    <div class="msg-body">
      <strong>You:</strong>
      <p>${prompt}</p>
    </div>
  `;
  display.appendChild(userMsg);

  // Add Assistant Loading Placeholder
  const loadingMsg = document.createElement('div');
  loadingMsg.className = 'chat-message assistant';
  loadingMsg.innerHTML = `
    <div class="msg-avatar">🧠</div>
    <div class="msg-body">
      <strong>Gemini 1.5 Reasoner:</strong>
      <p>Consulting Vertex AI fraud graph and BFSI regulatory knowledge...</p>
    </div>
  `;
  display.appendChild(loadingMsg);
  display.scrollTop = display.scrollHeight;

  try {
    const response = await fetch('/api/gemini/advisor', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt })
    });

    const data = await response.json();
    if (data.status === 'success') {
      const res = data.data;
      loadingMsg.innerHTML = `
        <div class="msg-avatar">🛡️</div>
        <div class="msg-body">
          <strong>Gemini 1.5 (Risk Assessment: <span style="color: ${res.riskLevel === 'CRITICAL' ? '#f87171' : '#38bdf8'}">${res.riskLevel}</span>):</strong>
          <p>${res.reasoning}</p>
          ${res.signals && res.signals.length > 0 ? `
            <div style="margin-top: 0.6rem; font-size: 0.8rem; color: #94a3b8;">
              <strong>Key Fraud Signals:</strong>
              <ul style="padding-left: 1.2rem; margin-top: 0.2rem;">
                ${res.signals.map(s => `<li>${s}</li>`).join('')}
              </ul>
            </div>
          ` : ''}
          <div style="margin-top: 0.6rem; padding: 0.5rem; background: rgba(16, 185, 129, 0.1); border-left: 3px solid #10b981; border-radius: 4px; font-size: 0.82rem; color: #6ee7b7;">
            <strong>Immediate Protocol:</strong> ${res.recommendedAction}
          </div>
        </div>
      `;
    }
  } catch (err) {
    loadingMsg.querySelector('.msg-body p').textContent = "Failed to communicate with Vertex AI service.";
  }

  display.scrollTop = display.scrollHeight;
}

// ========================================================
// 6. BIGQUERY MULE MATRIX & SOC ANALYTICS
// ========================================================
async function initBigQueryMatrix() {
  const threatBars = document.getElementById('threat-bars-container');
  const muleTable = document.getElementById('mule-table-body');

  try {
    const response = await fetch('/api/bigquery/analytics');
    const data = await response.json();

    if (data.status === 'success') {
      // Render Threat Vectors
      if (threatBars && data.topVectors) {
        threatBars.innerHTML = data.topVectors.map(v => `
          <div class="threat-bar-item">
            <div class="bar-meta">
              <span>${v.vector}</span>
              <span>${v.share}% (${v.count} incidents)</span>
            </div>
            <div class="bar-track">
              <div class="bar-fill" style="width: ${v.share}%"></div>
            </div>
          </div>
        `).join('');
      }

      // Render Mule Clusters Table
      if (muleTable && data.liveMuleClusters) {
        muleTable.innerHTML = data.liveMuleClusters.map(m => `
          <tr>
            <td><strong>${m.clusterId}</strong></td>
            <td>${m.nodes} Accounts</td>
            <td>${m.volumeINR}</td>
            <td><span style="color: #f87171; font-weight: 700;">${m.riskScore}%</span></td>
            <td><span class="finding-status failed">${m.status}</span></td>
          </tr>
        `).join('');
      }
    }
  } catch (err) {
    console.error("Failed to load BigQuery analytics", err);
  }
}

// ========================================================
// 7. CITIZEN SCAM REPORTER ("FEED SAFEMEAI")
// ========================================================
async function initCitizenReporting() {
  const form = document.getElementById('scam-report-form');
  const feedList = document.getElementById('citizen-reports-list');
  const successMsg = document.getElementById('report-success-msg');

  // Load existing reports
  loadCitizenReports();

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();

      const type = document.getElementById('report-type').value;
      const target = document.getElementById('report-target').value;
      const details = document.getElementById('report-details').value;
      const name = document.getElementById('report-name').value;
      const phone = document.getElementById('report-phone').value;

      try {
        const response = await fetch('/api/scam/report', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scamType: type,
            scamTarget: target,
            scamDetails: details,
            reporterName: name,
            reporterPhone: phone
          })
        });

        const data = await response.json();
        if (data.status === 'success') {
          form.reset();
          successMsg.style.display = 'block';
          setTimeout(() => { successMsg.style.display = 'none'; }, 4000);
          loadCitizenReports();
        }
      } catch (err) {
        alert("Failed to submit report. Please try again.");
      }
    });
  }
}

async function loadCitizenReports() {
  const feedList = document.getElementById('citizen-reports-list');
  if (!feedList) return;

  try {
    const response = await fetch('/api/scam/reports');
    const data = await response.json();

    if (data.status === 'success' && data.data) {
      feedList.innerHTML = data.data.map(r => `
        <div class="report-feed-item">
          <div class="feed-item-top">
            <span class="feed-item-badge">${r.scamType}</span>
            <span class="feed-item-time">${r.time}</span>
          </div>
          <div class="feed-item-target">${r.target}</div>
          <div class="feed-item-desc">${r.details}</div>
        </div>
      `).join('');
    }
  } catch (err) {
    console.error("Failed to load citizen reports", err);
  }
}
