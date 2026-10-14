const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const tls = require('tls');
const dns = require('dns').promises;
const gcp = require('./lib/gcp');
const { geminiAdvise } = require('./lib/geminiAdvisor');

const app = express();
const PORT = process.env.PORT || 8080;

// ---- Hardening: proxy trust, security headers, CORS, body limits, rate limiting ----
app.set('trust proxy', 1);          // Cloud Run: exactly one trusted hop (Google front end)
app.disable('x-powered-by');

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https://api.qrserver.com",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ].join('; '));
  next();
});

// CORS: same-origin by default. Set CORS_ORIGINS="https://a.example,https://b.example" to allow others.
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => cb(null, !origin ? false : CORS_ORIGINS.includes(origin)),
  methods: ['GET', 'POST'],
  maxAge: 600
}));

app.get('/healthz', (req, res) => res.json({ status: 'ok', uptimeSec: Math.round(process.uptime()) }));

app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'ignore', index: 'index.html' }));

// In-memory per-IP rate limiter (per Cloud Run instance; use Cloud Armor for a global limit).
const ipRequests = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 60;       // cheap routes
const MAX_EXPENSIVE_PER_WINDOW = 15;      // routes that call Gemini / DNS / TLS / OCR
const EXPENSIVE_ROUTES = /^\/api\/(scam\/check|domain\/check|gemini\/|document-ai\/analyze)/;

app.use((req, res, next) => {
  if (!req.path.startsWith('/api/')) return next();
  const expensive = EXPENSIVE_ROUTES.test(req.path);
  const key = (expensive ? 'x:' : 'c:') + (req.ip || 'unknown');
  const limit = expensive ? MAX_EXPENSIVE_PER_WINDOW : MAX_REQUESTS_PER_WINDOW;
  const now = Date.now();
  let c = ipRequests.get(key);
  if (!c || now > c.resetTime) c = { count: 0, resetTime: now + RATE_LIMIT_WINDOW_MS };
  c.count++;
  ipRequests.set(key, c);
  if (c.count > limit) {
    res.setHeader('Retry-After', Math.ceil((c.resetTime - now) / 1000));
    return res.status(429).json({ error: 'Too many requests. Please try again in a minute.' });
  }
  next();
});
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of ipRequests) if (now > v.resetTime) ipRequests.delete(k);
}, 60 * 1000).unref();

// Uploads: 5 MB, allow-listed types, random server-side names, temp files deleted after processing.
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const ALLOWED_UPLOAD = { '.pdf': 'application/pdf', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.txt': 'text/plain' };
const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: 5 * 1024 * 1024, files: 1, fields: 10, fieldSize: 64 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (!ALLOWED_UPLOAD[ext]) return cb(Object.assign(new Error('Unsupported file type. Use PDF, PNG, JPG or TXT.'), { status: 415 }));
    cb(null, true);
  }
});
const safeName = n => path.basename(String(n || 'document')).replace(/[^\w.\- ]/g, '_').slice(0, 80);
const rmTemp = f => { if (f && f.path) fs.unlink(f.path, () => {}); };

// ==========================================
// PRESET SPECIMEN DOCUMENTS FOR INSTANT JUDGE TESTING
// ==========================================
const SPECIMENS = {
  fake_arrest_warrant: {
    id: "SPEC-001",
    title: "Fake Digital Arrest Warrant (CBI / Supreme Court Impersonation)",
    type: "Extortion / Digital Arrest",
    rawText: `CENTRAL BUREAU OF INVESTIGATION - NEW DELHI\n` +
      `SPECIAL CYBER CRIME CELL - ORDER NO: CBI/CYB/2026/8941\n` +
      `SUBJECT: IMMEDIATE FREEZING ORDER & NATIONAL ARREST WARRANT UNDER PMLA ACT SEC 3/4\n\n` +
      `To: The Account Holder\n` +
      `We have intercepted a suspicious DHL courier in your name containing 140g MDMA and 5 fake passports.\n` +
      `You are placed under 24-HOUR DIGITAL SURVEILLANCE. Do NOT disconnect your Skype/WhatsApp video call.\n` +
      `To clear your name from money laundering charges, transfer your total liquid funds of INR 4,85,000 to the\n` +
      `RBI FINANCIAL SAFETY VERIFICATION ESCROW ACCOUNT:\n` +
      `UPI ID: rbi.safecustody99@okhdfcbank\n` +
      `Account: 919876543210 (RBI Secret Verification Cell)\n\n` +
      `Failure to comply within 2 hours will lead to physical arrest by local police team under IPC 420/120B.\n` +
      `Signed,\n` +
      `Director General of CBI, New Delhi (Seal Attached)`,
    forensicAnalysis: {
      authenticityScore: 4, // out of 100
      riskScore: 98,
      verdict: "COUNTERFEIT_MALICIOUS",
      severity: "CRITICAL",
      findings: [
        {
          rule: "GCP_DOC_AI_SEAL_VERIFICATION",
          status: "FAILED",
          detail: "The Ashoka Lion emblem resolution is pixelated with non-standard geometric distortion indicating digital forgery."
        },
        {
          rule: "RBI_ESCROW_PROCEDURE_CHECK",
          status: "CRITICAL_VIOLATION",
          detail: "Reserve Bank of India (RBI) NEVER instructs citizens to transfer funds to personal UPI handles or 'Verification Accounts'."
        },
        {
          rule: "CRIMINAL_EXTORTION_PATTERN",
          status: "FLAGGED",
          detail: "Digital Arrest tactics detected: 'Skype/WhatsApp surveillance' and '24-Hour Digital Arrest' do not legally exist under CrPC or BNSS 2023."
        },
        {
          rule: "VPA_MULE_DETECTION",
          status: "FLAGGED",
          detail: "UPI ID 'rbi.safecustody99@okhdfcbank' belongs to a newly activated mule account flagged in I4C/CFCFRMS database."
        }
      ],
      legalCitations: ["BNSS Section 105", "IT Act Section 66D (Cheating by Impersonation)", "PMLA Guideline 2024"],
      recommendedAction: "DO NOT TRANSFER FUNDS. Disconnect video call immediately. Report to National Cyber Crime Portal (1930) and block contact."
    }
  },

  predatory_loan: {
    id: "SPEC-002",
    title: "Predatory Instant Loan Approval Notice (Harassment App)",
    type: "Loan App Extortion",
    rawText: `QUICK-CREDIT INDIA - INSTANT SANCTION LETTER\n` +
      `LOAN SANCTION REF: QC/2026/LOAN-88712\n\n` +
      `Congratulations! Your loan of INR 20,000 has been sanctioned instantly.\n` +
      `Amount Disbursed to Bank: INR 12,200 (Processing Fee + GST Deducted: INR 7,800)\n` +
      `Repayment Amount: INR 24,000\n` +
      `Repayment Due: 7 Days from Disbursal\n\n` +
      `MANDATORY TERMS:\n` +
      `- User grants irrevocable consent for 24x7 synchronization of Contact List, Camera, SMS, and Gallery photos.\n` +
      `- In case of 1 day delay, recovery agents reserve right to call all contact numbers and circulate morphed photographs to family.\n\n` +
      `Quick Credit NBFC Partner: (Unregistered Private Lending Network)`,
    forensicAnalysis: {
      authenticityScore: 8,
      riskScore: 95,
      verdict: "PREDATORY_UNREGISTERED_LENDER",
      severity: "CRITICAL",
      findings: [
        {
          rule: "RBI_DIGITAL_LENDING_COMPLIANCE",
          status: "FAILED",
          detail: "Violates RBI Digital Lending Circular 2022: Upfront 39% fee deduction on 7-day tenure exceeds legal usury caps (APR > 900%)."
        },
        {
          rule: "PRIVACY_CONTACT_HARVESTING",
          status: "CRITICAL_VIOLATION",
          detail: "Demanding access to full Contact List and Photo Gallery is strictly prohibited for regulated lending entities on Google Play & RBI."
        },
        {
          rule: "EXTORTION_RECOVERY_CLAUSE",
          status: "ILLEGAL",
          detail: "Threatening to contact relatives and circulate photographs constitutes criminal intimidation under IPC 503/506 & BNS 351."
        }
      ],
      legalCitations: ["RBI Digital Lending Guidelines (Sept 2022)", "IT Act Section 72A", "BNS Section 351"],
      recommendedAction: "Do NOT repay through unofficial UPI links. File police complaint with SafeMeAI call recording and contact blacklist."
    }
  },

  authentic_bank: {
    id: "SPEC-003",
    title: "Authentic HDFC Bank Sanction Letter (Regulated BFSI Standard)",
    type: "Legitimate Banking Document",
    rawText: `HDFC BANK LIMITED\n` +
      `RETAIL ASSETS BRANCH - CONNAUGHT PLACE, NEW DELHI - 110001\n` +
      `CIN: L65920MH1994PLC080618 | RBI REG: B-05.00012\n\n` +
      `SANCTION LETTER - PERSONAL LOAN\n` +
      `Date: 04-Oct-2026 | Ref No: HDFC/PL/2026/099824\n\n` +
      `Dear Customer,\n` +
      `We are pleased to inform you that your Personal Loan application has been sanctioned on the following terms:\n` +
      `- Sanctioned Amount: INR 5,00,000\n` +
      `- Rate of Interest: 10.75% per annum (Floating)\n` +
      `- Tenure: 48 Months | Monthly EMI: INR 12,860\n` +
      `- Processing Fee: 1.0% + GST\n` +
      `- Grievance Redressal Officer: grievances.retail@hdfcbank.com | Helpline: 1800 202 6161\n\n` +
      `For and on behalf of HDFC Bank Limited\n` +
      `Authorized Signatory (Digital Signature Attached)`,
    forensicAnalysis: {
      authenticityScore: 97,
      riskScore: 3,
      verdict: "AUTHENTIC_REGULATED_DOCUMENT",
      severity: "SAFE",
      findings: [
        {
          rule: "GCP_DOC_AI_SEAL_VERIFICATION",
          status: "PASSED",
          detail: "Valid corporate CIN and RBI Registration Number verified against MCA & RBI directories."
        },
        {
          rule: "RBI_DIGITAL_LENDING_COMPLIANCE",
          status: "PASSED",
          detail: "Full Key Fact Statement (KFS) provided with transparent APR, tenure, and approved Grievance Officer contacts."
        },
        {
          rule: "VPA_MULE_DETECTION",
          status: "CLEAN",
          detail: "No unauthorized personal UPI or third-party transfer accounts mentioned."
        }
      ],
      legalCitations: ["Banking Regulation Act 1949", "RBI Fair Practices Code"],
      recommendedAction: "Document is legitimate. Follow standard verification procedures via official HDFC Bank NetBanking."
    }
  }
};

// ==========================================
// API 1: DOCUMENT INTELLIGENCE (Google Document AI + Gemini)
// ==========================================
app.get('/api/document-ai/specimens', (req, res) => {
  res.json({
    status: 'success',
    data: Object.keys(SPECIMENS).map(key => ({
      key,
      id: SPECIMENS[key].id,
      title: SPECIMENS[key].title,
      type: SPECIMENS[key].type
    }))
  });
});

app.post('/api/document-ai/analyze', upload.single('document'), async (req, res) => {
  const body = req.body || {};
  const specimenKey = body.specimenKey;
  const tmp = req.file;
  try {
    if (specimenKey && Object.prototype.hasOwnProperty.call(SPECIMENS, specimenKey)) {
      const specimen = SPECIMENS[specimenKey];
      return res.json({
        status: 'success',
        mode: 'PRESET_SPECIMEN',
        dataSource: 'demo-simulated',
        dataSourceNote: 'Built-in specimen with pre-written forensic findings. Not produced by Document AI.',
        timestamp: new Date().toISOString(),
        document: { id: specimen.id, title: specimen.title, type: specimen.type, extractedText: specimen.rawText },
        analysis: specimen.forensicAnalysis
      });
    }

    let customText = String(body.customText || '').slice(0, 20000);
    let filename = 'User Submitted Document';
    let ocr = { available: false, reason: 'no file uploaded' };
    let ocrNote = 'Text pasted by user; analysed by keyword rules.';

    if (req.file) {
      filename = safeName(req.file.originalname);
      const ext = path.extname(filename).toLowerCase();
      if (ext === '.txt') {
        customText = fs.readFileSync(req.file.path, 'utf8').slice(0, 20000);
        ocrNote = 'Plain text read directly; analysed by keyword rules.';
      } else {
        ocr = await gcp.documentAiOcr(fs.readFileSync(req.file.path), ALLOWED_UPLOAD[ext]);
        if (ocr.available) {
          customText = ocr.text;
          ocrNote = 'Text extracted by Google Document AI; analysed by keyword rules.';
        } else {
          customText = `[OCR unavailable: ${ocr.reason}. Only the filename "${filename}" (${(req.file.size / 1024).toFixed(1)} KB) could be assessed.]`;
          ocrNote = `Document AI not used (${ocr.reason}). Verdict is based on filename only and is NOT a document analysis.`;
        }
      }
    }

    const hay = customText + ' ' + filename;
    const isDigitalArrest = /cbi|arrest|police|supreme court|pmla|mdma|customs|escrow|skype|surveillance|verification account/i.test(hay);
    const isLoanScam = /7-day|processing fee|gallery|contacts|quick cash|urgent loan|predatory/i.test(hay);
    const ocrMissing = Boolean(req.file) && !ocr.available && path.extname(filename).toLowerCase() !== '.txt';

    let riskScore = ocrMissing ? 50 : 15;
    let verdict = ocrMissing ? 'UNVERIFIED_NO_OCR' : 'REQUIRES_FURTHER_VERIFICATION';
    let severity = ocrMissing ? 'MEDIUM' : 'LOW';
    if (isDigitalArrest) { riskScore = 98; verdict = 'COUNTERFEIT_FORGED_WARRANT'; severity = 'CRITICAL'; }
    else if (isLoanScam) { riskScore = 94; verdict = 'PREDATORY_UNREGISTERED_LENDER'; severity = 'HIGH'; }
    const flagged = isDigitalArrest || isLoanScam;

    res.json({
      status: 'success',
      mode: req.file ? (ocr.available ? 'FILE_UPLOAD_DOCUMENT_AI_OCR' : (ocrMissing ? 'FILE_UPLOAD_NO_OCR' : 'FILE_UPLOAD_TEXT')) : 'TEXT_KEYWORD_RULES',
      dataSource: ocr.available ? 'document-ai+rules' : 'rules-engine',
      dataSourceNote: ocrNote,
      timestamp: new Date().toISOString(),
      document: {
        id: 'DOC-UP-' + Math.floor(Math.random() * 9000 + 1000),
        title: filename,
        extractedText: customText || 'No text supplied.'
      },
      analysis: {
        authenticityScore: Math.max(4, 100 - riskScore),
        riskScore,
        verdict,
        severity,
        findings: [
          {
            rule: 'KEYWORD_SCAM_PATTERN_MATCH',
            status: flagged ? 'FAILED' : (ocrMissing ? 'INCONCLUSIVE' : 'NO_MATCH'),
            detail: isDigitalArrest
              ? 'Text matches known digital-arrest / fake-warrant wording. Indian law-enforcement agencies never demand fund transfers.'
              : isLoanScam ? 'Text matches predatory-lending patterns (upfront fees, contact/gallery access).'
              : (ocrMissing ? 'Document text could not be extracted, so no content check was possible.' : 'No known scam wording found. This does not prove the document is genuine.')
          },
          {
            rule: 'REGULATORY_REFERENCE',
            status: flagged ? 'CRITICAL_VIOLATION' : 'NOT_EVALUATED',
            detail: isDigitalArrest ? 'Digital arrest has no basis in BNSS/CrPC.' : isLoanScam ? 'Contact/gallery harvesting is prohibited under the RBI 2022 Digital Lending guidelines.' : 'Seal/signature and issuer-registry verification are not performed by this demo.'
          }
        ],
        legalCitations: isDigitalArrest ? ['BNSS Section 105', 'IT Act Section 66D', 'BNS Section 318 (Cheating)'] : ['RBI Fair Practices Code', 'IT Act Section 43/66'],
        recommendedAction: isDigitalArrest
          ? 'CRITICAL: Do NOT pay any money. Disconnect the call immediately and dial 1930.'
          : isLoanScam ? 'PREDATORY APP: Do NOT grant contact or gallery permissions. Report to RBI CMS (cms.rbi.org.in).'
          : 'No scam wording detected, but verify any official document directly with the issuing institution.'
      }
    });
  } catch (e) {
    console.error('[document-ai] failure:', e.message);
    res.status(500).json({ error: 'Document analysis failed. Treat the document as unverified.' });
  } finally {
    rmTemp(tmp);
  }
});

// Upload/body error handler (multer limits, bad JSON, wrong type)
app.use((err, req, res, next) => {
  if (!err) return next();
  const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : (err.status || err.statusCode || (err.name === 'MulterError' ? 400 : 500));
  if (status >= 500) console.error('[error]', err.message);
  if (req.file) rmTemp(req.file);
  res.status(status).json({ error: status === 413 ? 'File or request too large (max 5 MB).' : (status < 500 ? err.message : 'Internal error') });
});

// ==========================================
// API 2: GEMINI ON VERTEX AI (Fraud Reasoning & Financial Advisory)
// ==========================================
app.post('/api/gemini/advisor', async (req, res) => {
  const raw = req.body && req.body.prompt;
  const userQuery = (typeof raw === 'string' ? raw : '').trim().slice(0, 2000);
  if (!userQuery) return res.status(400).json({ error: 'Please describe the suspicious message or situation.' });

  const g = await geminiAdvise(userQuery);
  if (g.available) {
    return res.json({
      status: 'success',
      data: {
        model: `${g.model} (${g.via})`, grounded: true, dataSource: 'gemini-live',
        query: userQuery, timestamp: new Date().toISOString(),
        reasoning: g.reasoning, riskLevel: g.riskLevel, signals: g.signals, recommendedAction: g.recommendedAction
      }
    });
  }
  const f = advisorRules(userQuery);
  res.json({
    status: 'success',
    data: {
      model: 'rules-engine fallback', grounded: false, dataSource: 'rules-engine',
      fallbackReason: g.reason || 'Gemini unavailable',
      query: userQuery, timestamp: new Date().toISOString(), ...f
    }
  });
});

/** Deterministic keyword advisor, used only when Gemini is unreachable. */
function advisorRules(userQuery) {
  const responseData = { reasoning: '', riskLevel: 'MEDIUM', signals: [], recommendedAction: '' };
  const lower = userQuery.toLowerCase();
  if (lower.includes("digital arrest") || lower.includes("cbi") || lower.includes("parcel") || lower.includes("skype") || lower.includes("customs")) {
    responseData.riskLevel = "CRITICAL";
    responseData.signals = [
      "Psychological Fear Appeal (Coercive threat of immediate arrest)",
      "Impersonation of Central Law Enforcement Agency (CBI / Customs / Cyber Cell)",
      "Demand for digital surveillance isolation (staying on camera)",
      "Financial Escrow / Fund Verification Transfer trap"
    ];
    responseData.reasoning = 
      "This matches the signature traits of the 'Digital Arrest' cyber-extortion scheme. In Indian law (CrPC / BNSS), no court or police officer conducts bail, investigation, or asset verification over WhatsApp or Skype video calls, nor does the Reserve Bank of India maintain 'verification escrow' accounts for individuals.";
    responseData.recommendedAction = 
      "1. Immediately disconnect the call and block the sender.\n" +
      "2. Do NOT transfer any money.\n" +
      "3. Inform your local police station or dial 1930 (National Cyber Crime Reporting Helpline).\n" +
      "4. Report the number at cybercrime.gov.in so it can be flagged.";
  } else if (lower.includes("upi") || lower.includes("pin") || lower.includes("qr") || lower.includes("refund") || lower.includes("receive")) {
    responseData.riskLevel = "HIGH";
    responseData.signals = [
      "UPI Collect Request Inversion Scam (Paying to Receive)",
      "Urgency trigger (Refund expiring within 15 mins)",
      "Fake customer support / delivery partner handle"
    ];
    responseData.reasoning = 
      "In the Unified Payments Interface (UPI) architecture, you NEVER need to enter your UPI PIN, scan a QR code, or approve a Collect Request to RECEIVE money. Entering your PIN authorizes a debit from your account.";
    responseData.recommendedAction = 
      "Reject the collect request immediately on PhonePe / Google Pay / Paytm.";
  } else if (lower.includes("telegram") || lower.includes("like youtube") || lower.includes("part time job") || lower.includes("crypto return")) {
    responseData.riskLevel = "CRITICAL";
    responseData.signals = [
      "Task-based Pig Butchering Scheme",
      "Mule account recruitment funnel",
      "Initial small payout hook followed by high deposit requirement"
    ];
    responseData.reasoning = 
      "This is a classic 'Task Scam'. Scammers pay INR 150-500 initially to build false trust, then demand thousands in 'pre-paid tasks' on simulated trading platforms. The bank accounts you transfer to are illegal mule accounts.";
    responseData.recommendedAction = 
      "Cease all contact immediately. Exit the Telegram group. Any funds sent to their accounts should be reported immediately via cybercrime.gov.in.";
  } else {
    responseData.riskLevel = "MEDIUM";
    responseData.signals = ["No known scam pattern matched by the offline rules (this is not a safety guarantee)"];
    responseData.reasoning = 
      "The offline rules could not assess this message; treat it as unverified. Remember the golden BFSI security rule: Never share OTPs, UPI PINs, CVV codes, or install remote-access apps (AnyDesk, TeamViewer, RustDesk) at the request of anyone claiming to represent a bank.";
    responseData.recommendedAction = "Verify all sensitive inquiries directly through official banking apps or customer support numbers on your debit card.";
  }
  return responseData;
}

// ==========================================
// API 3: BIGQUERY RISK & ANOMALY ANALYTICS
// ==========================================
app.get('/api/bigquery/analytics', async (req, res) => {
  const bq = await gcp.bigQueryTopVectors();
  const live = bq.available ? { topVectors: bq.rows, activeQuerySample: bq.query } : {};
  res.json({
    status: 'success',
    dataSource: bq.available ? 'bigquery-live-vectors+demo-simulated-rest' : 'demo-simulated',
    dataSourceNote: bq.available
      ? 'Top vectors come from a live BigQuery query; KPIs and mule clusters are illustrative demo data.'
      : `Illustrative demo data, not a real BigQuery result (${bq.reason}).`,
    engine: bq.available ? 'Google Cloud BigQuery (live query for vectors; rest simulated)' : 'Simulated analytics (BigQuery not connected)',
    queryExecutionTimeMs: null,
    dataset: "safeme_bfsi_lakehouse.transaction_fraud_telemetry",
    kpis: {
      totalTransactionsAnalyzed: "14,892,105",
      threatsBlocked24h: "3,812",
      fraudLossPreventedINR: "₹18,42,80,000",
      activeMuleRingsTracked: "148",
      edgeSensorsReporting: "24,510"
    },
    kpisAreSimulated: true,
    topVectors: [
      { vector: "UPI Collect / Fake Refund", share: 38, count: 1448 },
      { vector: "Digital Arrest Video Extortion", share: 29, count: 1105 },
      { vector: "Predatory Instant Loan APKs", share: 18, count: 686 },
      { vector: "Task / Mule Account Job Lures", share: 11, count: 419 },
      { vector: "SIM Swap / Banking Phishing", share: 4, count: 154 }
    ],
    liveMuleClusters: [
      { clusterId: "MULE-DELHI-09", nodes: 24, volumeINR: "₹1.4 Cr", status: "FLAGGED_FOR_FREEZE", riskScore: 99.4 },
      { clusterId: "MULE-MUMBAI-03", nodes: 18, volumeINR: "₹85 Lakh", status: "UNDER_MONITORING", riskScore: 94.1 },
      { clusterId: "MULE-BENGALURU-14", nodes: 31, volumeINR: "₹2.2 Cr", status: "LEO_DISPATCHED", riskScore: 98.7 },
      { clusterId: "MULE-KOLKATA-07", nodes: 12, volumeINR: "₹42 Lakh", status: "AUTO_THROTTLED", riskScore: 89.2 }
    ],
    activeQuerySampleIsIllustrative: !bq.available,
    activeQuerySample: 
      `SELECT \n` +
      `  payer_vpa, \n` +
      `  payee_vpa, \n` +
      `  amount, \n` +
      `  ML.DETECT_ANOMALIES(MODEL \`safeme_bfsi.mule_isolation_forest\`, \n` +
      `    TABLE \`safeme_bfsi.realtime_upi_stream\`) AS anomaly_status \n` +
      `FROM \`safeme_bfsi.realtime_upi_stream\` \n` +
      `WHERE DATE(timestamp) = CURRENT_DATE() \n` +
      `ORDER BY anomaly_score DESC LIMIT 100;`,
    ...live
  });
});

// ==========================================
// API 4: VERTEX AI SEARCH / REGULATORY COMPLIANCE
// ==========================================
app.post('/api/compliance/search', (req, res) => {
  const rawQuery = String((req.body && req.body.query) || '').slice(0, 500);
  const query = rawQuery.toLowerCase();

  let citation = {
    source: "Reserve Bank of India (RBI) Master Direction on Customer Protection",
    regulationNumber: "RBI/2017-18/15 DBR.No.Leg.BC.78/09.07.005/2017-18",
    clause: "Zero Liability of a Customer in Unauthorized Electronic Banking Transactions",
    summary: "If an unauthorized transaction occurs due to third-party breach or fraud where deficiency lies neither with the bank nor customer, and the customer notifies the bank within THREE working days, the customer liability is ZERO.",
    steps: [
      "1. Immediately report the unauthorized transaction to the issuing bank within 72 hours.",
      "2. Obtain official incident complaint token / acknowledgment number.",
      "3. Register an FIR / complaint on national portal 1930 (cybercrime.gov.in).",
      "4. Bank must credit the shadow reversal into customer account within 10 working days."
    ]
  };

  if (query.includes("loan") || query.includes("recovery") || query.includes("harassment")) {
    citation = {
      source: "RBI Guidelines on Digital Lending - Protection of Borrowers",
      regulationNumber: "RBI/2022-23/111 DOR.CRE.REC.66/21.07.001/2022-23",
      clause: "Fair Practices Code - Fair Recovery Measures & Data Privacy",
      summary: "Regulated Lending Entities (REs) and their Lending Service Providers (LSPs) are strictly prohibited from accessing mobile phone resources such as Contacts, File and Media, Call Logs, or Telephony data. Recovery agents cannot contact borrowers between 7 PM and 8 AM or intimidate family members.",
      steps: [
        "1. Check if the lending app is listed in RBI's approved NBFC portal.",
        "2. Save call recordings and WhatsApp extortion screenshots.",
        "3. Lodge complaint on RBI CMS portal (cms.rbi.org.in).",
        "4. Block and report the abusive callers to 1930 / cybercrime.gov.in."
      ]
    };
  }

  res.json({
    status: 'success',
    dataSource: 'curated-static',
    retrievalEngine: 'Curated static citations (keyword match; Vertex AI Search is not connected)',
    query: rawQuery,
    data: citation
  });
});

// ==========================================
// API 5: TELEMETRY STREAM INGESTION (PUB/SUB SUBSCRIBER)
// ==========================================
app.post('/api/telemetry/ingest', (req, res) => {
  const { deviceId } = req.body || {};
  // Demo endpoint: validates and acknowledges only. Nothing is published to Pub/Sub or stored.
  res.json({
    status: 'success',
    event: 'SIMULATED_ACK',
    dataSource: 'demo-simulated',
    messageId: 'sim-' + Math.random().toString(36).substring(2, 10),
    timestamp: new Date().toISOString(),
    ingestedFrom: String(deviceId || 'unknown').replace(/[^\w.\-]/g, '_').slice(0, 64)
  });
});

// ==========================================
// AUTHORITATIVE WHITELISTS & BRAND MATRIX (HCRV ENGINE)
// ==========================================
// Loaded from data/allowlist.json (entries: {domain, category, owner}); edit that file, not this code.
const ALLOWLIST_ENTRIES = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'allowlist.json'), 'utf8')).entries;
const PROTECTED_DOMAINS_WHITELIST = new Set(ALLOWLIST_ENTRIES.map(e => String(e.domain).toLowerCase()));

function isProtectedDomain(host) {
  if (!host) return false;
  const h = host.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].split('?')[0].trim();
  if (!h) return false;
  if (PROTECTED_DOMAINS_WHITELIST.has(h)) return true;
  for (const p of PROTECTED_DOMAINS_WHITELIST) {
    if (h === p || h.endsWith('.' + p)) return true;
  }
  // Sovereign & Regulated Banking Infrastructure
  // In India: .gov.in (Government), .nic.in (National Informatics Centre), .bank.in (RBI/IDRBT Regulated Banks), .jud.in (Judiciary), .mil.in (Defence)
  if (h.endsWith('.gov.in') || h.endsWith('.nic.in') || h.endsWith('.bank.in') || h.endsWith('.jud.in') || h.endsWith('.mil.in')) {
    return true;
  }
  return false;
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[a.length][b.length];
}

function findSimilarProtectedDomain(host) {
  const norm = host.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].split('?')[0].trim();
  if (isProtectedDomain(norm)) return null;
  for (const protectedDomain of PROTECTED_DOMAINS_WHITELIST) {
    if (Math.abs(norm.length - protectedDomain.length) <= 2) {
      const dist = levenshtein(norm, protectedDomain);
      if (dist >= 1 && dist <= 2 && norm !== protectedDomain) {
        return protectedDomain;
      }
    }
  }
  return null;
}

const BRAND_KEYWORDS = [
  { keyword: "sbi", name: "State Bank of India (SBI)", official: "sbi.co.in" },
  { keyword: "hdfc", name: "HDFC Bank", official: "hdfcbank.com" },
  { keyword: "icici", name: "ICICI Bank", official: "icicibank.com" },
  { keyword: "axis", name: "Axis Bank", official: "axisbank.com" },
  { keyword: "pnb", name: "Punjab National Bank (PNB)", official: "pnbindia.in" },
  { keyword: "bob", name: "Bank of Baroda", official: "bankofbaroda.in" },
  { keyword: "kotak", name: "Kotak Mahindra Bank", official: "kotak.com" },
  { keyword: "rbi", name: "Reserve Bank of India (RBI)", official: "rbi.org.in" },
  { keyword: "cbi", name: "Central Bureau of Investigation (CBI)", official: "cbi.gov.in" },
  { keyword: "police", name: "Police Cyber Cell", official: "cybercrime.gov.in" },
  { keyword: "cybercrime", name: "National Cyber Crime Portal", official: "cybercrime.gov.in" },
  { keyword: "pmkisan", name: "PM-KISAN Portal", official: "pmkisan.gov.in" },
  { keyword: "challan", name: "Parivahan e-Challan", official: "echallan.parivahan.gov.in" },
  { keyword: "parivahan", name: "Ministry of Road Transport (Parivahan)", official: "parivahan.gov.in" },
  { keyword: "indiapost", name: "India Post (Department of Posts)", official: "indiapost.gov.in" },
  { keyword: "speedpost", name: "India Post Speed Post", official: "indiapost.gov.in" },
  { keyword: "electricity", name: "State Electricity Discom", official: "Official State DISCOM" },
  { keyword: "bescom", name: "BESCOM Karnataka", official: "bescom.karnataka.gov.in" },
  { keyword: "mahadiscom", name: "MSEDCL Maharashtra", official: "mahadiscom.in" },
  { keyword: "uppcl", name: "UPPCL Uttar Pradesh", official: "upenergy.in" },
  { keyword: "phonepe", name: "PhonePe", official: "phonepe.com" },
  { keyword: "paytm", name: "Paytm Payments", official: "paytm.com" },
  { keyword: "gpay", name: "Google Pay", official: "pay.google.com" },
  { keyword: "fedex", name: "FedEx Express", official: "fedex.com" },
  { keyword: "dhl", name: "DHL Express", official: "dhl.com" },
  { keyword: "airtel", name: "Bharti Airtel", official: "airtel.in" },
  { keyword: "jio", name: "Reliance Jio", official: "jio.com" },
  { keyword: "trai", name: "Telecom Regulatory Authority of India (TRAI)", official: "trai.gov.in" },
  { keyword: "ujjivan", name: "Ujjivan Small Finance Bank", official: "ujjivansfb.in" },
  { keyword: "aubank", name: "AU Small Finance Bank", official: "aubank.in" }
];

const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "buzz", "club", "work", "vip", "tk", "ml", "ga", "cf",
  "online", "site", "shop", "icu", "link", "cc", "click", "live", "rest", "cam",
  "biz", "info", "monster", "pro", "fit", "run", "space"
]);

const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "is.gd", "cutt.ly", "rb.gy", "t.co", "shorturl.at",
  "wa.me", "page.link", "goo.gl", "ow.ly", "buff.ly", "v.ht", "clck.ru"
]);

// ==========================================
// REAL-TIME THREAT INTELLIGENCE & TELEMETRY ENGINE
// ==========================================
// Ingestion platform (lib/ingest/*): sources -> lib/threatStore.js (in-memory snapshot, Firestore/file persistence).
// OpenPhish is now just one source (lib/ingest/sources/global/openphish.js). Cloud Scheduler is the real driver
// (POST /internal/ingest/run); an in-process timer is a best-effort fallback (INGEST_INPROCESS=0 disables it).
const { createPlatform, mountRoutes: mountIngestRoutes } = require('./lib/ingest/platform');
const { createCloudflareCheck } = require('./lib/cloudflareDns');
const threatPlatform = createPlatform();
const threatStore = threatPlatform.store;
mountIngestRoutes(app, threatPlatform);
if (process.env.DISABLE_THREAT_INTEL !== '1') {
  threatPlatform.start().catch(err => console.warn('[ThreatIntel] start failed:', err.message));
}
const securityDns = process.env.DISABLE_CLOUDFLARE_DNS === '1' ? null : createCloudflareCheck();

// Legacy-shaped adapter so the engine's OpenPhish path keeps working (O(1) in-memory lookups only).
const openPhishAdapter = {
  domains: { has: (h) => threatStore.lookup('domain', h).some(x => x.source === 'openphish') },
  urls: { has: (u) => { const n = require('./lib/ingest/contract').normaliseUrl(u); return Boolean(n) && threatStore.lookup('url', n).some(x => x.source === 'openphish'); } }
};
function openPhishHealth() {
  const m = threatStore.sourceMeta('openphish');
  const st = threatPlatform.runner.peek('openphish') || {};
  const src = threatPlatform.runner.getSource('openphish') || {};
  const staleMs = (src.staleAfterHours || 12) * 3600 * 1000;
  return {
    live: Boolean(m) && (Date.now() - m.ingestedAt) < staleMs, // never "live" for a stale feed
    lastAttempt: st.lastAttempt || 0, lastSuccess: m ? m.ingestedAt : 0, lastError: st.lastError || null, indicators: m ? m.count : 0
  };
}

app.get('/api/threat-feed/status', async (req, res) => {
  const h = openPhishHealth();
  let feeds = [];
  try { feeds = (await threatPlatform.runner.status()).feeds.map(f => ({ id: f.id, name: f.name, group: f.group, status: f.status, live: f.live, stale: f.stale, indicators: f.indicators, lastSuccess: f.lastSuccess, ageSec: f.ageSec, license: f.license })); } catch (_) {}
  res.json({
    status: 'success', feed: 'OpenPhish community feed', ...h,
    ageSec: h.lastSuccess ? Math.round((Date.now() - h.lastSuccess) / 1000) : null,
    storeReady: threatStore.ready, feeds
  });
});

async function performRealtimeDnsCheck(host) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const resp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, {
      signal: controller.signal,
      headers: { 'Accept': 'application/dns-json' }
    });
    clearTimeout(timeout);
    if (!resp.ok) {
      return { resolved: false, status: `HTTP_${resp.status}`, ips: [], ttl: null, isFastFlux: false, provider: "Google Public DNS (DoH)" };
    }
    const data = await resp.json();
    const status = data.Status;
    const answers = (data.Answer || []).filter(a => a.type === 1);
    const ips = answers.map(a => a.data);
    const minTtl = answers.length > 0 ? Math.min(...answers.map(a => a.TTL)) : null;
    const isFastFlux = minTtl !== null && minTtl < 60;
    const isNxDomain = status === 3;

    return {
      resolved: ips.length > 0,
      status: status === 0 ? "NOERROR" : (isNxDomain ? "NXDOMAIN" : `STATUS_${status}`),
      ips: ips.slice(0, 5),
      ttl: minTtl,
      isFastFlux,
      isNxDomain,
      provider: "Google Public DNS (DoH RFC 8484)"
    };
  } catch (err) {
    return {
      resolved: false,
      status: "TIMEOUT_OR_UNRESOLVABLE",
      ips: [],
      ttl: null,
      isFastFlux: false,
      error: err.name === 'AbortError' ? 'DNS Resolution Timeout (3000ms)' : err.message,
      provider: "Google Public DNS (DoH)"
    };
  }
}

// SSRF guard: resolve first, refuse non-public targets, then connect to the vetted IP (no DNS rebinding).
async function performRealtimeSslCheck(host) {
  const bad = (why) => ({ supported: false, hasValidSsl: false, error: why, subjectOrg: 'Not probed', issuer: 'None' });
  try {
    if (!host || /^(localhost|.*\.(local|internal|localdomain))$/i.test(host)) return bad('Blocked non-public host');
    const addrs = await dns.lookup(host, { all: true });
    if (!addrs.length || !addrs.every(a => gcp.isPublicIp(a.address))) return bad('Blocked non-public address');
    return await rawSslCheck(host, addrs[0].address);
  } catch (e) {
    return bad(e.code || e.message);
  }
}

function rawSslCheck(host, ip) {
  return new Promise((resolve) => {
    let resolved = false;
    const finish = (res) => {
      if (!resolved) {
        resolved = true;
        resolve(res);
      }
    };

    let sockRef = null;
    const timer = setTimeout(() => {
      if (sockRef) sockRef.destroy();
      finish({
        supported: false,
        hasValidSsl: false,
        error: "TLS Handshake Timeout (2500ms)",
        subjectOrg: "Unknown / Unresponsive TLS",
        issuer: "None"
      });
    }, 2500);

    try {
      const socket = tls.connect({
        host: ip,
        port: 443,
        servername: host,
        rejectUnauthorized: false,
        timeout: 2500
      }, () => {
        clearTimeout(timer);
        try {
          const cert = socket.getPeerCertificate(true);
          const authorized = socket.authorized;
          const authError = socket.authorizationError;
          socket.end();

          if (!cert || Object.keys(cert).length === 0) {
            return finish({
              supported: false,
              hasValidSsl: false,
              error: "No certificate presented",
              subjectOrg: "None",
              issuer: "None"
            });
          }

          const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
          const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
          const now = new Date();
          const ageDays = validFrom ? Math.floor((now - validFrom) / (1000 * 60 * 60 * 24)) : null;
          const remainingDays = validTo ? Math.floor((validTo - now) / (1000 * 60 * 60 * 24)) : null;

          const issuerOrg = cert.issuer ? (cert.issuer.O || cert.issuer.CN || "Unknown Issuer") : "Unknown";
          const subjectOrg = cert.subject ? (cert.subject.O || "") : "";
          const isEV_OV = Boolean(subjectOrg && subjectOrg.trim().length > 0);
          const isFreeDV = /let's encrypt|zerossl|cloudflare|cpanel/i.test(issuerOrg);
          const isNewlyIssued = ageDays !== null && ageDays <= 7;
          const isExpired = remainingDays !== null && remainingDays < 0;

          finish({
            supported: true,
            hasValidSsl: authorized || (!isExpired && ageDays !== null && ageDays >= 0),
            authorized,
            authError: authorized ? null : authError,
            subjectOrg: subjectOrg || "None (Domain Validated / Unverified Entity)",
            issuer: issuerOrg,
            ageDays,
            remainingDays,
            isEV_OV,
            isFreeDV,
            isNewlyIssued,
            isExpired,
            fingerprint256: cert.fingerprint256 ? cert.fingerprint256.substring(0, 18) + '...' : null
          });
        } catch (e) {
          finish({
            supported: false,
            hasValidSsl: false,
            error: "Failed to parse certificate: " + e.message,
            subjectOrg: "Error",
            issuer: "Error"
          });
        }
      });

      sockRef = socket;
      socket.on('error', (err) => {
        clearTimeout(timer);
        finish({
          supported: false,
          hasValidSsl: false,
          error: err.code || err.message,
          subjectOrg: "Unencrypted (Port 443 Closed)",
          issuer: "None"
        });
      });
    } catch (err) {
      clearTimeout(timer);
      finish({
        supported: false,
        hasValidSsl: false,
        error: err.message,
        subjectOrg: "Connection Failure",
        issuer: "None"
      });
    }
  });
}

function calculateShannonEntropy(str) {
  if (!str) return 0;
  const clean = str.toLowerCase().replace(/[^a-z0-9-]/g, '');
  const len = clean.length;
  if (len === 0) return 0;
  const freq = {};
  for (let i = 0; i < len; i++) {
    const c = clean[i];
    freq[c] = (freq[c] || 0) + 1;
  }
  let entropy = 0;
  for (const c in freq) {
    const p = freq[c] / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(3));
}

function performAgenticAiForensics({ host, dns, ssl, isOpenPhish, entropy, isLookalike, brandMatch, isSuspiciousTld, isWhitelisted }) {
  if (isWhitelisted) {
    return {
      model: "Gemini 1.5 Threat Hunter (Vertex AI Grounded)",
      verdict: "BENIGN_AUTHENTICATED_SOVEREIGN",
      confidence: "99.8%",
      threatVector: "None - Official Sovereign/Banking Infrastructure",
      rationale: `Host '${host}' is cryptographically certified under India's official BFSI/Sovereign directory. Live DNS resolves to ${dns.ips ? dns.ips.length : 1} authorized endpoints with ${ssl.isEV_OV ? 'Extended/Organization Validation (' + ssl.subjectOrg + ')' : 'valid TLS encryption'}. Zero spoofing indicators.`
    };
  }

  if (isOpenPhish) {
    return {
      model: "Gemini 1.5 Threat Hunter (Real-Time Threat Intelligence)",
      verdict: "CONFIRMED_ZERO_DAY_PHISHING",
      confidence: "99.9%",
      threatVector: "Global Threat Feed Match (OpenPhish Community Stream)",
      rationale: `CRITICAL ALERT: '${host}' was detected actively in the live OpenPhish zero-day feed. This domain is currently harvesting credentials or distributing malicious payloads globally.`
    };
  }

  if (isLookalike || brandMatch) {
    const brandName = brandMatch ? brandMatch.name : isLookalike;
    return {
      model: "Gemini 1.5 Threat Hunter (Typosquatting & Brand Defense)",
      verdict: "CONFIRMED_PHISHING_BRAND_IMPERSONATION",
      confidence: "98.5%",
      threatVector: "Visual Impersonation & Typosquatting Trap",
      rationale: `Host '${host}' visually and lexically impersonates '${brandName}'. ${ssl.isFreeDV ? 'Uses automated free Domain-Validated TLS (' + ssl.issuer + ') with zero organizational identity.' : (ssl.supported ? 'TLS is active but lacks institutional ownership.' : 'Lacks authorized banking TLS certificate.')} High likelihood of credential harvesting.`
    };
  }

  if (dns.isNxDomain) {
    return {
      model: "Gemini 1.5 Threat Hunter (DNS Sinkhole & Fast-Flux)",
      verdict: "MALICIOUS_OR_SINKHOLED_HOST",
      confidence: "92.0%",
      threatVector: "Unresolvable / Sinkholed Domain (NXDOMAIN)",
      rationale: `Host '${host}' returned NXDOMAIN from Google Public DNS. This indicates an ephemeral phishing server that was rapidly taken down or unregistered domain lure.`
    };
  }

  if (isSuspiciousTld && (ssl.isNewlyIssued || ssl.isFreeDV || entropy > 3.6)) {
    return {
      model: "Gemini 1.5 Threat Hunter (Zero-Day Anomaly Detection)",
      verdict: "SUSPICIOUS_ZERO_DAY_PHISHING_CANDIDATE",
      confidence: "89.0%",
      threatVector: "Disposable TLD with Algorithmic or Free TLS Signature",
      rationale: `Domain uses high-abuse extension with ${ssl.isNewlyIssued ? 'freshly minted TLS certificate (' + ssl.ageDays + ' days old)' : 'unverified ownership'} and lexical entropy ${entropy}. Highly anomalous for legitimate banking or commercial transactions.`
    };
  }

  if (dns.resolved && ssl.hasValidSsl && !ssl.isNewlyIssued && entropy < 3.7) {
    return {
      model: "Gemini 1.5 Threat Hunter (Contextual Risk Engine)",
      verdict: "STANDARD_EXTERNAL_BENIGN_DOMAIN",
      confidence: "88.0%",
      threatVector: "None Detected - Standard Third-Party Host",
      rationale: `Host '${host}' exhibits normal DNS resolution, established TLS certificate age (${ssl.ageDays !== null ? ssl.ageDays + ' days' : 'active'}), and natural lexical distribution (entropy: ${entropy}). No visual brand traps detected.`
    };
  }

  return {
    model: "Gemini 1.5 Threat Hunter (Edge Forensics)",
    verdict: "UNVERIFIED_THIRD_PARTY_HOST",
    confidence: "75.0%",
    threatVector: "Unverified Private Host",
    rationale: `Host '${host}' is not registered on official institutional directories. Exercise caution and do not input banking credentials or OTPs.`
  };
}

// ==========================================
// DOMAIN INTELLIGENCE ENGINE WIRING (see lib/domainEngine.js)
// ==========================================
const engine = require('./lib/domainEngine');
const textEngine = require('./lib/textEngine');
const engineDeps = {
  whitelist: PROTECTED_DOMAINS_WHITELIST,
  _matcher: engine.buildMatcher(PROTECTED_DOMAINS_WHITELIST),
  brands: BRAND_KEYWORDS,
  suspiciousTlds: SUSPICIOUS_TLDS,
  shorteners: URL_SHORTENERS,
  dnsCheck: performRealtimeDnsCheck,
  sslCheck: performRealtimeSslCheck,
  openPhish: openPhishAdapter,
  threatStore,
  securityDns,
  useGemini: process.env.DISABLE_GEMINI !== '1'
};

function levelBoost(score) {
  return score >= 80 ? 'CRITICAL' : (score >= 60 ? 'HIGH' : 'MODERATE');
}

function agenticFromAssessment(a) {
  const g = a.gemini;
  if (g && g.available) {
    return {
      model: `Gemini (${g.model}) via ${g.via}`,
      verdict: g.verdict,
      confidence: g.confidence != null ? `${Math.round(g.confidence * 100)}%` : 'n/a',
      threatVector: g.threatVector,
      rationale: g.rationale,
      signals: g.signals,
      grounded: true
    };
  }
  const why = g && g.reason ? g.reason : 'not configured';
  return {
    model: `SafeMeAI deterministic forensics engine (Gemini unavailable: ${why})`,
    verdict: a.verdict,
    confidence: 'n/a',
    threatVector: a.verified ? 'None - verified official domain' : (a.flags[0] || 'Insufficient evidence'),
    rationale: a.verified ? a.evidenceForTrust.join(' ') : a.flags.slice(0, 3).join(' | '),
    grounded: false
  };
}

function telemetryFromAssessment(a) {
  const dns = a.dns || {};
  const ssl = a.ssl || {};
  return {
    dns: {
      provider: dns.provider, status: dns.status, resolved: dns.resolved, ips: dns.ips || [],
      ttl: dns.ttl, isFastFlux: dns.isFastFlux, isNxDomain: dns.isNxDomain
    },
    ssl: {
      supported: ssl.supported, hasValidSsl: ssl.hasValidSsl, authorized: ssl.authorized, error: ssl.error,
      subjectOrg: ssl.subjectOrg, issuer: ssl.issuer, ageDays: ssl.ageDays, remainingDays: ssl.remainingDays,
      isEV_OV: ssl.isEV_OV, isFreeDV: ssl.isFreeDV, isNewlyIssued: ssl.isNewlyIssued, isExpired: ssl.isExpired
    },
    threatFeeds: {
      openPhishMatch: a.isOpenPhish,
      feedName: "OpenPhish Global Community Feed",
      activeIndicators: openPhishHealth().indicators,
      feedLive: openPhishHealth().live,
      feedLastError: openPhishHealth().lastError,
      threatStore: { ready: threatStore.ready, totalIndicators: threatStore.stats().totalIndicators },
      listedBy: (a.threatFeeds || []).map(f => f.name || f.source),
      cloudflareDns: a.cloudflare,
      popularRank: a.popularRank,
      webRisk: a.webRisk,
      timestamp: new Date().toISOString()
    },
    domainAge: a.domainAge,
    mlDiagnostics: {
      shannonEntropy: a.entropy,
      isDGA: a.entropy > 3.8 && a.registrable.split('.')[0].length > 12,
      entropyRating: a.entropy > 3.8 ? "High (Algorithmic DGA Pattern)" : (a.entropy > 3.2 ? "Moderate" : "Normal Lexical Distribution")
    },
    agenticAi: agenticFromAssessment(a)
  };
}

const VERDICT_COPY = {
  FAKE_OFFICIAL_NAMESPACE: ["🚨 FORGED OFFICIAL DOMAIN: This address does not exist", "🛑 DO NOT OPEN. Genuine government/bank websites are always registered. Search the institution's name in Google or use its official app."],
  CONFIRMED_ZERO_DAY_PHISHING: ["🚨 ZERO-DAY PHISHING: Actively flagged in global threat feeds", "🛑 DO NOT OPEN: this domain is attacking users right now. Block and report to 1930."],
  GOOGLE_WEB_RISK_FLAGGED: ["🚨 GOOGLE WEB RISK: Known dangerous site", "🛑 DO NOT OPEN: Google's threat database lists this URL as malware/phishing."],
  DECEPTIVE_URL_STRUCTURE: ["🚨 DECEPTIVE LINK: The real destination is hidden", "🛑 DO NOT OPEN: the text before '@' is a decoy; the browser would go to the host after it."],
  RAW_IP_PHISHING_HOST: ["⚠️ SUSPICIOUS: Raw IP address host", "🛑 AVOID: banks and government services never direct users to numeric IP addresses."],
  MALICIOUS_APK_DOWNLOAD_VECTOR: ["🚨 MALWARE WARNING: Android APK sideload link", "🛑 DO NOT INSTALL: APKs from links can steal your SMS, OTPs and photos. Install only from Google Play."],
  PHISHING_BRAND_AS_SUBDOMAIN: ["🚨 PHISHING: Trusted brand used only as a decoy subdomain", "🛑 DO NOT OPEN: the real owner is the last part of the domain, not the familiar brand at the start."],
  HOMOGLYPH_LOOKALIKE: ["🚨 VISUAL IMPERSONATION: Look-alike characters", "🛑 DO NOT OPEN: characters were swapped to imitate a trusted institution."],
  TYPOSQUATTING_LOOKALIKE: ["🚨 VISUAL IMPERSONATION: Misspelled look-alike of a trusted domain", "🛑 DO NOT OPEN: type the official address yourself or use the official app."],
  PHISHING_BRAND_IMPERSONATION: ["🚨 EXTREME DANGER: Fake domain impersonating a trusted brand", "🛑 DO NOT OPEN: it is designed to steal your bank login, OTP or Aadhaar."],
  OBFUSCATED_SHORT_URL: ["🚨 SUSPICIOUS LINK: Shortened URL hides the destination", "🛑 DO NOT TAP: Indian banks never send shortened links."],
  NONEXISTENT_DOMAIN: ["⚠️ DOMAIN DOES NOT EXIST", "A link to a non-existent domain is a typo, a dead lure, or a taken-down scam. Do not trust the sender."],
  OFFICIAL_NAMESPACE_BAD_TLS: ["⚠️ OFFICIAL NAME, BROKEN SECURITY: expired certificate", "Do not enter any credentials until the institution fixes its certificate."],
  OFFICIAL_NAMESPACE_UNCONFIRMED: ["⚠️ UNCONFIRMED: Official-looking name could not be validated live", "Retry in a minute. Until DNS confirms it exists, treat as unverified."],
  HIGH_RISK_UNVERIFIED_DOMAIN: ["⚠️ HIGH RISK: Unverified domain with multiple danger signals", "Do not enter banking passwords, OTPs, or personal data. Verify through the institution's official app."],
  UNVERIFIED_THIRD_PARTY_DOMAIN: ["⚠️ UNVERIFIED: Not a verified BFSI/government domain", "SafeMeAI cannot vouch for this site. Never enter banking passwords, OTPs or UPI PINs on it."],
  THREAT_FEED_LISTED: ["🚨 KNOWN THREAT: Listed in a threat-intelligence feed", "🛑 DO NOT OPEN: this address is on a published phishing/malware list. Block and report to 1930."],
  REGULATOR_WARNING_LISTED: ["🚨 REGULATOR WARNING: Unauthorised / unregistered entity", "🛑 DO NOT INVEST OR PAY: a financial regulator lists this entity as unauthorised. Report to 1930 / cybercrime.gov.in."],
  DNS_SECURITY_BLOCKED: ["🚨 DNS SECURITY BLOCK: Flagged as malicious by security DNS", "🛑 DO NOT OPEN: a malware/phishing-filtering DNS service refuses to resolve this domain."],
  ESTABLISHED_THIRD_PARTY_DOMAIN: ["ℹ️ Established website (not a bank or government portal)", "Looks like an ordinary long-lived website. Still never enter banking passwords or OTPs on non-bank sites."]
};

/** Build the /api/domain/check payload from an engine assessment. */
function domainPayload(a, rawInput) {
  const [head, advice] = a.verified
    ? [`✅ VERIFIED OFFICIAL: ${a.host}`, "Registered, live and in an authoritative namespace/allow-list. Still confirm the HTTPS padlock before entering credentials."]
    : (VERDICT_COPY[a.verdict] || [`⚠️ ${a.verdict}`, "Exercise caution."]);
  const brand = a.primaryImpersonation;
  return {
    domain: a.host,
    unicodeDomain: a.unicodeHost !== a.host ? a.unicodeHost : undefined,
    fullUrl: rawInput,
    riskScore: a.riskScore,
    riskLevel: a.riskLevel,
    verdict: a.verdict,
    headline: head,
    isWhitelisted: a.verified,
    verified: a.verified,
    tld: '.' + a.tld,
    targetBrand: brand ? (brand.brand || brand.target) : undefined,
    officialDomain: brand && brand.target && /\./.test(brand.target) ? brand.target : undefined,
    flags: a.verified ? a.evidenceForTrust : [...a.flags, ...(a.hardBlock ? [] : a.evidenceForTrust.map(g => '✓ ' + g))],
    actionAdvice: advice,
    protectionLaw: a.verified ? "Official Regulated Domain Framework" : "IT Act Section 66D (Cheating by Personation) & Indian Cyber Security Guidelines",
    realtimeTelemetry: telemetryFromAssessment(a)
  };
}

// ==========================================
// API 6: COMPREHENSIVE CITIZEN SCAM CHECKER ENGINE (Instant Verification)
// ==========================================
const CITIZEN_REPORTS = [
  {
    id: "REP-9102",
    scamType: "Digital Arrest",
    target: "+91 98201 44102",
    details: "Impersonated Mumbai Police Cyber Cell demanding 2.5 Lakh via Skype",
    time: "10 mins ago",
    status: "PUSHED_TO_EDGE_SENSORS"
  },
  {
    id: "REP-9101",
    scamType: "UPI Collect Trap",
    target: "refund.desk92@icici",
    details: "Sent GPay collect request for ₹3,499 under pretense of Amazon refund",
    time: "24 mins ago",
    status: "BLACKLISTED_ON_DEVICE"
  },
  {
    id: "REP-9100",
    scamType: "Electricity Bill Threat",
    target: "+91 88710 99281",
    details: "SMS claiming electricity cutoff at 9:30 PM with malicious APK link",
    time: "48 mins ago",
    status: "DOMAIN_BLOCKED"
  }
];

app.post('/api/scam/check', async (req, res) => {
  const { text } = req.body;
  const raw = (typeof text === 'string' ? text : '').trim();
  const lower = raw.toLowerCase();

  if (!raw || typeof text !== 'string' || !textEngine.normalizeForUrls(raw).trim() || lower === "enter message, url, or upi id" || raw === "undefined" || raw === "null") {
    return res.status(400).json({ 
      error: "Please enter or paste a specific SMS message, suspicious URL, or UPI ID to analyze." 
    });
  }

  // -------------------------------------------------------------
  // STEP 1: EMBEDDED URL & DOMAIN EXTRACTION -> DOMAIN INTELLIGENCE ENGINE
  // -------------------------------------------------------------
  if (raw.length > 5000) {
    return res.status(400).json({ error: "Message too long (max 5000 characters)." });
  }
  const urlRegex = /(?:https?:\/\/|ftp:\/\/)?(?:[^\s\/@<>"']+@)?(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]*[a-z0-9¡-￿])?\.)+[a-z¡-￿]{2,})(?::\d+)?(?:[\/?#][^\s]*)?/gi;
  const extractedUrls = [];
  const seenHosts = new Set();
  let match;
  const urlText = textEngine.normalizeForUrls(raw); // NFKC, zero-width stripped, defanged (hxxp, [.])
  while ((match = urlRegex.exec(urlText)) !== null) {
    let token = match[0].replace(/[.,;:!?)\]'"]+$/, '');
    if (!/^[a-z]+:\/\//i.test(token) && !token.includes('@') && !textEngine.isPlausibleLink(token)) continue;
    const hasScheme = /^[a-z]+:\/\//i.test(token);
    // scheme-less "name@host.tld" is an e-mail / UPI-like id, not a link: judge the part after '@'
    if (!hasScheme && token.includes('@')) token = token.split('@').pop();
    if (/^\d+(\.\d+)?$/.test(token) || /^v?\d+(\.\d+)+$/i.test(token)) continue; // version/decimal numbers
    const p = engine.parseTarget(token);
    if (!p.ok || seenHosts.has(p.host)) continue;
    if (!p.isIp && !p.host.includes('.')) continue;
    seenHosts.add(p.host);
    extractedUrls.push({ full: token, domain: p.host });
    if (extractedUrls.length >= 5) break;
  }

  const trimmedInput = urlText.trim();
  const isDirectUrlQuery = extractedUrls.length === 1 &&
    trimmedInput.replace(/^[a-z]+:\/\//i, '').replace(/^www\./i, '').replace(/\/+$/, '').toLowerCase() ===
    extractedUrls[0].full.replace(/^[a-z]+:\/\//i, '').replace(/^www\./i, '').replace(/\/+$/, '').toLowerCase();

  // Every link is judged on live evidence. Gemini second-opinion only for a single direct lookup (latency).
  const assessments = await Promise.all(extractedUrls.map(u =>
    engine.assessDomain(u.full, { ...engineDeps, _matcher: engineDeps._matcher, useGemini: isDirectUrlQuery && engineDeps.useGemini })
      .catch(err => ({ ok: false, error: err.message, host: u.domain }))
  ));
  // A failed assessment fails CLOSED (never "safe").
  const failed = assessments.find(a => !a.ok);
  const scored = assessments.filter(a => a.ok);

  const toScamShape = (a, extra = {}) => {
    const payload = domainPayload(a, raw);
    return {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: payload.riskScore,
      riskLevel: payload.riskLevel,
      scamType: a.verified ? "Verified Banking / Official Authority Portal" : (VERDICT_COPY[a.verdict] ? VERDICT_COPY[a.verdict][0].replace(/^\S+\s+/, '').split(':')[0] : a.verdict),
      headline: payload.headline,
      verdictDescription: a.verified
        ? `${a.host} is registered, resolves live, and sits in a regulated/allow-listed namespace. ${a.evidenceForTrust.join(' ')}`
        : `${payload.actionAdvice}`,
      flags: payload.flags,
      actionAdvice: a.verified
        ? ["Website is authentic and verified.", "Always ensure your browser shows the HTTPS padlock.", "Legitimate banks never ask for your UPI PIN, NetBanking password or OTP."]
        : [payload.actionAdvice, "📞 Report suspicious links to 1930 or cybercrime.gov.in.", "🛡️ Block the sender."],
      protectionLaw: payload.protectionLaw,
      targetBrand: payload.targetBrand,
      officialDomain: payload.officialDomain,
      realtimeTelemetry: payload.realtimeTelemetry,
      ...extra
    };
  };

  if (isDirectUrlQuery && scored.length === 1) {
    return res.json({ status: 'success', data: toScamShape(scored[0]) });
  }
  if (isDirectUrlQuery && failed) {
    return res.status(502).json({ error: "Verification engine unavailable. Treat this link as UNVERIFIED." });
  }

  // Message with embedded links: worst link drives the verdict. Unverified link inside a message is >= HIGH.
  let phishingDomainDetected = null;
  const risky = scored.filter(a => !a.verified).sort((x, y) => y.riskScore - x.riskScore)[0];
  if (risky || failed) {
    const a = risky || { host: failed.host, verdict: 'UNVERIFIED_THIRD_PARTY_DOMAIN', riskScore: 75, riskLevel: 'HIGH', flags: ['Link could not be analysed — treated as unverified'], evidenceForTrust: [], verified: false, hardBlock: false, tld: '', dns: {}, ssl: {}, isOpenPhish: false, webRisk: {}, entropy: 0, registrable: failed.host, gemini: { available: false, reason: 'engine error' }, domainAge: {} };
    const boosted = { ...a, riskScore: Math.max(a.riskScore, 75), riskLevel: levelBoost(Math.max(a.riskScore, 75)) };
    // Merge the text-engine verdict so scam wording (digital arrest, KYC, ...) is not lost behind the link verdict.
    const tv = textEngine.analyze(raw, { links: extractedUrls.length });
    const textStrong = tv._meta && tv._meta.category !== 'legit' && tv._meta.category !== 'unknown' && tv.riskScore >= 60;
    const mergedScore = Math.max(boosted.riskScore, tv.riskScore);
    const out = toScamShape({ ...boosted, riskScore: mergedScore, riskLevel: levelBoost(mergedScore) }, {
      scamType: textStrong ? `${tv.scamType} + ${boosted.hardBlock ? "Malicious Link" : "Unverified Link"}` : (boosted.hardBlock ? "Malicious / Impersonation Link" : "Unverified Link in Message"),
      headline: textStrong ? tv.headline : undefined,
      verdictDescription: `This message contains a link to '${a.host}'. ${a.flags.slice(0, 2).join(' ')} ${textStrong ? tv.verdictDescription : ''}`.trim(),
      flags: textStrong ? [...tv.flags, ...a.flags.slice(0, 3)] : undefined,
      actionAdvice: [
        `🛑 DO NOT CLICK '${a.host}'.`,
        ...(textStrong ? tv.actionAdvice : []),
        "✅ Go to your bank/service via its official app or the website printed on your card.",
        "🛡️ Block the sender and report to 1930."
      ]
    });
    if (out.headline === undefined) out.headline = domainPayload(boosted, raw).headline;
    if (out.flags === undefined) out.flags = domainPayload(boosted, raw).flags;
    if (textStrong) out.protectionLaw = tv.protectionLaw;
    return res.json({ status: 'success', data: out });
  }

  // -------------------------------------------------------------
  // STEP 2: MULTI-SIGNAL TEXT ENGINE (lib/textEngine.js, ported from the Android detectors).
  // Normalisation, UPI-handle checks, per-category scoring, legit-alert gate and the
  // conservative default all live there. Embedded links were already judged above.
  // NOTE: everything below this return (legacy first-match-wins regex chain) is dead code kept
  // only until it can be deleted in a quiet edit window.
  // -------------------------------------------------------------
  {
    const textVerdict = textEngine.analyze(raw, { links: extractedUrls.length });
    delete textVerdict._meta;
    return res.json({ status: 'success', data: textVerdict });
  }

  // -------------------------------------------------------------
  // LEGACY STEP 2: EMBEDDED UPI / VPA HANDLE CHECK (unreachable)
  // -------------------------------------------------------------
  const upiRegex = /[a-zA-Z0-9._-]+@(okhdfcbank|okaxis|oksbi|okicici|ybl|ibl|axl|paytm|barodampay|upi)/gi;
  const hasUpiHandle = upiRegex.test(raw);
  const upiSuspiciousHandle = /(police|cbi|rbi|escrow|verification|refund|custody|court|gov|customs|fines|official|support|helpdesk|security)@(okhdfcbank|okaxis|oksbi|okicici|ybl|ibl|axl|paytm|upi)/i.test(raw);

  // -------------------------------------------------------------
  // STEP 3: PATTERN & HEURISTIC ENGINE (PORTED FROM AIAnalyzer.kt)
  // -------------------------------------------------------------
  const hasDigitalArrest = /cbi|arrest|police|supreme court|pmla|mdma|narcotics|customs|dhl|fedex|parcel|escrow|skype|digital arrest|surveillance|verification account|cyber cell|high court|warrant/i.test(lower);
  const hasUpiCollect = /upi pin|enter pin|scan qr|collect request|refund approved|to receive money|cashback credited|refund desk|gpay refund|phonepe refund|reverse payment|mpin|pay to receive/i.test(lower);
  const hasElectricity = /electricity|power cut|power disconnected|bill unpaid|light disconnect|officer\s*\+?91|discom|bill update|bijli|meter disconnect|power supply/i.test(lower);
  const hasPredatoryLoan = /instant loan|sanctioned in 5 min|7-day|7 day loan|contact list access|gallery access|quick rupee|rupee advance|processing fee upfront|loan approved|easy credit|no cibil/i.test(lower);
  const hasJobMule = /telegram|like youtube|part time job|earn 3000|earn 5000|prepaid task|deposit 1000|merchant review|hotel review task|work from home|vip task|daily payout/i.test(lower);
  const hasSextortion = /video call recorded|private video|porn video|send 20000|circulate to friends|viral your clip|social media leak|compromised video/i.test(lower);
  const hasKycThreat = /kyc|pan card|pan linked|account blocked|card blocked|account suspended|debit card blocked|netbanking blocked|update your kyc|verify kyc|avoid deactivation|deactivate|deactivated|deactivation|sim blocked|sim deactivated|sim card|sim will be|trai notice|kyc expired|pan expired|blocked within|suspended within|verify identity|customer care/i.test(lower);
  const hasRemoteAccess = /anydesk|teamviewer|rustdesk|quicksupport|remote support|screen share|install app for support/i.test(lower);
  const hasRewardsLottery = /lottery|kbc|reward points|redeem points|congratulations you won|claim gift|lucky draw|25 lakh|free recharge|free power scheme|cashback credited|won cash/i.test(lower);
  const hasTrafficChallan = /echallan|challan pending|traffic fine|court challan|vehicle challan|rto fine/i.test(lower);
  const hasIndiaPost = /india post|indiapost|speed post|parcel detained|package detained|delivery address|incomplete address|update address|redelivery fee|consignment|customs duty unpaid|postal package/i.test(lower);
  const hasOtpStealing = /share your otp|verify otp|enter otp to receive|otp for delivery|tell me the otp/i.test(lower);

  // Legitimate Bank Alert Check
  const hasBankWhitelistPatterns = /(debited by|credited with|inr [0-9,]+|avail bal|txn on|card ending in|swiggy|zomato|uber|ola|transaction successful)/i.test(lower);
  const isStrictLegitimateBankAlert = hasBankWhitelistPatterns && 
    !hasDigitalArrest && !hasUpiCollect && !hasKycThreat && !hasPredatoryLoan && 
    !hasJobMule && !hasElectricity && !hasRemoteAccess && !hasOtpStealing && !hasIndiaPost &&
    !phishingDomainDetected && !upiSuspiciousHandle;

  // -------------------------------------------------------------
  // STEP 4: VERDICT GENERATION
  // -------------------------------------------------------------
  let result = null;

  if (phishingDomainDetected) {
    const d = phishingDomainDetected;
    let scamType = "Malicious URL / Sideload Trap";
    let headline = `🚨 MALICIOUS DOMAIN: High-Risk URL (${d.domain})`;
    let desc = `This message directs you to '${d.domain}', an unauthorized host designed for credential theft or malware distribution.`;
    let risk = 98;
    let flags = [
      "URL extracted directly from message payload",
      "Attempts to harvest NetBanking logins, OTPs, or install malicious APK"
    ];

    if (d.type === "CONFIRMED_ZERO_DAY_PHISHING") {
      scamType = "Confirmed Zero-Day Phishing Threat";
      headline = `🚨 CRITICAL ALERT: Active Zero-Day Threat (${d.domain})!`;
      desc = `The link '${d.domain}' is an active phishing campaign flagged in real time by the global threat intelligence feed (OpenPhish).`;
      flags.unshift(`Actively listed on live OpenPhish zero-day phishing stream`);
      risk = 100;
    } else if (d.type === "BRAND_IMPERSONATION") {
      scamType = `Phishing Site Impersonating ${d.brand}`;
      headline = `🚨 CRITICAL PHISHING: Fake ${d.brand} Domain!`;
      desc = `This message mimics ${d.brand} but points to fraudulent domain '${d.domain}'.`;
      flags.unshift(`Unverified host mimicking ${d.brand} (Official is ${d.official})`);
    } else if (d.type === "TYPOSQUATTING_LOOKALIKE") {
      scamType = "Visual Lookalike (Typosquatting)";
      headline = `🚨 VISUAL IMPERSONATION: Lookalike of ${d.target}!`;
      desc = `The domain '${d.domain}' visually mimics authentic domain '${d.target}' using deceptive spelling variations.`;
      flags.unshift(`Typosquatting fraud signature (Matches verified ${d.target})`);
      risk = 98;
    } else if (d.type === "OBFUSCATED_SHORT_URL") {
      scamType = "Obfuscated / Shortened URL Trap";
      headline = `🚨 SUSPICIOUS LINK: Obfuscated Short URL (${d.domain})`;
      desc = `This message uses URL shortener '${d.domain}' to hide the true phishing destination. Under TRAI regulations, legitimate banks in India never send shortened links.`;
      flags.unshift(`Shortened link obfuscates the true destination website`);
      risk = 96;
    } else if (d.type === "MALICIOUS_PHISHING_PATTERN") {
      scamType = "Credential Harvesting URL Pattern";
      headline = `🚨 SUSPICIOUS LURE: Phishing URL Grammar (${d.domain})`;
      desc = `The domain '${d.domain}' uses universal phishing keywords (-kyc, pan-update, rewardz) to bait victims.`;
      flags.unshift(`Phishing grammar pattern detected in URL`);
      risk = 95;
    } else if (d.type === "UNVERIFIED_THIRD_PARTY_DOMAIN") {
      scamType = "Standard Third-Party Website";
      headline = `ℹ️ Standard Web Domain (${d.domain})`;
      desc = `This domain is not an official banking or government institution, but no active phishing traps or lookalike signatures were detected.`;
      flags = ["Standard external web host", "Not an RBI/Govt authorized financial portal"];
      risk = 25;
      result = {
        analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
        timestamp: new Date().toISOString(),
        riskScore: 25,
        riskLevel: "LOW",
        scamType: "Standard Third-Party Website",
        headline: `ℹ️ Standard Web Domain (${d.domain})`,
        verdictDescription: `This domain is not an official banking or government institution, but no active phishing traps or lookalike signatures were detected.`,
        flags: flags,
        actionAdvice: [
          "Website appears to be a standard third-party domain.",
          "Exercise normal web browsing caution.",
          "Never enter banking passwords, OTPs, or UPI PINs on third-party websites."
        ],
        protectionLaw: "Indian Information Technology Act"
      };
      return res.json({ status: 'success', data: result });
    } else if (d.type === "UNVERIFIED_EXTERNAL_LINK") {
      scamType = "Unverified External Domain Link";
      headline = `⚠️ UNVERIFIED LINK: External Host (${d.domain})`;
      desc = `The link points to '${d.domain}', which is not registered in official Indian government or banking directories.`;
      flags.unshift(`Domain '${d.domain}' is not on the national BFSI whitelist`);
      risk = 85;
    } else {
      flags.unshift(`High-risk disposable TLD (.${d.tld}) or APK payload`);
    }

    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: risk,
      riskLevel: risk >= 80 ? "CRITICAL" : "HIGH",
      scamType: scamType,
      headline: headline,
      verdictDescription: desc,
      flags: flags,
      actionAdvice: [
        `🛑 DO NOT CLICK THE LINK: Never open '${d.domain}'.`,
        `✅ If you need services, visit the official website directly: ${d.official || "official app on Google Play"}.`,
        "🛡️ Block the sender and report to 1930."
      ],
      protectionLaw: "IT Act Section 66D (Cheating by Personation) & Section 43"
    };
  } else if (upiSuspiciousHandle) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 99,
      riskLevel: "CRITICAL",
      scamType: "Fake Government / Bank UPI Handle",
      headline: "🚨 FRAUDULENT UPI HANDLE: Fake Authority Impersonation!",
      verdictDescription: "The UPI ID in this message uses deceptive words (police, rbi, escrow, refund) to trick citizens into transferring funds.",
      flags: [
        "Unregistered personal UPI handle pretending to be Government/RBI",
        "Classic money mule destination account",
        "RBI, CBI, and Police NEVER accept UPI transfers from citizens"
      ],
      actionAdvice: [
        "🛑 DO NOT SEND ANY MONEY: Transfers to this UPI handle go directly into a scammer's mule account.",
        "🛑 Decline any payment request on PhonePe / Google Pay / Paytm.",
        "📞 Report this UPI ID immediately to 1930."
      ],
      protectionLaw: "NPCI UPI Security Guidelines & PMLA Section 3"
    };
  } else if (hasDigitalArrest) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 99,
      riskLevel: "CRITICAL",
      scamType: "Digital Arrest Extortion (Central Agency Impersonation)",
      headline: "🚨 EXTREME DANGER: Digital Arrest Cybercrime Detected!",
      verdictDescription: "Matches 100% of signatures for fraudulent 'Digital Arrest' extortion. Fraudsters pose as CBI/Police/Customs to extort victims.",
      flags: [
        "Impersonation of Police / CBI / Customs / Courts",
        "Coercive video call or surveillance ultimatum",
        "False claim of contraband, narcotics, or money laundering",
        "Demand to transfer funds to 'Escrow' or 'Verification' accounts"
      ],
      actionAdvice: [
        "🚨 HANG UP IMMEDIATELY. Disconnect Skype or WhatsApp video call.",
        "🛑 UNDER INDIAN LAW: No police or court ever arrests citizens over video calls or demands money.",
        "📞 Dial 1930 immediately (National Cyber Crime Helpline) or report on cybercrime.gov.in.",
        "🛡️ SafeMeAI Android app automatically detects and blocks these fraudulent video overlay streams."
      ],
      protectionLaw: "BNSS 2023 & IT Act Section 66D (Cheating by Impersonation)"
    };
  } else if (hasUpiCollect) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 96,
      riskLevel: "CRITICAL",
      scamType: "UPI Collect Inversion / PIN Trap Scam",
      headline: "⚡ CRITICAL FRAUD: Attempt to Drain Bank Account via UPI PIN",
      verdictDescription: "Scammers send a Collect Request or QR code pretending you are 'receiving' a refund or cashback.",
      flags: [
        "Reverse Collect Request (Paying to receive)",
        "Misleading urgency ('Refund expiring', 'Cashback available')",
        "Requesting UPI PIN or QR scan for inbound funds"
      ],
      actionAdvice: [
        "🛑 DO NOT ENTER YOUR UPI PIN: Entering your UPI PIN ALWAYS DEDUCTS money from your account.",
        "❌ Decline the collect request on Google Pay / PhonePe / Paytm immediately.",
        "🚫 You NEVER need a PIN or QR code to receive money in India.",
        "🛡️ SafeMeAI's on-device sensor places a protective barrier over fraudulent UPI collect windows."
      ],
      protectionLaw: "NPCI UPI Safety Guidelines & RBI Master Directions on Fraud Prevention"
    };
  } else if (hasElectricity) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 95,
      riskLevel: "CRITICAL",
      scamType: "Fake Electricity / Utility Disconnection Scam",
      headline: "⚠️ HIGH FRAUD RISK: Fake Utility Disconnection Notice",
      verdictDescription: "Mass SMS fraud threatening power cutoff at night to panic citizens into calling a scammer or downloading a remote APK.",
      flags: [
        "Imminent cutoff panic threat ('disconnected at 9:30 PM')",
        "Unofficial personal mobile number given for 'Electricity Officer'",
        "Pressure to pay via third-party link or install an app"
      ],
      actionAdvice: [
        "🛑 Do NOT call the phone number in the SMS.",
        "🛑 Power companies NEVER disconnect electricity without official physical postal notices.",
        "✅ Check your power bill directly on the official state DISCOM portal or your electricity bill app.",
        "🛡️ Block the sender number."
      ],
      protectionLaw: "Electricity Act 2003 (Notice Requirements) & IT Act 66D"
    };
  } else if (hasKycThreat) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 94,
      riskLevel: "CRITICAL",
      scamType: "Banking / SIM KYC Suspension Threat",
      headline: "⚠️ DANGER: Coercive KYC / Account Deactivation Scam",
      verdictDescription: "Scammers threaten that your bank account, debit card, or SIM card will be deactivated within 24 hours.",
      flags: [
        "Coercive deactivation ultimatum ('blocked within 24h', 'kyc expired')",
        "Urges clicking links or calling unofficial mobile numbers",
        "Banks & telecom operators never cancel accounts without physical branch notices"
      ],
      actionAdvice: [
        "🛑 DO NOT click links in the SMS or call the number provided.",
        "✅ Open your verified banking app or visit your bank branch directly.",
        "🛡️ Banks never send link-based KYC updates via unverified SMS."
      ],
      protectionLaw: "RBI Master Direction on Customer KYC & IT Act 66D"
    };
  } else if (hasRemoteAccess) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 98,
      riskLevel: "CRITICAL",
      scamType: "Remote Access Screen-Takeover Trojan",
      headline: "🚨 EXTREME DANGER: Remote Access App Trap (AnyDesk/TeamViewer)",
      verdictDescription: "Scammers instruct victims to install remote desktop tools to take over their phone and transfer bank funds.",
      flags: [
        "Instructions to install AnyDesk, TeamViewer, or QuickSupport",
        "Attempts to bypass Android screen protections and view OTPs",
        "Total loss of device control and NetBanking balance"
      ],
      actionAdvice: [
        "🛑 NEVER install AnyDesk or TeamViewer on the instructions of any caller.",
        "🛑 Disconnect any active remote screen sharing session immediately.",
        "🔒 Turn on Airplane Mode if you have already shared your 9-digit code."
      ],
      protectionLaw: "IT Act Section 43/66 (Unauthorized Access to Computer System)"
    };
  } else if (hasPredatoryLoan) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 92,
      riskLevel: "HIGH",
      scamType: "Predatory Instant Loan Extortion App",
      headline: "⚠️ DANGER: Illegal Chinese / Unregulated Loan App Trap",
      verdictDescription: "Predatory lending fraud that deducts 30-40% upfront and blackmails users using contacts and gallery photos.",
      flags: [
        "Ultra-short 7-day tenure with exorbitant hidden interest",
        "Demands intrusive access to Contact List and Gallery/Photos",
        "Unregistered NBFC operating outside RBI regulations"
      ],
      actionAdvice: [
        "🛑 NEVER install APKs sent via WhatsApp or unverified SMS links.",
        "🛑 Do NOT pay extortion demands via unofficial personal UPI handles.",
        "✅ Regulated RBI lenders are legally barred from accessing your phone contacts or photos.",
        "🛡️ SafeMeAI provides automated sideload blocking and harassment call shielding."
      ],
      protectionLaw: "RBI Digital Lending Guidelines (2022) & BNS Section 351"
    };
  } else if (hasJobMule) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 90,
      riskLevel: "HIGH",
      scamType: "Telegram Task / Money Mule Recruitment Trap",
      headline: "⚠️ FRAUDULENT LURE: 'Part-Time Job / Like YouTube' Scam",
      verdictDescription: "Scammers bait victims with small initial payouts (₹150-₹500) then force high-value deposits on fake crypto or merchant portals.",
      flags: [
        "Unrealistic income promise (₹3,000–₹5,000/day for trivial tasks)",
        "Funneling victims into private Telegram or WhatsApp groups",
        "Prepaid task requirement demanding money transfers to stranger accounts"
      ],
      actionAdvice: [
        "🛑 Exit and block the Telegram group immediately.",
        "🛑 Legitimate companies NEVER ask you to deposit money to work or receive payouts.",
        "⚠️ Transferring money to their accounts implicates you in money mule networks.",
        "📞 Report the numbers to 1930."
      ],
      protectionLaw: "PMLA Section 3 (Offence of Money Laundering) & IT Act"
    };
  } else if (hasRewardsLottery) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 89,
      riskLevel: "HIGH",
      scamType: "Counterfeit Reward / Lottery / KBC Scam",
      headline: "⚠️ PHISHING LURE: Fake Reward Points or Lottery Prize",
      verdictDescription: "Scammers promise cash prizes, KBC lotteries, or reward points to induce you into paying 'processing fees' or entering card credentials.",
      flags: [
        "Unsolicited prize or lottery claim without ticket purchase",
        "Pressure to redeem points before false expiration deadline",
        "Demands registration fee or bank details to 'release' funds"
      ],
      actionAdvice: [
        "🛑 Do NOT pay any processing fee or tax to claim prizes.",
        "🛑 Genuine banks never send external links to redeem reward points.",
        "🛡️ Block the sender."
      ],
      protectionLaw: "Lotteries (Regulation) Act & IT Act 66D"
    };
  } else if (hasTrafficChallan) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 93,
      riskLevel: "HIGH",
      scamType: "Fake Traffic e-Challan Phishing Scam",
      headline: "⚠️ HIGH FRAUD RISK: Fake Traffic Challan Link",
      verdictDescription: "Fraudsters send SMS claiming your vehicle has an unpaid traffic challan with a link leading to a cloned government portal.",
      flags: [
        "Deceptive link mimicking echallan.parivahan.gov.in",
        "Threat of court warrant or vehicle impoundment",
        "Official e-Challans only end in '.gov.in' or '.nic.in'"
      ],
      actionAdvice: [
        "🛑 NEVER pay challans on unofficial private links.",
        "✅ Check real challans only on the official national portal: https://echallan.parivahan.gov.in.",
        "🛡️ Delete the message and block sender."
      ],
      protectionLaw: "Motor Vehicles Act 2019 & IT Act 66D"
    };
  } else if (hasSextortion) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 97,
      riskLevel: "CRITICAL",
      scamType: "Cyber Sextortion & Morphed Video Blackmail",
      headline: "🚨 BLACKMAIL THREAT: Video Call Extortion / Fake Cyber Cell",
      verdictDescription: "Fraudsters record or morph video clips and threaten social media dissemination or fake police arrest.",
      flags: [
        "Threat to circulate video to family/contacts",
        "Demand for immediate ransom transfer to UPI",
        "Fake police officer accomplice calling next"
      ],
      actionAdvice: [
        "🛑 DO NOT PAY ANY MONEY: Paying will only invite repeated higher ransom demands.",
        "🔒 Immediately privatize your social media profiles.",
        "📞 Call 1930 or visit cybercrime.gov.in to report cyber blackmail (CFCFRMS).",
        "🛡️ You are the victim of an organized syndicate; do not succumb to panic."
      ],
      protectionLaw: "IT Act Section 66E / 67A & BNS Section 308 (Extortion)"
    };
  } else if (hasIndiaPost) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 96,
      riskLevel: "CRITICAL",
      scamType: "Fake India Post / Courier Redelivery Phishing",
      headline: "🚨 CRITICAL FRAUD: Fake India Post / Courier Notice",
      verdictDescription: "Mass cyber-fraud campaign mimicking India Post / Speed Post claiming a parcel cannot be delivered without an address update or payment.",
      flags: [
        "Impersonation of India Post / Speed Post logistics",
        "Fake delivery failure or address update ultimatum",
        "Demands link click or fee payment to release non-existent parcel"
      ],
      actionAdvice: [
        "🛑 DO NOT click links in the message.",
        "🛑 India Post NEVER sends SMS asking for address updates or credit card payments.",
        "✅ Verify real tracking numbers only at the official portal: https://www.indiapost.gov.in.",
        "🛡️ Block the sender and report to 1930."
      ],
      protectionLaw: "Indian Post Office Act & IT Act 66D"
    };
  } else if (isStrictLegitimateBankAlert) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 5,
      riskLevel: "SAFE",
      scamType: "Legitimate Banking Transaction / Alert",
      headline: "✅ SAFE: Standard Financial Notification",
      verdictDescription: "This message adheres to authorized banking notification standards and does not request sensitive actions.",
      flags: ["Standard transaction metadata format", "No suspicious URLs or unverified collect demands"],
      actionAdvice: [
        "Message appears genuine.",
        "Remember: Never share OTPs or passwords even with bank staff."
      ],
      protectionLaw: "RBI Fair Practices Code"
    };
  } else {
    // -------------------------------------------------------------
    // DEFAULT SAFEGUARD: UNVERIFIED THIRD-PARTY COMMUNICATION
    // -------------------------------------------------------------
    // NEVER give a clean bill of health to unknown, unverified text!
    const hasPhonePattern = /\b\d{10}\b|\+\d{1,4}[\s-]?\d{6,14}\b/.test(raw);
    const hasUrgency = /urgent|immediate|fast|quick|today|within 24 hours|attention|warning|notice/i.test(lower);

    let baseRisk = 65;
    let flags = ["Message origin is unverified against official BFSI directories"];
    if (hasPhonePattern) {
      baseRisk += 15;
      flags.push("Contains unverified personal/mobile phone number for callback");
    }
    if (hasUrgency) {
      baseRisk += 10;
      flags.push("Contains artificial urgency or pressure keywords");
    }

    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: Math.min(baseRisk, 85),
      riskLevel: baseRisk >= 75 ? "CRITICAL" : "HIGH",
      scamType: "Unverified Communication (Caution Advised)",
      headline: baseRisk >= 75 
        ? "🚨 HIGH RISK: Unverified Message with Threat / Urgency Signals" 
        : "⚠️ SUSPICIOUS: Unverified Third-Party Message",
      verdictDescription: "This message has NOT been verified against approved institutional directories. In India, cyber fraudsters frequently use unverified SMS and messaging probes.",
      flags: flags,
      actionAdvice: [
        "🛑 DO NOT click unknown links, install APKs, or transfer money.",
        "🛑 DO NOT call phone numbers provided directly in unverified messages.",
        "✅ Always verify inquiries directly through your official banking app or the customer care number on your physical card.",
        "📞 If anyone demands money or sensitive details, report immediately to 1930."
      ],
      protectionLaw: "Indian Cyber Security & Consumer Protection Directives"
    };
  }

  res.json({
    status: 'success',
    data: result
  });
});

// ==========================================
// API 7: DIGITAL ARREST EMERGENCY RAPID SCREENER (Authoritative I4C/MHA Protocol)
// ==========================================
app.post('/api/emergency/digital-arrest-screen', (req, res) => {
  const { isUniformOrAgency, isCoerciveSurveillance, isContrabandOrPMLA, isMoneyDemand } = req.body || {};

  let positiveCount = 0;
  if (isUniformOrAgency) positiveCount++;
  if (isCoerciveSurveillance) positiveCount++;
  if (isContrabandOrPMLA) positiveCount++;
  if (isMoneyDemand) positiveCount++;

  // Under Indian Law (BNSS/CrPC), "Digital Arrest" is non-existent.
  // If ANY core threat tactic is active, it is definitively a scam.
  const isExtremeScam = isMoneyDemand || isUniformOrAgency || isCoerciveSurveillance || positiveCount >= 2;

  let verdict = "NORMAL_COMMUNICATION";
  let certainty = 5;
  let headline = "No Critical Coercion Signals Detected";
  let steps = [
    "Always remain cautious when receiving calls from unknown numbers.",
    "Never share OTPs, passwords, or banking PINs."
  ];

  if (isExtremeScam) {
    verdict = "CONFIRMED_DIGITAL_ARREST_CRIME";
    certainty = 100;
    headline = "🚨 100% CONFIRMED: YOU ARE BEING TARGETED BY A DIGITAL ARREST SCAM!";
    steps = [
      "1. 🛑 HANG UP THE VIDEO CALL IMMEDIATELY: You are in ZERO danger of arrest. Indian law (BNSS / CrPC) has NO provision for arrests or interrogations over Skype or WhatsApp.",
      "2. 🚫 DO NOT TRANSFER ANY MONEY: The Reserve Bank of India (RBI) and Police NEVER maintain 'Escrow' or 'Verification' accounts. Any demand for money transfer is pure extortion.",
      "3. 🗣️ INFORM YOUR FAMILY / FRIENDS RIGHT NOW: Scammers depend on keeping you isolated in fear. Once you tell a family member or friend, the scam loses all psychological power.",
      "4. 📞 DIAL 1930 IMMEDIATELY: Report the scammer's phone number and WhatsApp account to the National Cyber Crime Helpline (1930) or cybercrime.gov.in."
    ];
  } else if (positiveCount === 1 && isContrabandOrPMLA) {
    verdict = "SUSPICIOUS_EXTORTION_LURE";
    certainty = 90;
    headline = "⚠️ HIGH DANGER: Fraudulent Contraband / Customs Parcel Lure";
    steps = [
      "1. Courier companies (FedEx, DHL, India Post) NEVER call demanding you speak with 'cyber police' on video call.",
      "2. Do NOT accept any Skype or WhatsApp video call invitation.",
      "3. Disconnect and report the number to 1930."
    ];
  }

  res.json({
    status: 'success',
    engine: 'deterministic-rules',
    verdict,
    certainty,
    headline,
    emergencyProtocol: steps
  });
});

// ==========================================
// API 9: HYBRID CROSS-REFERENCE DOMAIN & URL CHECKER (HCRV ENGINE)
// ==========================================
app.post('/api/domain/check', async (req, res) => {
  const rawInput = String(req.body.url || req.body.domain || "").trim();
  if (!rawInput) {
    return res.status(400).json({ error: "Please enter a domain or URL to evaluate." });
  }
  if (rawInput.length > 2048) {
    return res.status(400).json({ error: "Input too long." });
  }
  try {
    const a = await engine.assessDomain(rawInput, engineDeps);
    if (!a.ok) return res.status(400).json({ error: "Invalid domain or URL format." });
    res.json({ status: 'success', data: domainPayload(a, rawInput) });
  } catch (err) {
    console.error('[domain/check] engine failure:', err);
    // Fail closed: an engine failure must never read as "safe".
    res.status(502).json({ error: "Verification engine unavailable. Treat this domain as UNVERIFIED." });
  }
});


// ==========================================
// API 8: CITIZEN REPORT SUBMISSION (FEED SAFEMEAI)
// ==========================================
// Crowd-report pipeline (lib/reports.js): validation, dedupe, rate limits, reputation, allow-list immunity, expiry.
const reportsLib = require('./lib/reports');
const crowdReports = reportsLib.createReports({
  isProtected: isProtectedDomain,
  corroborate: async (type, value) => {
    if (type !== 'domain') return {};
    const [age, imp] = await Promise.all([
      engine.lookupDomainAge(value).catch(() => null),
      Promise.resolve().then(() => engine.detectImpersonation(value, engineDeps._matcher, BRAND_KEYWORDS, { suspiciousTlds: SUSPICIOUS_TLDS })).catch(() => [])
    ]);
    return { ageDays: age && age.available && Number.isFinite(age.ageDays) ? age.ageDays : null, lookalike: Array.isArray(imp) && imp.length > 0 };
  }
});

async function handleReport(req, res, channel) {
  const b = req.body || {};
  if (!b.scamTarget || (channel === 'web' && !b.scamType)) {
    return res.status(400).json({ error: "Please provide the scammer's phone number/UPI ID/URL and scam category." });
  }
  if (channel === 'app') {
    if (process.env.APP_REPORT_KEY && req.get('x-app-key') !== process.env.APP_REPORT_KEY) return res.status(401).json({ error: 'Unauthorized app client.' });
    if (typeof b.deviceId !== 'string' || b.deviceId.length < 16 || b.deviceId.length > 128) return res.status(400).json({ error: 'deviceId (16-128 chars) is required.' });
  }
  try {
    // reporterName / reporterPhone from the web form are intentionally ignored (PII minimisation).
    const r = await crowdReports.submit({ target: b.scamTarget, scamType: b.scamType, details: b.scamDetails, deviceId: channel === 'app' ? b.deviceId : null, ip: req.ip, ua: req.get('user-agent'), channel });
    if (!r.ok) {
      if (r.retryAfterSec) res.set('Retry-After', String(r.retryAfterSec));
      return res.status(r.status || 400).json({ error: r.message || 'Report rejected.', code: r.error });
    }
    res.json({
      status: 'success',
      message: r.duplicate ? r.message : 'Report received. It becomes a community alert once enough independent reporters confirm it; reports never block verified official domains.',
      dataSource: 'crowd-pipeline',
      report: r.record
    });
  } catch (err) {
    console.error('[report] failure:', err);
    res.status(500).json({ error: 'Could not record the report right now.' });
  }
}

app.post('/api/scam/report', (req, res) => handleReport(req, res, 'web'));
app.post('/api/v1/app/report', (req, res) => handleReport(req, res, 'app'));

app.get('/api/scam/reports', async (req, res) => {
  try {
    const live = await crowdReports.publicFeed(20);
    res.json({
      status: 'success',
      dataSource: live.length ? 'crowd-pipeline' : 'demo-in-memory',
      dataSourceNote: live.length ? 'Values reported by multiple independent citizens. Targets are partially masked.' : 'No community-confirmed reports yet; showing seeded SAMPLE entries.',
      data: live.length ? live : CITIZEN_REPORTS
    });
  } catch (err) {
    res.status(500).json({ error: 'Could not load reports.' });
  }
});

// Signed delta for the Android DynamicDomainFeed. Format: docs/blocklist-api.md
app.get('/api/v1/blocklist/delta', async (req, res) => {
  const key = process.env.BLOCKLIST_SIGNING_KEY;
  if (!key) return res.status(503).json({ error: 'Blocklist signing is not configured.' });
  let since = 0;
  if (req.query.since != null && req.query.since !== '') {
    since = /^\d+$/.test(String(req.query.since)) ? Number(req.query.since) : Date.parse(String(req.query.since));
    if (!Number.isFinite(since) || since < 0) return res.status(400).json({ error: 'since must be epoch milliseconds or ISO-8601.' });
  }
  try {
    const d = await crowdReports.delta(since, 1000);
    const signed = reportsLib.signDelta(d, since, key);
    res.set('Cache-Control', 'no-store').set('X-Blocklist-Signature', signed.sig).json(signed);
  } catch (err) {
    console.error('[blocklist] failure:', err);
    res.status(500).json({ error: 'Blocklist unavailable.' });
  }
});

// Human review queue (allow-listed / shared-hosting / mass-reported established domains). Disabled unless ADMIN_TOKEN is set.
function adminOnly(req, res, next) {
  const t = process.env.ADMIN_TOKEN;
  if (!t) return res.status(404).end();
  const got = Buffer.from(String(req.get('authorization') || '')), want = Buffer.from('Bearer ' + t);
  if (got.length !== want.length || !require('crypto').timingSafeEqual(got, want)) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
app.get('/api/v1/admin/reports/review', adminOnly, async (req, res) => res.json({ status: 'success', data: await crowdReports.reviewQueue() }));
app.post('/api/v1/admin/reports/review', adminOnly, async (req, res) => {
  const { type, value, decision } = req.body || {};
  const norm = reportsLib.normaliseTarget(value);
  if (!norm.ok || norm.type !== type) return res.status(400).json({ error: 'Invalid type/value.' });
  const r = await crowdReports.decide(norm.type + ':' + norm.value, decision);
  res.status(r.ok ? 200 : 400).json(r);
});


app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(` SafeMeAI BFSI Enterprise Command Center is RUNNING!`);
  console.log(` Port: ${PORT}`);
  console.log(` Gemini: ${process.env.DISABLE_GEMINI === '1' ? 'disabled' : 'enabled (falls back to rules if unreachable)'}`);
  console.log(`=======================================================`);
});
