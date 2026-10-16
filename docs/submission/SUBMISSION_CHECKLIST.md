# SafeMeAI: AI Builder Cup submission checklist

Everything below is based on facts verifiable in this repo or on the live site as of 16 Oct 2026. Nothing about customers, pilots or revenue is claimed because none exists.

## 1. Mandatory items

| Item | Status | Detail |
|---|---|---|
| Problem statement named | Done | BFSI: Intelligent Risk, Fraud & Financial Experiences |
| Deployed prototype link | Done | https://safemeai.in (Firebase Hosting in front of Cloud Run). Direct: https://safemeai-bfsi-846801666760.asia-south1.run.app |
| Prototype on Google Cloud | Done | Cloud Run (asia-south1) + Firebase Hosting; verified by `/api/system/status` (Cloud Run revision reported) |
| Public GitHub repo | Owner action: confirm | https://github.com/rps011/safemeai-portal-public. Confirm it is public, contains the latest `docs/`, `tests/eval/v2/`, `docs/submission/`, and that no secrets or `.env` are in the history. Local uncommitted work (new engine fixes, evaluation v2, this folder) must be committed and pushed by the owner; this package did not commit anything. |
| Deck PDF explaining the solution | Done (re-render after any edit) | `docs/submission/SafeMeAI_Deck.pdf` (16 slides), source `docs/submission/deck.html` |
| Video demo under 3 minutes | Owner action | Script ready in `docs/submission/VIDEO_SCRIPT.md` (2:45 plan + 90 s cut). Record, export, upload (unlisted/public), paste link. |
| Everything in English | Done | Deck, script, forms in English. The Hindi screens are shown deliberately as a feature. |
| Fresh work in window (7 Sep - 18 Oct 2026) | Done, with disclosure | Web platform built 14-16 Oct 2026. Separate earlier Android app is not part of the submission. See section 4. |
| Deck says Android app is separate | Done | Slide 16 |
| Team details / form logins | Owner action | Confirm team name, member names and e-mail on the form. The deck lists "Rana Pratap Singh (GitHub: rps011)" only. |
| Final pre-submit checks | Owner action | (a) re-run `node --test`; (b) open the live site on a phone; (c) confirm Gemini badge shows live; (d) re-verify the demo inputs in the video script; (e) check `/api/system/status`. |

## 2. Submission form text

**Project title**

SafeMeAI

**Tagline (under 100 characters)**

A plain-language fraud shield for Indian bank customers, powered by Gemini on Google Cloud.

**Problem statement category**

BFSI: Intelligent Risk, Fraud & Financial Experiences

**Short description (150 words)**

SafeMeAI is a browser-based fraud shield for Indian banking customers. A person pastes a suspicious message, link, UPI ID or phone number, uploads a photo of a notice, or answers six questions during a "digital arrest" call, and gets a plain verdict in English or Hindi with what to do next. A layered engine checks whether a domain really exists (forged .gov.in sites do not), its age, Google Web Risk, 522k threat-feed indicators including RBI and SEBI lists, lookalikes and the TLS certificate. Gemini 2.5 Flash on Vertex AI (Mumbai region) gives a guarded second opinion on ambiguous cases, answers questions in Hindi, and translates; it can only escalate on concrete evidence, never marks unverified sites safe, sees PII-redacted text only, and every answer labels whether AI or fallback rules produced it. A documented API supports bank pilots. We publish our honest blind evaluation, including weak spots.

**Long description (about 500 words)**

*The problem.* Fraud against Indian bank customers increasingly relies on social engineering rather than technical attacks: fake KYC-blocked SMS, forged .gov.in and bank links, UPI collect-request "refunds", and "digital arrest" video calls that pressure victims into sending money or an OTP themselves. The messages arrive in English, Hindi, Hinglish and mixed script, often with no classic trigger words, and a lookalike site may not appear in any blocklist yet. Official advice exists (RBI, the 1930 helpline, cybercrime.gov.in) but is not at hand at the moment of doubt.

*The solution.* SafeMeAI is a website with a public API; nothing to install. Users get a verdict in seconds, the evidence behind it, and clear next steps, in English or Hindi. Features: scam message checker (including links, UPI IDs and phone numbers), website verifier, a graded six-question digital-arrest panic check, a notice/document check (photos and PDFs read with Google Document AI, then wording triage), a Gemini advisor, citizen reports with abuse controls, and a Live analytics tab computed from BigQuery.

*How it works.* A layered domain engine treats official namespaces (.gov.in, .bank.in) as verified only if the name actually exists in Google Public DNS, then adds domain age, Google Web Risk, a Firestore-backed threat store (Phishing.Database, URLhaus, Tranco context, RBI alert list, SEBI registers; Cloud Scheduler refreshes it with OIDC-signed jobs), lookalike and homoglyph detection, and a live TLS audit with an SSRF guard. Gemini 2.5 Flash on Vertex AI (asia-south1) is used for a second opinion on ambiguous cases, a structured Hindi/English advisor, and translation. Guardrails: user text is quoted as untrusted data; PII (phones, Aadhaar, PAN, cards, e-mails, UPI IDs, OTP-like codes) is redacted before any model call; Gemini can raise risk only when concrete evidence exists and can lower it only when all evidence is stylistic; it can never turn an unverified domain safe; calls have a 4-second timeout and fall back to rules; every response states which engine answered.

*Responsible AI and privacy.* No raw input is stored: the audit trail keeps a SHA-256 of the input and an HMAC of the client network, written to Cloud Logging and a BigQuery audit table. Compute, storage and Gemini run in India (asia-south1); Document AI OCR also runs in a Mumbai (asia-south1) processor. Rate limits, upload caps, CSP, escaped output and human review for crowd reports defend against abuse.

*Evidence.* The repo contains 1,081 passing tests, an OpenAPI spec, and two evaluations. On a fresh, blind 253-item set (production, Gemini on): messages 82.9% recall and 10.0% false-alarm rate; domains 100% recall (with stated caveats); forged notices only 33.3% recall. Gemini added three true positives and removed one false alarm in the cases it handled. We list known gaps and fix plans openly.

*Path forward.* Shadow-mode bank pilot through the API with an agreed false-positive budget; later Vertex AI Search over RBI/NPCI circulars, a Pub/Sub event pipeline and a classifier trained on confirmed reports (future work, not built).

**Google Cloud technologies used (live in the deployment)**

- Cloud Run (app and API, asia-south1)
- Firebase Hosting (safemeai.in, CDN, proxies /api to Cloud Run)
- Vertex AI: Gemini 2.5 Flash (second opinion, advisor, Hindi translation), asia-south1
- Document AI (OCR for uploaded notice photos/PDFs)
- Web Risk (malicious URL lookup; configured, see note)
- Google Public DNS over HTTPS (existence checks)
- Firestore (threat store, citizen reports)
- Cloud Scheduler (feed ingestion jobs, OIDC)
- BigQuery (audit sink and Live analytics queries)
- Secret Manager (API keys and secrets)
- Cloud Logging (hash-only audit lines)

Note: `/api/system/status` on 16 Oct 2026 reported Web Risk as configured; its `lastOk` was empty at that moment (no successful call recorded since that instance started). Re-check before submitting and remove it from the list if it is not returning results.

Not Google: RDAP (rdap.org), Cloudflare security DNS (used as a signal), open feeds (Phishing.Database, URLhaus, Tranco, RBI, SEBI).

**What is simulated vs real**

Real and live: text, URL, UPI and phone scoring; domain verification (DNS, TLS, RDAP age, threat feeds); Gemini second opinion, advisor and translation; Document AI OCR on uploads; panic screener (deterministic); crowd reports with review rules; signed blocklist API; audit trail; BigQuery Live analytics and the hero counters.

Simulated or limited (and labelled in the product or here):
- Document lab preset specimens are pre-written examples (`dataSource: demo-simulated`); uploads use real OCR but the verdict is wording triage, not seal/signature forensics.
- Compliance search is curated static citations (Vertex AI Search is not connected).
- Telemetry ingest is a simulated acknowledgement (nothing published to Pub/Sub).
- Live analytics figures come from the prototype's own test and evaluation traffic, not real customers.
- Latest evaluation data were written by an LLM (stated in the report), not real victim data.
- The prototype has no customers, pilots or revenue.

**Links**

| | |
|---|---|
| Live prototype | https://safemeai.in |
| Cloud Run URL | https://safemeai-bfsi-846801666760.asia-south1.run.app |
| Public repo | https://github.com/rps011/safemeai-portal-public |
| Deck (PDF) | `docs/submission/SafeMeAI_Deck.pdf` (upload to the form; also commit to the repo) |
| Video | PLACEHOLDER: add link after recording |
| API docs | https://safemeai.in/api/docs and https://safemeai.in/api/v1/openapi.json |
| Contact | support@safemeai.in |

**Eligibility disclosure**

The SafeMeAI web platform submitted here (portal, API, detection engines, evaluation) was built between 14 and 16 October 2026, within the hackathon window of 7 September to 18 October 2026. SafeMeAI also has a separate, earlier Android application. It is NOT part of this submission and is not being judged. For transparency: the threat store includes 27 seed domains originally curated for that Android app, labelled as first-party data in the feed status. Open-source and public data feeds (Phishing.Database, URLhaus, Tranco, RBI, SEBI) and third-party libraries are used under their own terms, listed in the README licence table.

## 3. Items to double-check before pressing submit (found while preparing this package)

1. **Stale UI text on the Document lab**: the page still reads "Document AI is not connected ... photos and PDFs cannot be read yet" even though the live status shows Document AI configured and the upload works. Fix the copy or a judge may think the feature is off. (App code, owner of the app agent to change.)
2. **Hindi verdict text**: on the Hinglish message verdict in Hindi, the description contains a half-translated English sentence ("Scammers threaten that your bank account..."). Cosmetic but visible; avoid showing it, or fix.
3. **Analytics tile freshness**: the Live analytics figures grow with every test you run (including the ones for this video and these screenshots). Re-capture the screenshot on slide 11 just before submitting if you want it to match the live page; the text on the slide says "snapshot".
4. **Licences before commercial use**: Tranco (aggregates CC BY-NC data) and URLhaus (fair use, Auth-Key) need confirmation; OpenPhish is not used. See README.
5. **Engine fixes in progress**: the "Known gaps" box in the deck says fixes target the v2 failure classes and have not been re-measured. If the maintainers re-measure on a new unseen set before the deadline, update slide 10 with the new numbers and keep the v1/v2 caveat. Do not quote post-fix numbers measured on the burned v2 set as generalisation.
6. **Repo cleanliness**: no secrets, `.env`, API keys or `uploads/` content in the public repo.

## 4. Judge Q&A sheet (honest answers)

**1. Isn't this mostly rules?**
Largely yes, by design. The deterministic engine does most of the work because it is fast, explainable and auditable, and in our ablation rules-only already reaches 78.6% message recall. Gemini is used where rules are weakest: ambiguous cases, Hindi explanations, free-form questions. We say this on the product (each answer shows which engine produced it).

**2. How does Gemini add value measurably?**
On the blind v2 set (150 messages) Gemini was consulted on 9 messages: +3 true positives, -1 false alarm, 0 regressions; pooled F1 went from 84.5 to 86.5 versus the rules-only run. That sample is tiny and the ablation still had live DNS/TLS on, so we call it directional, not proof. Gemini also enables things rules cannot: Hindi advice, free-form Q&A, readable explanations.

**3. What about false positives?**
Measured: 10.0% of genuine messages were flagged HIGH/CRITICAL (8 of 80), 4.4% for domains, 0 of 12 for documents. About half of the message false alarms come from one design choice (an unverified link inside a message floors the score at HIGH) and the rest from genuine security alerts that use scam vocabulary ("UPI PIN changed"). Those classes are the first fix targets. For a bank we propose a shadow-mode phase and an agreed false-positive budget before any customer sees a warning. The hard-case share in our set is deliberately high, so real-world rates will differ.

**4. Was this built during the hackathon?**
The web platform was built 14-16 Oct 2026, inside 7 Sep - 18 Oct 2026. A separate earlier Android app exists and is explicitly excluded; 27 seed domains from it sit in the threat store and are labelled.

**5. How do you prevent abuse of crowd reports?**
Reports are not trusted directly: a target needs independent corroboration plus engine evidence (e.g. a young domain or a lookalike) before it is blocked; reports against allow-listed, government, shared-hosting-parent or long-established domains always go to human review; reporters whose reports are dismissed repeatedly stop counting; entries expire; the endpoint is rate limited. Allow-listed institutions can never be auto-blocked.

**6. Data privacy?**
The raw text is not stored. Audit lines hold a SHA-256 of the input and an HMAC of the client /24 network. PII is redacted before text goes to Gemini. Compute, Firestore, BigQuery, Gemini and the Document AI OCR processor are in asia-south1 (Mumbai). Disclosed external calls: domain lookups (Web Risk, DNS, RDAP) send only the domain name, not the message. A DPDP-oriented notice is in the UI; open items (DPO, breach runbook, processor agreement) are listed in the README. This is not legal advice.

**7. What if Gemini is down or slow?**
Calls time out at 4 seconds and fail open to the rules verdict, labelled "rules fallback" in the UI. In our run Gemini timed out on 4 cases and was rate-limited on 1; those cases fell back to rules.

**8. Can the LLM be prompt-injected through a scam message?**
The message is passed as quoted untrusted JSON data with an instruction to ignore embedded instructions; output must match a schema; and the model cannot lower risk when hard evidence (link, OTP ask, payment ask, number, UPI ID) exists, nor mark an unverified domain safe. Worst case, an injected message gets a wrong "second opinion" that rules still bound. We have injection test cases in the suite; we do not claim immunity.

**9. Why is document detection so weak (33.3%)?**
Because it is wording triage after OCR, not forensics; it catches overt "pay or be arrested" notices but misses forged letters that sit just under the HIGH threshold and fee-before-benefit letters from private companies. We report it, and the fix plan (fee/deposit/personal-account/free-mail signals, review the MEDIUM band) is on slide 10. No seal or signature verification is claimed.

**10. The domain recall is 100%. Isn't that too good?**
Yes, read it with care: all 11 resolving malicious cases carried the brand name or were IP literals/shorteners, and 23 more did not exist at all (the engine adds risk for non-existent names). No clean-looking, live, brand-free phishing domain was tested, so the number says nothing about zero-day clean domains. The threat feeds help there but could not be measured with synthetic names.

**11. Will it scale and what does it cost?**
Stateless Cloud Run behind Firebase Hosting; threat lookups are in-memory, refreshed from Firestore; Gemini only on ambiguous cases. Rough, labelled estimate: about US$0.04 per 1,000 message checks for Gemini at public list prices if ~6% consult the model; compute and other APIs are extra. Limits we know: per-instance rate limiting (Cloud Armor recommended, not enabled) and cold starts with scale-to-zero.

**12. What is the business model and is there traction?**
There is none to report: it is a prototype with no customers, pilots or revenue. The plan is a bank pilot via the API in shadow mode, with a free citizen tier. Before commercial use we must clear feed licences (Tranco, URLhaus), complete DPDP items, and re-evaluate on a larger independent set.

**13 (bonus). Why did you publish weak results?**
Because a fraud tool that overstates its accuracy is dangerous: people will rely on it. The v1 and v2 evaluations are not comparable (different sets and authors), so we do not claim an improvement; we only claim that on fresh data the system sits at roughly 80-90% recall and about 10% false alarms on messages, and that notice detection is weak.
