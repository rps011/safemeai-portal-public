# SafeMeAI Evaluation v2 (fresh blind set, second evaluator)

Run date: 2026-10-16. Target: production `https://safemeai.in` (engine `1.0.0+0ebdb07`, Gemini 2.5 Flash on Vertex enabled) and a local rules-only instance.
Everything here is reproducible from `tests/eval/v2/` (dataset, runner, raw per-case responses, metrics).

## 1. Methodology

**Independence.** The set was written by a second evaluator *before* reading `docs/EVALUATION.md`, `tests/eval/heldout.json`, `tests/fixtures/*`, `tests/accuracyFixes*.test.js`, `lib/textEngine.js`, `lib/domainEngine.js`, `lib/indicators.js`, `lib/docTriage.js`, `lib/textAi.js` or `data/allowlist.json`. The only code read before running was `tests/eval/run-eval.js` (runner mechanics, copied and adapted to `tests/eval/v2/run-eval-v2.js`) and a README grep for API shape and env flags. Engine code (`server.js`, `lib/textEngine.js`, `lib/domainEngine.js`) was read only **after** both runs, to diagnose errors. No engine or app code was edited; no cloud changes; nothing committed. The v1 set is burned (engine fixes were made against it), which is why a new set was needed.

**Dataset (`tests/eval/v2/fresh.json`, frozen read-only before any run).**

| SHA-256 (verified unchanged after both runs) |
|---|
| `c34189f0372195246703d430ff96f25f59b85335e7a5f053f7c02ca6e79bef8d` |

* **150 messages**: 70 scams, 80 genuine. Styles: long messy WhatsApp forwards, voice-note / call-centre transcripts, Telegram and Instagram DMs, marketplace/QR/UPI chats, WhatsApp-style typos, SMS abbreviations. 39 of 70 scams (56%, more than the ~30% planned) are "hard": no classic trigger words, or Hindi (Devanagari), Hinglish, mixed-script, or obfuscated (spaced, dotted, leetspeak, Cyrillic homoglyph). Genuine messages come from banks (incl. cooperative/regional), insurers, brokers, telcos, utilities, govt portals, e-commerce, edtech, travel, hospital/lab, RWA/school notices and personal chats. 41 genuine are tagged "tricky" (carry a link, helpline number, OTP/KYC/refund wording, urgency or money amounts) - more than the ~25 planned.
* **80 domains**: 35 malicious-style, 45 legit (30 well-known, 15 lesser-known real Indian institutions: coop/regional/small-finance banks, state DISCOM, universities, a hospital, insurers). Malicious names are synthetic; none was registered, visited or probed by us (the only lookups were DNS A-record queries for my own invented names, to learn which ones resolve, saved in `resolution.json`). I pre-tagged `believedResolving` in the dataset; my belief was wrong for one (DM23, `pages.dev` does not wildcard-resolve). Existence used in the split below is the *measured* DNS result: 11 of 35 malicious resolve (2 IP literals, 7 free-hosting subdomains on shared hosts, 2 legit URL shorteners); 24 do not exist (NXDOMAIN).
* **24 documents**: 12 forged/threatening (ED, IT, RBI, court, DoT, CBI, Customs, SEBI, NCB notices, plus fee-before-disbursal loan letter, fake appointment letter, fake LIC maturity letter) and 12 genuine (hospital bill, advocate's s.138 NI Act notice demanding genuine dues, IT s.143(3) assessment order, bank sanction letter, electricity bill, salary slip, insurance schedule, civil court summons, GST show-cause notice, university fee receipt, municipal property tax notice, bank statement).

**Protocol (same as v1).** Black-box HTTP only: `POST /api/scam/check {text}`, `/api/domain/check {url}`, `/api/document-ai/analyze {customText}`. Flagged = HIGH or CRITICAL. Live pacing 2.5 s per message/domain request (10.5 s per document request, in parallel stream), `Retry-After` honoured and a 429 never counted as a result (live: 0 retries; local: 139 retries because the local limiter is stricter at 300 ms pace, all retried to a real response). Metrics: confusion matrices, precision, recall, F1, FPR, "scam rated below MEDIUM", "genuine rated HIGH/CRITICAL", per-category/language/obfuscation, Wilson 95% CI, latency p50/p95, Gemini contribution. Ablation: `DISABLE_GEMINI=1 DISABLE_THREAT_INTEL=1 PORT=8099 node server.js` (DNS/TLS/RDAP lookups were still on) vs production.

**Call failures.** One call failed in both runs: DM17 (`xn--hdfcbnk-secure-w0a.com`, my synthetic invalid punycode) returned HTTP 400 "Invalid domain or URL format". It is excluded from the metrics (domains n=79 scored, malicious 34) and listed as an error below.

## 2. Headline results (production, Gemini on)

Flagged = HIGH/CRITICAL. Intervals are Wilson 95%.

| Set | n scored | TP | FP | TN | FN | Precision | Recall [95% CI] | FPR [95% CI] | F1 |
|---|---|---|---|---|---|---|---|---|---|
| Messages | 150 | 58 | 8 | 72 | 12 | 87.9% | **82.9%** [72.4-89.9] | **10.0%** [5.2-18.5] | 85.3% |
| Domains | 79 (of 80) | 34 | 2 | 43 | 0 | 94.4% | 100% [89.8-100] | 4.4% [1.2-14.8] | 97.1% |
| Documents | 24 | 4 | 0 | 12 | 8 | 100% | **33.3%** [13.8-60.9] | 0% [0-24.3] | 50.0% |
| **Pooled** | 253 | 96 | 10 | 127 | 20 | 90.6% | 82.8% [74.9-88.6] | 7.3% [4.0-12.9] | 86.5% |

Severity views (messages): scams rated below MEDIUM (a user would likely be told nothing is wrong): **12 of 70 (17.1%)** (10 SAFE, 2 LOW). Genuine messages rated HIGH/CRITICAL: **8 of 80 (10.0%)** (5 HIGH, 3 CRITICAL; no genuine message sat at MEDIUM). Documents: forged rated below MEDIUM 2/12; genuine rated MEDIUM+ 1/12 (a MEDIUM, "not flagged").

Latency, live (ms): messages p50 371 / p95 1,802; domains p50 1,297 / p95 2,695; documents p50 290 / p95 869.

### Message breakdowns (live)

| Slice | Recall |
|---|---|
| Classic scams (31) | 87.1% (27/31) |
| Hard scams: no triggers / non-English / obfuscated (39) | 79.5% (31/39) |
| English (47) / Hinglish (15) / Hindi Devanagari (4) / mixed-script (4) | 83.0% / 86.7% / 50.0% (2/4) / 100% (4/4) |
| Obfuscated (6): mixed-script 2/2, leetspeak 1/1, homoglyph 1/1, **letter-spaced 0/1, dot-separated 0/1** | 4/6 |
| Tricky genuine (41) flagged | 4 (9.8%): G22, G62, G64, G73 |
| Non-tricky genuine (39) flagged | 4 (10.3%): G25, G33, G39, G68 |

Categories with misses: kyc_upi 4/5, loan_app 1/2, fake_customer_care 1/2, fake_bank_call 1/2, tech_support 0/1, parcel (Hindi) 0/1, sim_swap 0/1, scholarship 0/1, social_phish 0/1, note_exchange 0/1, fake_shop 0/1, mudra_fee 0/1. Every other scam category was fully caught (digital arrest 3/3, investment, job/task, sextortion, marketplace QR, courier, electricity, etc.); single-case categories are anecdotes, not rates.

The "tricky" tag did not predict failure: half of all false alarms hit plain genuine messages (a driving-licence note, a debit-card-expiry note, a lab report, a matrimony prose mention).

### Domains: existing vs non-existent (NXDOMAIN caveat)

| Slice | Malicious flagged | Legit false alarms |
|---|---|---|
| Malicious that **resolve** (11: 2 IP, 7 free-host subdomains, 2 shorteners), + 45 legit | **11/11** (Wilson CI 74.1-100) | 2/45 |
| Malicious that **do not exist** (23 scored; DM17 excluded), + 45 legit | 23/23 | 2/45 |

Caution on reading this: all 11 resolving cases carry the brand name in the host or are IP literals / shorteners, and the 23 non-existent ones may be flagged partly *because* they do not resolve (the engine adds risk for "did not resolve"). The clean-looking, no-brand, *live* phishing domain (the hardest real-world case) is **not represented**: the 4 no-brand domains in the set were all non-existent. Domain recall of 100% therefore says nothing about zero-day clean domains. Legit side: 30/30 well-known passed; lesser-known institutions 13/15 (see DL33, DL43).

## 3. Ablation: local rules-only vs production

| | Local rules-only (`DISABLE_GEMINI=1 DISABLE_THREAT_INTEL=1`) | Production | Delta |
|---|---|---|---|
| Messages recall | 78.6% (55/70) [67.6-86.6] | 82.9% (58/70) | +3 TP |
| Messages FPR | 11.3% (9/80) | 10.0% (8/80) | -1 FP |
| Messages scam < MEDIUM | 14/70 | 12/70 | -2 |
| Domains (n=79) | 34/34 flagged, 2 FP | identical | 0 |
| Documents | 4/12, 0 FP | identical | 0 (Gemini not involved; identical scores) |
| Pooled | R 80.2% / FPR 8.0% / F1 84.5% | R 82.8% / FPR 7.3% / F1 86.5% | +2.0 pts F1 |
| Latency p50/p95 messages | 7 / 703 ms | 371 / 1,802 ms | |

**Gemini contribution (messages only).** Consulted on 9 of 150 messages (mid-range scores). 4 escalated (S21, S31, S39, S41: all scams, all correct; S31 was already flagged at 62, so 3 new true positives: S21, S39, S41), 3 de-escalated (G52 MEDIUM 50 to LOW 25, G65 HIGH 63 to LOW 25 which removed a false alarm, G80), 1 agreed, 1 "not applied" (S32, a miss). On 4 further messages Gemini timed out (4 s fail-open) and on 1 got HTTP 429, e.g. S51 (miss) fell back to rules. Net: +3 TP, -1 FP, 0 regressions, on an n=9 sample (not statistically meaningful, but directionally useful). On domains Gemini commented on 7 responses; for 6 it only added to an already-flagged verdict and for DL43 it escalated a false alarm from HIGH 65 to CRITICAL 80. Rules-only deterministic precision/recall is therefore the dominant behaviour; the live "AI" adds ~4 points of recall on this set.

Threat-intel feeds had no measurable effect here because none of my synthetic domains are in any feed; this ablation cannot evaluate feed value.

## 4. Error analysis (all 31 live errors)

Live errors: 12 missed scam messages, 8 false-alarm messages, 1 domain call failure, 2 false-alarm domains, 8 missed forged documents. Local-only extra errors (fixed by Gemini live): S21, S39, S41 (missed) and G65 (false alarm: business invoice, HIGH 63). No error was introduced by Gemini. Causes below were diagnosed from response flags first, then by reading `server.js` / `lib/*` after the runs; wording like "probably" marks inference I did not prove by experiment.

| ID | Input (truncated) | Expected | Actual (live) | Probable cause |
|---|---|---|---|---|
| S20 | Agent: Thank you for calling Paytm care. Please tell me the 6 digit number you just received by SMS so I can r | scam | SAFE 5 | Voice-transcript OTP phishing with no keyword ("OTP", "KYC", link). Engine matched the "standard bank/UPI alert" template and the "no links/payment demands" reassurance flag. Pure vocabulary gap. |
| S30 | ALERT: Your Windows is infected with 5 viruses. Call Microsoft support 1800-XXX-XXXX immediately. Do not shut  | scam | SAFE 8 | Classic tech-support scam; only the generic urgency flag fired. No tech-support / "call Microsoft" category evident. |
| S32 | भाई साहब आपका पार्सल वापस जा रहा है, पता सही करने के लिए 10 रुपये इस लिंक पर भेजिए, वरना कल पार्सल लौट जाएगा। | scam | LOW 34 | Hindi parcel-fee lure matched 3 Hindi flags but scored LOW 34. Gemini was consulted and "not applied". Hindi category weights too low; Gemini did not rescue. |
| S34 | U r e l i g i b l e f o r 5 0 0 0 0 l o a n.  S h a r e t h e O T P t o c o n f i r m. | scam | SAFE 8 | Letter-spaced obfuscation ("U r e l i g i b l e ... O T P") not collapsed by normaliser. Nothing matched. |
| S43 | Sir your 4G SIM needs an upgrade to 5G. Please reply with the 20-digit SIM number printed on the back and pres | scam | SAFE 8 | SIM-upgrade scam with no trigger words (asks for 20-digit SIM number). Nothing matched. |
| S45 | हेलो सर, मैं बैंक से बोल रहा हूँ, आपका क्रेडिट कार्ड का वार्षिक शुल्क माफ हो रहा है, बस आप फोन पर आए हुए कोड क | scam | SAFE 8 | Hindi voice-note: bank caller asks to read out a code; Hindi lexicon has no "code/OTP read-out" pattern. Nothing matched. |
| S51 | Dear student you are selected for PM Scholarship of Rs 50,000. Pay Rs 350 registration to the account below to | scam | LOW 25 | Advance-fee scholarship: only "recruiter contact" and "payment demand" flags (LOW 25). Gemini consulted but timed out (4 s fail-open). |
| S57 | Your Instagram copyright violation notice: appeal within 24 hours at meta-appeal-center.help or your account w | scam | SAFE 8 | Link "meta-appeal-center.help" probably never extracted: ".help" is not in the engine's known-TLD list and has no path (lib/textEngine.js isPlausibleLink), so no domain check ran. Only urgency flag fired. |
| S59 | Bhai mera dost RBI me hai, usne bola 2000 ke note wapas liye jaa rahe hain, kal tak bank me jama kar do ya fir | scam | SAFE 8 | Hinglish note-exchange / black-money lure. Only the threat flag fired. Not a pattern in the lexicon. |
| S65 | Flat 90% off on Nike shoes only today! Rs 499 only. Pay via UPI on the link: nike-clearance-india.sale . COD n | scam | SAFE 8 | Link "nike-clearance-india.sale": ".sale" is not in the known-TLD list so the link was probably never extracted/checked (same mechanism as S57). Fake-shop scams have no text category. |
| S67 | Y.o.u.r  A.d.h.a.a.r  b.l.o.c.k.e.d !! call 9XXXXXXXXX n.o.w | scam | SAFE 8 | Dot-separated obfuscation ("Y.o.u.r A.d.h.a.a.r b.l.o.c.k.e.d") not normalised; only the weak "threat" flag. |
| S68 | Bank manager bol raha hu, aapka Mudra loan 4 lakh sanction ho gaya hai. Insurance premium 2,500 pehle PhonePe  | scam | SAFE 8 | Hinglish Mudra-loan advance-fee scam; Hinglish flags "no known scam pattern". Payment demand in Hinglish ("premium ... PhonePe karna hoga") not recognised. |
| G22 | NPTEL: Hall ticket for Jan 2026 exams is available on nptel.ac.in. Last date for exam fee payment of Rs 1,000  | genuine | HIGH 75 | Message contains link nptel.ac.in. Domain engine alone rates it LOW 30 (Tranco #8808) but text-route rule "unverified link inside a message >= HIGH (floor 75)" in server.js (non allow-listed, non recognised-brand => floor 75) overrides. Systematic link-floor false positive. |
| G25 | Dr Lal PathLabs: Your report for ID 91XXXX is ready. View at https://www.lalpathlabs.com . Please do not share | genuine | HIGH 75 | Same mechanism: link to lalpathlabs.com (standalone domain check = LOW 30, Tranco #61062) floored to HIGH 75 in a message. |
| G33 | Your driving licence renewal application is approved. Collect the card at the RTO or download the DL from pari | genuine | HIGH 76 | Keyword "parivahan" triggers "Traffic e-challan theme" + "download" triggers app-install flag; no link involved. Text lexicon false positive. |
| G39 | Your debit card ending 9921 expires on 31-10-2025. A new card has been dispatched to your registered address a | genuine | CRITICAL 86 | Debit-card-expiry notice: "expires" keyword set fired "account/card will be blocked or expire" + "reward points about to expire". Score 86 CRITICAL. Text-lexicon false positive on a very common genuine alert type. |
| G62 | Mumbai University: Results of TYBCom Sem 6 are declared at mu.ac.in. Revaluation form can be submitted till 22 | genuine | HIGH 75 | Message links to mu.ac.in (org-validated cert "University of Mumbai", resolves). Domain engine: MODERATE 35; message-link floor lifted it to HIGH 75 because age could not be verified, so not "orgValidatedEstablished". |
| G64 | Your UPI PIN was changed successfully on 12-Oct. If this was not done by you, please call your bank's customer | genuine | CRITICAL 99 | "UPI PIN changed ... block UPI" alert: keywords UPI PIN + block + customer care + immediately stacked to CRITICAL 99. No attempt to detect the notifying-not-requesting pattern. |
| G68 | Hello uncle, we saw your daughter's profile on Shaadi.com. We are a family from Nagpur, can we call you this S | genuine | HIGH 75 | Text mentions "Shaadi.com" (no scheme); extracted as a link and floored to HIGH 75 although standalone domain check = LOW 30 (Tranco #35087). Same link-floor mechanism; also shows brand names with ".com" in prose are treated as links. |
| G73 | CoinDCX: Your withdrawal of 0.01 BTC has been initiated. If this was not you, freeze your account immediately  | genuine | CRITICAL 99 | CoinDCX "freeze your account" security notice with coindcx.com/support: crypto-bait + block/threat + urgency + link stacked to CRITICAL 99. Genuine alerts mimic scam vocabulary. |
| DM17 | xn--hdfcbnk-secure-w0a.com | malicious | HTTP 400 | HTTP 400 "Invalid domain or URL format" for my synthetic punycode input "xn--hdfcbnk-secure-w0a.com" (invalid punycode label). Input rejection, arguably a correct refusal but gives the user no verdict; my test input was malformed. Excluded from metrics (n=79). |
| DL33 | https://www.cosmosbank.in | legit | CRITICAL 96 | https://www.cosmosbank.in. The engine flagged impersonation: hostname "embeds cosmos.bank.in". GROUND-TRUTH PROBLEM ON MY SIDE: the bank's real domain is cosmosbank.com; cosmosbank.in resolves but I cannot confirm it is the bank, so this is probably a correct flag and a labelling mistake. The engine's stated reason (splitting "cosmosbank" into "cosmos.bank") is still a questionable heuristic. |
| DL43 | https://www.cmch-vellore.edu | legit | CRITICAL 80 | https://www.cmch-vellore.edu (genuine CMC Vellore). Engine said "did not resolve (NOERROR)" and age unknown. In DNS the apex cmch-vellore.edu has no A record while www is a CNAME to CloudFront; the engine strips "www." (lib/domainEngine.js:689) and probably queries the apex. Real false positive from www-only sites; Gemini then escalated HIGH to CRITICAL, reinforcing the error. |
| DF04 | HON'BLE SUPREME COURT OF INDIA - ARREST WARRANT Case No. CRL/2025/00921  State vs. Mobile No. 98XXXXXXXX  Wher | forged | MEDIUM 54 | Forged Supreme Court warrant: MEDIUM 54 NEEDS_REVIEW, no signals listed. Just under HIGH (60). |
| DF05 | DEPARTMENT OF TELECOMMUNICATIONS Notice of Permanent Disconnection  Your SIM numbers (3) registered against yo | forged | MEDIUM 53 | Forged DoT disconnection notice: MEDIUM 53, no signals. |
| DF06 | CENTRAL BUREAU OF INVESTIGATION Anti-Corruption & Cyber Crime Division CONFIDENTIAL - FOR ADDRESSEE ONLY  A pa | forged | MEDIUM 54 | Forged CBI letter ("digital arrest" language): MEDIUM 54, no signals. |
| DF07 | INDIAN CUSTOMS - NOTICE OF SEIZURE Consignment AWB 7741 8832 1190 from United Kingdom (gift parcel: laptop, je | forged | MEDIUM 53 | Forged Customs seizure notice with multiple fees: MEDIUM 53, no signals. |
| DF08 | SECURITIES AND EXCHANGE BOARD OF INDIA Recovery Notice no. SEBI/RC/2025/3321  Our records show you subscribed  | forged | MEDIUM 53 | Forged SEBI recovery notice with "refundable security": MEDIUM 53, no signals. |
| DF09 | GOLDEN FINSERV LIMITED - LOAN SANCTION LETTER Congratulations! Your personal loan of Rs 8,00,000 at 5.9% p.a.  | forged | LOW 19 | Forged loan sanction letter (fees before disbursal, UPI personal handle, no credit check): rated LOW 19 GENUINE_LOOKING. |
| DF10 | APPOINTMENT LETTER Infosys Limited (HR Division) - Ref INF/HR/2025/44112  Dear Candidate, we are pleased to of | forged | LOW 20 | Forged appointment letter with Rs 25,000 deposit and gmail HR address: rated LOW 20 GENUINE_LOOKING. |
| DF11 | LIFE INSURANCE CORPORATION OF INDIA - MATURITY INTIMATION Your old policy has matured with total bonus Rs 17,8 | forged | MEDIUM 51 | Forged LIC maturity letter demanding fees to a personal account: MEDIUM 51, no signals. |


### Patterns behind the errors

1. **Message-link floor (server.js, "Unverified link inside a message is >= HIGH", floor 75).** Any link to a domain that is not allow-listed, not a recognised brand and not "org-validated established" lifts the whole message to HIGH, even when the standalone domain verdict is LOW/MODERATE (I verified: `nptel.ac.in`, `lalpathlabs.com`, `shaadi.com` each score LOW 30 alone, `mu.ac.in` MODERATE 35). This causes 4 of the 8 message false alarms (G22, G25, G62, G68) and is a design decision, not noise: it will hit every genuine message that links to a smaller institution or a ".com" brand mentioned in prose.
2. **Scam vocabulary stacking on genuine security notices** (G39, G64, G73, G33): block/expire/PIN/immediately/crypto words push genuine alerts to CRITICAL (86-99). The engine has no concept of "notifying" versus "requesting".
3. **Lexicon gaps for no-trigger scams** (S20, S30, S43, S45, S59, S68, S57, S65): OTP read-out by voice, SIM-number harvesting, tech-support, fake shops, Hindi/Hinglish advance-fee. Two (S57 `.help`, S65 `.sale`) probably also lost their link because those TLDs are missing from the known-TLD list in `lib/textEngine.js`, so the domain engine, which would have flagged a brand-lookalike, never ran. That is a cheap, high-value fix.
4. **Obfuscation normaliser** does not collapse letter-spacing or dot-separation (S34, S67) although mixed-script, leetspeak and Cyrillic homoglyph cases passed.
5. **Documents: forged letters stop at MEDIUM 51-54 or look "GENUINE_LOOKING".** Six forged notices sit 6-9 points under the HIGH threshold (60) with no signals listed, and the two fee-before-benefit private-company letters (DF09 loan, DF10 job) score LOW 19-20. All 12 genuine documents passed, so the engine is conservative to the point of under-calling: the three it caught (ED, IT, RBI) plus NCB had overt "pay to avoid arrest" text. A fee-demand-to-personal-account / UPI / gmail-HR detector is the obvious gap.
6. **Domain engine: www-only sites** (DL43). Genuine hospital site with no apex A record is treated as unresolvable.

## 5. Limitations (read these before quoting any number)

* **Small sample.** 70 scams, 80 genuine, 34/45 domains, 12/12 documents. CIs are wide (message recall 72-90%, document recall 14-61%). Per-category rows with 1 case are anecdotes.
* **LLM-authored wording.** All 253 items were written by an LLM from knowledge of Indian fraud advisories; real scammers' text is messier, shorter, and adversarially adapted. Genuine messages are also my idea of genuine; real SMS templates differ, and many Indian institutions' real templates are unknown to me.
* **No real traffic.** No real phishing URLs, no live phishing pages, no real victim data; so no threat-feed test, no zero-day clean-looking live phishing domain (the hardest case), and domains only tested for name patterns. Domain recall of 100% should be read as "brand-pattern and NXDOMAIN detection works", not "phishing detection works".
* **Ground-truth errors on my side.** DL33 `cosmosbank.in`: I labelled it genuine but the bank's domain is `cosmosbank.com`; `cosmosbank.in` resolves but I cannot confirm ownership. Headline numbers keep the frozen label (counted as a false alarm). If it is relabelled, the domain FPR becomes 1/44 (2.3%) and pooled FPR 9/136 (6.6%); that is a post-hoc adjustment and is *not* used in the headline. I did not independently verify all 15 lesser-known domains beyond this; the 14 others passed DNS-wise without surprise, but "genuine" for them rests on my memory.
* **Hard share is not representative.** 56% of scams are deliberately hard and 41 of 80 genuine are deliberately tricky, so absolute recall/FPR are not field rates. Prevalence in real traffic is very low for scams, so real-world precision would be materially lower than the 87.9% here for the same FPR.
* **Gemini nondeterminism and availability.** Gemini timed out on 4 and was rate-limited on 1 of the cases it would have been consulted on; a re-run may differ by a few cases. Single run per configuration, no repeat to measure variance.
* **Ablation confound.** The local run still did live DNS/TLS/RDAP lookups; only Gemini and threat-feed ingestion were off.
* **Datasets are not independent of each other across time.** This v2 set is now also burned once the maintainers read this report; fixing only the errors above would overfit it exactly as happened with v1.
* **v1 comparison.** v1 measured 88.3% recall / 13.3% false-positive rate on messages and 50% document recall, *before* engine fixes, on a different (older, now-burned) set. v2 (production) shows 82.9% recall / 10.0% FPR on messages and 33.3% document recall, on a different, harder-styled set, after the fixes. **v1 to v2 is not an apples-to-apples comparison**: different items, different authors, different difficulty mix, different sample sizes (document recall CIs, 6/12 vs 4/12, overlap heavily). It must not be presented as improvement or regression. The only defensible statement is that on fresh data the system is in the same rough band (recall about 80-90%, FPR about 10%) and that document recall is weak in both.

## 6. Next steps (ordered by expected benefit)

1. Lower the message-link floor for links to domains with positive standalone evidence (resolving, Tranco-ranked, org-validated certificate): at minimum let the domain verdict (LOW/MODERATE) drive the message when the text itself is benign. Would remove about half of message false alarms.
2. Add a "notification, not request" gate (no ask for OTP/PIN/payment, only informs) before stacking block/expire/PIN words; cover card-expiry, UPI-PIN-changed, fraud-freeze notices.
3. Extend the known-TLD list (`.help`, `.sale`, and other cheap abuse TLDs) so links in text are always extracted; then re-test S57/S65.
4. Documents: add signals for "pay a fee/deposit/security before benefit", personal UPI/bank account or free-mail contact in an official-looking letter, "do not tell anyone" secrecy language, and review the MEDIUM 51-54 band (consider HIGH at 50 for the fee-demand signal).
5. Normaliser: collapse letter-spaced and dot-separated tokens.
6. Add lexicon for voice-note OTP read-out, SIM-number harvesting, tech-support, fake-shop and Hinglish/Hindi advance-fee phrasings (S20, S30, S43, S45, S59, S68).
7. Domain engine: test apex and `www.` for resolution (DL43); review the "embeds cosmos.bank.in" splitting heuristic.
8. Return a user-readable verdict instead of HTTP 400 for malformed punycode (DM17), or document the validation.
9. Measurement: a larger set from real (consented, anonymised) reports and real genuine SMS templates, reviewed by someone outside the engineering team, repeated Gemini runs for variance, and a live-phishing-domain test (no-brand, resolving, in a feed vs not in a feed) run by the people who own that risk.

## 7. Artifacts

`tests/eval/v2/fresh.json` (frozen), `fresh.sha256`, `build-fresh.js` (how it was assembled), `run-eval-v2.js` (runner/report), `resolution.json` (DNS existence of malicious names), `results-live.json`, `results-local.json` (raw responses + metrics), `live.log`, `local.log`. Re-report with `node tests/eval/v2/run-eval-v2.js --report-only tests/eval/v2/results-live.json --baseline tests/eval/v2/results-local.json` (no network).

## 7. Post-v2 changes (engine fixes made after this report; measured numbers above are unchanged)

v2 is now burned: these fixes address the general root causes in section 4, were not derived by copying v2 cases into rules, and are protected by NEW paraphrased tests (`tests/accuracyFixes3.test.js`, `tests/fixtures/benchmark3.json`). No re-measurement against the live site was done, so none of these changes has a measured effect on v2-style data; an offline mirror (`tests/helpers/benchWorld.js`) only shows the intended behaviour.

1. **Message links (`lib/linkPolicy.js`, shared by `server.js` and the offline mirror).** The blanket "unverified link => HIGH 75" rule is replaced by evidence: trusted/positive links (verified, recognised, org-validated, Tranco-popular, established) are never force-boosted; dangerous links (hard block, score >= 60, free-hosting, domain < 90 days, look-alike) and failed assessments keep the floor of 75; an unknown link alone is "not sure" (MEDIUM 45-59) unless the wording has a concrete risk signal (credential/OTP, payment, personal-data ask, urgency + threat, install, secrecy, shortener, call-this-mobile, a scam theme), which restores HIGH+.
2. **Genuine security notices (`lib/textEngine.js`).** A confirmation-vs-request gate: messages that report an action already done, say what to do if "this was not you", warn not to share credentials or point to the official app/branch, and request nothing (no unverified link, mobile, UPI id, OTP/PIN/payment/personal-data ask, install, secrecy, future threat) are capped at LOW. The reverse pattern ("if this was not you, call <personal mobile>") is now a fake-support signal. Theme words inside an already-verified link address are no longer scored as wording. A negation no longer reaches across a comma ("not you, send the OTP").
3. **Links on newer TLDs (`lib/tlds.js`).** Extraction uses a complete TLD table plus a generic shape rule (2-24 letters / punycode), with guards for file names, version numbers, abbreviations, and "Sentence.Word" run-ons; unlisted TLDs are accepted for domain-shaped names or with a scheme/www/path.
4. **www-only sites (`lib/domainEngine.js`).** For non-sovereign names the DNS check now also uses A/AAAA/CNAME on `www.<host>` and NS/SOA as existence proof (TLS judged on www). NXDOMAIN stays a hard block.
5. **Document triage (`lib/docTriage.js`).** Added personal-destination detection (UPI id, wallet, individual's/officer's account, "account below"), fee-before-benefit detection (loan, job, refund, prize, parcel release, maturity) with a genuine-fee exemption (deducted from disbursal, per KFS/schedule of charges, GST on the fee), and an authority + fee demand + any pressure tier. New forged scores are graded (72-89 agency tier, 80-95 advance-fee letters). Advocate notices with statutory/reference structure and no personal payee are not treated as authority impersonation.
6. **Hindi.** `lib/i18nHi.js` covers every new flag, verdict and document string; `tests/accuracyFixes3.test.js` asserts it.

Known remaining gaps (unchanged): lexicon gaps for no-trigger scams (S20, S30, S43, S45, S59, S68), letter-/dot-spaced obfuscation, Hindi advance-fee wording, and the Gemini dependence of some recall.
