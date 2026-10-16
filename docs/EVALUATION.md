# SafeMeAI held-out evaluation

Independent, black-box evaluation of the production checkers on a fresh dataset that was **not** used for tuning.
Nothing in the engines, the app or the existing benchmark was changed. Run date: 2026-10-16.

## 1. Methodology

**Integrity rule.** The existing 119-case benchmark (`tests/fixtures/benchmark.json`) was used to tune the engines, so it
says nothing about generalisation. The held-out set was written from general knowledge of Indian fraud typologies and public
advisories (RBI, NPCI, I4C/1930, CERT-In, SEBI) **without opening** `lib/textEngine.js`, `lib/domainEngine.js`,
`lib/indicators.js`, `lib/docTriage.js` or the existing benchmark/accuracy tests. Only the README and `docs/api.md` were read
for the API shape. One small deviation: during the later local-server setup, a `grep` for the rate-limit env names
incidentally printed `lib/rateLimit.js` and one line of `lib/domainEngine.js`; this happened after the dataset was frozen and
before any result was inspected. The engines were read for root-cause guesses only after both runs finished, and the causes in
section 5 are mostly hypotheses read off the response flags, not verified code paths.

**Freeze.** `tests/eval/heldout.json` was finalised, then hashed, then run. During authoring I trimmed two surplus
domains (D-M39, D-M40) to hit exactly 50/50; nothing was edited after the hash was taken.

`SHA-256(tests/eval/heldout.json) = ad761cad307957489694dedb139edba323a4f7a5c118b17798f86407b1ecf7b7`
(also stored in each results file and in `tests/eval/heldout.sha256`).

**Dataset (240 cases).**

| Set | Positives | Negatives |
| --- | --- | --- |
| Messages (`/api/scam/check`) | 60 scams, 20 typologies, 28 English / 23 Hinglish / 9 Hindi (Devanagari); 12 obfuscated (3 spacing, 5 leetspeak, 4 mixed-script) | 60 genuine: debit/credit alerts, OTPs, EMI, insurance, salary, delivery/ride/order, govt (ITR, EPFO, UIDAI, passport), telecom, refunds, family chat, 14 tricky look-alikes (real links, helplines, "KYC/OTP/refund") |
| Domains (`/api/domain/check`) | 50 malicious-style, incl. 12 "clean-looking zero-day" (gibberish, no brand/keyword) | 50 legit (private/PSU/small-finance/co-op banks, central + state govt, regulators, insurers, brokers, telecom, utilities, global, e-commerce, UPI apps, news, edu) |
| Documents (`/api/document-ai/analyze`, `customText`) | 10 forged/threatening | 10 genuine (sanction letters, KYC form, payslip, summons, statement notice, RBI circular, ITR intimation, court order) |

**Decision rule.** Flagged = riskLevel HIGH or CRITICAL (score >= 60). Positive class = scam / malicious / forged.
Also reported: "scam rated below MEDIUM" (loss-of-funds miss) and "genuine rated MEDIUM or above".
Confidence intervals are 95% Wilson. 429s were retried after `Retry-After` and never counted (0 occurred).

**Runs.**

| Run | What it includes | Results file |
| --- | --- | --- |
| A. Live, production default | https://safemeai.in: rules + Gemini 2.5 Flash second opinion (Vertex AI) + live threat store (about 522k indicators) + live DNS/TLS/RDAP/Tranco/Cloudflare/Web Risk signals. ~2.5 s pacing (docs ~10.5 s, run in parallel on their own rate-limit group). 12.5 min. | `tests/eval/results-live.json` |
| B. Local, deterministic only | `DISABLE_GEMINI=1 DISABLE_THREAT_INTEL=1 PORT=8098` (threat store empty, so no feed matches); rate limits raised via `RL_*` env only. Live DNS/TLS lookups from my machine were still active (not disabled). | `tests/eval/results-local.json` |

Repeat: `node tests/eval/run-eval.js --target <url> --label <name> --out <file>`; recompute metrics without network:
`node tests/eval/run-eval.js --report-only <file> [--baseline <file>]`.

## 2. Headline results

Flagged = HIGH/CRITICAL. 95% Wilson CI in brackets.

| Metric | Messages, live (A) | Messages, rules-only (B) | Domains, live (A) | Documents, live (A) |
| --- | --- | --- | --- | --- |
| n (pos / neg) | 60 / 60 | 60 / 60 | 50 / 50 | 10 / 10 |
| TP / FP / TN / FN | 53 / 8 / 52 / 7 | 52 / 7 / 53 / 8 | 50 / 1 / 49 / 0 | 5 / 0 / 10 / 5 |
| Precision | 86.9% [76.2-93.2] | 88.1% [77.5-94.1] | 98.0% [89.7-99.7] | 100% [56.6-100] |
| Recall (1 - miss rate) | 88.3% [77.8-94.2] | 86.7% [75.8-93.1] | 100% [92.9-100] | 50.0% [23.7-76.3] |
| Miss rate on scams | 11.7% (7/60) | 13.3% (8/60) | 0% (0/50) | 50% (5/10) |
| False-positive rate on genuine | 13.3% [6.9-24.2] | 11.7% [5.8-22.2] | 2.0% [0.4-10.5] | 0% [0-27.8] |
| F1 | 87.6% | 87.4% | 99.0% | 66.7% |
| Scam rated below MEDIUM (loss-of-funds miss) | 6/60 = 10.0% [4.7-20.1] | 7/60 = 11.7% | 0/50 | 2/10 = 20% [5.7-51.0] |
| Genuine rated HIGH/CRITICAL (customer incident) | 8/60 = 13.3% | 7/60 = 11.7% | 1/50 = 2.0% | 0/10 |
| Genuine rated MEDIUM or above | 9/60 = 15.0% | 10/60 = 16.7% | 2/50 = 4.0% | 0/10 |

Messages + domains pooled (live): precision 92.0%, recall 93.6% [87.4-96.9], FPR 8.2% [4.4-14.8], F1 92.8%.

Latency (client-measured, includes network; live from my location): messages p50 381 ms / p95 1183 ms; domains p50 1525 ms /
p95 2548 ms; documents p50 295 ms / p95 497 ms. Local (no network hop, no Gemini): messages 3 / 423 ms, domains 182 / 727 ms,
documents 1 / 18 ms.

**Read these numbers with the two caveats below before quoting any of them.**

1. **The domain result is inflated by my dataset design and must not be quoted as a zero-day result.** Malicious domains were
   deliberately synthetic/unregistered, so they do not resolve. 21 of the 50 "malicious" domains (including all 12
   "clean-looking zero-day" ones and several brand/gov look-alikes) were flagged because of `NONEXISTENT_DOMAIN` (NXDOMAIN,
   score 88), not because of any content or structure signal. Real phishing domains resolve, so this detection path would not
   fire for them. The 12/12 on zero-day names therefore shows only that the engine treats NXDOMAIN as critical; it says
   nothing about registered, resolving, brand-free fresh domains. Excluding the NXDOMAIN-driven cases, the structural
   detectors (typosquat, homoglyph, brand-as-subdomain, `@` trick, raw IP, shorteners) caught the remainder, but with n=29 and
   authored lookalikes.
2. **Message genuine-side errors include one defect of mine.** M-G23 contains a made-up email domain
   (`company-example.in`) that does not exist, so the engine's NXDOMAIN rule (correctly, for its logic) rated it CRITICAL.
   It is left in and counted as an error for honesty; excluding it gives live FPR 7/59 = 11.9%.

### Breakdowns (live run, messages)

Recall by category (flagged / scams): digital arrest 4/4, fake KYC 5/5, UPI collect/refund 4/4, QR 3/3, loan-app 3/3,
task/job 2/3, investment 4/4, sextortion 2/2, courier 3/3, electricity 3/3, e-challan 2/2, lottery 3/3, remote access 3/3,
fake customer care 3/3, **family emergency 1/3**, **romance 1/2**, **OLX/marketplace 1/2**, fake HR 2/3, SIM block 2/2,
tax refund 2/3. Every miss is in a "social-engineering without classic trigger words" typology.

| Slice | Recall | FPR |
| --- | --- | --- |
| English | 24/28 = 85.7% [68.5-94.3] | 6/46 = 13.0% |
| Hinglish | 21/23 = 91.3% [73.2-97.6] | 2/12 = 16.7% |
| Hindi (Devanagari) | 8/9 = 88.9% [56.5-98.0] | 0/2 |
| Plain wording | 43/48 = 89.6% [77.8-95.5] | n/a |
| Spacing obfuscation | 3/3 | n/a |
| Leetspeak | 5/5 | n/a |
| Mixed script | 2/4 = 50% [15-85] | n/a |

Genuine FPs by class: look-alikes 5/14 (36%), bank debit alert 1/5, salary 1/2, ride 1/2; every other genuine class 0.
Obfuscation: spacing and leetspeak were all caught, but my obfuscated samples still contained strong cue words (OTP, KYC, PIN),
so this is weak evidence of robustness. Mixed-script was the one weak spot (n=4).

Domains (live): all malicious categories 100%; legit false alarms: co-operative bank 1/1 (see D-L10), all other 49/49 clean.
Documents: forged caught: CBI warrant, Supreme Court, customs/NDPS, police summons, one of two predatory loans; missed:
ED notice, both RBI notices, one predatory loan, income-tax seizure notice. All 10 genuine documents scored an identical 12
(LOW, "Genuine-looking wording") including the ITR intimation, which suggests the document checker has little discrimination
on the benign side and mainly looks for absence of threat keywords.

## 3. Ablation: what each layer buys

| Layer | Evidence on this set |
| --- | --- |
| Deterministic rules only (B) vs rules + Gemini + threat store (A), messages | Same overall quality: F1 87.4% vs 87.6%. Only **2 of 120** messages changed flag status. |
| Gemini consulted (live messages) | Only on **13 of 120** (10.8%), all in the mid-score band; the other 107 were decided by rules ("no AI second opinion needed"). Actions: 3 escalated, 2 de-escalated, 1 agrees, 7 not applied. |
| Gemini escalations | M-S54 fake-HR fee (31 LOW to 72 HIGH): **right, converted a miss to a catch**. M-S26 pre-IPO quota (62 to 72): right, but already flagged. M-G01 genuine HDFC debit alert (56 MEDIUM to 72 HIGH): **wrong, created a false alarm** (it read the standard "SMS BLOCK UPI" instruction as a blocking threat). |
| Gemini de-escalations | M-G49 (36 to 25), M-G60 (41 to 25): both correct, neither changed the flag outcome. |
| Gemini "not applied" on scams | M-S22, M-S47, M-S60 stayed unflagged after consultation (45/33/38). I cannot tell from the response whether Gemini said "not a scam" or the guard-rails discarded its view. |
| Net effect of Gemini on flag decisions | +1 true catch, +1 false alarm: **zero net gain** at n=120. The sample is too small to say Gemini is useless; it does show it is not what is carrying the accuracy. |
| Gemini on domains | 9 domains carried a Gemini note; all 8 malicious ones were already flagged; for the one legit (saraswatbank.com) it raised 60 to 83 (flagged before and after). No outcome changed. |
| Live threat store, Web Risk etc. vs empty store | No flag change on any domain: the dataset is synthetic, so no feed can know these names. This run **cannot measure** the value of the threat feeds. |
| Documents | Identical in both runs (no AI, no store). |

Honest summary: on this set the rule engines do nearly all the work; Gemini is a rare, roughly zero-sum tie-breaker.

Rules-only domains (B) had the same flag outcome as live (50/1/49/0), but 7/50 legit domains were rated MEDIUM or above
versus 2/50 live; the live path's extra context (threat store, ranking and other live signals; cause not verified) probably lowered warnings
on legit sites, so the live product looks somewhat quieter on genuine domains even where the HIGH/CRITICAL decision is unchanged.

## 4. Latency and operations

No 429s occurred at the stated pacing, no failed calls in either run (0/240). Live domain checks are slow-ish (p95 2.5 s)
because they do DNS/TLS/RDAP/Tranco lookups on each call; text checks are fast unless Gemini is consulted.

## 5. Error analysis (live run; every error)

"Local" notes where the rules-only run differs. Root causes are plain-language guesses from response flags, not code-verified.

### Missed scams (7; expected scam, got below HIGH)

| ID | Input (abridged) | Actual | Guess at root cause |
| --- | --- | --- | --- |
| M-S22 | Part-time job: "ghar baithe roz Rs5000 ... Google Maps 5 star rating", mixed Hindi/Latin | MEDIUM 45 (Gemini consulted, not applied) | Mixed-script wording dilutes keyword matches; task-fraud lexicon lacks "star rating"/"Maps"; lands just under 60. |
| M-S46 | "Papa main Rohan, accident ho gaya ... naye number se ... 40,000 GPay kar do, mummy ko mat batana" | LOW 23 | Relative-in-distress + new-number impersonation pattern isn't modelled; Hinglish payment ask "GPay kar do" not recognised as a demand. |
| M-S47 | "Hi mom, new number, stuck in police station, Rs 30,000 urgently ... do not call dad" | LOW 33 (Gemini consulted, not applied) | Same family-emergency gap; "police station" triggered the police-impersonation flag but there is no payment-demand trigger for the account-number ask. |
| M-S50 | Romance: "UK se aa raha hu ... airport par rok liya ... 60,000 bhej do" | SAFE 8 | Zero cue words; no romance/advance-fee-to-release pattern. Worst miss: rated SAFE. |
| M-S51 | OLX "army officer ... send Rs 2,000 advance for token/packing" | LOW 25 | Only "courier" and "payment" fired; the army-officer / advance-token marketplace pretext isn't a scored pattern. |
| M-S55 | "Amazon work-from-home selection ... laptop security deposit Rs 7,500 UPI se bhejiye" (mixed script) | LOW 18 | Only the generic payment-demand fired; no job-offer cue in mixed-script wording; refundable-deposit pretext not weighted. |
| M-S60 | Hindi: "आयकर विभाग: 18,600 रुपये का रिफंड स्वीकृत ... लिंक पर बैंक खाता और डेबिट कार्ड विवरण भरें" | LOW 38 (Gemini consulted, not applied) | Hindi tax-refund + card-detail request scored only on generic refund/link flags; no link domain to check. Local run also missed S22, S46, S47, S50, S51, S54, S55, S60 (S54 is the one Gemini rescued). |

### False alarms on genuine messages (8)

| ID | Input (abridged) | Actual | Guess at root cause |
| --- | --- | --- | --- |
| M-G01 | HDFC debit alert with "Call 1800 202 6161 or SMS BLOCK UPI to 7308080808" | HIGH 72 | **Introduced by Gemini** (rules alone: MEDIUM 56). The legitimate "block" instruction and a phone number look like a threat plus a callback ask. Local run did not flag it. |
| M-G23 | HR payslip notice mentioning `hr@company-example.in` | CRITICAL 88 | **My dataset defect**: invented domain does not exist, NXDOMAIN rule fired. Not an engine fault. |
| M-G27 | Ola: "Share OTP 5632 with the driver to start the ride" | CRITICAL 88 | "Share OTP" phrase matched as an OTP-harvesting ask with no context awareness (ride-start OTP is legitimate). Also hits genuine delivery-agent OTPs, though M-G25 passed. |
| M-G52 | PM Kisan instalment released, pmkisan.gov.in, "kisi se OTP share na kare" | CRITICAL 97 | Three compounding errors: the "do not share OTP" warning parsed as asking for OTP; server-side TLS check of the real gov.in site reported an unverifiable chain (incomplete chains are common on Indian govt sites) and was treated as dangerous; link present. |
| M-G54 | Official echallan.parivahan.gov.in challan notice | CRITICAL 86 | Wording-only: "e-challan" theme + deadline + penalty language scored like the scam variant; the genuine .gov.in destination is not used to cancel it. |
| M-G55 | Bank of India loan sanctioned, "Congratulations", "no fee is charged", helpline | HIGH 74 | Loan-offer/reward-bait lexicon fires on "Congratulations ... loan sanctioned"; the negation ("no fee") is not understood. |
| M-G57 | Infosys interview invite with careers.infosys.com | HIGH 75 | Domain engine penalised a subdomain of a top-22k site (age "unverified", low TTL) despite an OV certificate for Infosys Limited. |
| M-G59 | Mutual-fund SIP debit, camsonline.com | HIGH 75 | Same mechanism: real CAMS domain (OV cert, Tranco-ranked) pushed to HIGH by missing-RDAP and low-TTL penalties. |

Rules-only run additionally lacked M-G01 and had 7 FPs; otherwise identical errors.

### Domain false alarm (1)

| ID | Input | Actual | Root cause guess |
| --- | --- | --- | --- |
| D-L10 | `https://www.saraswatbank.com` (genuine co-operative bank) | CRITICAL 83 (rules-only: HIGH 60) | Not on an allowlist; the server saw a TLS name mismatch (`ERR_TLS_CERT_ALTNAME_INVALID`) and unknown domain age; Gemini then raised it 60 to 83, calling it "impersonation of a legitimate bank" (it *is* the bank). Co-operative/small banks outside the allowlist are the weak class; the other 4 small-finance/co-op/PSU banks I tried passed. |

### Missed forged documents (5)

| ID | Input (abridged) | Actual | Root cause guess |
| --- | --- | --- | --- |
| X-F02 | "ENFORCEMENT DIRECTORATE ... transfer Rs 75,000 verification charges ... arrest" | MEDIUM 55 NEEDS_REVIEW | Coercion scored only "weak"; agency + payment + secrecy still did not reach 60. |
| X-F04 | "RESERVE BANK OF INDIA - unclaimed deposit ... pay Rs 18,500 processing fee ... do not share with bank manager" | LOW 12 "Genuine-looking" | RBI not recognised as an issuing agency and no coercion words, so an advance-fee demand alone scores nothing. Rated *genuine-looking*: worst document miss. |
| X-F05 | "RBI Compliance ... FEMA violation, pay penalty Rs 60,000 ... send OTP" | MEDIUM 55 | Same agency blind spot for RBI; fee + OTP demand only weakly weighted. |
| X-F07 | Instant-loan agreement: 7-day tenure, upfront fees, contact/photo access, "share with all contacts" | MEDIUM 55 | Only the contact-access rule fired; upfront-fee and 7-day rules did not match this wording ("deducted upfront", "net disbursal"). The sibling X-F08 was caught. |
| X-F10 | "INCOME TAX DEPARTMENT - SEIZURE NOTICE ... Rs 1,20,000 advance penalty ... prosecution and arrest ... confidential" | LOW 12 "Genuine-looking" | Agency only "mentioned", coercion words ("prosecution", "arrest", "seizure") not matched, so payment+secrecy alone scored 12. |

Additionally, no scam in the three sets was rated MEDIUM and left unflagged other than M-S22 (45) and the documents above (55).

## 6. Limitations (read before citing)

- **Small sample.** 60+60, 50+50, 10+10. CIs are wide (messages recall 78-94%, documents recall 24-76%). Differences of 1-3 cases between runs are noise.
- **Synthetic wording and author bias.** I (an LLM) wrote the scams from textbook knowledge. They are cleaner and more "typical" than real SMS/WhatsApp fraud, which is shorter, messier and constantly adapting. Real recall is plausibly lower. My genuine messages are also tidier than real bank SMS.
- **Same-author blind spots.** I wrote both sides and chose which look-alikes are "tricky"; I may have under-tested exactly the things I did not think of.
- **Domains are not zero-day-realistic.** Malicious names are unregistered (NXDOMAIN), 42% of detections rode on that signal (section 2). Raw-IP cases used documentation/reserved ranges for three samples (classified as "internal/non-public host"). The registered-and-resolving brand-free fresh domain, the hardest real case, is **not tested**.
- **Legit-domain checks depend on the server's view of the internet** (TLS chain, RDAP, DNS TTL) which varies by day and vantage point; the same site can flip.
- **No real traffic.** No class prior: 50/50 positive/negative here, whereas in production genuine messages vastly outnumber scams, so real precision would be **much lower** than shown at the same FPR. A 13% false-alarm rate on genuine messages would swamp true alerts at realistic base rates.
- **Rule-engine origin.** The engines were designed and tuned on a benchmark by the same team; the held-out result (about 88% recall, about 12% FPR on messages) is a better guide than the benchmark, but the engines' lexicons and my wording still share a common Indian-fraud vocabulary.
- **Local vs live differ in more than Gemini**: threat store empty locally, live DNS/RDAP timing differs, so the ablation attributes the 2 flag changes to Gemini based on the engine-string label in the response, not on a controlled switch.
- **Documents:** pasted-text mode only (no seal, signature, OCR or image forensics); results say nothing about the image/PDF path.
- Single run per configuration, single day; LLM output is non-deterministic, so repeat runs may shift a few mid-band cases.

## 7. What we will do next

1. Add a **second, larger, adversarially collected set** (target 500+) from real reported messages (user-submitted with consent, I4C/CERT-In/RBI advisory examples), with a rule that nobody who tunes may see it, and re-run this suite per release as a regression gate on FPR as well as recall.
2. **Register a handful of sinkholed canary domains** (fresh, resolving, brand-free, benign content) to measure the real zero-day behaviour; report the NXDOMAIN-independent domain result separately.
3. **Fix the genuine-message false alarms** at the root, on new data rather than these cases (to preserve their value): OTP-to-driver/agent context, "do not share OTP" negation, official .gov.in destinations cancelling e-challan/PM-Kisan wording, "no fee is charged" negation, and the TLS-chain-incomplete-on-govt-site case.
4. **Soften domain penalties for large, org-validated, Tranco-ranked sites** (age unverified / low TTL) and add co-operative and small-finance bank domains (RBI bank list) to the allowlist.
5. **Close typology gaps** with the highest rupee loss: family-emergency/new-number, romance/advance-to-release, OLX/army-officer advance, refundable-deposit fake HR, mixed-script job scams. Add these to the benchmark only after re-collecting fresh held-out examples.
6. **Constrain Gemini**: do not let it escalate a case when the rules already identified a known-genuine template (bank debit/credit alert, standard "SMS BLOCK" text); log the Gemini verdict separately from the final score so its contribution can be measured; do the same for the domain path (saraswatbank.com escalation).
7. **Document checker**: add RBI/Income-tax/ED as issuing agencies, widen coercion vocabulary (arrest, prosecution, seizure), weight "advance fee + secrecy" alone, and give genuine documents a positive evidence score instead of a flat 12.
8. **Report base-rate-adjusted precision** (assume 1-5% scam prevalence) in the product's accuracy statement, and publish the CIs rather than point estimates.
9. Re-run with at least 3 repeats to quantify Gemini non-determinism.

## 8. Post-evaluation changes

Made after sections 1-7 were frozen; **no v1 numbers above were rewritten.** The held-out set (`tests/eval/*`) is now burned for tuning:
nothing in it was edited, and none of its cases were copied into rules or tests. Fixes target the failure *classes* below with
generic logic, and are protected by NEW paraphrased cases in `tests/fixtures/benchmark2.json` and `tests/accuracyFixes2.test.js`.
A re-run on this set is no longer a fair generalisation estimate; use a fresh set. The 119-case benchmark gates and the whole
suite stay green (1024 tests at the time of writing).

| Class | What changed (files) |
| --- | --- |
| A. Message misses (loss of funds) | New intent signals in `lib/textEngine.js`: money-ask detection incl. transliterated Hindi verbs (bhejo, daalo, kar do, jama karo, ...) and passive "to be paid"; new `advance_fee` category (fee/deposit for a job, buyer/seller advance-token-packing, romance or "stranded" story ending in money, unsolicited gift + customs fee) and `refund_phish` (refund + card/bank details, or refund + click-to-verify); family-emergency now fires on a "new number" opener, colleague/boss/neighbour senders and "do not call dad"-style secrecy; star-rating task bait. Mixed script: Cyrillic/Greek lookalikes folded to Latin only inside Latin-bearing tokens, Devanagari digits folded to ASCII. `lib/textAi.js`: Gemini window widened to LOW scores (>= 12) when the message carries a concrete ask; the "scam opinion alone cannot escalate a routine alert" safeguard is unchanged. |
| B. Message false alarms | OTP given to a driver / agent / technician in person is exempt unless a caller, chat or unverified link channel or a refund/verification pretext is present; "share na kare" style Romanised warnings no longer read as OTP asks; a message whose every link is a verified official domain and that has no OTP/number/UPI/install/secrecy ask is returned as a notice (not a scam); promotional wording ("Congratulations", "loan sanctioned") with an explicit no-fee/branch-visit assurance and no ask is returned LOW; standard "SMS BLOCK ... to <shortcode>" is neither a threat nor a callback number; `apk` no longer matches inside "aapka"; "send ... on WhatsApp" needs a threat to count as sextortion; a Gemini "scam" opinion cannot escalate a recognised bank transaction-alert template. |
| C. Domain false alarms | `lib/domainEngine.js`: (1) strict-sovereign (.gov.in / .nic.in) names with an incomplete TLS chain (UNABLE_TO_VERIFY_LEAF_SIGNATURE etc.) stay verified with a caution flag when DNS confirms the name (expired certs, hostname mismatch and NXDOMAIN are unchanged); (2) an OV/EV certificate whose organisation matches the domain label (first significant word or initials), on a resolving host with no other negative signal, is no longer penalised for missing RDAP age or low TTL and is treated as trusted by the message path (`orgValidatedEstablished`); (3) Gemini escalation on such a site is capped at MEDIUM. `data/allowlist.json`: +40 entries (cooperative / regional / small-finance banks, RTAs, large Indian corporates), each with owner + category. |
| D. Document triage | `lib/docTriage.js`: more issuing authorities (RBI, Income-tax, SEBI, Finance Ministry, FIU, NIA, GST, courts); wider threat vocabulary (prosecution, seizure/attachment, defrozen, FEMA violation, "to avoid arrest"); generic fee/penalty/clearance demand detector; "OTP / screenshot / pay the officer's or clearance account" and secrecy detectors; authority + demand + (secrecy | OTP/officer account | deadline | strong threat) is LIKELY_FORGED. Predatory loans: "deducted upfront", "share defaulter details with contacts", per-day charges. Scores are graded: forged 90-99, review 48-58, and benign 4-30 from observable evidence (reference numbers, statutory citations, official domain/helpline, signature or system-generated block, grievance route) minus mild signals (urgency, payment instruction, WhatsApp/personal e-mail). |

Developer-only sanity replay of the burned set after the changes (rules only, offline world; **not** a generalisation number):
messages 60/60 scams flagged, genuine 59/60 clear (the remaining one is the invented `company-example.in` NXDOMAIN case noted in
section 2), documents 10/10 forged flagged and 10/10 genuine kept LOW. Open items: live-network behaviour of the TLS-chain and
org-match rules is covered by mocks only; the fresh set should be run on the live service.
