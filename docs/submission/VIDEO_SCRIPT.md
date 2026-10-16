# SafeMeAI demo video script (target 2:45, hard limit 3:00)

All demo inputs below were re-run against https://safemeai.in on 16 Oct 2026 and the verdicts recorded here are the ones actually returned. Live results can vary slightly (Gemini wording, latency). Re-verify the morning you record (see "Pre-flight").

## Pre-flight (5 minutes before recording)

1. Open https://safemeai.in in a clean browser profile, light theme, English. Hard refresh.
2. Run each paste once off-camera to warm the instance (first call after idle can take a few seconds: Cloud Run scale-to-zero). Rate limits: 20 burst / 30 per minute for checks, 10 for Gemini, 6 for documents. Do not rehearse more than that in a minute before recording.
3. Have the file `docs/submission/demo/forged_notice.png` ready on the desktop (a rendered image of a fake CBI warrant with the words "SAMPLE FOR DEMONSTRATION"; recreate it from the text under "Scene 5" if lost).
4. Have the architecture slide (slide 5) and the evaluation slide (slide 10) of `SafeMeAI_Deck.pdf` open in a second tab or in a presenter view.

## Shot list

| Time | On screen | Exact action | Narration (read as written) |
|---|---|---|---|
| 0:00-0:12 | Black title, then a phone-sized browser window (390x844) with a WhatsApp-style mock of the text below (or just the paste box) | Show the link text `https://parivahan-challan.gov.in` as a "challan notice" message. Cut to the SafeMeAI site. | "Meet Asha. She just got an SMS: pay your traffic challan at a dot gov dot in link, or your licence is blocked. It looks official. She has seconds to decide. This is SafeMeAI." |
| 0:12-0:40 | Tab "Website check" | Paste `https://parivahan-challan.gov.in`, click "Check this website". Wait for the red card. Point cursor at the warning line and the 99% ring. | "SafeMeAI does not just look for known bad lists. It asks: does this name even exist? This address claims the official dot gov dot in namespace, but it does not exist in DNS. Real government sites are always registered. Verdict: forged official domain, critical, 99 percent risk. Gemini adds a plain-language explanation." |
| 0:40-1:00 | Tab "Check a message or link" | Paste the Hinglish message (below), click "Check now". | "Scams do not come in neat English. This Hinglish KYC message has a lookalike link and asks for an OTP. SafeMeAI flags the coercive KYC pattern and the fake SBI domain: critical, 99." |
| 1:00-1:22 | Tab "Fake police call? Panic check" | Tap Yes on Q1: headline "Warning: real agencies do not threaten you on WhatsApp or Skype". Tap Yes on Q2: "Very likely a digital-arrest scam". Tap Yes on Q3 and Q4: "Confirmed: this is a digital-arrest extortion scam", warning level Maximum, big "Call 1930" button. | "Digital arrest is the scam that terrifies people most. These six taps are deterministic, no AI, and graded: one sign is a warning, two is very likely, three or more is confirmed, with clear steps and a one-tap call to 1930." |
| 1:22-1:42 | Tab "Notice or document check" | Click the upload box, choose `forged_notice.png`, click "Check file". Result: Likely forged, scam risk 96/100, looks genuine 4/100. Scroll slightly to show the italic line "Text extracted by Google Document AI OCR... No seal, signature or image forensics were run." | "A photo of a so-called CBI warrant. Google Document AI reads the text, then our triage looks for the pattern: an agency name, an arrest threat, a payment into a safe account, and secrecy. Likely forged, 96 out of 100. We are open about the limit: this is wording analysis, not seal forensics." |
| 1:42-2:05 | Tab "Ask the AI advisor", switch language to Hindi (button "हिन्दी" top right) | Paste the Hindi question (below), click Ask. Wait up to 8 s for the answer. Show risk level, signals, recommended actions. | "Now Asha's father asks in Hindi. Gemini on Vertex AI, in the Mumbai region, answers in Hindi: critical risk, the warning signs, and what to do: hang up, never send money, call 1930. Before the question reaches Gemini, phone numbers, Aadhaar, cards and OTP-like codes are redacted, and it can never mark an unverified site as safe." |
| 2:05-2:20 | Deck slide 5 (architecture) | Show diagram. Slow pan, no clicking. | "Architecture in fifteen seconds. Firebase Hosting in front of Cloud Run in Mumbai. Gemini on Vertex AI, Document AI, Web Risk and Google DNS for evidence. Firestore holds a threat store fed by Cloud Scheduler from open feeds and RBI and SEBI lists. Every check is hash-audited into BigQuery." |
| 2:20-2:35 | Deck slide 10 (evaluation) | Show headline table; highlight "82.9%", "10.0%", "33.3%". | "We tested honestly on 253 fresh, blind items. Messages: 83 percent recall, 10 percent false alarms. Domains are strong. Forged notices are weak, one in three, and we say so. Gemini added three true positives and removed one false alarm. All data is in the repo." |
| 2:35-2:45 | Live site home, then end card with the links | Show https://safemeai.in and the repo URL. | "SafeMeAI: a plain answer, in her language, before she pays. Try it at safemeai dot in. Code on GitHub." |

## Exact text to paste

**Scene 2, domain (verified: CRITICAL 99, verdict FORGED OFFICIAL DOMAIN, "does not exist"):**

```
https://parivahan-challan.gov.in
```

**Scene 3, Hinglish message (verified: CRITICAL 99, "Coercive KYC / Account or SIM Deactivation Scam", flags: link, OTP ask, impersonation of sbi.co.in):**

```
Sir aapka SBI account aaj raat band ho jayega. KYC update turant karo warna account block. Link: http://sbi-kyc-update.in/login aur OTP bata dijiye.
```

**Scene 4, panic check (verified live with the API behind the page):** Q1 Yes only = HIGH "Warning: real agencies do not threaten you on WhatsApp or Skype". Q1+Q2 Yes = CRITICAL "Very likely a digital-arrest scam". Q1-Q4 Yes (Q5, Q6 No) = CRITICAL "Confirmed: this is a digital-arrest extortion scam", warning level Maximum, "4/6 signs".

**Scene 5, notice photo:** upload an image containing this text (verified: Document AI OCR read it; LIKELY_FORGED, risk 96, authenticity 4, CRITICAL):

```
CENTRAL BUREAU OF INVESTIGATION
ARREST WARRANT AND FREEZE ORDER - SAMPLE FOR DEMONSTRATION
Notice No. CBI/CYB/2026/4471. Dear Sir/Madam, a case of money laundering has been registered against your Aadhaar and mobile number. An arrest warrant has been issued against you.
To avoid immediate arrest you must transfer Rs 4,85,000 to the RBI escrow safe account for verification of your savings. This is a confidential matter. Do not disclose this notice to your family or your bank. Remain on the video call until the verification is complete.
Failure to comply within 2 hours will result in arrest and freezing of all your bank accounts.
Issued by: Deputy Director, CBI Cyber Crime Division
```

**Scene 6, Hindi advisor (verified: model "gemini-2.5-flash (Vertex AI)", dataSource gemini-live, riskLevel CRITICAL, answer in Hindi with 4 signals and 4 actions incl. 1930):**

```
मुझे CBI अधिकारी का वीडियो कॉल आया है, कह रहे हैं मेरे आधार से ड्रग्स का पार्सल पकड़ा गया है और RBI के सेफ अकाउंट में पैसे भेजो। क्या करूं?
```

Contrast shot (optional, 3 s, for the "it does not cry wolf" point): paste `https://www.sbi.co.in` in Website check: verified live as VERIFIED OFFICIAL DOMAIN, score 0 (allow-listed and resolves in DNS).

## Fallbacks if something is slow or fails

| Problem | Fallback |
|---|---|
| Domain check takes more than 5 s | Keep talking over the spinner ("it is doing live DNS, certificate and threat-feed checks"); if over 10 s, cut and re-record; the result is stable once the instance is warm. |
| Gemini badge says "rules fallback" or the advisor errors | The product says so on screen: use it. Say "when Gemini is unavailable SafeMeAI says so and falls back to fixed rules, it never pretends". Retry once, or use a pre-recorded 10-second clip of a successful answer and label it "recorded earlier". |
| Document upload says OCR unavailable | Paste the notice text into the text box instead and click "Check this text"; narrate "same triage, text pasted". |
| HTTP 429 (rate limit) | Wait 60 s. Never loop retries on camera. |
| Site unreachable | Use the Cloud Run URL https://safemeai-bfsi-846801666760.asia-south1.run.app (same app). |
| Whole demo risky | Record scenes separately and edit; keep each take under 25 s. |

## Alternative 90-second cut

| Time | Content | Narration |
|---|---|---|
| 0:00-0:10 | Hook: fake .gov.in link on a phone | "A challan SMS, a dot gov dot in link. Is it real? SafeMeAI answers in seconds." |
| 0:10-0:30 | Website check of `https://parivahan-challan.gov.in` | "It claims to be government, but the name does not exist. Critical, 99." |
| 0:30-0:45 | Hinglish message | "Hinglish KYC scam: flagged critical, with the reasons." |
| 0:45-1:00 | Hindi advisor with Gemini | "Gemini advises in Hindi, with PII redacted first, and cannot mark an unverified site safe." |
| 1:00-1:15 | Slide 5 for 6 s, slide 10 for 9 s | "Cloud Run, Vertex AI, Document AI, Web Risk, Firestore, BigQuery. Honest evaluation: 83 percent recall on messages, 10 percent false alarms, weak on forged notices, and we publish it." |
| 1:15-1:30 | Home page and links | "safemeai dot in. Code on GitHub." |

## Recording checklist

- Resolution 1920x1080 (16:9) screen recording; browser window about 1366x768 for the laptop scenes; for the phone intro use Chrome DevTools device mode 390x844 or a real phone mirror.
- Light theme (already default), browser zoom 100%, hide bookmarks bar and extensions, one clean profile.
- Microphone: quiet room, headset or external mic, record narration in one take per scene, normalise audio, no background music over speech.
- No personal data on screen: no real phone numbers, Aadhaar, UPI IDs, e-mails, bank names tied to you; close notifications, hide other tabs, do not show Google Cloud console with project IDs or keys.
- Subtitles: burn in English subtitles from the narration column (also needed for the Hindi screens); keep font at least 36 px.
- Zoom or highlight (cursor ring) on the verdict, the 99% ring and the "does not exist" warning line.
- Total under 3:00 (aim 2:45); check the exported file duration. Upload as unlisted or public per the contest rule; put the link in the submission form.
- Say plainly in the first or last scene that figures in the analytics tab are the prototype's own test traffic (it is shown on the slide; do not imply real users).
