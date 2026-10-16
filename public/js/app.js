// ========================================================
// SafeMeAI — client. Plain-language UI, honest status, English / Hindi.
// ========================================================

// ---------- tiny helpers ----------
const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };
function esc(v) { return String(v == null ? '' : v).replace(/[&<>"'`]/g, c => ESC_MAP[c]); }
function safeHost(h) { return /^[a-z0-9.-]{1,253}$/i.test(String(h || '')) ? String(h) : ''; }
const $ = id => document.getElementById(id);
const show = (el, on) => { if (el) el.hidden = !on; };

// ---------- language (English / Hindi) ----------
// Keys are the English strings used in index.html (data-i18n) or in this file (t()). No external service.
const HI = {
  'Skip to main content': 'मुख्य सामग्री पर जाएँ',
  'Free scam checker for India (prototype)': 'भारत के लिए मुफ़्त स्कैम चेकर (प्रोटोटाइप)',
  'I am on a suspicious call right now': 'मैं अभी एक संदिग्ध कॉल पर हूँ',
  'Cyber Helpline:': 'साइबर हेल्पलाइन:',
  'Check a message or link': 'संदेश या लिंक जाँचें',
  'Main': 'मुख्य',
  'Fake police call? Panic check': 'फ़र्ज़ी पुलिस कॉल? तुरंत जाँच',
  'Website check': 'वेबसाइट जाँच',
  'Notice or document check': 'नोटिस या दस्तावेज़ जाँच',
  'Ask the AI advisor': 'AI सलाहकार से पूछें',
  'Report a scam': 'स्कैम की रिपोर्ट करें',
  'Scam trends': 'स्कैम के रुझान',
  'Demo': 'डेमो',
  'Free prototype. Not a government service.': 'मुफ़्त प्रोटोटाइप। यह सरकारी सेवा नहीं है।',
  'Got a strange message, link or call? Check it here first.': 'कोई अजीब संदेश, लिंक या कॉल आया? पहले यहाँ जाँचें।',
  'hero-sub': 'कोई संदेश, लिंक, UPI आईडी या फ़ोन नंबर पेस्ट करें। आपको सीधा जवाब मिलेगा: स्कैम, सही लगता है, या पक्का नहीं, और आगे क्या करना है। फ़र्ज़ी पुलिस "डिजिटल अरेस्ट" कॉल, UPI रिफंड जाल, लोन-ऐप की धमकी और नकली नौकरी के ऑफ़र के लिए।',
  'Demo figure': 'डेमो आँकड़ा',
  'Fraud loss prevented (example)': 'बचाई गई ठगी (उदाहरण)',
  'Protected devices (example)': 'सुरक्षित फ़ोन (उदाहरण)',
  'Fake-police calls caught (example)': 'पकड़ी गई फ़र्ज़ी पुलिस कॉल (उदाहरण)',
  'On-phone reaction time (target)': 'फ़ोन पर प्रतिक्रिया समय (लक्ष्य)',
  'kpi-note': 'ऊपर के चारों आँकड़े सिर्फ़ दिखाने के उदाहरण हैं। ये असली माप नहीं हैं।',
  'FREE SCAM CHECK': 'मुफ़्त स्कैम जाँच',
  'Paste a message, link, UPI ID or phone number': 'संदेश, लिंक, UPI आईडी या फ़ोन नंबर पेस्ट करें',
  'hero-sub-short': 'संदेश, लिंक, UPI आईडी या नंबर पेस्ट करें। सीधा जवाब पाएँ: स्कैम, ठीक लगता है, या पक्का नहीं।',
  'checker-lead': 'हम स्कैम वाली भाषा, नकली वेबसाइट और बुरे नंबर खोजते हैं। सिर्फ़ वेबसाइट का पता पेस्ट करने पर भी यहीं सीधा जवाब मिलेगा। विस्तृत वेबसाइट रिपोर्ट के लिए <a href="#tab-domain-checker" data-switch-tab="tab-domain-checker">वेबसाइट जाँच</a> खोलें।',
  'Try an example:': 'उदाहरण आज़माएँ:',
  'Fake police / CBI call': 'फ़र्ज़ी पुलिस / CBI कॉल',
  'UPI refund trap': 'UPI रिफंड जाल',
  'Electricity cut-off SMS': 'बिजली कटने का SMS',
  'Loan app trap': 'लोन-ऐप जाल',
  'Telegram job offer': 'टेलीग्राम नौकरी ऑफ़र',
  'Real bank SMS': 'असली बैंक SMS',
  '1. What do you want to check?': '1. आप क्या जाँचना चाहते हैं?',
  'Clear': 'साफ़ करें',
  'Paste the SMS, WhatsApp message, link, UPI ID (like name@okhdfcbank) or phone number here...': 'SMS, व्हाट्सऐप संदेश, लिंक, UPI आईडी (जैसे name@okhdfcbank) या फ़ोन नंबर यहाँ पेस्ट करें...',
  'Check now': 'अभी जाँचें',
  'privacy-tip': 'आप जो पेस्ट करते हैं वह जाँच के लिए भारत में SafeMeAI सर्वर पर भेजा जाता है और सहेजा नहीं जाता। OTP, PIN या पासवर्ड पेस्ट न करें। <a href="privacy.html">गोपनीयता सूचना</a>।',
  '2. Our answer': '2. हमारा जवाब',
  'Our answer': 'हमारा जवाब',
  'Ready': 'तैयार',
  'idle-answer': 'आपका जवाब यहाँ दिखेगा: स्कैम, सही लगता है या पक्का नहीं, साथ में क्या करना है।',
  'Checking... this can take a few seconds.': 'जाँच हो रही है... कुछ सेकंड लग सकते हैं।',
  'Try again': 'दोबारा कोशिश करें',
  'RISK': 'जोखिम',
  'What to do now': 'अभी क्या करें',
  'Warning signs we found': 'हमें मिले चेतावनी के संकेत',
  'Technical details (for experts)': 'तकनीकी जानकारी (विशेषज्ञों के लिए)',
  'sos-title': 'पुलिस, CBI, कस्टम या बैंक बनकर कोई कॉल पर है?',
  'sos-sub': 'आप गिरफ़्तार नहीं हैं। कोई एजेंसी व्हाट्सऐप या स्काइप पर गिरफ़्तारी नहीं करती। कॉल काटें, फिर 1930 पर फ़ोन करें।',
  'Call 1930 now': 'अभी 1930 पर कॉल करें',
  'PANIC CHECK': 'तुरंत जाँच',
  'Am I being scammed on this call?': 'क्या इस कॉल पर मुझे ठगा जा रहा है?',
  'panic-lead': 'इन 6 छोटे सवालों के जवाब दें। हाँ या नहीं दबाएँ। हर बार जवाब बदल जाएगा। यहाँ दबाया कुछ भी सहेजा नहीं जाता।',
  '1. Does the caller say they are police, CBI, customs, ED or a court?': '1. क्या कॉल करने वाला खुद को पुलिस, CBI, कस्टम, ED या कोर्ट का बताता है?',
  'They may sit in a fake office with uniforms, flags or wireless sets behind them.': 'वे नकली दफ़्तर में वर्दी, झंडे या वायरलेस सेट के साथ बैठे हो सकते हैं।',
  'Yes': 'हाँ',
  'No': 'नहीं',
  '2. Do they say a parcel, drugs or fake passports are linked to your Aadhaar or SIM?': '2. क्या वे कहते हैं कि कोई पार्सल, ड्रग्स या नकली पासपोर्ट आपके आधार या सिम से जुड़ा है?',
  'Often a FedEx or DHL courier story, or a money-laundering case in your name.': 'अक्सर FedEx या DHL कूरियर की कहानी, या आपके नाम पर मनी-लॉन्ड्रिंग का केस।',
  '3. Are they telling you not to hang up, or not to tell your family?': '3. क्या वे कह रहे हैं कि कॉल न काटें, या घरवालों को न बताएँ?',
  'They call it "digital surveillance" or "virtual custody".': 'वे इसे "डिजिटल निगरानी" या "वर्चुअल कस्टडी" कहते हैं।',
  '4. Are they asking you to send money to a "safe", "RBI" or "verification" account?': '4. क्या वे आपसे "सुरक्षित", "RBI" या "वेरिफ़िकेशन" खाते में पैसे भेजने को कह रहे हैं?',
  'They say your savings must be checked, or your accounts will be frozen.': 'वे कहते हैं कि आपकी बचत जाँची जाएगी, या खाते फ़्रीज़ हो जाएँगे।',
  '5. Are they asking you to share an OTP, Aadhaar, card or PIN details?': '5. क्या वे OTP, आधार, कार्ड या PIN की जानकारी माँग रहे हैं?',
  'No bank, police officer or government office ever needs your OTP or PIN.': 'कोई बैंक, पुलिस अधिकारी या सरकारी दफ़्तर आपका OTP या PIN कभी नहीं माँगता।',
  '6. Are they asking you to install an app, or move to Skype / WhatsApp video?': '6. क्या वे कोई ऐप इंस्टॉल करने या स्काइप / व्हाट्सऐप वीडियो पर आने को कह रहे हैं?',
  'Remote-control apps let them see your screen and empty your account.': 'रिमोट-कंट्रोल ऐप से वे आपकी स्क्रीन देखकर खाता खाली कर सकते हैं।',
  'Check my answers': 'मेरे जवाब जाँचें',
  'Answer the questions': 'सवालों के जवाब दें',
  'Your result will show here': 'आपका नतीजा यहाँ दिखेगा',
  'panic-idle': 'हर सवाल पर हाँ या नहीं दबाएँ। अगर एक भी जवाब हाँ है, तो कॉल जारी न रखें।',
  'Warning level': 'चेतावनी स्तर',
  'This is a simple score from your answers, not a chance of being right.': 'यह आपके जवाबों से बना एक सरल स्कोर है, सही होने की संभावना नहीं।',
  'Remember these rules': 'ये नियम याद रखें',
  'rule-1': '<strong>वीडियो कॉल पर गिरफ़्तारी नहीं:</strong> भारतीय क़ानून में स्काइप या व्हाट्सऐप पर गिरफ़्तारी या पूछताछ नहीं होती।',
  'rule-2': '<strong>कोई "RBI सुरक्षित खाता" नहीं:</strong> RBI और पुलिस "जाँच" के लिए नागरिकों से पैसे नहीं माँगते।',
  'rule-3': '<strong>आप कॉल काट सकते हैं:</strong> अनजान कॉल काटने पर कोई सज़ा नहीं दे सकता।',
  'Call 1930 (free)': '1930 पर कॉल करें (मुफ़्त)',
  'Report online: cybercrime.gov.in': 'ऑनलाइन रिपोर्ट: cybercrime.gov.in',
  'Answered': 'जवाब दिए',
  'of': 'में से',
  'WEBSITE CHECK': 'वेबसाइट जाँच',
  'Is this website real?': 'क्या यह वेबसाइट असली है?',
  'domain-lead': 'जब आपके पास सिर्फ़ एक वेबसाइट का पता हो (जैसे SMS में बैंक का लिंक) तब इसका उपयोग करें। यहाँ भी वही सीधा जवाब मिलता है, साथ में वैकल्पिक तकनीकी जानकारी। पूरा संदेश, UPI आईडी या फ़ोन नंबर है? <a href="#tab-scam-checker" data-switch-tab="tab-scam-checker">संदेश या लिंक जाँचें</a> खोलें।',
  'Website address': 'वेबसाइट का पता',
  'e.g. https://www.ujjivansfb.bank.in or sbi-kyc-update.xyz': 'जैसे https://www.ujjivansfb.bank.in या sbi-kyc-update.xyz',
  'Check this website': 'यह वेबसाइट जाँचें',
  'How we check': 'हम कैसे जाँचते हैं',
  'how-1': 'क्या साइट सच में मौजूद है, और क्या वह सरकारी या बैंक की आधिकारिक सूची में है?',
  'how-2': 'क्या नाम किसी जाने-माने बैंक या सरकारी साइट की थोड़ी बदली हुई नक़ल है?',
  'how-3': 'क्या वह स्कैम वाली वेबसाइटों की सार्वजनिक सूची में है, या Google Web Risk ने उसे चिह्नित किया है?',
  'how-4': 'क्या वह बिल्कुल नई है, या असली पता छुपाती है?',
  'how-note': 'किसी सूची में न होने का मतलब यह नहीं कि साइट सुरक्षित है। शक हो तो लिंक की जगह अपने बैंक का आधिकारिक ऐप खोलें।',
  'idle-domain': 'वेबसाइट का पता डालें या कोई उदाहरण दबाएँ, ताकि पता चले कि वह असली है या नहीं।',
  'NOTICE OR DOCUMENT CHECK': 'नोटिस या दस्तावेज़ जाँच',
  'Got a legal notice, warrant or loan paper?': 'कोई क़ानूनी नोटिस, वारंट या लोन का काग़ज़ मिला?',
  'doc-lead': 'नोटिस का टेक्स्ट पेस्ट करें या कोई नमूना चुनें। हम फ़र्ज़ी वारंट, "एस्क्रो" भुगतान की माँग और अवैध लोन शर्तों जैसी भाषा खोजते हैं।',
  'Document AI: not connected. Text triage mode (images and PDFs cannot be read).': 'Document AI: जुड़ा नहीं है। सिर्फ़ टेक्स्ट जाँच मोड (फ़ोटो और PDF नहीं पढ़े जा सकते)।',
  'Document AI: connected. Photos and PDFs are read with OCR.': 'Document AI: जुड़ा है। फ़ोटो और PDF OCR से पढ़े जाते हैं।',
  '1. Choose a sample or add your own': '1. नमूना चुनें या अपना जोड़ें',
  'Samples are made-up examples. Tapping one fills the box below. Press the button to check it.': 'नमूने बनावटी उदाहरण हैं। एक दबाने पर नीचे का बॉक्स भर जाता है। जाँचने के लिए बटन दबाएँ।',
  'Fake police warrant': 'फ़र्ज़ी पुलिस वारंट',
  'Fake CBI warrant with payment demand': 'पैसे की माँग वाला फ़र्ज़ी CBI वारंट',
  "Asks for ₹4.85 lakh into a fake 'RBI escrow' account.": "नकली 'RBI एस्क्रो' खाते में ₹4.85 लाख माँगता है।",
  'Loan-app trap': 'लोन-ऐप जाल',
  '7-day loan with huge upfront fee': 'भारी एडवांस फ़ीस वाला 7 दिन का लोन',
  'Takes a big fee first and demands your contacts and photos.': 'पहले बड़ी फ़ीस काटता है और आपके कॉन्टैक्ट व फ़ोटो माँगता है।',
  'Genuine letter': 'असली पत्र',
  'Normal bank sanction letter': 'सामान्य बैंक स्वीकृति पत्र',
  'Clear interest rate, RBI details and a key fact statement.': 'साफ़ ब्याज दर, RBI विवरण और मुख्य तथ्यों का विवरण।',
  'OR UPLOAD A FILE (TEXT ONLY WORKS FULLY)': 'या फ़ाइल अपलोड करें (पूरी तरह सिर्फ़ टेक्स्ट चलता है)',
  'Tap to choose a file or drop it here': 'फ़ाइल चुनने के लिए दबाएँ या यहाँ छोड़ें',
  'upload-note': 'TXT, PDF, PNG या JPG, अधिकतम 5 MB। Document AI जुड़ा न होने से फ़ोटो और PDF अभी पढ़े नहीं जा सकते; टेक्स्ट पेस्ट करें।',
  'Check file': 'फ़ाइल जाँचें',
  'OR PASTE THE NOTICE TEXT': 'या नोटिस का टेक्स्ट पेस्ट करें',
  'Paste the text of the notice here...': 'नोटिस का टेक्स्ट यहाँ पेस्ट करें...',
  'Check this text': 'यह टेक्स्ट जाँचें',
  '2. Result': '2. नतीजा',
  'Not checked yet': 'अभी जाँच नहीं हुई',
  'doc-idle': 'नमूना चुनें या टेक्स्ट पेस्ट करें, फिर जाँच बटन दबाएँ। बटन दबाने से पहले कुछ नहीं भेजा जाता।',
  'Looks genuine': 'असली लगता है',
  'Higher is better': 'ज़्यादा बेहतर है',
  'Scam risk': 'स्कैम का जोखिम',
  'What we found': 'हमें क्या मिला',
  'Text that was read': 'पढ़ा गया टेक्स्ट',
  'AI ADVISOR': 'AI सलाहकार',
  'Ask a question about a scam': 'स्कैम के बारे में सवाल पूछें',
  'advisor-lead': 'जो हुआ वह अपने शब्दों में बताएँ। सलाहकार उपलब्ध होने पर Google का Gemini AI इस्तेमाल करता है और जब तय नियमों से जवाब देता है तो बता देता है। उससे ग़लती हो सकती है, इसलिए पैसों के मामले में 1930 या अपने बैंक को कॉल करें। OTP, PIN या पासवर्ड न लिखें।',
  'Examples:': 'उदाहरण:',
  'advisor-welcome': 'नमस्ते! जो कॉल, संदेश या ऐप आपको परेशान कर रहा है उसके बारे में बताएँ। मैं जोखिम और आगे क्या करना है समझाऊँगा।',
  'Describe what happened...': 'बताएँ क्या हुआ...',
  'Ask': 'पूछें',
  'FOR BANKS AND ANALYSTS (DEMO)': 'बैंकों और विश्लेषकों के लिए (डेमो)',
  'Scam trends and money-mule networks': 'स्कैम के रुझान और मनी-म्यूल नेटवर्क',
  'bq-lead': 'बैंक की टीम स्कैम के रुझान कैसे देख सकती है, इसका नमूना डैशबोर्ड। <strong>यहाँ सभी संख्याएँ बनावटी डेमो डेटा हैं</strong>, जब तक सर्वर BigQuery से न जुड़ा हो (नीचे का नोट देखें)।',
  'Most common scam types (sample)': 'सबसे आम स्कैम के प्रकार (नमूना)',
  'Demo data': 'डेमो डेटा',
  'Example insight (demo data):': 'उदाहरण निष्कर्ष (डेमो डेटा):',
  'the sample shows fake-police calls and UPI refund traps as the biggest groups.': 'नमूने में फ़र्ज़ी पुलिस कॉल और UPI रिफंड जाल सबसे बड़े समूह हैं।',
  'Suspected mule-account groups (sample)': 'संदिग्ध म्यूल-खाता समूह (नमूना)',
  'COMMUNITY REPORTS': 'समुदाय की रिपोर्ट',
  'Report a scam number, UPI ID or link': 'स्कैम वाला नंबर, UPI आईडी या लिंक रिपोर्ट करें',
  'report-lead': 'रिपोर्ट बिना आपके नाम या फ़ोन नंबर के गिनी जाती है। जब कई अलग लोग एक ही नंबर, UPI आईडी या लिंक की रिपोर्ट करते हैं, तो वह समुदाय की चेतावनी बन सकता है। यहाँ की रिपोर्ट पुलिस शिकायत का विकल्प <strong>नहीं</strong> है: असली ठगी के लिए 1930 पर कॉल करें या cybercrime.gov.in पर जाएँ।',
  'Send a report': 'रिपोर्ट भेजें',
  'Type of scam *': 'स्कैम का प्रकार *',
  "Scammer's phone number, UPI ID or link *": 'ठग का फ़ोन नंबर, UPI आईडी या लिंक *',
  'What happened? (optional note, no personal details please)': 'क्या हुआ? (वैकल्पिक नोट, कृपया निजी जानकारी न लिखें)',
  'e.g. Caller in police uniform on WhatsApp video said my Aadhaar was found in a parcel...': 'जैसे: व्हाट्सऐप वीडियो पर पुलिस की वर्दी में एक व्यक्ति ने कहा कि मेरा आधार एक पार्सल में मिला...',
  'report-privacy': 'हम आपका नाम या फ़ोन नंबर नहीं माँगते। कृपया नोट में अपनी निजी जानकारी न लिखें।',
  'Send report': 'रिपोर्ट भेजें',
  'Recent community reports': 'हाल की समुदाय रिपोर्टें',
  'footer-tag': 'भारत के लिए मुफ़्त स्कैम चेकर। यह सिर्फ़ सलाह देता है और ग़लत हो सकता है। यह सरकारी या बैंक की सेवा नहीं है।',
  'How it works': 'यह कैसे काम करता है', 'Security': 'सुरक्षा', 'Contact': 'संपर्क', 'Privacy notice': 'गोपनीयता सूचना',
  'Terms of use': 'उपयोग की शर्तें',
  'Report fraud (official)': 'ठगी की रिपोर्ट (आधिकारिक)',
  'National Cyber Crime Helpline:': 'राष्ट्रीय साइबर क्राइम हेल्पलाइन:',
  'toll free': 'टोल फ़्री',
  'Built with': 'इनसे बना',
  '(used when available)': '(उपलब्ध होने पर)',
  '(when configured)': '(सेटअप होने पर)',
  '(demo only for now)': '(अभी सिर्फ़ डेमो)',
  'footer-disc': 'SafeMeAI सिर्फ़ सलाह देता है और ग़लत हो सकता है। अगर पैसे गँवा चुके हैं तो तुरंत 1930 पर कॉल करें या अपने बैंक और स्थानीय पुलिस से संपर्क करें।',

  // ----- dynamic strings -----
  'This looks like a scam. Do not act on it.': 'यह स्कैम लगता है। इस पर कुछ न करें।',
  'Risky. Do not trust this until you check it another way.': 'जोखिम भरा है। किसी और तरीक़े से जाँचे बिना भरोसा न करें।',
  'We could not confirm this is safe.': 'हम इसे सुरक्षित होने की पुष्टि नहीं कर सके।',
  'No scam signs found, but stay careful.': 'स्कैम के संकेत नहीं मिले, फिर भी सावधान रहें।',
  'This looks genuine.': 'यह असली लगता है।',
  'This is an official website.': 'यह एक आधिकारिक वेबसाइट है।',
  'This is not a bank or government site.': 'यह बैंक या सरकारी साइट नहीं है।',
  'This website does not exist.': 'यह वेबसाइट मौजूद ही नहीं है।',
  'This address cannot be checked online (not a public website).': 'यह पता ऑनलाइन जाँचा नहीं जा सकता (यह सार्वजनिक वेबसाइट नहीं है)।',
  'Fake copy of an official government or bank website.': 'सरकारी या बैंक की आधिकारिक वेबसाइट की नक़ल।',
  'Pretends to be a trusted brand. Do not open it.': 'किसी भरोसेमंद ब्रांड का रूप धरता है। इसे न खोलें।',
  'Known dangerous website. Do not open it.': 'जानी-पहचानी ख़तरनाक वेबसाइट। इसे न खोलें।',
  'The real destination of this link is hidden.': 'इस लिंक की असली मंज़िल छुपी है।',
  'This is a download link for an app installer file.': 'यह ऐप इंस्टॉलर फ़ाइल का डाउनलोड लिंक है।',
  'The address uses look-alike letters.': 'पते में मिलते-जुलते अक्षर इस्तेमाल हुए हैं।',
  'A short link hides where it goes.': 'छोटा लिंक असली मंज़िल छुपाता है।',
  'Warning from a financial regulator.': 'वित्तीय नियामक की चेतावनी।',
  'Not a verified site. Be careful with it.': 'यह जाँची हुई साइट नहीं है। सावधानी रखें।',
  'Looks like an ordinary website, not a bank.': 'सामान्य वेबसाइट लगती है, बैंक नहीं।',
  'The security certificate of this official site is broken.': 'इस आधिकारिक साइट का सुरक्षा प्रमाणपत्र ख़राब है।',
  'Could not check this': 'जाँच नहीं हो सकी',
  'Nothing was checked. Please try again. Do not assume it is safe.': 'कुछ भी जाँचा नहीं गया। दोबारा कोशिश करें। इसे सुरक्षित न मानें।',
  'Please paste something first': 'पहले कुछ पेस्ट करें',
  'Paste a message, link, UPI ID or phone number, then press Check now.': 'संदेश, लिंक, UPI आईडी या फ़ोन नंबर पेस्ट करें, फिर "अभी जाँचें" दबाएँ।',
  'Please enter a website address': 'कृपया वेबसाइट का पता डालें',
  'Type or paste a website address, then press Check this website.': 'वेबसाइट का पता लिखें या पेस्ट करें, फिर "यह वेबसाइट जाँचें" दबाएँ।',
  'Too many checks too quickly': 'बहुत जल्दी-जल्दी बहुत जाँचें हुईं',
  'Please wait': 'कृपया रुकें',
  'seconds and then press Try again.': 'सेकंड, फिर "दोबारा कोशिश करें" दबाएँ।',
  'a minute and then press Try again.': 'एक मिनट, फिर "दोबारा कोशिश करें" दबाएँ।',
  'Try again in': 'दोबारा कोशिश करें',
  'Network problem': 'नेटवर्क की समस्या',
  'Could not reach the server. Check your internet and try again. Do not assume the item is safe.': 'सर्वर तक नहीं पहुँच सके। इंटरनेट जाँचें और दोबारा कोशिश करें। इसे सुरक्षित न मानें।',
  'The check took too long. Please try again. Do not assume the item is safe.': 'जाँच में बहुत समय लगा। दोबारा कोशिश करें। इसे सुरक्षित न मानें।',
  'Service problem': 'सेवा की समस्या',
  'Something went wrong on our side. Please try again. Do not assume the item is safe.': 'हमारी तरफ़ कुछ गड़बड़ हुई। दोबारा कोशिश करें। इसे सुरक्षित न मानें।',
  'Detected: phone number': 'पहचाना: फ़ोन नंबर',
  'Detected: UPI ID': 'पहचाना: UPI आईडी',
  'Detected: website link': 'पहचाना: वेबसाइट लिंक',
  'Detected: message': 'पहचाना: संदेश',
  'Do not click links, call back, or send money.': 'लिंक न दबाएँ, वापस कॉल न करें, पैसे न भेजें।',
  'Do not enter passwords, OTP or UPI PIN anywhere because of this message.': 'इस संदेश के कारण कहीं भी पासवर्ड, OTP या UPI PIN न डालें।',
  'Block the sender and report it on 1930 or cybercrime.gov.in.': 'भेजने वाले को ब्लॉक करें और 1930 या cybercrime.gov.in पर रिपोर्ट करें।',
  'Check with the real organisation using the number on its official website or app.': 'असली संस्था से उसकी आधिकारिक वेबसाइट या ऐप के नंबर पर पूछें।',
  'Do not share OTP, PIN or passwords and do not install anything because of this.': 'इसके कारण OTP, PIN या पासवर्ड न बताएँ और कुछ इंस्टॉल न करें।',
  'Nothing alarming was found. Still, never share your OTP, PIN or password.': 'कुछ चिंताजनक नहीं मिला। फिर भी OTP, PIN या पासवर्ड कभी न बताएँ।',
  'If you already lost money, call 1930 right away. Banks can sometimes freeze the money if you act within the first hour.': 'अगर पैसे जा चुके हैं तो तुरंत 1930 पर कॉल करें। पहले घंटे में बताने पर बैंक कभी-कभी पैसे रोक सकते हैं।',
  'No warning signs were found by the automated checks. This is not proof that it is safe.': 'स्वचालित जाँच में चेतावनी के संकेत नहीं मिले। इसका मतलब यह नहीं कि यह सुरक्षित है।',
  'Official website:': 'आधिकारिक वेबसाइट:',
  'Official website': 'आधिकारिक वेबसाइट',
  'Lookalike of an official site': 'आधिकारिक साइट की नक़ल',
  'Official website (certificate problem)': 'आधिकारिक वेबसाइट (सर्टिफ़िकेट में दिक़्क़त)',
  'Lookalike address': 'मिलता-जुलता नकली पता',
  'Shortened link': 'छोटा किया गया लिंक',
  'App download link': 'ऐप डाउनलोड लिंक',
  'Website not found': 'वेबसाइट नहीं मिली',
  'Not a public website': 'सार्वजनिक वेबसाइट नहीं',
  'Known dangerous website': 'ज्ञात ख़तरनाक वेबसाइट',
  'Ordinary website': 'सामान्य वेबसाइट',
  'Unverified': 'पुष्टि नहीं हुई',
  'Flagged for freeze': 'फ़्रीज़ के लिए चिह्नित',
  'Under monitoring': 'निगरानी में',
  'Police team dispatched': 'पुलिस टीम भेजी गई',
  'Auto-throttled': 'अपने-आप धीमा किया गया',
  'Website:': 'वेबसाइट:',
  'Open the Message checker for this': 'इसके लिए संदेश जाँच खोलें',
  'This looks like a UPI ID or phone number, not a website. Checking it in the main checker instead.': 'यह UPI आईडी या फ़ोन नंबर लगता है, वेबसाइट नहीं। इसलिए मुख्य चेकर में जाँच रहे हैं।',
  'Warning: nothing selected': 'चेतावनी: कुछ नहीं चुना',
  'No warning signs selected': 'चेतावनी का कोई संकेत नहीं चुना',
  'Warning': 'चेतावनी',
  'Very likely a scam': 'बहुत संभव है स्कैम है',
  'Scam: confirmed pattern': 'स्कैम: पक्का पैटर्न',
  'Low': 'कम',
  'High': 'ज़्यादा',
  'Very high': 'बहुत ज़्यादा',
  'Maximum': 'अधिकतम',
  'signs': 'संकेत',
  'Could not run the check': 'जाँच नहीं हो सकी',
  'Hang up and call 1930 now if anyone asks for money or tells you to stay on a video call.': 'अगर कोई पैसे माँगे या वीडियो कॉल पर बने रहने को कहे, तो कॉल काटें और अभी 1930 पर फ़ोन करें।',
  'Likely fake or a scam': 'नक़ली या स्कैम होने की संभावना',
  'Likely an illegal lender': 'अवैध लेनदार होने की संभावना',
  'Could not read this file': 'यह फ़ाइल पढ़ी नहीं जा सकी',
  'High risk': 'ज़्यादा जोखिम',
  'Medium risk': 'मध्यम जोखिम',
  'Low risk': 'कम जोखिम',
  'Please paste text or choose a file first.': 'पहले टेक्स्ट पेस्ट करें या फ़ाइल चुनें।',
  'Nothing to check': 'जाँचने को कुछ नहीं',
  'File problem': 'फ़ाइल की समस्या',
  'This file is larger than 5 MB.': 'यह फ़ाइल 5 MB से बड़ी है।',
  'Only TXT, PDF, PNG or JPG files are accepted.': 'सिर्फ़ TXT, PDF, PNG या JPG फ़ाइलें मान्य हैं।',
  'We could not read this file. Paste the text of the notice into the box instead.': 'हम यह फ़ाइल नहीं पढ़ सके। इसकी जगह नोटिस का टेक्स्ट बॉक्स में पेस्ट करें।',
  'Sample': 'नमूना',
  'SAMPLE': 'नमूना',
  'Sample placeholder, not a real report': 'नमूना, असली रिपोर्ट नहीं',
  'Sample entries only. No community-confirmed reports yet.': 'सिर्फ़ नमूना प्रविष्टियाँ। अभी समुदाय से पुष्ट कोई रिपोर्ट नहीं।',
  'Confirmed by several people': 'कई लोगों द्वारा पुष्ट',
  'Could not load reports.': 'रिपोर्टें लोड नहीं हो सकीं।',
  'Report received. Thank you.': 'रिपोर्ट मिल गई। धन्यवाद।',
  'Could not send the report': 'रिपोर्ट नहीं भेजी जा सकी',
  'Analyzing...': 'जाँच हो रही है...',
  'Please wait...': 'कृपया रुकें...',
  'Gemini is answering...': 'जवाब तैयार हो रहा है...',
  'Answered by Gemini AI': 'Gemini AI का जवाब',
  'Answered by fixed rules (AI not used)': 'तय नियमों का जवाब (AI इस्तेमाल नहीं हुआ)',
  'Risk': 'जोखिम',
  'Key warning signs:': 'मुख्य चेतावनी संकेत:',
  'Recommended action:': 'सुझाई गई कार्रवाई:',
  'You': 'आप',
  'Demo data source note unavailable.': 'डेटा स्रोत नोट उपलब्ध नहीं।',
  'Accounts': 'खाते',
  'Cloud Run: live': 'Cloud Run: चालू',
  'demo': 'डेमो',
  'live': 'चालू',
  'not connected': 'जुड़ा नहीं',
  'unknown': 'अज्ञात',
  'checking': 'जाँच जारी',
  'Why we think so': 'हम ऐसा क्यों मानते हैं',
  'Category': 'श्रेणी',
  'Risk score': 'जोखिम स्कोर',
  'Other technical notes': 'अन्य तकनीकी टिप्पणी',

  // panic steps from the server
  'Do not share OTP, UPI PIN, CVV or passwords with anyone who calls you.': 'कॉल करने वाले किसी भी व्यक्ति को OTP, UPI PIN, CVV या पासवर्ड न बताएँ।',
  'If unsure, hang up and call the organisation back on its official number.': 'अगर शक हो तो कॉल काटें और संस्था को उसके आधिकारिक नंबर पर ख़ुद फ़ोन करें।',
  'Report anything suspicious on 1930 or cybercrime.gov.in.': 'कुछ भी संदिग्ध हो तो 1930 या cybercrime.gov.in पर रिपोर्ट करें।',
  'Do not send money, share OTPs or install any app while this call continues.': 'यह कॉल चलते हुए पैसे न भेजें, OTP न बताएँ और कोई ऐप इंस्टॉल न करें।',
  'Hang up and call the agency or your bank yourself on the number from its official website.': 'कॉल काटें और एजेंसी या अपने बैंक को उसकी आधिकारिक वेबसाइट के नंबर पर ख़ुद फ़ोन करें।',
  'Tell a family member or friend what is happening right now.': 'अभी किसी परिवार के सदस्य या दोस्त को बताएँ कि क्या हो रहा है।',
  'Report the number on 1930 or cybercrime.gov.in.': 'नंबर की रिपोर्ट 1930 या cybercrime.gov.in पर करें।',
  'Hang up the call or video call now. In India no one is "arrested" over WhatsApp or Skype.': 'अभी कॉल या वीडियो कॉल काट दें। भारत में व्हाट्सऐप या स्काइप पर किसी को "गिरफ़्तार" नहीं किया जाता।',
  'Do NOT transfer money or share any bank detail, even if they say it is refundable.': 'पैसे न भेजें और बैंक की कोई जानकारी न दें, भले ही वे कहें कि पैसे लौटा दिए जाएँगे।',
  'Tell a family member or friend immediately; scammers rely on isolating you.': 'तुरंत किसी परिवार के सदस्य या दोस्त को बताएँ; ठग आपको अकेला रखकर ही काम करते हैं।',
  'Dial 1930 and report the number and account on cybercrime.gov.in.': '1930 पर कॉल करें और नंबर व खाते की रिपोर्ट cybercrime.gov.in पर करें।',
  'HANG UP the call now. Indian law (BNSS) has no arrest or interrogation over Skype or WhatsApp.': 'अभी कॉल काट दें। भारतीय क़ानून (BNSS) में स्काइप या व्हाट्सऐप पर गिरफ़्तारी या पूछताछ नहीं है।',
  'DO NOT TRANSFER ANY MONEY. The RBI and the police never keep "escrow" or "verification" accounts for citizens.': 'कोई पैसा न भेजें। RBI और पुलिस नागरिकों के लिए कभी "एस्क्रो" या "वेरिफ़िकेशन" खाते नहीं रखते।',
  'TELL YOUR FAMILY OR A FRIEND RIGHT NOW. The scam loses its power the moment someone else knows.': 'अभी अपने परिवार या किसी दोस्त को बताएँ। किसी और को पता चलते ही स्कैम की ताक़त ख़त्म हो जाती है।',
  'DIAL 1930 immediately. If you already paid, call within the first hour: banks can freeze the money. Also report on cybercrime.gov.in.': 'तुरंत 1930 पर कॉल करें। अगर पैसे दे चुके हैं तो पहले घंटे में कॉल करें: बैंक पैसे रोक सकते हैं। cybercrime.gov.in पर भी रिपोर्ट करें।',
  'No scam signals selected': 'स्कैम का कोई संकेत नहीं चुना',
  'Nothing you selected matches the digital-arrest pattern. Stay careful: never share OTP, UPI PIN or passwords on a call, and if anything feels wrong dial 1930.': 'आपके चुने जवाबों में डिजिटल-अरेस्ट का पैटर्न नहीं मिला। फिर भी सावधान रहें: कॉल पर OTP, UPI PIN या पासवर्ड कभी न बताएँ, और कुछ भी ग़लत लगे तो 1930 पर कॉल करें।',
  'One warning sign is present. Do not continue the call or act on instructions until you verify independently.': 'एक चेतावनी का संकेत मिला है। कॉल जारी न रखें और अलग से जाँचे बिना किसी निर्देश पर अमल न करें।',
  'Very likely a digital-arrest scam': 'बहुत संभव है यह डिजिटल-अरेस्ट स्कैम है',
  'Two scam signs together match the standard digital-arrest script. You are not under arrest. Stop engaging.': 'दो संकेत मिलकर डिजिटल-अरेस्ट स्कैम की जानी-पहचानी स्क्रिप्ट से मेल खाते हैं। आप गिरफ़्तार नहीं हैं। बातचीत बंद करें।',
  'Confirmed: this is a digital-arrest extortion scam': 'पक्का: यह डिजिटल-अरेस्ट वसूली का स्कैम है',
  'You are in no legal danger from the police. You are facing an organised criminal extortion attempt.': 'पुलिस की तरफ़ से आपको कोई क़ानूनी ख़तरा नहीं है। यह संगठित अपराधियों की वसूली की कोशिश है।'
};

let LANG = 'en';
function t(en) { return (LANG === 'hi' && HI[en]) ? HI[en] : en; }
// Risk level code -> plain word. English keeps the code; Hindi never shows the raw English code.
const RISK_WORD_HI = { CRITICAL: 'अत्यंत ख़तरनाक', HIGH: 'ख़तरा', MEDIUM: 'सावधानी', LOW: 'कम ख़तरा', SAFE: 'सुरक्षित' };
function riskWord(level) {
  const code = String(level == null ? '' : level).toUpperCase();
  return (LANG === 'hi' && RISK_WORD_HI[code]) ? RISK_WORD_HI[code] : String(level == null ? '' : level);
}

function applyLang(lang) {
  const prevLang = LANG;
  LANG = lang === 'hi' ? 'hi' : 'en';
  document.documentElement.lang = LANG === 'hi' ? 'hi' : 'en';
  document.querySelectorAll('[data-i18n]').forEach(el => {
    if (el.dataset.en === undefined) el.dataset.en = el.innerHTML.trim();
    const key = el.dataset.i18n || el.dataset.en;
    el.innerHTML = (LANG === 'hi' && HI[key]) ? HI[key] : el.dataset.en;
  });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => {
    if (el.dataset.enPh === undefined) el.dataset.enPh = el.getAttribute('placeholder') || '';
    el.setAttribute('placeholder', (LANG === 'hi' && HI[el.dataset.i18nPh]) ? HI[el.dataset.i18nPh] : el.dataset.enPh);
  });
  document.querySelectorAll('.lang-btn').forEach(b => {
    const on = b.dataset.lang === LANG;
    b.classList.toggle('active', on);
    b.setAttribute('aria-pressed', on ? 'true' : 'false');
  });
  try { localStorage.setItem('safemeai_lang', LANG); } catch (_) { /* storage may be blocked */ }
  applyPills();
  rerenderAll();
  if (window.SafeTheme) window.SafeTheme.refresh();
  if (LANG !== prevLang) refetchForLang();
}

// Server text is translated per request, so after a switch re-run whatever result is on screen in the new language.
function refetchForLang() {
  try {
    if (lastScam && lastScam.text && !$('scam-result').hidden) runScamCheck(lastScam.text);
    if (lastDomain && lastDomain.input && !$('domain-result').hidden) runDomainCheck(lastDomain.input);
    if (lastPanic) evaluatePanicRisk();
    if (lastDoc && lastDocReq && !$('doc-result').hidden) renderDocument(lastDocReq.payload, lastDocReq.btn);
  } catch (_) { /* the old-language result simply stays */ }
}

// Advisor example chips: label and prompt are swapped for Hindi (the prompt is what gets sent, so Gemini receives Hindi).
const PILLS_HI = {
  'Skype call from "Mumbai Police" about an Aadhaar parcel': ['स्काइप पर "मुंबई पुलिस" का कॉल, आधार वाले पार्सल के बारे में', 'स्काइप पर कोई ख़ुद को मुंबई पुलिस का अधिकारी बता रहा है और कह रहा है कि मेरा आधार कंबोडिया जा रहे एक अवैध पार्सल में मिला है। मुझे क्या करना चाहिए?'],
  'UPI collect request for a "refund"': ['"रिफ़ंड" के नाम पर UPI कलेक्ट रिक्वेस्ट', 'मुझे PhonePe पर ₹4,999 की कलेक्ट रिक्वेस्ट आई है, लिखा है कि यह Flipkart का रिफ़ंड है। क्या पैसे पाने के लिए मुझे अपना UPI PIN डालना चाहिए?'],
  'Loan app threatening to send photos to contacts': ['लोन ऐप कॉन्टैक्ट्स को फ़ोटो भेजने की धमकी दे रहा है', 'एक इंस्टेंट लोन ऐप धमकी दे रहा है कि आज ₹15,000 नहीं चुकाए तो वह मेरी एडिट की हुई फ़ोटो मेरे कॉन्टैक्ट्स को भेज देगा। क्या वे ऐसा कर सकते हैं?'],
  'Telegram job: ₹3,000 a day for YouTube likes': ['टेलीग्राम जॉब: YouTube लाइक के ₹3,000 रोज़', 'टेलीग्राम पर किसी ने YouTube वीडियो लाइक करने के रोज़ ₹3,000 देने की बात कही, लेकिन पहले ₹1,000 का प्रीपेड डिपॉज़िट माँगा। क्या यह सुरक्षित है?']
};
function applyPills() {
  document.querySelectorAll('.gemini-pill').forEach(pill => {
    if (pill.dataset.enPrompt === undefined) {
      pill.dataset.enPrompt = pill.dataset.prompt || '';
      pill.dataset.enText = pill.textContent;
      const m = pill.textContent.trim().match(/^(\S+)\s+([\s\S]+)$/u);   // leading emoji + label
      pill.dataset.enIcon = m ? m[1] : '';
      pill.dataset.enLabel = m ? m[2].trim() : pill.textContent.trim();
    }
    const hi = LANG === 'hi' && PILLS_HI[pill.dataset.enLabel];
    pill.textContent = hi ? `${pill.dataset.enIcon} ${hi[0]}` : pill.dataset.enText;
    pill.dataset.prompt = hi ? hi[1] : pill.dataset.enPrompt;
  });
}

// ---------- fetch wrapper ----------
const FAIL_NOTE = 'Do not assume the item is safe.';
const reqSeq = {};
class ApiError extends Error { constructor(kind, status, retryAfter, serverMsg) { super(serverMsg || kind); this.kind = kind; this.status = status; this.retryAfter = retryAfter; this.serverMsg = serverMsg; } }

// Resolves null when superseded by a newer request of the same key. Throws ApiError otherwise.
async function api(key, url, { method = 'POST', json, form, timeoutMs = 20000 } = {}) {
  const seq = (reqSeq[key] = (reqSeq[key] || 0) + 1);
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    // The chosen language travels as the X-Lang header ('en' | 'hi') on every call; the server translates verdict text for 'hi'.
    const opts = { method, signal: ac.signal, headers: { 'X-Lang': LANG } };
    if (json !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(json); }
    if (form) opts.body = form;
    let resp;
    try { resp = await fetch(url, opts); }
    catch (e) { if (seq !== reqSeq[key]) return null; throw new ApiError(e.name === 'AbortError' ? 'timeout' : 'network'); }
    let data = null;
    try { data = await resp.json(); } catch (_) { /* non-JSON error page */ }
    if (seq !== reqSeq[key]) return null;
    if (resp.status === 429) {
      const ra = parseInt(resp.headers.get('Retry-After') || (data && data.retryAfter) || '', 10);
      throw new ApiError('rate', 429, Number.isFinite(ra) && ra > 0 ? ra : 60);
    }
    if (!resp.ok || !data || data.status !== 'success') {
      throw new ApiError(resp.status >= 500 || !resp.status ? 'server' : 'client', resp.status, null, data && data.error);
    }
    return data;
  } finally {
    clearTimeout(timer);
  }
}

function errorText(err) {
  if (err instanceof ApiError) {
    if (err.kind === 'rate') return { title: t('Too many checks too quickly'), msg: `${t('Please wait')} ${err.retryAfter} ${t('seconds and then press Try again.')}`, retryAfter: err.retryAfter };
    if (err.kind === 'network') return { title: t('Network problem'), msg: t('Could not reach the server. Check your internet and try again. Do not assume the item is safe.') };
    if (err.kind === 'timeout') return { title: t('Could not check this'), msg: t('The check took too long. Please try again. Do not assume the item is safe.') };
    if (err.kind === 'client' && err.serverMsg) return { title: t('Could not check this'), msg: err.serverMsg };
  }
  return { title: t('Service problem'), msg: t('Something went wrong on our side. Please try again. Do not assume the item is safe.') };
}

// Always restores the label the button had before it went busy.
function setBusy(btn, busy, label) {
  if (!btn) return;
  const span = btn.querySelector('span') || btn;
  btn.disabled = busy;
  btn.setAttribute('aria-busy', busy ? 'true' : 'false');
  if (busy) {
    if (btn.dataset.busyOrig === undefined) btn.dataset.busyOrig = span.innerHTML;
    if (label) span.textContent = t(label);
  } else if (btn.dataset.busyOrig !== undefined) {
    span.innerHTML = btn.dataset.busyOrig;
    delete btn.dataset.busyOrig;
    applyLangTo(span);
  }
}
function applyLangTo(el) {
  if (el.dataset && el.dataset.i18n && el.dataset.en !== undefined) {
    const key = el.dataset.i18n || el.dataset.en;
    el.innerHTML = (LANG === 'hi' && HI[key]) ? HI[key] : el.dataset.en;
  }
}

// ---------- plain-language text ----------
const PLAIN_WORDS = [
  [/\s*\(NXDOMAIN\)/g, ''],
  [/\bNXDOMAIN\b/g, 'does not exist'],
  [/\bFast-?Flux( DNS)?\b/gi, 'address that keeps changing'],
  [/\bDGA\b/g, 'random-looking name'],
  [/\bDomain Generation Algorithms?\b/gi, 'random-looking names'],
  [/\bShannon( lexical)? entropy\b/gi, 'name randomness'],
  [/\bRDAP\b/g, 'registration record'],
  [/\bX\.?509\b/g, 'security certificate'],
  [/\bTLS\b/g, 'HTTPS'],
  [/\bDoH\b/g, 'DNS lookup'],
  [/\bHCRV\b/g, 'our checker'],
  [/\bmule matrix\b/gi, 'money-trail analysis'],
  [/\bsinkhole[d]?\b/gi, 'blocked'],
  [/\btyposquatting\b/gi, 'look-alike spelling'],
  [/\bhomoglyph\b/gi, 'look-alike letters'],
  [/\bphishing\b/gi, 'fake-login scam'],
  [/\bIT Act Section 66D\b/g, 'IT Act section 66D (cheating by pretending to be someone)']
];
const VERDICT_PLAIN = {
  FAKE_OFFICIAL_NAMESPACE: 'Fake copy of an official government or bank website.',
  CONFIRMED_ZERO_DAY_PHISHING: 'Known dangerous website. Do not open it.',
  CONFIRMED_PHISHING_BRAND_IMPERSONATION: 'Pretends to be a trusted brand. Do not open it.',
  GOOGLE_WEB_RISK_FLAGGED: 'Known dangerous website. Do not open it.',
  DECEPTIVE_URL_STRUCTURE: 'The real destination of this link is hidden.',
  RAW_IP_PHISHING_HOST: 'This address cannot be checked online (not a public website).',
  MALICIOUS_APK_DOWNLOAD_VECTOR: 'This is a download link for an app installer file.',
  PHISHING_BRAND_AS_SUBDOMAIN: 'Pretends to be a trusted brand. Do not open it.',
  PHISHING_BRAND_IMPERSONATION: 'Pretends to be a trusted brand. Do not open it.',
  HOMOGLYPH_LOOKALIKE: 'The address uses look-alike letters.',
  TYPOSQUATTING_LOOKALIKE: 'Pretends to be a trusted brand. Do not open it.',
  OBFUSCATED_SHORT_URL: 'A short link hides where it goes.',
  NONEXISTENT_DOMAIN: 'This website does not exist.',
  OFFICIAL_NAMESPACE_BAD_TLS: 'The security certificate of this official site is broken.',
  OFFICIAL_NAMESPACE_UNCONFIRMED: 'We could not confirm this official-looking address.',
  HIGH_RISK_UNVERIFIED_DOMAIN: 'Risky. Do not trust this until you check it another way.',
  UNVERIFIED_THIRD_PARTY_DOMAIN: 'Not a verified site. Be careful with it.',
  UNVERIFIED_THIRD_PARTY_HOST: 'Not a verified site. Be careful with it.',
  INTERNAL_OR_NON_PUBLIC_HOST: 'This address cannot be checked online (not a public website).',
  THREAT_FEED_LISTED: 'Known dangerous website. Do not open it.',
  REGULATOR_WARNING_LISTED: 'Warning from a financial regulator.',
  DNS_SECURITY_BLOCKED: 'Known dangerous website. Do not open it.',
  ESTABLISHED_THIRD_PARTY_DOMAIN: 'Looks like an ordinary website, not a bank.',
  STANDARD_EXTERNAL_BENIGN_DOMAIN: 'Looks like an ordinary website, not a bank.',
  BENIGN_AUTHENTICATED_SOVEREIGN: 'This is an official website.',
  MALICIOUS_OR_SINKHOLED_HOST: 'Known dangerous website. Do not open it.'
};
function humanise(code) {
  const s = String(code || '').toLowerCase().replace(/_/g, ' ').trim();
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}
const CODE_RE = /\b[A-Z]{2,}(?:_[A-Z0-9]+)+\b/g;
// Clean a server string for ordinary readers: emoji prefixes, raw codes and jargon.
function plain(s) {
  let out = String(s == null ? '' : s)
    .replace(/^[\s -⯿️\u{1F000}-\u{1FFFF}]+/u, '')
    .replace(/[\u{1F000}-\u{1FFFF}️✅⚠ℹ\u{1F6D1}]/gu, '')
    .replace(CODE_RE, m => (VERDICT_PLAIN[m] ? t(VERDICT_PLAIN[m]) : humanise(m)));
  PLAIN_WORDS.forEach(([re, w]) => { out = out.replace(re, w); });
  return out.replace(/\s{2,}/g, ' ').trim();
}
function sentenceCase(s) {
  const x = String(s || '').trim();
  if (x && x === x.toUpperCase() && /[A-Z]{4,}/.test(x)) { const l = x.toLowerCase(); return l.charAt(0).toUpperCase() + l.slice(1); }
  return x;
}
// Internal operational state (feed offline, Gemini timeout...) is for the experts' panel only.
const OPS_RE = /(openphish|phishtank|feed\b.*\b(offline|stale|unavailable|down)|gemini|vertex|timed? ?out|rdap|web ?risk\b.*(not|unavailable|error)|rules fallback|engine error|lookup unavailable|not configured|threat[- ]?intel|dns (security|filter)|cloudflare|ocr unavailable)/i;
function splitFlags(flags) {
  const user = [], ops = [];
  (Array.isArray(flags) ? flags : []).forEach(f => { (OPS_RE.test(String(f)) ? ops : user).push(String(f)); });
  return { user, ops };
}
function splitSentences(text) {
  return plain(text).split(/(?<=[.!?।])\s+(?=[A-Z0-9\u0900-\u097F])/).map(s => s.trim()).filter(Boolean).slice(0, 6);
}

// ---------- verdict classification ----------
function classifyVerdict(res, { requireVerified }) {
  const score = Number(res.riskScore);
  const level = String(res.riskLevel || '').toUpperCase();
  if (score >= 80) return { ring: 'critical', badge: 'badge-critical', icon: '🚨', text: 'DANGER', tier: 'critical' };
  if (score >= 40) return { ring: 'high', badge: 'badge-danger', icon: '⚠️', text: 'RISKY', tier: 'high' };
  const green = requireVerified ? res.verified === true : (/^(SAFE|LOW|VERIFIED)$/.test(level) && res.verified !== false);
  if (green) return { ring: 'safe', badge: 'badge-safe', icon: '✅', text: res.verified === true ? 'VERIFIED' : 'LOOKS OK', tier: res.verified === true ? 'verified' : 'ok' };
  return { ring: 'unverified', badge: 'badge-unverified', icon: '❓', text: 'NOT SURE', tier: 'unsure' };
}
const BADGE_HI = { DANGER: 'ख़तरा', RISKY: 'जोखिम', VERIFIED: 'सत्यापित', 'LOOKS OK': 'ठीक लगता है', 'NOT SURE': 'पक्का नहीं' };
function tierTitle(tier) {
  return t({
    critical: 'This looks like a scam. Do not act on it.',
    high: 'Risky. Do not trust this until you check it another way.',
    verified: 'This looks genuine.',
    ok: 'No scam signs found, but stay careful.',
    unsure: 'We could not confirm this is safe.'
  }[tier]);
}

// ---------- card state machine (idle | loading | error | result) ----------
function setCardState(p, state) {
  ['idle', 'loading', 'error', 'result'].forEach(s => show($(`${p}-${s}`), s === state));
  const card = $(`${p}-card`);
  if (card) card.dataset.state = state;
  if (state !== 'result') {
    const badge = $(`${p}-badge`);
    if (badge) {
      badge.className = 'status-badge';
      badge.textContent = state === 'loading' ? t('Analyzing...') : (state === 'error' ? t('Could not check this') : t('Ready'));
    }
  }
}
let retryTimers = {};
function showCardError(p, err, retryFn) {
  const e = errorText(err);
  $(`${p}-error-title`).textContent = e.title;
  $(`${p}-error-msg`).textContent = e.msg;
  setCardState(p, 'error');
  const btn = $(`${p}-retry`);
  if (!btn) return;
  btn.onclick = retryFn;
  clearInterval(retryTimers[p]);
  btn.disabled = false;
  btn.textContent = t('Try again');
  if (e.retryAfter) {
    let left = e.retryAfter;
    btn.disabled = true;
    const tick = () => {
      if (left <= 0) { clearInterval(retryTimers[p]); btn.disabled = false; btn.textContent = t('Try again'); return; }
      btn.textContent = `${t('Try again in')} ${left}s`;
      left -= 1;
    };
    tick();
    retryTimers[p] = setInterval(tick, 1000);
  }
}
function showCardNotice(p, title, msg) {
  $(`${p}-error-title`).textContent = title;
  $(`${p}-error-msg`).textContent = msg;
  const btn = $(`${p}-retry`);
  if (btn) btn.hidden = true;
  setCardState(p, 'error');
}
function ensureRetryVisible(p) { const b = $(`${p}-retry`); if (b) b.hidden = false; }

// ---------- navigation ----------
const HOME_TAB = 'tab-scam-checker';
window.switchTab = function (targetId, { scroll = true } = {}) {
  document.querySelectorAll('.nav-tab').forEach(tb => {
    const on = tb.dataset.tab === targetId;
    tb.classList.toggle('active', on);
    tb.setAttribute('aria-current', on ? 'page' : 'false');
  });
  document.querySelectorAll('.tab-content-panel').forEach(p => p.classList.toggle('active', p.id === targetId));
  const activeTab = document.querySelector(`.nav-tab[data-tab="${targetId}"]`);
  const nav = $('main-navigation');
  if (activeTab && nav && nav.scrollWidth > nav.clientWidth) {
    nav.scrollTo({ left: activeTab.offsetLeft - (nav.clientWidth - activeTab.offsetWidth) / 2, behavior: 'smooth' });
  }
  const panel = $(targetId);
  const wasHome = document.body.classList.contains('is-home');
  const isHome = targetId === HOME_TAB;
  document.body.classList.toggle('is-home', isHome);
  if (scroll && panel) {
    requestAnimationFrame(() => {
      const navH = (document.querySelector('.nav-wrap') || { offsetHeight: 0 }).offsetHeight;
      // Home: show hero from the top when arriving from another tab; otherwise put the panel just under the sticky tab bar.
      const y = (isHome && !wasHome) ? 0 : Math.max(0, panel.getBoundingClientRect().top + window.scrollY - navH - 8);
      window.scrollTo({ top: y, behavior: 'auto' });
    });
  }
  try { history.replaceState(null, '', '#' + targetId); } catch (_) { /* ignore */ }
};

function initNavigation() {
  document.querySelectorAll('.nav-tab').forEach(tab => tab.addEventListener('click', () => window.switchTab(tab.dataset.tab)));
  // CSP forbids inline handlers: links use data-switch-tab. Delegated so translated HTML links also work.
  document.addEventListener('click', e => {
    const a = e.target.closest('[data-switch-tab]');
    if (!a) return;
    e.preventDefault();
    window.switchTab(a.dataset.switchTab);
  });
  const nav = $('main-navigation');
  const wrap = nav && nav.parentElement;
  const updateFade = () => {
    if (!nav || !wrap) return;
    wrap.classList.toggle('can-scroll-left', nav.scrollLeft > 4);
    wrap.classList.toggle('can-scroll-right', nav.scrollLeft + nav.clientWidth < nav.scrollWidth - 4);
  };
  if (nav) { nav.addEventListener('scroll', updateFade, { passive: true }); window.addEventListener('resize', updateFade); setTimeout(updateFade, 50); }
  const h = (location.hash || '').slice(1);
  if (h && $(h) && $(h).classList.contains('tab-content-panel')) window.switchTab(h, { scroll: false });
}

// ========================================================
// SCAM / MESSAGE CHECKER (main smart input)
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

let lastScam = null;       // { res } for re-render on language change
function detectInputType(text) {
  const x = String(text || '').trim();
  if (!x) return '';
  const compact = x.replace(/[\s-]/g, '');
  if (/^(\+?91)?[6-9]\d{9}$/.test(compact)) return 'Detected: phone number';
  if (!/\s/.test(x) && /^[\w.\-+]{2,}@[a-z][a-z0-9]{1,}$/i.test(x)) return 'Detected: UPI ID';
  if (!/\s/.test(x) && (/^[a-z][a-z0-9+.-]*:\/\//i.test(x) || /^[\w-]+(\.[\w-]+)+(\/\S*)?$/i.test(x))) return 'Detected: website link';
  return 'Detected: message';
}
function updateDetected() {
  const el = $('scam-detected');
  const input = $('checker-input-text');
  if (!el || !input) return;
  const d = detectInputType(input.value);
  el.textContent = d ? '🔎 ' + t(d) : '';
}

function initScamChecker() {
  const inputEl = $('checker-input-text');
  const btnRun = $('btn-run-check');
  document.querySelectorAll('.specimen-chip[data-sample]').forEach(chip => {
    chip.addEventListener('click', () => {
      const txt = PRESET_SCAM_SAMPLES[chip.dataset.sample];
      if (txt) { inputEl.value = txt; updateDetected(); runScamCheck(txt); }
    });
  });
  btnRun.addEventListener('click', () => {
    const text = (inputEl.value || '').trim();
    if (!text) { reqSeq.scam = (reqSeq.scam || 0) + 1; lastScam = null; ensureRetryVisible('scam'); showCardNotice('scam', t('Please paste something first'), t('Paste a message, link, UPI ID or phone number, then press Check now.')); inputEl.focus(); return; }
    runScamCheck(text);
  });
  inputEl.addEventListener('input', updateDetected);
  $('btn-clear-checker').addEventListener('click', () => { inputEl.value = ''; reqSeq.scam = (reqSeq.scam || 0) + 1; lastScam = null; updateDetected(); setCardState('scam', 'idle'); });
}

async function runScamCheck(text) {
  const btn = $('btn-run-check');
  lastScam = null;
  ensureRetryVisible('scam');
  setCardState('scam', 'loading');            // clears any previous verdict immediately
  setBusy(btn, true, 'Analyzing...');
  try {
    const data = await api('scam', '/api/scam/check', { json: { text }, timeoutMs: 25000 });
    if (!data) return;                         // superseded
    lastScam = { res: data.data, text };
    renderScamResult(data.data);
    if (window.matchMedia && window.matchMedia('(max-width: 992px)').matches) $('scam-card').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    lastScam = null;
    showCardError('scam', err, () => runScamCheck(text));
  } finally {
    setBusy(btn, false);
  }
}

function techRows(rows) {
  return rows.filter(r => r[1] !== undefined && r[1] !== null && r[1] !== '').map(r => `<div class="tech-row"><span>${esc(r[0])}</span><strong>${esc(r[1])}</strong></div>`).join('');
}

// Shared renderer for both cards. p = 'scam' | 'domain'
function renderVerdictCard(p, res, { requireVerified, title, desc, actions, extraHtml }) {
  const v = classifyVerdict(res, { requireVerified });
  $(`${p}-gauge-score`).textContent = `${Number(res.riskScore) || 0}%`;
  $(`${p}-gauge-ring`).className = 'gauge-ring ' + v.ring;
  const badge = $(`${p}-badge`);
  badge.className = 'status-badge ' + v.badge;
  badge.textContent = `${v.icon} ${LANG === 'hi' && BADGE_HI[v.text] ? BADGE_HI[v.text] : v.text}`;
  $(`${p}-headline`).textContent = title || tierTitle(v.tier);
  $(`${p}-desc`).textContent = desc || '';
  const split = splitFlags(res.flags);
  const flagIcon = v.tier === 'critical' || v.tier === 'high' ? '⚠️' : '•';
  $(`${p}-flags`).innerHTML = split.user.length
    ? split.user.map(f => `<li>${flagIcon} ${esc(plain(f))}</li>`).join('')
    : `<li class="empty-state">${esc(t('No warning signs were found by the automated checks. This is not proof that it is safe.'))}</li>`;
  const acts = actions && actions.length ? actions : [];
  $(`${p}-actions`).innerHTML = `<ul>${acts.map(a => `<li>${esc(a)}</li>`).join('')}</ul>${extraHtml || ''}`;
  $(`${p}-legal`).innerHTML = `<span>📞 ${esc(t('If you already lost money, call 1930 right away. Banks can sometimes freeze the money if you act within the first hour.'))}</span>`;
  setCardState(p, 'result');
  return { v, split };
}

function renderScamResult(res) {
  const v0 = classifyVerdict(res, { requireVerified: false });
  const code = String(res.verdict || '').toUpperCase();
  const title = (VERDICT_PLAIN[code] && /^(FAKE_|NONEXISTENT|INTERNAL)/.test(code)) ? t(VERDICT_PLAIN[code]) : tierTitle(v0.tier);
  const desc = plain(res.verdictDescription) || plain(sentenceCase(res.headline));
  let actions = (Array.isArray(res.actionAdvice) ? res.actionAdvice : []).map(plain).filter(Boolean).slice(0, 6);
  if (!actions.length) {
    actions = v0.tier === 'critical' || v0.tier === 'high'
      ? [t('Do not click links, call back, or send money.'), t('Do not enter passwords, OTP or UPI PIN anywhere because of this message.'), t('Block the sender and report it on 1930 or cybercrime.gov.in.')]
      : (v0.tier === 'unsure'
        ? [t('Check with the real organisation using the number on its official website or app.'), t('Do not share OTP, PIN or passwords and do not install anything because of this.')]
        : [t('Nothing alarming was found. Still, never share your OTP, PIN or password.')]);
  }
  const { split } = renderVerdictCard('scam', res, { requireVerified: false, title, desc, actions });
  $('scam-type-tag').textContent = res.scamType ? `${t('Category')}: ${plain(res.scamType)}` : '';
  // technical details (experts) - raw codes and internal state live here only
  const extra = ['engine', 'detectionEngine', 'source', 'dataSource', 'model', 'grounded', 'fallbackReason'].map(k => [k, res[k]]);
  $('scam-tech-body').innerHTML = techRows([
    [t('Category'), res.scamType], ['verdict', res.verdict], ['riskLevel', riskWord(res.riskLevel)], [t('Risk score'), res.riskScore],
    ['law', res.protectionLaw], ...extra
  ]) + (split.ops.length ? `<div class="tech-row tech-ops"><span>${esc(t('Other technical notes'))}</span><strong>${split.ops.map(esc).join('<br>')}</strong></div>` : '');
}

// ========================================================
// WEBSITE (DOMAIN) CHECKER
// ========================================================
let lastDomain = null;
function initDomainChecker() {
  const inputEl = $('domain-input-text');
  const btnRun = $('btn-run-domain-check');
  document.querySelectorAll('[data-domain-sample]').forEach(chip => chip.addEventListener('click', () => {
    const d = chip.dataset.domainSample;
    if (d) { inputEl.value = d; runDomainCheck(d); }
  }));
  btnRun.addEventListener('click', () => {
    const text = (inputEl.value || '').trim();
    if (!text) { reqSeq.domain = (reqSeq.domain || 0) + 1; lastDomain = null; ensureRetryVisible('domain'); showCardNotice('domain', t('Please enter a website address'), t('Type or paste a website address, then press Check this website.')); inputEl.focus(); return; }
    runDomainCheck(text);
  });
  inputEl.addEventListener('keydown', e => { if (e.key === 'Enter') btnRun.click(); });
  $('btn-clear-domain').addEventListener('click', () => { inputEl.value = ''; reqSeq.domain = (reqSeq.domain || 0) + 1; lastDomain = null; setCardState('domain', 'idle'); });
}

function renderTelemetry(tm) {
  const set = (id, html) => { const el = $(id); if (el) el.innerHTML = html; };
  const dns = tm.dns, ssl = tm.ssl, feed = tm.threatFeeds, ml = tm.mlDiagnostics, ai = tm.agenticAi;
  const none = '<span class="badge-warn">not available</span>';
  set('telemetry-dns-val', dns
    ? (dns.resolved
      ? `<span class="badge-safe">${esc(dns.status)}</span> ${esc((dns.ips || []).slice(0, 2).join(', '))} <small>(TTL ${esc(dns.ttl == null ? 'n/a' : dns.ttl)}s${dns.isFastFlux ? ', changes very fast' : ''})</small>`
      : `<span class="badge-crit">${esc(dns.status || 'UNRESOLVED')}</span> <small>not found in Google Public DNS</small>`)
    : none);
  if (ssl) {
    if (ssl.supported && ssl.hasValidSsl) {
      if (ssl.isEV_OV) set('telemetry-ssl-val', `<span class="badge-safe">Organisation-validated</span> <strong>${esc(ssl.subjectOrg)}</strong> <small>(${esc(ssl.issuer)})</small>`);
      else if (ssl.isFreeDV) set('telemetry-ssl-val', `<span class="badge-warn">Free certificate</span> ${esc(ssl.issuer)} <small>(${ssl.ageDays != null ? esc(ssl.ageDays) + ' days old' : 'active'}${ssl.isNewlyIssued ? ', newly issued' : ''})</small>`);
      else set('telemetry-ssl-val', `<span class="badge-warn">Valid</span> ${esc(ssl.issuer)} <small>(${ssl.ageDays != null ? esc(ssl.ageDays) + ' days' : 'age n/a'})</small>`);
    } else set('telemetry-ssl-val', `<span class="badge-crit">${esc(ssl.error || 'No secure connection')}</span>`);
  } else set('telemetry-ssl-val', none);
  const age = tm.domainAge;
  if (age && age.available && age.ageDays != null) {
    const cls = age.ageDays < 30 ? 'badge-crit' : (age.ageDays < 180 ? 'badge-warn' : 'badge-safe');
    set('telemetry-age-val', `<span class="${cls}">${esc(age.ageDays)} days old</span> <small>${esc(age.registrar || '')}</small>`);
  } else if (age && age.notRegistered) set('telemetry-age-val', '<span class="badge-crit">Not registered</span>');
  else set('telemetry-age-val', `<span class="badge-warn">Unknown</span> <small>${esc((age && age.error) || 'registration lookup unavailable')}</small>`);
  if (feed) {
    const wr = feed.webRisk || {};
    const wrHtml = wr.available
      ? (wr.flagged ? `<span class="badge-crit">Web Risk: ${esc((wr.threatTypes || []).join(', '))}</span>` : '<span class="badge-safe">Web Risk: no match</span>')
      : `<span class="badge-warn">Web Risk not checked</span> <small>(${esc(wr.reason || 'unavailable')})</small>`;
    const opHtml = feed.openPhishMatch
      ? '<span class="badge-crit">Listed in OpenPhish</span>'
      : (feed.feedLive ? `<span class="badge-warn">Not in OpenPhish</span> <small>(absence is not proof of safety)</small>` : '<span class="badge-warn">OpenPhish feed offline</span>');
    set('telemetry-feed-val', `${opHtml}<br>${wrHtml}`);
  } else set('telemetry-feed-val', none);
  if (ml) {
    const cls = ml.isDGA ? 'badge-crit' : (ml.shannonEntropy > 3.4 ? 'badge-warn' : 'badge-safe');
    set('telemetry-ml-val', `<span class="${cls}">${esc(ml.entropyRating)}</span> <small>entropy ${esc(ml.shannonEntropy)}</small>`);
  } else set('telemetry-ml-val', none);
  set('telemetry-rationale-val', ai ? `<div class="ai-head"><strong>${esc(ai.model)}</strong> ${ai.grounded === true ? '<span class="src-badge src-live">Gemini live</span>' : '<span class="src-badge src-rules">rules fallback</span>'} <span class="ai-conf">Confidence: ${esc(ai.confidence)}</span></div><div class="ai-body">${esc(ai.rationale)}</div>` : '');
}

async function runDomainCheck(input) {
  const btn = $('btn-run-domain-check');
  // A UPI ID or phone number is not a website: hand it to the main checker.
  const kind = detectInputType(input);
  if (kind === 'Detected: UPI ID' || kind === 'Detected: phone number') {
    $('checker-input-text').value = input; updateDetected();
    window.switchTab('tab-scam-checker');
    runScamCheck(input);
    return;
  }
  lastDomain = null;
  ensureRetryVisible('domain');
  setCardState('domain', 'loading');
  setBusy(btn, true, 'Analyzing...');
  try {
    const data = await api('domain', '/api/domain/check', { json: { url: input }, timeoutMs: 30000 });
    if (!data) return;
    lastDomain = { res: data.data, input };
    renderDomainResult(data.data);
    if (window.matchMedia && window.matchMedia('(max-width: 992px)').matches) $('domain-card').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    lastDomain = null;
    showCardError('domain', err, () => runDomainCheck(input));
  } finally {
    setBusy(btn, false);
  }
}

const DOMAIN_CATEGORY = {
  BENIGN_AUTHENTICATED_SOVEREIGN: 'Official website',
  FAKE_OFFICIAL_NAMESPACE: 'Lookalike of an official site',
  OFFICIAL_NAMESPACE_BAD_TLS: 'Official website (certificate problem)',
  HOMOGLYPH_LOOKALIKE: 'Lookalike address',
  TYPOSQUATTING_LOOKALIKE: 'Lookalike address',
  PHISHING_BRAND_IMPERSONATION: 'Lookalike address',
  CONFIRMED_PHISHING_BRAND_IMPERSONATION: 'Lookalike address',
  PHISHING_BRAND_AS_SUBDOMAIN: 'Lookalike address',
  OBFUSCATED_SHORT_URL: 'Shortened link',
  DECEPTIVE_URL_STRUCTURE: 'Shortened link',
  MALICIOUS_APK_DOWNLOAD_VECTOR: 'App download link',
  NONEXISTENT_DOMAIN: 'Website not found',
  RAW_IP_PHISHING_HOST: 'Not a public website',
  GOOGLE_WEB_RISK_FLAGGED: 'Known dangerous website',
  CONFIRMED_ZERO_DAY_PHISHING: 'Known dangerous website',
  DNS_SECURITY_BLOCKED: 'Known dangerous website',
  MALICIOUS_OR_SINKHOLED_HOST: 'Known dangerous website',
  ESTABLISHED_THIRD_PARTY_DOMAIN: 'Ordinary website',
  STANDARD_EXTERNAL_BENIGN_DOMAIN: 'Ordinary website'
};
function domainCategory(res, code) {
  if (res.verified === true) return 'Official website';
  return DOMAIN_CATEGORY[code] || 'Unverified';
}
// Never leave an empty pill/badge/tag on screen.
function hideEmptyPills() {
  document.querySelectorAll('.pill, .badge, .tag, .status-pill, .scam-type-tag, .finding-status, .src-badge, .risk-pct, [class*="badge"], [class*="-pill"], [class*="-tag"]:not(.hero-tagline)').forEach(el => {
    if (el.closest('.nav-tab')) return;
    el.hidden = !el.textContent.trim() && !el.querySelector('img,svg');
  });
}

function renderDomainResult(res) {
  const v0 = classifyVerdict(res, { requireVerified: true });
  const code = String(res.verdict || '').toUpperCase();
  const title = res.verified ? t('This is an official website.') : (VERDICT_PLAIN[code] ? t(VERDICT_PLAIN[code]) : (code ? humanise(code) : tierTitle(v0.tier)));
  const desc = `${t('Website:')} ${res.domain || ''}`;
  let actions = splitSentences(res.actionAdvice);
  if (!actions.length) actions = [tierTitle(v0.tier)];
  const host = safeHost(res.officialDomain);
  const extra = host ? `<p class="official-link">${esc(t('Official website:'))} <a href="https://${esc(host)}" target="_blank" rel="noopener noreferrer">${esc(host)}</a></p>` : '';
  const { split } = renderVerdictCard('domain', res, { requireVerified: true, title, desc, actions, extraHtml: extra });
  const cat = domainCategory(res, code);
  $('domain-type-tag').textContent = cat ? `${t('Category')}: ${t(cat)}` : '';
  hideEmptyPills();
  if (res.realtimeTelemetry) renderTelemetry(res.realtimeTelemetry);
  $('domain-tech-extra').innerHTML = techRows([['verdict', res.verdict], ['riskLevel', riskWord(res.riskLevel)], ['TLD', res.tld], ['law', res.protectionLaw]])
    + (split.ops.length ? `<div class="tech-row tech-ops"><span>${esc(t('Other technical notes'))}</span><strong>${split.ops.map(esc).join('<br>')}</strong></div>` : '');
}

// ========================================================
// PANIC CHECK
// ========================================================
const PANIC_KEYS = { q1: 'isUniformOrAgency', q2: 'isContrabandOrPMLA', q3: 'isCoerciveSurveillance', q4: 'isMoneyDemand', q5: 'isAskingSensitiveInfo', q6: 'isAppOrVideoMove' };
const panicAnswers = {};     // q -> 'yes' | 'no' ; unanswered until the user taps
let lastPanic = null;
let panicTimer = null;

function initDigitalArrestPanic() {
  document.querySelectorAll('.q-btn').forEach(btn => btn.addEventListener('click', () => {
    const q = btn.dataset.q;
    panicAnswers[q] = btn.dataset.val;
    document.querySelectorAll(`.q-btn[data-q="${q}"]`).forEach(b => {
      const on = b === btn;
      b.classList.toggle('active', on);
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
    updatePanicProgress();
    clearTimeout(panicTimer);
    panicTimer = setTimeout(evaluatePanicRisk, 120);
  }));
  $('btn-evaluate-panic').addEventListener('click', evaluatePanicRisk);
  updatePanicProgress();
}
function updatePanicProgress() {
  const n = Object.keys(panicAnswers).length;
  const el = $('panic-progress');
  if (el) el.textContent = `${t('Answered')} ${n} ${t('of')} 6`;
}
const PANIC_NICE = { NO_SIGNALS_SELECTED: 'No warning signs selected', SUSPICIOUS_SIGNAL: 'Warning', LIKELY_DIGITAL_ARREST_SCAM: 'Very likely a scam', CONFIRMED_DIGITAL_ARREST_CRIME: 'Scam: confirmed pattern' };
function panicLevelWord(c) { return c >= 100 ? 'Maximum' : (c >= 85 ? 'Very high' : (c >= 50 ? 'High' : 'Low')); }

async function evaluatePanicRisk() {
  const body = {};
  Object.keys(PANIC_KEYS).forEach(q => { body[PANIC_KEYS[q]] = panicAnswers[q] === 'yes'; });
  const card = $('panic-verdict-card');
  if (!Object.keys(panicAnswers).length) {
    lastPanic = null; $('panic-meter').hidden = true; card.dataset.level = '';
    $('panic-badge').textContent = t('Answer the questions'); $('panic-headline').textContent = t('Your result will show here');
    $('panic-summary').textContent = t('Tap Yes or No for each question. If even one is Yes, do not continue the call.');
    return;
  }
  try {
    const data = await api('panic', '/api/emergency/digital-arrest-screen', { json: body, timeoutMs: 10000 });
    if (!data) return;
    lastPanic = data;
    renderPanic(data);
  } catch (err) {
    lastPanic = null;
    $('panic-meter').hidden = true; card.dataset.level = 'error';
    $('panic-badge').textContent = t('Could not run the check');
    $('panic-headline').textContent = t('Could not run the check');
    $('panic-summary').textContent = t('Hang up and call 1930 now if anyone asks for money or tells you to stay on a video call.');
  }
}
function renderPanic(d) {
  const card = $('panic-verdict-card');
  const level = { NO_SIGNALS_SELECTED: 'none', SUSPICIOUS_SIGNAL: 'warn', LIKELY_DIGITAL_ARREST_SCAM: 'likely', CONFIRMED_DIGITAL_ARREST_CRIME: 'confirmed' }[d.verdict] || 'warn';
  card.dataset.level = level;
  const nice = PANIC_NICE[d.verdict] || humanise(d.verdict);
  $('panic-badge').textContent = `${t(nice)} · ${d.signalCount || 0}/6 ${t('signs')}`;
  $('panic-headline').textContent = t(d.headline) === d.headline ? d.headline : t(d.headline);
  $('panic-summary').textContent = t(d.summary || '');
  const c = Math.max(0, Math.min(100, Number(d.certainty) || 0));
  $('panic-meter').hidden = false;
  $('panic-level-text').textContent = t(panicLevelWord(c));
  $('panic-level-fill').style.width = c + '%';
  if (Array.isArray(d.emergencyProtocol)) {
    const steps = d.emergencyProtocol.map(s => String(s).replace(/^\s*\d+\.\s*/, ''));
    $('panic-steps-box').innerHTML = `<h4>${esc(t('What to do now'))}</h4><ol>${steps.map(s => `<li>${esc(t(s))}</li>`).join('')}</ol>`;
  }
}

// ========================================================
// DOCUMENT CHECK (no automatic API calls; specimens are local text)
// ========================================================
const DOC_SPECIMENS = {
  fake_arrest_warrant: `GOVERNMENT OF INDIA - CENTRAL BUREAU OF INVESTIGATION
ARREST WARRANT AND ASSET FREEZE NOTICE (CONFIDENTIAL)
You are named in a money-laundering case under PMLA. A parcel with illegal drugs and fake passports was found in your name.
You must stay on the video call and must not tell your family. To prove your savings are legal, deposit Rs 4,85,000 into the RBI Escrow Verification Account within 2 hours. Failure to comply will lead to immediate arrest.
Signed: Director, CBI Special Cell`,
  predatory_loan: `LOAN AGREEMENT - INSTANT CASH
Loan sanctioned: Rs 50,000. Amount disbursed: Rs 31,000 after processing fee and GST of 39% deducted upfront.
Repayment within 7 days. The borrower allows the lender access to contacts, gallery, camera and SMS. If payment is delayed the lender may send messages to all contacts.
Lender: QuickRupee Services (registration pending)`,
  authentic_bank: `HDFC BANK LIMITED - SANCTION LETTER
Personal loan of Rs 3,00,000. Interest rate 11.5% per annum (APR 12.1% including all charges). Tenure 36 months. Processing fee 1% plus GST, shown in the Key Fact Statement attached.
HDFC Bank Limited is regulated by the Reserve Bank of India. For queries visit hdfcbank.com or call the number printed on your bank statement. Grievance redressal details are given in the Key Fact Statement.`
};
let currentSelectedFile = null;
let lastDoc = null;
let lastDocReq = null;   // so a language switch can re-run the last document check in the new language
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;
const DOC_VERDICT_PLAIN = { LIKELY_FORGED: 'Likely a forged or fake notice', GENUINE_LOOKING: 'Wording looks genuine (not a full check)', NEEDS_REVIEW: 'Needs a careful manual check', COUNTERFEIT_MALICIOUS: 'Likely fake or a scam', PREDATORY_UNREGISTERED_LENDER: 'Likely an illegal lender', AUTHENTIC_REGULATED_DOCUMENT: 'This looks genuine.', UNVERIFIED_NO_OCR: 'Could not read this file' };

function initDocumentAILab() {
  const cards = document.querySelectorAll('.specimen-card');
  const textArea = $('custom-doc-text');
  const dropzone = $('doc-dropzone');
  const fileInput = $('doc-file-input');
  const fileBar = $('file-selected-bar');
  const pick = card => {
    cards.forEach(c => c.classList.remove('active'));
    card.classList.add('active');
    textArea.value = DOC_SPECIMENS[card.dataset.specimen] || '';
    clearFile();
  };
  function clearFile() { currentSelectedFile = null; if (fileInput) fileInput.value = ''; fileBar.style.display = 'none'; }
  function handleFileSelect(file) {
    clearFile();
    const okType = /\.(pdf|png|jpe?g|txt)$/i.test(file.name) || /^(application\/pdf|image\/(png|jpeg)|text\/plain)$/.test(file.type);
    if (!okType) { showDocError(t('File problem'), t('Only TXT, PDF, PNG or JPG files are accepted.')); return; }
    if (file.size > MAX_UPLOAD_BYTES) { showDocError(t('File problem'), t('This file is larger than 5 MB.')); return; }
    currentSelectedFile = file;
    $('selected-file-name').textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    fileBar.style.display = 'flex';
    resetDocResult();
  }
  cards.forEach(card => {
    card.addEventListener('click', () => pick(card));
    card.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(card); } });
  });
  textArea.value = DOC_SPECIMENS.fake_arrest_warrant;   // preloaded locally, nothing is sent
  dropzone.addEventListener('click', () => fileInput.click());
  dropzone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
  dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('dragover'); });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
  dropzone.addEventListener('drop', e => { e.preventDefault(); dropzone.classList.remove('dragover'); if (e.dataTransfer.files && e.dataTransfer.files[0]) handleFileSelect(e.dataTransfer.files[0]); });
  fileInput.addEventListener('change', e => { if (e.target.files && e.target.files[0]) handleFileSelect(e.target.files[0]); });
  $('btn-remove-file').addEventListener('click', e => { e.stopPropagation(); clearFile(); resetDocResult(); });
  $('btn-upload-file-doc').addEventListener('click', () => {
    if (!currentSelectedFile) { showDocError(t('Nothing to check'), t('Please paste text or choose a file first.')); return; }
    const fd = new FormData(); fd.append('document', currentSelectedFile);
    renderDocument({ form: fd }, $('btn-upload-file-doc'));
  });
  $('btn-analyze-doc').addEventListener('click', () => {
    const customText = (textArea.value || '').trim();
    if (!customText) { showDocError(t('Nothing to check'), t('Please paste text or choose a file first.')); return; }
    renderDocument({ json: { customText } }, $('btn-analyze-doc'));
  });
}
function resetDocResult() {
  reqSeq.doc = (reqSeq.doc || 0) + 1; lastDoc = null;
  show($('doc-result'), false); show($('doc-error'), false); show($('doc-idle'), true);
  const b = $('doc-verdict-badge'); b.className = 'status-pill'; b.textContent = t('Not checked yet');
}
function showDocError(title, msg) {
  reqSeq.doc = (reqSeq.doc || 0) + 1; lastDoc = null;
  show($('doc-result'), false); show($('doc-idle'), false); show($('doc-error'), true);
  $('doc-error-title').textContent = title; $('doc-error-msg').textContent = msg;
  const b = $('doc-verdict-badge'); b.className = 'status-pill'; b.textContent = t('Could not check this');
}
async function renderDocument(payload, btn) {
  reqSeq.doc = (reqSeq.doc || 0);
  show($('doc-result'), false); show($('doc-error'), false); show($('doc-idle'), false);   // old report never stays on screen
  const badge = $('doc-verdict-badge'); badge.className = 'status-pill'; badge.textContent = t('Analyzing...');
  setBusy(btn, true, 'Analyzing...');
  try {
    const data = await api('doc', '/api/document-ai/analyze', { ...payload, timeoutMs: 40000 });
    if (!data) return;
    lastDoc = data; lastDocReq = { payload, btn };
    renderDocResult(data);
  } catch (err) {
    const e = errorText(err);
    showDocError(e.title, e.msg + (e.retryAfter ? '' : ''));
  } finally {
    setBusy(btn, false);
  }
}
function renderDocResult(data) {
  const ana = data.analysis || {};
  const text = (data.document && data.document.extractedText) || '';
  if (ana.verdict === 'UNVERIFIED_NO_OCR' || /OCR unavailable/i.test(text)) {
    showDocError(t('Could not read this file'), t('We could not read this file. Paste the text of the notice into the box instead.'));
    return;
  }
  const risk = Number(ana.riskScore) || 0;
  const auth = Number(ana.authenticityScore) || 0;
  // Severity follows the server verdict (docTriage), not just the number.
  const SEV = { CRITICAL: ['Very high risk', 'danger'], HIGH: ['High risk', 'danger'], MEDIUM: ['Medium risk', 'warning'], LOW: ['Low risk', 'safe'] };
  const sev = SEV[String(ana.severity || '').toUpperCase()] || (risk >= 70 ? ['High risk', 'danger'] : (risk >= 40 ? ['Medium risk', 'warning'] : ['Low risk', 'safe']));
  const badge = $('doc-verdict-badge');
  badge.className = 'status-pill ' + sev[1];
  badge.textContent = t(DOC_VERDICT_PLAIN[ana.verdict] || humanise(ana.verdict));
  $('doc-auth-score').textContent = `${auth}/100`;
  $('doc-auth-score').className = 'score-number ' + (auth >= 70 ? 'safe-val' : (auth >= 40 ? 'warn-val' : 'danger-val'));
  $('doc-risk-score').textContent = `${risk}/100`;
  $('doc-risk-score').className = 'score-number ' + (risk >= 70 ? 'danger-val' : (risk >= 40 ? 'warn-val' : 'safe-val'));
  $('doc-risk-card').className = 'doc-score-card ' + (risk >= 70 ? 'danger' : '');
  $('doc-severity-sub').textContent = t(sev[0]);
  $('doc-raw-text').textContent = text || '-';
  $('doc-findings-list').innerHTML = (ana.findings || []).map(f => {
    const ok = ['PASSED', 'CLEAN', 'NO_MATCH'].includes(f.status);
    return `<div class="finding-row"><span class="finding-status ${ok ? 'passed' : 'failed'}">${ok ? 'OK' : 'CHECK'}</span><div><strong>${esc(plain(f.rule))}:</strong> ${esc(plain(f.detail))}</div></div>`;
  }).join('') + `<div class="datasource-note">${esc(plain(data.dataSourceNote || ''))}</div>`;
  const act = plain(ana.recommendedAction) || (risk >= 40 ? 'Do not pay anything. Verify through the official channel and call 1930.' : 'Verify through official banking channels.');
  $('doc-rec-action').innerHTML = `<ul>${splitSentences(act).map(s => `<li>${esc(s)}</li>`).join('')}</ul>`;
  show($('doc-idle'), false); show($('doc-error'), false); show($('doc-result'), true);
}

// ========================================================
// AI ADVISOR
// ========================================================
function initGeminiAdvisor() {
  const inputEl = $('gemini-input-field');
  const sendBtn = $('btn-send-gemini');
  const submit = () => {
    const text = (inputEl.value || '').trim();
    if (!text || sendBtn.disabled) return;
    inputEl.value = '';
    askGemini(text);
  };
  document.querySelectorAll('.gemini-pill').forEach(pill => pill.addEventListener('click', () => { if (!sendBtn.disabled) askGemini(pill.dataset.prompt); }));
  sendBtn.addEventListener('click', submit);
  inputEl.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
}
function chatMsg(cls, avatar, bodyHtml) {
  const d = document.createElement('div');
  d.className = 'chat-message ' + cls;
  d.innerHTML = `<div class="msg-avatar" aria-hidden="true">${avatar}</div><div class="msg-body">${bodyHtml}</div>`;
  return d;
}
async function askGemini(prompt) {
  const display = $('gemini-chat-display');
  const sendBtn = $('btn-send-gemini');
  display.appendChild(chatMsg('user', '👤', `<strong>${esc(t('You'))}</strong><p>${esc(prompt)}</p>`));
  const loading = chatMsg('assistant', '🧠', `<strong>SafeMeAI</strong><p>${esc(t('Gemini is answering...'))}</p>`);
  display.appendChild(loading);
  display.scrollTop = display.scrollHeight;
  setBusy(sendBtn, true);
  try {
    const data = await api('advisor', '/api/gemini/advisor', { json: { prompt }, timeoutMs: 30000 });
    if (!data) return;
    const r = data.data;
    const cls = r.riskLevel === 'CRITICAL' || r.riskLevel === 'HIGH' ? 'risk-high' : (r.riskLevel === 'MEDIUM' ? 'risk-med' : 'risk-low');
    const signals = Array.isArray(r.signals) ? r.signals : [];
    loading.innerHTML = `<div class="msg-avatar" aria-hidden="true">🛡️</div><div class="msg-body">
      <strong>SafeMeAI · ${esc(t('Risk'))}: <span class="${cls}">${esc(riskWord(r.riskLevel))}</span></strong>
      <p>${esc(plain(r.reasoning))}</p>
      ${signals.length ? `<div class="adv-signals"><strong>${esc(t('Key warning signs:'))}</strong><ul>${signals.map(s => `<li>${esc(plain(s))}</li>`).join('')}</ul></div>` : ''}
      <div class="adv-action"><strong>${esc(t('Recommended action:'))}</strong> <span class="pre">${esc(plain(r.recommendedAction))}</span></div>
      <div class="datasource-note">${esc(r.grounded ? t('Answered by Gemini AI') : t('Answered by fixed rules (AI not used)'))}</div>
    </div>`;
  } catch (err) {
    const e = errorText(err);
    loading.querySelector('.msg-body').innerHTML = `<strong>SafeMeAI</strong><p>${esc(e.title)}. ${esc(e.msg)}</p>`;
  } finally {
    setBusy(sendBtn, false);
    display.scrollTop = display.scrollHeight;
  }
}

// ========================================================
// SCAM TRENDS (demo data unless BigQuery is connected server-side)
// ========================================================
let pillTimer = null;
function watchEmptyPills() {
  const root = document.getElementById('main-content');
  if (!root || !window.MutationObserver) return hideEmptyPills();
  new MutationObserver(() => { clearTimeout(pillTimer); pillTimer = setTimeout(hideEmptyPills, 30); })
    .observe(root, { childList: true, subtree: true, characterData: true });
  hideEmptyPills();
}
const MULE_STATUS = { FLAGGED_FOR_FREEZE: 'Flagged for freeze', UNDER_MONITORING: 'Under monitoring', LEO_DISPATCHED: 'Police team dispatched', AUTO_THROTTLED: 'Auto-throttled' };
function muleStatus(code) {
  const c = String(code || '').trim();
  return MULE_STATUS[c] ? t(MULE_STATUS[c]) : humanise(c);
}
async function initBigQueryMatrix() {
  const threatBars = $('threat-bars-container');
  const muleTable = $('mule-table-body');
  try {
    const data = await api('bq', '/api/bigquery/analytics', { method: 'GET', timeoutMs: 15000 });
    if (!data) return;
    const note = $('bq-source-note');
    if (note) note.textContent = plain(data.dataSourceNote || '');
    if (threatBars && data.topVectors) {
      threatBars.innerHTML = data.topVectors.map(v => {
        const w = Math.max(0, Math.min(100, Number(v.share) || 0));
        return `<div class="threat-bar-item"><div class="bar-meta"><span>${esc(v.vector)}</span><span>${w}% (${esc(v.count)})</span></div><div class="bar-track"><div class="bar-fill" style="width:${w}%"></div></div></div>`;
      }).join('');
    }
    if (muleTable && data.liveMuleClusters) {
      muleTable.innerHTML = data.liveMuleClusters.map(m => `<tr>
        <td><strong>${esc(m.clusterId)}</strong></td><td>${esc(m.nodes)}</td><td>${esc(m.volumeINR)}</td>
        <td><span class="risk-pct">${esc(m.riskScore)}%</span></td><td><span class="finding-status failed">${esc(muleStatus(m.status))}</span></td></tr>`).join('');
    }
  } catch (err) {
    const note = $('bq-source-note');
    if (note) note.textContent = t('Demo data source note unavailable.');
  }
}

// ========================================================
// REPORTS
// ========================================================
function initCitizenReporting() {
  const form = $('scam-report-form');
  const ok = $('report-success-msg');
  const bad = $('report-error-msg');
  loadCitizenReports();
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const btn = $('btn-submit-report');
    ok.style.display = 'none'; bad.style.display = 'none';
    setBusy(btn, true, 'Please wait...');
    try {
      const data = await api('report', '/api/scam/report', {
        json: { scamType: $('report-type').value, scamTarget: $('report-target').value, scamDetails: $('report-details').value },
        timeoutMs: 10000
      });
      if (!data) return;
      form.reset();
      ok.textContent = '✅ ' + (data.message || t('Report received. Thank you.'));
      ok.style.display = 'block';
      loadCitizenReports();
    } catch (err) {
      const e2 = errorText(err);
      bad.textContent = `${t('Could not send the report')}. ${e2.msg}`;
      bad.style.display = 'block';
    } finally {
      setBusy(btn, false);
    }
  });
}
async function loadCitizenReports() {
  const feedList = $('citizen-reports-list');
  const tag = $('reports-source-tag');
  try {
    const data = await api('reports', '/api/scam/reports', { method: 'GET', timeoutMs: 10000 });
    if (!data || !data.data) return;
    const live = data.dataSource === 'crowd-pipeline';
    if (tag) { tag.textContent = live ? t('Confirmed by several people') : t('Sample'); tag.className = live ? 'tag-live' : 'tag-sample'; }
    if (live) {
      feedList.innerHTML = data.data.map(r => `
        <div class="report-feed-item">
          <div class="feed-item-top"><span class="feed-item-badge">${esc(r.scamType)}</span><span class="feed-item-time">${esc(r.time)}</span></div>
          <div class="feed-item-target">${esc(r.target)}</div>
          <div class="feed-item-desc">${esc(r.details)}</div>
        </div>`).join('');
    } else {
      // Server seeds fake entries when there are no real reports. Never show those numbers: masked placeholders only.
      const masks = ['+91 9•••• ••••1', 'name••••@••••', 'https://••••••.example'];
      feedList.innerHTML = `<div class="datasource-note sample-note">${esc(t('Sample entries only. No community-confirmed reports yet.'))}</div>` + data.data.slice(0, 3).map((r, i) => `
        <div class="report-feed-item sample-item">
          <div class="feed-item-top"><span class="feed-item-badge">${esc(r.scamType)}</span><span class="sample-chip-tag">${esc(t('SAMPLE'))}</span></div>
          <div class="feed-item-target">${esc(masks[i % masks.length])}</div>
          <div class="feed-item-desc">${esc(t('Sample placeholder, not a real report'))}</div>
        </div>`).join('');
    }
  } catch (err) {
    feedList.innerHTML = `<div class="datasource-note">${esc(t('Could not load reports.'))}</div>`;
  }
}

// ========================================================
// HONEST SERVICE STATUS
// ========================================================
const STATUS_TXT = { live: 'live', demo: 'demo', off: 'not connected', unknown: 'unknown', checking: 'checking' };
function setDot(id, state, title) {
  const el = $(id); if (!el) return;
  const dot = el.querySelector('.dot');
  dot.className = 'dot ' + ({ live: 'dot-green', warn: 'dot-amber' }[state] || 'dot-grey');
  const s = el.querySelector('.stack-state');
  const word = state === 'warn' ? 'unknown' : state;
  if (s) { s.textContent = t(STATUS_TXT[word] || word); s.className = 'stack-state' + (state === 'live' ? ' sr-only' : ''); }
  el.title = title;
  el.dataset.state = state;
}
async function getJson(url) {
  try { const ac = new AbortController(); const to = setTimeout(() => ac.abort(), 8000); const r = await fetch(url, { signal: ac.signal }); clearTimeout(to); if (!r.ok) return null; return await r.json(); } catch (_) { return null; }
}
let lastSystem = null;
async function loadStatus() {
  const [sys, feed] = await Promise.all([getJson('/api/system/status'), getJson('/api/threat-feed/status')]);
  lastSystem = sys;
  const s = (sys && sys.services) || {};
  const reached = Boolean(sys || feed);
  const onRun = /\.run\.app$/i.test(location.hostname) || (s.cloudRun && s.cloudRun.live === true && s.cloudRun.service);
  setDot('svc-cloudrun', reached && onRun ? 'live' : 'demo', onRun ? 'Running on Google Cloud Run' : 'Not running on Cloud Run (local or other host)');
  const g = s.vertexGemini;
  if (g && g.healthy === true) setDot('svc-gemini', 'live', 'Gemini on Vertex AI: last call succeeded');
  else if (g && g.configured && g.lastError) setDot('svc-gemini', 'warn', 'Gemini is configured but the last call failed. Fixed rules are used.');
  else if (g && g.configured) setDot('svc-gemini', 'warn', 'Gemini is configured but no successful call yet');
  else setDot('svc-gemini', 'off', 'Gemini is not connected. Fixed rules are used.');
  const w = s.webRisk;
  if (w && w.configured && w.healthy !== false) setDot('svc-webrisk', 'live', 'Google Web Risk is configured');
  else if (w && w.configured) setDot('svc-webrisk', 'warn', 'Google Web Risk is configured but the last call failed');
  else setDot('svc-webrisk', 'off', 'Google Web Risk is not configured');
  setDot('svc-docai', s.documentAI && s.documentAI.configured ? 'live' : 'demo', s.documentAI && s.documentAI.configured ? 'Document AI is configured' : 'Document AI is not connected (demo)');
  setDot('svc-bigquery', s.bigQuery && s.bigQuery.configured ? 'live' : 'demo', s.bigQuery && s.bigQuery.configured ? 'BigQuery is configured' : 'BigQuery is not connected (demo data)');
  const docOn = Boolean(s.documentAI && s.documentAI.configured);
  const badge = $('doc-mode-badge');
  if (badge) {
    badge.dataset.i18n = docOn ? 'Document AI: connected. Photos and PDFs are read with OCR.' : 'Document AI: not connected. Text triage mode (images and PDFs cannot be read).';
    badge.dataset.en = docOn ? 'Document AI: connected. Photos and PDFs are read with OCR.' : 'Document AI: not connected. Text triage mode (images and PDFs cannot be read).';
    badge.textContent = t(badge.dataset.en);
    badge.classList.toggle('mode-on', docOn);
  }
}

// ---------- re-render dynamic content on language switch ----------
function rerenderAll() {
  updateDetected(); updatePanicProgress();
  if (lastScam && !$('scam-result').hidden) renderScamResult(lastScam.res);
  if (lastDomain && !$('domain-result').hidden) renderDomainResult(lastDomain.res);
  if (lastPanic) renderPanic(lastPanic);
  if (lastDoc && !$('doc-result').hidden) renderDocResult(lastDoc);
  if (lastSystem !== undefined) loadStatusLabels();
  if ($('citizen-reports-list') && $('citizen-reports-list').children.length) loadCitizenReports();
}
function loadStatusLabels() {
  document.querySelectorAll('#service-status-bar .stack-item').forEach(el => {
    const st = el.dataset.state; const s = el.querySelector('.stack-state');
    if (s && st) { const word = st === 'warn' ? 'unknown' : st; s.textContent = t(STATUS_TXT[word] || word); }
  });
}

// ---------- boot ----------
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initScamChecker();
  initDomainChecker();
  initDigitalArrestPanic();
  initDocumentAILab();
  initGeminiAdvisor();
  initBigQueryMatrix();
  watchEmptyPills();
  initCitizenReporting();
  document.querySelectorAll('.lang-btn').forEach(b => b.addEventListener('click', () => applyLang(b.dataset.lang)));
  let saved = 'en';
  try { saved = localStorage.getItem('safemeai_lang') || 'en'; } catch (_) { /* ignore */ }
  if (saved === 'hi') applyLang('hi');
  loadStatus();
});
