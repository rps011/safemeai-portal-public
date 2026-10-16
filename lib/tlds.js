'use strict';
/**
 * Top-level-domain knowledge shared by link extraction (lib/textEngine.js).
 * Link extraction must not depend on a short hand-kept list: scammers use every cheap new gTLD (.help, .sale, .support ...).
 * Rules for a candidate written WITHOUT a scheme / "www." / path:
 *   1. the last label must be 2-24 letters (or valid-looking punycode);
 *   2. it is rejected when it is a file extension (report.pdf, invoice.zip), an abbreviation (e.g., i.e., a.m.), or
 *      "Sentence.Word" typed without a space (first letter of the last label uppercase);
 *   3. if the TLD is a real, delegated TLD (list below) it is accepted; an unlisted TLD is accepted only when the name is
 *      unmistakably domain-shaped (contains a hyphen or digit in a label) - so new TLDs still work, prose still does not.
 * With a scheme, "www." or a path the shape alone decides (any 2-24 letter TLD) apart from the file-extension guard.
 */
const GTLDS = (
  'com net org info biz name pro mobi asia tel travel jobs cat museum coop aero xxx post int edu gov mil arpa ' +
  'app dev page link click help sale store shop site online website tech fun vip top xyz club live icu cloud digital world today space ' +
  'support services solutions systems network email center company agency academy account accountant accountants active actor adult ' +
  'agency airforce alsace amsterdam apartments art associates attorney auction audio auto autos baby band bank bar bargains beer best bet bid bike bingo bio black blue boats bond boo boutique build builders business buzz cab cafe cam camera camp capital car cards care careers cars casa cash casino catering cc cfd charity chat cheap christmas church city claims cleaning clinic clothing coach codes coffee college community computer condos construction consulting contact contractors cooking cool corsica country coupons courses credit creditcard cricket cruises dance data date dating deals degree delivery democrat dental dentist design diamonds diet direct directory discount doctor dog domains download earth eco education energy engineer engineering enterprises equipment estate events exchange expert exposed express fail faith family fans farm fashion finance financial fish fishing fit fitness flights florist flowers football forsale foundation fund furniture futbol fyi gallery game games garden gift gifts gives glass global gmbh gold golf graphics gratis green gripe group guide guru hair haus health healthcare help hiphop hockey holdings holiday homes horse hospital host hosting house how immo immobilien industries ink institute insure international investments irish jetzt jewelry juegos kaufen kim kitchen kiwi land lawyer lease legal lgbt life lighting limited limo loan loans lol london love ltd luxury maison management market marketing mba media memorial men menu moda moe mom money monster mortgage movie navy network news ninja nrw nyc observer one onl organic page paris partners parts party pet photo photography photos physio pics pictures pink pizza place plumbing plus poker porn press productions promo properties property protection pub qpon quebec racing realty recipes red rehab reise reisen rent rentals repair report republican rest restaurant review reviews rich rip rocks rodeo run sarl sbs school schule science scot security select services sex sexy shiksha shoes show singles ski soccer social software solar solutions soy spa sport spot study style sucks supplies supply surf surgery sydney tattoo tax taxi team technology tennis theater theatre tickets tienda tips tires tirol tools tours town toys trade trading training tube university uno vacations vegas ventures vet viajes video villas vin vision vodka vote voting voto voyage wales watch webcam wedding wien wiki win wine work works wtf yoga zone zip mov ' +
  'blog mail stream secure safe save smile study tab talk tools trust ' +
  'bz cfd gd ink su ws sh'
).split(/\s+/).filter(Boolean);

const CCTLDS = (
  'ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz ' +
  'de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it ' +
  'je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz ' +
  'na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz ' +
  'tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw'
).split(/\s+/).filter(Boolean);

const TLD_SET = new Set([...GTLDS, ...CCTLDS, 'apk']);

// Words/extensions that look like "name.ext" but are files, not websites. (".zip" and ".mov" are real TLDs; as a bare token they are files.)
const FILE_EXT = new Set(('pdf doc docx xls xlsx ppt pptx txt jpg jpeg png gif bmp svg webp csv rtf mp3 mp4 avi mkv mov zip rar tar gz tgz exe msi dmg iso ' +
  'html htm php asp aspx jsp json xml log tmp bak ini cfg md').split(' '));

/** Is `tld` (no dot) a delegated TLD we know about? */
function isKnownTld(tld) { return TLD_SET.has(String(tld).toLowerCase()); }

/** Is the last label shaped like a TLD at all (2-24 letters, or xn-- punycode)? */
function isTldShape(tld) { return /^(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})$/i.test(tld); }

/** Regex alternation of the known TLDs that can safely be matched in running text (longest first). */
const TLD_ALT = [...TLD_SET].filter(t => !FILE_EXT.has(t)).sort((a, b) => b.length - a.length).join('|');

module.exports = { TLD_SET, FILE_EXT, isKnownTld, isTldShape, TLD_ALT };
