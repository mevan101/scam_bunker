// Scam Bunker: contact checks for raw email headers, phone numbers and email addresses. Runs on the device, also on GitHub Pages.
// Pure analysis first (window.ScamBunkerContact, testable in Node), then the UI: intake adapters, reasons/actions and the "Sender check" tab.
(function () {
  const W = typeof window !== 'undefined' ? window : globalThis;
  const H = () => W.DeduceHeuristics;

  // ======================= Reference data =======================
  // ITU-T E.164 country calling codes, compact: "code:name" separated by "|". Longest prefix wins.
  const CC_SRC = '1:United States / Canada|7:Russia / Kazakhstan|20:Egypt|27:South Africa|30:Greece|31:Netherlands|32:Belgium|33:France|34:Spain|36:Hungary|39:Italy|40:Romania|41:Switzerland|43:Austria|44:United Kingdom|45:Denmark|46:Sweden|47:Norway|48:Poland|49:Germany|51:Peru|52:Mexico|53:Cuba|54:Argentina|55:Brazil|56:Chile|57:Colombia|58:Venezuela|60:Malaysia|61:Australia|62:Indonesia|63:Philippines|64:New Zealand|65:Singapore|66:Thailand|81:Japan|82:South Korea|84:Vietnam|86:China|90:Turkey|91:India|92:Pakistan|93:Afghanistan|94:Sri Lanka|95:Myanmar|98:Iran|211:South Sudan|212:Morocco|213:Algeria|216:Tunisia|218:Libya|220:Gambia|221:Senegal|222:Mauritania|223:Mali|224:Guinea|225:Côte d’Ivoire|226:Burkina Faso|227:Niger|228:Togo|229:Benin|230:Mauritius|231:Liberia|232:Sierra Leone|233:Ghana|234:Nigeria|235:Chad|236:Central African Republic|237:Cameroon|238:Cape Verde|239:São Tomé and Príncipe|240:Equatorial Guinea|241:Gabon|242:Congo|243:DR Congo|244:Angola|245:Guinea-Bissau|247:Ascension Island|248:Seychelles|249:Sudan|250:Rwanda|251:Ethiopia|252:Somalia|253:Djibouti|254:Kenya|255:Tanzania|256:Uganda|257:Burundi|258:Mozambique|260:Zambia|261:Madagascar|262:Réunion|263:Zimbabwe|264:Namibia|265:Malawi|266:Lesotho|267:Botswana|268:Eswatini|269:Comoros|290:Saint Helena|291:Eritrea|297:Aruba|298:Faroe Islands|299:Greenland|350:Gibraltar|351:Portugal|352:Luxembourg|353:Ireland|354:Iceland|355:Albania|356:Malta|357:Cyprus|358:Finland|359:Bulgaria|370:Lithuania|371:Latvia|372:Estonia|373:Moldova|374:Armenia|375:Belarus|376:Andorra|377:Monaco|378:San Marino|380:Ukraine|381:Serbia|382:Montenegro|383:Kosovo|385:Croatia|386:Slovenia|387:Bosnia and Herzegovina|389:North Macedonia|420:Czechia|421:Slovakia|423:Liechtenstein|500:Falkland Islands|501:Belize|502:Guatemala|503:El Salvador|504:Honduras|505:Nicaragua|506:Costa Rica|507:Panama|509:Haiti|590:Guadeloupe|591:Bolivia|592:Guyana|593:Ecuador|594:French Guiana|595:Paraguay|596:Martinique|597:Suriname|598:Uruguay|599:Curaçao|670:Timor-Leste|673:Brunei|674:Nauru|675:Papua New Guinea|676:Tonga|677:Solomon Islands|678:Vanuatu|679:Fiji|680:Palau|682:Cook Islands|683:Niue|685:Samoa|686:Kiribati|687:New Caledonia|688:Tuvalu|689:French Polynesia|690:Tokelau|691:Micronesia|692:Marshall Islands|800:International freephone|808:International shared-cost service|850:North Korea|852:Hong Kong|853:Macau|855:Cambodia|856:Laos|870:Inmarsat satellite|880:Bangladesh|881:Global satellite phone|882:International networks|883:International networks|886:Taiwan|960:Maldives|961:Lebanon|962:Jordan|963:Syria|964:Iraq|965:Kuwait|966:Saudi Arabia|967:Yemen|968:Oman|970:Palestine|971:United Arab Emirates|972:Israel|973:Bahrain|974:Qatar|975:Bhutan|976:Mongolia|977:Nepal|979:International premium-rate service|992:Tajikistan|993:Turkmenistan|994:Azerbaijan|995:Georgia|996:Kyrgyzstan|998:Uzbekistan';
  const CC = Object.fromEntries(CC_SRC.split('|').map(x => x.split(':')));
  const ISO = { 1: 'US', 7: 'RU', 44: 'GB', 61: 'AU', 49: 'DE', 33: 'FR', 91: 'IN', 92: 'PK', 94: 'LK', 977: 'NP', 880: 'BD', 971: 'AE', 966: 'SA', 974: 'QA', 965: 'KW', 968: 'OM', 973: 'BH', 60: 'MY', 65: 'SG', 86: 'CN', 852: 'HK', 81: 'JP', 82: 'KR', 234: 'NG', 233: 'GH', 254: 'KE', 27: 'ZA', 353: 'IE', 64: 'NZ', 39: 'IT', 34: 'ES', 31: 'NL', 90: 'TR', 62: 'ID', 63: 'PH', 66: 'TH', 84: 'VN', 95: 'MM', 20: 'EG', 55: 'BR', 52: 'MX' };
  // NANP area codes that are separate countries: they look like +1 (US/Canada) but are charged as international calls.
  const NANP_INTL = { 242: 'Bahamas', 246: 'Barbados', 264: 'Anguilla', 268: 'Antigua and Barbuda', 284: 'British Virgin Islands', 340: 'US Virgin Islands', 345: 'Cayman Islands', 441: 'Bermuda', 473: 'Grenada', 649: 'Turks and Caicos', 664: 'Montserrat', 721: 'Sint Maarten', 758: 'Saint Lucia', 767: 'Dominica', 784: 'Saint Vincent', 809: 'Dominican Republic', 829: 'Dominican Republic', 849: 'Dominican Republic', 868: 'Trinidad and Tobago', 869: 'Saint Kitts and Nevis', 876: 'Jamaica' };
  // Destinations often used for "one ring" callback (wangiri) and international revenue-share fraud: calling back is expensive and part of the charge goes to the fraudster.
  const IRSF = new Set(['239', '247', '252', '290', '222', '674', '677', '678', '682', '683', '686', '688', '690', '691', '692', '870', '881', '882', '883', '979', '808']);
  // National premium-rate / personal-numbering ranges (after the country code).
  const PREMIUM = [[/^449/, 'UK premium-rate number (09…): calls can cost several pounds a minute'], [/^4470/, 'UK "personal number" (070…): looks like a mobile but costs much more to call'], [/^4487[1-3]/, 'UK service number (0871 / 0872 / 0873) with an extra charge'],
    [/^1900/, 'US / Canada 900 number: pay-per-call premium rate'], [/^6119/, 'Australian 190 premium-rate number'], [/^49(900|137)/, 'German premium-rate number (0900 / 0137)'], [/^3389/, 'French premium-rate number (089…)']];
  // Bangladesh mobile operators by prefix. Mobile number portability (since 2018) means the prefix shows the original operator only.
  const BD_OPERATORS = { 13: 'Grameenphone', 17: 'Grameenphone', 14: 'Banglalink', 19: 'Banglalink', 15: 'Teletalk', 16: 'Robi (formerly Airtel)', 18: 'Robi' };
  const MFS = { bkash: { name: 'bKash', helpline: '16247', ussd: '*247#' }, nagad: { name: 'Nagad', helpline: '16167', ussd: '*167#' }, rocket: { name: 'Rocket (Dutch-Bangla Bank)', helpline: '16216', ussd: '*322#' } };
  const MFS_RE = /(বিকাশ|\bb-?kash\b)|(নগদ|\bnagad\b)|(রকেট|\brocket\b|\bdbbl\b|dutch[- ]?bangla)/iu;
  const BANK_RE = /(\bbanks?\b|\bbanking\b|\bcard (services|team|department)\b|\bfraud (team|department)\b|ব্যাংক|ব্যাঙ্ক|বিকাশ|নগদ|রকেট|\bb-?kash\b|\bnagad\b|\brocket\b)/iu;

  const FREEMAIL = new Set(('gmail.com googlemail.com yahoo.com yahoo.co.uk yahoo.co.in ymail.com rocketmail.com outlook.com hotmail.com hotmail.co.uk live.com msn.com icloud.com me.com mac.com aol.com proton.me protonmail.com pm.me gmx.com gmx.de gmx.net mail.com email.com yandex.com yandex.ru mail.ru inbox.ru bk.ru list.ru zoho.com zohomail.com qq.com 163.com 126.com sina.com tutanota.com tuta.io rediffmail.com hushmail.com fastmail.com web.de libero.it orange.fr laposte.net naver.com daum.net').split(' '));
  // Small curated list of well-known throwaway-inbox services (domain names are facts, not copyrightable). The opt-in full check
  // downloads the CC0-licensed community list from github.com/disposable-email-domains/disposable-email-domains.
  const DISPOSABLE = new Set(('mailinator.com guerrillamail.com guerrillamail.net guerrillamailblock.com sharklasers.com grr.la pokemail.net spam4.me 10minutemail.com 10minutemail.net temp-mail.org tempmail.com temp-mail.io tempmail.net yopmail.com yopmail.net trashmail.com trashmail.de getnada.com nada.email dispostable.com maildrop.cc throwawaymail.com fakeinbox.com mintemail.com mohmal.com emailondeck.com tempail.com mailnesia.com mytemp.email burnermail.io spamgourmet.com moakt.com 1secmail.com 1secmail.net emailfake.com tempr.email discard.email mailcatch.com inboxkitten.com mail.tm mailpoof.com getairmail.com tempinbox.com spambox.us mailnull.com tmpmail.org tmpmail.net emailtemporanea.net mail-temp.com').split(' '));
  const DISPOSABLE_LIST_URL = 'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf';
  // Brands commonly impersonated in email, with the domains they really send from (subdomains of these count too).
  const BRANDS = [
    ['PayPal', /\bpay ?pal\b/i, ['paypal.com', 'paypal.co.uk']], ['Amazon', /\bamazon\b/i, ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amazon.ca', 'amazon.com.au']],
    ['Apple', /\bapple\b|\bicloud\b|\bitunes\b/i, ['apple.com', 'icloud.com']], ['Microsoft', /\bmicrosoft\b|\boffice ?365\b|\boutlook team\b/i, ['microsoft.com', 'office.com', 'microsoftonline.com']],
    ['Netflix', /\bnetflix\b/i, ['netflix.com']], ['Google', /\bgoogle\b|\bgmail team\b/i, ['google.com', 'youtube.com']], ['Facebook / Meta', /\bfacebook\b|\bmeta\b|\binstagram\b/i, ['facebook.com', 'facebookmail.com', 'meta.com', 'instagram.com']],
    ['WhatsApp', /\bwhatsapp\b/i, ['whatsapp.com']], ['LinkedIn', /\blinkedin\b/i, ['linkedin.com']], ['DHL', /\bdhl\b/i, ['dhl.com', 'dhl.de', 'dhl.co.uk']], ['FedEx', /\bfedex\b/i, ['fedex.com']],
    ['USPS', /\busps\b/i, ['usps.com', 'usps.gov']], ['IRS', /\birs\b|internal revenue/i, ['irs.gov']], ['Coinbase', /\bcoinbase\b/i, ['coinbase.com']], ['Binance', /\bbinance\b/i, ['binance.com']],
    ['Chase', /\bchase\b/i, ['chase.com', 'jpmorgan.com']], ['Bank of America', /\bbank of america\b/i, ['bankofamerica.com', 'bofa.com']], ['Wells Fargo', /\bwells ?fargo\b/i, ['wellsfargo.com']],
    ['HSBC', /\bhsbc\b/i, ['hsbc.com', 'hsbc.co.uk', 'hsbc.com.bd']], ['eBay', /\bebay\b/i, ['ebay.com', 'ebay.co.uk']], ['DocuSign', /\bdocu ?sign\b/i, ['docusign.com', 'docusign.net']],
    ['Dropbox', /\bdropbox\b/i, ['dropbox.com']], ['Norton', /\bnorton\b/i, ['norton.com', 'nortonlifelock.com']], ['McAfee', /\bmcafee\b/i, ['mcafee.com']],
    ['bKash', /\bb-?kash\b|বিকাশ/iu, ['bkash.com']], ['Nagad', /\bnagad\b|নগদ/iu, ['nagad.com.bd']], ['Dutch-Bangla Bank / Rocket', /\bdutch[- ]?bangla\b|\bdbbl\b|\brocket\b/i, ['dutchbanglabank.com']],
    ['BRAC Bank', /\bbrac bank\b/i, ['bracbank.com']], ['City Bank', /\bcity ?bank\b/i, ['thecitybank.com']], ['Sonali Bank', /\bsonali bank\b/i, ['sonalibank.com.bd']],
  ];
  const COMPANYISH = /\b(support|team|service|services|security|billing|account|accounts|helpdesk|help desk|customer|care|bank|official|admin|administrator|hr|recruit\w*|ltd|limited|inc|llc|plc|corp\w*|department|notification|alert|verification)\b/i;

  // ======================= Helpers =======================
  const lc = s => String(s || '').toLowerCase();
  const SLD = new Set(['co', 'com', 'org', 'net', 'ac', 'gov', 'edu', 'gob', 'or', 'ne']);
  function regDomain(host) {
    const p = lc(host).replace(/\.$/, '').split('.').filter(Boolean);
    if (p.length <= 2) return p.join('.');
    return (p[p.length - 1].length === 2 && SLD.has(p[p.length - 2]) ? p.slice(-3) : p.slice(-2)).join('.');
  }
  const underDomain = (host, dom) => { host = lc(host); return host === dom || host.endsWith('.' + dom); };
  const isFree = d => FREEMAIL.has(regDomain(d)) || FREEMAIL.has(lc(d));
  const isDisposable = (d, extra) => [lc(d), regDomain(d)].some(x => DISPOSABLE.has(x) || (extra && extra.has(x)));
  const brandIn = s => BRANDS.find(([, re]) => re.test(String(s || '')));
  const ownedBy = (brand, host) => brand[2].some(d => underDomain(host, d));
  const signal = (strength, text, detail) => ({ strength, text, detail: detail || '' });
  const WEIGHT = { proof: 40, strong: 28, moderate: 16, weak: 6 };

  // Lookalike / risky-domain flags from the shared link engine (scam.js), so emails and links are judged the same way.
  function domainFlags(domain) {
    const h = H(); if (!h || !domain) return [];
    const r = h.analyzeUrl('https://' + domain + '/');
    return (r.flags || []).filter(f => /look-alike|typosquat|brand name|punycode|high-abuse|raw ip/i.test(f));
  }

  // RFC 2047 encoded words (=?UTF-8?B?...?=), used to hide brand names and lookalike letters in display names.
  function decodeWords(s) {
    return String(s || '').replace(/=\?([\w-]+)\?([BQ])\?([^?]*)\?=\s*(?==\?)?/gi, (m, cs, enc, data) => {
      try {
        let bytes;
        if (enc.toUpperCase() === 'B') { const bin = typeof atob === 'function' ? atob(data) : Buffer.from(data, 'base64').toString('binary'); bytes = Uint8Array.from(bin, c => c.charCodeAt(0)); }
        else { const t = data.replace(/_/g, ' '); const out = []; for (let i = 0; i < t.length; i++) { if (t[i] === '=' && /^[0-9a-f]{2}$/i.test(t.slice(i + 1, i + 3))) { out.push(parseInt(t.slice(i + 1, i + 3), 16)); i += 2; } else out.push(t.charCodeAt(i)); } bytes = Uint8Array.from(out); }
        return typeof TextDecoder === 'function' ? new TextDecoder(cs, { fatal: false }).decode(bytes) : String.fromCharCode(...bytes);
      } catch { return m; }
    });
  }

  // "Display Name" <addr@domain>  |  addr@domain (Name)  |  addr@domain
  function parseAddress(v) {
    const raw = decodeWords(String(v || '').trim());
    const angle = raw.match(/^(.*?)<\s*([^<>\s]+@[^<>\s]+)\s*>/);
    let name = '', address = '';
    if (angle) { name = angle[1]; address = angle[2]; }
    else { const m = raw.match(/[^\s<>(),;"]+@[^\s<>(),;"]+/); address = m ? m[0] : ''; const c = raw.match(/\(([^)]*)\)/); name = c ? c[1] : ''; }
    name = name.trim().replace(/^"(.*)"$/, '$1').replace(/\\"/g, '"').trim();
    address = lc(address).replace(/[.>]+$/, '');
    const domain = address.includes('@') ? address.split('@').pop() : '';
    return address ? { raw, name, address, local: address.split('@')[0], domain } : null;
  }

  // ======================= Email headers =======================
  const HEADER_NAMES = /^(received|from|to|cc|subject|date|return-path|reply-to|sender|message-id|authentication-results|arc-authentication-results|arc-seal|arc-message-signature|dkim-signature|received-spf|mime-version|content-type|delivered-to|x-[\w-]+|list-unsubscribe|feedback-id)\s*:/i;
  function headerScore(text) {
    const lines = String(text || '').split(/\r?\n/);
    const names = new Set(); for (const l of lines) { const m = l.match(HEADER_NAMES); if (m) names.add(lc(m[1])); }
    const core = ['received', 'authentication-results', 'return-path', 'message-id', 'dkim-signature', 'received-spf'].filter(n => names.has(n)).length;
    if (names.size >= 3 && core >= 1) return Math.min(0.98, 0.7 + core * 0.07);
    return names.size >= 3 && names.has('from') ? 0.5 : 0;
  }

  // Unfolds and splits the header block. Returns { headers: [[name, value]], body }.
  function parseHeaders(text) {
    const lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
    let i = 0; while (i < lines.length && !HEADER_NAMES.test(lines[i])) i++; // skip anything pasted above the headers
    const headers = []; let started = false;
    for (; i < lines.length; i++) {
      const l = lines[i];
      if (/^[ \t]/.test(l) && headers.length) { headers[headers.length - 1][1] += ' ' + l.trim(); continue; }
      const m = l.match(/^([\w-]+)\s*:\s?(.*)$/);
      if (m) { headers.push([m[1], m[2].trim()]); started = true; continue; }
      if (started && !l.trim()) { i++; break; }
      if (started) break; // not a header and not a continuation: the headers have ended
    }
    return { headers, body: lines.slice(i).join('\n').trim() };
  }
  const all = (hs, n) => hs.filter(([k]) => lc(k) === n).map(([, v]) => v);
  const first = (hs, n) => all(hs, n)[0];

  function parseAuthResults(v) {
    const out = { server: (String(v).split(';')[0] || '').trim(), spf: null, dkim: [], dmarc: null };
    for (const part of String(v).split(';').slice(1)) {
      const m = part.match(/\b(spf|dkim|dmarc)\s*=\s*([a-z]+)/i); if (!m) continue;
      const method = lc(m[1]), result = lc(m[2]);
      const prop = k => { const x = part.match(new RegExp('\\b' + k.replace('.', '\\.') + '\\s*=\\s*"?([^\\s;"]+)', 'i')); return x ? lc(x[1]).replace(/^.*@/, '') : ''; };
      if (method === 'spf') out.spf = out.spf || { result, domain: prop('smtp.mailfrom') || prop('smtp.helo') };
      else if (method === 'dkim') out.dkim.push({ result, domain: prop('header.d') || prop('header.i') });
      else out.dmarc = out.dmarc || { result, domain: prop('header.from') };
    }
    return out;
  }

  function parseReceived(v) {
    const s = String(v).replace(/\s+/g, ' ');
    const semi = s.lastIndexOf(';');
    const head = semi >= 0 ? s.slice(0, semi) : s, dateStr = semi >= 0 ? s.slice(semi + 1).trim() : '';
    const from = (head.match(/\bfrom\s+([^\s()]+)/i) || [])[1] || '';
    const by = (head.match(/\bby\s+([^\s()]+)/i) || [])[1] || '';
    const ip = (head.match(/\[((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{3,}(?:[0-9a-f]{1,4}))\]/i) || head.match(/\(((?:\d{1,3}\.){3}\d{1,3})\)/) || [])[1] || '';
    const t = Date.parse(dateStr.replace(/\s*\([^)]*\)\s*$/, ''));
    return { from, by, ip, date: dateStr, time: Number.isFinite(t) ? t : null };
  }

  const authLabel = { pass: 'passed', fail: 'failed', softfail: 'soft-failed', neutral: 'gave no answer', none: 'not set up', temperror: 'could not be checked (temporary error)', permerror: 'could not be checked (broken record)', policy: 'blocked by policy', missing: 'not reported' };

  function analyzeHeaders(text) {
    const { headers: hs, body } = parseHeaders(text);
    if (!hs.length) return null;
    const from = parseAddress(first(hs, 'from')), replyTo = parseAddress(first(hs, 'reply-to')), sender = parseAddress(first(hs, 'sender'));
    const returnPath = parseAddress(first(hs, 'return-path'));
    const msgId = first(hs, 'message-id') || '';
    const msgIdDomain = lc((msgId.match(/@([^>\s]+)>?/) || [])[1] || '');
    const arRaw = all(hs, 'authentication-results');
    const ar = arRaw.length ? parseAuthResults(arRaw[0]) : null; // the top one was added by your own provider; lower ones can be forged
    const spfHdr = first(hs, 'received-spf');
    const spfHdrResult = spfHdr ? lc((spfHdr.match(/^\s*([a-z]+)/i) || [])[1] || '') : '';
    const dkimSig = all(hs, 'dkim-signature').map(v => lc((v.match(/\bd=([^;\s]+)/i) || [])[1] || '')).filter(Boolean);
    const hops = all(hs, 'received').map(parseReceived).reverse(); // oldest (origin) first
    const res = { from, replyTo, sender, returnPath, subject: decodeWords(first(hs, 'subject') || ''), date: first(hs, 'date') || '', to: decodeWords(first(hs, 'to') || ''), messageIdDomain: msgIdDomain,
      auth: { spf: ar?.spf?.result || spfHdrResult || 'missing', spfDomain: ar?.spf?.domain || '', dkim: ar ? (ar.dkim.find(d => d.result === 'pass') || ar.dkim[0] || { result: 'missing' }).result : 'missing', dkimDomains: ar ? ar.dkim.map(d => d.domain).filter(Boolean) : [], dmarc: ar?.dmarc?.result || 'missing', server: ar?.server || '', present: !!ar, count: arRaw.length },
      dkimSigned: dkimSig, hops, body, signals: [], headerCount: hs.length };
    const S = res.signals, fd = from?.domain || '', freg = regDomain(fd);

    // --- Who it claims to be vs who sent it ---
    if (!from) S.push(signal('weak', 'There is no readable "From" line, so we cannot tell who it claims to be from.'));
    if (from) {
      const brand = brandIn(from.name) || (!isFree(fd) ? null : brandIn(from.local));
      const nameAddr = (from.name.match(/[\w.+-]+@[\w-]+(\.[\w-]+)+/) || [])[0];
      if (nameAddr && lc(nameAddr) !== from.address) S.push(signal('strong', `The sender's name shows one email address (${lc(nameAddr)}) but the real address is ${from.address}.`, 'Putting a fake address in the display name is a classic spoofing trick: many phones show only the name.'));
      if (brand && !ownedBy(brand, fd)) {
        if (isFree(fd)) S.push(signal('strong', `It says it is from ${brand[0]}, but it was sent from a free personal account (${from.address}).`, `${brand[0]} sends email from its own domain (${brand[2][0]}), never from ${freg}.`));
        else S.push(signal('moderate', `It says it is from ${brand[0]}, but the address is at ${fd}, which is not a ${brand[0]} domain we know (${brand[2].join(', ')}).`, 'Companies sometimes use partner domains, so check the address against the company\'s real website.'));
      } else if (!brand && isFree(fd) && COMPANYISH.test(from.name)) S.push(signal('moderate', `The name "${from.name}" sounds like a company or official team, but it was sent from a free personal account (${from.address}).`, 'Real companies, banks and employers email from their own domain.'));
      for (const f of domainFlags(fd)) S.push(signal(/look-alike|typosquat|punycode/i.test(f) ? 'strong' : 'moderate', `Sender domain ${fd}: ${f}.`));
      if (isDisposable(fd)) S.push(signal('strong', `It was sent from a throwaway inbox service (${freg}).`, 'Disposable addresses are made in seconds and abandoned; no real organisation uses them.'));
    }
    // --- Where replies and bounces go ---
    if (from && replyTo && regDomain(replyTo.domain) !== freg) {
      const strong = isFree(replyTo.domain) && !isFree(fd) || isDisposable(replyTo.domain) || brandIn(from.name) && !ownedBy(brandIn(from.name), replyTo.domain);
      S.push(signal(strong ? 'strong' : 'moderate', `If you press Reply, your answer goes to ${replyTo.address}, not to ${from.address}.`, 'Scammers fake the From line and collect answers at a different address. Newsletters and help desks sometimes do this legitimately.'));
    }
    if (from && returnPath && returnPath.domain && regDomain(returnPath.domain) !== freg) {
      const sus = isFree(returnPath.domain) && !isFree(fd);
      S.push(signal(sus ? 'moderate' : 'weak', `The technical sender (Return-Path) is ${returnPath.address}, a different domain from the From line (${fd}).`, sus ? 'A company email whose bounces go to a free personal account is unusual.' : 'Mailing services often do this legitimately; it matters more when the checks below fail.'));
    }
    if (from && sender && regDomain(sender.domain) !== freg) S.push(signal('weak', `A "Sender" line says it was sent on behalf of ${from.address} by ${sender.address}.`));
    // --- Authentication ---
    const a = res.auth;
    if (!a.present) S.push(signal('weak', 'The headers have no "Authentication-Results" line, so we cannot see whether your email provider verified the sender.', 'Copy the full original headers from your email app (see "How to get the headers").'));
    else {
      if (a.dmarc === 'fail') S.push(signal('strong', `Your email provider checked the sender's anti-spoofing policy (DMARC) and this email failed it.`, `The ${fd || 'sender'} domain says it never sends email like this. Treat it as a fake.`));
      if (['fail'].includes(a.spf)) S.push(signal('moderate', 'The sending server is not on the sender domain\'s list of allowed servers (SPF failed).'));
      else if (a.spf === 'softfail') S.push(signal('weak', 'The sending server is probably not allowed to send for this domain (SPF soft-fail).'));
      if (a.dkim === 'fail') S.push(signal('moderate', 'The digital signature on this email is broken (DKIM failed): it may have been changed or forged.'));
      if (a.dkim === 'missing' && a.spf === 'missing' && a.dmarc === 'missing') S.push(signal('weak', 'No sender checks are reported at all.'));
      else if (['none', 'missing'].includes(a.dmarc) && a.dmarc !== 'fail' && fd) S.push(signal('weak', `The sender domain ${fd} has no anti-spoofing policy (DMARC) reported, so anyone could pretend to send from it.`));
      if (a.dkim === 'pass' && fd && a.dkimDomains.length && !a.dkimDomains.some(d => regDomain(d) === freg)) S.push(signal('weak', `The email was signed by ${a.dkimDomains.join(', ')}, not by ${freg}.`, 'Usually a mailing service; it only proves that service sent it.'));
    }
    // --- Message-ID and hops ---
    if (fd && msgIdDomain && regDomain(msgIdDomain) !== freg && !isFree(msgIdDomain) && !/(google|outlook|prod\.outlook|amazonses|sendgrid|mailgun|mailchimp|mcsv|sparkpost|mandrill|postmark|zoho|yahoo|apple|icloud|protonmail)/i.test(msgIdDomain))
      S.push(signal('weak', `The message ID was created by ${msgIdDomain}, not by ${fd}.`, 'Mailing services do this too; on its own it proves nothing.'));
    for (let i = 1; i < hops.length; i++) if (hops[i].time != null && hops[i - 1].time != null && hops[i].time < hops[i - 1].time - 5 * 60e3) { S.push(signal('weak', 'The delivery hops have timestamps out of order; the lowest hops may have been faked or a server clock is wrong.')); break; }
    if (a.present && a.spf === 'pass' && a.dkim === 'pass' && a.dmarc === 'pass') res.passed = true;
    S.sort((x, y) => WEIGHT[y.strength] - WEIGHT[x.strength]);
    return res;
  }

  // ======================= Phone numbers =======================
  function countryOf(digits) {
    for (const n of [3, 2, 1]) { const c = digits.slice(0, n); if (CC[c]) return { code: c, name: CC[c] }; }
    return null;
  }
  function parsePhone(raw) {
    const s = String(raw || '').trim(); if (!s) return null;
    const h = H();
    const n = h && h.normalizePhone ? h.normalizePhone(s) : null;
    let digits = n && n.e164 ? n.e164.slice(1) : null;
    if (!digits) {
      const d = s.replace(/[^\d+]/g, '');
      if (/^\+\d{7,15}$/.test(d)) digits = d.slice(1);
      else if (/^00[1-9]\d{6,14}$/.test(d)) digits = d.slice(2);
      else if (/^01[3-9]\d{8}$/.test(d)) digits = '880' + d.slice(1);
      else if (n) return { raw: s, e164: null, digits: n.digits, local: true };
      else return null;
    }
    if (/^(\d)\1+$/.test(digits) || digits.length < 8 || digits.length > 15) return null;
    return { raw: s, e164: '+' + digits, digits };
  }
  function analyzePhone(raw, opts = {}) {
    const p = parsePhone(raw); if (!p) return null;
    const out = { raw: p.raw, e164: p.e164, display: p.e164 || p.raw, country: null, code: null, kind: '', operator: '', signals: [], links: [] };
    const S = out.signals;
    if (!p.e164) { out.kind = 'Local number without a country code'; S.push(signal('weak', `We could not tell which country ${p.raw} belongs to because it has no country code.`)); }
    else {
      const d = p.digits, cc = countryOf(d);
      out.code = cc ? '+' + cc.code : null; out.country = cc ? cc.name : 'Unknown country code';
      out.iso = cc ? (ISO[cc.code] || null) : null;
      if (cc && cc.code === '1') { const nanp = NANP_INTL[d.slice(1, 4)]; if (nanp) { out.country = nanp; out.iso = 'NANP-' + d.slice(1, 4); S.push(signal('moderate', `+1 ${d.slice(1, 4)} looks like a US or Canada number but is ${nanp}, charged as an international call.`, 'Missed "one ring" calls from these area codes trick people into calling back at high cost.')); } }
      if (cc && IRSF.has(cc.code)) S.push(signal('moderate', `${cc.name} (+${cc.code}) numbers are often used in "one ring" missed-call and premium callback fraud.`, 'Calling back can cost a lot per minute and part of the charge goes to whoever set it up. This alone does not prove a scam.'));
      for (const [re, label] of PREMIUM) if (re.test(d)) { S.push(signal('moderate', label + '.', 'Premium-rate numbers are used to make victims pay just by calling.')); break; }
      if (cc && cc.code === '880') {
        const op = d.match(/^8801([3-9])\d{8}$/);
        if (op) { out.kind = 'Bangladesh mobile'; out.operator = BD_OPERATORS['1' + op[1]] || ''; }
        else out.kind = 'Bangladesh landline or service number';
      }
    }
    // Context: a message that claims to be from a local bank or mobile-money service, but the number is foreign or an ordinary mobile.
    const ctx = String(opts.context || '');
    const mfs = ctx.match(MFS_RE);
    if (mfs) {
      const m = mfs[1] ? MFS.bkash : mfs[2] ? MFS.nagad : MFS.rocket;
      if (out.e164 && !out.e164.startsWith('+880')) S.push(signal('strong', `The message mentions ${m.name}, but this number is from ${out.country}, not Bangladesh.`, `${m.name} does not contact customers from foreign numbers. Its helpline is ${m.helpline}.`));
      else if (out.kind === 'Bangladesh mobile') S.push(signal('moderate', `The message mentions ${m.name}, but this is an ordinary mobile number (${out.operator || 'Bangladesh'}), not ${m.name}'s official line.`, `${m.name}'s official helpline is the short number ${m.helpline}. Agents and staff never ask for your PIN or OTP.`));
      out.mfs = m;
    } else if (BANK_RE.test(ctx) && out.iso && opts.home && out.iso !== opts.home && !out.iso.startsWith('NANP-')) {
      S.push(signal('strong', `The message talks about a bank, but the number is from ${out.country}, not your country.`, 'Your bank calls and texts from its own local numbers. Call the number on the back of your card instead.'));
    }
    if (/\bagent\b|এজেন্ট/iu.test(ctx) && /(cash ?out|ক্যাশ ?আউট|send money|সেন্ড ?মানি|পাঠান|\bpathan\b)/iu.test(ctx)) S.push(signal('moderate', 'It asks you to send money or cash out to an "agent number".', 'Scammers pose as agents to collect money. Only use agents you visit in person, and never move money because a stranger asked.'));
    if (/(cash ?in|ক্যাশ ?ইন|received tk|টাকা গ্রহণ|you have received)/iu.test(ctx) && out.kind === 'Bangladesh mobile' && mfs) S.push(signal('moderate', 'This looks like a "you received money" message sent from an ordinary mobile number.', `Real ${out.mfs.name} messages come from the sender name "${out.mfs.name.split(' ')[0]}", not a phone number. Check your balance in the app or with ${out.mfs.ussd} before doing anything.`));
    // Check it yourself: search links only; no paid lookups and no owner lookups.
    const q = out.e164 || p.raw;
    out.links.push({ label: 'Search the web for reports', how: 'Looks for scam reports that mention this number', href: 'https://duckduckgo.com/?q=' + encodeURIComponent(`"${q}" scam`) });
    if (out.e164 && out.e164.length > 9) out.links.push({ label: 'Search in local format', how: 'Many reports write the number without the country code', href: 'https://duckduckgo.com/?q=' + encodeURIComponent(`"${localFormat(out)}" scam`) });
    if (out.e164) out.links.push({ label: 'Open WhatsApp profile', how: 'Shows the public WhatsApp profile, if any. Nothing is sent unless you type a message', href: 'https://wa.me/' + out.e164.slice(1) });
    S.sort((x, y) => WEIGHT[y.strength] - WEIGHT[x.strength]);
    return out;
  }
  function localFormat(p) {
    if (!p.e164) return p.raw;
    if (p.e164.startsWith('+880')) return '0' + p.e164.slice(4);
    if (p.e164.startsWith('+44')) return '0' + p.e164.slice(3);
    return p.e164.slice(1 + (p.code || '+').length - 1);
  }

  // ======================= Email addresses =======================
  function analyzeEmail(raw, opts = {}) {
    const a = parseAddress(raw); if (!a || !/^[^@\s]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(a.address)) return null;
    const d = a.domain, out = { address: a.address, name: a.name, domain: d, kind: '', signals: [], links: [] }, S = out.signals;
    const disp = isDisposable(d, opts.disposable);
    out.kind = disp ? 'Throwaway inbox' : isFree(d) ? 'Free personal account' : 'Own domain';
    if (disp) S.push(signal('strong', `${d} is a throwaway inbox service.`, 'Anyone can create these in seconds without giving their name. No real company, bank or employer uses them.'));
    const brand = brandIn(a.name) || brandIn(a.local) || null;
    if (brand && !ownedBy(brand, d)) {
      if (isFree(d) || disp) S.push(signal('strong', `It uses the name ${brand[0]} but is a ${disp ? 'throwaway' : 'free personal'} address (${a.address}).`, `${brand[0]} emails from its own domain (${brand[2][0]}).`));
      else if (!domainFlags(d).length) S.push(signal('moderate', `It uses the name ${brand[0]} but the domain ${d} is not a ${brand[0]} domain we know.`, 'Check it against the company\'s real website before trusting it.'));
    } else if (!brand && isFree(d) && COMPANYISH.test(a.local.replace(/[._-]+/g, ' '))) S.push(signal('weak', `${a.address} sounds like an official team or company, but it is a free personal account.`));
    for (const f of domainFlags(d)) S.push(signal(/look-alike|typosquat|punycode/i.test(f) ? 'strong' : 'moderate', `${d}: ${f}.`));
    out.links.push({ label: 'Search the web for reports', how: 'Looks for scam reports that mention this address', href: 'https://duckduckgo.com/?q=' + encodeURIComponent(`"${a.address}" scam`) });
    if (!isFree(d) && !disp) out.links.push({ label: 'Check when the domain was registered', how: `When ${regDomain(d)} was registered, from the official registry (ICANN)`, href: 'https://lookup.icann.org/en/lookup?name=' + encodeURIComponent(regDomain(d)) });
    S.sort((x, y) => WEIGHT[y.strength] - WEIGHT[x.strength]);
    return out;
  }

  // ======================= Whole input =======================
  const EMAIL_RE = /[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}/gi;
  const PHONE_RE = /(?<![\w+.:/@-])\+?\(?\d[\d\s().-]{6,}\d(?![\w-]|\.\d)/g;
  const homeCountry = () => { try { const r = (W.navigator && (W.navigator.language || '')).split('-')[1]; return r ? r.toUpperCase() : null; } catch { return null; } };

  function scan(text, opts = {}) {
    text = String(text || '');
    const home = opts.home !== undefined ? opts.home : homeCountry();
    const out = { headers: null, phones: [], emails: [] };
    let rest = text;
    if (headerScore(text) >= 0.5) { out.headers = analyzeHeaders(text); rest = out.headers ? out.headers.body + '\n' + out.headers.subject : text; }
    const seenE = new Set(), addEmail = (v, role) => { const e = analyzeEmail(v, opts); if (!e || seenE.has(e.address)) return; seenE.add(e.address); e.role = role; out.emails.push(e); };
    if (out.headers) { const h = out.headers; if (h.from) addEmail(h.from.raw, 'From'); if (h.replyTo) addEmail(h.replyTo.raw, 'Reply-To'); if (h.returnPath) addEmail(h.returnPath.address, 'Return-Path'); if (h.sender) addEmail(h.sender.raw, 'Sender'); }
    for (const m of rest.match(EMAIL_RE) || []) { if (out.emails.length >= 10) break; addEmail(m, ''); }
    const seenP = new Set();
    rest = rest.replace(/[০-৯]/g, d => String(d.charCodeAt(0) - 0x09E6));
    for (const m of rest.matchAll(PHONE_RE)) {
      if (out.phones.length >= 10) break;
      const h = H(); if (h && h.normalizePhone && !h.normalizePhone(m[0], rest.slice(Math.max(0, m.index - 25), m.index))) continue;
      const p = analyzePhone(m[0], { context: rest, home }); if (!p || seenP.has(p.display)) continue;
      seenP.add(p.display); out.phones.push(p);
    }
    out.found = !!(out.headers || out.phones.length || out.emails.length);
    out.reasons = reasonsFor(out); out.actions = actionsFor(out);
    return out;
  }

  // Plain-language reasons (strongest first) and to-do items for the Simple result.
  function reasonsFor(r) {
    const rs = [];
    if (r.headers) for (const s of r.headers.signals) rs.push({ text: s.text, weight: WEIGHT[s.strength], strength: s.strength, source: 'email headers' });
    for (const p of r.phones) for (const s of p.signals) rs.push({ text: s.text, weight: WEIGHT[s.strength], strength: s.strength, source: 'phone number ' + p.display });
    const fromHdr = new Set(r.headers ? r.emails.filter(e => e.role).map(e => e.address) : []);
    for (const e of r.emails) if (!fromHdr.has(e.address) || !r.headers) for (const s of e.signals) rs.push({ text: s.text, weight: WEIGHT[s.strength], strength: s.strength, source: 'email address ' + e.address });
    const seen = new Set();
    return rs.filter(x => x.strength !== 'weak' || rs.length < 4).filter(x => !seen.has(x.text) && seen.add(x.text)).sort((a, b) => b.weight - a.weight);
  }
  function actionsFor(r) {
    const a = [], bad = s => s.some(x => x.strength === 'strong' || x.strength === 'moderate');
    if (r.headers && bad(r.headers.signals)) {
      a.push({ text: 'Do not reply, click links or open attachments in this email.' });
      a.push({ text: 'Report it as phishing in your email app (Gmail: ⋮ › Report phishing; Outlook: Report › Report phishing), then delete it.' });
    }
    if (r.headers && r.headers.passed && !bad(r.headers.signals)) a.push({ text: 'Your email provider reports that the sender checks passed. If you copied the full headers, that means the email came from the domain shown, not that the domain is honest: still check the domain itself.' });
    const mfs = r.phones.find(p => p.mfs);
    if (mfs) a.push({ text: `Never share your ${mfs.mfs.name} PIN or OTP with anyone. If you are worried, call ${mfs.mfs.name} yourself on ${mfs.mfs.helpline}.` });
    if (r.phones.some(p => bad(p.signals))) a.push({ text: 'Do not call back or reply to this number. Block it and report it to your mobile operator.' });
    if (r.phones.some(p => p.signals.some(s => /bank/i.test(s.text)))) a.push({ text: 'Call your bank on the number printed on your card or its official website, not a number from the message.' });
    if (r.emails.some(e => bad(e.signals)) && !(r.headers && bad(r.headers.signals))) a.push({ text: 'Do not reply to this address or send it money, documents or codes.' });
    const seen = new Set(); return a.filter(x => !seen.has(x.text) && seen.add(x.text));
  }

  // "How to get the headers" help, in plain words.
  const HEADERS_HELP = [
    ['Gmail (on a computer)', 'Open the email, click the three dots (⋮) next to Reply, choose “Show original”, then click “Copy to clipboard” and paste it here. The Gmail phone app cannot show this.'],
    ['Outlook (web or new Outlook)', 'Open the email, click the three dots (…) at the top right of the message, choose “View” › “View message source” (or “View message details”), select everything and copy it.'],
    ['Outlook (classic Windows app)', 'Open the email in its own window, choose File › Properties, and copy the text in the “Internet headers” box.'],
    ['Apple Mail (Mac)', 'Select the email, choose View › Message › All Headers (or Raw Source, ⌥⌘U), then select everything and copy it.'],
  ];

  async function loadDisposableList(fetchFn = W.fetch) {
    const r = await fetchFn(DISPOSABLE_LIST_URL, { cache: 'force-cache', credentials: 'omit', referrerPolicy: 'no-referrer' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const set = new Set((await r.text()).split(/\r?\n/).map(l => lc(l.trim())).filter(l => l && !l.startsWith('#')));
    if (set.size < 100) throw new Error('list looks incomplete');
    return set;
  }

  // ======================= Intake adapters =======================
  const onlyPhone = t => { const s = String(t || '').trim(); return s.length <= 24 && /^[+(\d][\d\s().-]{6,}\d$/.test(s) && !!parsePhone(s); };
  const onlyEmail = t => /^\s*(?:"?[^"<>]*"?\s*<)?[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+>?\s*$/i.test(String(t || ''));
  const notes = list => list.slice(0, 5).map(x => x.text);
  const ADAPTERS = [
    { id: 'email-headers', label: 'Email headers', detect: input => headerScore(input && input.text),
      async extract(input) { const r = scan(input.text); const h = r.headers; return { text: [h && h.subject, h && h.body].filter(Boolean).join('\n\n') || input.text, notes: notes(r.reasons), contact: r }; } },
    { id: 'phone-number', label: 'Phone number', detect: input => onlyPhone(input && input.text) ? 0.9 : 0,
      async extract(input) { const r = scan(input.text); return { text: input.text, notes: notes(r.reasons), contact: r }; } },
    { id: 'email-address', label: 'Email address', detect: input => onlyEmail(input && input.text) ? 0.9 : 0,
      async extract(input) { const r = scan(input.text); return { text: input.text, notes: notes(r.reasons), contact: r }; } },
  ];

  const api = { parseHeaders, analyzeHeaders, parseAuthResults, parseReceived, parseAddress, decodeWords, analyzePhone, parsePhone, analyzeEmail, scan, regDomain, headerScore, countryOf, loadDisposableList, ADAPTERS, HEADERS_HELP, DISPOSABLE_LIST_URL, CC, BD_OPERATORS };
  W.ScamBunkerContact = api;
  if (typeof document === 'undefined' || !W.ScamBunker) return;

  // ======================= UI =======================
  const SB = W.ScamBunker, esc = SB.esc;
  const $ = s => document.querySelector(s);
  const safeHref = u => /^https?:/i.test(String(u || '')) ? esc(u) : '#';
  let extraDisposable = null;

  // Register with the Simple-mode shell whenever it exists (it may land in a parallel PR and load after this file).
  (W.ScamBunkerIntakes = W.ScamBunkerIntakes || []).push(...ADAPTERS);
  let registered = false;
  const register = () => { if (registered || typeof SB.registerIntake !== 'function') return; ADAPTERS.forEach(a => SB.registerIntake(a)); registered = true; };
  register(); document.addEventListener('sb:ready', register); document.addEventListener('sb:intake-ready', register);

  const addReasons = (c, r) => { if (!r.length) return; if (typeof SB.addReasons === 'function') SB.addReasons(c, r); else c.reasons = [...(c.reasons || []), ...r]; };
  const addActions = (c, a) => { if (!a.length) return; if (typeof SB.addActions === 'function') SB.addActions(c, a); else c.actions = [...(c.actions || []), ...a]; };

  const OBS_W = { strong: 'strong', moderate: 'moderate', weak: 'weak', proof: 'strong' };
  function observations(c) {
    const v = c.final || c.local; if (!v || !c.contact) return;
    v.observations = (v.observations || []).filter(o => !o.contact);
    const top = c.contact.reasons.filter(r => r.strength !== 'weak').slice(0, 4);
    v.observations.unshift(...top.map(r => ({ fact: r.source[0].toUpperCase() + r.source.slice(1), inference: r.text, weight: OBS_W[r.strength], contact: true })));
    if (v === c.local && top.some(r => r.strength === 'strong') && ['No strong red flags', 'Insufficient evidence', 'Likely legitimate'].includes(v.verdict)) {
      v.verdict = 'Suspicious'; v.category = c.contact.headers ? 'Sender looks spoofed' : 'Contact details look suspicious'; v.risk = Math.max(+v.risk || 0, 45);
      v.headline = 'The sender details show warning signs: ' + top[0].text;
      v.advice = 'Pause. Do not reply, call back or click anything in this message. Contact the company or person through a channel you find yourself, such as their official website or a number you already have.';
    }
  }

  // Saved cases keep only a text excerpt, so the full contact result is stored per case id and reused on reopen.
  const SAVE_KEY = 'scambunker.contact';
  const saved = id => (SB.store.get(SAVE_KEY, {}) || {})[id];
  function save(c) {
    if (!c || !c.id || !c.contact) return;
    const all = SB.store.get(SAVE_KEY, {}) || {};
    delete all[c.id];
    if (c.contact.found) all[c.id] = { ...c.contact, headers: c.contact.headers && { ...c.contact.headers, body: '' } };
    const keep = Object.keys(all).slice(-200); SB.store.set(SAVE_KEY, Object.fromEntries(keep.map(k => [k, all[k]])));
  }
  function apply(c, fresh) {
    if (!c) return;
    c.contact = (!fresh && !extraDisposable && saved(c.id)) || scan([c.text, c.url && !/^https?:/i.test(c.url) ? c.url : ''].filter(Boolean).join('\n'), { disposable: extraDisposable });
    if (fresh) save(c);
    c.caseExtras = { ...(c.caseExtras || {}), contact: c.contact.found ? { reasons: c.contact.reasons.slice(0, 8).map(r => `[${r.strength}] ${r.text}`), auth: c.contact.headers && c.contact.headers.auth, phones: c.contact.phones.map(p => ({ number: p.display, country: p.country, operator: p.operator })), emails: c.contact.emails.map(e => ({ address: e.address, kind: e.kind })) } : undefined };
    if (fresh && !c._contactShared) { addReasons(c, c.contact.reasons.slice(0, 5)); addActions(c, c.contact.actions); c._contactShared = true; }
    observations(c);
    SB.renderAll();
    render(c);
  }

  const weightTag = s => `<span class="w ${esc(OBS_W[s] || 'weak')}">${esc(s)}</span>`;
  const sigList = list => list.length ? `<ul>${list.map(s => `<li>${weightTag(s.strength)} ${esc(s.text)}${s.detail ? `<br><span class="muted">${esc(s.detail)}</span>` : ''}</li>`).join('')}</ul>` : '<ul><li><span class="w ok">ok</span> No warning signs in this detail. That is not proof it is safe.</li></ul>';
  const linkGrid = links => `<div class="rev">${links.map(l => `<a href="${safeHref(l.href)}" target="_blank" rel="noopener noreferrer"><b>${esc(l.label)} ↗</b><span>${esc(l.how)}</span></a>`).join('')}</div>`;
  const authCell = r => { const cls = r === 'pass' ? 'ok' : r === 'fail' ? 'strong' : ['softfail', 'permerror'].includes(r) ? 'moderate' : 'weak'; return `<span class="w ${cls}">${esc(r)}</span> ${esc(authLabel[r] || r)}`; };

  function helpHtml(open) {
    return `<details${open ? ' open' : ''}><summary>How to get the full email headers</summary>
      <p class="muted">Headers are the hidden lines at the top of every email that show which servers really sent it. Copy them and paste them into the box, then check again. They stay on your device.</p>
      <div class="kv">${HEADERS_HELP.map(([k, v]) => `<div>${esc(k)}</div><div>${esc(v)}</div>`).join('')}</div></details>`;
  }

  function headersHtml(h) {
    const who = [['Claims to be from', h.from ? `${h.from.name ? esc(h.from.name) + ' ' : ''}<code>${esc(h.from.address)}</code>` : 'Not shown'], ['Replies go to', h.replyTo ? `<code>${esc(h.replyTo.address)}</code>` : 'Same as above'], ['Bounces go to (Return-Path)', h.returnPath ? `<code>${esc(h.returnPath.address)}</code>` : 'Not shown'], h.subject && ['Subject', esc(h.subject)], h.date && ['Date', esc(h.date)], h.messageIdDomain && ['Message ID made by', `<code>${esc(h.messageIdDomain)}</code>`]].filter(Boolean);
    const a = h.auth;
    const hops = h.hops.length ? `<ol class="list">${h.hops.map((x, i) => `<li><b>${i === 0 ? 'Started at' : i === h.hops.length - 1 ? 'Delivered by' : 'Passed through'}</b> <code>${esc(x.by || x.from || 'unknown server')}</code>${x.from && x.by ? ` <span class="muted">from</span> <code>${esc(x.from)}</code>` : ''}${x.ip ? ` <span class="muted">IP</span> <code>${esc(x.ip)}</code>` : ''}${x.date ? `<br><span class="muted">${esc(x.date)}</span>` : ''}</li>`).join('')}</ol><p class="muted">Read from the top: the first line is where the email started. Only the last few lines, added by your own provider, can be fully trusted; earlier lines can be faked by the sender.</p>` : '<p class="empty">No delivery hops (Received lines) were pasted.</p>';
    return `<section aria-labelledby="ct-h-hdr"><h3 id="ct-h-hdr">Email headers</h3>
      <div class="linkcard"><div class="top"><b>Who sent it</b><span class="tag">${h.headerCount} header lines</span></div>${sigList(h.signals.filter(s => s.strength !== 'weak'))}</div>
      <div class="kv">${who.map(([k, v]) => `<div>${esc(k)}</div><div>${v}</div>`).join('')}</div>
    </section>
    <section aria-labelledby="ct-h-auth"><h3 id="ct-h-auth">Sender checks by your email provider</h3>
      ${a.present ? `<div class="kv"><div>Server allowed to send (SPF)</div><div>${authCell(a.spf)}${a.spfDomain ? ` · <code>${esc(a.spfDomain)}</code>` : ''}</div><div>Digital signature (DKIM)</div><div>${authCell(a.dkim)}${a.dkimDomains.length ? ` · <code>${esc(a.dkimDomains.join(', '))}</code>` : ''}</div><div>Anti-spoofing policy (DMARC)</div><div>${authCell(a.dmarc)}</div>${a.server ? `<div>Checked by</div><div><code>${esc(a.server)}</code></div>` : ''}</div>
      <p class="muted">We read the top Authentication-Results line, which your own provider adds when you copy the full headers; a sender can fake lines lower down. A pass means the email came from the domain shown, nothing more. Scammers can register a lookalike domain and pass every check.</p>` : '<p class="empty">No Authentication-Results line was pasted, so we cannot see the checks.</p>'}
      ${h.signals.some(s => s.strength === 'weak') ? `<details><summary>Minor notes (${h.signals.filter(s => s.strength === 'weak').length})</summary>${sigList(h.signals.filter(s => s.strength === 'weak'))}</details>` : ''}
    </section>
    <section aria-labelledby="ct-h-hops"><h3 id="ct-h-hops">Delivery route (${h.hops.length} hop${h.hops.length === 1 ? '' : 's'})</h3>${hops}</section>`;
  }

  function phoneHtml(p) {
    const meta = [p.country, p.kind, p.operator && `first issued by ${p.operator}`].filter(Boolean);
    return `<div class="linkcard"><div class="top"><code>${esc(p.display)}</code>${meta.map(m => `<span class="tag">${esc(m)}</span>`).join('')}</div>${sigList(p.signals)}
      ${p.operator ? '<p class="muted">People can keep their number when they switch operator, so the operator may have changed.</p>' : ''}${linkGrid(p.links)}</div>`;
  }
  function emailHtml(e) {
    return `<div class="linkcard"><div class="top"><code>${esc(e.address)}</code>${e.role ? `<span class="tag">${esc(e.role)}</span>` : ''}<span class="tag">${esc(e.kind)}</span></div>${sigList(e.signals)}${linkGrid(e.links)}</div>`;
  }

  function render(c) {
    const tab = $('#tab-contact'), p = SB.panel('contact'); if (!tab || !p) return;
    const r = c && c.contact;
    tab.hidden = !(r && r.found);
    if (!r || !r.found) { if (tab.getAttribute('aria-selected') === 'true') SB.showTab('deduction'); p.innerHTML = ''; return; }
    const top = r.reasons.slice(0, 5);
    p.innerHTML = `
      <section aria-labelledby="ct-h-sum"><h3 id="ct-h-sum">Sender check</h3>
        <p class="muted">Checked on your device. Nothing here was sent anywhere. We never look up who owns a number or address.</p>
        ${top.length ? `<ul class="list">${top.map(x => `<li>${weightTag(x.strength)} ${esc(x.text)}</li>`).join('')}</ul>` : '<p>No warning signs in the sender details. Stay careful: scammers also use clean-looking numbers and addresses.</p>'}
        ${r.actions.length ? `<div class="advice"><b>What to do now</b><ul>${r.actions.map(a => `<li>${a.href ? `<a href="${safeHref(a.href)}">${esc(a.text)}</a>` : esc(a.text)}</li>`).join('')}</ul></div>` : ''}
      </section>
      ${r.headers ? headersHtml(r.headers) : ''}
      ${r.phones.length ? `<section aria-labelledby="ct-h-ph"><h3 id="ct-h-ph">Phone number${r.phones.length > 1 ? 's' : ''}</h3>${r.phones.map(phoneHtml).join('')}</section>` : ''}
      ${r.emails.length ? `<section aria-labelledby="ct-h-em"><h3 id="ct-h-em">Email address${r.emails.length > 1 ? 'es' : ''}</h3>${r.emails.map(emailHtml).join('')}
        <p class="muted">Throwaway-inbox check uses a built-in list of ${DISPOSABLE.size} services.${extraDisposable ? ` Also checked against the full community list (${extraDisposable.size.toLocaleString()} domains).` : ''}</p>
        ${extraDisposable ? '' : `<button type="button" class="ghost sm" id="ct-disposable">Check against the full public list</button> <span class="muted" id="ct-disposable-note">Downloads the free community list (CC0) from GitHub; your address is not sent.</span>`}</section>` : ''}
      <section>${helpHtml(!r.headers && r.emails.length > 0)}</section>`;
    const btn = $('#ct-disposable');
    if (btn) btn.addEventListener('click', async () => {
      btn.disabled = true; btn.textContent = 'Downloading…';
      try { extraDisposable = await loadDisposableList(); apply(c, false); SB.toast('Checked against the full throwaway-inbox list'); }
      catch (e) { btn.disabled = false; btn.textContent = 'Try again'; const n = $('#ct-disposable-note'); if (n) n.textContent = 'Could not download the list (' + e.message + '). The built-in check still applies.'; }
    });
  }

  document.addEventListener('sb:case', e => apply(e.detail, true));
  document.addEventListener('sb:case-complete', e => { if (e.detail && e.detail.contact) { observations(e.detail); SB.renderAll(); render(e.detail); } });
  document.addEventListener('click', e => { if (e.target.closest('#history-list .hist')) setTimeout(() => apply(SB.current, false), 0); });
  if (typeof SB.openCase === 'function') { const open = SB.openCase; SB.openCase = id => { const ok = open(id); if (ok) apply(SB.current, false); return ok; }; }
})();
