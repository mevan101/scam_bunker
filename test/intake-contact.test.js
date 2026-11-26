// Zero-dependency tests for public/intake-contact.js (email headers, phone numbers, email addresses). Run: npm test
// All fixtures are invented. Domains use reserved names (example.org, .example, .invalid, RFC 2606); UK numbers use the
// Ofcom drama range 07700 900xxx; Bangladesh has no reserved range, so the BD numbers below are made-up placeholders.
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');
const ctx = { window: {}, URL, TextDecoder, atob, Buffer }; vm.createContext(ctx);
for (const f of ['public/scam.js', 'public/intake-contact.js']) vm.runInContext(fs.readFileSync(path.join(__dirname, '..', f), 'utf8'), ctx);
const C = ctx.window.ScamBunkerContact;
const plain = x => JSON.parse(JSON.stringify(x));
const fx = n => fs.readFileSync(path.join(__dirname, 'fixtures/contact', n), 'utf8');
const texts = list => list.map(s => s.text).join('\n');

const tests = [];
const test = (name, fn) => tests.push([name, fn]);

// ---------- Email headers ----------
test('parses folded headers, decodes the subject and orders hops oldest first', () => {
  const h = C.analyzeHeaders(fx('spoofed-paypal.eml'));
  assert.strictEqual(h.subject, 'Your account is limited');
  assert.strictEqual(h.from.address, 'billing@paypa1-billing.example');
  assert.strictEqual(h.from.name, 'PayPal Service');
  assert.strictEqual(h.replyTo.address, 'paypal.refund.desk.invented@gmail.com');
  assert.strictEqual(h.returnPath.address, 'bounce-77@mailer.invalid-sender.example');
  assert.strictEqual(h.messageIdDomain, 'bulk-sender.example');
  assert.strictEqual(h.hops.length, 2);
  assert.strictEqual(h.hops[0].ip, '203.0.113.45', 'origin hop first');
  assert.deepStrictEqual(plain({ spf: h.auth.spf, dkim: h.auth.dkim, dmarc: h.auth.dmarc }), { spf: 'fail', dkim: 'fail', dmarc: 'fail' });
  assert.match(h.body, /Confirm your details/);
});
test('flags spoofing: brand name on another domain, lookalike, reply-to to free-mail, failed checks', () => {
  const h = C.analyzeHeaders(fx('spoofed-paypal.eml')), t = texts(h.signals);
  assert.match(t, /says it is from PayPal/);
  assert.match(t, /paypa1-billing\.example: Look-alike spelling of "paypal"/);
  assert.match(t, /If you press Reply, your answer goes to paypal\.refund\.desk\.invented@gmail\.com/);
  assert.match(t, /failed the sender's anti-spoofing policy \(DMARC\)/);
  assert.match(t, /SPF failed/); assert.match(t, /DKIM failed/);
  assert.match(t, /Return-Path/);
  assert.strictEqual(h.signals[0].strength, 'strong', 'strongest first');
  assert(h.signals.find(s => /Reply/.test(s.text)).strength === 'strong', 'reply-to free-mail for a company sender is strong');
});
test('header sender checks are never graded above moderate and only the top Authentication-Results line is read', () => {
  const h = C.analyzeHeaders(fx('spoofed-paypal.eml'));
  assert(h.signals.filter(s => /SPF|DKIM|DMARC|sender-check/.test(s.text)).every(s => s.strength !== 'strong'));
  const forged = 'Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=shop.example; dkim=none; dmarc=fail header.from=shop.example\nReceived: from a by mx.example.org; Mon, 2 Nov 2026 10:00:00 +0000\nAuthentication-Results: fake.example; spf=pass; dkim=pass header.d=shop.example; dmarc=pass\nReceived-SPF: pass\nFrom: Shop <news@shop.example>\nSubject: x\n';
  const f = C.analyzeHeaders(forged);
  assert.deepStrictEqual(plain([f.auth.spf, f.auth.dmarc, f.auth.server, !!f.passed]), ['fail', 'fail', 'mx.example.org', false]);
  assert.match(texts(f.signals), /We only read the top one/);
  const noAr = C.analyzeHeaders('Received-SPF: pass\nReceived: from a by b; Mon, 2 Nov 2026 10:00:00 +0000\nFrom: Shop <news@shop.example>\nSubject: x\n');
  assert.strictEqual(noAr.auth.spf, 'missing', 'Received-SPF alone is not trusted');
});
test('clean newsletter: all checks pass and no moderate or strong signals', () => {
  const h = C.analyzeHeaders(fx('clean-newsletter.eml'));
  assert.strictEqual(h.passed, true);
  assert.deepStrictEqual(plain(h.signals.filter(s => s.strength !== 'weak').map(s => s.text)), []);
});
test('display-name spoofing with a free-mail sender and an address inside the name', () => {
  const h = C.analyzeHeaders('Received: from x.example by mx.example.org; Mon, 2 Nov 2026 10:00:00 +0000\nFrom: "service@paypal.com" <helpdesk.invented.123@gmail.com>\nSubject: Refund\n\nHi');
  const t = texts(h.signals);
  assert.match(t, /name shows one email address \(service@paypal\.com\) but the real address is helpdesk\.invented\.123@gmail\.com/);
  assert.match(t, /says it is from PayPal, but it was sent from a free personal account/);
  assert.match(t, /no "Authentication-Results" line/);
});
test('free-mail sender claiming to be a company (no known brand)', () => {
  const h = C.analyzeHeaders('Return-Path: <acme.hr.invented@outlook.com>\nFrom: Acme Recruitment Team <acme.hr.invented@outlook.com>\nMessage-ID: <id1.invented@outlook.com>\nSubject: Offer\n');
  assert.match(texts(h.signals), /sounds like a company or official team, but it was sent from a free personal account/);
});
test('Q-encoded display names are decoded before the brand check', () => {
  assert.strictEqual(C.decodeWords('=?UTF-8?Q?Pay=50al_Support?='), 'PayPal Support');
  const h = C.analyzeHeaders('Received: from a by b; Mon, 2 Nov 2026 10:00:00 +0000\nFrom: =?UTF-8?Q?Pay=50al_Support?= <x.invented@yahoo.com>\nSubject: hi\n');
  assert.match(texts(h.signals), /says it is from PayPal/);
});
test('the genuine brand domain is not flagged', () => {
  const h = C.analyzeHeaders('Received: from a by b; Mon, 2 Nov 2026 10:00:00 +0000\nAuthentication-Results: mx.example.org; spf=pass smtp.mailfrom=paypal.com; dkim=pass header.d=paypal.com; dmarc=pass header.from=paypal.com\nFrom: PayPal <service@mail.paypal.com>\nSubject: Receipt\n');
  assert.deepStrictEqual(plain(h.signals.filter(s => s.strength !== 'weak').map(s => s.text)), []);
});
test('header detection: confident for real headers, zero for ordinary text', () => {
  assert(C.headerScore(fx('spoofed-paypal.eml')) >= 0.9);
  assert.strictEqual(C.headerScore('From: Mum\nHi love, can you call me?'), 0);
  assert.strictEqual(C.headerScore('Hey, are we still on for lunch on Thursday?'), 0);
});
test('Received parsing reads by/from/IP/date', () => {
  const r = C.parseReceived('from mail.a.example (mail.a.example [192.0.2.10]) by mx.b.example with ESMTP; Mon, 2 Nov 2026 10:00:00 +0000');
  assert.deepStrictEqual(plain({ from: r.from, by: r.by, ip: r.ip }), { from: 'mail.a.example', by: 'mx.b.example', ip: '192.0.2.10' });
  assert(r.time > 0);
});
test('out-of-order hop timestamps are a weak note', () => {
  const h = C.analyzeHeaders('Received: from b by c; Mon, 2 Nov 2026 08:00:00 +0000\nReceived: from a by b; Mon, 2 Nov 2026 10:00:00 +0000\nFrom: a@shop.example\nSubject: x\n');
  assert(h.signals.some(s => /out of order/.test(s.text) && s.strength === 'weak'));
});

// ---------- Phone numbers ----------
test('normalises Bangladesh local mobiles and names the original operator', () => {
  const p = C.analyzePhone('01900-000123');
  assert.strictEqual(p.e164, '+8801900000123'); assert.strictEqual(p.country, 'Bangladesh'); assert.strictEqual(p.operator, 'Banglalink');
  assert.strictEqual(C.analyzePhone('+880 1300 000123').operator, 'Grameenphone');
  assert.strictEqual(C.analyzePhone('+880 1600 000123').operator, 'Robi (formerly Airtel)');
  assert.strictEqual(C.analyzePhone('+880 1500 000123').operator, 'Teletalk');
});
test('country from calling code (longest prefix wins)', () => {
  assert.strictEqual(C.analyzePhone('+44 7700 900123').country, 'United Kingdom');
  assert.strictEqual(C.analyzePhone('+234 800 000 0123').country, 'Nigeria');
  assert.strictEqual(C.analyzePhone('+971 50 000 0123').country, 'United Arab Emirates');
  assert.strictEqual(C.analyzePhone('00 91 98000 00123').country, 'India');
});
test('premium-rate, IRSF and Caribbean +1 callback numbers are flagged', () => {
  assert.match(texts(C.analyzePhone('+44 909 000 0123').signals), /UK premium-rate/);
  assert.match(texts(C.analyzePhone('+882 1600 0123').signals), /one ring/);
  const j = C.analyzePhone('+1 876 555 0123');
  assert.strictEqual(j.country, 'Jamaica'); assert.match(texts(j.signals), /looks like a US or Canada number but is Jamaica/);
  assert.deepStrictEqual(plain(C.analyzePhone('+1 212 555 0123').signals), []);
});
test('bKash message from a foreign number is strong; from an ordinary mobile is moderate', () => {
  const ctxText = 'bKash customer care: your account will be blocked. Call +44 7700 900123 now.';
  const f = C.analyzePhone('+44 7700 900123', { context: ctxText });
  assert.strictEqual(f.signals[0].strength, 'strong'); assert.match(f.signals[0].text, /mentions bKash, but this number is from United Kingdom/);
  const l = C.analyzePhone('01900-000123', { context: 'আমি বিকাশ অফিস থেকে বলছি, পিন নম্বর বলুন' });
  assert.match(texts(l.signals), /mentions bKash, but this is an ordinary mobile number/);
  assert.match(l.signals[0].detail, /16247/);
});
test('local bank but foreign number uses the home country', () => {
  const p = C.analyzePhone('+234 800 000 0123', { context: 'Your bank card is blocked, call us', home: 'GB' });
  assert.match(texts(p.signals), /talks about a bank, but the number is from Nigeria/);
  assert.deepStrictEqual(plain(C.analyzePhone('+44 7700 900123', { context: 'Your bank card is blocked', home: 'GB' }).signals), []);
});
test('fake "Cash In" SMS and agent-number cash-out script', () => {
  const p = C.analyzePhone('01900-000123', { context: 'Cash In Tk 5,000.00 from 01900-000123 successful. bKash. Sent by mistake, please send money back to agent number' });
  const t = texts(p.signals);
  assert.match(t, /"you received money" message sent from an ordinary mobile/); assert.match(t, /agent number/);
});
test('check-it-yourself links are search and WhatsApp only (no owner lookups)', () => {
  const p = C.analyzePhone('+44 7700 900123');
  assert.deepStrictEqual(plain(p.links.map(l => new URL(l.href).hostname)), ['duckduckgo.com', 'duckduckgo.com', 'wa.me']);
  assert.strictEqual(p.links[2].href, 'https://wa.me/447700900123');
  assert.match(decodeURIComponent(p.links[1].href), /"07700900123" scam/);
});
test('dates, times and junk are not phone numbers', () => {
  for (const s of ['2024-11-26 10', '1111111111', 'hello', '12']) assert.strictEqual(C.analyzePhone(s), null, s);
});

// ---------- Email addresses ----------
test('free-mail, own domain and disposable inboxes', () => {
  assert.strictEqual(C.analyzeEmail('someone.invented@gmail.com').kind, 'Free personal account');
  assert.strictEqual(C.analyzeEmail('team@shop.example').kind, 'Own domain');
  const d = C.analyzeEmail('x.invented@mailinator.com');
  assert.strictEqual(d.kind, 'Throwaway inbox'); assert.strictEqual(d.signals[0].strength, 'strong');
});
test('brand in a free-mail address and lookalike domains', () => {
  assert.match(texts(C.analyzeEmail('amazon.refunds.invented@gmail.com').signals), /uses the name Amazon but is a free personal address/);
  assert.match(texts(C.analyzeEmail('help@paypa1.com').signals), /Look-alike|One letter away/);
  assert.match(texts(C.analyzeEmail('help@microsoft-support.example').signals), /brand name "microsoft"/);
  assert.deepStrictEqual(plain(C.analyzeEmail('service@paypal.com').signals), []);
});
test('an extra runtime list extends the disposable check', () => {
  assert.strictEqual(C.analyzeEmail('a@new-throwaway.example').kind, 'Own domain');
  assert.strictEqual(C.analyzeEmail('a@new-throwaway.example', { disposable: new Set(['new-throwaway.example']) }).kind, 'Throwaway inbox');
});
test('loadDisposableList parses the community list format and rejects tiny responses', async () => {
  const body = Array.from({ length: 150 }, (_, i) => `throwaway${i}.example`).join('\n') + '\n# comment\n';
  const set = await C.loadDisposableList(async () => ({ ok: true, text: async () => body }));
  assert(set.has('throwaway7.example')); assert(!set.has('# comment'));
  await assert.rejects(C.loadDisposableList(async () => ({ ok: true, text: async () => 'a.example' })));
  await assert.rejects(C.loadDisposableList(async () => ({ ok: false, status: 503 })));
});
test('registrable domain handles two-part country suffixes', () => {
  assert.strictEqual(C.regDomain('mail.bank.com.bd'), 'bank.com.bd');
  assert.strictEqual(C.regDomain('a.b.shop.co.uk'), 'shop.co.uk');
  assert.strictEqual(C.regDomain('mx.example.org'), 'example.org');
});

// ---------- Whole-input scan and intake adapters ----------
test('scan of a message finds phones and emails with reasons and actions', () => {
  const r = C.scan('Nagad alert: your account will be blocked. Call +44 7700 900123 or email nagad.help.invented@gmail.com', { home: 'BD' });
  assert.strictEqual(r.phones.length, 1); assert.strictEqual(r.emails.length, 1);
  assert(r.reasons.length >= 2); assert.strictEqual(r.reasons[0].strength, 'strong');
  assert(r.actions.some(a => /16167/.test(a.text)));
  assert(r.actions.every(a => !a.href || /^https?:/.test(a.href)), 'only http(s) links');
});
test('scan of headers uses the header addresses and the body, not Received lines', () => {
  const r = C.scan(fx('spoofed-paypal.eml'), { home: null });
  assert(r.headers); assert.deepStrictEqual(plain(r.emails.map(e => e.role)), ['From', 'Reply-To', 'Return-Path']);
  assert.strictEqual(r.phones.length, 0, 'no phone numbers invented from header ids or dates');
  assert(r.actions.some(a => /Report it as phishing/.test(a.text)));
});
test('Bangla numerals are converted before phone matching', () => {
  const r = C.scan('আমি বিকাশ অফিস থেকে বলছি, ০১৯০০-০০০১২৩ নম্বরে পিন পাঠান', { home: 'BD' });
  assert.strictEqual(r.phones.length, 1); assert.strictEqual(r.phones[0].e164, '+8801900000123');
  for (const t of ['১. ০১৯০০-০০০১২৩ এ কল করুন', '1. 01900-000123 call', '2) 01900-000123']) assert.deepStrictEqual(plain(C.scan(t, { home: 'BD' }).phones.map(p => p.e164)), ['+8801900000123'], t);
});
test('a benign message produces nothing', () => {
  const r = C.scan('Hey, are we still on for lunch on Thursday at the usual place?', { home: 'GB' });
  assert.strictEqual(r.found, false); assert.deepStrictEqual(plain(r.reasons), []);
});
test('intake adapters follow the registerIntake contract', async () => {
  const by = Object.fromEntries(C.ADAPTERS.map(a => [a.id, a]));
  for (const a of C.ADAPTERS) { assert.strictEqual(typeof a.label, 'string'); assert.strictEqual(typeof a.detect, 'function'); assert.strictEqual(typeof a.extract, 'function'); }
  assert(by['email-headers'].detect({ text: fx('spoofed-paypal.eml') }) > 0.9);
  assert.strictEqual(by['email-headers'].detect({ text: 'Hi there' }), 0);
  assert.strictEqual(by['phone-number'].detect({ text: '+44 7700 900123' }), 0.9);
  assert.strictEqual(by['phone-number'].detect({ text: 'Call me on +44 7700 900123 tomorrow' }), 0);
  assert.strictEqual(by['email-address'].detect({ text: 'x.invented@mailinator.com' }), 0.9);
  assert.strictEqual(by['email-address'].detect({ text: '' }), 0);
  assert.strictEqual(by['phone-number'].detect({ file: {} }), 0, 'file-only input is not for these adapters');
  const out = await by['email-headers'].extract({ text: fx('spoofed-paypal.eml') });
  assert.match(out.text, /^Your account is limited\n\nYour account is limited\. Confirm/);
  assert(out.notes.length >= 3 && out.notes.every(n => typeof n === 'string'));
});
test('no real-looking personal data in fixtures: emails use reserved or invented names', () => {
  const all = fs.readdirSync(path.join(__dirname, 'fixtures/contact')).map(fx).join('\n') + fs.readFileSync(__filename, 'utf8');
  for (const m of all.match(/[\w.+-]+@[\w-]+(\.[\w-]+)+/g) || []) assert(/(\.example|\.invalid|example\.org|invented|paypal\.com$|^service@|^help@|^team@|^a@|^x@)/.test(m) || /\.example$/.test(m), 'suspicious fixture address ' + m);
});

(async () => {
  let fail = 0;
  for (const [name, fn] of tests) { try { await fn(); console.log('✓', name); } catch (e) { fail++; console.log('✗', name, '\n ', e.message); } }
  console.log(`${tests.length - fail}/${tests.length} passed`);
  process.exit(fail ? 1 : 0);
})();
