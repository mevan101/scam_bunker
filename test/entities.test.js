// Entity extraction (phones, wallets), signature-rule floor and benign-corpus checks. Run: npm test
const fs = require('fs'), path = require('path'), vm = require('vm');
const ctx = { window: {}, URL }; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../public/scam.js'), 'utf8'), ctx);
const H = ctx.window.DeduceHeuristics;
let fail = 0; const check = (ok, msg) => { if (!ok) fail++; console.log(`${ok ? '✓' : '✗'} ${msg}`); };
const E = t => H.analyze({ text: t }).entities;

// ----- Phones -----
const phones = [
  ['Call +880 1712-345678 now', '+8801712345678'], ['bKash number 01812345678', '+8801812345678'], ['WhatsApp 008801912345678', '+8801912345678'],
  ['ফোন করুন ০১৭১২৩৪৫৬৭৮', '+8801712345678'], ['Office +880 2 9876543', '+88029876543'], ['Text +1 (415) 555-2671', '+14155552671'],
  ['call (415) 555-2671 today', '+14155552671'], ['ring +44 7700 900123', '+447700900123'], ['my UK mobile 07700 900123', '+447700900123'],
  ['+91 98765 43210 on WhatsApp', '+919876543210'], ['Reach me on +62 812 3456 7890', '+6281234567890'],
];
for (const [t, want] of phones) { const got = E(t).phones; check(got.length === 1 && got[0] === want, `phone "${t}" → ${got.join(', ') || 'none'} (want ${want})`); }
const notPhones = ['Meeting 2024-11-26 10', 'logged 2024 11 26 1030', 'Born 26/11/2024 at noon', 'Order #20241126103 shipped', 'Invoice no. 4410023981 attached',
  'Tracking number: 9400111899223344556677', 'server 192.168.10.254', 'version 10.4.22.1', 'pin 1111111111', 'code 0123456789', 'ref 123456789012', 'Total 1,234,567.89',
  '+880 123 45', '+1 0123456789'];
for (const t of notPhones) { const got = E(t).phones; check(got.length === 0, `not a phone: "${t}" → ${got.join(', ') || 'none'}`); }
check(H.normalizePhone('01712-345678').country === 'BD', 'normalizePhone marks Bangladesh numbers');

// ----- Wallets (all synthetic: the payload bytes spell "scam-bunker-test...", invented for tests) -----
const VALID = {
  'Tron (USDT-TRC20)': 'TLVKmCi9zZ5MMLmM3xzN3MhNLhscYPMZUm', Bitcoin: '1BX7m9LRqpxQCAhiThLeXD1ERkndYSpTka',
  'Bitcoin/P2SH': '3CD8ggpsPjGnHLQ9ao1EwqNAaH5MQzhP5B', 'Bitcoin/bech32': 'bc1qwd3kzmfdvf6ku6m9wgkhgetnwskhwurt45p348',
  'Bitcoin/bech32m': 'bc1pwd3kzmfdvf6ku6m9wgkhgetnwskhgctswfhk7apdwpex7emjv9kstudycs', 'EVM/EIP-55': '0x7363616d2D62756e6b65722D746573742d65766D',
};
for (const [k, a] of Object.entries(VALID)) { const w = E(`send to ${a} today`).wallets; check(w.length === 1 && w[0].addr === a, `valid ${k} wallet kept (${w[0]?.checksum})`); }
check(E('to 0x7363616d2d62756e6b65722d746573742d65766d').wallets[0]?.checksum === 'unchecked', 'lowercase EVM address kept as format-valid, checksum unchecked');
const INVALID = ['TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT', 'TLVKmCi9zZ5MMLmM3xzN3MhNLhscYPMZUn', '1BX7m9LRqpxQCAhiThLeXD1ERkndYSpTkb', 'bc1qwd3kzmfdvf6ku6m9wgkhgetnwskhwurt45p349', '0x7363616d2D62756e6b65722D746573742d65766d', 'Reference 3Jk9ZpQ2mWx7Yb4Nc6Vd8Te1Rf5Gh2Kq'];
for (const a of INVALID) { const e = E(`pay ${a}`); check(e.wallets.length === 0, `checksum-invalid / random string rejected: ${a.slice(-12)} (${e.rejectedWallets.length} rejected)`); }
const shared = H.analyze({ text: 'USDT contract TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t' });
check(shared.entities.wallets.length === 0 && shared.entities.sharedWallets.length === 1 && shared.verdict === 'No strong red flags', `shared USDT contract alone is not identifying (${shared.verdict}, ${shared.score})`);
check(H.analyze({ text: 'send to TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT' }).score < H.analyze({ text: 'send to TLVKmCi9zZ5MMLmM3xzN3MhNLhscYPMZUm' }).score, 'only checksum-valid wallets add score');
check(H.eip55('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed') === '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', 'EIP-55 reference vector');

// ----- Signature rules: alone → Suspicious at most; with a payment / credential ask → at least Likely scam -----
const sig = [
  ['pay-to-withdraw', 'You must deposit 500 USDT to withdraw your profits'],
  ['seed-phrase', 'Please enter your 12 word seed phrase to verify'],
  ['hi-mum', 'Hi Mum, this is my new number, my phone broke. Can you send me £400 for a bill?'],
  ['sextortion', 'I have recorded you through your webcam. Send 1500 USD in bitcoin to this wallet'],
  ['gift-card', 'Buy three Apple gift cards and send me the codes'],
  ['bn-mfs-pin', 'আমি বিকাশ অফিস থেকে বলছি, আপনার একাউন্ট চালু রাখতে পিন নম্বরটি বলুন'],
  ['i18n-pay-to-withdraw', 'Debe depositar 500 USDT para poder retirar sus ganancias'],
  ['i18n-seed-phrase', 'Por favor ingresa tu frase semilla para verificar la cuenta'],
  ['i18n-hi-mum', 'Coucou maman, j\'ai perdu mon téléphone, voici mon nouveau numéro. Tu peux me faire un virement de 400 € ?'],
  ['account-recovery-help', 'Hey, I sent a code to your phone by mistake, can you forward it to me?'],
  ['loan-harassment', 'Repay today or we will send your morphed photos to all your contacts'],
  ['bn-loan-harassment', 'লোনের টাকা আজকে না দিলে আপনার ছবি এডিট করে সব কন্টাক্টে পাঠিয়ে দিব'],
  ['bn-customs', 'আপনার নামে একটি গিফট পার্সেল এসেছে, এয়ারপোর্টে কাস্টমস ফি ১৫০০০ টাকা বিকাশ করুন'],
  ['double-crypto', 'Send 0.1 BTC to the address and you will get double back'],
  ['marketplace-code', 'Before I buy I need to make sure you are real. I will send you a code, tell me what it says'],
];
for (const [id, t] of sig) { const v = H.analyze({ text: t }); check(v.hits.some(h => h.id === id && h.signature) && v.score >= 55 && ['Likely scam', 'Scam'].includes(v.verdict), `signature ${id} + ask → ${v.verdict} (${v.score}, ${v.category})`); }
const mumPhotos = H.analyze({ text: 'Hi Mum, this is my new number. Can you send me some photos of the dog?' });
check(!mumPhotos.signatureFloor && !['Likely scam', 'Scam'].includes(mumPhotos.verdict), `a photo request is not a payment ask → ${mumPhotos.verdict} (${mumPhotos.score})`);
const mumUsd = H.analyze({ text: 'Hi Mum, this is my new number. Can you send 500 USD today?' });
check(mumUsd.signatureFloor && mumUsd.verdict === 'Likely scam', `an amount with a currency code is a payment ask → ${mumUsd.verdict} (${mumUsd.score})`);
const mumOnly = H.analyze({ text: 'Hi Mum, this is my new number, my phone broke' });
check(!mumOnly.signatureFloor && mumOnly.verdict === 'Suspicious', `signature without an ask is not floored → ${mumOnly.verdict} (${mumOnly.score})`);
check(H.analyze({ text: 'Buy three Apple gift cards and send me the codes' }).category === 'Gift-card payment scam', 'gift-card signature gets a scheme category');
const all = H.RULES.filter(r => r.signature).map(r => r.id); const tested = new Set(sig.map(s => s[0]));
check(all.every(id => tested.has(id)), `every signature rule has a floor test (${all.join(', ')})`);

// ----- Benign corpus: no false positives; non-context rules must stay at <= 1% hit rate -----
const BENIGN = require('./fixtures/benign-corpus.js');
const flagged = BENIGN.map(t => [t, H.analyze({ text: t })]).filter(([, v]) => v.verdict !== 'No strong red flags');
for (const [t, v] of flagged) check(false, `benign flagged: "${t}" → ${v.verdict} (${v.score}) ${v.hits.map(h => h.id).join(',')}`);
check(!flagged.length, `${BENIGN.length} benign messages, ${flagged.length} flagged`);
const counts = {}; for (const t of BENIGN) for (const h of H.analyze({ text: t }).hits) counts[h.id] = (counts[h.id] || 0) + 1;
const over = H.RULES.filter(r => (counts[r.id] || 0) / BENIGN.length > 0.01);
console.log('  benign-corpus hit rate > 1%:', over.map(r => `${r.id}${r.context ? ' (context)' : ''} ${((counts[r.id] / BENIGN.length) * 100).toFixed(1)}%`).join(', ') || 'none');
check(over.every(r => r.context), 'only low-weight context rules exceed a 1% benign hit rate');
process.exit(fail ? 1 : 0);
