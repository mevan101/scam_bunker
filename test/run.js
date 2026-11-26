// Zero-dependency tests for the heuristic engine. Run: npm test
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');
const ctx = { window: {}, URL }; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../public/scam.js'), 'utf8'), ctx);
const H = ctx.window.DeduceHeuristics;
const cases = [
  ['pig-butchering DM', { text: 'Sorry, wrong number. My uncle is an expert trader, guaranteed 30% daily profit on USDT. Send to TLVKmCi9zZ5MMLmM3xzN3MhNLhscYPMZUm. Act now!' }, v => ['Scam', 'Likely scam'].includes(v.verdict)],
  ['phishing SMS', { text: 'Your account has been suspended. Verify your identity now', url: 'http://chase.com.secure-verify-account.top/signin' }, v => ['Scam', 'Likely scam'].includes(v.verdict)],
  ['job scam', { text: 'Remote job, no experience needed, earn $300 per day. Pay a training fee for the starter kit. Contact us on Telegram' }, v => ['Scam', 'Likely scam'].includes(v.verdict)],
  ['misinformation', { text: "SHARE BEFORE IT'S DELETED! Doctors don't want you to know this miracle cure. Wake up, do your own research" }, v => v.verdict === 'Misleading / manipulated'],
  ['wrong-number opener', { text: 'Hello, is this Anna?' }, v => v.hits.some(h => h.id === 'wrong-number')],
  ['date is not a phone', { text: 'Meeting moved to 2024-11-26 10 in room 4' }, v => v.entities.phones.length === 0],
  ['invalid TRON wallet ignored', { text: 'Send to TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT' }, v => v.entities.wallets.length === 0],
  ['benign message', { text: 'Hey, are we still on for lunch on Thursday at the usual place?' }, v => v.verdict === 'No strong red flags'],
];
let fail = 0;
for (const [name, input, ok] of cases) { const v = H.analyze(input); const pass = ok(v); if (!pass) fail++; console.log(`${pass ? '✓' : '✗'} ${name} → ${v.verdict} (${v.score})`); }
const typo = H.analyzeUrl('https://paypa1.com/login'); assert(typo.risk >= 30, 'typosquat detection'); console.log('✓ typosquat paypa1.com → risk', typo.risk);
const puny = H.analyzeUrl('https://xn--pple-43d.com'); assert(puny.risk >= 30, 'punycode detection'); console.log('✓ punycode → risk', puny.risk);
for (const f of ['server.js', 'public/app.js', 'public/forensics.js', 'public/scam.js', 'public/custody.js', 'public/video.js']) new vm.Script(fs.readFileSync(path.join(__dirname, '..', f), 'utf8'));
console.log('✓ all sources parse');
process.exit(fail ? 1 : 0);
