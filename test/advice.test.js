// Plain-language reasons and advice keys: every rule has both, hits expose them, ADVICE / REPORTING are well formed. Run: npm test
const fs = require('fs'), path = require('path'), vm = require('vm');
const ctx = { window: {}, URL }; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../public/scam.js'), 'utf8'), ctx);
const H = ctx.window.DeduceHeuristics;
let fail = 0; const check = (ok, msg) => { if (!ok) fail++; if (!ok || process.env.VERBOSE) console.log(`${ok ? '✓' : '✗'} ${msg}`); };

for (const r of H.RULES) {
  check(typeof r.plain === 'string' && /^[A-Z"]/.test(r.plain) && /[.!?]$/.test(r.plain) && r.plain.length >= 30 && r.plain.length <= 220, `${r.id}: plain is a short sentence (${r.plain})`);
  check(!!H.ADVICE[r.advice], `${r.id}: advice key "${r.advice}" exists in ADVICE`);
}
for (const [k, a] of Object.entries(H.ADVICE)) check(typeof a.action === 'string' && a.action.length > 20 && typeof a.report === 'boolean', `ADVICE.${k} has action text and report flag`);
const used = new Set(H.RULES.map(r => r.advice));
check(Object.keys(H.ADVICE).every(k => used.has(k) || ['block_report', 'contact_bank'].includes(k)), 'every ADVICE key is used by a rule (or is a general fallback)');
for (const cc of ['US', 'UK', 'IN', 'BD', 'EU']) {
  const r = H.REPORTING[cc];
  check(!!r && r.links.length > 0 && r.links.every(l => l.label && /^https:\/\/[^\s]+$/.test(l.url)) && (r.phones || []).every(ph => ph.label && /^\+?[\d ]{3,15}$/.test(ph.number)), `REPORTING.${cc}: ${r ? r.links.map(l => l.url).join(' ') : 'missing'}`);
}

const v = H.analyze({ text: 'Your parcel is held at the depot. Pay the customs fee of $3.99 to release it: http://parcel-hold.top/pay' });
const hit = v.hits.find(h => h.id === 'customs-fee');
check(!!hit && hit.plain && hit.advice === 'dont_pay', `hits expose plain + advice (${hit && hit.advice})`);
check(v.hits.every(h => !h.id || (h.plain && h.advice)), 'every rule hit carries plain + advice');
const a = H.adviceFor(v, 'UK');
check(a.reasons.length >= 1 && a.reasons[0].plain && a.actions.some(x => x.key === 'dont_pay' && x.text), `adviceFor gives reasons + actions (${a.actions.map(x => x.key).join(', ')})`);
check(a.report && a.report.name === 'United Kingdom', 'adviceFor adds the country reporting routes');
check(new Set(a.reasons.map(r => r.plain)).size === a.reasons.length, 'adviceFor de-duplicates reasons');
check(H.adviceFor(v).report === null && H.adviceFor(v, 'XX').report === null, 'no reporting block without a known country');
const clean = H.adviceFor(H.analyze({ text: 'Lunch on Thursday?' }), 'US');
check(!clean.reasons.length && !clean.actions.length && clean.report === null, 'benign text gets no reasons, actions or report block');
const share = H.adviceFor(H.analyze({ text: 'Share before it is deleted! Experts say this miracle cure works' }), 'US');
check(share.actions.every(x => x.key === 'check_before_sharing') && share.report === null, 'misinformation-only advice does not push a fraud report');

console.log(`${fail ? '✗' : '✓'} advice: ${H.RULES.length} rules with plain + advice, ${Object.keys(H.ADVICE).length} advice keys, ${Object.keys(H.REPORTING).length} countries`);
process.exit(fail ? 1 : 0);
