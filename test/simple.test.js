// Simple mode: plain-language answers and intake selection (public/simple.js pure helpers). Run: npm test
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');
const ctx = { window: {}, URL }; vm.createContext(ctx);
for (const f of ['public/scam.js', 'public/simple.js']) vm.runInContext(fs.readFileSync(path.join(__dirname, '..', f), 'utf8'), ctx);
const H = ctx.window.DeduceHeuristics, S = ctx.window.ScamBunkerSimple;
assert(S, 'simple.js exports window.ScamBunkerSimple');

// Invented examples only (no real people's data).
const CASES = [
  ['bank SMS', { text: 'ALERT: Unusual sign-in detected. Your account has been suspended. Verify your identity and confirm your card details immediately: http://examplebank.com.secure-verify-account.top/signin', url: '' }, /very likely a scam|looks like a scam/],
  ['job offer', { text: 'You have been selected for a remote job, no experience required. Earn $350 per day. You need to pay a $95 training fee for the starter kit. Contact our HR manager on Telegram.', url: '' }, /scam|warning signs/],
  ['viral claim', { text: "SHARE BEFORE IT'S DELETED!! Doctors don't want you to know this miracle cure. Do your own research. Wake up people!", url: '' }, /false or misleading/],
  ['benign', { text: 'Hey, are we still on for lunch on Thursday at the usual place?', url: '' }, /No warning signs/],
];
const JARGON = /\b(B[1-6]|C[1-6]|heuristic|signature|regex|OSINT|C2PA|IPTC|EXIF)\b/;
for (const [name, input, expect] of CASES) {
  const h = H.analyze(input);
  const c = { text: input.text, url: input.url, heuristics: h, platform: h.platform };
  const v = { verdict: h.verdict, category: h.category, risk: h.score };
  const vc = S.verdictCopy(v, c), reasons = S.plainReasons(c), acts = S.plainActions(c, v), checks = S.selfChecks(c, v);
  assert(expect.test(vc.title), `${name}: verdict sentence "${vc.title}"`);
  assert(['Low', 'Medium', 'High', 'Very high'].includes(vc.riskWord), `${name}: risk word`);
  assert(reasons.length >= 1 && reasons.length <= 5, `${name}: 1-5 reasons (${reasons.length})`);
  for (const r of reasons) {
    assert(r.text && !JARGON.test(r.text), `${name}: plain reason "${r.text}"`);
    if (r.source === 'rules') assert(input.text.toLowerCase().includes(r.quote.replace(/…$/, '').toLowerCase()), `${name}: reason quotes the exact words ("${r.quote}")`);
  }
  assert(acts.length >= 1 && acts.every(a => a.text && (!a.href || /^https:\/\//.test(a.href))), `${name}: actions`);
  assert(checks.every(x => /^https:\/\//.test(x.href)), `${name}: self-checks are https links`);
  console.log(`✓ ${name} → ${vc.title} · risk ${vc.riskWord} · ${reasons.length} reasons · ${acts.length} actions`);
}

// Scam answers always lead with "don't pay / don't share codes".
{ const h = H.analyze({ text: CASES[0][1].text }); const acts = S.plainActions({ heuristics: h }, { verdict: 'Scam', category: h.category }); assert(/Don’t send money/.test(acts[0].text)); console.log('✓ scam checklist starts with "don’t send money"'); }

// Rule hits may carry their own plain sentence; it wins over the shell's mapping.
{ const c = { heuristics: { hits: [{ id: 'urgency', category: 'Pressure', weight: 16, label: 'x', match: 'act now', plain: 'Custom plain sentence.' }], links: [], entities: {}, coordination: [] } };
  assert.strictEqual(S.plainReasons(c)[0].text, 'Custom plain sentence.'); console.log('✓ hit.plain overrides the built-in sentence'); }

// Every rule has a plain sentence (its own `plain` field from scam.js, else via its id, its base id, or its category).
for (const r of H.RULES) assert(S.plainFor({ id: r.id, category: r.category, label: r.label, plain: r.plain }) !== `${r.label}.`, `rule ${r.id} has a plain sentence`);
console.log(`✓ all ${H.RULES.length} rules have plain sentences`);

// Risk words and hidden-data copy.
assert.deepStrictEqual([0, 24, 25, 49, 50, 69, 70, 100].map(S.riskWord), ['Low', 'Low', 'Medium', 'Medium', 'High', 'High', 'Very high', 'Very high']);
assert(/exact place it was taken/.test(S.plainHidden(['GPS location: 51.5, -0.12'])[0]));
console.log('✓ risk words and hidden-data sentences');

// Intake: the best adapter above 0.5 wins; registered adapters can outrank the built-ins.
const pick = (input, list = S.BUILTIN_INTAKES) => S.pickIntake(list, input)?.id || null;
assert.strictEqual(pick({ text: 'example-shop.top/login', file: null }), 'url');
assert.strictEqual(pick({ text: 'https://example.com/a?b=c', file: null }), 'url');
assert.strictEqual(pick({ text: 'Your parcel is held, pay the fee at example.com', file: null }), 'text');
assert.strictEqual(pick({ text: '', file: { name: 'shot.png', type: 'image/png', size: 10 } }), 'image');
assert.strictEqual(pick({ text: '', file: { name: 'clip.mov', type: '', size: 10 } }), 'video');
assert.strictEqual(pick({ text: '  ', file: null }), null);
assert.strictEqual(pick({ text: '', file: { name: 'a.zip', type: 'application/zip', size: 1 } }), null);
const ocr = { id: 'ocr', label: 'Screenshot', detect: i => i.file && /image/.test(i.file.type) ? 0.97 : 0, extract: async () => ({ text: 'read' }) };
assert.strictEqual(pick({ text: '', file: { name: 's.png', type: 'image/png', size: 1 } }, [ocr, ...S.BUILTIN_INTAKES]), 'ocr');
const broken = { id: 'broken', detect: () => { throw new Error('x'); }, extract: async () => ({}) };
assert.strictEqual(pick({ text: 'hello there', file: null }, [broken, ...S.BUILTIN_INTAKES]), 'text');
console.log('✓ intake adapter selection (URL, text, image, video, unknown, registered, throwing)');
