// Zero-dependency tests for evidence grading and estimative language (docs/METHODOLOGY.md 3.1-3.4).
// The module is loaded in a node vm without `document`, so only the pure functions run. Run: npm test
// All examples are invented.
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');
const ctx = { window: {} }; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../public/grading.js'), 'utf8'), ctx);
const G = ctx.window.ScamBunkerGrading;

let failed = 0;
function test(name, fn) { try { fn(); console.log(`✓ ${name}`); } catch (e) { failed++; console.log(`✗ ${name}\n    ${e.stack.split('\n').slice(0, 3).join('\n    ')}`); } }

// Build a case the way app.js does: heuristic hits become “match” → label observations.
const hit = (category, label, match, weight = 22) => ({ category, label, match, weight });
const obsFromHits = hits => hits.map(x => ({ fact: `“${x.match}”`, inference: x.label, weight: x.weight >= 20 ? 'strong' : x.weight >= 14 ? 'moderate' : 'weak' }));
function mkCase({ hits = [], verdict = 'Scam', category = 'Investment / crypto', extra = [], forensics = null, final = null, offenders = [] } = {}) {
  const heuristics = { hits, links: [], coordination: [], entities: { wallets: [], handles: [], phones: [], emails: [] } };
  return { id: 't1', text: 'invented test message', url: '', heuristics, forensics, offenders, local: { verdict, category, observations: [...obsFromHits(hits), ...extra] }, final };
}
const agentObs = (fact, source, grade, weight = 'strong') => ({ fact, inference: fact + ' (inference)', source, grade, weight });

// ---------- 3.1 Admiralty grades ----------
test('parseGrade accepts A-F × 1-6 and rejects anything else', () => {
  assert.deepStrictEqual({ ...G.parseGrade('b2') }, { sourceGrade: 'B', credibility: 2 });
  assert.deepStrictEqual({ ...G.parseGrade('C-3') }, { sourceGrade: 'C', credibility: 3 });
  for (const bad of ['G1', 'A7', 'A0', '', null, 'AA', '<b>A1</b>']) assert.strictEqual(G.parseGrade(bad), null, bad);
});
test('every observation gets a grade; automated items never default to credibility 1; no-match is F6', () => {
  const c = mkCase({ hits: [hit('Investment / crypto', 'Guaranteed returns', 'guaranteed 40% daily')], extra: [{ fact: 'No pattern matched', inference: 'x', weight: 'weak' }] });
  const g = G.apply(c);
  for (const i of g.items) { assert.match(i.grade, /^[A-F][1-6]$/); assert.ok(i.credibility >= 2, 'automated items never default to 1 (confirmed)'); }
  assert.strictEqual(g.items.find(i => i.kind === 'none').grade, 'F6');
  assert.strictEqual(c.local.observations[0].grade, 'B3');
});
test('analyst override beats the agent grade, which beats the default', () => {
  const o = agentObs('Domain registered 2 days ago', 'domain registry', 'A2');
  const c = mkCase({ extra: [o], verdict: 'Suspicious' });
  assert.strictEqual(G.apply(c).items[0].grade, 'A2');
  assert.strictEqual(G.apply(c).items[0].by, 'agent', 'agent grade survives re-application');
  const g = G.apply(c, { overrides: { [G.keyOf(o)]: 'D4' } });
  assert.strictEqual(g.items[0].grade, 'D4'); assert.strictEqual(g.items[0].by, 'analyst');
  assert.strictEqual(G.apply(c, { overrides: { [G.keyOf(o)]: 'Z9' } }).items[0].grade, 'A2', 'invalid override ignored');
});

// ---------- 3.4 rule 1: confirmed needs two independent items graded 1 or 2 ----------
test('rule 1: one item graded 1 or 2 is not confirmed', () => {
  assert.strictEqual(G.apply(mkCase({ extra: [agentObs('Wallet listed in a public scam report', 'scam database', 'A1')] })).estimate.confirmed, false);
});
test('rule 1: two items graded 1-2 from the same source are not confirmed', () => {
  const c = mkCase({ extra: [agentObs('Fact one', 'scam database', 'A1'), agentObs('Fact two', 'scam database', 'B2')] });
  assert.strictEqual(G.apply(c).estimate.confirmed, false);
});
test('rule 1: two items graded 1-2 from different sources are confirmed; a grade-3 item does not count', () => {
  assert.strictEqual(G.apply(mkCase({ extra: [agentObs('Fact one', 'scam database', 'A1'), agentObs('Fact two', 'domain registry', 'B2')] })).estimate.confirmed, true);
  assert.strictEqual(G.apply(mkCase({ extra: [agentObs('Fact one', 'scam database', 'A1'), agentObs('Fact two', 'domain registry', 'B3')] })).estimate.confirmed, false);
});
test('rule 1 is enforced in code: ai_involvement "confirmed" is downgraded until the evidence supports it, and restored when it does', () => {
  const c = mkCase({ verdict: 'AI-generated content', category: 'Synthetic image', extra: [agentObs('Generator tag in XMP', 'image file', 'B2')] });
  c.local.ai_involvement = { assessment: 'confirmed', basis: 'XMP tag' };
  G.apply(c);
  assert.strictEqual(c.local.ai_involvement.assessment, 'likely');
  assert.match(c.local.ai_involvement.basis, /confirmed.*needs two independent/);
  c.local.observations.push(agentObs('C2PA manifest names a generator', 'content credentials', 'A1'));
  G.apply(c);
  assert.strictEqual(c.local.ai_involvement.assessment, 'confirmed');
  assert.strictEqual(c.local.ai_involvement.basis, 'XMP tag');
});

// ---------- 3.4 rule 2: shared root cause counts once ----------
test('rule 2: several pressure phrases in one message are one signal', () => {
  const hits = [hit('Pressure', 'Artificial urgency', 'act now'), hit('Pressure', 'Deadline threat', 'within 24 hours'), hit('Pressure', 'Account threat', 'account will be closed')];
  const g = G.apply(mkCase({ hits, verdict: 'Scam', category: 'Phishing' }));
  assert.strictEqual(new Set(g.items.map(i => i.root)).size, 1);
  assert.ok(g.estimate.notes.some(n => /3 evidence items share 1 independent root/.test(n)));
});
test('rule 2: three strong signals of one scheme category do not reach "very likely"', () => {
  const hits = [hit('Investment / crypto', 'Guaranteed returns', 'guaranteed profit'), hit('Investment / crypto', 'Fake trading platform', 'our platform'), hit('Investment / crypto', 'Pay-to-withdraw', 'pay a fee to withdraw')];
  const g = G.apply(mkCase({ hits, verdict: 'Scam' }));
  assert.strictEqual(g.estimate.likelihood, 'Likely');
});

// ---------- 3.4 rule 3: one strong scheme-specific signal can justify "likely scam" ----------
test('rule 3: a single seed-phrase request justifies "likely"', () => {
  const g = G.apply(mkCase({ hits: [hit('Investment / crypto', 'Asks for your wallet recovery phrase', 'send your 12-word seed phrase', 28)], verdict: 'Likely scam' }));
  assert.strictEqual(g.estimate.likelihood, 'Likely');
  assert.match(g.estimate.label, /^Likely an investment \/ crypto scam \((low|moderate|high) confidence\)$/);
});
test('rule 3: two independent strong signals allow "very likely"; independent confirmation from different sources allows "almost certain"', () => {
  const hits = [hit('Investment / crypto', 'Pay-to-withdraw', 'pay a fee to withdraw', 28), hit('Phishing', 'Credential request', 'enter your password', 24)];
  assert.strictEqual(G.apply(mkCase({ hits, verdict: 'Scam' })).estimate.likelihood, 'Very likely');
  const extra = [agentObs('Wallet reported in public abuse database', 'abuse database', 'A1'), agentObs('Domain registered 3 days ago', 'domain registry', 'A2')];
  const g = G.apply(mkCase({ hits, verdict: 'Scam', extra }));
  assert.strictEqual(g.estimate.confirmed, true);
  assert.strictEqual(g.estimate.likelihood, 'Almost certain');
});

test('rule 3: grading the only scheme-specific signal down to doubtful (4+) removes its weight', () => {
  const h = [hit('Investment / crypto', 'Asks for your wallet recovery phrase', 'send your seed phrase', 28)];
  const c = mkCase({ hits: h, verdict: 'Likely scam' });
  assert.strictEqual(G.apply(c, { overrides: { [G.keyOf(c.local.observations[0])]: 'D4' } }).estimate.likelihood, 'Roughly even chance');
});

// ---------- 3.4 rule 4: generic signals alone never justify "likely scam" ----------
test('rule 4: urgency + a brand name + crypto payment vocabulary alone are capped at "roughly even chance"', () => {
  const hits = [hit('Pressure', 'Artificial urgency', 'act now', 24), hit('Impersonation', 'Brand name', 'Examplebank', 22), hit('Payment rails', 'Crypto payment', 'USDT', 22)];
  const g = G.apply(mkCase({ hits, verdict: 'Scam', category: 'Phishing' }));
  assert.strictEqual(g.estimate.likelihood, 'Roughly even chance');
  assert.ok(g.estimate.notes.some(n => /Generic signals/.test(n)));
  assert.match(g.estimate.label, /^Roughly even chance that this is a phishing scam/);
});
test('rule 4: the lead investigator cannot talk the label up, only down', () => {
  const c = mkCase({ hits: [hit('Pressure', 'Artificial urgency', 'act now', 24)], verdict: 'Likely scam', category: 'Phishing' });
  c.local.likelihood = 'Almost certain';
  assert.strictEqual(G.apply(c).estimate.likelihood, 'Roughly even chance');
  const d = mkCase({ hits: [hit('Investment / crypto', 'Pay-to-withdraw', 'pay to withdraw', 28), hit('Phishing', 'Credential request', 'password', 24)], verdict: 'Scam' });
  d.local.likelihood = 'Unlikely';
  assert.strictEqual(G.apply(d).estimate.likelihood, 'Unlikely');
});

// ---------- 3.4 rule 5: statistical detectors alone are no better than C3 ----------
test('rule 5: an AI/ELA detector used alone is capped at C3 even if graded higher, and cannot lift the verdict above even chance', () => {
  const c = mkCase({ verdict: 'AI-generated content', category: 'Synthetic image', extra: [{ fact: 'Image pixels / dimensions', inference: 'Dimensions typical of a generator', weight: 'weak', grade: 'A1' }] });
  const g = G.apply(c);
  assert.strictEqual(g.items[0].grade, 'C3'); assert.strictEqual(g.items[0].capped, true);
  assert.strictEqual(g.estimate.likelihood, 'Roughly even chance');
  const ela = G.apply(mkCase({ verdict: 'Edited image', extra: [agentObs('Error-level analysis shows a bright region', 'image forensics agent', 'B2', 'moderate')] }));
  assert.strictEqual(ela.items[0].grade, 'C3');
});
test('rule 5: a detector corroborated by independent evidence keeps its grade', () => {
  const c = mkCase({ verdict: 'AI-generated content', extra: [agentObs('Error-level analysis shows a bright region', 'image forensics agent', 'B2', 'moderate'), agentObs('Earlier copy shows the original scene without the object', 'reverse image search', 'B2')] });
  assert.strictEqual(G.apply(c).items[0].grade, 'B2');
});

// ---------- 3.3 analytic confidence ----------
test('analytic confidence: low for nothing/weak, moderate for one strong item, high for several independent sources', () => {
  assert.strictEqual(G.analyticConfidence([]), 'low');
  assert.strictEqual(G.apply(mkCase({ hits: [hit('Pressure', 'Urgency', 'now', 8)], verdict: 'Suspicious' })).estimate.analytic_confidence, 'low');
  assert.strictEqual(G.apply(mkCase({ hits: [hit('Investment / crypto', 'Seed phrase', 'seed phrase', 28)], verdict: 'Likely scam' })).estimate.analytic_confidence, 'moderate');
  const hi = mkCase({ verdict: 'Scam', extra: [agentObs('A', 'abuse database', 'A2'), agentObs('B', 'domain registry', 'B2'), agentObs('C', 'blockchain explorer', 'B3')] });
  assert.strictEqual(G.apply(hi).estimate.analytic_confidence, 'high');
  const scammer = mkCase({ verdict: 'Suspicious', extra: [agentObs('Sender says they are a bank', 'sender', 'E5'), agentObs('Sender says it is urgent', 'sender', 'E5')] });
  assert.strictEqual(G.apply(scammer).estimate.analytic_confidence, 'low');
});
test('3.2 wording: no-red-flags is never called safe; legitimate is phrased as an estimate', () => {
  const g = G.apply(mkCase({ verdict: 'No strong red flags', category: 'General', extra: [{ fact: 'No pattern matched', inference: 'x', weight: 'weak' }] }));
  assert.strictEqual(g.estimate.likelihood, null);
  assert.match(g.estimate.label, /not a statement that it is safe/);
  assert.match(G.apply(mkCase({ verdict: 'Likely legitimate', category: 'Newsletter' })).estimate.label, /^Likely legitimate \(low confidence\)$/);
  for (const t of G.TERMS) assert.ok(G.RANGES[t], t);
});

// ---------- P1-1 checklist, P2-4 limitations / would-change ----------
test('checklist: five pillars, Date partial when EXIF has DateTimeOriginal, never auto-"done", analyst state wins', () => {
  const f = { sha256: 'ab'.repeat(32), exif: { DateTimeOriginal: '2021:03:04 10:11:12', Make: 'Examplecam' }, xmpFields: {}, ai: { signals: [], weak: [] }, editors: [], notes: [] };
  const c = mkCase({ verdict: 'No strong red flags', forensics: f });
  const g = G.apply(c);
  assert.deepStrictEqual([...g.checklist.map(p => p.id)], ['provenance', 'source', 'date', 'location', 'motivation']);
  assert.strictEqual(g.checklist.find(p => p.id === 'date').status, 'partial');
  assert.ok(g.checklist.every(p => p.status !== 'done'));
  const s = G.apply(c, { pillars: { location: { status: 'not possible', note: 'No landmarks visible' }, date: { status: 'bogus' } } });
  assert.strictEqual(s.checklist.find(p => p.id === 'location').status, 'not possible');
  assert.strictEqual(s.checklist.find(p => p.id === 'date').status, 'partial', 'invalid status ignored');
  assert.ok(s.reportLines.some(l => /Note: No landmarks visible/.test(l)));
});
test('limitations and would-change-if are always populated, merge agent items and appear in the report', () => {
  const c = mkCase({ hits: [hit('Investment / crypto', 'Seed phrase', 'seed phrase', 28)], verdict: 'Likely scam' });
  c.local.limitations = ['Agent could not open the attachment'];
  c.local.would_change_if = ['The exchange confirms the account is theirs'];
  G.apply(c); const g = G.apply(c);
  assert.ok(c.local.limitations.includes('Agent could not open the attachment'));
  assert.strictEqual(c.local.limitations.filter(x => x === 'Agent could not open the attachment').length, 1, 'idempotent');
  assert.ok(c.local.would_change_if.length >= 2);
  const txt = g.reportLines.join('\n');
  for (const h of ['ESTIMATIVE ASSESSMENT', 'VERIFICATION CHECKLIST', 'LIMITATIONS', 'WHAT WOULD CHANGE THIS VERDICT', 'Likely an investment / crypto scam']) assert.ok(txt.includes(h), h);
});

// ---------- Review regressions ----------
test('duplicate observations get distinct keys, so an override or attachment touches only one', () => {
  const dup = () => ({ fact: 'examplebank-secure.top', inference: 'Look-alike domain', weight: 'strong' });
  const c = mkCase({ verdict: 'Likely scam', category: 'Phishing', extra: [dup(), dup()] });
  const g = G.apply(c);
  assert.notStrictEqual(g.items[0].key, g.items[1].key);
  const o = G.apply(c, { overrides: { [g.items[1].key]: 'E5' }, pillars: { source: { attached: [g.items[1].key] } } });
  assert.strictEqual(o.items[0].by, 'default'); assert.strictEqual(o.items[1].grade, 'E5');
  assert.strictEqual(o.checklist.find(p => p.id === 'source').attached[0], o.items[1]);
});
test('AI involvement is only confirmed by AI-related items, not by unrelated well-graded evidence', () => {
  const c = mkCase({ verdict: 'Scam', category: 'Phishing', extra: [agentObs('Generator tag in XMP', 'image file', 'B2'), agentObs('Domain registered 2 days ago', 'domain registry', 'A2')] });
  c.local.ai_involvement = { assessment: 'confirmed', basis: 'XMP tag' };
  G.apply(c);
  assert.strictEqual(c.local.ai_involvement.assessment, 'likely');
});
test('an AI declaration in the image is not scheme-specific scam evidence', () => {
  const f = { exif: {}, xmpFields: {}, ai: { signals: [{ label: 'Generator named in metadata', strength: 'proof' }], weak: [] }, editors: [], notes: [] };
  const h = [hit('Phishing', 'Credential request', 'enter your password', 24)];
  const c = mkCase({ hits: h, verdict: 'Likely scam', category: 'Phishing', forensics: f, extra: [{ fact: 'Image metadata', inference: 'Generator named in metadata', weight: 'strong' }] });
  assert.strictEqual(G.apply(c).estimate.likelihood, 'Likely');
  assert.strictEqual(G.apply(c, { overrides: { [G.keyOf(c.local.observations[0])]: 'D5' } }).estimate.likelihood, 'Roughly even chance');
});
test('a suspicious image-only case is worded about AI or manipulation, not scams', () => {
  assert.match(G.apply(mkCase({ verdict: 'Suspicious', category: 'Possible AI image' })).estimate.label, /^Roughly even chance that this is AI-generated/);
  assert.strictEqual(G.noun('Suspicious', 'Metadata anomaly'), 'manipulated');
  assert.strictEqual(G.noun('Suspicious', 'Linked to earlier scam cases'), 'a scam');
});

// ---------- Wiring ----------
test('app.js, index.html and server.js carry the hooks', () => {
  const app = fs.readFileSync(path.join(__dirname, '../public/app.js'), 'utf8');
  const html = fs.readFileSync(path.join(__dirname, '../public/index.html'), 'utf8');
  const srv = fs.readFileSync(path.join(__dirname, '../server.js'), 'utf8');
  assert.ok(/c\.grading\?\.reportLines/.test(app) && /o\.grade/.test(app));
  assert.ok(/id="tab-checklist"[^>]*aria-controls="panel-checklist"/.test(html) && /<script src="grading.js">/.test(html));
  for (const k of ['"likelihood"', '"analytic_confidence"', '"grade"', '"limitations"', '"would_change_if"']) assert.ok(srv.includes(k), k);
});

console.log(failed ? `\n${failed} grading test(s) failed` : '\nAll grading tests passed');
process.exit(failed ? 1 : 0);
