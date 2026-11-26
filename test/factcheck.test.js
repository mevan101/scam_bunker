// Zero-dependency tests for fact-check lookup (server/factcheck.js) and template matching (public/similar.js).
// Run: npm test
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');
delete process.env.GOOGLE_FACTCHECK_API_KEY; delete process.env.FACTCHECK_API_KEY;
const F = require('../server/factcheck');
const ctx = { window: {} }; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../public/similar.js'), 'utf8'), ctx);
const S = ctx.window.ScamBunkerSimilar;
const fixture = n => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', n), 'utf8'));

let failed = 0;
async function test(name, fn) {
  try { await fn(); console.log(`✓ ${name}`); } catch (e) { failed++; console.log(`✗ ${name}\n    ${e.stack.split('\n').slice(0, 3).join('\n    ')}`); }
}

const VIRAL = "BREAKING 🚨 SHARE BEFORE IT'S DELETED!! Doctors don't want you to know this: a simple lemon and baking soda drink cures cancer in 7 days. Scientists confirm it is 100% TRUE but the mainstream media won't report it because big pharma pays them. Do your own research. Wake up people! Type AMEN if you agree and tag 10 friends 🙏🙏🙏";

(async () => {
  // ---------- Claim extraction ----------
  await test('claims: health hoax yields the cure claim first, call-to-action lines are skipped', () => {
    const c = F.extractClaims(VIRAL);
    assert(c.length >= 1 && c.length <= 3, `got ${c.length}`);
    assert.strictEqual(c[0].text, 'a simple lemon and baking soda drink cures cancer in 7 days');
    assert(c[0].why.includes('"cures"') && c[0].why.includes('number'));
    assert(!c.some(x => /type amen|do your own research|wake up/i.test(x.text)));
    assert(c[0].query.split(' ').length <= 10 && !/share|breaking/i.test(c[0].query));
    assert(c[0].explorerUrl.startsWith(F.EXPLORER) && c[0].explorerUrl.includes(encodeURIComponent('lemon')));
  });
  await test('claims: dates, named entities and "confirmed" are picked up; at most 3', () => {
    const t = 'The Ministry of Health confirmed on 3 March 2026 that tap water in Northvale contains 40% more fluoride than allowed. Officials have banned bottled water imports. A study found 9 in 10 dentists in Eastbrook agree. Researchers found the reservoir was closed in 2019. Please share!';
    const c = F.extractClaims(t);
    assert.strictEqual(c.length, 3);
    assert(/Ministry of Health confirmed/.test(c[0].text));
    assert(c[0].why.includes('date') && c[0].why.includes('named entity'));
  });
  await test('claims: small talk, questions and personal anecdotes are not claims', () => {
    assert.deepStrictEqual(F.extractClaims('Hey, are we still on for lunch on Thursday at the usual place?'), []);
    assert.deepStrictEqual(F.extractClaims('Did the government really ban 5 kinds of bread in 2025?'), []);
    assert.deepStrictEqual(F.extractClaims('My uncle is an expert trader and he taught me how to earn 30% daily profit on USDT.'), []);
    assert.deepStrictEqual(F.extractClaims(''), []);
    assert.deepStrictEqual(F.extractClaims('Did the government really ban 5 kinds of bread in 2025?! Officials say 12 bakeries in Northvale closed in 2026??'), []);
  });
  await test('claims: URLs, hashtags and handles are stripped from claim text', () => {
    const c = F.extractClaims('Scientists confirmed in 2026 that the moon is hollow https://example.org/x #truth @someone_example');
    assert.strictEqual(c.length, 1);
    assert(!/https?:|#|@/.test(c[0].text), c[0].text);
  });

  await test('claims: a denial before a colon stays attached to the claim', () => {
    const c = F.extractClaims('It is a hoax that: the Northvale reservoir was poisoned with 40 tonnes of chlorine in 2026.');
    assert.strictEqual(c.length, 1);
    assert(/^It is a hoax that/.test(c[0].text), c[0].text);
    assert(F.sentences('Doctors don\'t want you to know this: a simple lemon drink cures cancer in 7 days').length === 2);
  });
  await test('claims: a claim and its negation are both kept', () => {
    const c = F.extractClaims('Officials confirmed the Eastbrook bridge is safe after the 2026 inspection. Officials confirmed the Eastbrook bridge is not safe after the 2026 inspection.');
    assert.strictEqual(c.length, 2);
  });

  // ---------- API response parser ----------
  await test('parser: recorded claims:search sample → publisher, rating, review date, link', () => {
    const r = F.parseClaimSearch(fixture('factcheck-claims-search.json'));
    assert.strictEqual(r.length, 2, 'claims without reviews are dropped');
    const rv = r[0].reviews;
    assert.strictEqual(rv.length, 1, 'non-http review URL dropped');
    assert.deepStrictEqual({ p: rv[0].publisher, rt: rv[0].rating, d: rv[0].reviewDate, u: rv[0].url }, { p: 'Example Fact Check', rt: 'False', d: '2026-03-04T10:00:00Z', u: 'https://factcheck.example.org/2026/03/lemon-baking-soda-cancer' });
    assert.strictEqual(r[0].claimant, 'Viral social media post');
    assert.strictEqual(r[1].reviews[0].rating, 'Misleading');
    assert.deepStrictEqual(F.parseClaimSearch({}), []);
    assert.deepStrictEqual(F.parseClaimSearch(null), []);
  });
  await test('parser: recorded 403 error body becomes a readable message', () => {
    assert.strictEqual(F.parseApiError(fixture('factcheck-error-403.json'), 403), 'Fact Check Tools API: Permission denied on the service. (HTTP 403)');
    assert.strictEqual(F.parseApiError(null, 500), 'Fact Check Tools API HTTP 500');
  });

  // ---------- Lookup ----------
  await test('lookup: without a key → available:false, claims with Explorer links, no network call', async () => {
    let calls = 0;
    const r = await F.lookup({ text: VIRAL }, { key: '', fetchImpl: () => { calls++; }, guard: async () => { } });
    assert.strictEqual(r.available, false); assert.strictEqual(calls, 0);
    assert(r.claims.length && r.claims.every(c => c.explorerUrl));
  });
  await test('lookup: with a key → queries each claim via header key and the SSRF guard', async () => {
    const seen = [], guarded = [];
    const fetchImpl = async (url, opts) => { seen.push({ url, opts }); return { ok: true, status: 200, json: async () => fixture('factcheck-claims-search.json') }; };
    const r = await F.lookup({ text: VIRAL + ' Officials in Westmoor confirmed 12 new cases on 4 May 2026.' }, { key: 'test-key', fetchImpl, guard: async u => guarded.push(u) });
    assert.strictEqual(r.available, true);
    assert.strictEqual(seen.length, r.claims.length); assert.strictEqual(guarded.length, seen.length);
    assert(seen.every(s => s.url.startsWith('https://factchecktools.googleapis.com/v1alpha1/claims:search?') && !s.url.includes('test-key')));
    assert(seen.every(s => s.opts.headers['X-Goog-Api-Key'] === 'test-key' && s.opts.redirect === 'error'));
    assert.strictEqual(r.claims[0].matches[0].reviews[0].publisher, 'Example Fact Check');
  });
  await test('lookup: API error is reported per claim, not thrown', async () => {
    const r = await F.lookup({ text: 'The Council of Southport confirmed 7 bridges closed on 2 June 2026.' }, { key: 'k2', guard: async () => { }, fetchImpl: async () => ({ ok: false, status: 403, json: async () => fixture('factcheck-error-403.json') }) });
    assert.strictEqual(r.claims.length, 1);
    assert(/Permission denied/.test(r.claims[0].error));
  });
  await test('case file: prior fact-checks and similar cases are written for the agents', () => {
    const matches = F.parseClaimSearch(fixture('factcheck-claims-search.json'));
    const txt = F.caseFileSections({ factchecks: { available: true, claims: [{ text: 'lemon cures cancer in 7 days', matches }] }, similar: [{ at: '2026-01-02T00:00:00Z', verdict: 'Scam', platform: 'Telegram', similarity: 0.87, snippet: 'Invest now' }] });
    assert(/PRIOR FACT-CHECKS/.test(txt) && /Example Fact Check rated .* as "False" \(2026-03-04\) https:\/\/factcheck\.example\.org/.test(txt));
    assert(/SIMILAR EARLIER CASES/.test(txt) && /87% similar .* "Scam" on Telegram/.test(txt));
    assert(!txt.includes('Invest now'), 'earlier case text is not sent to the agents');
    assert(/Not searched automatically/.test(F.caseFileSections({ factchecks: { available: false, claims: [{ text: 'x y z' }] } })));
    assert.strictEqual(F.caseFileSections({}), '');
  });

  // ---------- MinHash / Jaccard ----------
  const SCRIPT_A = 'Hello dear, sorry I think I texted the wrong number but you seem very kind. My uncle is an expert trader and he taught me how to earn 30% daily profit on USDT. If you want I can be your mentor. Download the app from https://coinbase-pro-wallet.example/login and deposit 500 USDT to start. Send to TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT. Message me on WhatsApp +44 7700 900123';
  const SCRIPT_B = 'Hello dear, sorry I think I texted the wrong number but you seem very kind. My aunt is an expert trader and she taught me how to earn 25% daily profit on USDT. If you want I can be your mentor. Download the app from https://bitvault-secure.example/app and deposit 300 USDT to start. Send to 0x52908400098527886E0F7030069857D2E4169EE7. Message me on Telegram @trader_mentor_demo';
  const OTHER = 'Hi! I am a recruiter at Global Talent. We reviewed your profile and you have been selected for a remote job with no experience required. Pay a training fee for the starter kit and contact our HR manager on Telegram.';
  await test('normalize: wallets, handles, links, phones and numbers become placeholders', () => {
    const n = S.normalize('Send to TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT or 0x52908400098527886E0F7030069857D2E4169EE7, see https://x.example/a, DM @someone_demo, call +44 7700 900123, earn 30%');
    for (const t of ['wallettoken', 'urltoken', 'handletoken', 'phonetoken', 'numtoken']) assert(n.includes(t), `${t} in ${n}`);
    assert(!/tjyeas|0x5290|someone|7700/.test(n));
    assert.strictEqual(S.normalize('pay TQiOaB1cDeFgHiJkLmNoPqRsTuVwXyZ123 now'), 'pay wallettoken now', 'Tron address with I/O');
  });
  await test('jaccard: same script with rotated wallet/handle/link ≥ 0.6; different script < 0.35', () => {
    const j = S.jaccard(S.shingles(SCRIPT_A), S.shingles(SCRIPT_B));
    assert(j >= 0.6, `same script ${j}`);
    assert(S.jaccard(S.shingles(SCRIPT_A), S.shingles(OTHER)) < 0.35);
    assert.strictEqual(S.jaccard(S.shingles(SCRIPT_A), S.shingles(SCRIPT_A)), 1);
  });
  await test('minhash: estimate tracks exact Jaccard within 0.15 and is deterministic', () => {
    const a = S.shingles(SCRIPT_A), b = S.shingles(SCRIPT_B), o = S.shingles(OTHER);
    const sa = S.minhash(a);
    assert(Math.abs(S.estimate(sa, S.minhash(b)) - S.jaccard(a, b)) <= 0.15);
    assert(S.estimate(sa, S.minhash(o)) < 0.2);
    assert.strictEqual(S.estimate(sa, S.minhash(new Set(a))), 1);
  });
  await test('findSimilar: links earlier same-script cases, ignores later, short and unrelated ones', () => {
    const past = [
      { id: 'p1', at: '2026-01-01T00:00:00Z', text: SCRIPT_B, verdict: 'Scam', platform: 'Instagram' },
      { id: 'p2', at: '2026-01-02T00:00:00Z', text: OTHER, verdict: 'Likely scam' },
      { id: 'p3', at: '2027-01-01T00:00:00Z', text: SCRIPT_B, verdict: 'Scam' },
      { id: 'p4', at: '2026-01-03T00:00:00Z', text: 'ok thanks', verdict: 'No strong red flags' },
      { id: 'self', at: '2026-01-04T00:00:00Z', text: SCRIPT_A, verdict: 'Scam' },
    ];
    const m = S.findSimilar({ id: 'self', at: '2026-06-01T00:00:00Z', text: SCRIPT_A }, past);
    assert.strictEqual(JSON.stringify(m.map(x => x.id)), '["p1"]');
    assert(m[0].sameScript && m[0].similarity >= 0.6);
    const o = S.observation(m);
    assert(o && o.weight === 'moderate' && /earlier case/.test(o.fact));
    assert.strictEqual(S.observation([]), null);
    assert.strictEqual(S.findSimilar({ id: 'x', text: 'too short to compare' }, past).length, 0);
  });

  for (const f of ['public/factcheck.js', 'public/similar.js', 'server/factcheck.js']) new vm.Script(fs.readFileSync(path.join(__dirname, '..', f), 'utf8'));
  console.log('✓ factcheck sources parse');
  process.exit(failed ? 1 : 0);
})();
