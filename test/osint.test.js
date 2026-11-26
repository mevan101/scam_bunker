// Zero-dependency tests for the subject investigation / dossier feature. Run: npm test
// Fixtures in test/fixtures are hand-built in the documented response formats (RDAP RFC 9083, mempool.space / Esplora, Tronscan accountv2).
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert'), crypto = require('crypto');
const osint = require('../server/osint');
const fx = n => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', n), 'utf8'));

const ctx = { window: {}, URL, TextEncoder }; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../public/dossier.js'), 'utf8'), ctx);
const D0 = ctx.window.ScamBunkerDossier;
// Re-wrap vm-realm results as plain objects so deepStrictEqual compares structure, not prototypes.
const plain = x => JSON.parse(JSON.stringify(x));
const D = { ...D0, buildClusters: (...a) => plain(D0.buildClusters(...a)) };

let fail = 0, pass = 0;
const tests = [];
const test = (name, fn) => tests.push([name, fn]);

// ---------- Entity resolution ----------
const ind = (type, v, label) => ({ type, key: `${type}:${v}`, label: label || v });
test('union-find merges cases that share any strong indicator, transitively', () => {
  const cases = [
    { id: 'a', at: '2026-01-01T00:00:00Z', verdict: 'Scam', risk: 80, platform: 'Instagram', indicators: [ind('wallet', 'TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT'), ind('handle', 'mentor_amy')] },
    { id: 'b', at: '2026-02-01T00:00:00Z', verdict: 'Likely scam', risk: 60, platform: 'Telegram', indicators: [ind('wallet', 'TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT'), ind('phone', '7700900123')] },
    { id: 'c', at: '2026-03-01T00:00:00Z', verdict: 'Suspicious', risk: 40, platform: 'WhatsApp', indicators: [ind('phone', '7700900123')] },
    { id: 'd', at: '2026-03-05T00:00:00Z', verdict: 'Scam', risk: 90, indicators: [ind('email', 'lone@scam.example')] },
    { id: 'e', at: '2026-03-06T00:00:00Z', verdict: 'Suspicious', risk: 30, indicators: [ind('hashtag', '#crypto')] },
    { id: 'f', at: '2026-03-07T00:00:00Z', verdict: 'Suspicious', risk: 35, indicators: [ind('hashtag', '#crypto')] },
  ];
  const cl = D.buildClusters(cases, []);
  assert.strictEqual(cl.length, 1, 'one actor cluster (d is alone, e/f share only a hashtag)');
  assert.deepStrictEqual(cl[0].cases.map(c => c.id), ['a', 'b', 'c']);
  const w = cl[0].indicators.find(i => i.type === 'wallet');
  assert.strictEqual(w.caseCount, 2); assert.strictEqual(w.firstSeen, '2026-01-01T00:00:00Z'); assert.strictEqual(w.lastSeen, '2026-02-01T00:00:00Z');
  assert.ok(cl[0].risk >= 75, 'confirmed scam + reused wallet raises risk to at least 75');
  assert.strictEqual(cl[0].riskLevel, 'high');
  assert.deepStrictEqual([...cl[0].platforms].sort(), ['Instagram', 'Telegram', 'WhatsApp']);
  assert.ok(cl[0].aliases.includes('mentor_amy'));
  assert.deepStrictEqual(cl[0].timeline.map(t => t.when), cl[0].timeline.map(t => t.when).slice().sort());
});
test('subjects join clusters by indicator and by hand-linked case ids; weak types never link', () => {
  const cases = [
    { id: 'x', at: '2026-04-01T00:00:00Z', verdict: 'Scam', risk: 70, indicators: [ind('handle', 'jess_trades')] },
    { id: 'y', at: '2026-04-02T00:00:00Z', verdict: 'Suspicious', risk: 30, indicators: [] },
    { id: 'z', at: '2026-04-03T00:00:00Z', verdict: 'Suspicious', risk: 30, indicators: [ind('money', '$500')] },
  ];
  const subj = { id: 's1', name: 'Jessica', aliases: ['Mrs Jessica'], createdAt: '2026-04-05T00:00:00Z', caseIds: ['y'], indicators: [{ ...ind('handle', 'jess_trades', '@jess_trades'), addedAt: '2026-04-05T00:00:00Z' }, ind('money', '$500')], findings: { usernames: { jess_trades: { at: '2026-04-06T00:00:00Z', results: [{ site: 'GitHub', status: 'found', url: 'https://github.com/jess_trades' }, { site: 'Reddit', status: 'unknown' }] } }, domains: { 'new.example': { domain: 'new.example', registeredAt: '2026-03-30T00:00:00Z', ageDays: 7, young: true } } } };
  const empty = { id: 's2', name: 'Nobody yet', indicators: [], caseIds: [] };
  const cl = D.buildClusters(cases, [subj, empty]);
  const c1 = cl.find(c => c.subjects.some(s => s.id === 's1'));
  assert.deepStrictEqual(c1.cases.map(c => c.id).sort(), ['x', 'y'], 'z only shares a weak "money" indicator');
  assert.strictEqual(c1.title, 'Jessica');
  assert.ok(c1.aliases.includes('Mrs Jessica'));
  assert.deepStrictEqual(c1.profiles.map(p => p.site), ['GitHub'], 'only found profiles are listed');
  assert.ok(c1.platforms.includes('GitHub'));
  assert.ok(c1.timeline.some(t => /Domain registered/.test(t.what)));
  assert.ok(cl.some(c => c.subjects[0]?.id === 's2'), 'an empty subject still gets a dossier');
  assert.strictEqual(cl.length, 2);
});
test('unionFind basics', () => {
  const uf = D.unionFind(); uf.union('a', 'b'); uf.union('c', 'd'); uf.union('b', 'd');
  assert.strictEqual(uf.find('a'), uf.find('c')); assert.notStrictEqual(uf.find('a'), uf.find('e'));
});
test('indicatorFor uses the same key format as app.js indicators()', () => {
  assert.strictEqual(D.indicatorFor('handle', '@Mrs_Jessica_Trades').key, 'handle:mrs_jessica_trades');
  assert.strictEqual(D.indicatorFor('phone', '+44 7700 900123').key, 'phone:7700900123');
  assert.strictEqual(D.indicatorFor('email', 'HR@Amaz0n-Jobs.example').key, 'email:hr@amaz0n-jobs.example');
  assert.strictEqual(D.indicatorFor('domain', 'https://www.coinbase-pro-wallet.xyz/login').key, 'domain:coinbase-pro-wallet.xyz');
  assert.strictEqual(D.indicatorFor('wallet', 'TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT').chain, 'Tron (USDT-TRC20)');
  assert.strictEqual(D.indicatorFor('wallet', 'not-a-wallet'), null);
  assert.strictEqual(D.indicatorFor('phone', '123'), null);
});
test('sha256Hex fallback matches node:crypto', () => {
  for (const s of ['', 'abc', 'é🙂 dossier', 'x'.repeat(55), 'x'.repeat(56), 'x'.repeat(64), 'y'.repeat(1000)]) assert.strictEqual(D.sha256Hex(s), crypto.createHash('sha256').update(s, 'utf8').digest('hex'));
});

// ---------- sites.json schema ----------
test('data/sites.json schema', () => {
  const raw = JSON.parse(fs.readFileSync(path.join(__dirname, '../data/sites.json'), 'utf8'));
  assert.strictEqual(raw.license, 'CC BY-SA 4.0');
  const sites = raw.sites; assert.ok(Array.isArray(sites));
  assert.ok(sites.length >= 40 && sites.length <= 70, `40-70 sites (got ${sites.length})`);
  const names = new Set();
  const allowed = new Set(['name', 'category', 'url', 'probeUrl', 'checkType', 'errorMsg', 'okMsg', 'absentOkMeansNotFound', 'notFoundStatus', 'regex', 'probe', 'notes']);
  for (const s of sites) {
    const where = s.name || JSON.stringify(s);
    for (const k of Object.keys(s)) assert.ok(allowed.has(k), `${where}: unknown field ${k}`);
    assert.ok(typeof s.name === 'string' && s.name, `${where}: name`); assert.ok(!names.has(s.name), `${where}: duplicate`); names.add(s.name);
    assert.ok(typeof s.category === 'string' && s.category, `${where}: category`);
    for (const u of [s.url, s.probeUrl].filter(Boolean)) { assert.ok(/^https:\/\//.test(u) && u.includes('{username}'), `${where}: url must be https and contain {username}`); new URL(u.replace('{username}', 'test')); }
    assert.ok(['status', 'message', 'redirect'].includes(s.checkType), `${where}: checkType`);
    if (s.checkType === 'message') assert.ok(s.errorMsg || s.okMsg, `${where}: message check needs errorMsg or okMsg`);
    if (s.regex) new RegExp(s.regex);
    if (s.notFoundStatus) assert.ok(s.notFoundStatus.every(Number.isInteger));
    if (s.probe !== undefined) assert.strictEqual(typeof s.probe, 'boolean');
    if (s.probe === false) assert.ok(s.notes, `${where}: unprobeable sites must explain why in notes`);
  }
  for (const must of ['GitHub', 'Reddit', 'X / Twitter', 'Instagram', 'TikTok', 'Telegram', 'YouTube', 'Facebook', 'LinkedIn', 'Cash App', 'Venmo', 'PayPal.me', 'Bluesky', 'Steam', 'Keybase', 'Mastodon (mastodon.social)']) assert.ok(names.has(must), `missing ${must}`);
});

// ---------- Validation ----------
test('username validation', () => {
  for (const ok of ['jo', 'mrs_jessica.trades', 'a-b_c.d', '@handle', '$cashtag', 'x'.repeat(40)]) assert.ok(osint.validateUsername(ok), ok);
  for (const bad of ['', 'a', 'x'.repeat(41), 'has space', '../etc', 'a/b', 'q?x=1', '<script>', 'émile', null, undefined, 'a%2Fb']) assert.strictEqual(osint.validateUsername(bad), null, String(bad));
  assert.strictEqual(osint.validateUsername('@Handle'), 'Handle');
});
test('domain and wallet validation', () => {
  assert.strictEqual(osint.validateDomain('https://WWW.Coinbase-Pro-Wallet.xyz/login?x=1'), 'coinbase-pro-wallet.xyz');
  assert.strictEqual(osint.validateDomain('münchen.de'), 'xn--mnchen-3ya.de');
  for (const bad of ['', 'localhost', '127.0.0.1', 'http://10.0.0.1/', 'no_underscores.com', 'a'.repeat(300) + '.com']) assert.strictEqual(osint.validateDomain(bad), null, bad);
  assert.deepStrictEqual(osint.domainCandidates('login.secure.example.co.uk'), ['login.secure.example.co.uk', 'secure.example.co.uk', 'example.co.uk']);
  assert.strictEqual(osint.normalizeChain('Tron (USDT-TRC20)'), 'tron');
  assert.strictEqual(osint.normalizeChain('Bitcoin'), 'btc');
  assert.strictEqual(osint.normalizeChain('Ethereum/EVM'), 'eth');
  assert.strictEqual(osint.normalizeChain('', 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh'), 'btc');
  assert.ok(osint.WALLET_RE.tron.test('TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT'));
  assert.ok(!osint.WALLET_RE.eth.test('0x123'));
});
test('routes reject invalid input with HTTP 400', async () => {
  const noop = () => assert.fail('should not send');
  for (const [route, body] of [['/api/osint/username', { username: 'bad name' }], ['/api/osint/domain', { domain: '192.168.1.1' }], ['/api/osint/wallet', { chain: 'btc', address: 'nope' }], ['/api/osint/wallet', { chain: 'doge', address: 'D123' }]]) {
    await assert.rejects(osint.routes[route](body, {}, noop), e => e.status === 400, route);
  }
});

// ---------- Parsers ----------
test('RDAP parser: young domain', () => {
  const r = osint.parseRdap(fx('rdap-young.json'), Date.parse('2026-11-26T12:00:00Z'));
  assert.strictEqual(r.domain, 'coinbase-pro-wallet.xyz');
  assert.strictEqual(r.registeredAt, '2026-11-12T08:15:30.000Z');
  assert.strictEqual(r.ageDays, 14); assert.strictEqual(r.young, true);
  assert.strictEqual(r.registrar, 'Example Registrar, LLC'); assert.strictEqual(r.registrarIanaId, '1068');
  assert.strictEqual(r.registrarAbuseEmail, 'abuse@registrar.example');
  assert.deepStrictEqual(r.nameservers, ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com']);
  assert.ok(r.status.includes('server hold'));
  assert.strictEqual(r.expiresAt, '2027-11-12T23:59:59.000Z');
  assert.ok(!JSON.stringify(r).includes('REDACTED'), 'registrant data is not extracted');
});
test('RDAP parser: old domain and empty record', () => {
  const r = osint.parseRdap(fx('rdap-old.json'), Date.parse('2026-11-26T00:00:00Z'));
  assert.strictEqual(r.young, false); assert.ok(r.ageDays > 11000);
  assert.strictEqual(r.registrar, 'RESERVED-Internet Assigned Numbers Authority');
  const e = osint.parseRdap({}, Date.now());
  assert.strictEqual(e.ageDays, null); assert.strictEqual(e.young, false); assert.deepStrictEqual(e.nameservers, []);
});
test('mempool.space parsers', () => {
  const a = osint.parseMempoolAddress(fx('mempool-address.json'));
  assert.strictEqual(a.txCount, 5); assert.strictEqual(a.unconfirmedTxCount, 1);
  assert.strictEqual(a.fundedTxo, 3); assert.strictEqual(a.spentTxo, 1);
  assert.strictEqual(a.totalReceivedSats, 152000000); assert.strictEqual(a.totalReceivedBtc, 1.52);
  assert.strictEqual(a.balanceSats, 52500000); assert.strictEqual(a.balanceBtc, 0.525);
  const t = osint.parseMempoolTxs(fx('mempool-txs.json'), a.txCount);
  assert.strictEqual(t.firstSeen, new Date(1731300000 * 1000).toISOString());
  assert.strictEqual(t.lastSeen, new Date(1732000000 * 1000).toISOString());
  assert.strictEqual(t.firstSeenExact, true);
  assert.strictEqual(osint.parseMempoolTxs(fx('mempool-txs.json'), 900).firstSeenExact, false, 'not exact when more txs exist than the page holds');
  assert.strictEqual(osint.parseMempoolTxs([], 0).firstSeen, null);
});
test('TronGrid parsers (account + USDT-TRC20 transfers)', () => {
  const A = 'TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT';
  const a = osint.parseTrongridAccount(fx('trongrid-account.json'), A);
  assert.strictEqual(a.activated, true); assert.strictEqual(a.address, A);
  assert.strictEqual(a.balanceTrx, 12.5); assert.strictEqual(a.usdtBalance, 48210.5);
  assert.strictEqual(a.firstSeen, new Date(1729000000000).toISOString()); assert.strictEqual(a.lastSeen, new Date(1732500000000).toISOString());
  assert.strictEqual(a.trc20Contracts, 2);
  const none = osint.parseTrongridAccount({ data: [], success: true, meta: {} }, A);
  assert.strictEqual(none.activated, false); assert.strictEqual(none.firstSeen, null);
  const t = osint.parseTrc20Transfers(fx('trongrid-trc20.json'), A);
  assert.strictEqual(t.usdtTransfersIn, 3); assert.strictEqual(t.usdtTransfersOut, 1);
  assert.strictEqual(t.uniqueSenders, 2); assert.strictEqual(t.usdtReceived, 2250);
  assert.strictEqual(t.usdtFirstTransfer, new Date(1729100000000).toISOString());
  assert.strictEqual(t.usdtPageComplete, true);
  assert.strictEqual(osint.parseTrc20Transfers({ data: [], meta: { fingerprint: 'abc' } }, A).usdtPageComplete, false);
});
test('rateLimiter keeps rdap.org under its request budget', async () => {
  let clock = 0; const waits = [];
  const slot = osint.rateLimiter(8, 10000, () => clock, async ms => { waits.push(ms); clock += ms; });
  const at = [];
  for (let i = 0; i < 20; i++) { await slot(); at.push(clock); }
  for (let i = 0; i < at.length; i++) assert.ok(at.filter(t => t > at[i] - 10000 && t <= at[i]).length <= 8, 'never more than 8 in any 10 s window');
  assert.ok(waits.length >= 2, 'callers beyond the budget wait');
});
test('Tronscan parser (keyed fallback)', () => {
  const t = osint.parseTronscan(fx('tronscan-account.json'), 'TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT');
  assert.strictEqual(t.txCount, 214); assert.strictEqual(t.transactionsIn, 190);
  assert.strictEqual(t.balanceTrx, 12.5); assert.strictEqual(t.usdtBalance, 48210.5);
  assert.strictEqual(t.firstSeen, new Date(1729000000000).toISOString());
  const empty = osint.parseTronscan({}, 'TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT');
  assert.strictEqual(empty.activated, false); assert.strictEqual(empty.firstSeen, null);
});

// ---------- Username check classification ----------
const site = o => ({ name: 'T', category: 'x', url: 'https://t.example/{username}', checkType: 'status', ...o });
test('classify(): status / message / redirect checks never guess', () => {
  const c = (s, r) => osint.classify(site(s), { body: '', redirects: [], ...r }, 'alice').status;
  assert.strictEqual(c({}, { status: 200 }), 'found');
  assert.strictEqual(c({}, { status: 404 }), 'not_found');
  assert.strictEqual(c({ notFoundStatus: [400] }, { status: 400 }), 'not_found');
  assert.strictEqual(c({}, { status: 400 }), 'unknown');
  for (const s of [401, 403, 429, 999]) assert.strictEqual(c({}, { status: s }), 'blocked', String(s));
  assert.strictEqual(c({}, { status: 200, body: '<title>Just a moment...</title>' }), 'blocked');
  assert.strictEqual(c({}, { status: 200, body: '<html><title>Client Challenge</title>' }), 'blocked', 'PyPI-style JS challenge answered with HTTP 200 (seen live)');
  assert.strictEqual(c({}, { status: 500 }), 'unknown');
  assert.strictEqual(c({}, { status: 200, redirects: [{ url: 'https://t.example/alice', status: 302 }], finalUrl: 'https://t.example/login?next=alice' }), 'unknown');
  const msg = { checkType: 'message', errorMsg: 'could not be found', okMsg: '"id":"{username}"' };
  assert.strictEqual(c(msg, { status: 200, body: '{"id":"Alice"}' }), 'found', 'okMsg with substitution, case-insensitive');
  assert.strictEqual(c(msg, { status: 200, body: 'The profile could not be found' }), 'not_found');
  assert.strictEqual(c(msg, { status: 200, body: 'something else' }), 'unknown');
  assert.strictEqual(c({ checkType: 'message', okMsg: 'tgme_page_title' }, { status: 200, body: 'nothing' }), 'unknown', 'okMsg-only absence is unknown');
  assert.strictEqual(c({ checkType: 'message', okMsg: 'tgme_page_title', absentOkMeansNotFound: true }, { status: 200, body: 'nothing' }), 'not_found');
  assert.strictEqual(c({ checkType: 'message', errorMsg: 'not found' }, { status: 200, body: 'profile page' }), 'found');
  assert.strictEqual(c({ checkType: 'redirect' }, { status: 200, redirects: [{ status: 302 }], finalUrl: 'https://t.example/explore' }), 'not_found');
  assert.strictEqual(c({ checkType: 'redirect' }, { status: 200, redirects: [{ status: 301 }], finalUrl: 'https://t.example/alice/' }), 'found');
});
test('checkSite(): probe:false and regex mismatches make no request; errors are unknown', async () => {
  const never = () => assert.fail('no request expected');
  assert.strictEqual((await osint.checkSite(site({ probe: false, notes: 'login wall' }), 'alice', never)).status, 'unknown');
  assert.strictEqual((await osint.checkSite(site({ regex: '^[a-z]{6,}$' }), 'alice', never)).status, 'not_found');
  const r = await osint.checkSite(site({ probeUrl: 'https://api.t.example/u/{username}' }), 'alice', async url => { assert.strictEqual(url, 'https://api.t.example/u/alice'); return { status: 200, body: '{}', redirects: [] }; });
  assert.strictEqual(r.status, 'found'); assert.strictEqual(r.url, 'https://t.example/alice'); assert.strictEqual(r.httpStatus, 200);
  const e = await osint.checkSite(site({}), 'alice', async () => { throw Object.assign(new Error('fetch failed'), { cause: { code: 'ENOTFOUND' } }); });
  assert.strictEqual(e.status, 'unknown'); assert.match(e.note, /ENOTFOUND/);
});
test('pool() never exceeds its concurrency limit', async () => {
  let live = 0, peak = 0; const seen = [];
  const out = await osint.pool([...Array(30).keys()], 8, async i => { live++; peak = Math.max(peak, live); await new Promise(r => setTimeout(r, 2 + (i % 5))); live--; return i * 2; }, (r, i) => seen.push(i));
  assert.strictEqual(peak, 8); assert.deepStrictEqual(out, [...Array(30).keys()].map(i => i * 2)); assert.strictEqual(seen.length, 30);
});
test('sources parse', () => {
  for (const f of ['server/osint.js', 'server/net-guard.js', 'public/osint.js', 'public/dossier.js']) new vm.Script(fs.readFileSync(path.join(__dirname, '..', f), 'utf8'));
});

(async () => {
  for (const [name, fn] of tests) {
    try { await fn(); pass++; console.log(`✓ ${name}`); } catch (e) { fail++; console.log(`✗ ${name}\n  ${e.stack.split('\n').slice(0, 3).join('\n  ')}`); }
  }
  console.log(`${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
