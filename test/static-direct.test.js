// Proves the browser-direct fallbacks (GitHub Pages / static mode) and the server produce the same results.
// The server routes run with fetch mocked to the fixtures; their outputs must equal test/fixtures/static-golden.json,
// which was recorded from the server code before the parsers moved to public/shared/. Then the browser modules
// (public/shared/*.js) run in a vm with the same mocked fetch and must return exactly the same objects.
// Regenerate the golden file (only when a change to the output is intended): node test/static-direct.test.js --golden
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');
const fx = n => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', n), 'utf8'));
const GOLDEN = path.join(__dirname, 'fixtures', 'static-golden.json');
const NOW = Date.parse('2026-11-26T12:00:00Z');
const realNow = Date.now;
Date.now = () => NOW; // fixed clock so ageDays in the golden file never drifts

// Server modules must not do DNS in tests: stub the SSRF guard before they load (osint.js destructures it at load).
const guard = require('../server/net-guard');
guard.assertPublicUrl = async () => { };
const osint = require('../server/osint');
const prov = require('../server/provenance');

const BTC = 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', TRON = 'TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT', TRON_NEW = 'TXexampNeverUsed'.padEnd(34, '1');
const USDT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
const CDX = 'https://web.archive.org/cdx/search/cdx?';
const CDX_SAMPLE = [['timestamp', 'original', 'statuscode', 'mimetype', 'digest'],
  ['20190314083012', 'http://www.example.com:80/photos/flood.jpg', '302', 'text/html', '3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ'],
  ['20190316101500', 'https://www.example.com/photos/flood.jpg', '200', 'image/jpeg', 'JQ4TB3A5Y2G2S6ZK6V3D7Q4N6W5Y2C3D'],
  ['20260310120000', 'https://www.example.com/photos/flood.jpg', '200', 'image/jpeg', 'ZZZZTB3A5Y2G2S6ZK6V3D7Q4N6W5Y2C3']];

// [name, route, body, { url: [status, body] }]. Unlisted URLs answer 404 with an empty body.
const OSINT = [
  ['domain: young, from a full URL', '/api/osint/domain', { domain: 'https://www.coinbase-pro-wallet.xyz/login' }, { 'https://rdap.org/domain/coinbase-pro-wallet.xyz': [200, fx('rdap-young.json')] }],
  ['domain: subdomain falls back to the parent', '/api/osint/domain', { domain: 'login.example.com' }, { 'https://rdap.org/domain/example.com': [200, fx('rdap-old.json')] }],
  ['domain: no RDAP record', '/api/osint/domain', { domain: 'nothing-here.example' }, {}],
  ['domain: rate limited', '/api/osint/domain', { domain: 'busy.example' }, { 'https://rdap.org/domain/busy.example': [429, ''] }],
  ['domain: registry error', '/api/osint/domain', { domain: 'broken.example' }, { 'https://rdap.org/domain/broken.example': [500, 'oops'] }],
  ['domain: invalid', '/api/osint/domain', { domain: 'not a domain' }, {}],
  ['wallet: BTC', '/api/osint/wallet', { chain: 'Bitcoin', address: BTC }, { [`https://mempool.space/api/address/${BTC}`]: [200, fx('mempool-address.json')], [`https://mempool.space/api/address/${BTC}/txs`]: [200, fx('mempool-txs.json')] }],
  ['wallet: BTC lookup fails', '/api/osint/wallet', { address: '1BoatSLRHtKNngkdXEeobR76b53LETtpyT' }, {}],
  ['wallet: TRON with USDT transfers', '/api/osint/wallet', { chain: 'tron', address: TRON }, { [`https://api.trongrid.io/v1/accounts/${TRON}`]: [200, fx('trongrid-account.json')], [`https://api.trongrid.io/v1/accounts/${TRON}/transactions/trc20?limit=200&contract_address=${USDT}`]: [200, fx('trongrid-trc20.json')] }],
  ['wallet: TRON never activated', '/api/osint/wallet', { chain: 'trc20', address: TRON_NEW }, { [`https://api.trongrid.io/v1/accounts/${TRON_NEW}`]: [200, { data: [], success: true }] }],
  ['wallet: TRON TronGrid down', '/api/osint/wallet', { chain: 'tron', address: 'TXexampTronGridDown'.padEnd(34, '1') }, {}],
  ['wallet: ETH without a key', '/api/osint/wallet', { chain: 'eth', address: '0x' + 'ab'.repeat(20) }, {}],
  ['wallet: unknown chain', '/api/osint/wallet', { chain: 'doge', address: 'D' + 'x'.repeat(30) }, {}],
  ['wallet: bad address', '/api/osint/wallet', { chain: 'btc', address: 'nope' }, {}],
];
const WAYBACK = [
  ['wayback: captures', { url: 'https://www.example.com/photos/flood.jpg' }, [200, CDX_SAMPLE]],
  ['wayback: not archived', { url: 'https://new.example/' }, [200, '']],
  ['wayback: excluded', { url: 'https://excluded.example/' }, [403, 'org.archive.wayback.exception.AdministrativeAccessControlException: Blocked Site Error']],
];

function mockFetch(responses, log) {
  return async (url, opts = {}) => {
    log.push({ url: String(url), accept: (opts.headers || {}).Accept || (opts.headers || {}).accept || null });
    const [status, body] = responses[url] || [404, ''];
    return new Response(status === 204 ? null : typeof body === 'string' ? body : JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  };
}
async function serverOsint([, route, body, responses]) {
  const log = []; global.fetch = mockFetch(responses, log);
  let out;
  try { await osint.routes[route](body, null, (res, code, payload) => { out = { code, body: payload }; }); }
  catch (e) { out = { status: e.status || 500, error: e.message }; }
  return { out: JSON.parse(JSON.stringify(out)), urls: log.map(l => l.url) };
}
async function serverWayback([, body, resp]) {
  const r = await prov.wayback(body, { fetchImpl: async u => { assert(String(u).startsWith(CDX)); return { ok: resp[0] < 400, status: resp[0], text: async () => typeof resp[1] === 'string' ? resp[1] : JSON.stringify(resp[1]) }; } });
  return { out: JSON.parse(JSON.stringify(r)) };
}

async function main() {
  const golden = {};
  for (const s of OSINT) golden[s[0]] = await serverOsint(s);
  for (const s of WAYBACK) golden[s[0]] = await serverWayback(s);
  if (process.argv.includes('--golden')) { fs.writeFileSync(GOLDEN, JSON.stringify(golden, null, 1) + '\n'); console.log('wrote', GOLDEN); return; }
  const expected = JSON.parse(fs.readFileSync(GOLDEN, 'utf8'));
  let pass = 0, fail = 0;
  const test = async (name, fn) => { try { await fn(); pass++; console.log('  \u2713', name); } catch (e) { fail++; console.log('  \u2717', name, '\n   ', e.message.split('\n').slice(0, 12).join('\n    ')); } };
  const plain = o => JSON.parse(JSON.stringify(o));

  // 1. The server, now backed by public/shared/*, returns exactly what it returned before the refactor.
  for (const [name, v] of Object.entries(golden)) await test(`server unchanged · ${name}`, () => assert.deepStrictEqual(v, expected[name]));

  // 2. The browser-direct path (public/shared/direct.js in a browser-like vm) returns the same objects.
  const browser = () => {
    const ctx = { console, URL, URLSearchParams, AbortSignal, Response, Blob, setTimeout, clearTimeout, Promise, Date };
    ctx.window = ctx; ctx.globalThis = ctx;
    vm.createContext(ctx);
    for (const f of ['osint-core.js', 'provenance-core.js', 'direct.js']) vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'public', 'shared', f), 'utf8'), ctx, { filename: f });
    return ctx;
  };
  const ctx = browser();
  for (const s of OSINT) {
    await test(`browser matches server · ${s[0]}`, async () => {
      const log = [];
      const d = ctx.ScamBunkerDirect.create({ fetchImpl: mockFetch(s[3], log) });
      const fn = s[1].endsWith('/domain') ? d.domain : d.wallet;
      let out;
      try { out = { code: 200, body: plain(await fn(s[2])) }; } catch (e) { out = { status: e.status || 500, error: e.message }; }
      const want = expected[s[0]];
      if (s[0] === 'wallet: ETH without a key') { assert.strictEqual(out.body.available, false); assert.match(out.body.note, /local app/); assert.strictEqual(out.body.explorer, want.out.body.explorer); assert.deepStrictEqual(log, []); return; }
      assert.deepStrictEqual(out, want.out);
      assert.deepStrictEqual(log.map(l => l.url), want.urls, 'same upstream requests in the same order');
    });
  }

  const { ScamBunkerDirect: SD } = ctx;
  await test('browser never sends an API key, cookies or a referrer', async () => {
    const seen = [];
    const d = SD.create({ fetchImpl: async (url, o) => { seen.push(o); return new Response(JSON.stringify({ data: [] }), { status: 200 }); } });
    await d.wallet({ chain: 'tron', address: TRON_NEW });
    assert(seen.length && seen.every(o => o.credentials === 'omit' && o.referrerPolicy === 'no-referrer' && o.mode === 'cors'));
    assert(seen.every(o => Object.keys(o.headers).every(h => /^accept$/i.test(h))), 'only the CORS-safelisted Accept header (no preflight)');
  });
  await test('RDAP: at most N requests per window, cached repeats, back-off after 429', async () => {
    const calls = [];
    const fetchImpl = async url => { calls.push(Date.now()); return new Response(JSON.stringify({ ldhName: 'X.EXAMPLE', events: [] }), { status: 200 }); };
    Date.now = realNow; // the limiter needs a moving clock
    try {
      const d = ctx.ScamBunkerDirect.create({ fetchImpl, rdapMax: 3, rdapWindowMs: 150 });
      const t0 = realNow();
      await Promise.all(['a1.example', 'a2.example', 'a3.example', 'a4.example'].map(x => d.domain({ domain: x })));
      assert.strictEqual(calls.length, 4);
      assert(calls[3] - calls[0] >= 150, `4th request waited for the window (${calls[3] - calls[0]} ms)`);
      assert(realNow() - t0 < 1000);
      await d.domain({ domain: 'a1.example' }); assert.strictEqual(calls.length, 4, 'second lookup of the same domain is served from the cache');
    } finally { Date.now = () => NOW; }
    let n = 0;
    const d2 = ctx.ScamBunkerDirect.create({ fetchImpl: async () => (n++, new Response('', { status: 429 })), rdapBackoffMs: 40 });
    await assert.rejects(d2.domain({ domain: 'busy.example' }), e => e.status === 503 && /rate limit/.test(e.message));
    assert.strictEqual(n, 1, 'a 429 is not retried in a loop');
  });
  await test('network/CORS failure is a readable error, not a TypeError', async () => {
    const d = SD.create({ fetchImpl: async () => { throw new TypeError('Failed to fetch'); } });
    await assert.rejects(d.wallet({ chain: 'btc', address: BTC }), e => e.status === 502 && /mempool\.space could not be reached from the browser/.test(e.message));
  });

  // 3. Wayback in the browser: the Availability API (CORS) instead of CDX (no CORS).
  const avail = (ts, status = '200') => ({ url: 'example.com', archived_snapshots: ts ? { closest: { status, available: true, url: `http://web.archive.org/web/${ts}/https://www.example.com/photos/flood.jpg`, timestamp: ts } } : {} });
  await test('wayback: earliest + latest capture from the Availability API', async () => {
    const urls = [];
    const d = SD.create({ fetchImpl: async u => { urls.push(u); return new Response(JSON.stringify(/timestamp=19900101/.test(u) ? avail('20190316101500') : avail('20260310120000')), { status: 200 }); } });
    const u = 'https://www.example.com/photos/flood.jpg';
    const w = plain(await d.wayback(u));
    assert.deepStrictEqual(urls, [`https://archive.org/wayback/available?url=${encodeURIComponent(u)}&timestamp=19900101`, `https://archive.org/wayback/available?url=${encodeURIComponent(u)}`]);
    assert.strictEqual(w.firstSeen, '2019-03-16T10:15:00Z'); assert.strictEqual(w.lastSeen, '2026-03-10T12:00:00Z');
    assert.strictEqual(w.firstSnapshot, 'https://web.archive.org/web/20190316101500/' + u);
    assert.strictEqual(w.captures, null); assert.strictEqual(w.approximate, true); assert.strictEqual(w.ok, true);
    // the earliest 2xx capture matches what the server's CDX summary reports for the same history
    assert.strictEqual(w.firstSeen, expected['wayback: captures'].out.firstSeen);
    await d.wayback(u); assert.strictEqual(urls.length, 2, 'cached');
  });
  await test('wayback: not archived → same shape as the server', async () => {
    const d = SD.create({ fetchImpl: async () => new Response(JSON.stringify(avail(null)), { status: 200 }) });
    const w = plain(await d.wayback('https://new.example/'));
    const s = expected['wayback: not archived'].out;
    for (const k of ['ok', 'url', 'captures', 'firstSeen', 'lastSeen', 'saveUrl', 'note']) assert.deepStrictEqual(w[k], s[k], k);
  });
  await test('wayback: failures resolve to {ok:false}, never throw', async () => {
    const d = SD.create({ fetchImpl: async () => { throw new TypeError('Failed to fetch'); } });
    const w = await d.wayback('https://x.example/a.jpg'); assert.strictEqual(w.ok, false); assert.match(w.error, /archive\.org could not be reached/);
    assert.strictEqual((await d.wayback('javascript:alert(1)')).ok, false);
  });

  // 4. Images straight from CORS-enabled hosts; everything else is a "local app" state.
  await test('image: CORS-enabled host → bytes for the forensics engine', async () => {
    const d = SD.create({ fetchImpl: async () => new Response(new Uint8Array([0xff, 0xd8, 0xff]), { status: 200, headers: { 'content-type': 'image/jpeg', 'last-modified': 'Tue, 12 Mar 2019 08:00:00 GMT' } }) });
    const r = await d.image('https://cdn.example/flood.jpg');
    assert.strictEqual(r.contentType, 'image/jpeg'); assert.strictEqual(r.size, 3); assert.strictEqual(r.lastModified, '2019-03-12T08:00:00.000Z'); assert(r.blob);
  });
  await test('image: no CORS / a web page / not an image → code local_only', async () => {
    const mk = f => SD.create({ fetchImpl: f });
    await assert.rejects(mk(async () => { throw new TypeError('Failed to fetch'); }).image('https://news.example/a.jpg'), e => e.code === 'local_only' && /no CORS headers/.test(e.message));
    await assert.rejects(mk(async () => new Response('<html>', { status: 200, headers: { 'content-type': 'text/html' } })).image('https://news.example/story'), e => e.code === 'local_only' && /web page/.test(e.message));
    await assert.rejects(mk(async () => new Response('', { status: 404 })).image('https://news.example/gone.jpg'), e => e.code === 'local_only' && /HTTP 404/.test(e.message));
  });
  await test('sendsNote says exactly what is sent and to whom', () => {
    assert.equal(SD.sendsNote([{ what: 'domain', values: ['example.top'], to: 'rdap.org' }]), 'Sends the domain example.top to rdap.org.');
    assert.equal(SD.sendsNote([{ what: 'domain', values: ['a.example', 'b.example'], to: 'rdap.org' }, { what: 'BTC wallet', values: [], to: 'mempool.space' }, { what: 'TRON wallet', values: ['T1'], to: 'api.trongrid.io' }], { via: 'Your Scam Bunker server' }),
      'Your Scam Bunker server sends the domains a.example and b.example to rdap.org and the TRON wallet T1 to api.trongrid.io.');
    assert.equal(SD.sendsNote([{ what: 'domain', values: [], to: 'rdap.org' }]), '');
  });
  await test('localAppHtml escapes and links the README quick start', () => {
    const esc = x => String(x).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
    const h = SD.localAppHtml(esc, 'Username <sweep>', 'x"y');
    assert(h.includes('Username &lt;sweep&gt;') && h.includes('x&quot;y') && !h.includes('<sweep>'));
    assert(h.includes('href="https://github.com/mevan101/scam_bunker#quick-start"') && h.includes('role="note"'));
  });

  // 5. One implementation: the server modules use the shared parsers themselves.
  await test('server/osint.js and server/provenance.js re-export the shared functions', () => {
    const oc = require('../public/shared/osint-core'), pc = require('../public/shared/provenance-core');
    for (const k of ['parseRdap', 'domainCandidates', 'parseMempoolAddress', 'parseMempoolTxs', 'parseTrongridAccount', 'parseTrc20Transfers', 'parseTronscan', 'validateDomain', 'validateUsername', 'normalizeChain', 'rateLimiter']) assert.strictEqual(osint[k], oc[k], k);
    for (const k of ['parseCdx', 'summarizeWayback', 'tsToIso', 'extractPageDates', 'mapLens']) assert.strictEqual(prov[k], pc[k], k);
  });
  await test('static build ships the shared modules before the feature modules', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
    const i = n => html.indexOf(`<script src="${n}"></script>`);
    for (const n of ['shared/osint-core.js', 'shared/provenance-core.js', 'shared/direct.js']) { assert(i(n) > i('app.js'), n); assert(i(n) < i('osint.js') && i(n) < i('provenance.js'), n); }
  });
  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}
main().catch(e => { console.error(e); process.exit(1); });
