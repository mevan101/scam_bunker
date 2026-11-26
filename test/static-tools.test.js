// Static mode (GitHub Pages) for Events, Corroborate, Fact-check and Video. Proves that the parsers moved into
// public/shared/ give exactly the output the server gave before the move (test/fixtures/static-tools-golden.json was
// recorded from the pre-refactor server code), that the browser builds results with the same functions, and that the
// shared files load as plain browser scripts. No network access.
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
delete process.env.GOOGLE_FACTCHECK_API_KEY; delete process.env.FACTCHECK_API_KEY;
const S = require('../server/corroborate.js');
const F = require('../server/factcheck.js');
const K = require('../public/shared/corroborate-core.js');
const X = require('../public/shared/claims.js');
const root = path.join(__dirname, '..');
const fixture = f => fs.readFileSync(path.join(__dirname, 'fixtures', f));
const golden = JSON.parse(fixture('static-tools-golden.json'));
const plain = v => JSON.parse(JSON.stringify(v));
const fake = map => async url => { const k = Object.keys(map).find(p => url.startsWith(p)); return { status: 200, buffer: Buffer.isBuffer(map[k]) ? map[k] : Buffer.from(JSON.stringify(map[k])), headers: {} }; };
const WX = [{ lat: 23.81, lon: 90.41, date: '2024-07-15', hour: 9, claim: 'snow' }, { lat: 23.81, lon: 90.41, date: '2024-07-15' }, { lat: 23.81, lon: 90.41, date: '2024-07-15', hour: 15, offsetMin: 360, claim: 'rain' }, { lat: 23.81, lon: 90.41, date: '2024-07-15', hour: 3, claim: 'clear' }];
const SS_LIST = ['phish-wallet-claim.invalid', 'www.fake-airdrop.invalid', 'evil-mint.invalid'];
const SS_IN = { domains: ['login.phish-wallet-claim.invalid', 'https://www.fake-airdrop.invalid/claim', 'fake-airdrop.invalid', 'example.com', 'bad domain'] };

const results = [];
async function t(name, fn) { try { await fn(); results.push(['✓', name]); } catch (e) { results.push(['✗', name, e]); } }

(async () => {
  await t('server crt.sh output is unchanged by the refactor', async () => {
    S._setRequest(fake({ 'https://crt.sh/': fixture('crtsh-example.com.json') }));
    assert.deepStrictEqual(plain(await S.crtsh({ domain: 'example.com' })), golden.crt);
    assert.deepStrictEqual(plain(await S.crtsh({ domain: 'example.net' })), golden.crtEmpty);
  });
  await t('server Open-Meteo output is unchanged by the refactor', async () => {
    for (let i = 0; i < WX.length; i++) {
      S._setRequest(fake({ 'https://archive-api.open-meteo.com/': fixture('open-meteo-dhaka-2024-07-15.json') }));
      assert.deepStrictEqual(plain(await S.weather(WX[i])), golden.weather[i], `case ${i}`);
    }
    assert.deepStrictEqual(plain(['cloudy', 'fog', 'thunderstorm', 'clear', 'rain', 'snow'].map(c => S.checkClaim(golden.weather[0], c))), golden.claims);
  });
  await t('server ScamSniffer output and domain normalisation are unchanged', async () => {
    S._setRequest(fake({ [S.SCAMSNIFFER_URL]: SS_LIST }));
    const r = await S.scamsniffer(SS_IN); delete r.fetchedAt;
    assert.deepStrictEqual(plain(r), golden.scamsniffer);
    assert.deepStrictEqual(['https://www.Example-Shop.invalid/login?x=1', '*.example.com', 'Sub.Example.org.', 'www.keep.example'].map(d => [S.normalizeDomain(d), S.normalizeDomain(d, { keepWww: true })]), golden.normalize);
  });
  // The browser path (public/corroborate.js in static mode) calls exactly these shared builders on the raw API JSON.
  await t('browser-direct builders give the same results as the server', () => {
    const crt = JSON.parse(fixture('crtsh-example.com.json'));
    assert.deepStrictEqual(plain(K.crtResult(crt, K.normalizeDomain('EXAMPLE.com'))), golden.crt);
    const om = JSON.parse(fixture('open-meteo-dhaka-2024-07-15.json'));
    WX.forEach((b, i) => assert.deepStrictEqual(plain(K.weatherResult(K.parseWeatherInput(b), om, false)), golden.weather[i], `weather ${i}`));
    const ss = K.scamResult(K.scamDomains(SS_IN), { t: 0, set: K.scamSet(SS_LIST) }); delete ss.fetchedAt;
    assert.deepStrictEqual(plain(ss), golden.scamsniffer);
    assert.strictEqual(K.crtUrl('example.com'), 'https://crt.sh/?q=example.com&output=json');
    const q = new URL(K.weatherUrl(K.parseWeatherInput(WX[0]))); assert.strictEqual(q.origin, 'https://archive-api.open-meteo.com');
    assert.strictEqual(q.searchParams.get('start_date'), '2024-07-14');
    assert.ok(K.weatherApiError({ error: true, reason: 'Parameter x is invalid' }).status === 400 && K.weatherApiError({ daily: {} }) === null);
    assert.throws(() => K.parseWeatherInput({ lat: 123, lon: 0, date: '2024-07-15' }), e => e.status === 400);
    assert.throws(() => K.scamDomains({ domains: ['127.0.0.1'] }), e => e.status === 400);
  });
  await t('one implementation: server modules import the shared parsers', () => {
    assert.strictEqual(S.summarizeCrt, K.summarizeCrt); assert.strictEqual(S.summarizeWeather, K.summarizeWeather);
    assert.strictEqual(S.checkClaim, K.checkClaim); assert.strictEqual(S.normalizeDomain, K.normalizeDomain); assert.strictEqual(S.matchDomain, K.matchDomain);
    assert.strictEqual(F.extractClaims, X.extractClaims); assert.strictEqual(F.EXPLORER, X.EXPLORER);
    const src = fs.readFileSync(path.join(root, 'server', 'corroborate.js'), 'utf8');
    assert.ok(!/function (summarizeCrt|summarizeWeather|checkClaim|normalizeDomain)\b/.test(src), 'no second copy in the server');
  });
  await t('claims extracted in the browser match the server', async () => {
    const VIRAL = "BREAKING 🚨 SHARE BEFORE IT'S DELETED!! Doctors don't want you to know this: a simple lemon and baking soda drink cures cancer in 7 days. Scientists confirm it is 100% TRUE but the mainstream media won't report it because big pharma pays them. Do your own research. Wake up people! Type AMEN if you agree and tag 10 friends 🙏🙏🙏";
    assert.deepStrictEqual(plain((await F.lookup({ text: VIRAL })).claims), golden.factcheck[0].claims);
    const ctx = { window: {}, URL, URLSearchParams }; vm.createContext(ctx);
    vm.runInContext(fs.readFileSync(path.join(root, 'public/shared/claims.js'), 'utf8'), ctx);
    assert.deepStrictEqual(plain(ctx.window.ScamBunkerClaims.extractClaims(VIRAL)), golden.factcheck[0].claims);
    assert.ok(golden.factcheck[0].claims[0].explorerUrl.startsWith('https://toolbox.google.com/factcheck/explorer/search/'));
  });
  await t('weather keeps capture minutes across fractional offsets; hour-only input unchanged', () => {
    const om = JSON.parse(fixture('open-meteo-dhaka-2024-07-15.json'));
    // The fixture is in GMT. 09:45 at UTC+05:30 is 04:15 UTC; truncating to 09:00 first would give 03:30 -> the 03 record.
    const r = K.weatherResult(K.parseWeatherInput({ lat: 23.81, lon: 90.41, date: '2024-07-15', hour: 9, minute: 45, offsetMin: 330 }), om, false);
    assert.strictEqual(r.hourly.time.slice(0, 13), '2024-07-15T04'); assert.strictEqual(r.minute, 45);
    const h = K.weatherResult(K.parseWeatherInput({ lat: 23.81, lon: 90.41, date: '2024-07-15', hour: 9, minute: 0, offsetMin: 330 }), om, false);
    assert.strictEqual(h.hourly.time.slice(0, 13), '2024-07-15T03'); assert.ok(!('minute' in h));
    assert.throws(() => K.parseWeatherInput({ lat: 1, lon: 1, date: '2024-07-15', hour: 9, minute: 61 }), e => e.status === 400);
  });
  await t('browser Claude handoff includes locally extracted claims, same text as the server', () => {
    const ctx = { window: {}, URL, URLSearchParams }; vm.createContext(ctx);
    for (const f of ['public/shared/claims.js', 'public/shared/prompt.js']) vm.runInContext(fs.readFileSync(path.join(root, f), 'utf8'), ctx);
    const text = 'Invented post: the Example Valley reservoir was closed in 2019 by the regional council.';
    const factchecks = { available: false, claims: ctx.window.ScamBunkerClaims.extractClaims(text).map(c => ({ text: c.text, explorerUrl: c.explorerUrl })) };
    const body = { case: { text, factchecks } };
    const app = fs.readFileSync(path.join(root, 'public', 'app.js'), 'utf8');
    assert.ok(app.includes('buildHandoffPrompt(body, window.ScamBunkerClaims?.caseFileSections)'), 'browser handoff passes the formatter');
    const browser = ctx.window.ScamBunkerPrompt.buildHandoffPrompt(body, ctx.window.ScamBunkerClaims.caseFileSections);
    assert.ok(/PRIOR FACT-CHECKS \(claims extracted locally, not searched/.test(browser) && browser.includes('reservoir was closed in 2019'));
    assert.strictEqual(browser, require('../public/shared/prompt.js').buildHandoffPrompt(body, F.caseFileSections));
  });
  await t('shared corroborate core loads as a plain browser script', () => {
    const ctx = { window: {}, URL, URLSearchParams }; vm.createContext(ctx);
    vm.runInContext(fs.readFileSync(path.join(root, 'public/shared/corroborate-core.js'), 'utf8'), ctx);
    const B = ctx.window.ScamBunkerCorroborateCore;
    const om = JSON.parse(fixture('open-meteo-dhaka-2024-07-15.json'));
    assert.deepStrictEqual(plain(B.weatherResult(B.parseWeatherInput(WX[2]), om, false)), golden.weather[2]);
  });
  await t('index.html loads each shared module before the module that uses it', () => {
    const html = fs.readFileSync(path.join(root, 'public', 'index.html'), 'utf8'), at = s => html.indexOf(`<script src="${s}"></script>`);
    assert.ok(at('shared/claims.js') > 0 && at('shared/claims.js') < at('factcheck.js'));
    assert.ok(at('shared/corroborate-core.js') > 0 && at('shared/corroborate-core.js') < at('corroborate.js'));
  });
  await t('static mode: no /api call without an isStatic() check', () => {
    const src = f => fs.readFileSync(path.join(root, 'public', f), 'utf8');
    const video = src('video.js'), vis = video.slice(video.indexOf('async function vision'));
    assert.ok(vis.indexOf('isStatic()') > 0 && vis.indexOf('isStatic()') < vis.indexOf("'/api/agent'"), 'video skips /api/agent');
    const fc = src('factcheck.js'), lk = fc.slice(fc.indexOf('async function lookup'));
    assert.ok(lk.indexOf('isStatic()') < lk.indexOf("'/api/factcheck'"), 'fact-check stays local');
    const ev = src('events.js'), fa = ev.slice(ev.indexOf('async function fetchAll'));
    assert.ok(fa.indexOf('isStatic') < fa.indexOf("'/api/events/extract'"), 'events extraction gated');
    assert.ok(/id="ev-static"/.test(ev) && /npm start/.test(ev), 'events explains the local app');
    const co = src('corroborate.js');
    assert.ok(/isStatic\(\) && K \? browserLookups\[name\]/.test(co), 'corroborate goes browser-direct');
    assert.ok(!/crtsh\(body\)/.test(co.slice(co.indexOf('browserLookups'))) && /Certificate history needs the local app/.test(co), 'crt.sh has a local-app state, no browser call');
    for (const u of [K.SCAMSNIFFER_URL, K.crtUrl('x.example'), K.weatherUrl(K.parseWeatherInput(WX[0]))]) assert.ok(u.startsWith('https://'), u);
  });

  for (const [ok, name, e] of results) console.log(`${ok} ${name}${e ? '\n    ' + (e.stack || e).toString().split('\n').slice(0, 3).join('\n    ') : ''}`);
  if (results.some(r => r[0] === '✗')) process.exit(1);
})();
