// Zero-dependency tests for the Corroborate module: NOAA sun position, shadow helper, reporting routes, and the
// server lookups against recorded API samples (test/fixtures). No network access.
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const C = require('../public/corroborate.js');
const S = require('../server/corroborate.js');

const results = [];
async function t(name, fn) { try { await fn(); results.push(['✓', name]); } catch (e) { results.push(['✗', name, e]); } }
const near = (a, b, tol, msg) => assert.ok(Math.abs(a - b) <= tol, `${msg}: ${a} vs ${b} (±${tol})`);
const fixture = f => fs.readFileSync(path.join(__dirname, 'fixtures', f));

(async () => {
  // Reference values from NOAA's own Solar Calculator code (gml.noaa.gov/grad/solcalc/main.js, calcAzEl), invented places.
  const NOAA = [
    ['2024-06-21T06:00:00Z', 23.81, 90.41, 171.906, 89.624],
    ['2024-12-21T08:30:00Z', 23.81, 90.41, 221.019, 29.878],
    ['2024-03-20T12:00:00Z', 51.5, -0.12, 177.513, 38.641],
    ['2023-09-23T18:00:00Z', 40.71, -74.0, 206.26, 46.009],
    ['2025-01-15T02:00:00Z', -33.87, 151.21, 4.748, 77.195],
    ['2024-07-04T15:45:00Z', 64.15, -21.94, 223.819, 43.258],
    ['2022-11-02T10:10:00Z', -1.29, 36.82, 223.81, 71.063],
    ['2024-06-21T23:00:00Z', 69.65, 18.96, 3.173, 3.341],
  ];
  await t('sun position matches NOAA Solar Calculator values', () => {
    for (const [iso, lat, lon, az, el] of NOAA) {
      const s = C.sunPosition(new Date(iso), lat, lon);
      near(s.elevation, el, 0.02, `elevation ${iso}`);
      // azimuth is ill-defined right under the zenith (first case: 89.6° up), so allow more there
      near(C.angDiff(s.azimuth, az), 0, el > 89 ? 1 : 0.02, `azimuth ${iso}`);
    }
  });
  await t('sun position matches the NREL SPA reference case', () => {
    // Reda & Andreas (2008) SPA example: 2003-10-17 12:30:30 MST (UTC-7), 39.742476 N, 105.1786 W → zenith 50.11162°, azimuth 194.34024°
    const s = C.sunPosition(Date.UTC(2003, 9, 17, 19, 30, 30), 39.742476, -105.1786);
    near(90 - s.elevation, 50.11162, 0.03, 'zenith');
    near(s.azimuth, 194.34024, 0.03, 'azimuth');
  });
  await t('sun below the horizon at local midnight; refraction lifts the horizon', () => {
    assert.ok(C.sunPosition(Date.UTC(2024, 5, 21, 18, 0), 23.81, 90.41).elevation < -20);
    near(C.refraction(0) * 60, 28.9, 0.2, 'horizon refraction in arcmin');
    assert.strictEqual(C.refraction(86), 0);
  });
  await t('shadow points away from the sun with length 1/tan(elevation)', () => {
    const sh = C.shadow({ azimuth: 135, elevation: 45 });
    near(sh.bearing, 315, 1e-9, 'bearing'); assert.strictEqual(sh.compass, 'NW'); near(sh.lengthRatio, 1, 1e-9, 'ratio');
    assert.strictEqual(C.shadow({ azimuth: 10, elevation: -3 }).sunUp, false);
    assert.strictEqual(C.compass(359), 'N'); assert.strictEqual(C.compass(200), 'SSW');
  });
  await t('UTC offsets and local time conversion', () => {
    assert.strictEqual(C.parseOffset('+06:00'), 360); assert.strictEqual(C.parseOffset('-0530'), -330);
    assert.strictEqual(C.parseOffset('Z'), 0); assert.strictEqual(C.parseOffset(''), 0); assert.strictEqual(C.parseOffset('+25:00'), null);
    assert.strictEqual(C.localToUtc('2024-12-21', '14:30', 360), Date.UTC(2024, 11, 21, 8, 30));
  });
  await t('shadow helper recovers the time from a shadow bearing (chronolocation)', () => {
    // Invented scenario: a photo at 14:30 local (+06:00), 23.81 N 90.41 E, 21 Dec 2024.
    const sun = C.sunPosition(C.localToUtc('2024-12-21', '14:30', 360), 23.81, 90.41), sh = C.shadow(sun);
    const hits = C.timesForShadow({ date: '2024-12-21', offsetMin: 360, lat: 23.81, lon: 90.41, bearing: sh.bearing, ratio: sh.lengthRatio });
    assert.strictEqual(hits.length, 1); assert.strictEqual(hits[0].time, '14:30');
    const none = C.timesForShadow({ date: '2024-12-21', offsetMin: 360, lat: 23.81, lon: 90.41, bearing: 180 }); // winter, north of the tropic: never a south-pointing shadow
    assert.strictEqual(none.length, 0);
  });
  await t('reporting routes: Bangladesh, platforms, only https links', () => {
    const r = C.routesFor('Instagram', 'BD');
    assert.strictEqual(r.country.name, 'Bangladesh');
    const names = r.country.routes.map(x => x.name).join(' | ');
    for (const k of ['BTRC', 'CID Cyber Police', 'Police Cyber Support for Women', 'bKash']) assert.ok(names.includes(k), k);
    assert.strictEqual(r.country.routes.find(x => /bKash/.test(x.name)).phone, '16247');
    assert.deepStrictEqual(r.platforms.map(p => p.key), ['meta']);
    assert.deepStrictEqual(C.routesFor('X / Twitter', 'US').platforms.map(p => p.key), ['x']);
    assert.strictEqual(C.routesFor('Email / SMS', 'GB').platforms.length, 0);
    const all = [...Object.values(C.ROUTES.countries).flatMap(c => c.routes), ...C.ROUTES.platforms, ...C.ROUTES.web];
    for (const x of all) if (x.url) assert.ok(/^https:\/\//.test(x.url), x.url);
  });

  // ---------- server lookups with recorded samples ----------
  const calls = [];
  const fake = map => async (url, opts) => {
    calls.push({ url, opts });
    const k = Object.keys(map).find(p => url.startsWith(p));
    if (!k) throw new Error('unexpected url ' + url);
    const v = map[k]; if (v instanceof Error) throw v;
    return { status: 200, buffer: Buffer.isBuffer(v) ? v : Buffer.from(JSON.stringify(v)), headers: {} };
  };
  await t('domain normalisation rejects IPs, localhost and junk', () => {
    assert.strictEqual(S.normalizeDomain('https://www.Example-Shop.invalid/login?x=1'), 'example-shop.invalid');
    assert.strictEqual(S.normalizeDomain('*.example.com'), 'example.com');
    for (const bad of ['127.0.0.1', 'localhost', 'http://10.0.0.1/', 'a b.com', '', 'example.com%2f@evil']) assert.throws(() => S.normalizeDomain(bad), bad);
  });
  await t('crt.sh: first-seen from recorded sample, 20 s timeout, cached', async () => {
    S._setRequest(fake({ 'https://crt.sh/': fixture('crtsh-example.com.json') })); calls.length = 0;
    const r = await S.crtsh({ domain: 'example.com' });
    assert.strictEqual(calls[0].url, 'https://crt.sh/?q=example.com&output=json');
    assert.strictEqual(calls[0].opts.timeoutMs, 20000);
    assert.strictEqual(r.firstSeen, '2016-07-14T00:00:00Z'); assert.strictEqual(r.count, 4);
    assert.ok(r.names.includes('dev.example.com') && r.names.includes('*.example.com'));
    assert.ok(!r.names.some(n => n.includes('@')));
    const again = await S.crtsh({ domain: 'EXAMPLE.com' });
    assert.strictEqual(again.cached, true); assert.strictEqual(calls.length, 1);
  });
  await t('crt.sh: slow/failed upstream degrades to a clear 504', async () => {
    S._setRequest(fake({ 'https://crt.sh/': Object.assign(new Error('Timed out'), { status: 504 }) }));
    await assert.rejects(S.crtsh({ domain: 'example.org' }), e => e.status === 504 && /crt\.sh/.test(e.message));
    const empty = S.summarizeCrt([], 'example.net'); assert.strictEqual(empty.firstSeen, null);
  });
  await t('Open-Meteo: recorded sample summarised, claims graded honestly', async () => {
    S._setRequest(fake({ 'https://archive-api.open-meteo.com/v1/archive?': fixture('open-meteo-dhaka-2024-07-15.json') })); calls.length = 0;
    const r = await S.weather({ lat: 23.81, lon: 90.41, date: '2024-07-15', hour: 9, claim: 'snow' });
    const q = new URL(calls[0].url).searchParams;
    assert.strictEqual(q.get('start_date'), '2024-07-15'); assert.strictEqual(q.get('latitude'), '23.81');
    assert.ok(q.get('daily').includes('weather_code') && q.get('hourly').includes('snow_depth'));
    assert.strictEqual(r.attribution.text, 'Weather data by Open-Meteo.com');
    assert.ok(r.daily.text && r.daily.tmax > 25, 'monsoon day temperature');
    assert.strictEqual(r.hourly.time.slice(11), '09:00');
    assert.strictEqual(r.check.result, 'contradicted'); assert.strictEqual(r.check.strength, 'moderate'); // never "proof"
    const rain = S.checkClaim(r, 'rain'); assert.ok(['consistent', 'unclear'].includes(rain.result)); assert.strictEqual(rain.strength, 'weak');
    await S.weather({ lat: 23.811, lon: 90.409, date: '2024-07-15' }); assert.strictEqual(calls.length, 1, 'cached by rounded grid');
    await assert.rejects(S.weather({ lat: 123, lon: 0, date: '2024-07-15' }), e => e.status === 400);
    await assert.rejects(S.weather({ lat: 1, lon: 1, date: '2999-01-01' }), e => e.status === 400);
    await assert.rejects(S.weather({ lat: 1, lon: 1, date: '2024-01-01', claim: '<script>' }), e => e.status === 400);
  });
  await t('ScamSniffer: runtime list, parent-domain match, single download, credited', async () => {
    const list = ['phish-wallet-claim.invalid', 'www.fake-airdrop.invalid', 'evil-mint.invalid']; // invented sample in the list's format
    S._setRequest(fake({ [S.SCAMSNIFFER_URL]: list })); calls.length = 0;
    const [a, b] = await Promise.all([
      S.scamsniffer({ domains: ['login.phish-wallet-claim.invalid', 'https://www.fake-airdrop.invalid/claim', 'fake-airdrop.invalid', 'example.com'] }),
      S.scamsniffer({ domain: 'evil-mint.invalid' }),
    ]);
    assert.strictEqual(calls.length, 1, 'concurrent lookups share one download');
    assert.deepStrictEqual(a.results.map(x => [x.domain, x.listed, x.matched]), [
      ['login.phish-wallet-claim.invalid', true, 'phish-wallet-claim.invalid'], ['www.fake-airdrop.invalid', true, 'www.fake-airdrop.invalid'], ['fake-airdrop.invalid', false, null], ['example.com', false, null]]);
    // a listed www host does not make the bare parent domain listed
    assert.strictEqual(b.results[0].listed, true);
    assert.strictEqual(a.source.license, 'GPL-3.0'); assert.ok(/scamsniffer/.test(a.source.url));
    assert.strictEqual(S.matchDomain(new Set(['invalid']), 'x.invalid'), null, 'a bare TLD on the list never matches');
  });
  await t('ScamSniffer list is not vendored in the repo', () => {
    const files = fs.readdirSync(path.join(__dirname, '..'), { recursive: true }).filter(f => !String(f).includes('node_modules') && !String(f).startsWith('.git'));
    assert.ok(!files.some(f => /scam-?database|domains\.json/i.test(f)), 'no copy of the list');
  });
  await t('default request path is the SSRF-guarded client', async () => {
    S._setRequest(null);
    const src = fs.readFileSync(path.join(__dirname, '..', 'server', 'corroborate.js'), 'utf8');
    assert.ok(/require\('\.\/net-guard'\)/.test(src) && /let request = guardedRequest/.test(src));
    assert.ok(!/\bfetch\(/.test(src), 'no unguarded fetch()');
  });

  for (const [ok, name, e] of results) console.log(`${ok} ${name}${e ? '\n    ' + (e.stack || e).toString().split('\n').slice(0, 3).join('\n    ') : ''}`);
  if (results.some(r => r[0] === '✗')) process.exit(1);
})();
