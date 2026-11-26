// Zero-dependency tests for image provenance: perceptual hashing (run under node vm with fake pixel arrays),
// the verdict logic, the Wayback CDX parser, page-date extraction and the SSRF-guarded image fetch. Run: npm test
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert'), http = require('http');

let failed = 0;
const results = [];
async function test(name, fn) {
  try { await fn(); console.log(`✓ ${name}`); } catch (e) { failed++; console.log(`✗ ${name}\n    ${e.stack.split('\n').slice(0, 3).join('\n    ')}`); }
}

// ---------- Load the browser module in a sandbox (no document → UI does not boot) ----------
const ctx = { window: {} }; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../public/provenance.js'), 'utf8'), ctx);
const P = ctx.window.ScamBunkerProvenance;

// Deterministic procedural "photo": smooth gradients, blobs and texture, sampled at any resolution / window.
// Sampling the same scene at another size = a resize; sampling a sub-window = a crop.
function scene(seed) {
  let s = seed; const rnd = () => (s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32;
  const blobs = Array.from({ length: 9 }, () => ({ x: rnd(), y: rnd(), r: 0.05 + rnd() * 0.2, c: [rnd() * 255, rnd() * 255, rnd() * 255] }));
  const f1 = 2 + rnd() * 6, f2 = 2 + rnd() * 6, ph = rnd() * 6;
  return (u, v) => {
    let c = [120 + 80 * Math.sin(u * f1 + ph), 110 + 70 * Math.cos(v * f2), 100 + 60 * Math.sin((u + v) * 3)];
    for (const b of blobs) { const d = Math.hypot(u - b.x, v - b.y); if (d < b.r) { const k = 1 - d / b.r; c = c.map((x, i) => x * (1 - k) + b.c[i] * k); } }
    return c;
  };
}
function render(sc, w, h, win = { u: 0, v: 0, w: 1, h: 1 }, { noise = 0, seed = 7, flip = false } = {}) {
  let s = seed; const rnd = () => (s = (s * 1103515245 + 12345) >>> 0) / 2 ** 32 - 0.5;
  const rgba = new Uint8ClampedArray(w * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const xx = flip ? w - 1 - x : x;
    const c = sc(win.u + win.w * (xx + 0.5) / w, win.v + win.h * (y + 0.5) / h);
    const i = (y * w + x) * 4;
    rgba[i] = c[0] + noise * rnd(); rgba[i + 1] = c[1] + noise * rnd(); rgba[i + 2] = c[2] + noise * rnd(); rgba[i + 3] = 255;
  }
  return P.toGray(rgba, w, h);
}
// JPEG-like damage: 8×8 block averaging blended in + quantisation
function degrade(g) {
  const d = Float64Array.from(g.data);
  for (let by = 0; by < g.h; by += 8) for (let bx = 0; bx < g.w; bx += 8) {
    let sum = 0, n = 0;
    for (let y = by; y < Math.min(g.h, by + 8); y++) for (let x = bx; x < Math.min(g.w, bx + 8); x++) { sum += d[y * g.w + x]; n++; }
    const m = sum / n;
    for (let y = by; y < Math.min(g.h, by + 8); y++) for (let x = bx; x < Math.min(g.w, bx + 8); x++) { const k = y * g.w + x; d[k] = Math.round((0.6 * d[k] + 0.4 * m) / 12) * 12; }
  }
  return { w: g.w, h: g.h, data: d };
}
const img = g => ({ gray: g, hash: P.hashGray(g), width: g.w, height: g.h });

(async () => {
  const A = scene(1), Bsc = scene(99);
  const orig = render(A, 192, 144);
  const resized = render(A, 96, 72);
  const big = render(A, 384, 288);
  const noisy = degrade(render(A, 160, 120, undefined, { noise: 18 }));
  const other = render(Bsc, 192, 144);
  const mirror = render(A, 192, 144, undefined, { flip: true });
  const crop = render(A, 120, 96, { u: 0.2, v: 0.15, w: 0.6, h: 0.64 }); // 60 % × 64 % window (115×92 px of the 192×144 frame), same pixel aspect

  await test('hamming distance on hex hashes', () => {
    assert.strictEqual(P.hamming('0000000000000000', '0000000000000000'), 0);
    assert.strictEqual(P.hamming('ffffffffffffffff', '0000000000000000'), 64);
    assert.strictEqual(P.hamming('8000000000000001', '0000000000000000'), 2);
    assert.strictEqual(P.hamming('abc', '0000000000000000'), 64, 'length mismatch = maximal distance');
  });
  await test('dHash / pHash are 64-bit hex and deterministic', () => {
    const h = P.hashGray(orig);
    assert.match(h.d, /^[0-9a-f]{16}$/); assert.match(h.p, /^[0-9a-f]{16}$/);
    assert.deepStrictEqual(P.hashGray(render(A, 192, 144)), h);
  });
  await test('resized copy (½× and 2×) stays within the SAME threshold (≤6)', () => {
    for (const g of [resized, big]) { const c = P.compareHashes(P.hashGray(orig), P.hashGray(g)); results.push(['resize', c]); assert(c.combined <= P.THRESHOLDS.same, JSON.stringify(c)); }
  });
  await test('noisy + block-quantised re-encode stays within LIKELY SAME (≤10)', () => {
    const c = P.compareHashes(P.hashGray(orig), P.hashGray(noisy)); results.push(['re-encode', c]);
    assert(c.combined <= P.THRESHOLDS.likely, JSON.stringify(c));
  });
  await test('a different image is far apart (>18)', () => {
    const c = P.compareHashes(P.hashGray(orig), P.hashGray(other)); results.push(['different', c]);
    assert(c.combined > P.THRESHOLDS.related, JSON.stringify(c));
    assert.strictEqual(P.classifyDistance(c.combined), 'different');
  });
  await test('compareImages: same / mirrored / different / uncropped original', () => {
    const o = img(orig);
    assert.strictEqual(P.compareImages(o, img(big)).relation, 'same');
    assert.strictEqual(P.compareImages(o, img(mirror)).relation, 'mirrored');
    assert.strictEqual(P.compareImages(o, img(other)).relation, 'different');
    // The case image is a crop; the candidate is the full frame → "case-is-crop" (candidate is closer to the original)
    const r = P.compareImages(img(crop), o); results.push(['crop', r]);
    assert.strictEqual(r.relation, 'case-is-crop', JSON.stringify(r));
    assert(r.crop.areaFraction > 0.25 && r.crop.areaFraction < 0.5, 'crop area ≈ 36 %: ' + r.crop.areaFraction);
    assert(Math.abs(r.crop.rect.x - 0.2) < 0.08, 'crop x ≈ 0.2: ' + r.crop.rect.x);
    // and the other way round
    assert.strictEqual(P.compareImages(o, img(crop)).relation, 'crop-of-case');
    assert.strictEqual(P.compareImages({ ...o, sha256: 'x' }, { ...img(orig), sha256: 'x' }).relation, 'identical');
  });

  // ---------- Verdict logic ----------
  const caseItem = { id: 'case', isCase: true, label: 'Case image', width: 1080, height: 810, jpegQuality: 72, platformMarks: 2, editors: [] };
  const sameRel = { relation: 'same', label: 'Same image', d: 2, p: 4, combined: 3, matchPct: 91 };
  await test('synthesize: recycled image (2019 copy vs claimed 2026 event)', () => {
    const cand = { id: 'c1', label: 'Copy 1 · news.example', width: 4032, height: 3024, jpegQuality: 95, camera: 'Canon EOS 5D', exifCapture: '2019-03-14T08:30:00', editors: [], platformMarks: 0, compare: sameRel,
      imageUrl: 'https://news.example/p.jpg', lastModified: '2019-03-15T10:00:00.000Z', wayback: { image: { ok: true, firstSeen: '2019-03-16T00:00:00Z', firstSnapshot: 'https://web.archive.org/web/20190316000000/https://news.example/p.jpg' } } };
    const claimed = P.parseClaimedDate('BREAKING: flooding in the city today, 12 March 2026', '2026-03-12T10:00:00Z');
    assert.strictEqual(claimed.date, '2026-03-12');
    const v = P.synthesize([{ ...caseItem }, cand], claimed);
    assert.strictEqual(v.original.itemId, 'c1');
    assert.strictEqual(v.capture.date, '2019-03-14T08:30:00');
    assert.strictEqual(v.earliest.date.slice(0, 10), '2019-03-14');
    assert(v.contradictions.some(c => /^Recycled/.test(c.text) && c.weight === 'strong'), JSON.stringify(v.contradictions));
    assert.strictEqual(v.independent.date.slice(0, 10), '2019-03-16');
    const lines = P.reportLines({ verdict: v, items: [cand] });
    assert(lines.includes('IMAGE PROVENANCE') && lines.some(l => /Recycled/.test(l)));
  });
  await test('synthesize: static-mode Wayback dates (Availability API) are URL history, never a recycled-image finding', () => {
    const cand = { id: 'c2', label: 'Copy 1 · cdn.example', width: 1080, height: 810, editors: [], platformMarks: 0, compare: sameRel, imageUrl: 'https://cdn.example/photo.jpg',
      wayback: { image: { ok: true, approximate: true, captures: null, firstSeen: '2015-05-01T00:00:00Z', firstSnapshot: 'https://web.archive.org/web/20150501000000/https://cdn.example/photo.jpg' } } };
    const v = P.synthesize([{ ...caseItem }, cand], { date: '2026-11-26', precision: 'day' });
    assert(!v.contradictions.some(c => /^Recycled/.test(c.text)), JSON.stringify(v.contradictions));
    assert.strictEqual(v.earliest, null);
    assert(v.dates.some(d => d.trust === 'low' && /URL history/.test(d.source)));
  });
  await test('reportLines: a candidate the browser could not read still exports its Wayback URL history', () => {
    const it = { id: 'c3', label: 'Copy 2 · news.example', imageUrl: 'https://news.example/story', localOnly: 'news.example does not allow other websites to load this file (no CORS headers)',
      wayback: { image: { ok: true, approximate: true, firstSeen: '2019-01-20T14:25:10Z', firstSnapshot: 'https://web.archive.org/web/20190120142510/https://news.example/story', lastSeen: '2026-11-01T00:00:00Z', lastSnapshot: 'https://web.archive.org/web/20261101000000/https://news.example/story' } } };
    const lines = P.reportLines({ verdict: P.synthesize([{ ...caseItem }], null), items: [it] }).join('\n');
    assert(/not compared \(needs the local app\)/.test(lines) && /Wayback URL history \(image URL, not proof of this image\): first 2019-01-20 14:25:10 <https:\/\/web\.archive\.org\/web\/20190120142510\//.test(lines), lines);
  });
  await test('synthesize: forged EXIF (capture after first archived) and modify-before-capture', () => {
    const cs = { ...caseItem, camera: 'Apple iPhone 15', exifCapture: '2026-01-02T12:00:00', exifModify: '2025-12-30T09:00:00' };
    const cand = { id: 'c1', label: 'Copy 1', width: 800, height: 600, compare: sameRel, wayback: { image: { ok: true, firstSeen: '2021-06-01T00:00:00Z' } } };
    const v = P.synthesize([cs, cand], null);
    assert(v.contradictions.some(c => /forged/.test(c.text) && c.weight === 'strong'));
    assert(v.contradictions.some(c => /modify date/.test(c.text)));
  });
  await test('synthesize: non-matching candidates are ignored', () => {
    const v = P.synthesize([{ ...caseItem }, { id: 'x', label: 'X', width: 10, height: 10, compare: { relation: 'different' }, exifCapture: '2001-01-01T00:00:00', camera: 'Nikon' }], { date: '2026-01-01', precision: 'day' });
    assert.strictEqual(v.matches, 0); assert.strictEqual(v.contradictions.length, 0); assert.strictEqual(v.original.isCase, true);
  });
  await test('parseClaimedDate formats', () => {
    assert.strictEqual(P.parseClaimedDate('Taken on March 3, 2026 at the rally').date, '2026-03-03');
    assert.strictEqual(P.parseClaimedDate('scenes from 2024-11-05 and 2026-02-01').date, '2026-02-01');
    assert.deepStrictEqual([P.parseClaimedDate('the riots in 2026').date, P.parseClaimedDate('the riots in 2026').precision], ['2026-01-01', 'year']);
    assert.strictEqual(P.parseClaimedDate('happened yesterday!!', '2026-11-26T09:00:00Z').date, '2026-11-25');
    assert.strictEqual(P.parseClaimedDate('nice photo'), null);
    assert.strictEqual(P.normDate('2019:03:14 08:30:12'), '2019-03-14T08:30:12');
    assert.strictEqual(P.normDate('0000:00:00 00:00:00'), null);
  });

  // ---------- Server: Wayback parser ----------
  const prov = require('../server/provenance');
  // Sample in the documented CDX JSON shape (output=json&fl=timestamp,original,statuscode,mimetype,digest).
  // Hand-written: archive.org was not reachable from the sandbox these tests were written in.
  const CDX_SAMPLE = [['timestamp', 'original', 'statuscode', 'mimetype', 'digest'],
    ['20190314083012', 'http://www.example.com:80/photos/flood.jpg', '302', 'text/html', '3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ'],
    ['20190316101500', 'https://www.example.com/photos/flood.jpg', '200', 'image/jpeg', 'JQ4TB3A5Y2G2S6ZK6V3D7Q4N6W5Y2C3D'],
    ['20210601000000', 'https://www.example.com/photos/flood.jpg', '200', 'image/jpeg', 'JQ4TB3A5Y2G2S6ZK6V3D7Q4N6W5Y2C3D'],
    ['20260310120000', 'https://www.example.com/photos/flood.jpg', '200', 'image/jpeg', 'ZZZZTB3A5Y2G2S6ZK6V3D7Q4N6W5Y2C3'],
    ['20260311120000', 'https://www.example.com/photos/flood.jpg', '404', 'text/html', 'AAAA']];
  await test('parseCdx + summarizeWayback', () => {
    const rows = prov.parseCdx(CDX_SAMPLE);
    assert.strictEqual(rows.length, 5); assert.strictEqual(rows[1].statuscode, '200');
    const s = prov.summarizeWayback('https://www.example.com/photos/flood.jpg', rows);
    assert.strictEqual(s.captures, 5);
    assert.strictEqual(s.firstSeen, '2019-03-16T10:15:00Z', 'first 2xx capture, not the redirect');
    assert.strictEqual(s.firstAnyCapture, '2019-03-14T08:30:12Z');
    assert.strictEqual(s.lastSeen, '2026-03-10T12:00:00Z', 'last 2xx capture');
    assert.strictEqual(s.firstSnapshot, 'https://web.archive.org/web/20190316101500/https://www.example.com/photos/flood.jpg');
    assert.strictEqual(s.firstRaw, 'https://web.archive.org/web/20190316101500im_/https://www.example.com/photos/flood.jpg');
    assert.strictEqual(s.distinctDigests, 2);
    assert.deepStrictEqual(prov.parseCdx([]), []); assert.deepStrictEqual(prov.parseCdx({ error: 1 }), []);
    assert.strictEqual(prov.summarizeWayback('https://x.example/', []).captures, 0);
    assert.strictEqual(prov.tsToIso('2019'), '2019-01-01T00:00:00Z'); assert.strictEqual(prov.tsToIso('201903'), '2019-03-01T00:00:00Z'); assert.strictEqual(prov.tsToIso('nope'), null);
  });
  await test('wayback() handles success, empty, blocked and network failure gracefully', async () => {
    const fake = (status, body) => async url => { assert(url.startsWith('https://web.archive.org/cdx/search/cdx?')); assert(/fl=timestamp%2Coriginal%2Cstatuscode%2Cmimetype%2Cdigest/.test(url)); return { ok: status < 400, status, text: async () => body }; };
    const ok = await prov.wayback({ url: 'https://www.example.com/photos/flood.jpg' }, { fetchImpl: fake(200, JSON.stringify(CDX_SAMPLE)) });
    assert.strictEqual(ok.ok, true); assert.strictEqual(ok.captures, 5);
    const empty = await prov.wayback({ url: 'https://new.example/' }, { fetchImpl: fake(200, '') });
    assert.strictEqual(empty.captures, 0); assert(empty.saveUrl);
    const blocked = await prov.wayback({ url: 'https://new.example/' }, { fetchImpl: fake(403, 'Blocked Site Error') });
    assert.strictEqual(blocked.ok, false); assert(/excluded/.test(blocked.error));
    const down = await prov.wayback({ url: 'https://new.example/' }, { fetchImpl: async () => { const e = new Error('fetch failed'); e.cause = { code: 'ENOTFOUND' }; throw e; } });
    assert.strictEqual(down.ok, false); assert(/unreachable/.test(down.error));
    await assert.rejects(prov.wayback({ url: 'ftp://x' }), e => e.status === 400);
  });
  await test('extractPageDates + mapLens', () => {
    const html = `<html><head><title> Flood hits town </title><meta property="og:image" content="/img/flood.jpg"><meta property="article:published_time" content="2019-03-15T07:00:00+00:00"><meta name="date" content="2020-01-01"><script type="application/ld+json">{"datePublished":"2019-03-15T06:59:00Z","dateModified":"2024-01-01T00:00:00Z"}</script></head><body><time datetime="2019-03-15">15 March</time></body></html>`;
    const d = prov.extractPageDates(html);
    assert.strictEqual(d.published.iso, '2019-03-15T00:00:00.000Z');
    assert.strictEqual(d.ogImage, '/img/flood.jpg'); assert.strictEqual(d.title, 'Flood hits town');
    assert.strictEqual(d.modified, '2024-01-01T00:00:00.000Z');
    assert.strictEqual(prov.extractPageDates('<p>nothing</p>').published, null);
    const m = prov.mapLens({ visual_matches: [{ title: 'A', link: 'https://a.example/1', source: 'a.example', thumbnail: 'https://t/1', image: 'https://a.example/1.jpg' }, { link: 'https://a.example/1' }] });
    assert.strictEqual(m.length, 1); assert.deepStrictEqual(Object.keys(m[0]).sort(), ['date', 'imageUrl', 'link', 'source', 'thumbnail', 'title']);
  });
  await test('reverse() without SERPAPI_API_KEY reports unavailable', async () => {
    assert.deepStrictEqual(await prov.reverse({ imageUrl: 'https://a.example/x.jpg' }), { available: false });
  });

  // ---------- SSRF-guarded fetch ----------
  const guard = require('../server/net-guard');
  await test('isPrivateIp', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.0.1', '172.16.5.5', '169.254.169.254', '100.64.0.1', '::1', 'fd00::1', '::ffff:127.0.0.1', '0.0.0.0']) assert(guard.isPrivateIp(ip), ip);
    for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700::1111']) assert(!guard.isPrivateIp(ip), ip);
  });
  await test('fetch-image refuses localhost, private IPs and non-http schemes', async () => {
    await assert.rejects(prov.fetchImage({ url: 'http://127.0.0.1:4400/x.png' }), e => e.status === 403 && e.code === 'ssrf_blocked');
    await assert.rejects(prov.fetchImage({ url: 'http://localhost:4400/x.png' }), e => e.status === 403);
    await assert.rejects(prov.fetchImage({ url: 'http://[::1]/x.png' }), e => e.status === 403);
    await assert.rejects(prov.fetchImage({ url: 'http://169.254.169.254/latest/meta-data' }), e => e.status === 403);
    await assert.rejects(prov.fetchImage({ url: 'file:///etc/passwd' }), e => e.status === 400);
    await assert.rejects(prov.fetchImage({ url: 'http://user:pw@example.com/x.png' }), e => e.status === 400);
  });

  // Local server reachable only because the test swaps the guard for "block 127.0.0.2 only".
  const PNG = Buffer.from('89504e470d0a1a0a0000000d4948445200000001000000010806000000', 'hex');
  const srv = http.createServer((req, res) => {
    if (req.url === '/img.png') { res.writeHead(200, { 'Content-Type': 'image/png', 'Last-Modified': 'Thu, 14 Mar 2019 08:30:00 GMT' }); return res.end(PNG); }
    if (req.url === '/page') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end('<html></html>'); }
    if (req.url === '/hop') { res.writeHead(302, { Location: '/img.png' }); return res.end(); }
    if (req.url === '/evil') { res.writeHead(302, { Location: `http://127.0.0.2:${srv.address().port}/img.png` }); return res.end(); }
    if (req.url === '/huge') { res.writeHead(200, { 'Content-Type': 'image/jpeg' }); const chunk = Buffer.alloc(64 * 1024); let n = 0; const pump = () => { while (n++ < 40) if (!res.write(chunk)) return res.once('drain', pump); res.end(); }; return pump(); }
    if (req.url === '/slow') { res.writeHead(200, { 'Content-Type': 'image/png' }); res.write(PNG); return; /* never ends */ }
    res.writeHead(404); res.end();
  });
  await new Promise(r => srv.listen(0, '0.0.0.0', r));
  const base = `http://localhost:${srv.address().port}`;
  const opts = { isBlocked: ip => ip === '127.0.0.2' };
  await test('fetch-image: success with redirect, Last-Modified and base64 body', async () => {
    const r = await prov.fetchImage({ url: base + '/hop' }, opts);
    assert.strictEqual(r.contentType, 'image/png'); assert.strictEqual(r.size, PNG.length);
    assert.strictEqual(Buffer.from(r.dataBase64, 'base64').toString('hex'), PNG.toString('hex'));
    assert.strictEqual(r.lastModified, '2019-03-14T08:30:00.000Z');
    assert.strictEqual(r.finalUrl, base + '/img.png'); assert.strictEqual(r.redirects.length, 2);
  });
  await test('fetch-image: redirect into a blocked address is refused on the hop', async () => {
    await assert.rejects(prov.fetchImage({ url: base + '/evil' }, opts), e => e.status === 403 && e.code === 'ssrf_blocked');
  });
  await test('fetch-image: non-image content type is refused with code bad_type', async () => {
    await assert.rejects(prov.fetchImage({ url: base + '/page' }, opts), e => e.status === 415 && e.code === 'bad_type' && /html/.test(e.contentType));
  });
  await test('fetch-image: size cap and timeout', async () => {
    await assert.rejects(prov.fetchImage({ url: base + '/huge' }, { ...opts, maxBytes: 1024 * 1024 }), e => e.status === 413);
    await assert.rejects(prov.fetchImage({ url: base + '/slow' }, { ...opts, timeoutMs: 300 }), e => e.status === 504);
  });
  srv.close();

  for (const f of ['server.js', 'server/provenance.js', 'server/net-guard.js', 'public/provenance.js']) new vm.Script(fs.readFileSync(path.join(__dirname, '..', f), 'utf8'));
  console.log('✓ provenance sources parse');
  console.log('  measured distances (combined of dHash/pHash, /64):', results.map(([k, c]) => `${k}: d${c.d} p${c.p}`).join(' · '));
  process.exit(failed ? 1 : 0);
})();
