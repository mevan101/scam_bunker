// Zero-dependency tests for the dating timeline (public/timeline.js): merge, sort, time zones, contradictions,
// bounds and the export lines. Every case below is invented. Run: npm test
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');
const ctx = { window: {}, URL }; vm.createContext(ctx);
for (const f of ['provenance.js', 'events-core.js', 'timeline.js']) vm.runInContext(fs.readFileSync(path.join(__dirname, '../public', f), 'utf8'), ctx);
const T = ctx.window.ScamBunkerTimeline, P = ctx.window.ScamBunkerProvenance, C = ctx.window.SBEventsCore;
let failed = 0;
const test = (name, fn) => { try { fn(); console.log(`✓ ${name}`); } catch (e) { failed++; console.log(`✗ ${name}\n    ${e.stack.split('\n').slice(0, 3).join('\n    ')}`); } };
const opts = { parseClaimedDate: P.parseClaimedDate, now: Date.parse('2026-11-26T12:00:00Z') };

const baseCase = () => ({
  at: '2026-11-26T10:00:00.000Z', text: 'Flood today in the fictional town of Riverton', url: 'https://social.example/post/1',
  forensics: {
    exif: { Make: 'ExampleCam', Model: 'X1', DateTimeOriginal: '2019:03:14 12:00:00', DateTime: '2019:03:14 12:05:00' }, xmpFields: {}, editors: [],
    earliest: { when: '2019-03-14T12:00:00' },
    timeline: [
      { when: '2019-03-14T12:05:00', what: 'Last written by software', src: 'EXIF DateTime', trust: 'medium' },
      { when: '2019-03-14T12:00:00', what: 'Shutter pressed / image captured', src: 'EXIF DateTimeOriginal', trust: 'high' },
      { when: '2026-11-25T08:00:00', what: 'File last modified on this device', src: 'Filesystem', trust: 'low' },
    ],
  },
});

test('parseWhen: EXIF has no zone, ISO offsets and Z are kept', () => {
  const a = T.parseWhen('2019:03:14 12:00:00');
  assert.strictEqual(a.zone.kind, 'unknown'); assert.strictEqual(a.when, '2019-03-14T12:00:00'); assert.strictEqual(T.zoneLabel(a), 'timezone unknown');
  const b = T.parseWhen('2019-03-14T12:00:00+06:00');
  assert.strictEqual(b.zone.offsetMin, 360); assert.strictEqual(b.ms, Date.parse('2019-03-14T06:00:00Z')); assert.strictEqual(T.zoneLabel(b), 'UTC+06:00');
  const c = T.parseWhen('2019-03-14T12:00:00Z'); assert.strictEqual(c.zone.kind, 'utc');
  const d = T.parseWhen('2019:03:14 12:00:00', '-05:30'); assert.strictEqual(d.zone.offsetMin, -330);
  assert.strictEqual(T.parseWhen('0000:00:00 00:00:00'), null); assert.strictEqual(T.parseWhen(''), null);
  assert.strictEqual(T.parseWhen('2020-05').precision, 'month');
});

test('span: unknown zone widens by 14 h; day precision covers the day', () => {
  const [lo, hi] = T.span(T.parseWhen('2019-03-14T12:00:00'));
  assert.strictEqual(hi - lo, 28 * 3600e3);
  const day = T.parseWhen('2019-03-14', 'utc', 'day'); const s = T.span(day); assert.strictEqual(s[1] - s[0], 864e5);
});

test('collect: merges file dates and the case, sorted oldest first, with grades', () => {
  const rows = T.collect(baseCase(), opts);
  assert.strictEqual(rows.map(r => r.kind).join(','), 'capture,modified,device,claimed,case');
  for (let i = 1; i < rows.length; i++) assert(rows[i - 1].ms <= rows[i].ms, 'sorted');
  assert.strictEqual(rows[0].src, 'EXIF DateTimeOriginal'); assert.strictEqual(rows[0].grade, 'C3'); assert.strictEqual(rows[0].zone.kind, 'unknown');
  const opened = rows.find(r => r.kind === 'case'); assert.strictEqual(opened.grade, 'A1'); assert.strictEqual(opened.zone.kind, 'utc');
  assert(rows.some(r => r.kind === 'claimed' && r.precision === 'day'), 'claimed date from “today”');
});

test('collect: EXIF offset tag gives the capture a real zone', () => {
  const c = baseCase(); c.forensics.exif.OffsetTimeOriginal = '+06:00';
  const cap = T.collect(c, opts).find(r => r.src === 'EXIF DateTimeOriginal');
  assert.strictEqual(cap.zone.offsetMin, 360); assert.strictEqual(cap.ms, Date.parse('2019-03-14T06:00:00Z'));
});

test('contradiction: claimed event date after the media was captured', () => {
  const rows = T.collect(baseCase(), opts);
  const cl = rows.find(r => r.kind === 'claimed');
  assert.strictEqual(cl.flags.length, 1); assert.match(cl.flags[0].text, /recycled/i); assert.strictEqual(cl.flags[0].weight, 'moderate');
});

test('contradiction: modify before capture within one file', () => {
  const c = baseCase(); c.forensics.timeline[0].when = '2019-03-13T09:00:00';
  const m = T.collect(c, opts).find(r => r.kind === 'modified');
  assert.strictEqual(m.flags.length, 1); assert.match(m.flags[0].text, /Modified before it was captured/);
});

test('no modify-before-capture flag when the order is normal', () => {
  assert(!T.collect(baseCase(), opts).find(r => r.kind === 'modified').flags.length);
});

const provCase = () => {
  const c = baseCase();
  c.text = 'Photo from the fictional Riverton flood on 12 August 2024';
  c.provenance = {
    claimed: { date: '2024-08-12', precision: 'day', basis: '12 August 2024' },
    items: [{ id: 'c1', label: 'Copy 1', imageUrl: 'https://img.example.org/flood.jpg', pageUrl: 'https://news.example.org/story', exifModify: '2016-01-01T00:00:00', pageDate: { published: { iso: '2018-06-01T09:00:00+02:00', source: 'article:published_time' } } }],
    verdict: { dates: [
      { date: '2018-05-02T10:11:12', kind: 'existed', trust: 'high', source: 'Wayback Machine first capture of the image URL (independent archive)', item: 'Copy 1', itemId: 'c1', note: 'https://web.archive.org/web/20180502101112/https://img.example.org/flood.jpg' },
      { date: '2018-06-01T07:00:00', kind: 'page', trust: 'medium', source: 'Page publish date (article:published_time, set by the publisher)', item: 'Copy 1', itemId: 'c1', note: '' },
      { date: '2019-03-14T12:00:00', kind: 'capture', trust: 'medium', source: 'EXIF DateTimeOriginal (embedded, editable)', item: 'Case image', itemId: 'case', note: '' },
    ] },
  };
  return c;
};

test('provenance: Wayback, page publish (keeps its offset) and copy dates are merged; case-file duplicates skipped', () => {
  const rows = T.collect(provCase(), opts);
  const wb = rows.find(r => r.kind === 'existed');
  assert.strictEqual(wb.grade, 'B2'); assert.strictEqual(wb.zone.kind, 'utc'); assert.match(wb.href, /^https:\/\/web\.archive\.org\//);
  const pg = rows.find(r => r.kind === 'page'); assert.strictEqual(pg.zone.offsetMin, 120); assert.strictEqual(pg.href, 'https://news.example.org/story');
  assert.strictEqual(rows.filter(r => r.src.startsWith('EXIF DateTimeOriginal')).length, 1, 'case EXIF not duplicated');
});

test('contradiction: capture after first-seen (strong) and claimed after a copy existed (strong)', () => {
  const rows = T.collect(provCase(), opts);
  const cap = rows.find(r => r.kind === 'capture' && r.origin === 'Image file');
  assert(cap.flags.some(f => f.weight === 'strong' && /already existed/.test(f.text)));
  const cl = rows.find(r => r.kind === 'claimed');
  assert.strictEqual(cl.flags[0].weight, 'strong'); assert.match(cl.flags[0].text, /2018-05-02/);
});

test('contradiction tolerance: zone-less capture within 14 h of first-seen is not flagged', () => {
  const c = provCase(); c.forensics.exif.DateTimeOriginal = '2018:05:02 20:00:00';
  c.forensics.timeline = [{ when: '2018-05-02T20:00:00', what: 'Shutter pressed', src: 'EXIF DateTimeOriginal', trust: 'high' }];
  const cap = T.collect(c, opts).find(r => r.kind === 'capture' && r.origin === 'Image file');
  assert(!cap.flags.length);
});

test('bounds: earliest possible from the file, existed-by from the archive; strong-contradicted capture is dropped', () => {
  let b = T.bounds(T.collect(baseCase(), opts));
  assert.strictEqual(b.early.src, 'EXIF DateTimeOriginal'); assert.strictEqual(b.late.kind, 'case');
  b = T.bounds(T.collect(provCase(), opts));
  assert.strictEqual(b.late.kind, 'existed'); assert.strictEqual(b.early, null);
});

test('video, corroboration, RDAP, crt.sh and event listings are merged', () => {
  const c = { at: '2026-11-26T10:00:00Z', text: '', url: 'https://events.example.org/e/1',
    video: { timeline: [{ when: '2025-01-02T03:04:05', what: 'Container created (movie header)', src: 'MP4 mvhd creation_time (UTC by spec, 1904 epoch)', trust: 'medium' }, { when: '2025-01-02T09:04:05', what: 'Recorded (device local time, zone unknown)', src: 'Apple com.apple.quicktime.creationdate', trust: 'high' }] },
    corroborate: { sun: { date: '2025-01-02', time: '09:00', offset: '+06:00', lat: 23.7, lon: 90.4 }, wx: { date: '2025-01-02', time: '', offsetMin: 360, timezone: 'Asia/Dhaka', text: 'Clear sky', claim: 'rain', result: 'contradicted', url: 'https://open-meteo.com/' }, crt: { domain: 'riverton-relief.example', firstSeen: '2025-01-01T00:00:00', url: 'https://crt.sh/' } },
    domainAges: { 'riverton-relief.example': { registeredAt: '2024-12-30T00:00:00Z', registrar: 'Example Registrar' } } };
  const listings = [C.normalizeListing({ id: 'L1', url: 'https://events.example.org/e/1', title: 'Fictional Relief Meetup', start: '2025-01-05T18:00', tz: 'Asia/Dhaka', city: 'Dhaka' })];
  const rows = T.collect(c, { ...opts, listings });
  const kinds = rows.map(r => r.kind);
  for (const k of ['created', 'capture', 'check', 'domain', 'event', 'case']) assert(kinds.includes(k), k);
  assert.strictEqual(rows.find(r => r.src.startsWith('MP4 mvhd')).zone.kind, 'utc');
  assert.strictEqual(rows.find(r => r.src.startsWith('Apple')).zone.kind, 'unknown');
  const ev = rows.find(r => r.kind === 'event'); assert.strictEqual(ev.ms, Date.parse('2025-01-05T12:00:00Z')); assert.match(T.zoneLabel(ev), /Asia\/Dhaka/);
  assert(rows.find(r => /Historical weather/.test(r.what)).flags.length === 1, 'weather contradiction');
  assert.strictEqual(rows.find(r => /RDAP/.test(r.src)).grade, 'A2');
});

test('dates after the case was opened are flagged; unsafe links are dropped', () => {
  const c = baseCase(); c.url = 'javascript:alert(1)';
  c.forensics.timeline.push({ when: '2030-01-01T00:00:00', what: 'Created', src: 'XMP CreateDate', trust: 'medium' });
  const rows = T.collect(c, opts);
  assert(rows.find(r => r.src === 'XMP CreateDate').flags.some(f => /after the case was opened/.test(f.text)));
  assert.strictEqual(rows.find(r => r.kind === 'claimed').href, null);
});

test('ticks pick a readable unit', () => {
  assert.strictEqual(T.ticks(Date.parse('2010-01-01'), Date.parse('2026-01-01')).unit, 'year');
  assert.strictEqual(T.ticks(Date.parse('2026-01-01'), Date.parse('2026-01-03')).unit, 'day');
  assert(T.ticks(Date.parse('2010-01-01'), Date.parse('2026-01-01')).ticks.length <= 6);
});

test('svg is labelled and escapes content; export lines include contradictions', () => {
  const esc = s => String(s).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const c = provCase(); c.provenance.verdict.dates[0].item = '<img src=x onerror=1>';
  const rows = T.collect(c, opts);
  const s = T.svg(rows, T.bounds(rows), esc);
  assert.match(s, /role="img"/); assert.match(s, /<title id="tlv-t">/); assert(!s.includes('<img'), 'escaped');
  const L = T.reportLines(rows);
  assert.strictEqual(L[1], 'DATING TIMELINE'); assert(L.some(l => /! \[strong\]/.test(l))); assert(L.some(l => /timezone unknown/.test(l)));
});

test('review fixes: unlinked listings skipped, multi-date posts give no fallback claim, domains never date media, page dates do not bound', () => {
  const listings = [C.normalizeListing({ id: 'L9', url: 'https://events.example.org/e/9', title: 'Unrelated', start: '2025-01-05T18:00', tz: 'Asia/Dhaka' })];
  assert(!T.collect(baseCase(), { ...opts, listings }).some(r => r.kind === 'event'));
  const c = baseCase(); c.text = 'Archive photo from 2019, reposted in 2024';
  assert(!T.collect(c, opts).some(r => r.kind === 'claimed'));
  const m = baseCase(); m.forensics.timeline = []; m.domainAges = { 'a.example': { registeredAt: '2020-01-01T00:00:00Z' } };
  assert.strictEqual(T.bounds(T.collect(m, opts)).early, null);
  const t = { at: '2026-11-26T10:00:00Z', text: '', domainAges: m.domainAges };
  assert.strictEqual(T.bounds(T.collect(t, opts)).early.kind, 'domain');
  const pc = provCase(); pc.provenance.verdict.dates = pc.provenance.verdict.dates.filter(d => d.kind === 'page');
  assert.strictEqual(T.bounds(T.collect(pc, opts)).late.kind, 'case');
});

console.log(failed ? `✗ timeline: ${failed} failed` : 'timeline: all tests passed');
process.exit(failed ? 1 : 0);
