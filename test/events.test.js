// Event-listing overlap detector tests. Zero dependencies: node --test
// All fixtures are invented: fictional organisers, venues and programs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), path = require('path'), vm = require('vm'), crypto = require('crypto');
const core = require('../public/events-core');
const ev = require('../server/events');
const fx = f => fs.readFileSync(path.join(__dirname, 'fixtures/events', f), 'utf8');
const H = 3600000;

// ---------- Time-zone normalisation ----------
test('UTC+06 (Asia/Dhaka) normalises both ways', () => {
  const z = core.zonedToUtc('2025-10-24T16:30', 'Asia/Dhaka');
  assert.equal(new Date(z.utcMs).toISOString(), '2025-10-24T10:30:00.000Z');
  assert.equal(z.offsetMin, 360); assert.equal(z.status, 'ok');
  assert.equal(core.utcToZoned(z.utcMs, { tz: 'Asia/Dhaka' }).iso, '2025-10-24T16:30:00+06:00');
  assert.equal(core.parseIso('2025-10-24T16:30:00+06:00').utcMs, z.utcMs);
  assert.equal(core.parseIso('2025-10-24T16:30:00+0600').utcMs, z.utcMs);
  assert.equal(core.utcToZoned(z.utcMs, { offsetMin: 360 }).time, '16:30');
});

test('DST zones: London, New York, Sydney', () => {
  assert.equal(core.tzOffsetMinutes('Europe/London', Date.UTC(2025, 6, 1)), 60);
  assert.equal(core.tzOffsetMinutes('Europe/London', Date.UTC(2025, 0, 15)), 0);
  assert.equal(core.tzOffsetMinutes('America/New_York', Date.UTC(2025, 6, 1)), -240);
  assert.equal(core.tzOffsetMinutes('America/New_York', Date.UTC(2025, 0, 15)), -300);
  assert.equal(core.tzOffsetMinutes('Australia/Sydney', Date.UTC(2025, 0, 15)), 660);
  assert.equal(core.tzOffsetMinutes('Australia/Sydney', Date.UTC(2025, 6, 15)), 600);
  // Same wall clock either side of a DST change maps to different UTC instants
  const before = core.zonedToUtc('2025-03-08T18:00', 'America/New_York'), after = core.zonedToUtc('2025-03-10T18:00', 'America/New_York');
  assert.equal(new Date(before.utcMs).toISOString(), '2025-03-08T23:00:00.000Z');
  assert.equal(new Date(after.utcMs).toISOString(), '2025-03-10T22:00:00.000Z');
});

test('DST gap and repeated hour are reported, not silently guessed', () => {
  const gap = core.zonedToUtc('2025-03-09T02:30', 'America/New_York');
  assert.equal(gap.status, 'nonexistent');
  assert.equal(core.utcToZoned(gap.utcMs, { tz: 'America/New_York' }).time, '03:30');
  const rep = core.zonedToUtc('2025-11-02T01:30', 'America/New_York');
  assert.equal(rep.status, 'ambiguous');
  assert.equal(new Date(rep.utcMs).toISOString(), '2025-11-02T05:30:00.000Z'); // earlier (EDT) occurrence
  const l = core.normalizeListing({ title: 'x', start: '2025-11-02T01:30', tz: 'America/New_York' });
  assert.ok(l.warnings.some(w => /occurs twice/.test(w)));
});

test('listings: floating times, invalid zones, offset/zone mismatch', () => {
  const f = core.normalizeListing({ title: 'x', start: '2025-10-24T16:30' });
  assert.equal(f.startUtc, null); assert.ok(f.warnings.some(w => /no time zone/.test(w)));
  const bad = core.normalizeListing({ title: 'x', start: '2025-10-24T16:30:00+06:00', tz: 'Mars/Olympus' });
  assert.equal(bad.zone.offsetMin, 360); assert.ok(bad.warnings.some(w => /not a recognised/.test(w)));
  const mm = core.normalizeListing({ title: 'x', start: '2025-10-24T16:30:00+05:30', tz: 'Asia/Dhaka' });
  assert.deepEqual(mm.offsetMismatch, { listed: 330, zone: 360 });
  assert.ok(core.detectFlags([mm]).some(x => x.code === 'offset-mismatch' && x.type === 'c'));
  const noEnd = core.normalizeListing({ title: 'x', start: '2025-10-24T16:30:00Z' });
  assert.equal(noEnd.endUtc - noEnd.startUtc, 2 * H); assert.equal(noEnd.endAssumed, true);
});

// ---------- Overlap math ----------
test('overlap minutes', () => {
  assert.equal(core.overlapMinutes(0, 2 * H, H, 3 * H), 60);
  assert.equal(core.overlapMinutes(0, H, H, 2 * H), 0); // touching is not overlapping
  assert.equal(core.overlapMinutes(0, H, 2 * H, 3 * H), 0);
  assert.equal(core.overlapMinutes(0, 4 * H, H, 2 * H), 60); // containment
});

// ---------- Parsers ----------
test('JSON-LD Event parser (with @graph, Place, PostalAddress, geo)', () => {
  const r = ev.extractFromHtml(fx('jsonld-event.html'), { baseUrl: 'https://lu.ma/aistudy7' });
  const f = r.fields;
  assert.deepEqual([f.title.value, f.title.source], ['Applied AI Study Night', 'jsonld']);
  assert.deepEqual([f.start.value, f.start.source], ['2025-10-24T16:30:00+06:00', 'jsonld']);
  assert.equal(f.end.value, '2025-10-24T18:30:00+06:00');
  assert.deepEqual([f.timeZone.value, f.timeZone.source, f.timeZone.via], ['Asia/Dhaka', 'meta', 'embedded page data']);
  assert.equal(f.venueName.value, 'Northbank Innovation Hub');
  assert.equal(f.venueAddress.value, '12 Lakeview Road, Dhaka, BD');
  assert.equal(f.city.value, 'Dhaka');
  assert.deepEqual(f.geo.value, { lat: 23.7801, lon: 90.4072 });
  assert.deepEqual(f.organizers.value, ['Northwind Dev Circle']);
  assert.deepEqual([f.programs.value, f.programs.source], [['Cloudwave Community Program'], 'jsonld']);
  assert.deepEqual([f.attendees.value, f.attendees.detail], [150, 'capacity']);
  assert.deepEqual(r.discrepancies, [], 'JSON-LD, Google Calendar link and text all agree');
});

test('JSON-LD without offset is interpreted in the page time zone and says so', () => {
  const r = ev.extractFromHtml(fx('jsonld-no-offset.html'));
  assert.equal(r.fields.start.listed, '2025-10-24T02:00:00');
  assert.equal(r.fields.start.value, '2025-10-24T02:00:00+06:00');
  assert.match(r.fields.start.note, /interpreted in Asia\/Dhaka/);
});

test('iCalendar parser: TZID, escaping, GEO, organiser CN, DST gap', () => {
  const [e] = ev.parseIcs(fx('ics-event.ics'));
  assert.equal(e.title, 'Open Data Workshop, Spring Edition');
  assert.equal(e.timeZone, 'Europe/London');
  assert.equal(e.start, '2025-03-30T02:30:00+01:00'); // 01:30 does not exist on 30 Mar 2025 in London
  assert.equal(e.end, '2025-03-30T03:00:00+01:00');
  assert.equal(e.location, 'Harbourside Library, Room 2, 7 Quay Street, Bristol');
  assert.deepEqual(e.geo, { lat: 51.45, lon: -2.597 });
  assert.deepEqual(e.organizers, ['Contoso Builders Guild']);
  assert.deepEqual(ev.parseIcs('BEGIN:VCALENDAR\nBEGIN:VEVENT\nDTSTART:20251024T103000Z\nEND:VEVENT\nEND:VCALENDAR')[0].start, '2025-10-24T10:30:00Z');
  assert.deepEqual(ev.findIcsLinks(fx('ics-link.html'), 'https://www.meetup.com/contoso-builders/events/304821111/'), [{ url: 'https://www.meetup.com/contoso-builders/events/304821111/ical/event.ics' }]);
});

test('Google Calendar dates= parser and page self-disagreement', () => {
  const [g] = ev.parseGoogleCalendar(fx('gcal-conflict.html'));
  assert.equal(g.start, '2025-10-24T16:30:00-04:00'); // floating + ctz=America/New_York (EDT)
  assert.equal(g.end, '2025-10-24T18:30:00-04:00');
  const [z] = ev.parseGoogleCalendar('<a href="https://calendar.google.com/calendar/render?action=TEMPLATE&dates=20251024T103000Z/20251024T123000Z">x</a>');
  assert.equal(z.start, '2025-10-24T10:30:00Z');
  const r = ev.extractFromHtml(fx('gcal-conflict.html'));
  assert.equal(r.fields.start.source, 'ics'); assert.equal(r.fields.start.via, 'google-calendar link');
  assert.deepEqual(r.fields.programs.value, ['Stackline Student Network', 'OpenModel Builders']);
  assert.equal(r.fields.programs.source, 'text');
  assert.equal(r.discrepancies.length, 1);
  assert.deepEqual(r.discrepancies[0].values.map(v => v.value), ['2025-10-24T16:30:00-04:00', '2025-10-25T10:00:00']);
  const flags = core.detectFlags([{ title: 'Student Cloud Day', start: r.fields.start.value, discrepancies: r.discrepancies }]);
  assert.ok(flags.some(f => f.code === 'internal-discrepancy' && f.type === 'b'));
});

test('visible-text parser: date, time range, GMT offset, hosts, sponsors, count; ignores scripts', () => {
  const r = ev.extractFromHtml(fx('text-only.html'));
  const f = r.fields;
  assert.equal(f.title.value, 'Community AI Meetup: Retrieval in Practice');
  assert.deepEqual([f.start.value, f.start.source], ['2025-10-24T16:30:00+06:00', 'text']);
  assert.equal(f.end.value, '2025-10-24T18:00:00+06:00');
  assert.equal(f.venueName.value, 'Riverside Makerspace');
  assert.deepEqual(f.organizers.value, ['Fabrikam AI Collective']);
  assert.deepEqual(f.programs.value, ['Cloudwave Community Program', 'Stackline Student Network']);
  assert.equal(f.attendees.value, 56);
  assert.deepEqual(ev.parseTextDate('Oct 24, 2025 4:30 pm', 2025), { start: '2025-10-24T16:30:00', end: '', detail: '' });
  assert.deepEqual(ev.parseTextDate('24 Oct 12:00 AM', 2025), { start: '2025-10-24T00:00:00', end: '', detail: 'year assumed' });
});

// ---------- Fetch: SSRF guard on every hop, redirect chain, final URL ----------
const fakeFetch = routes => async url => {
  const r = routes[url]; if (!r) throw new Error('unexpected fetch ' + url);
  return new Response(r.body ?? '', { status: r.status ?? 200, headers: r.headers ?? { 'content-type': 'text/html' } });
};
test('fetchFollow re-checks the guard on every redirect hop and refuses private targets', async () => {
  const { assertPublicUrl } = require('../server/net-guard');
  const routes = { 'http://93.184.216.34/s': { status: 302, headers: { location: 'http://127.0.0.1:4400/api/status' } } };
  await assert.rejects(ev.fetchFollow('http://93.184.216.34/s', { fetchImpl: fakeFetch(routes) }), /private or local/);
  await assert.rejects(assertPublicUrl('http://169.254.169.254/latest/meta-data/'), /private or local/);
  await assert.rejects(assertPublicUrl('file:///etc/passwd'), /Only http/);
  const checked = [];
  const r = await ev.fetchFollow('https://short.example/x', {
    guard: async u => { checked.push(u); },
    fetchImpl: fakeFetch({ 'https://short.example/x': { status: 301, headers: { location: 'https://www.meetup.com/g/events/309999999/' } }, 'https://www.meetup.com/g/events/309999999/': { body: '<h1>ok</h1>' } }),
  });
  assert.deepEqual(checked, ['https://short.example/x', 'https://www.meetup.com/g/events/309999999/']);
  assert.deepEqual(r.chain, [{ url: 'https://short.example/x', status: 301 }, { url: 'https://www.meetup.com/g/events/309999999/', status: 200 }]);
  assert.equal(r.finalUrl, 'https://www.meetup.com/g/events/309999999/');
});

test('extractFromUrl: redirect to a different event ID, follows the .ics link through the guard', async () => {
  const cited = 'https://www.meetup.com/contoso-builders/events/301111111/';
  const final = 'https://www.meetup.com/contoso-builders/events/304821111/';
  const guarded = [];
  const r = await ev.extractFromUrl(cited, {
    guard: async u => { guarded.push(u); },
    fetchImpl: fakeFetch({ [cited]: { status: 301, headers: { location: final } }, [final]: { body: fx('ics-link.html') }, [final + 'ical/event.ics']: { body: fx('ics-event.ics'), headers: { 'content-type': 'text/calendar' } } }),
  });
  assert.equal(r.finalUrl, final);
  assert.equal(r.eventId.cited.id, '301111111'); assert.equal(r.eventId.final.id, '304821111');
  assert.equal(r.fields.start.source, 'ics'); assert.equal(r.fields.start.value, '2025-03-30T02:30:00+01:00');
  assert.ok(guarded.includes(final + 'ical/event.ics'));
  const flags = core.detectFlags([{ url: r.url, finalUrl: r.finalUrl, redirects: r.redirects, title: r.fields.title.value, start: r.fields.start.value }]);
  const d = flags.find(f => f.type === 'd'); assert.ok(d); assert.equal(d.strength, 'strong');
});

// ---------- Flag rules ----------
const base = { venueName: 'Northbank Innovation Hub', venueAddress: '12 Lakeview Road, Dhaka', city: 'Dhaka', tz: 'Asia/Dhaka' };
test('implausible-hour rule: 02:00 local is flagged as a likely entry error, never wrongdoing', () => {
  const l = { ...base, title: 'University session', start: '2025-10-24T02:00:00+06:00', end: '2025-10-24T04:00:00+06:00' };
  const f = core.detectFlags([l]).find(x => x.code === 'implausible-hour');
  assert.equal(f.type, 'c'); assert.equal(f.strength, 'moderate');
  assert.match(f.explanation, /14:00 local/); assert.match(f.explanation, /Not evidence of wrongdoing/);
  assert.ok(f.innocent.some(s => /not evidence of wrongdoing/i.test(s)));
  // Same instant shown in UTC (20:00) is fine: the rule uses venue local time, not UTC
  assert.equal(core.detectFlags([{ ...l, start: '2025-10-24T16:30:00+06:00', end: '2025-10-24T18:00:00+06:00' }]).filter(x => x.type === 'c').length, 0);
  assert.equal(core.detectFlags([{ ...l, start: '2025-10-24T06:00:00+06:00' }]).find(x => x.code === 'implausible-hour').strength, 'weak');
  assert.ok(core.detectFlags([{ ...l, start: '2025-10-24T18:00:00+06:00', end: '2025-10-24T17:00:00+06:00' }]).some(x => x.code === 'implausible-duration'));
});

test('redirect-to-different-ID rule', () => {
  const mk = (url, finalUrl, extra) => ({ title: 't', start: '2025-10-24T16:30:00+06:00', url, finalUrl, redirects: [{ url, status: 301 }, { url: finalUrl, status: 200 }], ...extra });
  const d = l => core.detectFlags([l]).filter(f => f.type === 'd');
  assert.equal(d(mk('https://www.meetup.com/g/events/301111111/', 'https://www.meetup.com/g/events/302222222/'))[0].strength, 'strong');
  assert.equal(d(mk('https://lu.ma/oldslug1', 'https://lu.ma/newslug2'))[0].strength, 'moderate'); // slugs get renamed
  assert.equal(d(mk('https://lu.ma/aistudy7', 'https://luma.com/aistudy7')).length, 0); // host change only
  assert.equal(d(mk('https://bit.ly/3abcDEF', 'https://www.meetup.com/g/events/302222222/')).length, 0); // short link: nothing cited
  assert.equal(d(mk('https://bit.ly/3abcDEF', 'https://www.meetup.com/g/events/302222222/', { citedId: '301111111' }))[0].strength, 'strong');
  assert.deepEqual(core.eventIdFromUrl('https://www.eventbrite.com/e/ai-night-tickets-987654321012'), { platform: 'Eventbrite', id: '987654321012', kind: 'numeric' });
  assert.deepEqual(core.eventIdFromUrl('https://developer.microsoft.com/en-us/reactor/events/25123/'), { platform: 'Microsoft Reactor', id: '25123', kind: 'numeric' });
  assert.equal(core.eventIdFromUrl('https://bit.ly/x'), null);
});

test('same venue + overlapping time across different programs', () => {
  const a = { ...base, title: 'AI Study Night', start: '2025-10-24T16:30:00+06:00', end: '2025-10-24T18:30:00+06:00', programs: ['Cloudwave Community Program'] };
  const b = { ...base, venueName: 'Northbank Innovation Hub', title: 'Builders Evening', start: '2025-10-24T17:00:00+06:00', end: '2025-10-24T19:00:00+06:00', programs: ['OpenModel Builders'] };
  const f = core.detectFlags([a, b]).find(x => x.type === 'a');
  assert.equal(f.strength, 'strong'); assert.deepEqual(f.listings, ['L1', 'L2']);
  assert.ok(f.innocent.length >= 2);
  assert.equal(core.detectFlags([a, { ...b, programs: a.programs }]).filter(x => x.type === 'a').length, 0, 'same program: no flag');
  assert.equal(core.detectFlags([a, { ...b, start: '2025-10-24T18:30:00+06:00', end: '2025-10-24T20:00:00+06:00' }]).filter(x => x.type === 'a').length, 0, 'back-to-back: no flag');
  assert.equal(core.detectFlags([a, { ...b, venueName: 'Online', venueAddress: '' }]).filter(x => x.type === 'a').length, 0, 'online: no flag');
  // Same instant expressed in a different zone still overlaps
  assert.equal(core.detectFlags([a, { ...b, start: '2025-10-24T11:00:00Z', end: '2025-10-24T13:00:00Z' }]).filter(x => x.type === 'a').length, 1);
});

test('same listing with conflicting dates across platforms', () => {
  const a = { ...base, title: 'Applied AI Study Night', url: 'https://lu.ma/aistudy7', start: '2025-10-24T16:30:00+06:00', programs: ['Cloudwave Community Program'] };
  const b = { ...base, title: 'Applied AI Study Night', url: 'https://www.meetup.com/northwind/events/305555555/', start: '2025-10-25T10:00:00+06:00', programs: ['OpenModel Builders'] };
  const f = core.detectFlags([a, b]).find(x => x.type === 'b');
  assert.equal(f.strength, 'moderate'); assert.match(f.explanation, /2025-10-24 16:30.*2025-10-25 10:00/);
  const sameId = core.detectFlags([{ ...a, finalUrl: 'https://lu.ma/aistudy7' }, { ...b, title: 'Other name', url: 'https://bit.ly/x', finalUrl: 'https://luma.com/aistudy7' }]).find(x => x.type === 'b');
  assert.equal(sameId.strength, 'strong');
  const ampm = core.detectFlags([a, { ...a, start: '2025-10-24T04:30:00+06:00' }]).find(x => x.type === 'b');
  assert.match(ampm.explanation, /AM\/PM/);
});

test('same day + same city across programs is only ever weak', () => {
  const a = { title: 'A', city: 'Dhaka', tz: 'Asia/Dhaka', start: '2025-10-24T10:00:00+06:00', programs: ['Cloudwave Community Program'], venueName: 'Hall A' };
  const b = { title: 'B', city: 'dhaka', tz: 'Asia/Dhaka', start: '2025-10-24T15:00:00+06:00', programs: ['OpenModel Builders'], venueName: 'Different Place Entirely' };
  const f = core.detectFlags([a, b]).filter(x => x.type === 'e');
  assert.equal(f.length, 1); assert.equal(f[0].strength, 'weak');
  assert.equal(core.detectFlags([a, { ...b, start: '2025-10-25T15:00:00+06:00' }]).filter(x => x.type === 'e').length, 0);
});

// ---------- Claims ledger ----------
test('SHA-256 fallback matches node crypto; ledger hash covers the content', async () => {
  for (const s of ['', 'abc', 'é'.repeat(100), 'x'.repeat(1000)]) assert.equal(core.sha256Fallback(new TextEncoder().encode(s)), crypto.createHash('sha256').update(s).digest('hex'));
  const L = [{ ...base, title: 'Applied <b>AI</b> Study Night', start: '2025-10-24T16:30:00+06:00', sources: { title: 'jsonld', start: 'jsonld' } }];
  const flags = core.detectFlags(L);
  const { html, hash } = await core.buildLedger(L, flags, '2025-10-20T12:00:00.000Z');
  const inner = html.slice(html.indexOf(core.LEDGER_BEGIN) + core.LEDGER_BEGIN.length, html.indexOf(core.LEDGER_END));
  assert.equal(crypto.createHash('sha256').update(inner).digest('hex'), hash);
  assert.ok(html.includes(hash));
  assert.ok(html.includes('not findings of misconduct') && html.includes('Only the sponsoring programs can verify funding or approval'));
  assert.ok(html.includes('Applied &lt;b&gt;AI&lt;/b&gt;'), 'remote content is escaped');
  assert.ok(html.includes('2025-10-24T10:30Z'));
});

test('front-end sources parse', () => {
  for (const f of ['public/events-core.js', 'public/events.js', 'server/events.js', 'server/net-guard.js']) new vm.Script(fs.readFileSync(path.join(__dirname, '..', f), 'utf8'));
});
