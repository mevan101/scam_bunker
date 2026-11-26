// Zero-dependency tests for the MP4/MOV atom parser and keyframe picker in public/video.js.
// The sample file is hand-built here, atom by atom. All metadata is invented.
const assert = require('assert');
const V = require('../public/video.js');

let passed = 0;
const test = (name, fn) => { try { fn(); passed++; } catch (e) { console.error('FAIL', name, '\n ', e.message); process.exitCode = 1; } };

// ---------- atom builders ----------
const enc = s => Buffer.from(s, 'utf8');
const fourcc = s => Buffer.from(s, 'latin1'); // '©' is 0xA9 in latin1, as in real files
const u8 = n => Buffer.from([n & 255]);
const u16 = n => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const box = (type, ...parts) => { const body = Buffer.concat(parts); return Buffer.concat([u32(8 + body.length), fourcc(type), body]); };
const full = (type, v, flags, ...parts) => box(type, u8(v), Buffer.from([0, 0, flags]), ...parts);
const mac = iso => Math.round(Date.parse(iso + 'Z') / 1000) + V.MAC_EPOCH;
const matrix = Buffer.concat([u32(0x10000), u32(0), u32(0), u32(0), u32(0x10000), u32(0), u32(0), u32(0), u32(0x40000000)]);

const mvhd = (v, c, m, ts, dur) => full('mvhd', v, 0, ...(v === 1 ? [u64(c), u64(m), u32(ts), u64(dur)] : [u32(c), u32(m), u32(ts), u32(dur)]), u32(0x10000), u16(0x100), Buffer.alloc(10), matrix, Buffer.alloc(24), u32(3));
const tkhd = (c, m, id, dur, w, h) => full('tkhd', 0, 3, u32(c), u32(m), u32(id), u32(0), u32(dur), Buffer.alloc(8), u16(0), u16(0), u16(0), u16(0), matrix, u32(w * 65536), u32(h * 65536));
const mdhd = (c, m, ts, dur) => full('mdhd', 0, 0, u32(c), u32(m), u32(ts), u32(dur), u16(((5) << 10) | ((14) << 5) | 7) /* 'eng' */, u16(0));
const hdlr = t => full('hdlr', 0, 0, u32(0), fourcc(t), Buffer.alloc(12), enc('Handler\0'));
const visual = (codec, w, h, compressor) => { const name = Buffer.alloc(32); name[0] = compressor.length; enc(compressor).copy(name, 1); return box(codec, Buffer.alloc(6), u16(1), Buffer.alloc(16), u16(w), u16(h), u32(0x480000), u32(0x480000), u32(0), u16(1), name, u16(24), u16(0xffff)); };
const audio = codec => box(codec, Buffer.alloc(6), u16(1), Buffer.alloc(8), u16(2), u16(16), u32(0), u32(48000 << 16));
const stsd = entry => full('stsd', 0, 0, u32(1), entry);
const stts = (count, delta) => full('stts', 0, 0, u32(1), u32(count), u32(delta));
const trak = (tk, md, h, entry, sttsBox) => box('trak', tk, box('mdia', md, hdlr(h), box('minf', box('stbl', stsd(entry), sttsBox))));
const qtText = (type, s) => box(type, u16(enc(s).length), u16(0x15c7), enc(s));
const dataBox = s => box('data', u32(1), u32(0), enc(s));
function appleMeta(pairs) {
  const keys = full('keys', 0, 0, u32(pairs.length), ...pairs.map(([k]) => box('mdta', enc(k))));
  const ilst = box('ilst', ...pairs.map(([, v], i) => Buffer.concat([u32(8 + 16 + enc(v).length), u32(i + 1), dataBox(v)])));
  return box('meta', hdlr('mdta'), keys, ilst); // QuickTime-style meta: no version/flags
}

// An invented iPhone-style clip: 12.5 s, H.264 1920x1080 at 30 fps + AAC, Apple keys, ©xyz GPS.
const C1 = mac('2026-03-14T08:26:53'), M1 = mac('2026-03-14T08:27:10');
function sampleMov({ withApple = true } = {}) {
  return Buffer.concat([
    box('ftyp', fourcc('qt  '), u32(0), fourcc('qt  ')),
    box('wide'),
    box('mdat', Buffer.alloc(64, 0x55)),
    box('moov',
      mvhd(0, C1, M1, 600, 7500),
      trak(tkhd(C1, M1, 1, 7500, 1920, 1080), mdhd(C1, M1, 30000, 375000), 'vide', visual('avc1', 1920, 1080, 'H.264'), stts(375, 1000)),
      trak(tkhd(C1, M1, 2, 7500, 0, 0), mdhd(C1, M1, 48000, 600000), 'soun', audio('mp4a'), stts(586, 1024)),
      box('udta', qtText('©xyz', '+48.8577+002.2950+035.000/'), qtText('©too', 'Example Encoder 1.0'), qtText('©mak', 'ExampleCam'), qtText('©mod', 'Model X')),
      ...(withApple ? [appleMeta([
        ['com.apple.quicktime.make', 'Apple'], ['com.apple.quicktime.model', 'iPhone 15 Pro'], ['com.apple.quicktime.software', '18.3'],
        ['com.apple.quicktime.creationdate', '2026-03-14T09:26:53+0100'], ['com.apple.quicktime.location.ISO6709', '+48.8584+002.2945+033.000/'],
      ])] : [])),
  ]);
}

test('detects MP4/QuickTime and Matroska magic', () => {
  assert.strictEqual(V.detect(new Uint8Array(sampleMov())), 'mp4');
  assert.strictEqual(V.detect(new Uint8Array([0x1A, 0x45, 0xDF, 0xA3, 0x9F])), 'mkv');
  assert.strictEqual(V.detect(new Uint8Array([0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0])), null);
});

test('1904 epoch: mac seconds convert to UTC ISO; 0 means "not set"', () => {
  assert.strictEqual(V.macToIso(V.MAC_EPOCH), '1970-01-01T00:00:00');
  assert.strictEqual(V.macToIso(3786912000), '2024-01-01T00:00:00');
  assert.strictEqual(V.macToIso(0), null);
  assert.strictEqual(V.unixMisread(1700000000), '2023-11-14T22:13:20'); // Unix seconds written into a 1904 field
  assert.strictEqual(V.unixMisread(3786912000), null);
});

test('ISO 6709 parsing (decimal degrees, DDMM.mm, DDMMSS)', () => {
  assert.deepStrictEqual(V.parseISO6709('+48.8577+002.2950+035.000/'), { lat: 48.8577, lon: 2.295, alt: 35, raw: '+48.8577+002.2950+035.000/' });
  assert.deepStrictEqual(V.parseISO6709('-3351.5+15112.5/').lat, -33.858333);
  const s = V.parseISO6709('+404530-0735900/'); assert.strictEqual(s.lat, 40.758333); assert.strictEqual(s.lon, -73.983333);
  assert.strictEqual(V.parseISO6709('nonsense'), null);
  assert.strictEqual(V.parseISO6709('+99.0+000.0/'), null);
});

test('time-zone aware Apple creationdate', () => {
  assert.deepStrictEqual(V.parseIsoTz('2026-03-14T09:26:53+0100'), { local: '2026-03-14T09:26:53', offset: '+01:00', utc: '2026-03-14T08:26:53' });
  assert.strictEqual(V.parseIsoTz('2026-03-14T09:26:53-05:30').utc, '2026-03-14T14:56:53');
  assert.strictEqual(V.parseIsoTz('2026').local, '2026-01-01T00:00:00');
});

test('raw atom walk: mvhd, tkhd, mdhd, stsd, udta, Apple keys', () => {
  const r = V.parseMP4(new Uint8Array(sampleMov()));
  assert.deepStrictEqual(r.topLevel, ['ftyp', 'wide', 'mdat', 'moov']);
  assert.strictEqual(r.brand, 'qt');
  assert.strictEqual(r.movie.created, '2026-03-14T08:26:53');
  assert.strictEqual(r.movie.modified, '2026-03-14T08:27:10');
  assert.strictEqual(r.movie.duration, 12.5);
  assert.strictEqual(r.tracks.length, 2);
  const [vt, at] = r.tracks;
  assert.strictEqual(vt.handler, 'vide'); assert.strictEqual(vt.codec, 'avc1'); assert.strictEqual(vt.codecName, 'H.264 / AVC');
  assert.strictEqual(vt.width, 1920); assert.strictEqual(vt.height, 1080); assert.strictEqual(vt.id, 1);
  assert.strictEqual(vt.created, '2026-03-14T08:26:53'); assert.strictEqual(vt.modified, '2026-03-14T08:27:10');
  assert.strictEqual(vt.fps, 30); assert.strictEqual(vt.language, 'eng'); assert.strictEqual(vt.compressor, 'H.264');
  assert.strictEqual(at.handler, 'soun'); assert.strictEqual(at.codecName, 'AAC');
  assert.strictEqual(r.udta['©xyz'], '+48.8577+002.2950+035.000/');
  assert.strictEqual(r.udta['©too'], 'Example Encoder 1.0');
  assert.strictEqual(r.keys['com.apple.quicktime.model'], 'iPhone 15 Pro');
  assert.strictEqual(r.keys['com.apple.quicktime.creationdate'], '2026-03-14T09:26:53+0100');
});

test('interpretation: device, GPS, encoder, timeline, verdict', () => {
  const v = V.parseContainer(new Uint8Array(sampleMov()), { lastModified: Date.parse('2026-04-01T10:00:00Z'), now: Date.parse('2026-05-01T00:00:00Z') });
  assert.strictEqual(v.container, 'QuickTime MOV');
  assert.strictEqual(v.make, 'Apple'); assert.strictEqual(v.model, 'iPhone 15 Pro'); // Apple keys win over ©mak/©mod
  assert.strictEqual(v.encoder, 'Example Encoder 1.0');
  assert.strictEqual(v.software, '18.3');
  assert.deepStrictEqual([v.gps.lat, v.gps.lon], [48.8584, 2.2945]); // Apple ISO6709 key wins over ©xyz
  assert.strictEqual(v.videoCodec, 'H.264 / AVC'); assert.strictEqual(v.audioCodec, 'AAC'); assert.strictEqual(v.duration, 12.5);
  assert.strictEqual(v.created, '2026-03-14T08:26:53');
  const whats = v.timeline.map(t => t.src);
  assert.ok(whats.some(s => /mvhd creation/.test(s)));
  assert.ok(whats.some(s => /creationdate/.test(s)));
  assert.ok(whats.some(s => /Filesystem/.test(s)));
  assert.ok(v.timeline.find(t => /creationdate/.test(t.src)).what.includes('UTC+01:00'));
  assert.strictEqual(v.timeline.find(t => t.src === 'Filesystem').trust, 'low');
  assert.strictEqual(v.earliest.when, '2026-03-14T08:26:53');
  assert.ok(v.hidden.some(h => /GPS location: 48.8584, 2.2945/.test(h)));
  assert.ok(v.hidden.some(h => /Device: Apple iPhone 15 Pro/.test(h)));
  assert.strictEqual(v.ai.verdict, 'none detected');
  assert.deepStrictEqual(v.notes, []);
  assert.ok(V.report(v).includes('QuickTime MOV · 1920×1080 · 12.5 s · 30 fps · H.264 / AVC + AAC'));
});

test('without Apple keys falls back to ©mak/©mod/©xyz', () => {
  const v = V.parseContainer(new Uint8Array(sampleMov({ withApple: false })));
  assert.strictEqual(v.make, 'ExampleCam'); assert.strictEqual(v.model, 'Model X');
  assert.deepStrictEqual([v.gps.lat, v.gps.lon, v.gps.alt], [48.8577, 2.295, 35]);
});

test('version-1 mvhd (64-bit times), zero times, FFmpeg + generator name', () => {
  const buf = Buffer.concat([
    box('ftyp', fourcc('isom'), u32(512), fourcc('isom'), fourcc('mp41')),
    box('moov', mvhd(1, 0, 0, 1000, 5000),
      trak(tkhd(0, 0, 1, 5000, 1280, 768), mdhd(0, 0, 16000, 80000), 'vide', visual('hvc1', 1280, 768, ''), stts(80, 1000)),
      box('udta', box('meta', u32(0), hdlr('mdir'), box('ilst', box('©too', dataBox('Lavf61.1.100')), box('©cmt', dataBox('made with Sora (invented sample)'))))))]);
  const v = V.parseContainer(new Uint8Array(buf), { now: Date.parse('2026-05-01T00:00:00Z') });
  assert.strictEqual(v.container, 'MP4'); assert.strictEqual(v.videoCodec, 'H.265 / HEVC');
  assert.strictEqual(v.duration, 5); assert.strictEqual(v.fps, 16);
  assert.strictEqual(v.created, null); assert.strictEqual(v.earliest, null);
  assert.strictEqual(v.encoder, 'Lavf61.1.100');
  assert.ok(v.platformMarks.some(m => /FFmpeg/.test(m)));
  assert.ok(v.platformMarks.some(m => /Creation time is zero/.test(m)));
  assert.deepStrictEqual(v.ai.generators, ['OpenAI Sora']);
  assert.strictEqual(v.ai.verdict, 'likely');
  assert.ok(v.ai.weak.some(w => /silent clip/.test(w)) && v.ai.weak.some(w => /16 fps/.test(w)));
});

test('ordinary words are not generator names; ai_generated=false is not proof', () => {
  const mk = (k, val) => Buffer.concat([box('ftyp', fourcc('mp42'), u32(0)), box('moov', mvhd(0, C1, C1, 1000, 30000), appleMeta([[k, val]]))]);
  const a = V.parseContainer(new Uint8Array(mk('com.apple.quicktime.title', 'Airport runway inspection, Gen 3 crew')));
  assert.deepStrictEqual(a.ai.generators, []); assert.strictEqual(a.ai.verdict, 'none detected');
  assert.strictEqual(V.parseContainer(new Uint8Array(mk('ai_generated', 'false'))).ai.verdict, 'none detected');
  assert.deepStrictEqual(V.parseContainer(new Uint8Array(mk('com.apple.quicktime.software', 'RunwayML Gen-3'))).ai.generators, ['Runway']);
});

test('64-bit largesize boxes and truncated input do not throw', () => {
  const big = Buffer.concat([u32(1), fourcc('free'), u64(24), Buffer.alloc(8)]);
  const full2 = Buffer.concat([box('ftyp', fourcc('mp42'), u32(0)), big, box('moov', mvhd(0, C1, C1, 1000, 1000))]);
  assert.strictEqual(V.parseMP4(new Uint8Array(full2)).movie.created, '2026-03-14T08:26:53');
  const whole = sampleMov();
  for (const n of [9, 40, 120, whole.length - 30]) assert.doesNotThrow(() => V.parseContainer(new Uint8Array(whole.subarray(0, n))));
});

test('anomalies: modified before created, future timestamp', () => {
  const buf = Buffer.concat([box('ftyp', fourcc('mp42'), u32(0)), box('moov', mvhd(0, mac('2031-01-01T00:00:00'), mac('2030-01-01T00:00:00'), 1000, 1000))]);
  const v = V.parseContainer(new Uint8Array(buf), { now: Date.parse('2026-05-01T00:00:00Z') });
  assert.ok(v.notes.some(n => /EARLIER/.test(n)));
  assert.ok(v.notes.some(n => /future/.test(n)));
});

test('readMetadataBytes skips mdat but keeps moov after it', async () => {
  const whole = sampleMov();
  let mdatRead = false;
  const readAt = async (o, n) => { if (o > 50 && o < 100 && n > 16) mdatRead = true; return new Uint8Array(whole.subarray(o, o + n)); };
  return V.readMetadataBytes(readAt, whole.length).then(b => { assert.ok(!mdatRead); assert.strictEqual(V.parseContainer(b).model, 'iPhone 15 Pro'); });
});

// ---------- Matroska / WebM ----------
const ebml = (id, body) => { const idb = Buffer.from(id.toString(16).padStart(id > 0xffffff ? 8 : id > 0xffff ? 6 : id > 0xff ? 4 : 2, '0'), 'hex'); const n = body.length; return Buffer.concat([idb, Buffer.from([0x08, 0, 0, 0, 0, 0, 0, 0]).map((x, i) => i === 0 ? 1 : 0).subarray(0, 1).fill(0x01), Buffer.from([0, 0, 0, 0, 0, 0, n >> 8, n & 255]).subarray(1), body]); };
test('WebM: DocType, Duration, DateUTC (2001 epoch), apps, tracks', () => {
  const f64 = x => { const b = Buffer.alloc(8); b.writeDoubleBE(x); return b; };
  const date = Buffer.alloc(8); date.writeBigInt64BE(BigInt(Date.parse('2026-02-01T12:00:00Z') / 1000 - 978307200) * 1000000000n);
  const buf = Buffer.concat([
    ebml(0x1A45DFA3, ebml(0x4282, enc('webm'))),
    ebml(0x18538067, Buffer.concat([
      ebml(0x1549A966, Buffer.concat([ebml(0x2AD7B1, Buffer.from([0x0F, 0x42, 0x40])), ebml(0x4489, f64(4200)), ebml(0x4461, date), ebml(0x4D80, enc('Chrome')), ebml(0x5741, enc('Chrome'))])),
      ebml(0x1654AE6B, ebml(0xAE, Buffer.concat([ebml(0x83, Buffer.from([1])), ebml(0x86, enc('V_VP9')), ebml(0xE0, Buffer.concat([ebml(0xB0, Buffer.from([0x02, 0x80])), ebml(0xBA, Buffer.from([0x01, 0x68]))]))]))),
    ])),
  ]);
  const v = V.parseContainer(new Uint8Array(buf));
  assert.strictEqual(v.container, 'WebM'); assert.strictEqual(v.duration, 4.2);
  assert.strictEqual(v.videoCodec, 'VP9'); assert.strictEqual(v.width, 640); assert.strictEqual(v.height, 360);
  assert.strictEqual(v.created, '2026-02-01T12:00:00');
  assert.ok(v.platformMarks.some(m => /browser/.test(m)));
});

// ---------- keyframe selection ----------
test('frameDiff and scene-change picking', () => {
  assert.strictEqual(V.frameDiff(new Uint8Array([0, 0]), new Uint8Array([255, 255])), 1);
  assert.strictEqual(V.frameDiff(new Uint8Array([10]), new Uint8Array([10])), 0);
  const times = V.sampleTimes(20, 40);
  assert.ok(times.length >= 39 && times.length <= 41 && times[0] < 0.1 && times[times.length - 1] < 20);
  const samples = times.map((t, i) => ({ t, diff: i === 0 ? 0 : [12, 30].includes(i) ? 0.6 : 0.01 }));
  const { frames, threshold } = V.pickKeyframes(samples, 20, { even: 8 });
  const scenes = frames.filter(f => f.kind === 'scene').map(f => f.t);
  assert.deepStrictEqual(scenes, [times[12], times[30]]);
  assert.ok(threshold >= 0.12);
  assert.ok(frames.filter(f => f.kind === 'interval').length >= 6);
  for (let i = 1; i < frames.length; i++) assert.ok(frames[i].t > frames[i - 1].t);
  assert.deepStrictEqual(V.pickKeyframes([{ t: 0, diff: 0 }], 0).frames, [{ t: 0, kind: 'interval', diff: null }]);
});

test('summarize drops image data, keeps hashes', () => {
  const v = V.parseContainer(new Uint8Array(sampleMov()));
  v.frames = [{ t: 1, kind: 'interval', hash: { d: 'ab', p: 'cd' }, vision: 'data:image/jpeg;base64,AAAA', weak: [] }];
  const s = V.summarize(v);
  assert.ok(!JSON.stringify(s).includes('base64'));
  assert.deepStrictEqual(s.frames[0].hash, { d: 'ab', p: 'cd' });
});

setTimeout(() => console.log(`video: ${passed} tests passed${process.exitCode ? ' (with failures)' : ''}`), 50);
