// Zero-dependency tests for the user guide (public/guide.html) and the guided first case (public/tour.js).
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const PUB = path.join(__dirname, '..', 'public');
const html = fs.readFileSync(path.join(PUB, 'guide.html'), 'utf8');
const index = fs.readFileSync(path.join(PUB, 'index.html'), 'utf8');
const Tour = require('../public/tour.js');
const { ROUTES } = require('../public/corroborate.js');

const results = [];
function t(name, fn) { try { fn(); results.push(['✓', name]); } catch (e) { results.push(['✗', name, e]); } }
const attrs = (re) => [...html.matchAll(re)].map(m => m[1]);
const hrefs = attrs(/<a\b[^>]*\shref="([^"]*)"/g);
const fakeStore = (init = {}) => { const m = { ...init }; return { getItem: k => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, m }; };
const throwing = { getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('QuotaExceededError'); } };

t('tour: offered on first visit, not after it is done', () => {
  const s = fakeStore();
  assert.strictEqual(Tour.shouldOffer(s), true);
  assert.strictEqual(Tour.markDone(s), true);
  assert.strictEqual(s.m[Tour.KEY], 'done');
  assert.strictEqual(Tour.shouldOffer(s), false);
});
t('tour: blocked or missing localStorage never throws', () => {
  assert.doesNotThrow(() => Tour.shouldOffer(throwing));
  assert.strictEqual(Tour.markDone(throwing), false);
  assert.strictEqual(Tour.shouldOffer(null), true);
  assert.strictEqual(Tour.markDone(null), false);
});
t('tour: five steps in the PRODUCT.md order, each targeting a [data-tour] key', () => {
  assert.deepStrictEqual(Tour.STEPS.map(s => [].concat(s.key).join('+')), ['input', 'examples', 'verdict+reasons', 'actions', 'mode']);
  for (const s of Tour.STEPS) assert.ok(s.title && s.body.length > 40 && Array.isArray(s.fallback));
});
t('tour: steps with a missing target are skipped in both directions', () => {
  const present = new Set([0, 2, 4]), ex = (s, i) => present.has(i);
  assert.strictEqual(Tour.nextIndex(Tour.STEPS, -1, 1, ex), 0);
  assert.strictEqual(Tour.nextIndex(Tour.STEPS, 0, 1, ex), 2);
  assert.strictEqual(Tour.nextIndex(Tour.STEPS, 2, 1, ex), 4);
  assert.strictEqual(Tour.nextIndex(Tour.STEPS, 4, 1, ex), -1);
  assert.strictEqual(Tour.nextIndex(Tour.STEPS, 4, -1, ex), 2);
  assert.strictEqual(Tour.nextIndex(Tour.STEPS, -1, 1, () => false), -1);
});
t('index: Take the tour and Guide in the top bar, tour script and stylesheet loaded', () => {
  assert.match(index, /<button class="ghost" type="button" data-tour-start>Take the tour<\/button>/);
  assert.match(index, /<a class="ghost" href="guide.html">Guide<\/a>/);
  assert.match(index, /<script src="tour.js"><\/script>/);
  assert.match(index, /<link rel="stylesheet" href="guide.css">/);
});
t('guide: one h1, lang set, unique ids, in-page anchors resolve', () => {
  assert.strictEqual((html.match(/<h1\b/g) || []).length, 1);
  assert.match(html, /<html lang="en">/);
  const ids = attrs(/\sid="([^"]+)"/g);
  assert.deepStrictEqual(ids.filter((x, i) => ids.indexOf(x) !== i), [], 'duplicate ids');
  for (const h of hrefs.filter(h => h.startsWith('#'))) assert.ok(ids.includes(h.slice(1)), 'broken anchor ' + h);
  for (const a of attrs(/aria-labelledby="([^"]+)"/g)) assert.ok(ids.includes(a), 'aria-labelledby target missing: ' + a);
});
t('guide: covers every required topic', () => {
  for (const id of ['what', 'submit', 'modes-two', 'read', 'images', 'people', 'claude', 'modes', 'report', 'tour']) assert.ok(html.includes(`id="${id}"`), id);
  assert.match(html, /Leads, not verdicts/);
  assert.match(html, /href="\.\/#tour"/);
});
t('guide: links are https or local files that exist; no javascript: or http:', () => {
  for (const h of hrefs) {
    if (h.startsWith('#')) continue;
    if (/^https:\/\//.test(h)) continue;
    assert.ok(!/^[a-z]+:/i.test(h), 'unexpected scheme: ' + h);
    const file = h.split('#')[0] || 'index.html';
    assert.ok(fs.existsSync(path.join(PUB, file === './' ? 'index.html' : file)), 'missing local file: ' + h);
  }
});
t('guide: no emoji', () => {
  const text = html.replace(/<script[\s\S]*?<\/script>/g, '');
  assert.ok(!/\p{Extended_Pictographic}/u.test(text), 'emoji found');
  assert.ok(!/\p{Extended_Pictographic}/u.test(Tour.STEPS.map(s => s.title + s.body).join(' ')), 'emoji in tour');
});
t('guide: reporting routes match the Corroborate tab and include every Bangladesh route', () => {
  const sec = html.slice(html.indexOf('id="report"'), html.indexOf('id="tour"'));
  const known = new Set([...Object.values(ROUTES.countries).flatMap(c => c.routes), ...ROUTES.platforms, ...ROUTES.web].map(r => r.url).filter(Boolean));
  const used = [...sec.matchAll(/href="(https:[^"]+)"/g)].map(m => m[1]);
  assert.ok(used.length >= 8);
  for (const u of used) assert.ok(known.has(u), 'not in corroborate ROUTES: ' + u);
  for (const r of ROUTES.countries.BD.routes) {
    assert.ok(used.includes(r.url), 'missing BD route ' + r.name);
    if (r.phone) assert.ok(sec.includes(r.phone), 'missing phone for ' + r.name);
  }
  assert.ok(sec.includes(ROUTES.countries.BD.emergency));
});

let fail = 0;
for (const [s, n, e] of results) { console.log(`${s} ${n}`); if (e) { fail++; console.log('   ', e.message); } }
console.log(`\n${results.length - fail}/${results.length} guide tests passed`);
process.exit(fail ? 1 : 0);
