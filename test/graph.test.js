// Zero-dependency tests for the link graph (public/graph.js): graph building, clusters, table data and layout determinism. Run: npm test
// All identifiers are invented (example domains, 555 numbers, made-up wallets).
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');
const src = fs.readFileSync(path.join(__dirname, '../public/graph.js'), 'utf8');
const load = () => { const ctx = { window: {} }; vm.createContext(ctx); vm.runInContext(src, ctx); return ctx.window.ScamBunkerGraph; };
const G = load();
const plain = x => JSON.parse(JSON.stringify(x));

let fail = 0, pass = 0;
const test = (name, fn) => { try { fn(); pass++; console.log('✓', name); } catch (e) { fail++; console.log('✗', name, '\n  ', e.message); } };
const ind = (type, v, label) => ({ type, key: `${type}:${v}`, label: label || v });
const W1 = 'TXk3exampleWalletAAAAAAAAAAAAAAAAA';

const sample = () => [
  { id: 'a', at: '2026-01-01T00:00:00Z', verdict: 'Scam', risk: 80, platform: 'Telegram', text: 'Guaranteed profit, send USDT', indicators: [ind('wallet', W1), ind('handle', 'mentor_example')] },
  { id: 'b', at: '2026-02-01T00:00:00Z', verdict: 'Likely scam', risk: 62, platform: 'WhatsApp', indicators: [ind('wallet', W1), ind('phone', '5550100123', '+1 555 010 0123')] },
  { id: 'c', at: '2026-03-01T00:00:00Z', verdict: 'Suspicious', risk: 40, indicators: [ind('phone', '5550100123'), ind('hashtag', '#crypto')] },
  { id: 'd', at: '2026-03-05T00:00:00Z', verdict: 'No strong red flags', risk: 5, indicators: [ind('email', 'alone@example.org')] },
  { id: 'e', at: '2026-03-06T00:00:00Z', verdict: 'Coordinated / inauthentic', risk: 50, indicators: [ind('domain', 'shop-example.test'), ind('hashtag', '#crypto')] },
  { id: 'f', at: '2026-03-07T00:00:00Z', verdict: 'AI-generated content', risk: 58, indicators: [ind('domain', 'shop-example.test')] },
];

test('shared-only graph: cases linked by a shared strong identifier; edges are labelled "appears in"', () => {
  const g = plain(G.buildGraph(sample()));
  assert.deepStrictEqual(g.nodes.filter(n => n.kind === 'case').map(n => n.caseId), ['a', 'b', 'c', 'e', 'f'], 'd shares nothing; hashtags never link');
  assert.deepStrictEqual(g.nodes.filter(n => n.kind === 'indicator').map(n => n.key), [`wallet:${W1}`, 'phone:5550100123', 'domain:shop-example.test']);
  assert.strictEqual(g.edges.length, 6);
  assert.ok(g.edges.every(e => e.label === 'appears in'));
  assert.ok(g.edges.every(e => g.nodes[e.source].kind === 'indicator' && g.nodes[e.target].kind === 'case'), 'edges run identifier → case');
  assert.deepStrictEqual(g.counts, { cases: 5, indicators: 3, edges: 6, clusters: 2 });
});

test('clusters get pseudonymous letters, largest first; refs number cases by date', () => {
  const g = plain(G.buildGraph(sample()));
  assert.deepStrictEqual(g.clusters.map(c => [c.id, c.cases.length]), [['A', 3], ['B', 2]]);
  const byCase = Object.fromEntries(g.nodes.filter(n => n.kind === 'case').map(n => [n.caseId, [n.ref, n.cluster]]));
  assert.deepStrictEqual(byCase, { a: ['C1', 'A'], b: ['C2', 'A'], c: ['C3', 'A'], e: ['C5', 'B'], f: ['C6', 'B'] });
  assert.strictEqual(G.clusterName(25), 'Z'); assert.strictEqual(G.clusterName(26), 'AA');
});

test('verdict families drive case shape; unknown verdicts are not guessed', () => {
  const g = plain(G.buildGraph(sample()));
  const fam = Object.fromEntries(g.nodes.filter(n => n.kind === 'case').map(n => [n.caseId, n.family]));
  assert.deepStrictEqual(fam, { a: 'scam', b: 'scam', c: 'suspect', e: 'synthetic', f: 'synthetic' });
  assert.strictEqual(G.verdictFamily('Insufficient evidence'), 'unknown');
  assert.strictEqual(G.verdictFamily(undefined), 'unknown');
  for (const f of Object.values(G.FAMILIES)) assert.match(G.shapePath(f.shape, 10), /^M.*Z$/);
});

test('a recorded correction (custody log) supersedes the original verdict and risk', () => {
  const s = sample(); s[0].correction = { verdict: 'No strong red flags', category: null, risk: 10, reason: 'invented', at: '2026-04-01T00:00:00Z' };
  const n = plain(G.buildGraph(s)).nodes.find(x => x.caseId === 'a');
  assert.deepStrictEqual([n.verdict, n.family, n.risk, n.label], ['No strong red flags', 'benign', 10, 'C1 · No strong red flags']);
});

test('all mode keeps single-case identifiers and unlinked cases; handles are weak', () => {
  const g = plain(G.buildGraph(sample(), { sharedOnly: false }));
  assert.strictEqual(g.counts.cases, 6);
  assert.ok(g.nodes.some(n => n.key === 'email:alone@example.org'));
  assert.ok(!g.nodes.some(n => n.type === 'hashtag'), 'weak types never become nodes');
  const h = g.nodes.find(n => n.type === 'handle'); assert.ok(h.weak);
  assert.ok(g.edges.filter(e => e.weak).length === 1);
});

test('input order, duplicate cases and duplicate indicators do not change the graph', () => {
  const s = sample(); s[0].indicators.push(ind('wallet', W1));
  const a = plain(G.buildGraph(s)), b = plain(G.buildGraph([...s].reverse().concat([s[2]])));
  assert.deepStrictEqual(a, b);
});

test('table rows carry the same data as the graph edges', () => {
  const g = G.buildGraph(sample(), { sharedOnly: false });
  const t = plain(G.tableRows(g));
  assert.strictEqual(t.rows.reduce((n, r) => n + r.cases.length, 0), g.edges.length);
  assert.strictEqual(t.rows.length, g.counts.indicators);
  assert.strictEqual(t.rows[0].cluster, 'A');
  const empty = plain(G.tableRows(G.buildGraph([{ id: 'z', at: '2026-01-01', verdict: 'Scam', indicators: [] }], { sharedOnly: false })));
  assert.deepStrictEqual(empty.unlinked.map(c => c.caseId), ['z']);
});

test('empty and malformed input never throws', () => {
  assert.strictEqual(G.buildGraph().nodes.length, 0);
  assert.strictEqual(G.buildGraph(null).nodes.length, 0);
  assert.strictEqual(G.buildGraph([null, {}, { id: 1, indicators: [null, { type: 'wallet' }] }]).nodes.length, 0);
  assert.deepStrictEqual(plain(G.layout(G.buildGraph([]))), { positions: [], bounds: { x0: 0, y0: 0, x1: 0, y1: 0 } });
});

// 200 invented cases (the case-file cap in app.js) in 25 rings that reuse wallets, phones and domains.
function big(n = 200) {
  const out = [], verdicts = ['Scam', 'Likely scam', 'Suspicious', 'Coordinated / inauthentic', 'No strong red flags'];
  for (let i = 0; i < n; i++) {
    const ring = i % 25;
    out.push({ id: 'k' + i, at: new Date(Date.UTC(2026, 0, 1) + i * 36e5).toISOString(), verdict: verdicts[i % 5], risk: (i * 37) % 100, indicators: [
      ind('wallet', `TExampleRing${ring}`), ind('phone', `555010${String(ring).padStart(4, '0')}`), ind('domain', `ring${ring % 12}.example`),
      ind('handle', `user_${i}`), ind('email', `inbox${i}@example.net`), i % 7 === 0 ? ind('image', 'ab' + (i % 3) + 'cd'.repeat(30)) : null].filter(Boolean) });
  }
  return out;
}

test('layout is deterministic: same seed → identical positions, also across fresh module loads', () => {
  const cases = sample();
  const a = plain(G.layout(G.buildGraph(cases), { seed: 7 })), b = plain(G.layout(G.buildGraph([...cases].reverse()), { seed: 7 }));
  assert.deepStrictEqual(a, b);
  const c = plain(load().layout(load().buildGraph(cases), { seed: 7 }));
  assert.deepStrictEqual(a, c);
  const d = plain(G.layout(G.buildGraph(cases), { seed: 8 }));
  assert.notDeepStrictEqual(a.positions, d.positions, 'a different seed gives a different layout');
});

test('layout places connected nodes closer than unconnected ones and keeps every position finite', () => {
  const g = G.buildGraph(sample());
  const { positions: P } = G.layout(g);
  assert.ok(P.every(p => Number.isFinite(p.x) && Number.isFinite(p.y)));
  const dist = (i, j) => Math.hypot(P[i].x - P[j].x, P[i].y - P[j].y);
  const edgeAvg = g.edges.reduce((s, e) => s + dist(e.source, e.target), 0) / g.edges.length;
  const a = g.nodes.findIndex(n => n.caseId === 'a'), f = g.nodes.findIndex(n => n.caseId === 'f');
  assert.ok(edgeAvg < dist(a, f), `edges (${edgeAvg.toFixed(1)}) shorter than the gap between clusters (${dist(a, f).toFixed(1)})`);
  for (let i = 0; i < P.length; i++) for (let j = i + 1; j < P.length; j++) assert.ok(dist(i, j) > 5, 'no overlapping nodes');
});

test('200 cases: builds and lays out fast, deterministically, in both modes', () => {
  const cases = big();
  for (const sharedOnly of [true, false]) {
    const t0 = Date.now();
    const g = G.buildGraph(cases, { sharedOnly });
    const L = G.layout(g);
    const ms = Date.now() - t0;
    console.log(`   ${sharedOnly ? 'shared' : 'all'}: ${g.nodes.length} nodes, ${g.edges.length} edges, ${g.counts.clusters} clusters in ${ms} ms`);
    assert.strictEqual(g.counts.cases, 200);
    assert.ok(ms < 4000, `layout took ${ms} ms`);
    assert.ok(L.positions.every(p => Number.isFinite(p.x) && Number.isFinite(p.y)));
    assert.deepStrictEqual(plain(G.layout(G.buildGraph(cases, { sharedOnly }))), plain(L));
  }
});

test('plain-language reason source: only strong identifiers shared with other saved cases', () => {
  const s = sample();
  const cur = { id: 'new', indicators: [ind('wallet', W1), ind('handle', 'mentor_example')] };
  const r = plain(G.sharedWithEarlier(cur, s));
  assert.deepStrictEqual(r.map(x => [x.type, x.n]), [['wallet', 2]], 'handles are too weak to mention');
  assert.deepStrictEqual(plain(G.sharedWithEarlier({ id: 'a', indicators: s[0].indicators }, [s[0]])), [], 'a case never matches itself');
});

test('graph.js parses and ships no network calls', () => {
  new vm.Script(src);
  assert.ok(!/fetch\(|XMLHttpRequest|\/api\//.test(src), 'local data only, so it works in static mode');
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
