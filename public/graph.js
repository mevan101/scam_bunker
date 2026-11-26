// Scam Bunker: link graph for the offender index (docs/BACKLOG.md P2-2). Investigator mode only.
// Cases and the identifiers that appear in them, drawn with a seeded force layout on SVG.
// Local data only (saved case files), so it works the same in server and static mode.
// The first half is pure (no DOM) so test/graph.test.js can load it in a vm.
(function () {
  const W = typeof window !== 'undefined' ? window : globalThis;

  // ---------- Pure core ----------
  // Same identifying types as dossier.js STRONG_TYPES. Hashtags, amounts and platforms never link cases.
  const TYPES = ['wallet', 'handle', 'phone', 'email', 'domain', 'image', 'camera'];
  // Colour shows the identifier type only, never risk. The glyph repeats the type so colour is never the only cue.
  const TYPE_INFO = {
    wallet: { name: 'Wallet', glyph: 'W', color: 'var(--violet)' },
    handle: { name: 'Handle', glyph: '@', color: 'var(--blue)' },
    phone: { name: 'Phone', glyph: 'P', color: 'var(--amber)' },
    email: { name: 'Email', glyph: 'E', color: 'var(--green)' },
    domain: { name: 'Domain', glyph: 'D', color: 'var(--ink)' },
    image: { name: 'Image', glyph: 'I', color: 'var(--ink-2)' },
    camera: { name: 'Camera', glyph: 'C', color: 'var(--muted)' },
  };
  // Handles are weak: trivially re-registered or impersonated. Their edges are drawn dashed.
  const WEAK_TYPES = ['handle'];
  // Case shape by verdict family. Cases are drawn in neutral ink: the shape and the label carry the verdict.
  const FAMILIES = {
    scam: { label: 'Scam or likely scam', shape: 'diamond' },
    suspect: { label: 'Suspicious, misleading or edited', shape: 'triangle' },
    synthetic: { label: 'Coordinated or AI-generated', shape: 'hexagon' },
    benign: { label: 'No strong red flags', shape: 'square' },
    unknown: { label: 'No verdict / insufficient evidence', shape: 'circle' },
  };
  const FAMILY_OF = { 'Scam': 'scam', 'Likely scam': 'scam', 'Suspicious': 'suspect', 'Misleading / manipulated': 'suspect', 'Edited image': 'suspect', 'Coordinated / inauthentic': 'synthetic', 'AI-generated content': 'synthetic', 'Likely legitimate': 'benign', 'No strong red flags': 'benign' };
  const verdictFamily = v => FAMILY_OF[v] || 'unknown';
  const EDGE_LABEL = 'appears in';
  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

  function shortLabel(type, key, label) {
    const v = String(key).slice(type.length + 1);
    const clip = s => (s.length > 16 ? s.slice(0, 6) + '…' + s.slice(-6) : s);
    if (type === 'wallet') return clip(v);
    if (type === 'image') return 'image ' + v.slice(0, 8) + '…';
    if (type === 'camera') return 'camera ' + clip(v);
    const l = String(label || v);
    return l.length > 28 ? l.slice(0, 27) + '…' : l;
  }

  // Spreadsheet-style pseudonymous cluster ids: A … Z, AA, AB …
  function clusterName(i) { let s = ''; i += 1; while (i > 0) { const r = (i - 1) % 26; s = String.fromCharCode(65 + r) + s; i = Math.floor((i - 1) / 26); } return s; }

  // cases: saved case objects ({id, at, verdict, risk, platform, text, url, indicators:[{type,key,label}]}).
  // opts.sharedOnly (default true): keep only identifiers that appear in two or more cases, and the cases they link.
  // Edges always run identifier → case: "identifier appears in case".
  function buildGraph(cases = [], opts = {}) {
    const types = new Set(opts.types || TYPES);
    const sharedOnly = opts.sharedOnly !== false;
    const seen = new Set(), cs = [];
    for (const c of Array.isArray(cases) ? cases : []) {
      if (!c || c.id == null || seen.has(String(c.id))) continue;
      seen.add(String(c.id)); cs.push(c);
    }
    cs.sort((a, b) => cmp(String(a.at || ''), String(b.at || '')) || cmp(String(a.id), String(b.id)));

    const inds = new Map();
    const caseKeys = cs.map((c, ci) => {
      const keys = [];
      for (const i of c.indicators || []) {
        if (!i || !types.has(i.type) || !i.key) continue;
        const k = String(i.key); if (keys.includes(k)) continue;
        keys.push(k);
        let e = inds.get(k);
        if (!e) inds.set(k, e = { type: i.type, key: k, label: String(i.label || k), cases: [] });
        e.cases.push(ci);
      }
      return keys;
    });
    const keptInds = [...inds.values()].filter(e => !sharedOnly || e.cases.length >= 2)
      .sort((a, b) => TYPES.indexOf(a.type) - TYPES.indexOf(b.type) || b.cases.length - a.cases.length || cmp(a.key, b.key));
    const keptKeys = new Set(keptInds.map(e => e.key));

    const nodes = [], caseNode = new Map();
    cs.forEach((c, ci) => {
      if (sharedOnly && !caseKeys[ci].some(k => keptKeys.has(k))) return;
      const ref = 'C' + (ci + 1);
      caseNode.set(ci, nodes.length);
      // A correction recorded in the custody log supersedes the original verdict and risk.
      const fix = c.correction && typeof c.correction === 'object' ? c.correction : {};
      const verdict = fix.verdict || c.verdict || null, risk = fix.risk ?? c.risk;
      nodes.push({ id: 'c:' + c.id, kind: 'case', caseId: String(c.id), ref, verdict, family: verdictFamily(verdict), risk: Number.isFinite(+risk) && risk !== null && risk !== '' ? +risk : null, at: c.at || null, platform: c.platform || null, excerpt: String(c.text || c.url || (c.forensics ? 'Image case' : '')).slice(0, 160), label: `${ref} · ${verdict || 'No verdict'}`, cluster: null });
    });
    const edges = [];
    for (const e of keptInds) {
      const ni = nodes.length;
      nodes.push({ id: 'i:' + e.key, kind: 'indicator', type: e.type, key: e.key, label: e.label, short: shortLabel(e.type, e.key, e.label), count: e.cases.length, weak: WEAK_TYPES.includes(e.type), cluster: null });
      for (const ci of e.cases) if (caseNode.has(ci)) edges.push({ source: ni, target: caseNode.get(ci), label: EDGE_LABEL, weak: WEAK_TYPES.includes(e.type) });
    }

    const adj = nodes.map(() => []);
    edges.forEach((e, k) => { adj[e.source].push(k); adj[e.target].push(k); });

    // Connected components (union-find over node indices) → pseudonymous clusters, largest first.
    const parent = nodes.map((_, i) => i);
    const find = x => { while (parent[x] !== x) { parent[x] = parent[parent[x]]; x = parent[x]; } return x; };
    edges.forEach(e => { const a = find(e.source), b = find(e.target); if (a !== b) parent[Math.max(a, b)] = Math.min(a, b); });
    const comps = new Map();
    nodes.forEach((n, i) => { if (!adj[i].length) return; const r = find(i); if (!comps.has(r)) comps.set(r, []); comps.get(r).push(i); });
    const clusters = [...comps.values()]
      .map(m => ({ members: m, cases: m.filter(i => nodes[i].kind === 'case'), indicators: m.filter(i => nodes[i].kind === 'indicator') }))
      .sort((a, b) => b.cases.length - a.cases.length || b.indicators.length - a.indicators.length || a.members[0] - b.members[0])
      .map((c, i) => ({ id: clusterName(i), label: 'Cluster ' + clusterName(i), ...c }));
    clusters.forEach(c => c.members.forEach(i => { nodes[i].cluster = c.id; }));

    return { nodes, edges, adj, clusters, sharedOnly, totalCases: cs.length, counts: { cases: caseNode.size, indicators: keptInds.length, edges: edges.length, clusters: clusters.length } };
  }

  // Same data as the graph, as rows for the table fallback: one row per identifier, grouped by cluster.
  function tableRows(g) {
    const rows = [];
    g.nodes.forEach((n, i) => {
      if (n.kind !== 'indicator') return;
      const cases = g.adj[i].map(k => g.nodes[g.edges[k].target]);
      rows.push({ cluster: n.cluster, type: n.type, label: n.label, weak: n.weak, count: cases.length, cases: cases.map(c => ({ caseId: c.caseId, ref: c.ref, verdict: c.verdict, at: c.at })) });
    });
    const order = new Map(g.clusters.map((c, i) => [c.id, i]));
    rows.sort((a, b) => (order.get(a.cluster) ?? 1e9) - (order.get(b.cluster) ?? 1e9));
    const unlinked = g.nodes.filter((n, i) => n.kind === 'case' && !g.adj[i].length);
    return { rows, unlinked };
  }

  // Seeded PRNG (mulberry32): same seed → same layout.
  function mulberry32(a) { return () => { a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }

  // Barnes–Hut quadtree for O(n log n) repulsion, so 200 cases (~1000 nodes) lay out in well under a second.
  function quadtree(xs, ys, n) {
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (let i = 0; i < n; i++) { if (xs[i] < x0) x0 = xs[i]; if (xs[i] > x1) x1 = xs[i]; if (ys[i] < y0) y0 = ys[i]; if (ys[i] > y1) y1 = ys[i]; }
    const cell = (x, y, s) => ({ x, y, s, m: 0, sx: 0, sy: 0, kids: null, bodies: [] });
    const root = cell(x0 - 1, y0 - 1, Math.max(x1 - x0, y1 - y0) + 2);
    const kidOf = (c, i) => { const h = c.s / 2; return c.kids[(xs[i] >= c.x + h ? 1 : 0) + (ys[i] >= c.y + h ? 2 : 0)]; };
    const insert = (c, i, depth) => {
      for (;;) {
        c.m++; c.sx += xs[i]; c.sy += ys[i];
        if (c.kids) { c = kidOf(c, i); depth++; continue; }
        if (!c.bodies.length || depth > 24) { c.bodies.push(i); return; }
        const h = c.s / 2;
        c.kids = [cell(c.x, c.y, h), cell(c.x + h, c.y, h), cell(c.x, c.y + h, h), cell(c.x + h, c.y + h, h)];
        for (const j of c.bodies) { const k = kidOf(c, j); k.m++; k.sx += xs[j]; k.sy += ys[j]; k.bodies.push(j); }
        c.bodies = [];
        c = kidOf(c, i); depth++;
      }
    };
    for (let i = 0; i < n; i++) insert(root, i, 0);
    return root;
  }

  // Fruchterman–Reingold with Barnes–Hut repulsion and a weak pull to the centre. Returns rounded positions.
  function layout(g, opts = {}) {
    const n = g.nodes.length;
    const seed = (opts.seed ?? 1) >>> 0 || 1;
    const k = opts.k || 42, k2 = k * k, theta2 = (opts.theta ?? 0.9) ** 2, gravity = opts.gravity ?? 0.035;
    const iterations = opts.iterations ?? (n > 600 ? 220 : 300);
    const rnd = mulberry32(seed);
    const xs = new Float64Array(n), ys = new Float64Array(n), dx = new Float64Array(n), dy = new Float64Array(n);
    // Seed each cluster around its own centre on a sunflower spiral, so components start untangled.
    const R = k * Math.sqrt(n + 1);
    const centre = new Map();
    g.clusters.forEach((c, i) => { const a = i * 2.399963, r = k * 2.2 * Math.sqrt(i); centre.set(c.id, [r * Math.cos(a), r * Math.sin(a), k * Math.sqrt(c.members.length)]); });
    for (let i = 0; i < n; i++) {
      const c = centre.get(g.nodes[i].cluster) || [0, 0, R];
      const a = rnd() * Math.PI * 2, r = c[2] * Math.sqrt(rnd());
      xs[i] = c[0] + r * Math.cos(a); ys[i] = c[1] + r * Math.sin(a);
    }
    const t0 = opts.temperature ?? Math.max(k * 2, R / 4);
    const stack = [];
    for (let it = 0; it < iterations && n > 1; it++) {
      dx.fill(0); dy.fill(0);
      const root = quadtree(xs, ys, n);
      for (let i = 0; i < n; i++) {
        stack.length = 0; stack.push(root);
        while (stack.length) {
          const c = stack.pop(); if (!c.m) continue;
          if (!c.kids) {
            for (const j of c.bodies) {
              if (j === i) continue;
              let ex = xs[i] - xs[j], ey = ys[i] - ys[j], d2 = ex * ex + ey * ey;
              if (d2 < 1e-4) { const a = ((i * 7919 + j * 104729) % 360) * Math.PI / 180; ex = Math.cos(a) * 0.01; ey = Math.sin(a) * 0.01; d2 = 1e-4; }
              const f = k2 / d2; dx[i] += ex * f; dy[i] += ey * f;
            }
            continue;
          }
          const cx = c.sx / c.m, cy = c.sy / c.m, ex = xs[i] - cx, ey = ys[i] - cy, d2 = ex * ex + ey * ey;
          if (c.s * c.s < theta2 * d2) { const f = k2 * c.m / d2; dx[i] += ex * f; dy[i] += ey * f; }
          else for (const q of c.kids) stack.push(q);
        }
      }
      for (const e of g.edges) {
        const a = e.source, b = e.target, ex = xs[a] - xs[b], ey = ys[a] - ys[b], d = Math.sqrt(ex * ex + ey * ey) || 0.01, f = d / k;
        dx[a] -= ex * f; dy[a] -= ey * f; dx[b] += ex * f; dy[b] += ey * f;
      }
      const t = t0 * (1 - it / iterations) + 0.5;
      for (let i = 0; i < n; i++) {
        dx[i] -= xs[i] * gravity * k / 10; dy[i] -= ys[i] * gravity * k / 10;
        const d = Math.sqrt(dx[i] * dx[i] + dy[i] * dy[i]);
        if (d > 0) { const s = Math.min(d, t) / d; xs[i] += dx[i] * s; ys[i] += dy[i] * s; }
      }
    }
    const round = v => Math.round(v * 100) / 100;
    const pos = []; let bx0 = Infinity, by0 = Infinity, bx1 = -Infinity, by1 = -Infinity;
    for (let i = 0; i < n; i++) { const x = round(xs[i]), y = round(ys[i]); pos.push({ x, y }); if (x < bx0) bx0 = x; if (x > bx1) bx1 = x; if (y < by0) by0 = y; if (y > by1) by1 = y; }
    return { positions: pos, bounds: n ? { x0: bx0, y0: by0, x1: bx1, y1: by1 } : { x0: 0, y0: 0, x1: 0, y1: 0 } };
  }

  // SVG path for a node shape centred on 0,0.
  function shapePath(shape, r) {
    const f = v => Math.round(v * 100) / 100;
    const poly = (sides, rot) => 'M' + Array.from({ length: sides }, (_, i) => { const a = rot + i * 2 * Math.PI / sides; return `${f(r * Math.cos(a))} ${f(r * Math.sin(a))}`; }).join(' L') + 'Z';
    if (shape === 'diamond') return poly(4, -Math.PI / 2);
    if (shape === 'triangle') return poly(3, -Math.PI / 2);
    if (shape === 'hexagon') return poly(6, 0);
    if (shape === 'square') { const s = f(r * 0.82); return `M${-s} ${-s} L${s} ${-s} L${s} ${s} L${-s} ${s}Z`; }
    const c = f(r * 0.9); return `M${-c} 0 A${c} ${c} 0 1 0 ${c} 0 A${c} ${c} 0 1 0 ${-c} 0Z`;
  }

  // Strong identifiers (not handles) that a new case shares with earlier saved cases. Used for the plain-language reason.
  function sharedWithEarlier(c, saved) {
    const keys = new Map((c?.indicators || []).filter(i => i && TYPES.includes(i.type) && !WEAK_TYPES.includes(i.type)).map(i => [i.key, i]));
    const out = new Map();
    for (const s of saved || []) {
      if (!s || String(s.id) === String(c.id)) continue;
      for (const i of s.indicators || []) if (keys.has(i.key)) out.set(i.key, { ...keys.get(i.key), n: (out.get(i.key)?.n || 0) + 1 });
    }
    return [...out.values()];
  }

  const core = { TYPES, TYPE_INFO, FAMILIES, EDGE_LABEL, verdictFamily, buildGraph, tableRows, layout, shapePath, clusterName, mulberry32, sharedWithEarlier };
  W.ScamBunkerGraph = core;

  // ---------- UI ----------
  const SB = W.ScamBunker;
  if (!SB || typeof document === 'undefined') return;
  const { esc, store, toast } = SB;
  const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const SVGNS = 'http://www.w3.org/2000/svg';
  const isSimple = () => typeof SB.mode === 'function' && SB.mode() === 'simple';
  const fmtDate = iso => { if (!iso) return 'undated'; const d = new Date(iso); return isNaN(d) ? 'undated' : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }); };
  const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
  const typeName = t => TYPE_INFO[t]?.name || t;
  const caseName = n => `Case ${n.ref}: ${n.verdict || 'no verdict'}${n.risk != null ? `, risk ${n.risk}` : ''}, ${fmtDate(n.at)}${n.platform ? ', ' + n.platform : ''}`;
  const indName = n => `${typeName(n.type)} ${n.label}`;

  let dlg = null, g = null, lay = null, nodeEls = [], lineEls = [], view = { s: 1, tx: 0, ty: 0, w: 800, h: 500 }, sel = -1, focusIdx = 0, mode = 'graph';
  const layoutCache = new Map();

  function ensureDialog() {
    if (dlg) return dlg;
    dlg = document.createElement('dialog');
    dlg.id = 'dlg-graph'; dlg.className = 'drawer lg'; dlg.setAttribute('aria-labelledby', 'lg-h');
    const legendShapes = Object.entries(FAMILIES).map(([, f]) => `<li><svg class="lg-key" viewBox="-11 -11 22 22" aria-hidden="true" focusable="false"><path d="${shapePath(f.shape, 9)}" class="lg-case-shape${f.shape === 'circle' ? ' lg-unknown' : ''}"/></svg>${esc(f.label)}</li>`).join('');
    const legendTypes = TYPES.map(t => `<li><svg class="lg-key" viewBox="-11 -11 22 22" aria-hidden="true" focusable="false"><circle r="8" style="fill:${TYPE_INFO[t].color}"/><text class="lg-glyph" dy="0.35em">${esc(TYPE_INFO[t].glyph)}</text></svg>${esc(TYPE_INFO[t].name)}</li>`).join('');
    dlg.innerHTML = `<div class="lg-wrap">
      <header role="none"><h3 id="lg-h">Link graph</h3><button type="button" class="x" data-lg-close aria-label="Close">×</button></header>
      <p class="lg-note"><b>A line means “appears in”:</b> that identifier appears in that saved case. A shared identifier is a lead, not proof that the same person is behind these cases: numbers can be spoofed and handles impersonated. Colours show the identifier type only, never risk or guilt.</p>
      <div class="lg-bar">
        <div class="lg-views" role="group" aria-label="View"><button type="button" class="ghost sm" data-view="graph" aria-pressed="true">Graph</button><button type="button" class="ghost sm" data-view="table" aria-pressed="false">Table</button></div>
        <label class="lg-check"><input type="checkbox" id="lg-all"> Include identifiers seen in only one case</label>
        <span class="grow"></span>
        <span class="lg-sum" id="lg-sum" aria-live="polite"></span>
        <div class="lg-zoom" role="group" aria-label="Zoom" data-pane="graph"><button type="button" class="ghost sm" data-zoom="out" aria-label="Zoom out">−</button><button type="button" class="ghost sm" data-zoom="in" aria-label="Zoom in">+</button><button type="button" class="ghost sm" data-zoom="fit">Fit</button></div>
      </div>
      <div class="lg-main" data-pane="graph">
        <div class="lg-stage"><svg class="lg-svg" id="lg-svg" role="group" aria-roledescription="link graph" aria-describedby="lg-help" xmlns="${SVGNS}"><g class="lg-vp"><g class="lg-edges"></g><g class="lg-elabels" aria-hidden="true"></g><g class="lg-nodes"></g></g></svg>
          <p class="sr-only" id="lg-help">Each node is a saved case or an identifier. Arrow keys move between nearby nodes and select them; plus and minus zoom; 0 fits the graph. The selected node's connections are listed beside the graph. The Table view has the same data.</p></div>
        <aside class="lg-side" id="lg-side" aria-label="Selected node"></aside>
      </div>
      <div class="lg-legend" data-pane="graph"><div><h4>Cases (shape = verdict)</h4><ul>${legendShapes}</ul></div><div><h4>Identifiers (colour and letter = type)</h4><ul>${legendTypes}</ul></div><div><h4>Lines</h4><ul><li><svg class="lg-key" viewBox="0 -6 26 12" aria-hidden="true" focusable="false"><line x1="1" x2="25" class="lg-e"/></svg>appears in</li><li><svg class="lg-key" viewBox="0 -6 26 12" aria-hidden="true" focusable="false"><line x1="1" x2="25" class="lg-e weak"/></svg>appears in (handle: weak, easy to impersonate)</li></ul></div></div>
      <div class="lg-tablewrap" data-pane="table" hidden></div>
    </div>`;
    document.body.append(dlg);
    $('[data-lg-close]', dlg).addEventListener('click', () => dlg.close());
    $$('[data-view]', dlg).forEach(b => b.addEventListener('click', () => setMode(b.dataset.view)));
    $('#lg-all', dlg).addEventListener('change', () => render());
    $$('[data-zoom]', dlg).forEach(b => b.addEventListener('click', () => { const z = b.dataset.zoom; if (z === 'fit') fit(); else zoomAt(view.w / 2, view.h / 2, z === 'in' ? 1.3 : 1 / 1.3); }));
    bindSvg($('#lg-svg', dlg));
    new ResizeObserver(() => { const svg = $('#lg-svg', dlg); if (!svg.clientWidth) return; const cx = (view.w / 2 - view.tx) / view.s, cy = (view.h / 2 - view.ty) / view.s; sizeSvg(svg); view.tx = view.w / 2 - cx * view.s; view.ty = view.h / 2 - cy * view.s; apply(); }).observe($('.lg-stage', dlg));
    $('#lg-side', dlg).addEventListener('click', e => {
      const b = e.target.closest('[data-sel]'); if (b) { select(+b.dataset.sel, { pan: true }); $('#lg-side h4', dlg)?.focus(); return; }
      const o = e.target.closest('[data-open]'); if (o) openCase(o.dataset.open);
    });
    $('.lg-tablewrap', dlg).addEventListener('click', e => { const o = e.target.closest('[data-open]'); if (o) openCase(o.dataset.open); });
    return dlg;
  }

  function openCase(id) {
    if (SB.openCase && SB.openCase(id)) { dlg.close(); document.getElementById('dlg-subjects')?.close(); toast('Case opened'); }
    else toast('That case is no longer in your case files');
  }

  function setMode(m) {
    mode = m;
    $$('[data-view]', dlg).forEach(b => b.setAttribute('aria-pressed', String(b.dataset.view === m)));
    $$('[data-pane]', dlg).forEach(p => { p.hidden = p.dataset.pane !== m; });
    if (m === 'graph') { sizeSvg($('#lg-svg', dlg)); if (lay) fit(); }
  }

  function open(opts = {}) {
    if (isSimple()) { toast('The link graph is part of Investigator mode'); return false; }
    ensureDialog();
    if (!dlg.open) dlg.showModal();
    render();
    setMode(opts.view || (matchMedia('(max-width: 640px)').matches ? 'table' : 'graph'));
    return true;
  }

  function render() {
    const prev = sel >= 0 && g ? g.nodes[sel]?.id : null;
    g = buildGraph(store.get('scambunker.cases', []), { sharedOnly: !$('#lg-all', dlg).checked });
    const sig = g.nodes.map(n => n.id).join('|') + '#' + g.edges.length;
    if (!layoutCache.has(sig)) { if (layoutCache.size > 6) layoutCache.clear(); layoutCache.set(sig, layout(g, { seed: 1 })); }
    lay = layoutCache.get(sig);
    $('#lg-sum', dlg).textContent = g.nodes.length ? [plural(g.counts.cases, 'case'), plural(g.counts.indicators, 'identifier'), plural(g.counts.clusters, 'cluster')].join(' · ') : '';
    drawSvg(); drawTable();
    sel = -1; focusIdx = 0;
    const keep = prev ? g.nodes.findIndex(n => n.id === prev) : -1;
    if (keep >= 0) select(keep); else { setRoving(0); renderSide(); }
    if (mode === 'graph') { sizeSvg($('#lg-svg', dlg)); fit(); }
  }

  function emptyText() {
    if (!g.totalCases) return 'No saved cases yet. Each case you check is saved on this device, and the graph links the ones that share a wallet, phone, email, domain, handle, image or camera.';
    return `None of your ${plural(g.totalCases, 'saved case')} share an identifier yet. Tick “Include identifiers seen in only one case” to see every case.`;
  }

  function nodeMarkup(n, i, p) {
    const name = n.kind === 'case' ? `${caseName(n)}. Contains ${plural(g.adj[i].length, 'identifier')}${n.cluster ? `. Cluster ${n.cluster}` : ''}` : `${indName(n)}. Appears in ${plural(g.adj[i].length, 'case')}${n.cluster ? `. Cluster ${n.cluster}` : ''}`;
    if (n.kind === 'case') {
      const shape = FAMILIES[n.family].shape;
      return `<g class="lg-n lg-c" data-i="${i}" transform="translate(${p.x} ${p.y})" role="button" tabindex="-1" aria-pressed="false" aria-label="${esc(name)}"><circle class="lg-ring" r="15"/><path class="lg-case-shape${n.family === 'unknown' ? ' lg-unknown' : ''}" d="${shapePath(shape, 10)}"/><text class="lg-lbl" y="22">${esc(n.ref)} · ${esc(n.verdict || 'No verdict')}</text></g>`;
    }
    const r = 6 + Math.min(6, (n.count - 1) * 1.5), t = TYPE_INFO[n.type] || { glyph: '?', color: 'var(--muted)' };
    return `<g class="lg-n lg-i" data-i="${i}" transform="translate(${p.x} ${p.y})" role="button" tabindex="-1" aria-pressed="false" aria-label="${esc(name)}"><circle class="lg-ring" r="${r + 5}"/><circle class="lg-dot" r="${r}" style="fill:${t.color}"/><text class="lg-glyph" dy="0.35em" style="font-size:${Math.max(8, r * 1.1)}px">${esc(t.glyph)}</text><text class="lg-lbl" y="${r + 12}">${esc(n.short)}</text></g>`;
  }

  function drawSvg() {
    const svg = $('#lg-svg', dlg), P = lay.positions;
    svg.setAttribute('aria-label', g.nodes.length ? `Link graph: ${plural(g.counts.cases, 'case')} and ${plural(g.counts.indicators, 'identifier')} in ${plural(g.counts.clusters, 'cluster')}` : 'Link graph: empty');
    $('.lg-edges', svg).innerHTML = g.edges.map((e, k) => `<line class="lg-e${e.weak ? ' weak' : ''}" data-e="${k}" x1="${P[e.source].x}" y1="${P[e.source].y}" x2="${P[e.target].x}" y2="${P[e.target].y}"/>`).join('');
    $('.lg-nodes', svg).innerHTML = g.nodes.map((n, i) => nodeMarkup(n, i, P[i])).join('');
    $('.lg-elabels', svg).innerHTML = '';
    nodeEls = $$('.lg-n', svg); lineEls = $$('.lg-e', $('.lg-edges', svg));
    $('.lg-stage', dlg).classList.toggle('lg-empty', !g.nodes.length);
    let empty = $('.lg-empty-msg', dlg);
    if (!g.nodes.length) { if (!empty) { empty = document.createElement('p'); empty.className = 'empty lg-empty-msg'; $('.lg-stage', dlg).append(empty); } empty.textContent = emptyText(); }
    else empty?.remove();
  }

  function drawTable() {
    const { rows, unlinked } = tableRows(g);
    const caseCell = c => `<li><button type="button" class="lg-link" data-open="${esc(c.caseId)}">${esc(c.ref)}</button> ${esc(c.verdict || 'No verdict')} · ${esc(fmtDate(c.at))}</li>`;
    $('.lg-tablewrap', dlg).innerHTML = (rows.length ? `<table class="os-table lg-table"><caption>Identifiers and the saved cases they appear in</caption><thead><tr><th scope="col">Cluster</th><th scope="col">Type</th><th scope="col">Identifier</th><th scope="col">Appears in</th></tr></thead><tbody>${rows.map(r => `<tr><td>${esc(r.cluster || '—')}</td><td>${esc(typeName(r.type))}${r.weak ? ' <span class="lg-weak">(weak)</span>' : ''}</td><td><code>${esc(r.label)}</code></td><td><span class="lg-count">${plural(r.count, 'case')}</span><ul class="lg-cases">${r.cases.map(caseCell).join('')}</ul></td></tr>`).join('')}</tbody></table>` : `<p class="empty">${esc(emptyText())}</p>`)
      + (unlinked.length ? `<section class="lg-unlinked"><h4>Cases with no identifiers</h4><ul class="lg-cases">${unlinked.map(caseCell).join('')}</ul></section>` : '');
  }

  function renderSide() {
    const side = $('#lg-side', dlg);
    if (!g.nodes.length) { side.innerHTML = ''; return; }
    if (sel < 0) {
      side.innerHTML = `<h4 tabindex="-1">Clusters</h4><p class="muted">Select a node to list its connections. Clusters are groups of cases joined by shared identifiers; the letters are pseudonyms, not names.</p>${g.clusters.length ? `<ul class="lg-conn">${g.clusters.map(c => `<li><button type="button" class="lg-link" data-sel="${c.cases[0] ?? c.members[0]}">${esc(c.label)}</button> <span class="muted">${plural(c.cases.length, 'case')} · ${plural(c.indicators.length, 'identifier')}</span></li>`).join('')}</ul>` : '<p class="empty">No identifier is shared between cases.</p>'}`;
      return;
    }
    const n = g.nodes[sel], others = g.adj[sel].map(k => { const e = g.edges[k]; return e.source === sel ? e.target : e.source; });
    if (n.kind === 'case') {
      side.innerHTML = `<p class="eyebrow">Case${n.cluster ? ` · Cluster ${esc(n.cluster)}` : ''}</p><h4 tabindex="-1">${esc(n.ref)} · ${esc(n.verdict || 'No verdict')}</h4>
        <dl class="kv lg-kv"><dt>Risk</dt><dd>${n.risk != null ? esc(n.risk) + '/100' : '—'}</dd><dt>Saved</dt><dd>${esc(fmtDate(n.at))}</dd>${n.platform ? `<dt>Platform</dt><dd>${esc(n.platform)}</dd>` : ''}</dl>
        ${n.excerpt ? `<p class="lg-excerpt">${esc(n.excerpt)}</p>` : ''}
        <h5>${others.length ? `${plural(others.length, 'identifier')} in this case` : 'No identifiers shown for this case'}</h5>
        <ul class="lg-conn">${others.map(j => { const m = g.nodes[j]; return `<li><button type="button" class="lg-link" data-sel="${j}"><span class="tag">${esc(typeName(m.type))}</span> <code>${esc(m.short)}</code></button> <span class="muted">${EDGE_LABEL} ${plural(m.count, 'case')}</span></li>`; }).join('')}</ul>
        <button type="button" class="ghost sm" data-open="${esc(n.caseId)}">Open case</button>`;
    } else {
      side.innerHTML = `<p class="eyebrow">${esc(typeName(n.type))}${n.cluster ? ` · Cluster ${esc(n.cluster)}` : ''}</p><h4 tabindex="-1"><code>${esc(n.label)}</code></h4>
        ${n.weak ? '<p class="lg-weak-note">Handles are weak identifiers: anyone can register a similar name or impersonate one. Treat this link as a lead only.</p>' : ''}
        <h5>${EDGE_LABEL} ${plural(others.length, 'case')}</h5>
        <ul class="lg-conn">${others.map(j => { const m = g.nodes[j]; return `<li><button type="button" class="lg-link" data-sel="${j}">${esc(m.ref)} · ${esc(m.verdict || 'No verdict')}</button> <span class="muted">${esc(fmtDate(m.at))}${m.platform ? ' · ' + esc(m.platform) : ''}</span></li>`; }).join('')}</ul>`;
    }
  }

  function setRoving(i) {
    const nodes = nodeEls;
    nodes[focusIdx]?.setAttribute('tabindex', '-1');
    focusIdx = Math.max(0, Math.min(i, nodes.length - 1));
    nodes[focusIdx]?.setAttribute('tabindex', '0');
  }

  function select(i, opts = {}) {
    const svg = $('#lg-svg', dlg), nodes = nodeEls, lines = lineEls;
    $$('.lg-hl', svg).forEach(el => el.classList.remove('lg-hl'));
    $$('.lg-sel', svg).forEach(el => { el.classList.remove('lg-sel'); el.setAttribute('aria-pressed', 'false'); });
    sel = i;
    const labels = $('.lg-elabels', svg);
    if (i < 0 || !nodes[i]) { svg.classList.remove('lg-has-sel'); labels.innerHTML = ''; renderSide(); return; }
    svg.classList.add('lg-has-sel');
    nodes[i].classList.add('lg-sel', 'lg-hl'); nodes[i].setAttribute('aria-pressed', 'true');
    const P = lay.positions;
    const ks = g.adj[i];
    ks.forEach(k => { const e = g.edges[k]; lines[k]?.classList.add('lg-hl'); nodes[e.source].classList.add('lg-hl'); nodes[e.target].classList.add('lg-hl'); });
    labels.innerHTML = ks.slice(0, 60).map(k => { const e = g.edges[k], a = P[e.source], b = P[e.target]; return `<text class="lg-el" x="${(a.x + b.x) / 2}" y="${(a.y + b.y) / 2}" dy="-3">${EDGE_LABEL}</text>`; }).join('');
    // Draw the selection on top.
    nodes[i].parentNode.append(nodes[i]);
    setRoving(i);
    renderSide();
    if (opts.pan) ensureVisible(i);
    if (opts.focus) nodes[i].focus({ preventScroll: true });
  }

  // ---------- Pan / zoom ----------
  function sizeSvg(svg) { const w = svg.clientWidth, h = svg.clientHeight; if (!w || !h) return; view.w = w; view.h = h; svg.setAttribute('viewBox', `0 0 ${w} ${h}`); }
  function apply() {
    const svg = $('#lg-svg', dlg);
    $('.lg-vp', svg).setAttribute('transform', `translate(${Math.round(view.tx * 10) / 10} ${Math.round(view.ty * 10) / 10}) scale(${Math.round(view.s * 1000) / 1000})`);
    svg.style.setProperty('--lg-s', String(view.s));
    svg.classList.toggle('lg-zoomed', view.s >= 1.4);
  }
  function fit() {
    if (!lay || !g.nodes.length) return;
    const b = lay.bounds, pad = 40, bw = b.x1 - b.x0 + pad * 2, bh = b.y1 - b.y0 + pad * 2;
    view.s = Math.min(view.w / bw, view.h / bh, 2);
    view.tx = view.w / 2 - view.s * (b.x0 + b.x1) / 2; view.ty = view.h / 2 - view.s * (b.y0 + b.y1) / 2;
    apply();
  }
  function zoomAt(px, py, f) {
    const s = Math.max(0.05, Math.min(8, view.s * f)); f = s / view.s;
    view.tx = px - (px - view.tx) * f; view.ty = py - (py - view.ty) * f; view.s = s; apply();
  }
  function ensureVisible(i) {
    const p = lay.positions[i], x = p.x * view.s + view.tx, y = p.y * view.s + view.ty, m = 30;
    if (x < m || y < m || x > view.w - m || y > view.h - m) { view.tx = view.w / 2 - p.x * view.s; view.ty = view.h / 2 - p.y * view.s; apply(); }
  }
  // Nearest node in an arrow-key direction, preferring nodes close to the axis.
  function neighbourInDirection(i, ux, uy) {
    const P = lay.positions, p = P[i]; let best = -1, score = Infinity;
    for (let j = 0; j < P.length; j++) {
      if (j === i) continue;
      const ex = P[j].x - p.x, ey = P[j].y - p.y, along = ex * ux + ey * uy;
      if (along <= 0.5) continue;
      const perp = Math.abs(ex * uy - ey * ux), s = along + perp * 2.5;
      if (s < score) { score = s; best = j; }
    }
    return best;
  }
  function bindSvg(svg) {
    let drag = null;
    const pt = e => { const r = svg.getBoundingClientRect(); return [(e.clientX - r.left) * view.w / r.width, (e.clientY - r.top) * view.h / r.height]; };
    svg.addEventListener('pointerdown', e => { if (e.button !== 0) return; const [x, y] = pt(e); drag = { x, y, tx: view.tx, ty: view.ty, moved: false, node: e.target.closest('.lg-n'), id: e.pointerId }; });
    svg.addEventListener('pointermove', e => {
      if (!drag || drag.id !== e.pointerId) return;
      const [x, y] = pt(e);
      if (!drag.moved && Math.hypot(x - drag.x, y - drag.y) > 4) { drag.moved = true; svg.setPointerCapture(e.pointerId); svg.classList.add('lg-panning'); }
      if (drag.moved) { view.tx = drag.tx + x - drag.x; view.ty = drag.ty + y - drag.y; apply(); }
    });
    const end = e => {
      if (!drag || drag.id !== e.pointerId) return;
      if (!drag.moved) { if (drag.node) select(+drag.node.dataset.i, { focus: true }); else select(-1); }
      svg.classList.remove('lg-panning'); drag = null;
    };
    svg.addEventListener('pointerup', end); svg.addEventListener('pointercancel', e => { if (drag) { svg.classList.remove('lg-panning'); drag = null; } });
    svg.addEventListener('wheel', e => { e.preventDefault(); const [x, y] = pt(e); zoomAt(x, y, Math.exp(-e.deltaY * (e.deltaMode ? 0.05 : 0.0015))); }, { passive: false });
    svg.addEventListener('keydown', e => {
      const node = e.target.closest('.lg-n'); if (!node) return;
      const i = +node.dataset.i;
      const dir = { ArrowRight: [1, 0], ArrowLeft: [-1, 0], ArrowDown: [0, 1], ArrowUp: [0, -1] }[e.key];
      if (dir) { e.preventDefault(); const j = neighbourInDirection(i, dir[0], dir[1]); if (j >= 0) select(j, { focus: true, pan: true }); return; }
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(i, { focus: true }); return; }
      if (e.key === '+' || e.key === '=') { e.preventDefault(); zoomAt(view.w / 2, view.h / 2, 1.3); return; }
      if (e.key === '-' || e.key === '_') { e.preventDefault(); zoomAt(view.w / 2, view.h / 2, 1 / 1.3); return; }
      if (e.key === '0') { e.preventDefault(); fit(); return; }
      if (e.key === 'Home') { e.preventDefault(); select(0, { focus: true, pan: true }); return; }
      if (e.key === 'End') { e.preventDefault(); select(g.nodes.length - 1, { focus: true, pan: true }); }
    });
    svg.addEventListener('focusin', e => { const n = e.target.closest('.lg-n'); if (n && sel !== +n.dataset.i) select(+n.dataset.i); });
  }

  // Investigator-only: close if the user switches to Simple mode.
  document.addEventListener('sb:mode', () => { if (dlg?.open && isSimple()) dlg.close(); });

  // Plain-language reason for Simple mode: the same payment or contact detail was in other messages checked on this device.
  document.addEventListener('sb:case', e => {
    const c = e.detail; if (!c || typeof SB.addReasons !== 'function') return;
    try {
      const shared = sharedWithEarlier(c, store.get('scambunker.cases', []));
      if (!shared.length) return;
      const what = { wallet: 'crypto wallet', phone: 'phone number', email: 'email address', domain: 'website', image: 'picture', camera: 'camera' };
      const top = shared.sort((a, b) => b.n - a.n)[0], others = shared.reduce((m, s) => Math.max(m, s.n), 0);
      SB.addReasons(c, [{ text: `The same ${what[top.type] || 'detail'} was also in ${plural(others, 'other message')} you checked on this device. Scammers often reuse the same numbers, wallets and websites, but someone else's details can also be copied, so treat this as a warning sign, not proof.`, weight: 'moderate', source: 'graph' }]);
    } catch (err) { console.debug('graph reason skipped:', err); }
  });

  W.ScamBunkerGraph = { ...core, open, select: i => select(i, { focus: true, pan: true }), get graph() { return g; } };
})();
