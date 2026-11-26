// Scam Bunker: offender dossier core. Pure functions (no DOM), so test/ can load them in a vm.
// Entity resolution: union-find over cases and subjects that share any identifying indicator key.
(function () {
  // Indicator types that identify an actor. Anything else (hashtags, amounts, platforms) is too weak to link cases.
  const STRONG_TYPES = ['wallet', 'handle', 'phone', 'email', 'domain', 'image', 'camera'];
  const BAD_VERDICTS = ['Scam', 'Likely scam'];
  const SUSPECT_VERDICTS = ['Scam', 'Likely scam', 'Suspicious', 'Coordinated / inauthentic'];
  const WALLET_RE = { Bitcoin: /^(bc1[a-z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/, 'Ethereum/EVM': /^0x[a-fA-F0-9]{40}$/, 'Tron (USDT-TRC20)': /^T[1-9A-HJ-NP-Za-km-z]{33}$/ };

  // Same key format as indicators() in app.js, so manual identifiers link to case identifiers.
  function indicatorFor(type, raw) {
    const v = String(raw ?? '').trim();
    if (!v) return null;
    if (type === 'handle') { const h = v.replace(/^[@$]/, '').toLowerCase(); return /^[a-z0-9._-]{2,40}$/.test(h) ? { type, key: `handle:${h}`, label: '@' + h } : null; }
    if (type === 'phone') { const d = v.replace(/\D/g, ''); return d.length >= 9 ? { type, key: `phone:${v.startsWith('+') ? d : d.slice(-10)}`, label: v } : null; } // same rule as app.js: E.164 keeps the country code
    if (type === 'email') { const e = v.toLowerCase(); return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) ? { type, key: `email:${e}`, label: e } : null; }
    if (type === 'domain') {
      let h = v.toLowerCase();
      try { h = new URL(/^[a-z]+:\/\//.test(h) ? h : 'http://' + h).hostname; } catch { return null; }
      h = h.replace(/^www\./, '');
      return /^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(h) ? { type, key: `domain:${h}`, label: h } : null;
    }
    if (type === 'wallet') {
      const chain = walletChain(v); if (!chain) return null;
      return { type, key: `wallet:${v}`, label: `${chain} wallet ${v}`, chain };
    }
    return null;
  }
  const walletChain = a => Object.keys(WALLET_RE).find(k => WALLET_RE[k].test(String(a).trim())) || null;

  function unionFind() {
    const parent = new Map();
    const find = x => { if (!parent.has(x)) parent.set(x, x); let r = x; while (parent.get(r) !== r) r = parent.get(r); while (parent.get(x) !== r) { const n = parent.get(x); parent.set(x, r); x = n; } return r; };
    const union = (a, b) => { const ra = find(a), rb = find(b); if (ra !== rb) parent.set(ra < rb ? rb : ra, ra < rb ? ra : rb); };
    return { find, union, nodes: () => [...parent.keys()] };
  }

  // cases: saved case objects ({id, at, verdict, risk, platform, text, url, indicators}).
  // subjects: manual subjects ({id, name, aliases, indicators, caseIds, findings, createdAt}).
  // Returns clusters that hold a subject or at least two cases.
  function buildClusters(cases = [], subjects = [], opts = {}) {
    const strong = new Set(opts.types || STRONG_TYPES);
    const uf = unionFind();
    const byKey = new Map();
    const link = (node, ind) => {
      if (!ind || !strong.has(ind.type) || !ind.key) return;
      uf.find(node);
      if (byKey.has(ind.key)) uf.union(byKey.get(ind.key), node); else byKey.set(ind.key, node);
    };
    const caseById = new Map(cases.map(c => [String(c.id), c]));
    cases.forEach(c => { uf.find('c:' + c.id); (c.indicators || []).forEach(i => link('c:' + c.id, i)); });
    subjects.forEach(s => {
      uf.find('s:' + s.id);
      (s.indicators || []).forEach(i => link('s:' + s.id, i));
      (s.caseIds || []).forEach(id => { if (caseById.has(String(id))) uf.union('s:' + s.id, 'c:' + id); });
    });

    const groups = new Map();
    uf.nodes().forEach(n => { const r = uf.find(n); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(n); });
    const subjById = new Map(subjects.map(s => [String(s.id), s]));
    const clusters = [];
    for (const members of groups.values()) {
      const cs = members.filter(n => n.startsWith('c:')).map(n => caseById.get(n.slice(2))).filter(Boolean).sort((a, b) => String(a.at).localeCompare(String(b.at)));
      const ss = members.filter(n => n.startsWith('s:')).map(n => subjById.get(n.slice(2))).filter(Boolean);
      if (!ss.length && cs.length < 2) continue;
      clusters.push(describeCluster(cs, ss, strong));
    }
    return clusters.sort((a, b) => b.risk - a.risk || b.cases.length - a.cases.length);
  }

  function describeCluster(cs, ss, strong) {
    const idx = new Map();
    const touch = (ind, when, source) => {
      if (!ind || !strong.has(ind.type)) return;
      const e = idx.get(ind.key) || { type: ind.type, key: ind.key, label: ind.label || ind.key, firstSeen: null, lastSeen: null, sources: [] };
      if (when) { if (!e.firstSeen || when < e.firstSeen) e.firstSeen = when; if (!e.lastSeen || when > e.lastSeen) e.lastSeen = when; }
      if (source && !e.sources.includes(source)) e.sources.push(source);
      idx.set(ind.key, e);
    };
    cs.forEach(c => (c.indicators || []).forEach(i => touch(i, c.at, 'case:' + c.id)));
    ss.forEach(s => (s.indicators || []).forEach(i => touch(i, i.addedAt || s.createdAt, 'subject:' + s.id)));
    const indicators = [...idx.values()].map(e => ({ ...e, caseCount: e.sources.filter(x => x.startsWith('case:')).length }))
      .sort((a, b) => STRONG_TYPES.indexOf(a.type) - STRONG_TYPES.indexOf(b.type) || b.caseCount - a.caseCount);

    const aliases = [...new Set([...ss.flatMap(s => [s.name, ...(s.aliases || [])]), ...indicators.filter(i => i.type === 'handle').map(i => i.label)].filter(Boolean).map(String))];
    const platforms = new Set(cs.map(c => c.platform).filter(Boolean));
    const profiles = [];
    ss.forEach(s => Object.entries(s.findings?.usernames || {}).forEach(([u, f]) => (f.results || []).filter(r => r.status === 'found').forEach(r => { platforms.add(r.site); profiles.push({ username: u, site: r.site, url: r.url, checkedAt: f.at }); })));

    const verdicts = {}; cs.forEach(c => { verdicts[c.verdict || 'Unknown'] = (verdicts[c.verdict || 'Unknown'] || 0) + 1; });
    const timeline = [
      ...cs.map(c => ({ when: c.at, what: `Case: ${c.verdict || 'unknown verdict'}${c.platform ? ' on ' + c.platform : ''}`, ref: 'case:' + c.id })),
      ...ss.map(s => ({ when: s.createdAt, what: `Subject file opened: ${s.name || 'unnamed'}`, ref: 'subject:' + s.id })),
      ...indicators.filter(i => i.firstSeen).map(i => ({ when: i.firstSeen, what: `First seen: ${i.label}`, ref: i.key })),
      ...ss.flatMap(s => Object.values(s.findings?.domains || {}).filter(d => d.registeredAt).map(d => ({ when: d.registeredAt, what: `Domain registered: ${d.domain}${d.young ? ` (${d.ageDays} days old when checked)` : ''}`, ref: 'domain:' + d.domain }))),
      ...ss.flatMap(s => Object.values(s.findings?.wallets || {}).filter(w => w.firstSeen).map(w => ({ when: w.firstSeen, what: `First on-chain activity: ${w.chain} ${String(w.address).slice(0, 10)}…`, ref: 'wallet:' + w.address }))),
    ].filter(t => t.when).sort((a, b) => String(a.when).localeCompare(String(b.when)));

    const risk = clusterRisk(cs, indicators, ss);
    const anchor = ss[0] ? 's:' + ss[0].id : 'c:' + (cs[0] && cs[0].id);
    const title = ss[0]?.name || aliases[0] || indicators[0]?.label || 'Unnamed actor';
    return { id: anchor, title, subjects: ss, cases: cs, indicators, aliases, platforms: [...platforms], profiles, verdicts, timeline, risk, riskLevel: risk >= 70 ? 'high' : risk >= 40 ? 'medium' : 'low' };
  }

  // Overall risk: the worst linked case, raised by repetition and by payment/contact identifiers reused across confirmed scams.
  function clusterRisk(cs, indicators, ss = []) {
    let risk = Math.max(0, ...cs.map(c => +c.risk || 0));
    if (cs.length > 1) risk += Math.min(20, (cs.length - 1) * 5);
    const confirmed = cs.filter(c => BAD_VERDICTS.includes(c.verdict)).length;
    const reusedPayment = indicators.some(i => ['wallet', 'phone', 'email', 'domain', 'image'].includes(i.type) && i.caseCount >= 2);
    if (confirmed && reusedPayment) risk = Math.max(risk, 75);
    if (cs.filter(c => SUSPECT_VERDICTS.includes(c.verdict)).length >= 3) risk = Math.max(risk, 70);
    if (ss.some(s => Object.values(s.findings?.domains || {}).some(d => d.young))) risk += 10;
    return Math.min(100, Math.round(risk));
  }

  // Minimal SHA-256 (fallback when crypto.subtle is unavailable, e.g. a non-secure origin). Input: string → hex.
  function sha256Hex(str) {
    const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    const bytes = new TextEncoder().encode(str);
    const len = bytes.length, total = ((len + 9 + 63) >> 6) << 6;
    const m = new Uint8Array(total); m.set(bytes); m[len] = 0x80;
    const dv = new DataView(m.buffer); dv.setUint32(total - 8, Math.floor(len / 0x20000000)); dv.setUint32(total - 4, (len << 3) >>> 0);
    const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const W = new Uint32Array(64), rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let o = 0; o < total; o += 64) {
      for (let i = 0; i < 16; i++) W[i] = dv.getUint32(o + i * 4);
      for (let i = 16; i < 64; i++) { const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3), s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10); W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0; }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + W[i]) >>> 0;
        const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0; H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    return H.map(x => x.toString(16).padStart(8, '0')).join('');
  }

  window.ScamBunkerDossier = { STRONG_TYPES, indicatorFor, walletChain, unionFind, buildClusters, clusterRisk, sha256Hex };
})();
