// Scam Bunker — template / script matching across local cases (BACKLOG P2-1).
// Recycled scam scripts rotate wallets, handles and links but keep the wording. Each case's text is normalised
// (identifiers replaced by placeholders), cut into word 5-gram shingles and compared with earlier saved cases:
// MinHash signatures pick candidates cheaply, then exact Jaccard similarity of the shingle sets is reported.
// Everything stays in this browser (localStorage). Pure functions are on window.ScamBunkerSimilar and unit-tested
// under node's vm (test/factcheck.test.js); the UI only boots when window.ScamBunker exists.
(function () {
  'use strict';
  const K = 5, PERMS = 128, MIN_TOKENS = 12;
  const SAME_SCRIPT = 0.6, RELATED = 0.35;

  // Identifiers become placeholders so a new wallet or handle does not hide a reused script.
  function normalize(text) {
    return String(text || '').normalize('NFKC').toLowerCase()
      .replace(/https?:\/\/\S+|\bwww\.\S+/g, ' urltoken ')
      .replace(/[\w.+-]+@[\w-]+\.[\w.-]+/g, ' emailtoken ')
      .replace(/@[\w.]{2,}/g, ' handletoken ')
      .replace(/\b(?:0x[0-9a-f]{40}|t[1-9a-z]{33}|(?:bc1|[13])[0-9a-z]{25,61})\b/g, ' wallettoken ')
      .replace(/\+?\d[\d\s().-]{6,}\d/g, ' phonetoken ')
      .replace(/\d+(?:[.,]\d+)*/g, ' numtoken ')
      .replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
  }
  const tokens = text => { const n = normalize(text); return n ? n.split(' ') : []; };

  function shingles(text, k = K) {
    const t = tokens(text), out = new Set();
    if (t.length < MIN_TOKENS) return out; // too short to call anything a "script"
    for (let i = 0; i + k <= t.length; i++) out.add(t.slice(i, i + k).join(' '));
    return out;
  }

  function fnv1a(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); } return h >>> 0; }
  function mix(h, seed) { // murmur3 fmix32 of (h xor seed): one cheap independent-looking hash per permutation
    h = (h ^ seed) >>> 0; h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16; return h >>> 0;
  }
  const SEEDS = Array.from({ length: PERMS }, (_, i) => fnv1a('scambunker-minhash-' + i));

  function minhash(set) {
    const sig = new Uint32Array(PERMS).fill(0xffffffff);
    for (const sh of set) { const h = fnv1a(sh); for (let i = 0; i < PERMS; i++) { const v = mix(h, SEEDS[i]); if (v < sig[i]) sig[i] = v; } }
    return sig;
  }
  function estimate(a, b) { if (!a || !b || a.length !== b.length) return 0; let n = 0; for (let i = 0; i < a.length; i++) n += a[i] === b[i]; return n / a.length; }
  function jaccard(a, b) {
    if (!a.size || !b.size) return 0;
    const [s, l] = a.size < b.size ? [a, b] : [b, a]; let inter = 0;
    for (const x of s) if (l.has(x)) inter++;
    return inter / (a.size + b.size - inter);
  }

  // past: saved cases [{id, at, text, verdict, platform}]. Returns earlier cases at or above RELATED, best first.
  function findSimilar(c, past, { threshold = RELATED } = {}) {
    const a = shingles(c && c.text); if (!a.size) return [];
    const sa = minhash(a), out = [];
    for (const p of past || []) {
      if (!p || p.id === c.id || !p.text || (c.at && p.at && p.at > c.at)) continue;
      const b = shingles(p.text); if (!b.size) continue;
      if (estimate(sa, minhash(b)) < threshold - 0.15) continue; // MinHash prefilter (±0.09 at 128 permutations)
      const j = jaccard(a, b);
      if (j >= threshold) out.push({ id: p.id, at: p.at, verdict: p.verdict || 'Unknown', platform: p.platform || '', similarity: Math.round(j * 1000) / 1000, sameScript: j >= SAME_SCRIPT, snippet: String(p.text).replace(/\s+/g, ' ').slice(0, 120) });
    }
    return out.sort((x, y) => y.similarity - x.similarity);
  }

  const BAD = ['Scam', 'Likely scam', 'Suspicious', 'Coordinated / inauthentic', 'Misleading / manipulated'];
  function observation(matches) {
    const same = matches.filter(m => m.sameScript); if (!same.length) return null;
    const bad = same.filter(m => BAD.includes(m.verdict)).length;
    const top = Math.round(same[0].similarity * 100);
    return { fact: `Text is ${top}% identical in wording to ${same.length} earlier case${same.length > 1 ? 's' : ''}`,
      inference: `Same script reused${bad ? `; ${bad} of those case${bad > 1 ? 's were' : ' was'} judged a scam or manipulation` : ''}. Shared wording links campaigns, not necessarily the same sender. Legitimate notices are templated too.`,
      weight: bad ? 'moderate' : 'weak', similar: true };
  }

  const api = { normalize, shingles, minhash, estimate, jaccard, findSimilar, observation, SAME_SCRIPT, RELATED };
  if (typeof window !== 'undefined') window.ScamBunkerSimilar = api;
  if (typeof window === 'undefined' || !window.ScamBunker || typeof document === 'undefined') return;

  // ======================= UI =======================
  const SB = window.ScamBunker, esc = SB.esc;
  function apply(c) {
    if (!c) return;
    const past = SB.store.get('scambunker.cases', []);
    c.similar = findSimilar(c, past);
    c.caseExtras = { ...(c.caseExtras || {}), similar: c.similar.slice(0, 5).map(({ at, verdict, platform, similarity }) => ({ at, verdict, platform, similarity })) };
    const v = c.final || c.local;
    if (v) { v.observations = (v.observations || []).filter(o => !o.similar); const o = observation(c.similar); if (o) v.observations.unshift(o); }
    SB.renderAll();
    document.dispatchEvent(new CustomEvent('sb:similar', { detail: c }));
  }
  function html(c) {
    const m = (c && c.similar) || [];
    const same = m.filter(x => x.sameScript).length;
    const head = m.length ? `Similar to ${m.length} earlier case${m.length > 1 ? 's' : ''}${same ? ` (${same} same script)` : ''}` : 'No similar earlier cases';
    return `<section aria-labelledby="sim-h"><h3 id="sim-h">${esc(head)}</h3>
      <p class="muted">Word-for-word comparison with your saved cases on this device, ignoring wallets, handles, links, numbers and phone numbers. ${Math.round(SAME_SCRIPT * 100)}% or more is treated as the same script, ${Math.round(RELATED * 100)}% to ${Math.round(SAME_SCRIPT * 100) - 1}% as related wording. A shared script links campaigns, not people.</p>
      ${m.length ? `<ul class="list">${m.map(x => `<li><b>${Math.round(x.similarity * 100)}%</b> ${x.sameScript ? '<span class="w strong">same script</span>' : '<span class="w weak">related wording</span>'} · ${esc(new Date(x.at).toLocaleDateString())} · ${esc(x.verdict)}${x.platform ? ' · ' + esc(x.platform) : ''}: “${esc(x.snippet)}…”</li>`).join('')}</ul>` : ''}
    </section>`;
  }
  window.ScamBunkerSimilar.html = html;
  document.addEventListener('sb:case', e => apply(e.detail));
  document.addEventListener('sb:case-complete', e => apply(e.detail)); // the lead's verdict replaces observations
  document.addEventListener('click', e => { if (e.target.closest('#history-list .hist')) setTimeout(() => apply(SB.current), 0); });
})();
