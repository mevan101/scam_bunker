// Scam Bunker — "Claims" tab: existing fact-checks for the post's checkable claims (BACKLOG P1-7) and
// similar earlier cases from public/similar.js (BACKLOG P2-1). Claim extraction and the Google Fact Check Tools
// lookup run on the server (server/factcheck.js); without GOOGLE_FACTCHECK_API_KEY no third-party call is made and
// each claim links to Google Fact Check Explorer instead. In static mode (GitHub Pages) claims are extracted in the
// browser with the same code (public/shared/claims.js) and each claim gets the Explorer deep link.
// Results are added to the agents' case file.
(function () {
  'use strict';
  if (!window.ScamBunker) return;
  const SB = window.ScamBunker, esc = SB.esc;
  const $ = s => document.querySelector(s);
  const EXPLORER_HOME = 'https://toolbox.google.com/factcheck/explorer';
  const safeHref = u => (/^https?:\/\//i.test(String(u || '')) ? esc(u) : '#');
  const ratingClass = r => /\b(false|fake|incorrect|misleading|pants|hoax|fabricated|no evidence|not true|wrong|scam|satire|distort|unsupported|baseless|altered)\b/i.test(r) ? 'strong'
    : /\b(true|correct|accurate)\b/i.test(r) && !/\b(half|mostly false|partly|partially)\b/i.test(r) ? 'ok' : 'moderate';

  // What the agents receive (compact, no UI state)
  function forAgents(fc) {
    return { available: !!fc.available, claims: (fc.claims || []).map(c => ({ text: c.text, error: c.error, matches: (c.matches || []).slice(0, 3).map(m => ({ text: m.text, reviews: m.reviews.slice(0, 2) })) })) };
  }
  function observations(c) {
    const v = c.final || c.local; if (!v) return;
    v.observations = (v.observations || []).filter(o => !o.factcheck);
    const fc = c.factcheck; if (!fc || !fc.available) return;
    for (const cl of fc.claims || []) {
      const r = (cl.matches || [])[0] && cl.matches[0].reviews[0]; if (!r) continue;
      v.observations.push({ fact: `Published fact-check: ${r.publisher} rated “${(cl.matches[0].text || cl.text).slice(0, 120)}” as “${r.rating}”`,
        inference: `Found by searching the claim “${cl.text.slice(0, 80)}”. It may be a different claim: open the fact-check and confirm it is the same before relying on the rating.`, weight: 'weak', factcheck: true });
    }
  }
  function persist(c) {
    const list = SB.store.get('scambunker.cases', []);
    const row = list.find(x => x.id === c.id); if (!row) return;
    row.factcheck = c.factcheck; row.caseExtras = c.caseExtras;
    SB.store.set('scambunker.cases', list);
  }

  const isStatic = () => !!(SB.isStatic && SB.isStatic());
  function local(c) {
    const X = window.ScamBunkerClaims;
    if (!X) { render(c); return; }
    c.factcheck = { available: false, local: true, service: 'Google Fact Check Explorer (manual)', claims: X.extractClaims(String(c.text).slice(0, 12000)) };
    c.caseExtras = { ...(c.caseExtras || {}), factchecks: forAgents(c.factcheck) };
    observations(c); persist(c); render(c);
  }
  async function lookup(c) {
    if (!c || !c.text) { render(c); return; }
    if (isStatic() || !(SB.server() || {}).online) return local(c);
    c.factcheck = { status: 'run', claims: [] }; render(c);
    const p = SB.post('/api/factcheck', { text: c.text })
      .then(r => { c.factcheck = r; })
      .catch(e => { c.factcheck = { error: e.message, claims: [] }; })
      .then(() => {
        c.caseExtras = { ...(c.caseExtras || {}), factchecks: forAgents(c.factcheck) };
        observations(c); persist(c);
        if (SB.current === c) { SB.renderAll(); render(c); }
      });
    (c.pending = c.pending || []).push(p); // app.js waits for module lookups before the agents run
    return p;
  }

  function claimHtml(cl, fc) {
    const explorer = `<a style="color:var(--blue)" href="${safeHref(cl.explorerUrl)}" target="_blank" rel="noopener">Search Google Fact Check Explorer<span class="sr-only"> for this claim</span> ↗</a>`;
    let body;
    if (!fc.available) body = `<ul><li>${explorer}</li></ul>`;
    else if (cl.error) body = `<ul><li>Lookup failed: ${esc(cl.error)}. ${explorer}</li></ul>`;
    else if (!(cl.matches || []).length) body = `<ul><li>No published fact-check found. That is not evidence either way. ${explorer}</li></ul>`;
    else body = `<ul>${cl.matches.slice(0, 5).map(m => m.reviews.slice(0, 3).map(r => `<li><span class="w ${ratingClass(r.rating)}">${esc(r.rating || 'unrated')}</span> <b>${esc(r.publisher)}</b>${r.reviewDate ? ` · <time datetime="${esc(r.reviewDate)}">${esc(r.reviewDate.slice(0, 10))}</time>` : ''} · <a style="color:var(--blue)" href="${safeHref(r.url)}" target="_blank" rel="noopener">${esc(r.title || 'Read the fact-check')} ↗</a><br><span class="muted">Claim reviewed: “${esc(m.text)}”${m.claimant ? ` (claimant: ${esc(m.claimant)})` : ''}</span></li>`).join('')).join('')}<li>${explorer}</li></ul>`;
    return `<div class="linkcard"><div class="top"><b>“${esc(cl.text)}”</b>${(cl.why || []).map(w => `<span class="tag">${esc(w)}</span>`).join('')}</div>${body}</div>`;
  }

  function render(c) {
    const el = SB.panel('claims'); if (!el) return;
    const count = $('#claims-count');
    if (!c) { el.innerHTML = ''; return; }
    const fc = c.factcheck, sim = window.ScamBunkerSimilar && window.ScamBunkerSimilar.html ? window.ScamBunkerSimilar.html(c) : '';
    if (count) count.textContent = (c.similar || []).length ? String(c.similar.length) : '';
    let claims;
    if (!c.text) claims = '<p class="empty">Paste the post text to extract its checkable claims and look for published fact-checks.</p>';
    else if (!fc) claims = '<p class="empty">Fact-check lookup needs the Scam Bunker server.</p>';
    else if (fc.status === 'run') claims = '<p class="muted" role="status">Extracting claims and searching published fact-checks…</p>';
    else if (fc.error) claims = `<div class="callout">Could not search fact-checks: ${esc(fc.error)}. Try <a style="color:var(--blue)" href="${EXPLORER_HOME}" target="_blank" rel="noopener">Google Fact Check Explorer ↗</a> by hand.</div>`;
    else claims = `<p class="muted">${fc.local
      ? 'Claims were extracted in this browser and nothing was sent to a third party. The automatic Google Fact Check Tools search needs the local app (<code>npm start</code>) with <code>GOOGLE_FACTCHECK_API_KEY</code>; here, open each claim in Google Fact Check Explorer.'
      : fc.available
      ? 'Each claim below was sent to the Google Fact Check Tools API, which searches fact-checks published with ClaimReview markup. A match may be about a different claim. Open it and confirm before relying on the rating.'
      : 'Automatic lookup is off (set <code>GOOGLE_FACTCHECK_API_KEY</code> on the server to enable it). Nothing was sent to a third party. Search each claim in Google Fact Check Explorer by hand.'}</p>
      ${(fc.claims || []).length ? fc.claims.map(cl => claimHtml(cl, fc)).join('') : `<p class="empty">No checkable factual claims found. Claims are sentences with numbers, dates, names, or words such as “cures” or “confirmed”. <a style="color:var(--blue)" href="${EXPLORER_HOME}" target="_blank" rel="noopener">Google Fact Check Explorer ↗</a></p>`}`;
    el.innerHTML = `<section aria-labelledby="fc-h"><h3 id="fc-h">Checkable claims and existing fact-checks</h3>${claims}</section>${sim}`;
  }

  document.addEventListener('sb:case', e => lookup(e.detail));
  document.addEventListener('sb:similar', e => render(e.detail));
  document.addEventListener('sb:case-complete', e => { observations(e.detail); persist(e.detail); SB.renderAll(); render(e.detail); });
  document.addEventListener('click', e => {
    if (!e.target.closest('#history-list .hist')) return;
    setTimeout(() => { const c = SB.current; if (!c) return; if (c.factcheck && !c.factcheck.status) { observations(c); SB.renderAll(); render(c); } else lookup(c); }, 0);
  });
  render(SB.current);
})();
