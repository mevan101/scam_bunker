// Scam Bunker: subject investigation + offender dossiers. Loaded after app.js and dossier.js.
// Public profiles and public ledgers only: no people-search, home-address, relatives or phone-owner lookups.
(() => {
  const SB = window.ScamBunker, D = window.ScamBunkerDossier;
  if (!SB || !D) return;
  const { esc, store, toast } = SB;
  const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const KEY = 'scambunker.subjects';
  const MAX_USERNAMES = 5, MAX_LOOKUPS = 10;
  const VERDICT_COLOR = { 'Scam': 'var(--red)', 'Likely scam': 'var(--red)', 'Suspicious': 'var(--amber)', 'Misleading / manipulated': 'var(--amber)', 'Coordinated / inauthentic': 'var(--violet)', 'AI-generated content': 'var(--violet)', 'Likely legitimate': 'var(--green)', 'No strong red flags': 'var(--green)' };
  const STATUS_LABEL = { found: 'found', not_found: 'none', unknown: 'unknown', blocked: 'blocked', checking: 'checking' };
  const DISCLAIMER = 'This dossier lists investigative leads compiled from the investigator\'s own case files and from public sources. It is not proof of identity, ownership or guilt. A matching username on a platform does not mean the account belongs to the same person, and identifiers can be spoofed or reused by others. Everyone named here is presumed innocent unless and until a competent authority decides otherwise. Do not publish the personal data of private individuals; share this report only with the affected platforms, law enforcement, banks or fraud-reporting bodies.';

  const loadSubjects = () => store.get(KEY, []);
  const saveSubjects = list => store.set(KEY, list);
  const getSubject = id => loadSubjects().find(s => s.id === id) || null;
  function putSubject(s) {
    const list = loadSubjects(); const i = list.findIndex(x => x.id === s.id);
    s.updatedAt = new Date().toISOString();
    if (i >= 0) list[i] = s; else list.unshift(s);
    saveSubjects(list); return s;
  }
  const newSubject = name => ({ id: 's' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), name: name || 'Unnamed subject', aliases: [], indicators: [], caseIds: [], notes: '', findings: { usernames: {}, domains: {}, wallets: {} }, createdAt: new Date().toISOString() });
  const fmtDate = iso => { if (!iso) return '—'; const d = new Date(iso); return isNaN(d) ? '—' : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }); };
  const safeUrl = u => /^https?:\/\//i.test(String(u || '')) ? String(u) : '#';
  const splitList = v => String(v || '').split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
  const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;

  async function postJson(path, body) { return SB.post(path, body); }
  // Static mode (GitHub Pages): RDAP, mempool.space and TronGrid straight from the browser, same code as the server.
  const direct = window.ScamBunkerDirect;
  // Simple mode (default) vs Investigator mode: ScamBunker.mode() lands with the Simple-mode shell, so call it defensively.
  const isSimple = () => typeof SB.mode === 'function' && SB.mode() === 'simple';
  const addReasons = (c, r) => { if (typeof SB.addReasons === 'function' && r.length) SB.addReasons(c, r); };
  const addActions = (c, a) => { if (typeof SB.addActions === 'function' && a.length) SB.addActions(c, a); };
  const canLookup = () => SB.server().online || (SB.isStatic() && !!direct);
  const lookupDomain = body => SB.isStatic() ? direct.domain(body) : postJson('/api/osint/domain', body);
  const lookupWallet = body => SB.isStatic() ? direct.wallet(body) : postJson('/api/osint/wallet', body);

  // ---------- Dialog & tabs ----------
  const dlg = $('#dlg-subjects');
  let state = { subjectId: null, tab: 'investigate', cluster: null, running: false };
  $('#btn-subjects').addEventListener('click', () => openWorkspace());
  $('#subjects-close').addEventListener('click', () => dlg.close());
  function openWorkspace(opts = {}) {
    if (opts.subjectId !== undefined) state.subjectId = opts.subjectId;
    if (state.subjectId && !getSubject(state.subjectId)) state.subjectId = null;
    if (!state.subjectId) state.subjectId = loadSubjects()[0]?.id || null;
    showOsTab(opts.tab || state.tab);
    if (!dlg.open) dlg.showModal();
  }
  $$('[data-ostab]', dlg).forEach(b => b.addEventListener('click', () => showOsTab(b.dataset.ostab)));
  $('.os-tabs', dlg).addEventListener('keydown', e => {
    const tabs = $$('[data-ostab]', dlg), i = tabs.indexOf(document.activeElement); if (i < 0) return;
    const j = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key]; if (j === undefined) return;
    e.preventDefault(); const n = tabs[(j + tabs.length) % tabs.length]; n.focus(); showOsTab(n.dataset.ostab);
  });
  function showOsTab(t) {
    state.tab = t;
    $$('[data-ostab]', dlg).forEach(b => { const on = b.dataset.ostab === t; b.setAttribute('aria-selected', on); b.tabIndex = on ? 0 : -1; });
    $$('[data-ospanel]', dlg).forEach(p => { p.hidden = p.dataset.ospanel !== t; });
    if (t === 'investigate') renderInvestigate(); else renderDossiers();
    updateCount();
  }
  function updateCount() { const n = clusters().length; $('#os-dossier-count').textContent = n || ''; }
  const clusters = () => D.buildClusters(store.get('scambunker.cases', []), loadSubjects());

  // ---------- Investigate ----------
  const FIELD_TYPES = [['usernames', 'handle', 'Usernames / handles', 'One per line. Checked on ~60 public platforms'], ['phones', 'phone', 'Phone numbers', 'Linked to cases only. No owner lookup'], ['emails', 'email', 'Email addresses', 'Linked to cases only'], ['wallets', 'wallet', 'Crypto wallets', 'BTC, TRON or ETH addresses'], ['domains', 'domain', 'Domains', 'Checked against RDAP for age and registrar']];
  const fieldValue = (s, type) => (s?.indicators || []).filter(i => i.type === type).map(i => type === 'handle' ? i.label.replace(/^@/, '') : type === 'wallet' ? i.key.slice(7) : i.label).join('\n');

  function renderInvestigate() {
    const p = $('#os-panel-investigate'), list = loadSubjects(), s = state.subjectId ? getSubject(state.subjectId) : null;
    const extra = (s?.indicators || []).filter(i => !FIELD_TYPES.some(f => f[1] === i.type));
    p.innerHTML = `
      <div class="os-bar" style="margin-top:14px">
        <label class="field grow" style="margin:0"><span>Subject file</span>
          <select id="os-subject">${list.map(x => `<option value="${esc(x.id)}" ${x.id === state.subjectId ? 'selected' : ''}>${esc(x.name)}</option>`).join('')}<option value="" ${!s ? 'selected' : ''}>+ New subject</option></select>
        </label>
      </div>
      <form id="os-form" class="os-section" style="margin-top:12px" novalidate>
        <div class="os-grid2">
          <label class="field"><span>Display name / alias</span><input type="text" name="name" value="${esc(s?.name || '')}" placeholder="e.g. “Jessica the trader”" autocomplete="off"></label>
          <label class="field"><span>Other aliases <span class="os-hint">comma separated</span></span><input type="text" name="aliases" value="${esc((s?.aliases || []).join(', '))}" autocomplete="off"></label>
          ${FIELD_TYPES.map(([name, type, label, hint]) => `<label class="field"><span>${label} <span class="os-hint">${hint}</span></span><textarea name="${name}" rows="3" spellcheck="false">${esc(fieldValue(s, type))}</textarea></label>`).join('')}
          <label class="field"><span>Notes</span><textarea name="notes" rows="3">${esc(s?.notes || '')}</textarea></label>
        </div>
        ${extra.length ? `<div class="muted">Also linked from cases: ${extra.map(i => `<span class="tag">${esc(i.type)}</span> ${esc(i.label)}`).join(' · ')}</div>` : ''}
        ${(s?.caseIds || []).length ? `<div class="muted">${plural(s.caseIds.length, 'case')} linked by hand.</div>` : ''}
        <div class="os-bar">
          <button type="submit" class="primary sm">Save subject</button>
          <button type="button" class="ghost" id="os-run" ${canLookup() ? '' : 'disabled title="The Scam Bunker server is not reachable"'}>Save &amp; run public checks</button>
          ${s ? `<button type="button" class="ghost" id="os-dossier">View dossier</button><button type="button" class="ghost" id="os-delete">Delete subject</button>` : ''}
        </div>
      </form>
      <div id="os-results" class="os-section" style="margin-top:18px">${s ? findingsHtml(s) : ''}</div>`;
    $('#os-subject', p).addEventListener('change', e => { state.subjectId = e.target.value || null; renderInvestigate(); });
    $('#os-form', p).addEventListener('submit', e => { e.preventDefault(); const saved = saveForm(); if (saved) toast(`Saved subject “${saved.name}”`); });
    $('#os-run', p).addEventListener('click', () => { const saved = saveForm(); if (saved) runChecks(saved.id); });
    $('#os-dossier', p)?.addEventListener('click', () => { state.cluster = 's:' + state.subjectId; showOsTab('dossiers'); });
    $('#os-delete', p)?.addEventListener('click', () => {
      if (!confirm(`Delete the subject file “${s.name}”? Linked cases are kept.`)) return;
      saveSubjects(loadSubjects().filter(x => x.id !== s.id)); state.subjectId = loadSubjects()[0]?.id || null; renderInvestigate(); updateCount(); toast('Subject deleted');
    });
    bindHideToggles(p);
  }

  function saveForm() {
    const f = $('#os-form'); const fd = new FormData(f);
    const s = (state.subjectId && getSubject(state.subjectId)) || newSubject();
    const before = new Map((s.indicators || []).map(i => [i.key, i]));
    const now = new Date().toISOString();
    const rejected = [];
    const inds = (s.indicators || []).filter(i => !FIELD_TYPES.some(t => t[1] === i.type)); // keep image/camera links from cases
    for (const [name, type] of FIELD_TYPES) {
      for (const raw of splitList(fd.get(name))) {
        const ind = D.indicatorFor(type, raw);
        if (!ind) { rejected.push(raw); continue; }
        if (inds.some(x => x.key === ind.key)) continue;
        const old = before.get(ind.key);
        inds.push({ ...ind, addedAt: old?.addedAt || now, source: old?.source || 'manual' });
      }
    }
    s.name = String(fd.get('name') || '').trim() || inds.find(i => i.type === 'handle')?.label || 'Unnamed subject';
    s.aliases = splitList(fd.get('aliases'));
    s.notes = String(fd.get('notes') || '').slice(0, 4000);
    s.indicators = inds;
    putSubject(s); state.subjectId = s.id;
    if (rejected.length) toast(`Skipped ${rejected.length} entr${rejected.length === 1 ? 'y' : 'ies'} that did not look valid: ${rejected.slice(0, 3).join(', ')}`);
    renderInvestigate(); updateCount();
    return s;
  }

  // ---------- Public checks ----------
  async function runChecks(id) {
    if (state.running) return;
    const s = getSubject(id); if (!s) return;
    const handles = s.indicators.filter(i => i.type === 'handle').map(i => i.key.slice(7));
    const domains = s.indicators.filter(i => i.type === 'domain').map(i => i.key.slice(7)).slice(0, MAX_LOOKUPS);
    const wallets = s.indicators.filter(i => i.type === 'wallet').slice(0, MAX_LOOKUPS);
    if (!handles.length && !domains.length && !wallets.length) { toast('Add a username, domain or wallet first'); return; }
    state.running = true;
    const btn = $('#os-run'); if (btn) { btn.disabled = true; btn.textContent = 'Checking…'; }
    const out = $('#os-results');
    $('.empty', out)?.remove();
    try {
      await Promise.all([
        (async () => { for (const u of handles.slice(0, MAX_USERNAMES)) await sweep(id, u, out); })(),
        ...domains.map(d => lookup(id, 'domains', d, () => lookupDomain({ domain: d }))),
        ...wallets.map(w => lookup(id, 'wallets', w.key.slice(7), () => lookupWallet({ chain: w.chain || D.walletChain(w.key.slice(7)), address: w.key.slice(7) }))),
      ]);
      if (handles.length > MAX_USERNAMES) toast(`Checked the first ${MAX_USERNAMES} usernames only, to stay polite to the platforms`);
    } finally {
      state.running = false;
      if (state.subjectId === id && state.tab === 'investigate' && dlg.open) renderInvestigate();
      updateCount();
    }
  }

  function updateFindings(id, kind, key, value) {
    const s = getSubject(id); if (!s) return;
    s.findings = s.findings || { usernames: {}, domains: {}, wallets: {} };
    (s.findings[kind] = s.findings[kind] || {})[key] = value;
    putSubject(s);
  }

  async function lookup(id, kind, key, fn) {
    const slot = ensureSlot(kind === 'domains' ? 'os-domains' : 'os-wallets', kind === 'domains' ? 'Domains (RDAP)' : 'Wallets (public ledgers)');
    let card = $(`[data-key="${CSS.escape(key)}"]`, slot);
    if (!card) { card = document.createElement('div'); card.dataset.key = key; slot.append(card); }
    card.className = 'linkcard'; card.innerHTML = `<div class="top"><code>${esc(key)}</code><span class="tag">checking…</span></div>`;
    try {
      const r = await fn();
      const v = { ...r, at: new Date().toISOString() };
      updateFindings(id, kind, key, v);
      card.outerHTML = kind === 'domains' ? domainCard(v) : walletCard(v);
    } catch (e) {
      const v = { error: e.message, at: new Date().toISOString(), ...(kind === 'domains' ? { domain: key } : { address: key }) };
      updateFindings(id, kind, key, v);
      card.outerHTML = kind === 'domains' ? domainCard(v) : walletCard(v);
    }
  }
  function ensureSlot(slotId, title) {
    const out = $('#os-results');
    let sec = $('#' + slotId, out);
    if (!sec) { sec = document.createElement('section'); sec.className = 'os-section'; sec.id = slotId; sec.innerHTML = `<h4>${esc(title)}</h4>`; out.append(sec); }
    return sec;
  }

  // Username sweep: NDJSON stream so the grid fills in live.
  async function sweep(id, username, out) {
    let sec = $(`section[data-user="${CSS.escape(username)}"]`, out);
    if (!sec) { sec = document.createElement('section'); sec.className = 'os-section'; sec.dataset.user = username; out.prepend(sec); }
    if (SB.isStatic()) { sec.innerHTML = `<h4>Username <code>${esc(username)}</code></h4>${localSweepHtml()}`; return; }
    sec.innerHTML = `<h4>Username <code>${esc(username)}</code></h4><p class="os-sum" role="status">Starting…</p>`;
    const results = [];
    try {
      const r = await fetch('/api/osint/username', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, stream: true }) });
      if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || `HTTP ${r.status}`); }
      const reader = r.body.getReader(), dec = new TextDecoder(); let buf = '', total = 0;
      const onMsg = m => {
        if (m.type === 'start') {
          total = m.sites.length;
          sec.innerHTML = usernameSectionHtml(username, m.sites.map(x => ({ ...x, status: 'checking' })), null, true);
          bindHideToggles(sec);
        } else if (m.type === 'result') {
          results.push(m);
          const li = $(`li[data-site="${CSS.escape(m.site)}"]`, sec); if (li) li.outerHTML = siteCard(m);
          const found = results.filter(x => x.status === 'found').length;
          $('.os-sum', sec).textContent = `Checked ${results.length} of ${total} · ${found} found`;
        } else if (m.type === 'done') {
          $('.os-sum', sec).textContent = summaryLine(m.summary, total);
        }
      };
      for (;;) {
        const { done, value } = await reader.read(); if (done) break;
        buf += dec.decode(value, { stream: true });
        let i; while ((i = buf.indexOf('\n')) >= 0) { const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1); if (line) { try { onMsg(JSON.parse(line)); } catch { /* skip bad line */ } } }
      }
      const summary = results.reduce((a, x) => (a[x.status] = (a[x.status] || 0) + 1, a), { found: 0, not_found: 0, unknown: 0, blocked: 0 });
      updateFindings(id, 'usernames', username, { at: new Date().toISOString(), summary, results });
    } catch (e) {
      $('.os-sum', sec).textContent = `Sweep failed: ${e.message}`;
    }
  }

  // Platforms send no CORS headers, so a browser page cannot read their answers: the sweep needs the local server.
  const localSweepHtml = () => direct ? direct.localAppHtml(esc, 'Username sweep', 'Checking a username across ~60 platforms needs the Scam Bunker server, because the platforms do not let other websites read their pages. Domain and wallet checks still run here.')
    : '<p class="os-sum">The username sweep needs the local app.</p>';
  const summaryLine = (sum, total) => `${total} platforms · ${sum.found || 0} found · ${sum.not_found || 0} not found · ${sum.unknown || 0} unknown · ${sum.blocked || 0} blocked`;
  function usernameSectionHtml(username, results, at, live) {
    const sum = results.reduce((a, x) => (a[x.status] = (a[x.status] || 0) + 1, a), {});
    const order = { found: 0, blocked: 1, unknown: 2, checking: 2, not_found: 3 };
    const rows = live ? results : results.slice().sort((a, b) => order[a.status] - order[b.status] || a.site.localeCompare(b.site));
    return `<h4>Username <code>${esc(username)}</code>${at ? ` <span class="os-hint">checked ${esc(fmtDate(at))}</span>` : ''}</h4>
      <p class="os-sum" role="status">${live ? `Checking ${results.length} platforms…` : esc(summaryLine(sum, results.length))}</p>
      <label class="os-hint"><input type="checkbox" class="os-hide-nf" checked> Hide platforms with no account</label>
      <ul class="os-sites" data-hide-nf="1">${rows.map(siteCard).join('')}</ul>
      <p class="os-hint">“Found” means a profile with this exact name exists. It does not show that your subject owns it. “Unknown” and “blocked” mean the platform could not be checked anonymously. Open the link to verify by hand.</p>`;
  }
  function siteCard(r) {
    const st = r.status || 'checking', found = st === 'found';
    const name = found ? `<a href="${esc(safeUrl(r.url))}" target="_blank" rel="noopener noreferrer">${esc(r.site)} ↗</a>` : `<span>${esc(r.site)}</span>`;
    const verify = (st === 'unknown' || st === 'blocked') && r.url ? ` · <a href="${esc(safeUrl(r.url))}" target="_blank" rel="noopener noreferrer">verify by hand<span class="sr-only"> on ${esc(r.site)}</span></a>` : '';
    const detail = st === 'checking' ? esc(r.category || '') : `${esc(r.note || r.category || '')}${r.httpStatus ? ` · HTTP ${r.httpStatus}` : ''}${verify}`;
    return `<li class="os-site" data-status="${esc(st)}" data-site="${esc(r.site)}"${st === 'not_found' ? ' data-nf="1"' : ''}><span class="n">${name}<span class="os-st">${STATUS_LABEL[st] || esc(st)}</span></span><small>${detail}</small></li>`;
  }
  function bindHideToggles(root) {
    $$('.os-hide-nf', root).forEach(cb => {
      const apply = () => { const ul = cb.closest('section').querySelector('.os-sites'); if (!ul) return; $$('li[data-nf]', ul).forEach(li => { li.hidden = cb.checked; }); };
      cb.addEventListener('change', apply); apply();
      new MutationObserver(apply).observe(cb.closest('section').querySelector('.os-sites') || cb, { childList: true });
    });
  }

  function domainCard(d) {
    if (d.error) return `<div class="linkcard" data-key="${esc(d.domain)}"><div class="top"><code>${esc(d.domain)}</code><span class="w moderate">lookup failed</span></div><ul><li>${esc(d.error)}</li><li><a href="https://lookup.icann.org/en/lookup?name=${encodeURIComponent(d.domain)}" target="_blank" rel="noopener noreferrer">Check on lookup.icann.org ↗</a></li></ul></div>`;
    const key = d.input || d.domain;
    if (d.registered === false) return `<div class="linkcard" data-key="${esc(key)}"><div class="top"><code>${esc(key)}</code><span class="tag">no RDAP record</span></div><ul><li>${esc(d.note || '')}</li></ul></div>`;
    const age = d.ageDays != null ? `<span class="w ${d.young ? 'strong' : 'ok'}">${d.young ? `registered ${plural(d.ageDays, 'day')} ago` : `${plural(d.ageDays, 'day')} old`}</span>` : '';
    return `<div class="linkcard" data-key="${esc(key)}"><div class="top"><code>${esc(d.domain || key)}</code>${age}</div><ul>
      <li>Registered: ${esc(fmtDate(d.registeredAt))}${d.expiresAt ? ` · expires ${esc(fmtDate(d.expiresAt))}` : ''}</li>
      <li>Registrar: ${esc(d.registrar || 'unknown')}${d.registrarAbuseEmail ? ` · abuse contact for reports: ${esc(d.registrarAbuseEmail)}` : ''}</li>
      ${(d.status || []).length ? `<li>Status: ${esc(d.status.join(', '))}</li>` : ''}
      ${(d.nameservers || []).length ? `<li>Nameservers: ${esc(d.nameservers.join(', '))}</li>` : ''}
      ${d.young ? '<li>Young domains are a strong scam signal: phishing and fake-investment sites are usually days or weeks old.</li>' : ''}
      ${d.lookup ? `<li><a href="${esc(safeUrl(d.lookup))}" target="_blank" rel="noopener noreferrer">Full record on lookup.icann.org ↗</a></li>` : ''}</ul></div>`;
  }
  function walletCard(w) {
    const addr = w.address || '';
    const link = w.explorer ? `<li><a href="${esc(safeUrl(w.explorer))}" target="_blank" rel="noopener noreferrer">Open in block explorer ↗</a></li>` : '';
    if (w.error) return `<div class="linkcard" data-key="${esc(addr)}"><div class="top"><code>${esc(addr)}</code><span class="w moderate">lookup failed</span></div><ul><li>${esc(w.error)}</li></ul></div>`;
    if (w.available === false) return `<div class="linkcard" data-key="${esc(addr)}"><div class="top"><code>${esc(addr)}</code><span class="tag">${esc(w.chain || '')}</span></div><ul><li>${esc(w.note || 'Not available')}</li>${link}</ul></div>`;
    const lines = [];
    if (w.txCount != null) lines.push(`${plural(w.txCount, 'transaction')}${w.unconfirmedTxCount ? ` (${w.unconfirmedTxCount} unconfirmed)` : ''}`);
    if (w.chain === 'BTC') lines.push(`Received ${w.totalReceivedBtc} BTC in ${plural(w.fundedTxo, 'payment')} · balance ${w.balanceBtc} BTC`);
    if (w.chain === 'TRON') {
      lines.push(`${w.activated === false ? 'Never activated on chain · ' : ''}Balance ${w.balanceTrx} TRX · ${w.usdtBalance} USDT${w.transactionsIn != null ? ` · ${w.transactionsIn} in / ${w.transactionsOut} out` : ''}`);
      if (w.usdtTransfersIn != null) lines.push(`USDT-TRC20: ${plural(w.usdtTransfersIn, 'incoming transfer')} from ${plural(w.uniqueSenders, 'sender')} (${w.usdtReceived} USDT), ${w.usdtTransfersOut} outgoing${w.usdtPageComplete ? '' : ' · latest 200 only, more exist'}`);
    }
    if (w.chain === 'ETH' && w.balanceEth != null) lines.push(`Balance ${w.balanceEth} ETH`);
    if (w.firstSeen) lines.push(`First activity ${esc(fmtDate(w.firstSeen))}${w.firstSeenExact ? '' : ' (earliest of the latest page; may be older)'} · last ${esc(fmtDate(w.lastSeen))}`);
    const many = (w.fundedTxo || w.uniqueSenders || w.transactionsIn || 0) >= 5 ? '<span class="w strong">many incoming payments</span>' : '';
    return `<div class="linkcard" data-key="${esc(addr)}"><div class="top"><code>${esc(addr)}</code><span class="tag">${esc(w.chain)}</span>${many}</div><ul>${lines.map(l => `<li>${esc(l)}</li>`).join('')}${link}</ul></div>`;
  }
  function findingsHtml(s) {
    const f = s.findings || {}; const parts = [];
    Object.entries(f.usernames || {}).forEach(([u, x]) => parts.push(`<section class="os-section" data-user="${esc(u)}">${usernameSectionHtml(u, x.results || [], x.at, false)}</section>`));
    if (SB.isStatic()) (s.indicators || []).filter(i => i.type === 'handle').map(i => i.key.slice(7)).filter(u => !Object.hasOwn(f.usernames || {}, u)).slice(0, MAX_USERNAMES)
      .forEach(u => parts.push(`<section class="os-section" data-user="${esc(u)}"><h4>Username <code>${esc(u)}</code></h4>${localSweepHtml()}</section>`));
    const ds = Object.values(f.domains || {}), ws = Object.values(f.wallets || {});
    if (ds.length) parts.push(`<section class="os-section" id="os-domains"><h4>Domains (RDAP)</h4>${ds.map(domainCard).join('')}</section>`);
    if (ws.length) parts.push(`<section class="os-section" id="os-wallets"><h4>Wallets (public ledgers)</h4>${ws.map(walletCard).join('')}</section>`);
    return parts.join('') || '<p class="empty">No public checks run yet. Add usernames, domains or wallets, then press “Save &amp; run public checks”.</p>';
  }

  // ---------- Dossiers ----------
  function renderDossiers() {
    const p = $('#os-panel-dossiers'), all = clusters();
    const cl = state.cluster && all.find(c => c.id === state.cluster || c.subjects.some(s => 's:' + s.id === state.cluster) || c.cases.some(x => 'c:' + x.id === state.cluster));
    if (cl) return renderDossier(p, cl);
    state.cluster = null;
    p.innerHTML = `<p class="muted" style="margin-top:14px">Scam Bunker links your saved cases into actor clusters whenever they share a wallet, handle, phone, email, domain, image or camera serial, and merges in the subject files you create. Hashtags and other weak signals never link cases.</p>
      ${all.length ? `<div class="os-dossiers">${all.map(c => `<button type="button" class="os-dcard" data-cluster="${esc(c.id)}"><span class="os-risk ${c.riskLevel}" aria-label="Risk ${c.risk} of 100">${c.risk}</span><span class="t"><b>${esc(c.title)}</b><span>${esc([plural(c.cases.length, 'case'), plural(c.indicators.length, 'identifier'), c.subjects.length ? 'subject file' : 'auto-linked', c.platforms.slice(0, 4).join(', ')].filter(Boolean).join(' · '))}</span></span></button>`).join('')}</div>` : '<p class="empty">No dossiers yet. They appear when two cases share an identifier, or when you create a subject.</p>'}`;
    $$('[data-cluster]', p).forEach(b => b.addEventListener('click', () => { state.cluster = b.dataset.cluster; renderDossiers(); $('#os-panel-dossiers h4, #os-panel-dossiers [data-back]')?.focus(); }));
  }

  function renderDossier(p, cl) {
    const s = cl.subjects[0];
    const verdicts = Object.entries(cl.verdicts).map(([v, n]) => `${n}× ${v}`).join(', ');
    p.innerHTML = `<div class="os-section" style="margin-top:14px">
      <div class="os-bar"><button type="button" class="ghost" data-back>← All dossiers</button><span class="grow"></span>
        <button type="button" class="ghost" data-export>Export dossier</button>
        ${s ? `<button type="button" class="ghost" data-edit>Edit subject</button>` : `<button type="button" class="ghost" data-adopt>Save as subject</button>`}</div>
      <div class="verdict card" style="--v:${cl.riskLevel === 'high' ? 'var(--red)' : cl.riskLevel === 'medium' ? 'var(--amber)' : 'var(--blue)'}">
        <div class="os-risk ${cl.riskLevel}" aria-label="Overall risk ${cl.risk} of 100">${cl.risk}</div>
        <div class="v-body"><div class="eyebrow">Offender dossier · ${cl.riskLevel} risk</div><h4 tabindex="-1" style="font:600 22px var(--serif);margin:4px 0">${esc(cl.title)}</h4>
          <div class="v-tags">${[plural(cl.cases.length, 'linked case'), plural(cl.indicators.length, 'identifier'), verdicts].filter(Boolean).map(t => `<span class="tag">${esc(t)}</span>`).join('')}</div></div>
      </div>
      ${cl.aliases.length ? `<section class="os-section"><h4>Aliases &amp; handles</h4><div class="os-chips">${cl.aliases.map(a => `<span class="tag">${esc(a)}</span>`).join('')}</div></section>` : ''}
      <section class="os-section"><h4>Identifiers</h4>${cl.indicators.length ? `<table class="os-table"><thead><tr><th scope="col">Type</th><th scope="col">Value</th><th scope="col">First seen</th><th scope="col">Last seen</th><th scope="col">Cases</th></tr></thead><tbody>${cl.indicators.map(i => `<tr><td>${esc(i.type)}</td><td><code>${esc(i.label)}</code></td><td>${esc(fmtDate(i.firstSeen))}</td><td>${esc(fmtDate(i.lastSeen))}</td><td>${i.caseCount}</td></tr>`).join('')}</tbody></table>` : '<p class="empty">No identifiers yet.</p>'}</section>
      <section class="os-section"><h4>Platforms</h4>${cl.platforms.length ? `<div class="os-chips">${cl.platforms.map(x => `<span class="tag">${esc(x)}</span>`).join('')}</div>` : '<p class="empty">None recorded.</p>'}
        ${cl.profiles.length ? `<ul class="list">${cl.profiles.map(pr => `<li><a href="${esc(safeUrl(pr.url))}" target="_blank" rel="noopener noreferrer">${esc(pr.site)}: ${esc(pr.username)} ↗</a> <span class="os-hint">username match, not confirmed ownership · checked ${esc(fmtDate(pr.checkedAt))}</span></li>`).join('')}</ul>` : ''}</section>
      <section class="os-section"><h4>Linked cases</h4>${cl.cases.length ? `<ul class="os-cases">${cl.cases.map(c => `<li><button type="button" data-case="${esc(c.id)}"><span class="d" style="background:${VERDICT_COLOR[c.verdict] || 'var(--muted)'}" aria-hidden="true"></span><b>${esc(c.verdict || '—')} · ${esc(c.risk ?? '—')}</b><span class="s">${esc(fmtDate(c.at))}${c.platform ? ' · ' + esc(c.platform) : ''} · ${esc((c.text || c.url || 'Image case').slice(0, 120))}</span></button></li>`).join('')}</ul>` : '<p class="empty">No saved cases share these identifiers yet.</p>'}</section>
      ${cl.timeline.length ? `<section class="os-section"><h4>Timeline</h4><div class="tl">${cl.timeline.map(t => `<div class="tl-item"><time>${esc(fmtDate(t.when))}</time><p>${esc(t.what)}</p></div>`).join('')}</div></section>` : ''}
      ${s?.notes ? `<section class="os-section"><h4>Notes</h4><p style="white-space:pre-wrap;margin:0">${esc(s.notes)}</p></section>` : ''}
      <div class="advice"><b>Use with care:</b> ${esc(DISCLAIMER)}</div>
    </div>`;
    $('[data-back]', p).addEventListener('click', () => { state.cluster = null; renderDossiers(); });
    $('[data-export]', p).addEventListener('click', () => exportDossier(cl));
    $('[data-edit]', p)?.addEventListener('click', () => { state.subjectId = s.id; showOsTab('investigate'); });
    $('[data-adopt]', p)?.addEventListener('click', () => {
      const ns = newSubject(cl.title);
      const now = new Date().toISOString();
      ns.indicators = cl.indicators.map(i => ({ type: i.type, key: i.key, label: i.label, addedAt: i.firstSeen || now, source: 'cluster' }));
      ns.caseIds = cl.cases.map(c => c.id);
      putSubject(ns); state.subjectId = ns.id; state.cluster = 's:' + ns.id; renderDossiers(); updateCount(); toast('Saved as a subject file');
    });
    $$('[data-case]', p).forEach(b => b.addEventListener('click', () => {
      if (SB.openCase && SB.openCase(b.dataset.case)) { dlg.close(); toast('Case opened'); } else toast('That case is no longer in your case files');
    }));
  }

  // ---------- Export (printable HTML + SHA-256) ----------
  async function sha256(text) {
    try { if (crypto?.subtle) { const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)); return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join(''); } } catch { /* fall back */ }
    return D.sha256Hex(text);
  }
  function dossierBody(cl, generatedAt) {
    const s = cl.subjects[0];
    const tr = cells => `<tr>${cells.map(c => `<td>${esc(c)}</td>`).join('')}</tr>`;
    const domains = cl.subjects.flatMap(x => Object.values(x.findings?.domains || {})).filter(d => !d.error && d.registered !== false);
    const wallets = cl.subjects.flatMap(x => Object.values(x.findings?.wallets || {})).filter(w => !w.error && w.available !== false);
    return `<header><p class="eyebrow">Scam Bunker · offender dossier</p><h1>${esc(cl.title)}</h1>
<p>Generated ${esc(generatedAt)} (UTC) · overall risk <b>${cl.risk}/100 (${cl.riskLevel})</b> · ${plural(cl.cases.length, 'linked case')} · ${plural(cl.indicators.length, 'identifier')}</p></header>
<section><h2>Important</h2><p class="disclaimer">${esc(DISCLAIMER)}</p></section>
${cl.aliases.length ? `<section><h2>Aliases and handles</h2><p>${cl.aliases.map(esc).join(' · ')}</p></section>` : ''}
<section><h2>Identifiers</h2><table><thead><tr><th>Type</th><th>Value</th><th>First seen</th><th>Last seen</th><th>Cases</th></tr></thead><tbody>${cl.indicators.map(i => tr([i.type, i.label, i.firstSeen || '—', i.lastSeen || '—', String(i.caseCount)])).join('')}</tbody></table></section>
<section><h2>Platforms</h2><p>${cl.platforms.length ? cl.platforms.map(esc).join(' · ') : 'None recorded'}</p>${cl.profiles.length ? `<table><thead><tr><th>Platform</th><th>Username</th><th>Profile URL</th><th>Checked</th></tr></thead><tbody>${cl.profiles.map(p => tr([p.site, p.username, p.url, p.checkedAt || '—'])).join('')}</tbody></table><p class="note">Username matches show that a public profile with that exact name existed when checked. They do not establish who operates it.</p>` : ''}</section>
${domains.length ? `<section><h2>Domain registrations (RDAP)</h2><table><thead><tr><th>Domain</th><th>Registered</th><th>Age (days)</th><th>Registrar</th><th>Nameservers</th></tr></thead><tbody>${domains.map(d => tr([d.domain, d.registeredAt || '—', d.ageDays ?? '—', d.registrar || '—', (d.nameservers || []).join(', ')])).join('')}</tbody></table></section>` : ''}
${wallets.length ? `<section><h2>Wallets (public ledgers)</h2><table><thead><tr><th>Chain</th><th>Address</th><th>Transactions</th><th>First activity</th><th>Last activity</th><th>Source</th></tr></thead><tbody>${wallets.map(w => tr([w.chain, w.address, w.txCount ?? '—', w.firstSeen || '—', w.lastSeen || '—', w.source || '—'])).join('')}</tbody></table></section>` : ''}
<section><h2>Linked cases</h2>${cl.cases.length ? `<table><thead><tr><th>Date</th><th>Verdict</th><th>Risk</th><th>Platform</th><th>Excerpt</th></tr></thead><tbody>${cl.cases.map(c => tr([c.at || '—', c.verdict || '—', c.risk ?? '—', c.platform || '—', (c.text || c.url || 'Image case').slice(0, 240)])).join('')}</tbody></table>` : '<p>None.</p>'}</section>
${cl.timeline.length ? `<section><h2>Timeline</h2><table><thead><tr><th>When</th><th>Event</th></tr></thead><tbody>${cl.timeline.map(t => tr([t.when, t.what])).join('')}</tbody></table></section>` : ''}
${s?.notes ? `<section><h2>Investigator notes</h2><p style="white-space:pre-wrap">${esc(s.notes)}</p></section>` : ''}`;
  }
  async function exportDossier(cl) {
    const generatedAt = new Date().toISOString();
    const body = dossierBody(cl, generatedAt);
    const hash = await sha256(body);
    const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Offender dossier: ${esc(cl.title)}</title>
<style>body{font:14px/1.55 Georgia,'Times New Roman',serif;color:#1b1d22;background:#fff;max-width:900px;margin:32px auto;padding:0 20px}h1{font-size:26px;margin:4px 0}h2{font-size:17px;margin:26px 0 8px;border-bottom:1px solid #ccc;padding-bottom:4px}.eyebrow{font:600 11px/1 ui-monospace,monospace;letter-spacing:.12em;text-transform:uppercase;color:#94570a;margin:0}table{width:100%;border-collapse:collapse;font-size:12.5px}th,td{text-align:left;border:1px solid #d6d6d6;padding:5px 7px;vertical-align:top;overflow-wrap:anywhere}th{background:#f3f1ec}.disclaimer{border:2px solid #a8241d;padding:10px 12px;background:#fdf3f2}.note{color:#555;font-size:12px}footer{margin-top:30px;border-top:2px solid #1b1d22;padding-top:10px;font-size:12px}code{font:12px ui-monospace,monospace;overflow-wrap:anywhere}@media print{body{margin:0;max-width:none}section{break-inside:avoid-page}a{color:inherit}}</style></head>
<body><main>
<!--BEGIN DOSSIER-->${body}<!--END DOSSIER-->
</main>
<footer><b>Chain of custody.</b> SHA-256 of the report content (the UTF-8 text between the <code>BEGIN DOSSIER</code> and <code>END DOSSIER</code> comment markers in this file's source): <code>${hash}</code><br>Exported ${esc(generatedAt)} from Scam Bunker, which ran locally in the investigator's browser. Recompute the hash over the same bytes to confirm the content has not changed since export.</footer>
</body></html>`;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
    a.download = `scam-bunker-dossier-${String(cl.title).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'actor'}-${generatedAt.slice(0, 10)}.html`;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 10000);
    toast(`Dossier exported · SHA-256 ${hash.slice(0, 12)}…`);
    return { html, hash };
  }

  // ---------- Current case: "Add indicator to subject" ----------
  const linksPanel = SB.panel('links');
  function injectAttach() {
    const c = SB.current;
    if (!c || !linksPanel || isSimple() || $('.os-attach', linksPanel)) return;
    const inds = (c.indicators || []).filter(i => D.STRONG_TYPES.includes(i.type));
    const subjects = loadSubjects();
    const keys = new Set(inds.map(i => i.key));
    const linked = subjects.filter(s => (s.caseIds || []).includes(c.id) || (s.indicators || []).some(i => keys.has(i.key)));
    const sec = document.createElement('section');
    sec.className = 'os-attach';
    sec.innerHTML = `<h3>Link to a subject</h3>
      <p class="muted">${linked.length ? `Already connected to: ${linked.map(s => `<b>${esc(s.name)}</b>`).join(', ')}. ` : ''}Add this case's identifiers to a subject file to build an offender dossier across cases and platforms.</p>
      ${inds.length ? `<fieldset style="border:0;padding:0;margin:0"><legend class="sr-only">Identifiers to add</legend><div class="os-inds">${inds.map((i, n) => `<label><input type="checkbox" value="${esc(i.key)}" checked id="os-ind-${n}"> <span class="tag">${esc(i.type)}</span> ${esc(i.label)}</label>`).join('')}</div></fieldset>` : '<p class="empty">This case has no identifiers to link, but you can still attach the case itself.</p>'}
      <div class="os-bar"><label class="sr-only" for="os-attach-subject">Subject file</label>
        <select id="os-attach-subject">${subjects.map(s => `<option value="${esc(s.id)}" ${linked[0]?.id === s.id ? 'selected' : ''}>${esc(s.name)}</option>`).join('')}<option value="">+ New subject</option></select>
        <button type="button" class="primary sm" id="os-attach-go">Add indicator to subject</button>
        <button type="button" class="ghost" id="os-attach-open">Open subjects</button></div>`;
    linksPanel.append(sec);
    $('#os-attach-go', sec).addEventListener('click', () => {
      const chosen = new Set($$('input[type=checkbox]:checked', sec).map(x => x.value));
      const sid = $('#os-attach-subject', sec).value;
      const s = (sid && getSubject(sid)) || newSubject(inds.find(i => i.type === 'handle')?.label || `Subject from case ${c.id}`);
      const now = new Date().toISOString();
      let added = 0;
      inds.filter(i => chosen.has(i.key)).forEach(i => { if (!s.indicators.some(x => x.key === i.key)) { s.indicators.push({ type: i.type, key: i.key, label: i.label, addedAt: c.at || now, source: 'case:' + c.id }); added++; } });
      s.caseIds = [...new Set([...(s.caseIds || []), c.id])];
      putSubject(s);
      toast(`Added ${plural(added, 'identifier')} and this case to “${s.name}”`);
      sec.remove(); injectAttach();
    });
    $('#os-attach-open', sec).addEventListener('click', () => openWorkspace({ subjectId: $('#os-attach-subject', sec).value || state.subjectId, tab: 'investigate' }));
  }
  if (linksPanel) new MutationObserver(() => injectAttach()).observe(linksPanel, { childList: true });

  // ---------- Current case: domain age via RDAP ----------
  const domainObs = (d, r) => ({ fact: `${d} was registered ${plural(r.ageDays, 'day')} ago (${fmtDate(r.registeredAt)}${r.registrar ? ', ' + r.registrar : ''})`, inference: 'Newly registered domain. Phishing and fake-investment sites are usually days or weeks old when they are used; established businesses rarely are.', weight: r.ageDays < 30 ? 'strong' : 'moderate', source: 'rdap' });
  function addObs(v, ob) { if (v && Array.isArray(v.observations) && !v.observations.some(o => o.fact === ob.fact)) v.observations.unshift(ob); }
  async function checkCaseDomains(c) {
    if (!c || c._osintDomains || !canLookup()) return;
    c._osintDomains = true;
    const risk = new Map((c.heuristics?.links || []).filter(l => l.host).map(l => [l.host.replace(/^www\./, ''), l.risk || 0]));
    const doms = (c.indicators || []).filter(i => i.type === 'domain').map(i => i.key.slice(7)).sort((a, b) => (risk.get(b) || 0) - (risk.get(a) || 0)).slice(0, 3);
    if (!doms.length) return;
    const results = await Promise.all(doms.map(d => lookupDomain({ domain: d }).then(r => [d, r]).catch(e => [d, { error: e.message }])));
    c.domainAges = Object.fromEntries(results.map(([d, r]) => [d, r.error ? { error: r.error } : { registeredAt: r.registeredAt || null, ageDays: r.ageDays ?? null, registrar: r.registrar || null, young: !!r.young, registered: r.registered !== false }]));
    const young = results.filter(([, r]) => r.young && r.ageDays != null);
    addReasons(c, young.map(([d, r]) => ({ text: `The website ${d} was created only ${plural(r.ageDays, 'day')} ago (${fmtDate(r.registeredAt)}). Scam websites are usually brand new. Real banks, shops and employers have had theirs for years.`, weight: r.ageDays < 30 ? 'strong' : 'moderate', source: 'Public domain registration records (RDAP)' })));
    addActions(c, results.filter(([, r]) => !r.error).map(([d]) => ({ text: `See when ${d} was created and who registered it`, href: `https://lookup.icann.org/en/lookup?name=${encodeURIComponent(d)}` })));
    const obs = young.map(([d, r]) => domainObs(d, r));
    if (!obs.length) return;
    c._osintObs = obs;
    obs.forEach(ob => { addObs(c.local, ob); addObs(c.final, ob); });
    if (SB.current === c) SB.renderAll();
    patchSavedCase(c);
  }
  function patchSavedCase(c) {
    const list = store.get('scambunker.cases', []); const x = list.find(i => i.id === c.id); if (!x) return;
    (c._osintObs || []).forEach(ob => { addObs(x.local, ob); addObs(x.final, ob); });
    x.domainAges = c.domainAges;
    store.set('scambunker.cases', list);
  }
  // Plain-language to-dos for a crypto wallet in the case (Simple mode result). No lookup is needed for this.
  function walletActions(c) {
    if (!c || c._osintWalletActions) return;
    c._osintWalletActions = true;
    const core = window.ScamBunkerOsintCore;
    const wallets = (c.indicators || []).filter(i => i.type === 'wallet').map(i => i.key.slice(7)).map(a => [a, D.walletChain(a)]).filter(([, ch]) => ch && core && core.EXPLORER[ch]).slice(0, 3);
    addActions(c, wallets.map(([a, ch]) => ({ text: `Do not send money to the crypto wallet ${a.slice(0, 6)}…${a.slice(-4)}. Crypto payments cannot be reversed. You can see its public payment history here`, href: core.EXPLORER[ch](a) })));
  }
  function syncMode() {
    const btn = document.getElementById('btn-subjects'); if (btn) btn.hidden = isSimple();
    if (isSimple()) $$('.os-attach').forEach(x => x.remove()); else injectAttach();
  }
  document.addEventListener('sb:mode', syncMode);
  document.addEventListener('sb:ready', syncMode);
  document.addEventListener('sb:case', e => { walletActions(e.detail); checkCaseDomains(e.detail).catch(err => console.debug('domain age check skipped:', err)); });
  document.addEventListener('sb:case-complete', e => {
    const c = e.detail; if (!c?._osintObs) return;
    c._osintObs.forEach(ob => { addObs(c.local, ob); addObs(c.final, ob); });
    patchSavedCase(c);
    if (SB.current === c) SB.renderAll();
  });

  window.ScamBunkerOsint = { openWorkspace, clusters, exportDossier, dossierBody, loadSubjects };
})();
