// Scam Bunker: Events tab. Compares event listings and flags scheduling overlaps without inferring motive.
// Hooks in through window.ScamBunker (see AGENTS.md); pure logic lives in events-core.js.
(() => {
  const SB = window.ScamBunker, C = window.SBEventsCore;
  if (!SB || !C) return;
  const { esc, toast, panel, showTab, store, post } = SB;
  const $ = s => document.querySelector(s);
  const KEY = 'scambunker.events';
  let raw = store.get(KEY, []);
  let sort = { key: 'start', dir: 1 };
  let editing = null;
  const save = () => store.set(KEY, raw);
  const nextId = () => `L${raw.reduce((m, l) => Math.max(m, +String(l.id).slice(1) || 0), 0) + 1}`;
  const safeHref = u => { try { const x = new URL(u); return /^https?:$/.test(x.protocol) && !x.username && !x.password ? x.href : null; } catch { return null; } };
  const link = (u, label) => { const h = safeHref(u); return h ? `<a href="${esc(h)}" target="_blank" rel="noopener noreferrer">${esc(label || h)}</a>` : esc(label || u || ''); };
  const srcTag = (l, k) => { const s = (l.sources || {})[k] || (l.manual ? 'manual' : ''); return s ? ` <span class="ev-src" title="Source of this value">${esc(s)}</span>` : ''; };
  const zones = (() => { try { return Intl.supportedValuesOf('timeZone'); } catch { return ['UTC', 'Asia/Dhaka', 'Europe/London', 'America/New_York']; } })();
  const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';

  // ---------- Tab + entry point ----------
  const tabBtn = $('#tab-events'), host = panel('events');
  if (!tabBtn || !host) return;
  const nav = $('.topbar .actions');
  if (nav && !$('#btn-events')) {
    nav.insertAdjacentHTML('afterbegin', '<button class="ghost" id="btn-events" type="button">Event overlap</button>');
    $('#btn-events').addEventListener('click', open);
  }
  function open() {
    if (!SB.current) {
      $('#placeholder').hidden = true; $('#report').hidden = false;
      $('#verdict').hidden = true; const ra = $('#report .report-actions'); if (ra) ra.hidden = true;
    }
    showTab('events'); tabBtn.focus();
  }
  document.addEventListener('sb:case', () => { $('#verdict').hidden = false; const ra = $('#report .report-actions'); if (ra) ra.hidden = false; });

  const field = (id, label, type = 'text', extra = '') => `<label class="field"><span>${label}</span><input id="ev-f-${id}" type="${type}" ${extra}></label>`;
  host.innerHTML = `
    <div class="ev">
      <div class="eyebrow">Scheduling observations</div>
      <h3>Event listing overlap check</h3>
      <p class="muted ev-lede">Paste listing URLs from Luma, Meetup, Eventbrite, community or sponsor pages. Times are normalised to UTC and to each venue's local time, and overlaps are flagged with an honest strength and the innocent explanations. These are scheduling observations, not findings of misconduct; only the sponsoring programs can verify funding or approval.</p>
      <p class="callout" id="ev-static" role="note" hidden><b>Manual entry in the web version.</b> Fetching listing pages needs the local app (<code>npm start</code>), because a browser cannot read other sites' pages. Add each listing by hand below; overlap flags, time zones, the timeline and the claims ledger all work here, on your device.</p>
      <section id="ev-url-sec">
        <label class="field"><span>Listing URLs (one per line)</span><textarea id="ev-urls" rows="3" placeholder="https://lu.ma/…&#10;https://www.meetup.com/…/events/…"></textarea></label>
        <div class="ev-row"><button class="primary sm" id="ev-fetch" type="button">Fetch listings</button><button class="ghost" id="ev-demo" type="button">Load fictional demo</button><button class="ghost" id="ev-clear" type="button">Clear all</button></div>
        <div id="ev-status" class="ev-status" role="status" aria-live="polite"></div>
      </section>
      <details id="ev-manual" class="ev-manual">
        <summary>Add a listing manually <span class="muted">(for login-walled pages or screenshots)</span></summary>
        <form id="ev-form" class="ev-form" novalidate>
          ${field('title', 'Title', 'text', 'required')}
          ${field('url', 'Listing URL (optional)', 'url', 'placeholder="https://…"')}
          ${field('start', 'Start (venue local time)', 'datetime-local', 'required')}
          ${field('end', 'End (venue local time, optional)', 'datetime-local')}
          ${field('tz', 'Venue time zone (IANA)', 'text', `list="ev-tzlist" required autocomplete="off" placeholder="${esc(browserTz)}"`)}
          ${field('venue', 'Venue name')}
          ${field('address', 'Venue address')}
          ${field('city', 'City')}
          ${field('org', 'Organiser / host (comma-separated)')}
          ${field('programs', 'Sponsors / programs / brands (comma-separated)')}
          ${field('attendees', 'Public attendee count', 'number', 'min="0" inputmode="numeric"')}
          ${field('cited', 'Event ID as cited by the program (optional)')}
          <datalist id="ev-tzlist">${zones.map(z => `<option value="${esc(z)}">`).join('')}</datalist>
          <div class="ev-row ev-span"><button class="primary sm" type="submit" id="ev-save">Add listing</button><button class="ghost" type="button" id="ev-cancel" hidden>Cancel edit</button></div>
        </form>
      </details>
      <section><h3>Flags <span class="count" id="ev-flag-count"></span></h3><div id="ev-flags"></div></section>
      <section><h3>Comparison</h3><div class="ev-tablewrap" id="ev-table"></div></section>
      <section><div class="ev-head"><h3>Timeline</h3><label class="ev-inline"><span>Day lanes in</span><select id="ev-tlzone"></select></label></div><div id="ev-timeline"></div></section>
      <div class="ev-row ev-end"><button class="ghost" id="ev-print" type="button">Open printable ledger</button><button class="ghost" id="ev-ledger" type="button">Export claims ledger</button></div>
    </div>`;

  // Static mode (GitHub Pages): no /api, so manual entry comes first and is open; everything else runs locally.
  let staticApplied = false;
  function applyMode() {
    const st = !!SB.isStatic?.();
    $('#ev-static').hidden = !st;
    $('#ev-fetch').textContent = st ? 'Fetch listings (local app only)' : 'Fetch listings';
    if (st && !staticApplied) { staticApplied = true; const m = $('#ev-manual'); $('#ev-url-sec').before(m); m.open = true; if (!F('tz').value) F('tz').value = browserTz; }
  }
  document.addEventListener('sb:ready', applyMode);

  // ---------- Data ----------
  const listings = () => raw.map((l, i) => C.normalizeListing(l, i));
  function fromExtract(r) {
    const f = r.fields || {}, v = k => f[k]?.value, sources = {};
    for (const [k, x] of Object.entries(f)) sources[k] = x.source + (x.via ? ` · ${x.via}` : '') + (x.note ? ` · ${x.note}` : '') + (k === 'attendees' && x.detail ? ` · ${x.detail}` : '');
    return {
      id: nextId(), url: r.url, finalUrl: r.finalUrl, redirects: r.redirects, fetchedAt: r.fetchedAt, loginWall: r.loginWall,
      title: v('title'), start: v('start'), end: v('end'), tz: v('timeZone'), venueName: v('venueName'), venueAddress: v('venueAddress'), city: v('city'), geo: v('geo'),
      organizers: v('organizers') || [], programs: v('programs') || [], attendees: v('attendees'), sources, discrepancies: r.discrepancies || [],
    };
  }
  async function fetchAll() {
    const urls = $('#ev-urls').value.split(/\s+/).map(s => s.trim()).filter(Boolean);
    const bad = urls.filter(u => !safeHref(u)); const good = urls.filter(u => safeHref(u));
    const st = $('#ev-status');
    if (!good.length) { toast(bad.length ? 'Only http(s) links can be fetched' : 'Paste at least one listing URL'); return; }
    if (SB.isStatic?.() || !SB.server()?.online) { st.innerHTML = `<p class="callout">${SB.isStatic?.() ? 'This is the web version without a server, so pages cannot be fetched. Run the local app (<code>npm start</code>) for URL extraction, or add' : 'The local server is offline, so pages cannot be fetched. Add'} the listings manually${good.length === 1 ? ` <button class="link" type="button" data-ev-manual-url="${esc(good[0])}">with this URL</button>` : ''}.</p>`; return; }
    const btn = $('#ev-fetch'); btn.disabled = true; btn.textContent = 'Fetching…';
    const lines = [];
    for (const u of good) {
      st.innerHTML = `<p class="muted">Fetching ${esc(u)}…</p>`;
      try {
        const r = await post('/api/events/extract', { url: u });
        const l = fromExtract(r); raw.push(l);
        const missing = !l.start ? ' No start time found.' : '';
        lines.push(`<li>${esc(l.id)} ${esc(l.title || u)}: fetched${r.redirects?.length > 1 ? ` after ${r.redirects.length - 1} redirect(s)` : ''}.${missing}${r.loginWall ? ' The page looks login-walled; check or complete it manually.' : ''}${missing || r.loginWall ? ` <button class="link" type="button" data-ev-edit="${esc(l.id)}">Complete manually</button>` : ''}</li>`);
      } catch (e) {
        lines.push(`<li>${esc(u)}: ${esc(e.message)} <button class="link" type="button" data-ev-manual-url="${esc(u)}">Enter manually</button></li>`);
      }
      save(); render();
    }
    bad.forEach(u => lines.push(`<li>${esc(u)}: skipped, only http(s) links without embedded credentials are fetched</li>`));
    st.innerHTML = `<ul class="ev-log">${lines.join('')}</ul>`;
    btn.disabled = false; btn.textContent = 'Fetch listings';
    applyMode();
  }

  // ---------- Manual entry / edit ----------
  const F = id => $(`#ev-f-${id}`);
  const FORM_MAP = [['title', 'title'], ['url', 'url'], ['venue', 'venueName'], ['address', 'venueAddress'], ['city', 'city'], ['cited', 'citedId']];
  function formPrefill(l) {
    const n = C.normalizeListing(l);
    const pre = {
      title: l.title || '', url: l.url || '', venue: l.venueName || '', address: l.venueAddress || '', city: l.city || '', cited: l.citedId || '',
      start: n.startLocal ? `${n.startLocal.date}T${n.startLocal.time}` : '', end: n.endLocal && !n.endAssumed ? `${n.endLocal.date}T${n.endLocal.time}` : '',
      tz: l.tz || (n.zone ? (n.zone.tz || '') : ''), org: (l.organizers || []).join(', '), programs: (l.programs || []).join(', '), attendees: l.attendees ?? '',
    };
    return pre;
  }
  function edit(id, presetUrl) {
    const l = raw.find(x => x.id === id);
    editing = l ? { id, pre: formPrefill(l) } : null;
    const pre = editing ? editing.pre : { url: presetUrl || '', tz: browserTz };
    for (const k of ['title', 'url', 'start', 'end', 'tz', 'venue', 'address', 'city', 'org', 'programs', 'attendees', 'cited']) F(k).value = pre[k] ?? '';
    $('#ev-save').textContent = editing ? `Save ${id}` : 'Add listing';
    $('#ev-cancel').hidden = !editing;
    const d = $('#ev-manual'); d.open = true; d.scrollIntoView({ behavior: 'smooth', block: 'start' }); F('title').focus();
  }
  function resetForm() { $('#ev-form').reset(); editing = null; $('#ev-save').textContent = 'Add listing'; $('#ev-cancel').hidden = true; }
  function submitForm(e) {
    e.preventDefault();
    const val = k => F(k).value.trim();
    const tz = val('tz') || browserTz;
    if (!val('title') || !val('start')) { toast('Title and start time are required'); (val('title') ? F('start') : F('title')).focus(); return; }
    if (!C.isValidTz(tz)) { toast(`“${tz}” is not a recognised time zone`); F('tz').focus(); return; }
    if (val('url') && !safeHref(val('url'))) { toast('Listing URL must start with http:// or https://'); F('url').focus(); return; }
    const list = s => s.split(',').map(x => x.trim()).filter(Boolean);
    const pre = editing ? editing.pre : {};
    const l = editing ? { ...raw.find(x => x.id === editing.id) } : { id: nextId(), manual: true, sources: {} };
    l.sources = { ...(l.sources || {}) };
    const changed = k => !editing || val(k) !== String(pre[k] ?? '');
    const set = (formKey, prop, value, srcKey = prop) => { if (changed(formKey)) { l[prop] = value; l.sources[srcKey] = 'manual'; } };
    for (const [fk, prop] of FORM_MAP) set(fk, prop, val(fk));
    if (editing && changed('url') && l.finalUrl) { // values and redirect evidence came from the old URL: say so instead of attaching them to the new one
      const from = ` · fetched from ${l.finalUrl}`;
      for (const k of Object.keys(l.sources)) if (l.sources[k] !== 'manual' && !l.sources[k].includes(from)) l.sources[k] += from;
      delete l.finalUrl; delete l.redirects; delete l.fetchedAt;
    }
    const timeChanged = changed('start') || changed('end') || changed('tz');
    if (timeChanged) {
      l.tz = tz; l.sources.timeZone = 'manual';
      if (changed('start') || changed('tz')) { l.start = val('start'); l.sources.start = 'manual'; }
      if (changed('end') || changed('tz')) { l.end = val('end'); l.sources.end = 'manual'; }
      if (editing && !changed('start') && changed('tz')) { l.start = val('start'); }
    }
    set('org', 'organizers', list(val('org')));
    set('programs', 'programs', list(val('programs')));
    set('attendees', 'attendees', val('attendees') === '' ? null : Math.max(0, Math.round(+val('attendees'))));
    if (editing) raw = raw.map(x => x.id === l.id ? l : x); else raw.push(l);
    save(); toast(editing ? `${l.id} updated` : `${l.id} added`); resetForm(); render();
  }

  // ---------- Render ----------
  const fmtLocal = l => l.startLocal ? `${l.startLocal.weekday ? l.startLocal.weekday + ' ' : ''}${l.startLocal.date} ${l.startLocal.time}${l.endLocal && !l.endAssumed ? '–' + l.endLocal.time : ''}` : '—';
  const SORTS = {
    id: l => +String(l.id).slice(1) || 0, title: l => (l.title || '').toLowerCase(), platform: l => `${l.platform || ''} ${l.programs.join(' ')}`.toLowerCase(),
    start: l => l.startUtc ?? Infinity, venue: l => `${l.venueName || ''} ${l.venueAddress || ''}`.toLowerCase(), city: l => (l.city || '').toLowerCase(),
    organizers: l => l.organizers.join(' ').toLowerCase(), attendees: l => l.attendees ?? -1,
  };
  function renderTable(L, flagged) {
    if (!L.length) return '<p class="empty">No listings yet. Fetch some URLs, add one manually, or load the fictional demo.</p>';
    const rows = [...L].sort((a, b) => { const x = SORTS[sort.key](a), y = SORTS[sort.key](b); return (x > y ? 1 : x < y ? -1 : 0) * sort.dir; });
    const th = (key, label) => `<th scope="col" aria-sort="${sort.key === key ? (sort.dir > 0 ? 'ascending' : 'descending') : 'none'}"><button type="button" data-ev-sort="${key}">${label}<span aria-hidden="true">${sort.key === key ? (sort.dir > 0 ? ' ▲' : ' ▼') : ''}</span></button></th>`;
    return `<table class="ev-table"><caption class="sr-only">Listings compared. Column buttons sort the table.</caption><thead><tr>${th('id', '#')}${th('title', 'Title')}${th('platform', 'Platform · programs')}${th('start', 'Start: venue local / UTC')}${th('venue', 'Venue')}${th('city', 'City')}${th('organizers', 'Organiser')}${th('attendees', 'Attendees')}<th scope="col"><span class="sr-only">Actions</span></th></tr></thead><tbody>${rows.map(l => {
      const f = flagged.get(l.id);
      return `<tr>
        <td><b>${esc(l.id)}</b>${f ? ` <span class="w ${esc(f)}" title="Highest flag strength for this listing">${esc(f)}</span>` : ''}</td>
        <td>${l.url ? link(l.url, l.title || l.url) : esc(l.title || '—')}${srcTag(l, 'title')}${l.finalUrl && l.finalUrl !== l.url ? `<div class="ev-sub">final URL: ${link(l.finalUrl)}</div>` : ''}${l.redirects && l.redirects.length > 1 ? `<div class="ev-sub">redirects: ${l.redirects.map(r => `${esc(r.status)} ${esc(r.url)}`).join(' → ')}</div>` : ''}</td>
        <td>${esc(l.platform || '—')}${l.programs.length ? `<div class="ev-sub">${l.programs.map(p => `<span class="tag">${esc(p)}</span>`).join(' ')}${srcTag(l, 'programs')}</div>` : ''}</td>
        <td><span class="ev-mono">${esc(fmtLocal(l))}</span> <span class="ev-sub">${esc(l.zone ? C.zoneLabel(l.zone) : 'no zone')}${srcTag(l, 'start')}</span><div class="ev-mono ev-sub">${l.startUtc != null ? esc(C.fmtUtc(l.startUtc)) + (l.endAssumed ? ' · end assumed +2 h' : '') : 'UTC unknown'}</div>${l.start ? `<div class="ev-sub">as listed: <code>${esc(l.start)}</code></div>` : ''}${l.warnings.map(w => `<div class="ev-warn">${esc(w)}</div>`).join('')}</td>
        <td>${esc(l.venueName || '—')}${srcTag(l, 'venueName')}${l.venueAddress ? `<div class="ev-sub">${esc(l.venueAddress)}</div>` : ''}${l.geo ? `<div class="ev-sub ev-mono">${esc(l.geo.lat)}, ${esc(l.geo.lon)}</div>` : ''}</td>
        <td>${esc(l.city || '—')}</td>
        <td>${esc(l.organizers.join(', ') || '—')}${l.organizers.length ? srcTag(l, 'organizers') : ''}</td>
        <td>${l.attendees != null ? esc(l.attendees) + srcTag(l, 'attendees') : '—'}</td>
        <td class="ev-act"><button class="link" type="button" data-ev-edit="${esc(l.id)}" aria-label="Edit ${esc(l.id)}">Edit</button> <button class="link" type="button" data-ev-del="${esc(l.id)}" aria-label="Remove ${esc(l.id)}">Remove</button></td>
      </tr>`;
    }).join('')}</tbody></table>`;
  }
  function renderFlags(flags) {
    if (!flags.length) return '<p class="empty">No scheduling flags for the current listings.</p>';
    return flags.map(f => `<article class="ev-flag ${esc(f.strength)}">
      <header><span class="w ${esc(f.strength)}">${esc(f.strength)}</span><b>${esc(f.title)}</b><span class="ev-sub">(${esc(f.type)}) ${esc(f.listings.join(', '))}</span></header>
      <p>${esc(f.explanation)}</p>
      <p class="ev-innocent"><b>Innocent explanations:</b> ${esc(f.innocent.join(' '))}</p>
    </article>`).join('');
  }
  function renderTimeline(L, flagged) {
    const sel = $('#ev-tlzone'), prev = sel.value;
    const zs = [...new Set(L.filter(l => l.zone).map(l => C.zoneLabel(l.zone)))];
    const opts = [...new Set([...zs, 'UTC'])];
    sel.innerHTML = opts.map(z => `<option${z === prev ? ' selected' : ''}>${esc(z)}</option>`).join('');
    const zl = sel.value || 'UTC';
    const zone = /^UTC[+-]/.test(zl) ? { offsetMin: (zl[3] === '-' ? -1 : 1) * (+zl.slice(4, 6) * 60 + +zl.slice(7, 9)) } : { tz: zl };
    const timed = L.filter(l => l.startUtc != null);
    if (!timed.length) return '<p class="empty">Nothing to plot yet.</p>';
    const lanes = new Map();
    for (const l of timed) {
      const s = C.utcToZoned(l.startUtc, zone), dur = (l.endUtc - l.startUtc) / 60000;
      const startMin = s.hour * 60 + s.minute, endMin = Math.min(1440, startMin + Math.max(dur, 15));
      if (!lanes.has(s.date)) lanes.set(s.date, { wd: s.weekday, items: [] });
      lanes.get(s.date).items.push({ l, startMin, endMin, s, cont: startMin + dur > 1440 });
    }
    const hrs = [0, 3, 6, 9, 12, 15, 18, 21, 24];
    const axis = `<div class="ev-axis" aria-hidden="true">${hrs.map(h => `<span style="left:${h / 24 * 100}%">${String(h).padStart(2, '0')}</span>`).join('')}</div>`;
    const lane = ([date, { wd, items }]) => {
      items.sort((a, b) => a.startMin - b.startMin);
      const rowsEnd = []; for (const it of items) { let r = rowsEnd.findIndex(e => e <= it.startMin); if (r < 0) { r = rowsEnd.length; rowsEnd.push(0); } rowsEnd[r] = it.endMin; it.row = r; }
      return `<div class="ev-lane"><div class="ev-day">${esc(wd)} ${esc(date)}</div><div class="ev-track" role="list" aria-label="${esc(wd)} ${esc(date)} in ${esc(zl)}" style="height:${rowsEnd.length * 34 + 6}px">${hrs.map(h => `<i class="ev-grid" style="left:${h / 24 * 100}%" aria-hidden="true"></i>`).join('')}${items.map(it => {
        const f = flagged.get(it.l.id) || 'none', e = C.utcToZoned(it.l.endUtc, zone);
        const label = `${it.l.id} ${it.l.title || ''}, ${it.s.time}–${e.time}${it.cont ? ' (continues next day)' : ''}${it.l.programs.length ? ', ' + it.l.programs.join(', ') : ''}`;
        return `<div class="ev-bar f-${esc(f)}" role="listitem" title="${esc(label)}" style="left:${it.startMin / 1440 * 100}%;width:${Math.max(0.8, (it.endMin - it.startMin) / 1440 * 100)}%;top:${it.row * 34 + 4}px"><b>${esc(it.l.id)}</b> ${esc(it.s.time)} ${esc(it.l.title || '')}<span class="sr-only"> to ${esc(e.time)}${it.cont ? ', continues next day' : ''}${f !== 'none' ? `, ${f} flag` : ''}</span></div>`;
      }).join('')}</div></div>`;
    };
    const skipped = L.length - timed.length;
    return `<div class="ev-tl">${axis}${[...lanes.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(lane).join('')}</div><p class="ev-sub">Bars use an assumed 2 h when no end time was listed. Outline colour = strongest flag on that listing.${skipped ? ` ${skipped} listing(s) without a resolvable time are not plotted.` : ''}</p>`;
  }
  function render() {
    const L = listings(), flags = C.detectFlags(L);
    const flagged = new Map();
    const rank = { strong: 0, moderate: 1, weak: 2 };
    for (const f of flags) for (const id of f.listings) if (!flagged.has(id) || rank[f.strength] < rank[flagged.get(id)]) flagged.set(id, f.strength);
    $('#ev-flag-count').textContent = flags.length || '';
    $('#ev-flags').innerHTML = renderFlags(flags);
    $('#ev-table').innerHTML = renderTable(L, flagged);
    $('#ev-timeline').innerHTML = renderTimeline(L, flagged);
    const n = $('#tab-events .count'); if (n) n.textContent = L.length || '';
  }

  // ---------- Ledger ----------
  async function ledger() {
    const L = listings(); if (!L.length) { toast('Add listings first'); return null; }
    return C.buildLedger(L, C.detectFlags(L), new Date().toISOString());
  }
  $('#ev-ledger').addEventListener('click', async () => {
    const r = await ledger(); if (!r) return;
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([r.html], { type: 'text/html' }));
    a.download = `claims-ledger-${new Date().toISOString().slice(0, 19).replace(/:/g, '')}.html`; a.click();
    toast(`Ledger exported · SHA-256 ${r.hash.slice(0, 12)}…`);
  });
  $('#ev-print').addEventListener('click', async () => {
    const r = await ledger(); if (!r) return;
    const w = window.open(URL.createObjectURL(new Blob([r.html], { type: 'text/html' })), '_blank', 'noopener');
    if (!w) toast('Pop-up blocked: use Export claims ledger instead');
  });

  // ---------- Demo (all invented) ----------
  const DEMO = [
    { id: 'L1', url: 'https://lu.ma/aistudy7', finalUrl: 'https://lu.ma/aistudy7', redirects: [{ url: 'https://lu.ma/aistudy7', status: 200 }], title: 'Applied AI Study Night', start: '2025-10-24T16:30:00+06:00', end: '2025-10-24T18:30:00+06:00', tz: 'Asia/Dhaka', venueName: 'Northbank Innovation Hub', venueAddress: '12 Lakeview Road, Dhaka', city: 'Dhaka', geo: { lat: 23.7801, lon: 90.4072 }, organizers: ['Northwind Dev Circle'], programs: ['Cloudwave Community Program'], attendees: 128, sources: { title: 'jsonld', start: 'jsonld', end: 'jsonld', timeZone: 'meta · embedded page data', venueName: 'jsonld', venueAddress: 'jsonld', city: 'jsonld', geo: 'jsonld', organizers: 'jsonld', programs: 'jsonld', attendees: 'text' } },
    { id: 'L2', url: 'https://www.meetup.com/northwind-dev/events/305555555/', finalUrl: 'https://www.meetup.com/northwind-dev/events/305555555/', redirects: [{ url: 'https://www.meetup.com/northwind-dev/events/305555555/', status: 200 }], title: 'Applied AI Study Night', start: '2025-10-25T10:00:00+06:00', end: '2025-10-25T12:00:00+06:00', tz: 'Asia/Dhaka', venueName: 'Northbank Innovation Hub', venueAddress: '12 Lakeview Road, Dhaka', city: 'Dhaka', organizers: ['Northwind Dev Circle'], programs: ['OpenModel Builders'], attendees: 41, sources: { title: 'meta', start: 'ics · calendar file', end: 'ics · calendar file', timeZone: 'ics', venueName: 'text', venueAddress: 'text', city: 'text', organizers: 'text', programs: 'text', attendees: 'text' } },
    { id: 'L3', url: 'https://events.example.org/stackline/events/88231', finalUrl: 'https://events.example.org/stackline/events/88917', redirects: [{ url: 'https://events.example.org/stackline/events/88231', status: 301 }, { url: 'https://events.example.org/stackline/events/88917', status: 200 }], title: 'Builders Evening: Retrieval Patterns', start: '2025-10-24T17:00:00+06:00', end: '2025-10-24T19:00:00+06:00', tz: 'Asia/Dhaka', venueName: 'Northbank Innovation Hub', venueAddress: '12 Lakeview Road, Dhaka', city: 'Dhaka', geo: { lat: 23.7802, lon: 90.4071 }, organizers: ['Northwind Dev Circle'], programs: ['Stackline Student Network'], sources: { title: 'jsonld', start: 'jsonld', end: 'jsonld', venueName: 'jsonld', venueAddress: 'jsonld', city: 'jsonld', geo: 'jsonld', organizers: 'jsonld', programs: 'text' } },
    { id: 'L4', manual: true, title: 'Generative Models Lab', start: '2025-10-24T02:00', end: '2025-10-24T04:00', tz: 'Asia/Dhaka', venueName: 'Example University, Hall B', venueAddress: '1 Campus Way, Dhaka', city: 'Dhaka', organizers: ['Example University AI Club'], programs: ['OpenModel Builders'], sources: {} },
    { id: 'L5', url: 'https://www.meetup.com/contoso-builders/events/304821111/', finalUrl: 'https://www.meetup.com/contoso-builders/events/304821111/', redirects: [{ url: 'https://www.meetup.com/contoso-builders/events/304821111/', status: 200 }], title: 'Open Data Workshop', start: '2025-10-24T18:00:00+01:00', end: '2025-10-24T20:00:00+01:00', tz: 'Europe/London', venueName: 'Harbourside Library, Room 2', venueAddress: '7 Quay Street, Bristol', city: 'Bristol', organizers: ['Contoso Builders Guild'], programs: ['Contoso Builders Guild'], sources: { title: 'ics', start: 'ics', end: 'ics', timeZone: 'ics', venueName: 'ics', venueAddress: 'ics', organizers: 'ics' } },
  ];

  // ---------- Events ----------
  $('#ev-fetch').addEventListener('click', fetchAll);
  $('#ev-demo').addEventListener('click', () => {
    if (raw.length && !confirm(`Replace the ${raw.length} current listing(s) with the fictional demo?`)) return;
    raw = JSON.parse(JSON.stringify(DEMO)); save(); resetForm(); render(); toast('Loaded 5 fictional listings');
  });
  window.addEventListener('storage', e => { if (e.key === KEY) { raw = store.get(KEY, []); render(); } }); // another tab changed the comparison
  $('#ev-clear').addEventListener('click', () => { if (!raw.length || confirm('Remove all listings from this comparison?')) { raw = []; save(); resetForm(); render(); $('#ev-status').innerHTML = ''; } });
  $('#ev-form').addEventListener('submit', submitForm);
  $('#ev-cancel').addEventListener('click', resetForm);
  $('#ev-tlzone').addEventListener('change', () => { const L = listings(); const fl = new Map(); C.detectFlags(L).forEach(f => f.listings.forEach(id => fl.has(id) || fl.set(id, f.strength))); $('#ev-timeline').innerHTML = renderTimeline(L, fl); });
  host.addEventListener('click', e => {
    const s = e.target.closest('[data-ev-sort]'), ed = e.target.closest('[data-ev-edit]'), del = e.target.closest('[data-ev-del]'), mu = e.target.closest('[data-ev-manual-url]');
    if (s) { const k = s.dataset.evSort; sort = { key: k, dir: sort.key === k ? -sort.dir : 1 }; render(); host.querySelector(`[data-ev-sort="${k}"]`)?.focus(); }
    if (ed) edit(ed.dataset.evEdit);
    if (mu) edit(null, mu.dataset.evManualUrl);
    if (del) { raw = raw.filter(l => l.id !== del.dataset.evDel); save(); render(); toast(`${del.dataset.evDel} removed`); }
  });
  applyMode();
  render();
})();
