// Scam Bunker — Corroborate tab (docs/BACKLOG.md ii-3, ii-7, ii-8, ii-9 and P2-5).
// Sun position (NOAA Solar Calculator algorithm) and the shadow helper run locally in the browser.
// Certificate transparency (crt.sh), historical weather (Open-Meteo) and the ScamSniffer phishing list are fetched by
// server/corroborate.js, only when the investigator presses the button for that lookup. In static mode (GitHub Pages, no
// /api) the browser calls Open-Meteo and the ScamSniffer list on GitHub directly (both CORS-enabled, no key). crt.sh is
// not: its frequent timeout / 502 responses carry no CORS header, so a browser cannot read them and the web version
// shows a "local app" state with a manual crt.sh link instead. Parsing and validation are shared with the server through
// public/shared/corroborate-core.js, so both paths return the same result.
// Pure functions are exported on window.ScamBunkerCorroborate and unit-tested in test/corroborate.test.js.
(function () {
  'use strict';
  const rad = d => d * Math.PI / 180, deg = r => r * 180 / Math.PI;

  // ======================= Sun position (NOAA) =======================
  // Port of the NOAA Global Monitoring Laboratory Solar Calculator (https://gml.noaa.gov/grad/solcalc/),
  // after Meeus, "Astronomical Algorithms". Good to ~0.01° for 1950-2050; refraction uses NOAA's standard atmosphere.
  function sunPosition(date, lat, lon) {
    const ms = date instanceof Date ? date.getTime() : Number(date);
    const jd = ms / 86400000 + 2440587.5, T = (jd - 2451545) / 36525;
    const L0 = ((280.46646 + T * (36000.76983 + 0.0003032 * T)) % 360 + 360) % 360;
    const M = 357.52911 + T * (35999.05029 - 0.0001537 * T);
    const e = 0.016708634 - T * (0.000042037 + 0.0000001267 * T);
    const C = Math.sin(rad(M)) * (1.914602 - T * (0.004817 + 0.000014 * T)) + Math.sin(rad(2 * M)) * (0.019993 - 0.000101 * T) + Math.sin(rad(3 * M)) * 0.000289;
    const omega = 125.04 - 1934.136 * T;
    const lambda = L0 + C - 0.00569 - 0.00478 * Math.sin(rad(omega));
    const eps0 = 23 + (26 + (21.448 - T * (46.815 + T * (0.00059 - T * 0.001813))) / 60) / 60;
    const eps = eps0 + 0.00256 * Math.cos(rad(omega));
    const decl = deg(Math.asin(Math.sin(rad(eps)) * Math.sin(rad(lambda))));
    const y = Math.tan(rad(eps / 2)) ** 2;
    const eqTime = 4 * deg(y * Math.sin(2 * rad(L0)) - 2 * e * Math.sin(rad(M)) + 4 * e * y * Math.sin(rad(M)) * Math.cos(2 * rad(L0))
      - 0.5 * y * y * Math.sin(4 * rad(L0)) - 1.25 * e * e * Math.sin(2 * rad(M)));
    const utcMin = ((ms % 86400000) + 86400000) % 86400000 / 60000;
    const tst = (((utcMin + eqTime + 4 * lon) % 1440) + 1440) % 1440;
    let ha = tst / 4 - 180; if (ha < -180) ha += 360;
    const csz = Math.max(-1, Math.min(1, Math.sin(rad(lat)) * Math.sin(rad(decl)) + Math.cos(rad(lat)) * Math.cos(rad(decl)) * Math.cos(rad(ha))));
    const zenith = deg(Math.acos(csz));
    const den = Math.cos(rad(lat)) * Math.sin(rad(zenith));
    let az;
    if (Math.abs(den) > 0.001) {
      const a = Math.max(-1, Math.min(1, (Math.sin(rad(lat)) * Math.cos(rad(zenith)) - Math.sin(rad(decl))) / den));
      az = 180 - deg(Math.acos(a)); if (ha > 0) az = -az;
    } else az = lat > 0 ? 180 : 0;
    if (az < 0) az += 360;
    const geo = 90 - zenith;
    return { azimuth: az, elevation: geo + refraction(geo), declination: decl, equationOfTime: eqTime, hourAngle: ha };
  }
  function refraction(el) {
    if (el > 85) return 0;
    const te = Math.tan(rad(el));
    const c = el > 5 ? 58.1 / te - 0.07 / te ** 3 + 0.000086 / te ** 5 : el > -0.575 ? 1735 + el * (-518.2 + el * (103.4 + el * (-12.79 + el * 0.711))) : -20.774 / te;
    return c / 3600;
  }

  // ======================= Shadow helper =======================
  const POINTS = ['N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE', 'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW'];
  const compass = b => POINTS[Math.round((((b % 360) + 360) % 360) / 22.5) % 16];
  const angDiff = (a, b) => { const d = Math.abs((((a - b) % 360) + 540) % 360 - 180); return d; };
  // Shadows point away from the sun; a vertical object of height 1 casts a shadow 1/tan(elevation) long.
  function shadow(sun) {
    if (sun.elevation <= 0) return { bearing: null, compass: null, lengthRatio: null, sunUp: false };
    const bearing = (sun.azimuth + 180) % 360;
    return { bearing, compass: compass(bearing), lengthRatio: 1 / Math.tan(rad(sun.elevation)), sunUp: true };
  }
  // "+06:00" / "-0530" / "Z" / "UTC" → minutes east of UTC.
  function parseOffset(s) {
    s = String(s == null ? '' : s).trim().toUpperCase();
    if (!s || s === 'Z' || s === 'UTC' || s === 'GMT') return 0;
    const m = /^(?:UTC|GMT)?\s*([+-])(\d{1,2})(?::?(\d{2}))?$/.exec(s);
    if (!m || +m[2] > 14 || +(m[3] || 0) > 59) return null;
    return (m[1] === '-' ? -1 : 1) * (+m[2] * 60 + +(m[3] || 0));
  }
  // Local wall-clock date/time + offset → UTC milliseconds.
  function localToUtc(date, time, offsetMin) {
    const d = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date || ''), t = /^(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(time || '00:00');
    if (!d || !t) return null;
    return Date.UTC(+d[1], +d[2] - 1, +d[3], +t[1], +t[2], +(t[3] || 0)) - offsetMin * 60000;
  }
  const hhmm = min => `${String(Math.floor(min / 60)).padStart(2, '0')}:${String(Math.round(min % 60)).padStart(2, '0')}`;
  // Chronolocation: at which local times on this day/place does a vertical object cast a shadow toward `bearing`
  // (and optionally with this length/height ratio)? Returns the best minute in each matching window.
  function timesForShadow({ date, offsetMin = 0, lat, lon, bearing, ratio = null, tolerance = 5 }) {
    const start = localToUtc(date, '00:00', offsetMin); if (start == null) return [];
    const runs = []; let cur = null;
    for (let m = 0; m < 1440; m++) {
      const sun = sunPosition(start + m * 60000, lat, lon), sh = shadow(sun);
      let score = sh.sunUp ? angDiff(sh.bearing, bearing) : Infinity, ratioOk = true;
      if (sh.sunUp && ratio != null && ratio > 0) { const r = Math.abs(Math.log(sh.lengthRatio / ratio)); ratioOk = r < 0.25; score += r * 20; }
      if (sh.sunUp && angDiff(sh.bearing, bearing) <= tolerance && ratioOk) {
        if (!cur) runs.push(cur = { best: null });
        if (!cur.best || score < cur.best.score) cur.best = { score, minute: m, time: hhmm(m), azimuth: sun.azimuth, elevation: sun.elevation, shadowBearing: sh.bearing, lengthRatio: sh.lengthRatio, off: angDiff(sh.bearing, bearing) };
      } else cur = null;
    }
    return runs.map(r => r.best);
  }

  // ======================= Reporting routes (P2-5) =======================
  // Every URL below was opened and checked when added (Nov 2026). Phone numbers are the organisations' published lines.
  const ROUTES = {
    countries: {
      BD: { name: 'Bangladesh', emergency: '999', routes: [
        { name: 'CID Cyber Police Centre (Bangladesh Police)', url: 'https://www.cid.gov.bd/public/cpc', phone: '01320010148', email: 'cyber@police.gov.bd', what: 'Online fraud, hacking, impersonation and other cyber crime, nationwide.' },
        { name: 'Police Cyber Support for Women (PCSW)', url: 'https://www.police.gov.bd/en/police_cyber_support_for_women', phone: '01320000888', email: 'cybersupport.women@police.gov.bd', what: 'Harassment, sextortion and abuse of women online.' },
        { name: 'DMP Cyber Crime Investigation (CTTC)', url: 'https://dmp.gov.bd/', email: 'cyberhelp@dmp.gov.bd', what: 'Cyber crime in the Dhaka Metropolitan area.' },
        { name: 'BTRC Complain Box', url: 'https://crm.btrc.gov.bd/', what: 'Fraud calls/SMS and complaints against mobile operators or ISPs (SIM misuse, unresolved operator complaints).' },
        { name: 'bKash fraud helpline', url: 'https://www.bkash.com/en/customer-service/avoid-fraud', phone: '16247', what: 'Report a fraudulent bKash transaction or number immediately (24/7). Never share your PIN or OTP. Alternative line 02-55663001 (bkash.com contact page).' },
        { name: 'Bangladesh Bank CIPC', url: 'https://www.bb.org.bd/en/index.php/services/cipc_procedure', phone: '16236', email: 'bb.cipc@bb.org.bd', what: 'Escalate a complaint against a bank or mobile financial service after the provider has not resolved it.' },
        { name: 'BGD e-GOV CIRT', url: 'https://www.cirt.gov.bd/', what: 'National CERT: phishing sites, malware and security incidents.' },
      ] },
      US: { name: 'United States', emergency: '911', routes: [
        { name: 'FBI Internet Crime Complaint Center (IC3)', url: 'https://www.ic3.gov/', what: 'Online fraud and crypto investment scams, especially with losses.' },
        { name: 'FTC ReportFraud', url: 'https://reportfraud.ftc.gov/', what: 'Scams, impersonation, bad business practices.' },
      ] },
      GB: { name: 'United Kingdom', emergency: '999', routes: [
        { name: 'Report Fraud (England, Wales, Northern Ireland)', url: 'https://www.reportfraud.police.uk/', phone: '0300 123 2040', what: 'Fraud and cyber crime. Replaced Action Fraud in December 2025. In Scotland call Police Scotland on 101.' },
        { name: 'NCSC: report a scam email or website', url: 'https://www.ncsc.gov.uk/collection/phishing-scams/report-scam-email', what: 'Forward phishing email to the Suspicious Email Reporting Service; report scam websites.' },
      ] },
      CA: { name: 'Canada', emergency: '911', routes: [
        { name: 'Canadian Anti-Fraud Centre', url: 'https://antifraudcentre-centreantifraude.ca/', what: 'Fraud and scams, including crypto and romance scams.' },
      ] },
      AU: { name: 'Australia', emergency: '000', routes: [
        { name: 'Scamwatch (ACCC)', url: 'https://www.scamwatch.gov.au/report-a-scam', what: 'Report a scam to help warn others.' },
        { name: 'ReportCyber (ASD)', url: 'https://www.cyber.gov.au/report-and-recover/report', what: 'Cyber crime with losses or identity theft; referred to police.' },
      ] },
      IN: { name: 'India', emergency: '112', routes: [
        { name: 'National Cyber Crime Reporting Portal', url: 'https://cybercrime.gov.in/', what: 'Financial fraud and other cyber crime.' },
      ] },
    },
    platforms: [
      { key: 'meta', match: /facebook|instagram|messenger|threads|\bmeta\b/i, name: 'Facebook / Instagram (Meta)', url: 'https://www.meta.com/safety/scam-protection-center/safety-tips/how-to-report-on-meta/', what: 'Use “Report” on the post, profile or message; this page lists every route.' },
      { key: 'whatsapp', match: /whatsapp/i, name: 'WhatsApp', url: 'https://faq.whatsapp.com/1142481766359885', what: 'Chat → contact or group info → Report. WhatsApp receives the last five messages.' },
      { key: 'telegram', match: /telegram/i, name: 'Telegram', url: 'https://telegram.org/faq_spam', what: 'Report the account or channel in the app; see the Spam FAQ.' },
      { key: 'linkedin', match: /linkedin/i, name: 'LinkedIn', url: 'https://www.linkedin.com/help/linkedin/answer/a1338436', what: 'Report fake profiles and fake recruiters from the profile’s “More” menu.' },
      { key: 'tiktok', match: /tiktok/i, name: 'TikTok', url: 'https://support.tiktok.com/en/safety-hc/report-a-problem', what: 'Long-press or Share → Report on the video, account or comment.' },
      { key: 'youtube', match: /youtube/i, name: 'YouTube', url: 'https://support.google.com/youtube/answer/2802027', what: 'Report the video, channel, comment or ad.' },
      { key: 'reddit', match: /reddit/i, name: 'Reddit', url: 'https://support.reddithelp.com/hc/en-us/articles/360058309512', what: 'Report the post, comment or account.' },
      { key: 'x', match: /\bx\b|twitter/i, name: 'X / Twitter', url: null, what: 'Use “Report post” or “Report account” from the ⋯ menu in the app (no public form verified).' },
    ],
    web: [
      { name: 'Google Safe Browsing: report phishing', url: 'https://safebrowsing.google.com/safebrowsing/report_phish/', what: 'Gets a phishing URL blocked in Chrome, Firefox and Safari.' },
      { name: 'Microsoft: report an unsafe site', url: 'https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site', what: 'Blocks the URL in Edge / SmartScreen.' },
      { name: 'Netcraft', url: 'https://report.netcraft.com/report', what: 'Phishing and fraud sites; Netcraft notifies hosts and registrars.' },
      { name: 'APWG', url: 'https://apwg.org/reportphishing/', what: 'Forward phishing emails to the Anti-Phishing Working Group.' },
      { name: 'Chainabuse', url: 'https://www.chainabuse.com/', what: 'Crypto scam addresses and sites (public, multi-chain).' },
    ],
  };
  function routesFor(platform, country) {
    return {
      country: ROUTES.countries[country] || null,
      platforms: platform ? ROUTES.platforms.filter(p => p.match.test(platform)) : [],
      web: ROUTES.web,
    };
  }

  const api = { sunPosition, refraction, shadow, compass, angDiff, parseOffset, localToUtc, timesForShadow, routesFor, ROUTES };
  if (typeof window !== 'undefined') window.ScamBunkerCorroborate = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof window === 'undefined' || !window.ScamBunker || typeof document === 'undefined') return;

  // ======================= UI =======================
  const SB = window.ScamBunker, esc = SB.esc;
  // Feature-scoped: links inherit the theme accent so they keep 4.5:1 contrast in both themes.
  const style = document.createElement('style');
  style.textContent = '[data-panel="corroborate"] a { color: var(--accent); } [data-panel="corroborate"] h3 { margin: 22px 0 10px; } [data-panel="corroborate"] h4 { margin: 16px 0 8px; }';
  document.head.appendChild(style);
  const $ = s => document.querySelector(s);
  const panelEl = () => document.querySelector('[data-panel="corroborate"]');
  const safeUrl = u => (/^https?:\/\//i.test(u || '') ? u : null);
  const ext = (u, label) => (safeUrl(u) ? `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(label)} ↗<span class="sr-only"> (opens in a new tab)</span></a>` : esc(label));
  const fmt = (n, d = 1) => (n == null || !isFinite(n) ? '–' : Number(n).toFixed(d));
  const PLATFORM_HOSTS = /(^|\.)(facebook|instagram|linkedin|lnkd|twitter|x|t|tiktok|youtube|youtu|google|whatsapp|wa|telegram|reddit|threads|bit|tinyurl|goo)\.(com|net|org|ly|me|in|gl|be)$/i;

  function caseDefaults(c) {
    const ex = (c && c.forensics && c.forensics.exif) || {};
    const out = { date: '', time: '', offset: '', lat: '', lon: '', domains: [], platform: (c && (c.platform || (c.heuristics && c.heuristics.platform))) || '' };
    const orig = !!ex.DateTimeOriginal, dt = /^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2})/.exec(ex.DateTimeOriginal || ex.DateTime || '');
    if (dt) { out.date = `${dt[1]}-${dt[2]}-${dt[3]}`; out.time = `${dt[4]}:${dt[5]}`; }
    out.offset = (orig ? ex.OffsetTimeOriginal : ex.OffsetTime) || ''; // only the offset that belongs to this timestamp
    if (ex.GPSDecimal && isFinite(ex.GPSDecimal.lat)) { out.lat = (+ex.GPSDecimal.lat).toFixed(5); out.lon = (+ex.GPSDecimal.lon).toFixed(5); }
    const urls = [c && c.url, ...((c && c.heuristics && c.heuristics.links) || []).map(l => l.url || l)].filter(Boolean);
    for (const u of urls) { try { const h = new URL(/^https?:/i.test(u) ? u : 'https://' + u).hostname; if (h && !PLATFORM_HOSTS.test(h) && !out.domains.includes(h)) out.domains.push(h); } catch { } }
    return out;
  }

  function sel(id, opts, val) { return `<select id="${id}">${opts.map(([v, l]) => `<option value="${esc(v)}"${v === val ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select>`; }

  function render(c) {
    const p = panelEl(); if (!p) return;
    if (!c) { p.innerHTML = '<p class="empty">Analyse something first. Corroboration checks use the date, place and links from the case.</p>'; return; }
    const d = caseDefaults(c), st = c.corroborate || (c.corroborate = {});
    const f = st.form || (st.form = { ...d, domain: d.domains[0] || '', claim: '', bearing: '', ratio: '', country: SB.store.get('sb-corroborate-country', 'BD'), platformSel: d.platform });
    const countries = Object.entries(ROUTES.countries).map(([k, v]) => [k, v.name]);
    p.innerHTML = `
      <p class="callout">Each check is a <b>lead, not a verdict</b>. Nothing leaves your machine until you press a lookup button; sun position is computed locally. Examples here are invented.${isStatic() ? ' <b>Web version:</b> there is no Scam Bunker server here, so weather, certificate and phishing-list lookups go straight from your browser to Open-Meteo and GitHub (ScamSniffer list); the crt.sh certificate summary needs the local app.' : ''}</p>
      <h3 id="cor-sun-h">Sun &amp; shadows <span class="tag">local · NOAA algorithm</span></h3>
      <div class="grid2">
        <label class="field"><span>Date (local)</span><input id="cor-date" type="date" value="${esc(f.date)}"></label>
        <label class="field"><span>Time (local, 24 h)</span><input id="cor-time" type="time" value="${esc(f.time)}"></label>
        <label class="field"><span>UTC offset (e.g. +06:00)</span><input id="cor-offset" inputmode="text" value="${esc(f.offset)}" placeholder="+06:00"></label>
        <div class="row"><label class="field grow"><span>Latitude</span><input id="cor-lat" inputmode="decimal" value="${esc(f.lat)}" placeholder="23.81"></label>
          <label class="field grow"><span>Longitude</span><input id="cor-lon" inputmode="decimal" value="${esc(f.lon)}" placeholder="90.41"></label></div>
        <label class="field"><span>Shadow direction in the photo (° from north, optional)</span><input id="cor-bearing" inputmode="decimal" value="${esc(f.bearing)}" placeholder="e.g. 315"></label>
        <label class="field"><span>Shadow length ÷ object height (optional)</span><input id="cor-ratio" inputmode="decimal" value="${esc(f.ratio)}" placeholder="e.g. 1.2"></label>
      </div>
      <div class="row"><button class="primary sm" id="cor-sun-run" type="button">Compute sun &amp; shadow</button></div>
      <div id="cor-sun-out" aria-live="polite">${st.sunHtml || ''}</div>

      <h3 id="cor-wx-h">Weather on that day <span class="tag">Open-Meteo</span></h3>
      <p class="muted">Uses the date, latitude and longitude above (and the hour, if a time is set).</p>
      <div class="row">
        <label class="field grow"><span>Weather claimed or visible</span>${sel('cor-claim', [['', 'Just show the record'], ['clear', 'Clear / sunny'], ['cloudy', 'Cloudy / overcast'], ['rain', 'Rain / wet ground'], ['snow', 'Snow'], ['fog', 'Fog'], ['thunderstorm', 'Thunderstorm']], f.claim)}</label>
      </div>
      <div class="row"><button class="primary sm" id="cor-wx-run" type="button">Check historical weather</button></div>
      <div id="cor-wx-out" aria-live="polite">${st.wxHtml || ''}</div>

      <h3 id="cor-dom-h">Domain checks</h3>
      <label class="field"><span>Domain</span><input id="cor-domain" list="cor-domains" value="${esc(f.domain)}" placeholder="example-shop.invalid" autocomplete="off" spellcheck="false"></label>
      <datalist id="cor-domains">${d.domains.map(h => `<option value="${esc(h)}">`).join('')}</datalist>
      <div class="row"><button class="primary sm" id="cor-crt-run" type="button">Certificate first seen (crt.sh)</button>
        <button class="ghost sm" id="cor-ss-run" type="button">Check ScamSniffer phishing list</button></div>
      <p class="muted">Registration age (RDAP) lives in the Subjects module.</p>
      <div id="cor-dom-out" aria-live="polite">${st.domHtml || ''}</div>

      <h3 id="cor-rep-h">Where to report</h3>
      <div class="row">
        <label class="field grow"><span>Country</span>${sel('cor-country', countries, f.country)}</label>
        <label class="field grow"><span>Platform</span>${sel('cor-platform', [['', 'Any / not listed'], ...ROUTES.platforms.map(x => [x.name, x.name])], (ROUTES.platforms.find(x => x.match.test(f.platformSel || '')) || {}).name || '')}</label>
      </div>
      <div id="cor-rep-out">${renderRoutes(f)}</div>`;
    if (st.focus) { const el = document.getElementById(st.focus); st.focus = null; if (el) el.focus(); }
  }

  function routeCard(r) {
    const bits = [r.phone && `Phone <b>${esc(r.phone)}</b>`, r.email && `Email <code>${esc(r.email)}</code>`].filter(Boolean).join(' · ');
    return `<div class="linkcard"><div class="top"><b>${ext(r.url, r.name)}</b></div><p class="muted">${esc(r.what)}${bits ? '<br>' + bits : ''}</p></div>`;
  }
  function renderRoutes(f) {
    const r = routesFor(f.platformSel, f.country);
    return `${r.country ? `<h4>${esc(r.country.name)} <span class="tag">emergency ${esc(r.country.emergency)}</span></h4>${r.country.routes.map(routeCard).join('')}` : ''}
      ${r.platforms.length ? `<h4>On the platform</h4>${r.platforms.map(routeCard).join('')}` : ''}
      <h4>Phishing sites, email and crypto</h4>${r.web.map(routeCard).join('')}
      <p class="muted">Report what you saw, keep your own evidence (screenshots, URLs, transaction IDs) and do not contact or accuse the person yourself.</p>`;
  }

  function readForm(c) {
    const f = c.corroborate.form, v = id => ($('#' + id) || {}).value || '';
    Object.assign(f, { date: v('cor-date'), time: v('cor-time'), offset: v('cor-offset'), lat: v('cor-lat'), lon: v('cor-lon'), bearing: v('cor-bearing'), ratio: v('cor-ratio'), claim: v('cor-claim'), domain: v('cor-domain').trim(), country: v('cor-country'), platformSel: v('cor-platform') });
    return f;
  }
  function place(f, needOffset = false) {
    const lat = parseFloat(f.lat), lon = parseFloat(f.lon), off = parseOffset(f.offset);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(f.date)) return { err: 'Enter the date.' };
    if (needOffset && !String(f.offset).trim()) return { err: 'Enter the UTC offset of the local time (the photo did not record one). Guessing UTC would shift the sun by hours.' };
    if (!(lat >= -90 && lat <= 90) || !(lon >= -180 && lon <= 180)) return { err: 'Enter latitude (-90 to 90) and longitude (-180 to 180).' };
    if (off == null) return { err: 'UTC offset must look like +06:00 or -05:30.' };
    return { lat, lon, off };
  }
  const errBox = m => `<p class="callout" role="alert">${esc(m)}</p>`;

  // ---------- Lookups: server route, or browser-direct in static mode ----------
  const K = window.ScamBunkerCorroborateCore;
  const isStatic = () => !!(SB.isStatic && SB.isStatic());
  const direct = { weather: new Map(), scam: null, scamLoading: null };
  async function getJson(url, ms, failMsg) {
    let r, j;
    try { r = await fetch(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(ms), credentials: 'omit', referrerPolicy: 'no-referrer' }); }
    catch { throw new Error(failMsg); } // network error, timeout, or an error page without CORS headers
    try { j = await r.json(); } catch { j = null; }
    return { ok: r.ok, status: r.status, j };
  }
  const browserLookups = {
    async weather(body) {
      const p = K.parseWeatherInput(body), key = K.weatherKey(p);
      let j = direct.weather.get(key); const cached = !!j;
      if (!j) {
        const r = await getJson(K.weatherUrl(p), 15000, 'Open-Meteo is unavailable right now; try again later.');
        const bad = K.weatherApiError(r.j); if (bad) throw bad;
        if (!r.ok) throw new Error('Open-Meteo is unavailable right now; try again later.');
        direct.weather.set(key, j = r.j);
      }
      return K.weatherResult(p, j, cached);
    },
    async scamsniffer(body) {
      const domains = K.scamDomains(body);
      if (!direct.scam || Date.now() - direct.scam.t > 6 * 3600e3) {
        direct.scamLoading = direct.scamLoading || getJson(K.SCAMSNIFFER_URL, 60000, 'Could not download the ScamSniffer list right now.')
          .then(r => { if (!r.ok) throw new Error('Could not download the ScamSniffer list right now.'); return (direct.scam = { t: Date.now(), set: K.scamSet(r.j) }); })
          .finally(() => { direct.scamLoading = null; });
        await direct.scamLoading;
      }
      return K.scamResult(domains, direct.scam);
    },
  };
  const lookup = (name, body) => (isStatic() && K ? browserLookups[name](body) : SB.post('/api/corroborate/' + name, body));

  function runSun(c) {
    const f = readForm(c), pl = place(f, true), st = c.corroborate;
    if (pl.err) { st.sunHtml = errBox(pl.err); return render(c); }
    let html = '';
    if (f.time) {
      const sun = sunPosition(localToUtc(f.date, f.time, pl.off), pl.lat, pl.lon), sh = shadow(sun);
      html += `<div class="kv">
        <div>Sun azimuth</div><div>${fmt(sun.azimuth)}° (${esc(compass(sun.azimuth))})</div>
        <div>Sun elevation</div><div>${fmt(sun.elevation)}°${sun.elevation <= 0 ? ' · sun below the horizon: no direct shadows, so a sunlit photo contradicts this time/place' : ''}</div>
        <div>Shadows point</div><div>${sh.sunUp ? `${fmt(sh.bearing)}° (${esc(sh.compass)})` : '–'}</div>
        <div>Shadow length</div><div>${sh.sunUp ? `${fmt(sh.lengthRatio, 2)} × object height` : '–'}</div></div>`;
    }
    const b = parseFloat(f.bearing);
    if (isFinite(b)) {
      const ratio = parseFloat(f.ratio);
      const t = timesForShadow({ date: f.date, offsetMin: pl.off, lat: pl.lat, lon: pl.lon, bearing: ((b % 360) + 360) % 360, ratio: isFinite(ratio) ? ratio : null });
      html += `<h4>Times that match a shadow toward ${fmt(b, 0)}° (${esc(compass(b))})${isFinite(ratio) ? ` with length ≈ ${fmt(ratio, 2)}×` : ''}</h4>` + (t.length
        ? `<ul class="list">${t.map(x => `<li><b>${esc(x.time)}</b> local · shadow ${fmt(x.shadowBearing)}°, ${fmt(x.lengthRatio, 2)}× height, sun ${fmt(x.elevation)}° up</li>`).join('')}</ul>`
        : '<p class="muted">No time that day matches within ±5°. Check the bearing (true north, not magnetic), the date and the place; a genuine mismatch is a moderate signal.</p>');
    }
    if (!html) html = errBox('Enter a time, a shadow direction, or both.');
    st.sunHtml = html + '<p class="muted">Strength: <span class="w moderate">moderate</span> at best. Bearings read off a photo are rarely better than ±10°.</p>';
    render(c);
  }

  async function runWeather(c) {
    const f = readForm(c), pl = place(f), st = c.corroborate;
    if (pl.err) { st.wxHtml = errBox(pl.err); return render(c); }
    st.wxHtml = '<p class="muted">Looking up Open-Meteo…</p>'; render(c);
    try {
      const r = await lookup('weather', { lat: pl.lat, lon: pl.lon, date: f.date, hour: f.time ? +f.time.slice(0, 2) : null, minute: f.time ? +f.time.slice(3, 5) || 0 : null, offsetMin: f.time && f.offset.trim() ? pl.off : null, claim: f.claim || null });
      const dd = r.daily, h = r.hourly, ck = r.check;
      st.wxHtml = `${ck ? `<div class="obs"><div class="ob"><div><span class="k">Claimed: ${esc(ck.claim)}</span><p>${esc(ck.why)}</p></div><div><span class="k">Strength</span><p>${esc(ck.strength)}: gridded model, not a local observation</p></div><span class="w ${ck.result === 'contradicted' ? 'moderate' : ck.result === 'consistent' ? 'ok' : 'weak'}">${esc(ck.result)}</span></div></div>` : ''}
        <div class="kv">
          <div>Day (${esc(r.timezone)})</div><div>${esc(dd.text)} · ${fmt(dd.tmin)}–${fmt(dd.tmax)} °C · precipitation ${fmt(dd.precip)} mm · snow ${fmt(dd.snow)} cm · cloud ${fmt(dd.cloud, 0)}%</div>
          <div>Sunrise / sunset</div><div>${esc(String(dd.sunrise || '–').slice(11))} / ${esc(String(dd.sunset || '–').slice(11))}</div>
          ${h ? `<div>At ${esc(String(h.time).slice(11))}</div><div>${esc(h.text)} · ${fmt(h.temp)} °C · cloud ${fmt(h.cloud, 0)}% · precipitation ${fmt(h.precip)} mm${h.snowDepth ? ` · snow depth ${fmt(h.snowDepth, 2)} m` : ''}</div>` : ''}
          <div>Grid cell</div><div>${fmt(r.gridLat, 2)}, ${fmt(r.gridLon, 2)} · ${fmt(r.elevation, 0)} m</div>
        </div>
        <p class="muted">${esc(r.note)} ${ext(r.attribution.url, r.attribution.text)} (${esc(r.attribution.license)})${r.cached ? ' · cached' : ''}</p>`;
    } catch (e) { st.wxHtml = errBox(e.message); }
    if (SB.current === c) render(c);
  }

  async function runCrt(c) {
    const f = readForm(c), st = c.corroborate;
    if (!f.domain) { st.domHtml = errBox('Enter a domain.'); return render(c); }
    if (isStatic()) {
      let d; try { d = K.normalizeDomain(f.domain); } catch (e) { st.domHtml = errBox(e.message); return render(c); }
      st.domHtml = `<div class="callout" role="status"><p><b>Certificate history needs the local app.</b> crt.sh does not allow browser requests from other sites when it is slow or failing (which is often), so the web version cannot query it reliably. Run Scam Bunker locally (<code>npm start</code>) for the automatic summary, or open crt.sh yourself and note the earliest <i>Not Before</i> date.</p><p>${ext(`https://crt.sh/?q=${encodeURIComponent(d)}`, `Search crt.sh for ${d}`)}</p></div>`;
      return render(c);
    }
    st.domHtml = '<p class="muted">Querying crt.sh (can take up to 20 s)…</p>'; render(c);
    try {
      const r = await lookup('crtsh', { domain: f.domain });
      const days = r.firstSeen ? Math.floor((Date.now() - Date.parse(r.firstSeen)) / 864e5) : null;
      st.domHtml = `<div class="linkcard"><div class="top"><code>${esc(r.domain)}</code><span class="w ${days != null && days < 90 ? 'moderate' : 'weak'}">${r.firstSeen ? `first certificate ${esc(r.firstSeen.slice(0, 10))}` : 'no certificates logged'}</span></div>
        ${r.firstSeen ? `<div class="kv"><div>First seen</div><div>${esc(r.firstSeen)} (${days} days ago)</div><div>Latest</div><div>${esc(r.lastSeen)}</div><div>Certificates</div><div>${r.count}</div>
        <div>Issuers</div><div>${r.issuers.map(i => `${esc(i.name)} (${i.n})`).join(', ')}</div>
        <div>Names on certificates</div><div>${r.names.map(n => `<code>${esc(n)}</code>`).join(' ')}${r.namesTotal > r.names.length ? ` … +${r.namesTotal - r.names.length}` : ''}</div></div>` : ''}
        <p class="muted">${esc(r.note)} Source: ${ext(r.source.url, r.source.name)}${r.cached ? ' · cached' : ''}</p></div>`;
    } catch (e) { st.domHtml = errBox(e.message); }
    if (SB.current === c) render(c);
  }

  async function runScam(c) {
    const f = readForm(c), st = c.corroborate;
    const doms = [...new Set([f.domain, ...caseDefaults(c).domains].filter(Boolean))];
    if (!doms.length) { st.domHtml = errBox('Enter a domain.'); return render(c); }
    st.domHtml = `<p class="muted" role="status">${isStatic() ? 'Loading the ScamSniffer list (first lookup downloads ~9 MB into this tab from GitHub, then it is kept in memory)…' : 'Loading the ScamSniffer list (first lookup downloads ~9 MB to the server, then it is cached)…'}</p>`; render(c);
    try {
      const r = await lookup('scamsniffer', { domains: doms });
      st.domHtml = `<div class="obs">${r.results.map(x => `<div class="ob"><div><span class="k">Domain</span><p><code>${esc(x.domain)}</code>${x.listed && x.matched !== x.domain ? ` (via <code>${esc(x.matched)}</code>)` : ''}</p></div><div><span class="k">ScamSniffer</span><p>${x.listed ? 'On the phishing list' : 'Not on the list'}</p></div><span class="w ${x.listed ? 'strong' : 'weak'}">${x.listed ? 'listed' : 'not listed'}</span></div>`).join('')}</div>
        <p class="muted">${esc(r.note)} ${r.listSize.toLocaleString()} domains, fetched ${esc(r.fetchedAt.slice(0, 16).replace('T', ' '))} UTC. Data: ${ext(r.source.url, r.source.name)} (${esc(r.source.license)}), downloaded at runtime and not redistributed.</p>`;
    } catch (e) { st.domHtml = errBox(e.message); }
    if (SB.current === c) render(c);
  }

  document.addEventListener('sb:case', e => render(e.detail));
  // Simple mode (parallel shell PR; call defensively): the tool tab is Investigator-only, but anyone with a link in their
  // case gets a plain "report this website" step.
  const corTab = document.querySelector('#tab-corroborate');
  function applyUiMode() {
    if (!corTab) return;
    const simple = typeof SB.mode === 'function' && SB.mode() === 'simple';
    corTab.hidden = simple;
    if (simple && corTab.getAttribute('aria-selected') === 'true') SB.showTab('deduction');
  }
  document.addEventListener('sb:mode', applyUiMode);
  document.addEventListener('sb:ready', applyUiMode);
  applyUiMode();
  const contributed = new WeakSet();
  document.addEventListener('sb:case', e => {
    const c = e.detail; if (!c || contributed.has(c) || typeof SB.addActions !== 'function' || !caseDefaults(c).domains.length) return;
    contributed.add(c);
    try { SB.addActions(c, [{ text: 'If the link looks fake, report it to Google so browsers warn other people.', href: 'https://safebrowsing.google.com/safebrowsing/report_phish/' }]); } catch { }
  });

  document.addEventListener('click', e => {
    if (e.target.closest('#history-list .hist')) { setTimeout(() => render(SB.current), 0); return; }
    const c = SB.current, btn = e.target.closest('[data-panel="corroborate"] button[id^="cor-"]'); if (!c || !btn) return;
    c.corroborate.focus = btn.id;
    if (e.target.closest('#cor-sun-run')) runSun(c);
    else if (e.target.closest('#cor-wx-run')) runWeather(c);
    else if (e.target.closest('#cor-crt-run')) runCrt(c);
    else if (e.target.closest('#cor-ss-run')) runScam(c);
  });
  document.addEventListener('change', e => {
    const c = SB.current; if (!c || !c.corroborate || !e.target.closest('#cor-country, #cor-platform')) return;
    const f = readForm(c); SB.store.set('sb-corroborate-country', f.country);
    $('#cor-rep-out').innerHTML = renderRoutes(f);
  });
  render(SB.current);
})();
