// Shared between server/corroborate.js and the browser (GitHub Pages / static mode): input validation, the parsers for
// crt.sh, Open-Meteo and the ScamSniffer list, and the result shape. One implementation, so a lookup made by the
// server and one made directly from the browser give the same answer. No dependencies; UMD-style export.
(function (root) {
'use strict';
// Same shape as server/net-guard.js httpError: the server's outer handler answers with e.status.
function httpError(status, message, code) { const e = new Error(message); e.status = status; if (code) e.code = code; return e; }

// ---------- domain helpers ----------
function normalizeDomain(input, { keepWww = false } = {}) {
  let s = String(input || '').trim().toLowerCase();
  if (!s) throw httpError(400, 'Enter a domain', 'bad_input');
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(s)) { try { s = new URL(s).hostname; } catch { throw httpError(400, 'Not a valid URL or domain', 'bad_input'); } }
  s = s.replace(/^\*\./, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
  if (!keepWww && s.startsWith('www.')) s = s.slice(4);
  if (s.length > 253 || !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/.test(s) || /^\d+(\.\d+){3}$/.test(s))
    throw httpError(400, 'Not a valid domain name', 'bad_input');
  return s;
}

// ---------- ii-3 crt.sh certificate transparency ----------
const crtUrl = domain => `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
function summarizeCrt(records, domain) {
  if (!Array.isArray(records)) throw httpError(502, 'Unexpected crt.sh response', 'upstream');
  // crt.sh's identity search also matches e-mail SANs and organisation names; keep certificates that name this host.
  const hostNames = r => String(r.name_value || '').split(/\n/).concat(r.common_name || '').map(n => n.trim().toLowerCase());
  const forHost = n => n === domain || n === '*.' + domain || n.endsWith('.' + domain);
  const certs = records.filter(r => r && r.not_before && hostNames(r).some(forHost));
  if (!certs.length) return { domain, count: 0, firstSeen: null, lastSeen: null, issuers: [], names: [] };
  const sorted = [...certs].sort((a, b) => String(a.not_before).localeCompare(String(b.not_before)));
  const first = sorted[0], last = sorted[sorted.length - 1];
  const issuerCount = new Map(), names = new Set();
  for (const c of certs) {
    const o = /(?:^|,\s*)O=("?)([^,"]+)\1/.exec(c.issuer_name || ''), cn = /(?:^|,\s*)CN=([^,]+)/.exec(c.issuer_name || '');
    const iss = (o && o[2]) || (cn && cn[1]) || 'Unknown CA';
    issuerCount.set(iss, (issuerCount.get(iss) || 0) + 1);
    for (const h of hostNames(c)) if (!h.includes('@') && forHost(h)) names.add(h);
  }
  const iso = s => (/Z$|[+-]\d\d:?\d\d$/.test(s) ? s : s + 'Z');
  return {
    domain, count: certs.length,
    firstSeen: iso(first.not_before), firstCertId: first.id, firstIssuer: String(first.issuer_name || '').replace(/,?\s*emailAddress=[^,]*/g, ''),
    lastSeen: iso(last.not_before),
    issuers: [...issuerCount].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, n]) => ({ name, n })),
    names: [...names].sort().slice(0, 60), namesTotal: names.size,
  };
}
function crtResult(records, domain) {
  const s = summarizeCrt(records, domain);
  return {
    ...s, source: { name: 'crt.sh (Sectigo)', url: `https://crt.sh/?q=${encodeURIComponent(domain)}` },
    strength: 'moderate',
    note: s.firstSeen
      ? 'First certificate logged is an upper bound on when the site went live with HTTPS. A domain whose first certificate is days old but claims years of history is a strong mismatch; old certificates do not prove the current owner is the same.'
      : 'No certificates logged for this exact name. Many legitimate sites sit behind shared certificates, so absence alone is weak.',
  };
}

// ---------- ii-7 Open-Meteo historical weather ----------
const WMO = {
  0: 'Clear sky', 1: 'Mainly clear', 2: 'Partly cloudy', 3: 'Overcast', 45: 'Fog', 48: 'Depositing rime fog',
  51: 'Light drizzle', 53: 'Moderate drizzle', 55: 'Dense drizzle', 56: 'Light freezing drizzle', 57: 'Dense freezing drizzle',
  61: 'Slight rain', 63: 'Moderate rain', 65: 'Heavy rain', 66: 'Light freezing rain', 67: 'Heavy freezing rain',
  71: 'Slight snow', 73: 'Moderate snow', 75: 'Heavy snow', 77: 'Snow grains', 80: 'Slight rain showers', 81: 'Moderate rain showers',
  82: 'Violent rain showers', 85: 'Slight snow showers', 86: 'Heavy snow showers', 95: 'Thunderstorm', 96: 'Thunderstorm with slight hail', 99: 'Thunderstorm with heavy hail',
};
const wmoText = c => (c == null ? 'unknown' : WMO[c] || `WMO code ${c}`);
const CLAIMS = ['clear', 'cloudy', 'rain', 'snow', 'fog', 'thunderstorm'];

function parseWeatherInput(b) {
  const lat = Number(b.lat), lon = Number(b.lon);
  if (!Number.isFinite(lat) || lat < -90 || lat > 90 || !Number.isFinite(lon) || lon < -180 || lon > 180) throw httpError(400, 'Latitude must be -90..90 and longitude -180..180', 'bad_input');
  const date = String(b.date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || isNaN(Date.parse(date + 'T00:00:00Z'))) throw httpError(400, 'Date must be YYYY-MM-DD', 'bad_input');
  if (date < '1940-01-01') throw httpError(400, 'Open-Meteo history starts in 1940', 'bad_input');
  if (Date.parse(date) > Date.now()) throw httpError(400, 'Date is in the future', 'bad_input');
  let hour = b.hour === '' || b.hour == null ? null : Number(b.hour);
  if (hour != null && !(Number.isInteger(hour) && hour >= 0 && hour <= 23)) throw httpError(400, 'Hour must be 0-23', 'bad_input');
  const minute = b.minute === '' || b.minute == null || hour == null ? 0 : Number(b.minute);
  if (!(Number.isInteger(minute) && minute >= 0 && minute <= 59)) throw httpError(400, 'Minute must be 0-59', 'bad_input');
  const claim = b.claim ? String(b.claim) : null;
  if (claim && !CLAIMS.includes(claim)) throw httpError(400, 'Unknown weather claim', 'bad_input');
  const offsetMin = b.offsetMin === '' || b.offsetMin == null ? null : Number(b.offsetMin);
  if (offsetMin != null && !(Number.isInteger(offsetMin) && Math.abs(offsetMin) <= 840)) throw httpError(400, 'UTC offset must be -14:00..+14:00', 'bad_input');
  const p = { lat: Math.round(lat * 100) / 100, lon: Math.round(lon * 100) / 100, date, hour, offsetMin, claim };
  if (minute) p.minute = minute;
  return p;
}

const shiftDay = (date, n) => new Date(Date.parse(date + 'T00:00:00Z') + n * 864e5).toISOString().slice(0, 10);
const weatherKey = p => `${p.lat},${p.lon},${p.date}`;
function weatherUrl(p) {
  const q = new URLSearchParams({
    latitude: p.lat, longitude: p.lon, timezone: 'auto',
    start_date: p.date > '1940-01-01' ? shiftDay(p.date, -1) : p.date,
    end_date: [shiftDay(p.date, 1), new Date().toISOString().slice(0, 10)].sort()[0],
    daily: 'weather_code,temperature_2m_max,temperature_2m_min,precipitation_sum,snowfall_sum,cloud_cover_mean,sunrise,sunset',
    hourly: 'temperature_2m,weather_code,cloud_cover,precipitation,snowfall,snow_depth',
  });
  return `https://archive-api.open-meteo.com/v1/archive?${q}`;
}
// Open-Meteo answers bad input with HTTP 400 and {error:true, reason}.
function weatherApiError(j) { return j && j.error ? httpError(400, String(j.reason || 'Open-Meteo rejected the request').slice(0, 200), 'bad_input') : null; }

// `hour`:`minute` is wall-clock time at `offsetMin` (capture offset) or, without an offset, local time at the place.
// Open-Meteo answers in the place's timezone, so the full instant is moved into it before picking the day and hour.
function summarizeWeather(j, hour = null, date = null, offsetMin = null, minute = 0) {
  if (!j || !j.daily || !Array.isArray(j.daily.time)) throw httpError(502, 'Unexpected Open-Meteo response', 'upstream');
  date = date || j.daily.time[0];
  const hourKey = hour == null ? null : offsetMin == null ? `${date}T${String(hour).padStart(2, '0')}`
    : new Date(Date.parse(`${date}T${String(hour).padStart(2, '0')}:${String(minute || 0).padStart(2, '0')}:00Z`) + ((j.utc_offset_seconds || 0) - offsetMin * 60) * 1000).toISOString().slice(0, 13);
  const localDate = hourKey ? hourKey.slice(0, 10) : date;
  const d = j.daily, i = d.time.indexOf(localDate), pick = k => (i >= 0 && d[k] ? d[k][i] ?? null : null), h = j.hourly || {};
  const sameDay = (h.time || []).map((t, k) => (String(t).slice(0, 10) === localDate ? h.snow_depth?.[k] : null)).filter(v => v != null);
  const daily = {
    date: localDate, code: pick('weather_code'), text: wmoText(pick('weather_code')),
    tmax: pick('temperature_2m_max'), tmin: pick('temperature_2m_min'), precip: pick('precipitation_sum'), snow: pick('snowfall_sum'),
    cloud: pick('cloud_cover_mean'), sunrise: pick('sunrise'), sunset: pick('sunset'),
    snowDepth: sameDay.length ? Math.max(...sameDay) : null,
  };
  let hourly = null;
  if (hourKey && Array.isArray(h.time)) {
    const k = h.time.findIndex(t => String(t).slice(0, 13) === hourKey);
    if (k >= 0) hourly = { time: h.time[k], code: h.weather_code?.[k], text: wmoText(h.weather_code?.[k]), temp: h.temperature_2m?.[k], cloud: h.cloud_cover?.[k], precip: h.precipitation?.[k], snow: h.snowfall?.[k], snowDepth: h.snow_depth?.[k] };
  }
  const missing = daily.code == null && (!hourly || hourly.code == null);
  return { timezone: j.timezone || 'GMT', utcOffsetSeconds: j.utc_offset_seconds || 0, elevation: j.elevation, gridLat: j.latitude, gridLon: j.longitude, daily, hourly, missing };
}

// Compare a claimed condition with the reanalysis. Gridded data: agreement is supporting only (weak);
// a stark contradiction (claimed snow at 30 °C with no snowfall) is moderate, never proof.
function checkClaim(s, claim) {
  if (!claim) return null;
  const x = s.hourly && s.hourly.code != null ? s.hourly : s.daily;
  const code = x.code, cloud = x.cloud, precip = x.precip ?? 0, snow = x.snow ?? 0;
  const temp = x.temp ?? s.daily.tmax;
  if (code == null) return { claim, result: 'unverifiable', strength: 'weak', why: 'No reanalysis value for this date/place.' };
  const rainy = (code >= 51 && code <= 67) || (code >= 80 && code <= 82) || code >= 95 || precip >= 0.5;
  const depth = x.snowDepth ?? s.daily.snowDepth;
  const snowy = (code >= 71 && code <= 77) || code === 85 || code === 86 || snow > 0 || (depth ?? 0) > 0;
  const r = (result, strength, why) => ({ claim, result, strength, why });
  switch (claim) {
    case 'clear': return code <= 1 || (cloud != null && cloud < 30) ? r('consistent', 'weak', `Model shows ${x.text.toLowerCase()} (${cloud ?? '?'}% cloud).`)
      : rainy && (cloud ?? 100) >= 90 ? r('contradicted', 'moderate', `Model shows ${x.text.toLowerCase()} with ${cloud}% cloud and ${precip} mm precipitation.`)
      : r('unclear', 'weak', `Model shows ${x.text.toLowerCase()}; local breaks in cloud are possible.`);
    case 'cloudy': return code >= 2 || (cloud ?? 0) >= 50 ? r('consistent', 'weak', `Model shows ${x.text.toLowerCase()} (${cloud ?? '?'}% cloud).`)
      : r('unclear', 'weak', `Model shows ${x.text.toLowerCase()} (${cloud ?? '?'}% cloud); local cloud is possible.`);
    case 'rain': return rainy ? r('consistent', 'weak', `Model shows ${x.text.toLowerCase()}, ${precip} mm.`)
      : (cloud ?? 100) < 20 ? r('contradicted', 'moderate', `Model shows ${x.text.toLowerCase()} with ${cloud}% cloud and no precipitation.`)
      : r('unclear', 'weak', 'Model shows no precipitation, but showers can be local.');
    case 'snow': return snowy ? r('consistent', 'weak', `Model shows snowfall ${snow} cm / snow depth ${depth ?? '?'} m.`)
      : temp != null && temp >= 10 ? r('contradicted', 'moderate', `No snowfall or snow cover in the model, and ${temp} °C.`)
      : r('unclear', 'weak', 'No snow in the model; check elevation and nearby grid cells.');
    case 'fog': return code === 45 || code === 48 ? r('consistent', 'weak', 'Model flags fog.') : r('unclear', 'weak', 'Reanalysis rarely resolves fog; absence is not evidence.');
    case 'thunderstorm': return code >= 95 ? r('consistent', 'weak', `Model shows ${x.text.toLowerCase()}.`)
      : (cloud ?? 100) < 20 && precip === 0 ? r('contradicted', 'moderate', `Model shows ${x.text.toLowerCase()} with ${cloud}% cloud.`)
      : r('unclear', 'weak', 'No storm in the model; convective storms are local.');
  }
}
function weatherResult(p, j, cached) {
  const s = summarizeWeather(j, p.hour, p.date, p.offsetMin, p.minute || 0);
  return {
    ...p, ...s, cached, check: checkClaim(s, p.claim),
    attribution: { text: 'Weather data by Open-Meteo.com', url: 'https://open-meteo.com/', license: 'CC BY 4.0' },
    note: 'ERA5-based reanalysis on a ~9-25 km grid. Agreement is supporting evidence only; treat a contradiction as a reason to dig, not a verdict.',
  };
}

// ---------- ii-9 ScamSniffer phishing-domain list (GPL-3.0, fetched at runtime, never vendored) ----------
const SCAMSNIFFER_URL = 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json';
function scamSet(arr) {
  if (!Array.isArray(arr)) throw httpError(502, 'Unexpected ScamSniffer list format', 'upstream');
  const set = new Set();
  for (const d of arr) if (typeof d === 'string' && d) set.add(d.trim().toLowerCase().replace(/\.$/, ''));
  return set;
}
// Exact name plus parent domains (sub.evil.example matches evil.example), never the bare TLD.
function matchDomain(set, domain) {
  const parts = domain.split('.');
  for (let i = 0; i < parts.length - 1; i++) { const d = parts.slice(i).join('.'); if (set.has(d)) return d; }
  return null;
}
function scamDomains(body = {}) {
  const domains = [...new Set((Array.isArray(body.domains) ? body.domains : [body.domain]).filter(Boolean).slice(0, 50).map(d => { try { return normalizeDomain(d, { keepWww: true }); } catch { return null; } }).filter(Boolean))];
  if (!domains.length) throw httpError(400, 'Enter a domain', 'bad_input');
  return domains;
}
// list = { t: fetched-at ms, set }
function scamResult(domains, list) {
  return {
    results: domains.map(d => { const m = matchDomain(list.set, d); return { domain: d, listed: !!m, matched: m }; }),
    listSize: list.set.size, fetchedAt: new Date(list.t).toISOString(),
    strength: 'strong',
    source: { name: 'ScamSniffer scam-database', url: 'https://github.com/scamsniffer/scam-database', license: 'GPL-3.0' },
    note: 'Community-maintained crypto-phishing list (C2). A hit is a strong lead; no hit means only that this list has not seen it.',
  };
}

const api = { httpError, normalizeDomain, crtUrl, summarizeCrt, crtResult, WMO, wmoText, CLAIMS, parseWeatherInput, shiftDay, weatherKey, weatherUrl, weatherApiError, summarizeWeather, checkClaim, weatherResult, SCAMSNIFFER_URL, scamSet, matchDomain, scamDomains, scamResult };
if (typeof module === 'object' && module.exports) module.exports = api;
else root.ScamBunkerCorroborateCore = api;
})(typeof window !== 'undefined' ? window : globalThis);
