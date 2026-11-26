// Scam Bunker — existing fact-check lookup (BACKLOG P1-7).
// Extracts up to three checkable claims from the post text and searches published fact-checks (ClaimReview) through the
// Google Fact Check Tools API (claims:search). Optional: GOOGLE_FACTCHECK_API_KEY (FACTCHECK_API_KEY also accepted).
// Without a key no third-party call is made; the UI links each claim to Google Fact Check Explorer instead.
// Results are leads: a search hit may be a different claim, so the investigator must confirm it is the same one.
const { assertPublicUrl } = require('./net-guard');

const KEY = process.env.GOOGLE_FACTCHECK_API_KEY || process.env.FACTCHECK_API_KEY || '';
const ENDPOINT = 'https://factchecktools.googleapis.com/v1alpha1/claims:search';
const EXPLORER = 'https://toolbox.google.com/factcheck/explorer/search/';
const CACHE_MS = 6 * 3600 * 1000;
const cache = new Map();

// ---------- Claim extraction (simple, explainable heuristics) ----------
const MONTHS = 'jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?';
const DATE_RE = new RegExp(`\\b(?:(?:19|20)\\d{2}|\\d{1,2}(?:st|nd|rd|th)? (?:${MONTHS})|(?:${MONTHS}) \\d{1,2}(?:st|nd|rd|th)?|\\d{1,2}[/.-]\\d{1,2}[/.-]\\d{2,4}|(?:yester|to)day|last (?:week|month|year))\\b`, 'i');
const NUMBER_RE = /\d/;
const CLAIM_VERBS = /\b(cure[sd]?|curing|confirm(?:s|ed)?|prove[sn]?|proved|caus(?:es|ed|ing)|kill(?:s|ed)?|ban(?:s|ned)?|announc(?:es|ed)|approv(?:es|ed)|declar(?:es|ed)|arrest(?:s|ed)|died|dead|reveal(?:s|ed)|admit(?:s|ted)|warn(?:s|ed)|found|discover(?:s|ed)|study|studies|research(?:ers)? (?:show|found)|scientists?|doctors?|experts?|officials?|government|ministry|vaccines?|elections?|percent|per ?cent)\b/i;
const CALL_TO_ACTION = /^(share|tag|type|like|comment|follow|click|tap|dm|message|send|reply|subscribe|retweet|repost|forward|download|join|contact|call|text|act now|wake up|do your own research)\b/i;
const FIRST_SECOND_PERSON = /\b(i|i'm|i've|me|my|we|our|you|your|you're)\b/gi;
const STOP = new Set('i me my we our you your he him she her they a an the and or but of to in on at for with by from as is are was were be been being it its this that these those there their they them he she his her has have had do does did not no so if than then into over about after before just very can could would should will may might must also only even such which who whom what when where why how all any each more most other some own same too out up down off again further once here both few nor'.split(' '));
const HYPE = /^(breaking|urgent|share|shared|deleted|before|true|100%|amen|wow|omg|people|please|now|news|alert|viral|exclusive)$/i;

const clean = s => String(s || '').replace(/https?:\/\/\S+/g, ' ').replace(/[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}\u{200D}]/gu, ' ').replace(/[#@][\w.]+/g, ' ').replace(/\s+/g, ' ').trim();

function sentences(text) {
  const out = [];
  for (const line of String(text || '').split(/\n+/)) {
    for (const part of line.split(/(?<=[.!?…])\s+|(?<=[!?]{2})(?=\S)/)) {
      // "Doctors don't want you to know this: <claim>" → keep the claim after the colon when it is substantial
      const i = part.indexOf(': ');
      if (i > 0 && part.slice(i + 2).split(/\s+/).length >= 5) out.push(part.slice(0, i), part.slice(i + 2)); else out.push(part);
    }
  }
  return out.map(clean).map(s => s.replace(/[.!…]+$/, '').trim()).filter(Boolean);
}

function scoreSentence(s) {
  const words = s.split(/\s+/);
  const why = [];
  let score = 0;
  if (words.length < 5 || words.length > 45) return { score: -1, why };
  if (/\?$/.test(s) || CALL_TO_ACTION.test(s)) return { score: -1, why };
  if (DATE_RE.test(s)) { score += 2; why.push('date'); }
  else if (NUMBER_RE.test(s)) { score += 2; why.push('number'); }
  const verb = CLAIM_VERBS.exec(s); if (verb) { score += 3; why.push(`"${verb[0].toLowerCase()}"`); }
  // Named entities: capitalised words that do not start the sentence (shouting in ALL CAPS does not count)
  const names = words.slice(1).filter(w => /^[A-Z][a-z]+(?:[-'][A-Za-z]+)?[,.;:]?$/.test(w) && !STOP.has(w.toLowerCase().replace(/\W/g, '')));
  if (names.length) { score += Math.min(2, names.length); why.push('named entity'); }
  const personal = (s.match(FIRST_SECOND_PERSON) || []).length;
  if (personal) score -= Math.min(4, 2 * personal); // personal anecdotes are rarely fact-checkable
  return { score, why };
}

// Short keyword query: the API matches claim text, and long sentences full of filler return nothing.
function toQuery(claim) {
  const kept = claim.replace(/[“”"'’]/g, '').split(/[^\p{L}\p{N}%$€£]+/u).filter(w => w && !STOP.has(w.toLowerCase()) && !HYPE.test(w));
  return kept.slice(0, 10).join(' ').toLowerCase();
}

function extractClaims(text, max = 3) {
  const seen = new Set();
  return sentences(text)
    .map((s, i) => ({ text: s.slice(0, 240), i, ...scoreSentence(s) }))
    .filter(c => c.score >= 3)
    .sort((a, b) => b.score - a.score || a.i - b.i)
    .filter(c => { const q = toQuery(c.text); if (!q || seen.has(q)) return false; seen.add(q); c.query = q; return true; })
    .slice(0, max)
    .map(c => ({ text: c.text, query: c.query, why: c.why, explorerUrl: EXPLORER + encodeURIComponent(c.query) }));
}

// ---------- API response parsing ----------
const httpUrl = u => (/^https?:\/\//i.test(String(u || '')) ? String(u) : null);
const str = (v, n = 300) => (v == null ? '' : String(v).slice(0, n));

function parseClaimSearch(json) {
  if (!json || typeof json !== 'object') return [];
  return (Array.isArray(json.claims) ? json.claims : []).slice(0, 10).map(c => ({
    text: str(c.text, 500),
    claimant: str(c.claimant, 120),
    claimDate: str(c.claimDate, 40),
    reviews: (Array.isArray(c.claimReview) ? c.claimReview : []).map(r => ({
      publisher: str(r.publisher?.name || r.publisher?.site || 'Unknown publisher', 120),
      site: str(r.publisher?.site, 120),
      url: httpUrl(r.url),
      title: str(r.title, 300),
      reviewDate: str(r.reviewDate, 40),
      rating: str(r.textualRating, 120),
      languageCode: str(r.languageCode, 12),
    })).filter(r => r.url),
  })).filter(c => c.reviews.length);
}

function parseApiError(json, status) {
  const e = json && json.error;
  return e ? `Fact Check Tools API: ${str(e.message || e.status, 200)} (HTTP ${e.code || status})` : `Fact Check Tools API HTTP ${status}`;
}

// ---------- Lookup ----------
async function searchClaim(query, { key = KEY, fetchImpl = fetch, guard = assertPublicUrl, languageCode } = {}) {
  const ck = `${languageCode || ''}|${query}`;
  const hit = cache.get(ck); if (hit && Date.now() - hit.at < CACHE_MS) return hit.value;
  const u = new URL(ENDPOINT);
  u.searchParams.set('query', query.slice(0, 200));
  u.searchParams.set('pageSize', '5');
  if (languageCode && /^[a-z]{2}(-[A-Z]{2})?$/.test(languageCode)) u.searchParams.set('languageCode', languageCode);
  await guard(u.href); // fixed Google endpoint, still checked like every outbound fetch
  // Key goes in a header, not the URL, so it never appears in logs or error messages.
  const r = await fetchImpl(u.href, { headers: { 'X-Goog-Api-Key': key, Accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(10000) });
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error(parseApiError(j, r.status));
  const value = parseClaimSearch(j);
  cache.set(ck, { at: Date.now(), value });
  if (cache.size > 500) cache.delete(cache.keys().next().value);
  return value;
}

async function lookup(body = {}, opts = {}) {
  const key = opts.key !== undefined ? opts.key : KEY;
  const claims = extractClaims(String(body.text || '').slice(0, 12000));
  if (!key) return { available: false, service: 'Google Fact Check Explorer (manual)', claims };
  const out = await Promise.all(claims.map(async c => {
    try { return { ...c, matches: await searchClaim(c.query, { ...opts, key, languageCode: body.languageCode }) }; }
    catch (e) { return { ...c, matches: [], error: e.cause?.code ? `Fact Check Tools API unreachable (${e.cause.code})` : e.message }; }
  }));
  return { available: true, service: 'Google Fact Check Tools API', claims: out };
}

// ---------- Case-file sections for the agent team ----------
function caseFileSections(c = {}) {
  const parts = [];
  const fc = c.factchecks;
  if (fc && Array.isArray(fc.claims) && fc.claims.length) {
    const lines = fc.claims.map((cl, i) => {
      const head = `${i + 1}. CLAIM: "${str(cl.text, 240)}"`;
      if (!fc.available) return `${head}\n   Not searched automatically (no API key). Investigator can check Google Fact Check Explorer.`;
      if (cl.error) return `${head}\n   Lookup failed: ${str(cl.error, 160)}`;
      if (!(cl.matches || []).length) return `${head}\n   No published fact-check found by search. Absence of a fact-check is not evidence either way.`;
      return `${head}\n` + cl.matches.slice(0, 3).map(m => m.reviews.slice(0, 2).map(r => `   - ${r.publisher} rated "${str(m.text, 160)}" as "${r.rating}"${r.reviewDate ? ` (${r.reviewDate.slice(0, 10)})` : ''} ${r.url}`).join('\n')).join('\n');
    });
    parts.push(`PRIOR FACT-CHECKS (${fc.available ? 'Google Fact Check Tools claims:search, ClaimReview' : 'claims extracted locally, not searched'}; search matches may be a different claim, confirm before relying on them):\n${lines.join('\n')}`);
  }
  const sim = c.similar;
  if (Array.isArray(sim) && sim.length) {
    parts.push(`SIMILAR EARLIER CASES (local template match, word 5-gram Jaccard similarity; links to a reused script, not proof of the same sender):\n${sim.slice(0, 5).map(s => `- ${Math.round(s.similarity * 100)}% similar to a case from ${str(s.at, 10)} judged "${str(s.verdict, 40)}"${s.platform ? ` on ${str(s.platform, 30)}` : ''}: "${str(s.snippet, 120)}"`).join('\n')}`);
  }
  return parts.join('\n\n');
}

const routes = { '/api/factcheck': b => lookup(b) };

module.exports = { routes, extractClaims, toQuery, sentences, parseClaimSearch, parseApiError, searchClaim, lookup, caseFileSections, available: () => !!KEY, EXPLORER };
