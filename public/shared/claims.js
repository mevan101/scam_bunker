// Shared between server/factcheck.js and the browser (GitHub Pages / static mode): explainable claim extraction and
// the Google Fact Check Explorer deep link. One implementation, so both modes extract the same claims.
// No dependencies; UMD-style export.
(function (root) {
'use strict';
const EXPLORER = 'https://toolbox.google.com/factcheck/explorer/search/';

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

const DENIAL = /\b(not|no|never|false|fake|myth|hoax|debunked|untrue|lies?|isn't|wasn't|aren't)\b/i;
const NEGATION = /\b(not|no|never|cannot)\b|n't\b/i;

function sentences(text) {
  const out = [];
  for (const line of String(text || '').split(/\n+/)) {
    for (const part of line.split(/(?<=[.!?…])\s+|(?<=[!?]{2})(?=\S)/)) {
      // "Doctors don't want you to know this: <claim>" → keep the claim after the colon when it is substantial,
      // unless the lead-in denies it ("It is a hoax that: …"); a call to action ("Share, not their lies: …") is still split off
      const i = part.indexOf(': ');
      if (i > 0 && (CALL_TO_ACTION.test(clean(part.slice(0, i))) || !DENIAL.test(part.slice(0, i))) && part.slice(i + 2).split(/\s+/).length >= 5) out.push(part.slice(0, i), part.slice(i + 2)); else out.push(part);
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

// Cuts at n UTF-16 units without leaving half of a surrogate pair (which encodeURIComponent rejects).
function cut(s, n) { s = String(s); if (s.length <= n) return s; const c = s.charCodeAt(n - 1); return s.slice(0, c >= 0xd800 && c <= 0xdbff ? n - 1 : n); }

function extractClaims(text, max = 3) {
  const seen = new Set();
  return sentences(text)
    .map((s, i) => ({ text: cut(s, 240), i, ...scoreSentence(s) }))
    .filter(c => c.score >= 3)
    .sort((a, b) => b.score - a.score || a.i - b.i)
    .filter(c => { const q = toQuery(c.text), key = q + (NEGATION.test(c.text) ? '|neg' : ''); if (!q || seen.has(key)) return false; seen.add(key); c.query = q; return true; })
    .slice(0, max)
    .map(c => ({ text: c.text, query: c.query, why: c.why, explorerUrl: EXPLORER + encodeURIComponent(c.query) }));
}

// Case-file sections for the agents and the Claude handoff (server prompt and browser prompt use the same text).
const str = (v, n = 300) => (v == null ? '' : cut(v, n));
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
    parts.push(`SIMILAR EARLIER CASES (local template match, word 5-gram Jaccard similarity; links to a reused script, not proof of the same sender; earlier case text stays on the investigator's device):\n${sim.slice(0, 5).map(s => `- ${Math.round(s.similarity * 100)}% similar to a case from ${str(s.at, 10)} judged "${str(s.verdict, 40)}"${s.platform ? ` on ${str(s.platform, 30)}` : ''}`).join('\n')}`);
  }
  return parts.join('\n\n');
}

const api = { EXPLORER, extractClaims, toQuery, sentences, scoreSentence, caseFileSections, cut };
if (typeof module === 'object' && module.exports) module.exports = api;
else root.ScamBunkerClaims = api;
})(typeof window !== 'undefined' ? window : globalThis);
