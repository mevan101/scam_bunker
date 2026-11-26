// Scam Bunker — evidence grading, estimative verdict language and the verification checklist.
// Implements docs/METHODOLOGY.md section 3 and BACKLOG (iii) P1-1, P1-2, P1-3, P2-4:
//  - Admiralty grade per evidence item (source reliability A-F, information credibility 1-6) with analyst override
//  - ICD 203 likelihood term + analytic confidence, combined under the rules of METHODOLOGY 3.4
//  - First Draft five-pillar checklist (provenance, source, date, location, motivation)
//  - "What would change this verdict" and limitations
// The pure functions are exported on window.ScamBunkerGrading and tested under node's vm (test/grading.test.js).
// The UI only boots when window.ScamBunker exists.
(function () {
  const SOURCE = { A: 'Completely reliable', B: 'Usually reliable', C: 'Fairly reliable', D: 'Not usually reliable', E: 'Unreliable', F: 'Reliability cannot be judged' };
  const CREDIBILITY = { 1: 'Confirmed by other sources', 2: 'Probably true', 3: 'Possibly true', 4: 'Doubtful', 5: 'Improbable', 6: 'Truth cannot be judged' };
  const TERMS = ['Almost no chance', 'Very unlikely', 'Unlikely', 'Roughly even chance', 'Likely', 'Very likely', 'Almost certain'];
  const RANGES = { 'Almost no chance': '1–5 %', 'Very unlikely': '5–20 %', 'Unlikely': '20–45 %', 'Roughly even chance': '45–55 %', 'Likely': '55–80 %', 'Very likely': '80–95 %', 'Almost certain': '95–99 %' };
  const CONFIDENCE = ['low', 'moderate', 'high'];
  // Engine label → default Admiralty pair (METHODOLOGY 3.1 mapping; conservative end of each range).
  // Credibility 1 means "confirmed by other independent sources", so no single automated item defaults to it.
  const DEFAULTS = { proof: 'B2', strong: 'B3', moderate: 'C3', weak: 'C4' };
  // Categories whose signals are generic (METHODOLOGY 3.4): they never justify "likely scam" on their own.
  const GENERIC = new Set(['Pressure', 'Payment rails', 'Off-platform move', 'Manipulation / misinformation', 'Engagement bait', 'Impersonation']);
  const SCAM_VERDICTS = new Set(['Scam', 'Likely scam']);
  const PILLARS = [
    { id: 'provenance', name: 'Provenance', q: 'Is this the original piece of content?' },
    { id: 'source', name: 'Source', q: 'Who created it (the capturer), and who is sharing this copy (the poster)?' },
    { id: 'date', name: 'Date', q: 'When was it created?' },
    { id: 'location', name: 'Location', q: 'Where was it created?' },
    { id: 'motivation', name: 'Motivation', q: 'Why was it created or shared? Record only what the content observably asks for. Do not infer a person\'s motive.' },
  ];
  const STATUSES = ['not started', 'partial', 'done', 'not possible'];

  const parseGrade = g => { const m = /^\s*([A-F])\s*-?\s*([1-6])\s*$/i.exec(String(g ?? '')); return m ? { sourceGrade: m[1].toUpperCase(), credibility: +m[2] } : null; };
  const fmt = g => g.sourceGrade + g.credibility;
  const keyOf = o => `${o.fact ?? ''}|${o.inference ?? ''}`.slice(0, 300);
  const weightOf = o => ['proof', 'strong', 'moderate', 'weak'].includes(o.weight) ? o.weight : 'weak';
  const isStrong = i => i.weight === 'proof' || i.weight === 'strong';
  const counted = items => items.filter(i => i.kind !== 'none');

  // Where an observation came from: its kind, its root cause (signals sharing a root are not independent),
  // its source (for "confirmed" the two items must come from different sources) and whether it is scheme-specific.
  function classify(o, c) {
    const h = (c && c.heuristics) || { hits: [], links: [], entities: { wallets: [] } }, f = c && c.forensics;
    const w = weightOf(o);
    if (o.provenance) return { kind: 'provenance', root: 'provenance:' + o.inference, source: 'provenance trace', scheme: false, weight: w };
    if (o.fact === 'No pattern matched') return { kind: 'none', root: 'none', source: 'none', scheme: false, weight: 'weak' };
    const hit = (h.hits || []).find(x => x.label === o.inference && `“${x.match}”` === o.fact);
    if (hit) return { kind: 'text', category: hit.category, root: 'text:' + hit.category, source: 'message', scheme: !GENERIC.has(hit.category), weight: w };
    const link = (h.links || []).find(l => (l.host || l.url) === o.fact);
    if (link) return { kind: 'link', category: 'Phishing', root: 'link:' + (link.host || link.url), source: 'message', scheme: w === 'strong', weight: w };
    if (/ wallet /.test(o.fact || '') && /^Payment demanded/.test(o.inference || '')) return { kind: 'wallet', category: 'Payment rails', root: 'text:Payment rails', source: 'message', scheme: false, weight: w };
    if (o.fact === 'Text pattern') return { kind: 'coordination', root: 'coordination', source: 'message', scheme: false, weight: w };
    if (o.fact === 'Image metadata') {
      const proof = f && f.ai && (f.ai.signals || []).some(s => s.label === o.inference && s.strength === 'proof');
      return { kind: 'image-meta', root: 'file:ai-declaration', source: 'image file', scheme: false, weight: proof ? 'proof' : w };
    }
    if (o.fact === 'Image pixels / dimensions') return { kind: 'detector', root: 'file:statistics', source: 'image file', scheme: false, detector: true, weight: w };
    if (/^Software: /.test(o.fact || '')) return { kind: 'image-editor', root: 'file:editor', source: 'image file', scheme: false, weight: w };
    const off = (c && c.offenders || []).find(x => x.label === o.fact);
    if (off) {
      const confirmedBefore = off.cases.some(p => SCAM_VERDICTS.has(p.verdict)) && ['wallet', 'phone', 'email', 'domain', 'image'].includes(off.type);
      return { kind: 'offender', root: 'offender:' + off.key, source: 'case index', scheme: confirmedBefore, weight: confirmedBefore ? 'proof' : w };
    }
    const src = String(o.source || '').trim().toLowerCase().slice(0, 60) || 'agent reports';
    return { kind: 'agent', root: 'agent:' + src + ':' + keyOf(o), source: src, scheme: isStrong({ weight: w }) && !/urgen|pressure|brand|crypto vocab/i.test(o.inference || ''), detector: /\b(ela|error[- ]level|detector|noise statistic)/i.test(`${o.fact} ${o.inference}`), weight: w };
  }

  // Grade every observation. Order of precedence: analyst override > agent-supplied grade > default for the engine label.
  // Statistical detectors used alone are capped at C3 (METHODOLOGY 3.4), whoever graded them.
  function gradeItems(obs, c, overrides = {}) {
    const used = new Set();
    const items = (obs || []).map(o => {
      const base = keyOf(o); let key = base;
      for (let n = 1; used.has(key); n++) key = `${base}#${n}`;
      used.add(key);
      const m = classify(o, c);
      const agent = parseGrade(o.agentGrade) || (o.gradeBy === undefined ? parseGrade(o.grade) || (o.sourceGrade && o.credibility ? parseGrade(o.sourceGrade + o.credibility) : null) : null);
      if (agent && o.agentGrade === undefined) o.agentGrade = fmt(agent);
      const ov = parseGrade(overrides[key]);
      const g = ov || agent || (m.kind === 'none' ? { sourceGrade: 'F', credibility: 6 } : parseGrade(DEFAULTS[m.weight]));
      return { o, key, ...m, ...g, by: ov ? 'analyst' : agent ? 'agent' : 'default', capped: false };
    });
    const corroborated = i => items.some(j => j !== i && !j.detector && j.kind !== 'none' && j.root !== i.root && j.credibility <= 3);
    items.forEach(i => {
      if (i.detector && !corroborated(i) && (i.sourceGrade < 'C' || i.credibility < 3)) { i.sourceGrade = i.sourceGrade < 'C' ? 'C' : i.sourceGrade; i.credibility = Math.max(3, i.credibility); i.capped = true; }
      i.grade = fmt(i);
    });
    return items;
  }

  // "Confirmed" needs two or more independent items graded 1 or 2, from different sources (METHODOLOGY 3.4, BACKLOG P1-2).
  function isConfirmed(items, about = () => true) {
    const good = counted(items).filter(i => i.credibility <= 2 && about(i));
    for (const a of good) for (const b of good) if (a.source !== b.source && a.root !== b.root) return true;
    return false;
  }
  const roots = items => new Set(items.map(i => i.root));
  const minTerm = (a, b) => TERMS[Math.min(TERMS.indexOf(a), TERMS.indexOf(b))];

  function analyticConfidence(items) {
    const it = counted(items);
    if (!it.length) return 'low';
    const good = it.filter(i => i.sourceGrade <= 'C' && i.credibility <= 3 && i.weight !== 'weak');
    const fromScammer = it.filter(i => i.sourceGrade === 'E').length * 2 > it.length;
    if (fromScammer) return 'low';
    const goodRoots = roots(good).size, goodSources = new Set(good.map(i => i.source)).size;
    if (goodRoots >= 3 && goodSources >= 2) return 'high';
    if (goodRoots >= 2 || good.some(isStrong)) return 'moderate';
    return 'low';
  }

  const BASE = { 'Scam': 'Very likely', 'Likely scam': 'Likely', 'Suspicious': 'Roughly even chance', 'AI-generated content': 'Likely', 'Edited image': 'Likely', 'Misleading / manipulated': 'Likely', 'Coordinated / inauthentic': 'Likely', 'Likely legitimate': 'Likely' };
  const SCHEMES = /^(phishing|investment \/ crypto|romance \/ pig-butchering|job \/ recruitment|giveaway \/ prize|advance-fee|tech support|recovery scam|marketplace|task|sextortion|toll|parcel)/i;
  function noun(verdict, category) {
    if (SCAM_VERDICTS.has(verdict) || verdict === 'Suspicious') {
      const cat = String(category || '').trim();
      if (!SCHEMES.test(cat)) return verdict === 'Suspicious' && /\b(ai|synthetic|generat\w*)\b/i.test(cat) ? 'AI-generated' : verdict === 'Suspicious' && /image|metadata|edit/i.test(cat) ? 'manipulated' : 'a scam';
      const t = cat.toLowerCase().replace(/\s+scam$/, '');
      return `${/^[aeiou]/.test(t) ? 'an' : 'a'} ${t} scam`;
    }
    return { 'AI-generated content': 'AI-generated', 'Edited image': 'an edited image', 'Misleading / manipulated': 'misleading or manipulated', 'Coordinated / inauthentic': 'coordinated inauthentic activity', 'Likely legitimate': 'legitimate' }[verdict] || 'a scam';
  }
  function phrase(term, n) {
    if (term === 'Roughly even chance' || term === 'Almost no chance') return `${term} that this is ${n}`;
    if (term === 'Unlikely' || term === 'Very unlikely') return `${term} to be ${n}`;
    return `${term} ${n}`;
  }

  // Likelihood term + analytic confidence for a verdict object, applying the combination rules of METHODOLOGY 3.4.
  function estimate(v, items) {
    const it = counted(items), notes = [];
    // A strong label only counts while its credibility is at least "possibly true" (an analyst can grade it down).
    const IMAGE = new Set(['image-meta', 'detector', 'image-editor']);
    const strong = it.filter(i => isStrong(i) && i.credibility <= 3 && !(SCAM_VERDICTS.has(v.verdict) && IMAGE.has(i.kind)));
    const strongRoots = roots(strong).size;
    const schemeStrong = strong.some(i => i.scheme);
    const confirmed = isConfirmed(items);
    const dup = it.length - roots(it).size;
    if (dup > 0) notes.push(`${it.length} evidence items share ${roots(it).size} independent root causes; repeated signals of the same kind are counted once.`);
    let term = BASE[v.verdict] || null;
    const agentTerm = TERMS.find(t => t.toLowerCase() === String(v.likelihood_raw ?? v.likelihood ?? '').trim().toLowerCase());
    if (term && agentTerm && v.verdict !== 'Likely legitimate') {
      const t = minTerm(term, agentTerm);
      if (t !== term) notes.push(`The lead investigator's own estimate (${agentTerm}) is more cautious than the verdict label; the more cautious term is used.`);
      term = t;
    }
    if (term && SCAM_VERDICTS.has(v.verdict)) {
      if (!schemeStrong && TERMS.indexOf(term) > TERMS.indexOf('Roughly even chance')) { term = 'Roughly even chance'; notes.push('Capped at "roughly even chance": no strong, scheme-specific signal. Generic signals (urgency, a brand name, crypto vocabulary) cannot justify "likely scam" on their own.'); }
      if (term === 'Very likely' && strongRoots < 2) { term = 'Likely'; notes.push('Capped at "likely": "very likely" needs at least two independent strong signals.'); }
      if (term === 'Very likely' && v.verdict === 'Scam' && confirmed && strongRoots >= 3) { term = 'Almost certain'; notes.push('Raised to "almost certain": confirmed by independent, well-graded evidence from different sources.'); }
    } else if (term && v.verdict !== 'Likely legitimate') {
      const usable = it.filter(i => !i.detector && i.weight !== 'weak');
      if (!usable.length && TERMS.indexOf(term) > TERMS.indexOf('Roughly even chance')) { term = 'Roughly even chance'; notes.push('Capped at "roughly even chance": the only evidence is weak or comes from statistical detectors, which are leads, not proof.'); }
    }
    let conf = analyticConfidence(items);
    const agentConf = CONFIDENCE.find(x => x === String(v.analytic_confidence_raw ?? '').trim().toLowerCase());
    if (agentConf && CONFIDENCE.indexOf(agentConf) < CONFIDENCE.indexOf(conf)) { conf = agentConf; notes.push(`Analytic confidence lowered to "${conf}" to match the lead investigator's own assessment.`); }
    if (!confirmed) notes.push('Nothing here is "confirmed": that needs two or more independent items graded 1 or 2 from different sources.');
    const label = term ? `${phrase(term, noun(v.verdict, v.category))} (${conf} confidence)`
      : v.verdict === 'Insufficient evidence' ? `Insufficient evidence for an estimate (${conf} confidence)`
        : `No known scam pattern matched. This is not a statement that it is safe (${conf} confidence)`;
    return { likelihood: term, range: term ? RANGES[term] : null, analytic_confidence: conf, label, confirmed, notes };
  }

  // Items that bear on AI involvement: only these can confirm it.
  const aboutAI = i => i.kind === 'image-meta' || i.kind === 'detector' || (i.kind === 'agent' && /\b(ai|a\.i\.|generat\w*|synthetic|c2pa|content credentials|diffusion|midjourney|dall-?e|dall·e|deepfake|comfyui|flux|firefly|imagen|gemini|ideogram|leonardo|novelai|sora|runway|grok|bing image creator|microsoft designer|gpt[- ]?image)\b/i.test(`${i.o.fact} ${i.o.inference}`));

  // Nothing may be labelled "confirmed" without passing isConfirmed (BACKLOG P1-2). Reversible: the raw value is kept.
  function enforceConfirmed(v, confirmed) {
    const ai = v.ai_involvement; if (!ai) return;
    if (ai.assessment_raw === undefined) ai.assessment_raw = ai.assessment;
    if (ai.basis_raw === undefined) ai.basis_raw = ai.basis;
    if (ai.assessment_raw === 'confirmed' && !confirmed) { ai.assessment = 'likely'; ai.basis = `${ai.basis_raw} (shown as "likely": "confirmed" needs two independent items graded 1 or 2 from different sources)`; }
    else { ai.assessment = ai.assessment_raw; ai.basis = ai.basis_raw; }
  }

  const clean = a => (Array.isArray(a) ? a : []).filter(x => typeof x === 'string' && x.trim()).map(x => x.trim().slice(0, 400)).slice(0, 8);
  function limitations(c, v, items) {
    const L = [], h = c.heuristics || { links: [], entities: { wallets: [], handles: [] } }, f = c.forensics, it = counted(items);
    if (c.text) L.push('The text was analysed as pasted. The engine cannot see the sender\'s account, its history or the rest of the conversation.');
    if (!c.final) L.push('No specialist agent reviewed this case; the verdict comes from local rules only.');
    if (it.length && new Set(it.map(i => i.source)).size === 1) L.push(`All evidence comes from a single source (${it[0].source}); none of it has been independently corroborated.`);
    if (!it.length) L.push('No pattern matched. Absence of evidence is not evidence that the content is legitimate.');
    if (f && !Object.keys(f.exif || {}).length) L.push('The image metadata was stripped, so the file alone cannot establish when, where or on what device it was captured.');
    if (it.some(i => i.detector)) L.push('AI-image and error-level statistics are investigative leads, not calibrated probabilities.');
    if (f && f.c2pa) L.push('Content Credentials were detected but their signatures were not validated.');
    if (c.url && !(c.page && !c.page.error)) L.push('The linked page was not fetched, so its content was not examined.');
    if ((h.links || []).length || (h.entities?.wallets || []).length) L.push('No external lookups (domain registration age, archive history, blockchain activity) were run as part of this verdict.');
    if ((c.offenders || []).length) L.push('Repeat-offender links compare only against your own saved cases on this device.');
    if (!c.provenance && f) L.push('The image has not been traced to its original copy (Provenance tab).');
    return [...new Set([...clean(v.limitations_raw ?? v.limitations), ...L])].slice(0, 10);
  }
  function wouldChange(c, v, items) {
    const W = [], h = c.heuristics || { links: [], entities: { wallets: [], handles: [] } }, f = c.forensics;
    const scammy = SCAM_VERDICTS.has(v.verdict) || v.verdict === 'Suspicious';
    if (scammy) {
      W.push('The sender is verified through a channel you already trust (an official website or a number you already had) and confirms the request.');
      if ((h.links || []).some(l => l.host)) W.push('Domain registration and archive history show a long-established owner matching the organisation named.');
      if ((h.entities?.wallets || []).length) W.push('The wallet turns out to belong to a known exchange deposit service or a legitimate merchant (it would then link payments, not a scheme).');
      if ((c.offenders || []).length) W.push('The earlier cases sharing this identifier were themselves mislabelled, or the identifier was spoofed.');
    } else {
      W.push('A later message asks for money, codes, credentials or a move to another app.');
      if ((h.links || []).some(l => l.host)) W.push('The linked domain turns out to be days old or listed in a phishing feed.');
    }
    if (f) W.push('An earlier copy of the image is found in a different context, or the original file with intact metadata is obtained.');
    if (v.ai_involvement && v.ai_involvement.assessment_raw && v.ai_involvement.assessment_raw !== 'none detected') W.push('A validated Content Credentials manifest or the original camera file shows a different origin.');
    if (estimateCache.get(v)?.confirmed === false) W.push('Two independent sources, graded 1 or 2, corroborate the central finding (it would then count as confirmed).');
    return [...new Set([...clean(v.would_change_if_raw ?? v.would_change_if), ...W])].slice(0, 10);
  }
  const estimateCache = new WeakMap();

  // Automated pre-fill for the five pillars. Never marks a pillar "done": only the analyst can.
  function prefill(c, v, items) {
    const f = c.forensics, h = c.heuristics || { links: [], hits: [], entities: { handles: [], phones: [], wallets: [] } };
    const P = {};
    const ev = [], put = (id, status, evidence, hint) => { P[id] = { status, evidence, hint }; };
    ev.length = 0;
    const prov = [];
    if (f && f.sha256) prov.push(`SHA-256 of the file as received: ${f.sha256.slice(0, 16)}…`);
    if (f && f.c2pa) prov.push('Content Credentials present (not validated)');
    if (c.provenance && c.provenance.verdict && c.provenance.verdict.summary) prov.push('Provenance trace: ' + c.provenance.verdict.summary);
    (c.offenders || []).forEach(o => prov.push(`${o.label} appeared in ${o.cases.length} earlier case${o.cases.length > 1 ? 's' : ''}`));
    if (h.coordination && h.coordination.length) prov.push('Templated text: ' + h.coordination[0]);
    put('provenance', c.provenance && c.provenance.verdict ? 'partial' : prov.length > 1 || (c.offenders || []).length ? 'partial' : 'not started', prov,
      f ? 'Reverse-search the image (oldest first) and use the Provenance tab to compare copies.' : 'Search for the text in quotes and in existing fact-checks to see whether it is a known template.');
    const src = [];
    if (c.platform) src.push('Platform: ' + c.platform);
    (h.links || []).filter(l => l.host).slice(0, 3).forEach(l => src.push(`Link host ${l.host} (structural risk ${l.risk})`));
    if ((h.entities.handles || []).length) src.push(`${h.entities.handles.length} handle${h.entities.handles.length > 1 ? 's' : ''} in the content: ${h.entities.handles.slice(0, 3).join(', ')}`);
    if (f && (f.exif?.Make || f.exif?.Model)) src.push(`Camera: ${[f.exif.Make, f.exif.Model].filter(Boolean).join(' ')}`);
    put('source', src.length ? 'partial' : 'not started', src, 'Read laterally: check account age, domain registration (RDAP) and what independent sources say about the sender. Separate the capturer from the poster.');
    const date = [];
    if (f && f.exif && f.exif.DateTimeOriginal) date.push(`EXIF DateTimeOriginal: ${f.exif.DateTimeOriginal}`);
    if (f && f.earliest) date.push(`Earliest firm timestamp: ${String(f.earliest.when).replace('T', ' ')} (${f.earliest.src})`);
    if (c.provenance && c.provenance.verdict && c.provenance.verdict.earliest) date.push(`Earliest evidence of existence: ${String(c.provenance.verdict.earliest.date).slice(0, 10)} (${c.provenance.verdict.earliest.source})`);
    put('date', date.length ? 'partial' : 'not started', date, f ? 'Find the earliest indexed copy (TinEye, sort by oldest) and archive captures.' : 'Find when this text or account first appeared (search, archive captures).');
    const loc = [];
    if (f && f.exif && f.exif.GPSDecimal) loc.push('GPS coordinates are embedded in the file (see Image lab)');
    if (f && f.xmpFields && (f.xmpFields['photoshop:City'] || f.xmpFields['photoshop:Country'])) loc.push(`XMP place fields: ${[f.xmpFields['photoshop:City'], f.xmpFields['photoshop:Country']].filter(Boolean).join(', ')}`);
    put('location', loc.length ? 'partial' : 'not started', loc, f ? 'Geolocate landmarks, signs and terrain, then check shadows and weather for the claimed date.' : 'If the content claims a place, check it against maps and independent reports.');
    const mot = (h.hits || []).filter(x => ['Payment rails', 'Off-platform move', 'Engagement bait', 'Pressure'].includes(x.category)).slice(0, 4).map(x => `Asks: ${x.label}`);
    if ((h.entities.wallets || []).length) mot.push('Asks for payment to a crypto address');
    put('motivation', 'not started', mot, 'Record what the content asks the reader to do (pay, click, share, move apps). That is observable; a person\'s motive is not.');
    return P;
  }

  // Grade the verdict in place, compute the estimative label, the checklist and the report lines. Idempotent.
  function apply(c, state = {}) {
    const v = c && (c.final || c.local); if (!v) return null;
    if (v.likelihood_raw === undefined) v.likelihood_raw = v.likelihood ?? null;
    if (v.analytic_confidence_raw === undefined) v.analytic_confidence_raw = v.analytic_confidence ?? null;
    if (v.limitations_raw === undefined) v.limitations_raw = clean(v.limitations);
    if (v.would_change_if_raw === undefined) v.would_change_if_raw = clean(v.would_change_if);
    const items = gradeItems(v.observations, c, state.overrides || {});
    items.forEach(i => Object.assign(i.o, { grade: i.grade, sourceGrade: i.sourceGrade, credibility: i.credibility, gradeBy: i.by, gradeMeaning: `${SOURCE[i.sourceGrade]}; ${CREDIBILITY[i.credibility].toLowerCase()}`, source: i.source }));
    const est = estimate(v, items);
    estimateCache.set(v, est);
    enforceConfirmed(v, isConfirmed(items, aboutAI));
    Object.assign(v, { likelihood: est.likelihood, analytic_confidence: est.analytic_confidence, estimative: est.label });
    v.limitations = limitations(c, v, items);
    v.would_change_if = wouldChange(c, v, items);
    const auto = prefill(c, v, items), saved = state.pillars || {};
    const checklist = PILLARS.map(p => {
      const s = saved[p.id] || {};
      const attached = (s.attached || []).map(k => items.find(i => i.key === k)).filter(Boolean);
      return { ...p, status: STATUSES.includes(s.status) ? s.status : auto[p.id].status, statusBy: STATUSES.includes(s.status) ? 'analyst' : 'automatic', evidence: auto[p.id].evidence, hint: auto[p.id].hint, attached, note: String(s.note || '').slice(0, 2000) };
    });
    c.grading = { items, estimate: est, checklist, reportLines: reportLines(v, est, checklist) };
    return c.grading;
  }

  function reportLines(v, est, checklist) {
    const L = ['\nESTIMATIVE ASSESSMENT (ICD 203 scale; Admiralty grades on each evidence line: source reliability A-F, information credibility 1-6)', est.label];
    if (est.likelihood) L.push(`"${est.likelihood}" means ${est.range}. Analytic confidence: ${est.analytic_confidence}.`);
    est.notes.forEach(n => L.push('- ' + n));
    L.push('\nVERIFICATION CHECKLIST (First Draft five pillars)');
    checklist.forEach(p => {
      L.push(`- ${p.name}: ${p.status}${p.statusBy === 'analyst' ? ' (set by analyst)' : ''}`);
      p.evidence.forEach(e => L.push(`    · ${e}`));
      p.attached.forEach(i => L.push(`    · [${i.grade}] ${i.o.fact} → ${i.o.inference}`));
      if (p.note) L.push(`    Note: ${p.note}`);
    });
    L.push('\nLIMITATIONS', ...(v.limitations || []).map(x => '- ' + x));
    L.push('\nWHAT WOULD CHANGE THIS VERDICT', ...(v.would_change_if || []).map(x => '- ' + x));
    return L;
  }

  const api = { SOURCE, CREDIBILITY, TERMS, RANGES, DEFAULTS, PILLARS, STATUSES, parseGrade, keyOf, classify, gradeItems, isConfirmed, analyticConfidence, estimate, enforceConfirmed, limitations, wouldChange, prefill, apply, reportLines, noun, phrase };
  if (typeof window !== 'undefined') window.ScamBunkerGrading = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof document === 'undefined' || typeof window === 'undefined' || !window.ScamBunker) return;

  // ======================= UI =======================
  const SB = window.ScamBunker, esc = SB.esc, $ = s => document.querySelector(s);
  const KEY = 'scambunker.grading';
  const loadAll = () => SB.store.get(KEY, {});
  const stateFor = id => (loadAll()[id] || { overrides: {}, pillars: {} });
  function saveState(id, st) {
    const all = loadAll(); all[id] = { ...st, at: Date.now() };
    const ids = Object.keys(all).sort((a, b) => (all[b].at || 0) - (all[a].at || 0));
    ids.slice(200).forEach(k => delete all[k]);
    SB.store.set(KEY, all);
  }

  function sync(c, rerender = true) {
    if (!c) return;
    apply(c, stateFor(c.id));
    if (rerender) SB.renderAll();
    render(c);
  }

  const opt = (val, label, sel) => `<option value="${esc(val)}"${sel ? ' selected' : ''}>${esc(label)}</option>`;
  function render(c, focusId) {
    const p = $('[data-panel="checklist"]'); if (!p || !c || !c.grading) return;
    const g = c.grading, est = g.estimate, v = c.final || c.local;
    const pillars = g.checklist.map(x => `
      <fieldset class="box gr-pillar">
        <legend>${esc(x.name)}</legend>
        <p>${esc(x.q)}</p>
        <label class="field"><span>Status${x.statusBy === 'automatic' ? ' (pre-filled)' : ''}</span>
          <select id="gr-st-${x.id}" data-gr-status="${x.id}">${STATUSES.map(s => opt(s, s.charAt(0).toUpperCase() + s.slice(1), s === x.status)).join('')}</select></label>
        ${x.evidence.length ? `<div class="k">Found automatically</div><ul class="list">${x.evidence.map(e => `<li>${esc(e)}</li>`).join('')}</ul>` : `<p class="muted">Nothing found automatically. ${esc(x.hint)}</p>`}
        ${x.evidence.length ? `<p class="muted">Next: ${esc(x.hint)}</p>` : ''}
        ${g.items.some(i => i.kind !== 'none') ? `<details class="gr-attach"${x.attached.length ? ' open' : ''}><summary>Attach evidence (${x.attached.length})</summary>${g.items.filter(i => i.kind !== 'none').map((i, n) => `<label><input type="checkbox" data-gr-attach="${x.id}" data-key="${esc(i.key)}" id="gr-at-${x.id}-${n}"${x.attached.includes(i) ? ' checked' : ''}><span><b>${esc(i.grade)}</b> ${esc(i.o.inference || i.o.fact)}</span></label>`).join('')}</details>` : ''}
        <label class="field"><span>Note</span><textarea rows="2" id="gr-note-${x.id}" data-gr-note="${x.id}" placeholder="What you checked, where, and what you found">${esc(x.note)}</textarea></label>
      </fieldset>`).join('');
    const rows = g.items.map((i, n) => i.kind === 'none' ? '' : `
      <div class="ob gr-item">
        <div><span class="k">Observation</span><p>${esc(i.o.fact)}</p><span class="k">Inference</span><p>${esc(i.o.inference)}</p><p class="muted">Source: ${esc(i.source)}${i.capped ? ' · capped at C3: statistical detector used alone' : ''}</p></div>
        <div class="gr-sel">
          <label class="field"><span>Source reliability</span><select id="gr-s-${n}" data-gr-src="${esc(i.key)}">${Object.entries(SOURCE).map(([k, t]) => opt(k, `${k}: ${t}`, k === i.sourceGrade)).join('')}</select></label>
          <label class="field"><span>Information credibility</span><select id="gr-c-${n}" data-gr-cred="${esc(i.key)}">${Object.entries(CREDIBILITY).map(([k, t]) => opt(k, `${k}: ${t}`, +k === i.credibility)).join('')}</select></label>
        </div>
        <div class="gr-badges" style="display:flex;flex-wrap:wrap;gap:6px;align-items:center"><span class="tag">${esc(i.grade)}</span><span class="w ${esc(i.weight)}">${esc(i.weight)}</span><span class="muted">${i.by === 'analyst' ? 'Analyst override' : i.by === 'agent' ? 'Graded by agent' : 'Default for engine label'}</span>${i.by === 'analyst' ? `<button type="button" class="link" data-gr-reset="${esc(i.key)}" id="gr-r-${n}">Reset<span class="sr-only"> grade for item ${n + 1}</span></button>` : ''}</div>
      </div>`).join('');
    p.innerHTML = `
      <section><h3>Estimative verdict</h3>
        <div class="box"><div class="k">Assessment of the content, not of any person</div><div class="big" id="gr-label">${esc(est.label)}</div>
        <p>${est.likelihood ? `“${esc(est.likelihood)}” means ${esc(est.range)} on the ICD 203 scale.` : 'No likelihood term applies.'} Analytic confidence is <b>${esc(est.analytic_confidence)}</b>: ${{ high: 'several independent, well-graded items agree', moderate: 'credible but limited or single-source evidence', low: 'fragmentary, weakly graded or dependent on the sender\'s own claims' }[est.analytic_confidence]}.</p></div>
        ${est.notes.length ? `<ul class="list gr-notes">${est.notes.map(n => `<li>${esc(n)}</li>`).join('')}</ul>` : ''}
      </section>
      <section><h3>Verification checklist</h3><p class="muted">First Draft's five pillars. Statuses are pre-filled from the automated checks; only you can mark a pillar done.</p><div class="gr-pillars">${pillars}</div></section>
      <section><h3>Evidence grading</h3><p class="muted">Admiralty code: source reliability A (completely reliable) to F (cannot be judged), information credibility 1 (confirmed) to 6 (cannot be judged). Judge the two separately. Change a grade to override the default.</p><div class="obs">${rows || '<p class="empty">No evidence items to grade.</p>'}</div></section>
      <section><h3>Limitations</h3><ul class="list">${(v.limitations || []).map(x => `<li>${esc(x)}</li>`).join('')}</ul></section>
      <section><h3>What would change this verdict</h3><ul class="list">${(v.would_change_if || []).map(x => `<li>${esc(x)}</li>`).join('')}</ul></section>`;
    if (focusId && document.getElementById(focusId)) document.getElementById(focusId).focus();
  }

  function update(mut, focusId) {
    const c = SB.current; if (!c) return;
    const st = stateFor(c.id); st.overrides = st.overrides || {}; st.pillars = st.pillars || {};
    mut(st); saveState(c.id, st);
    apply(c, st); SB.renderAll(); render(c, focusId);
  }

  document.addEventListener('sb:case', e => sync(e.detail));
  document.addEventListener('sb:case-complete', e => sync(e.detail));
  document.addEventListener('sb:provenance', e => sync(e.detail));
  document.addEventListener('click', e => {
    if (e.target.closest('#history-list .hist')) { setTimeout(() => sync(SB.current), 0); return; }
    const r = e.target.closest('[data-gr-reset]');
    if (r) { const k = r.dataset.grReset; const n = r.id.replace('gr-r-', ''); update(st => { delete st.overrides[k]; }, 'gr-s-' + n); }
  });
  document.addEventListener('change', e => {
    const t = e.target, c = SB.current; if (!c || !c.grading || !t.closest('[data-panel="checklist"]')) return;
    if (t.dataset.grStatus) return update(st => { st.pillars[t.dataset.grStatus] = { ...st.pillars[t.dataset.grStatus], status: t.value }; }, t.id);
    if (t.dataset.grAttach) return update(st => { const p = st.pillars[t.dataset.grAttach] = { ...st.pillars[t.dataset.grAttach] }; const set = new Set(p.attached || []); t.checked ? set.add(t.dataset.key) : set.delete(t.dataset.key); p.attached = [...set]; }, t.id);
    const key = t.dataset.grSrc || t.dataset.grCred;
    if (key) {
      const it = c.grading.items.find(i => i.key === key); if (!it) return;
      const g = t.dataset.grSrc ? t.value + it.credibility : it.sourceGrade + t.value;
      update(st => { st.overrides[key] = g; }, t.id);
    }
  });
  document.addEventListener('input', e => {
    const t = e.target, c = SB.current; if (!c || !c.grading || !t.dataset.grNote) return;
    const st = stateFor(c.id); st.pillars = st.pillars || {}; st.pillars[t.dataset.grNote] = { ...st.pillars[t.dataset.grNote], note: t.value }; saveState(c.id, st);
    apply(c, st); // keeps the report lines current without re-rendering the field being typed in
  });

  if (SB.current) sync(SB.current);
})();
