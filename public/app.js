// Scam Bunker — orchestration & UI
(() => {
  const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const store = { get(k, d) { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } }, set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { } } };

  const DEFAULT_PERSONA = `Name of method: Consulting detective (Sherlock Holmes school).

Who I am: An independent investigator who debunks scams, false information and manipulated media for the public.

What I investigate:
- Scam posts and DMs on Facebook, Instagram, X/Twitter, LinkedIn, TikTok, Telegram and WhatsApp
- Fake recruiters, crypto "mentors", romance / pig-butchering operations, fake giveaways, brand impersonation
- Images: when were they really taken, are they AI-generated or edited, are they reused from older events
- Coordinated networks: accounts that post together, copy-paste comment rings, bot amplification

How I want you to work:
1. Observe before you infer. List exactly what is visible, then what it implies.
2. Separate PROOF from STRONG SIGNALS from WEAK HINTS. Never call something a scam without stating why.
3. "When you have eliminated the impossible, whatever remains, however improbable, must be the truth." Consider the innocent explanation and rule it in or out explicitly.
4. Always give me the next pivots: what to search, which tool, which account or wallet to trace.
5. Tell the potential victim, in plain words, what to do now.`;

  const AGENT_META = {
    heuristics: { name: 'Pattern Engine', role: 'local · rule-based', glyph: 'P', color: 'var(--blue)', bg: 'var(--blue-soft)' },
    metadata: { name: 'Metadata Engine', role: 'local · file forensics', glyph: 'M', color: 'var(--violet)', bg: 'var(--violet-soft)' },
    forensics: { name: 'Image Forensics', role: 'agent · vision + metadata', glyph: 'I', color: 'var(--violet)', bg: 'var(--violet-soft)' },
    scam: { name: 'Fraud Analyst', role: 'agent · scheme typing', glyph: 'F', color: 'var(--red)', bg: 'var(--red-soft)' },
    osint: { name: 'OSINT & Platform Analyst', role: 'agent · accounts & spread', glyph: 'O', color: 'var(--blue)', bg: 'var(--blue-soft)' },
    factcheck: { name: 'Fact Checker', role: 'agent · claims & sources', glyph: 'C', color: 'var(--green)', bg: 'var(--green-soft)' },
    lead: { name: 'The Lead Investigator', role: 'agent · cross-examination & verdict', glyph: 'H', color: 'var(--accent)', bg: 'var(--accent-soft)' },
  };

  const VERDICT_COLOR = { 'Scam': 'var(--red)', 'Likely scam': 'var(--red)', 'Suspicious': 'var(--amber)', 'Misleading / manipulated': 'var(--amber)', 'Coordinated / inauthentic': 'var(--violet)', 'AI-generated content': 'var(--violet)', 'Edited image': 'var(--amber)', 'Likely legitimate': 'var(--green)', 'No strong red flags': 'var(--green)', 'Insufficient evidence': 'var(--muted)' };

  const SAMPLES = {
    crypto: { platform: 'Instagram', url: 'https://instagram.com/coinbase.support_desk', text: `Hello dear 😊 sorry, I think I texted the wrong number... but you seem very kind. My uncle is an expert trader and he taught me how to earn 30% daily profit on USDT. It's guaranteed and risk-free, I already made $48,000 this month!\n\nIf you want I can be your mentor. Just download the app from https://coinbase-pro-wallet.xyz/login and deposit 500 USDT to start. Send to TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT\n\nAct now, only 3 spots left this week. Please don't tell anyone, keep it between us. Message me on WhatsApp +44 7700 900123` },
    job: { platform: 'LinkedIn', url: 'https://lnkd.in/eXq3Zt9', text: `Hi! I'm a recruiter at Amaz0n Global Talent. We reviewed your profile and you've been selected for a remote job — no experience required. Earn $350 per day reviewing products from home (task-based, 1-2 hours).\n\nTo activate your account you will need to pay a $95 training fee for the starter kit, refunded with your first salary. Please contact our HR manager on Telegram @amazon_hr_onboarding to continue. Limited slots, reply within 24 hours.` },
    phish: { platform: 'Email / SMS', url: 'http://chase.com.secure-verify-account.top/signin?ref=sms', text: `CHASE ALERT: Unusual sign-in activity detected on your account. Your account has been temporarily suspended. To restore access, verify your identity and confirm your card details immediately: http://chase.com.secure-verify-account.top/signin\nDo not share this message. Reply STOP to opt out.` },
    viral: { platform: 'Facebook', url: '', text: `BREAKING 🚨 SHARE BEFORE IT'S DELETED!! Doctors don't want you to know this: a simple lemon and baking soda drink cures cancer in 7 days. Scientists confirm it is 100% TRUE but the mainstream media won't report it because big pharma pays them. Do your own research. Wake up people! Type AMEN if you agree and tag 10 friends 🙏🙏🙏` },
    bots: { platform: 'X / Twitter', url: '', text: `I made $27,400 in two weeks thanks to @Mrs_Jessica_Trades, she is the best!! #bitcoin #crypto #forex #trading #investing #money #wealth #btc #passiveincome\nI made $27,400 in two weeks thanks to @Mrs_Jessica_Trades, she is the best!! #bitcoin #crypto #forex\nI made $27,400 in two weeks thanks to @Mrs_Jessica_Trades, she is the best!! #bitcoin #crypto\nWow is she legit? @Mrs_Jessica_Trades\nYes 100% legit, she helped me recover my lost funds too. DM her on Telegram` },
  };

  let server = { ai: false, firecrawl: false, online: false };
  let imageFile = null, current = null;

  // ---------- Init ----------
  async function init() {
    $('#pill-local').classList.add('on');
    try { server = { ...(await (await fetch('/api/status')).json()), online: true }; } catch { }
    $('#pill-agents').classList.toggle('on', !!server.ai);
    $('#pill-agents').lastChild.textContent = server.ai ? `Agents · ${server.provider}` : 'Agents via claude.ai';
    $('#pill-agents').title = server.ai ? `Lead: ${server.leadModel} · specialists: ${server.agentModel}` : 'No AI provider on the server. Use "Investigate with Claude" to run the agent team in claude.ai, or install Ollama for free local agents.';
    $('#pill-web').classList.toggle('on', !!server.online);
    $('#pill-web').lastChild.textContent = server.firecrawl ? 'Web + search' : server.online ? 'Web fetch' : 'Web';
    $('#persona').value = store.get('scambunker.persona', DEFAULT_PERSONA);
  }

  // ---------- Intake ----------
  const drop = $('#drop');
  ['dragenter', 'dragover'].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', ev => { const f = ev.dataTransfer.files[0]; if (f && f.type.startsWith('image/') || f && /\.(heic|avif|webp)$/i.test(f.name)) setImage(f); });
  $('#file').addEventListener('change', e => e.target.files[0] && setImage(e.target.files[0]));
  document.addEventListener('paste', e => { const it = [...(e.clipboardData?.items || [])].find(i => i.type.startsWith('image/')); if (it) setImage(it.getAsFile()); });
  $('#clear-img').addEventListener('click', e => { e.preventDefault(); e.stopPropagation(); imageFile = null; $('#file').value = ''; $('#drop-full').hidden = true; $('#drop-empty').hidden = false; });
  function setImage(f) {
    imageFile = f; $('#preview').src = URL.createObjectURL(f); $('#file-name').textContent = `${f.name} · ${(f.size / 1024).toFixed(0)} KB`;
    $('#drop-full').hidden = false; $('#drop-empty').hidden = true;
  }
  $$('[data-sample]').forEach(b => b.addEventListener('click', () => { const s = SAMPLES[b.dataset.sample]; $('#text').value = s.text; $('#url').value = s.url; $('#platform').value = s.platform; investigate(); }));
  $('#go').addEventListener('click', investigate);
  document.addEventListener('keydown', e => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') investigate(); });

  // ---------- Tabs ----------
  $$('#tabs button').forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));
  $('#tabs').addEventListener('keydown', e => {
    const tabs = $$('#tabs button').filter(b => !b.hidden), i = tabs.indexOf(document.activeElement); if (i < 0) return;
    const j = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key]; if (j === undefined) return;
    e.preventDefault(); const n = tabs[(j + tabs.length) % tabs.length]; n.focus(); showTab(n.dataset.tab);
  });
  function showTab(t) { $$('#tabs button').forEach(b => { const on = b.dataset.tab === t; b.setAttribute('aria-selected', on); b.tabIndex = on ? 0 : -1; }); $$('[data-panel]').forEach(p => p.hidden = p.dataset.panel !== t); }
  const panel = n => $(`[data-panel="${n}"]`);

  // ---------- Investigation ----------
  async function investigate() {
    const text = $('#text').value.trim(), url = $('#url').value.trim();
    if (!text && !url && !imageFile) { toast('Add an image, some text or a link first'); return; }
    const go = $('#go'); go.disabled = true; go.firstElementChild.textContent = 'Investigating…';
    $('#placeholder').hidden = true; $('#report').hidden = false; showTab('deduction');
    if (innerWidth < 1020) $('#results').scrollIntoView({ behavior: 'smooth' });

    const c = current = { id: Date.now().toString(36), at: new Date().toISOString(), text, url, persona: $('#persona').value, agents: {}, imagePreview: imageFile ? $('#preview').src : null };
    try {
      // 1. Local engines
      c.heuristics = DeduceHeuristics.analyze({ text, url });
      c.platform = $('#platform').value || c.heuristics.platform || '';
      c.agents.heuristics = { status: 'done', report: heuristicsReport(c.heuristics) };
      if (imageFile) {
        c.agents.metadata = { status: 'run' }; renderAll(c);
        c.forensics = await DeduceForensics.analyze(imageFile);
        c.agents.metadata = { status: 'done', report: metadataReport(c.forensics) };
      }
      c.offenders = matchOffenders(c);
      c.local = localVerdict(c);
      renderAll(c);
      document.dispatchEvent(new CustomEvent('sb:case', { detail: c })); // modules hook in here

      // 2. Web fetch + corroboration
      if (url && server.online) {
        try { c.page = await post('/api/fetch', { url }); } catch (e) { c.page = { error: e.message }; }
        if (c.page?.markdown) { const ph = DeduceHeuristics.analyze({ text: c.page.markdown.slice(0, 6000) }); c.pageHeuristics = { score: ph.score, verdict: ph.verdict, hits: ph.hits.map(h => h.label) }; }
        renderAll(c);
      }
      if (server.firecrawl && text) {
        const q = text.replace(/https?:\S+/g, '').replace(/\s+/g, ' ').slice(0, 160);
        try { c.corroboration = (await post('/api/search', { query: q })).results; } catch { }
      }

      // 3. Agent team
      if (server.ai) {
        const caseData = { persona: c.persona, platform: c.platform, url, text, heuristics: compactHeuristics(c.heuristics), forensics: c.forensics ? DeduceForensics.summarize(c.forensics) : null, page: c.page?.markdown ? `${c.page.title || ''}\n${JSON.stringify(c.page.redirects || '')}\n${c.page.markdown}` : null, corroboration: c.corroboration, imageData: c.forensics?.visionData };
        const roster = ['scam', 'osint', 'factcheck']; if (c.forensics) roster.unshift('forensics');
        roster.forEach(a => c.agents[a] = { status: 'run' }); c.agents.lead = { status: 'wait' };
        renderAgents(c); $('#agents-count').textContent = '…';
        const reports = await Promise.all(roster.map(async a => {
          try { const r = await post('/api/agent', { agent: a, case: caseData }); c.agents[a] = { status: 'done', report: r.report }; renderAgents(c); return r; }
          catch (e) { c.agents[a] = { status: 'err', report: e.message }; renderAgents(c); return null; }
        }));
        c.agents.lead = { status: 'run' }; renderAgents(c);
        try {
          const { imageData, ...leanCase } = caseData;
          const r = await post('/api/lead', { case: leanCase, reports: reports.filter(Boolean) });
          if (r.verdict) { c.final = r.verdict; c.agents.lead = { status: 'done', report: r.verdict.deduction }; }
          else c.agents.lead = { status: 'done', report: r.raw };
        } catch (e) { c.agents.lead = { status: 'err', report: e.message }; }
        renderAll(c);
      }
      saveCase(c);
      document.dispatchEvent(new CustomEvent('sb:case-complete', { detail: c }));
    } catch (e) {
      console.error(e); toast('Something went wrong: ' + e.message);
    } finally { go.disabled = false; go.firstElementChild.textContent = 'Open investigation'; }
  }

  async function post(path, body) {
    const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
    return j;
  }
  const compactHeuristics = h => ({ score: h.score, verdict: h.verdict, category: h.category, hits: h.hits.map(x => `${x.category}: ${x.label} ["${x.match}"]`), links: h.links, coordination: h.coordination, entities: h.entities, platform: h.platform });

  // ---------- Repeat-offender profiling ----------
  // Identifiers a scammer reuses across campaigns. Big platforms and shorteners are excluded: they identify nobody.
  const SHARED_HOST_PARENT = /^(www\.)?(github\.io|pages\.dev|vercel\.app|netlify\.app|web\.app|firebaseapp\.com|blogspot\.com|wixsite\.com|square\.site|carrd\.co|notion\.site|linktr\.ee|beacons\.ai|bio\.link)$/i; // the parent itself is shared; subdomains (scam-x.vercel.app) still identify
  const NOT_IDENTIFYING = /(^|\.)(facebook|instagram|linkedin|twitter|x|tiktok|youtube|google|whatsapp|telegram|reddit|threads|bsky|discord|snapchat|bit|t|lnkd|tinyurl|goo|ow|is|buff|rebrand|cutt|rb|linktr|wa)\.(com|net|org|ly|me|in|gl|gd|co|ee|app)$/i;
  function indicators(h, f) {
    const out = [];
    const add = (type, value, label) => value && out.push({ type, key: `${type}:${value}`, label: label || value });
    (h.entities.wallets || []).forEach(w => add('wallet', w.addr, `${w.chain} wallet ${w.addr}`));
    // Handles are weak indicators only (trivially re-registered / impersonated): they never trigger the confirmed repeat-offender escalation below.
    (h.entities.handles || []).forEach(x => add('handle', x.replace(/^@/, '').toLowerCase(), x));
    (h.entities.phones || []).forEach(x => { const d = x.replace(/\D/g, ''); if (d.length >= 9) add('phone', x.startsWith('+') ? d : d.slice(-10), x); });
    (h.entities.emails || []).forEach(x => add('email', x.toLowerCase()));
    (h.links || []).forEach(l => { if (l.host && !NOT_IDENTIFYING.test(l.host) && !SHARED_HOST_PARENT.test(l.host)) add('domain', l.host.replace(/^www\./, '')); });
    if (f?.sha256) add('image', f.sha256, `Identical image (SHA-256 ${f.sha256.slice(0, 12)}…)`);
    if (f?.exif?.BodySerialNumber) add('camera', f.exif.BodySerialNumber, `Camera serial ${f.exif.BodySerialNumber}`);
    const seen = new Set(); return out.filter(i => !seen.has(i.key) && seen.add(i.key));
  }
  function matchOffenders(c) {
    c.indicators = indicators(c.heuristics, c.forensics);
    const past = store.get('scambunker.cases', []);
    const hits = [];
    for (const ind of c.indicators) {
      const cases = past.filter(p => (p.indicators || []).some(k => k.key === ind.key));
      if (cases.length) hits.push({ ...ind, cases: cases.map(p => ({ id: p.id, at: p.at, verdict: p.verdict, platform: p.platform, snippet: (p.text || p.url || '').slice(0, 90) })) });
    }
    return hits;
  }

  // ---------- Local reasoning ----------
  function localVerdict(c) {
    const h = c.heuristics, f = c.forensics;
    let verdict = h.verdict, category = h.category, risk = h.score;
    const obs = [];
    h.hits.slice().sort((a, b) => b.weight - a.weight).slice(0, 6).forEach(x => obs.push({ fact: `“${x.match}”`, inference: x.label, weight: x.weight >= 20 ? 'strong' : x.weight >= 14 ? 'moderate' : 'weak' }));
    h.links.filter(l => l.risk >= 25).forEach(l => obs.push({ fact: l.host || l.url, inference: l.flags[0], weight: l.risk >= 35 ? 'strong' : 'moderate' }));
    h.entities.wallets.forEach(w => obs.push({ fact: `${w.chain} wallet ${w.addr.slice(0, 10)}…`, inference: 'Payment demanded to an irreversible crypto address', weight: 'strong' }));
    h.coordination.forEach(s => obs.push({ fact: 'Text pattern', inference: s, weight: 'moderate' }));
    if (f) {
      f.ai.signals.forEach(s => obs.push({ fact: 'Image metadata', inference: s.label, weight: s.strength === 'proof' ? 'strong' : s.strength }));
      f.ai.weak.forEach(s => obs.push({ fact: 'Image pixels / dimensions', inference: s, weight: 'weak' }));
      if (f.editors.length) obs.push({ fact: `Software: ${f.editors.join(', ')}`, inference: 'Image was processed in an editor after capture', weight: 'moderate' });
      if (['confirmed', 'likely'].includes(f.ai.verdict)) {
        risk = Math.max(risk, f.ai.verdict === 'confirmed' ? 72 : 58);
        if (!['Scam', 'Likely scam'].includes(verdict)) { verdict = 'AI-generated content'; category = f.ai.generators[0] || 'Synthetic image'; }
      }
      else if (!c.text && !c.url) {
        if (f.editors.length || f.notes.length) { verdict = 'Edited image'; category = f.editors[0] ? `Processed in ${f.editors[0]}` : 'Metadata anomaly'; }
        else if (f.ai.verdict === 'possible') { verdict = 'Suspicious'; category = 'Possible AI image'; }
        else { verdict = 'No strong red flags'; category = Object.keys(f.exif).length ? 'Camera original' : 'Metadata stripped'; }
      }
      risk = Math.max(risk, Math.round(f.suspicion * 0.8));
    }
    (c.offenders || []).forEach(o => {
      const bad = o.cases.filter(p => ['Scam', 'Likely scam', 'Suspicious', 'Coordinated / inauthentic'].includes(p.verdict)).length;
      obs.unshift({ fact: `${o.label}`, inference: `Seen before in ${o.cases.length} earlier case${o.cases.length > 1 ? 's' : ''}${bad ? `, ${bad} of them judged a scam or suspicious` : ''}. This is a repeat actor.`, weight: bad ? 'strong' : 'moderate' });
      const confirmed = o.cases.some(p => ['Scam', 'Likely scam'].includes(p.verdict));
      if (confirmed && ['wallet', 'phone', 'email', 'domain', 'image'].includes(o.type)) {
        // Payment / contact identifiers reused from a confirmed scam are among the strongest evidence there is
        risk = Math.max(risk + 20, 75);
        if (verdict !== 'Scam') { verdict = 'Likely scam'; category = `Repeat offender (${o.type} reused)`; }
      } else if (bad) { risk = Math.min(100, risk + 15); if (['No strong red flags', 'Insufficient evidence'].includes(verdict)) { verdict = 'Suspicious'; category = 'Linked to earlier scam cases'; } }
      risk = Math.min(100, risk);
    });
    if (!obs.length) obs.push({ fact: 'No pattern matched', inference: 'None of the known scam, manipulation or AI signatures fired. That is not proof of legitimacy.', weight: 'weak' });

    const conf = Math.min(92, 35 + obs.filter(o => o.weight === 'strong').length * 12 + obs.filter(o => o.weight === 'moderate').length * 5);
    return { verdict, category, risk, confidence: conf, observations: obs, headline: headlineFor(verdict, category, c), deduction: deductionFor(c, verdict, category, obs),
      image_dating: f ? { earliest: f.earliest ? f.earliest.when.replace('T', ' ') : null, basis: f.earliest ? `${f.earliest.src} (${f.earliest.what.toLowerCase()})` : 'No embedded timestamps survived. Run a reverse image search and sort by oldest to date it.' } : null,
      ai_involvement: f ? { assessment: f.ai.verdict, basis: f.ai.signals[0]?.label || f.ai.weak[0] || 'No generator signature, C2PA AI assertion or statistical anomaly found' } : null,
      hidden_info: f ? f.hidden : [], next_steps: nextSteps(c), advice: adviceFor(verdict) };
  }
  function headlineFor(v, cat, c) {
    const p = c.platform ? ` on ${c.platform}` : '';
    return ({ 'Scam': `A scam${p}, ${cat.toLowerCase()} type. Do not pay, click or reply.`, 'Likely scam': `It follows the ${cat.toLowerCase()} playbook closely${p}. Treat it as a scam until it's proven otherwise.`, 'Suspicious': `Several red flags (${cat.toLowerCase()}). Verify through an independent channel before you act.`, 'Misleading / manipulated': 'It uses classic misinformation techniques and gives no verifiable source.', 'Coordinated / inauthentic': 'Repeated, templated text points to a coordinated network, not real people.', 'AI-generated content': 'The image shows evidence of AI generation.', 'Edited image': 'A real camera photo that was altered or re-saved in editing software after capture.', 'No strong red flags': 'None of the known scam or manipulation patterns matched. Stay sceptical anyway.', 'Insufficient evidence': 'There is not enough material to reach a conclusion.' })[v] || '';
  }
  function deductionFor(c, v, cat, obs) {
    const strong = obs.filter(o => o.weight === 'strong'), h = c.heuristics, f = c.forensics;
    const s = [];
    if (h.hits.length) {
      const cats = Object.keys(h.byCategory);
      s.push(`I observe ${h.hits.length} distinct pressure and persuasion markers across ${cats.length} categories: ${cats.slice(0, 4).join(', ').toLowerCase()}.`);
    }
    if (h.byCategory['Payment rails'] || h.entities.wallets.length) s.push(`The decisive detail is the payment method: ${h.entities.wallets.length ? 'a raw crypto address' : 'an irreversible rail'}. A legitimate organisation would never ask for it, and once the money is sent it cannot be clawed back.`);
    const bad = h.links.find(l => l.risk >= 30); if (bad) s.push(`The link gives itself away. ${bad.host} ${bad.flags[0].charAt(0).toLowerCase() + bad.flags[0].slice(1)}.`);
    if (h.byCategory['Off-platform move']) s.push('Moving the conversation to WhatsApp or Telegram is deliberate. It takes the victim away from the platform\'s reporting tools and moderation.');
    if (h.coordination.length) s.push(`The text was not written by independent people. ${h.coordination[0]}.`);
    if (f) {
      if (f.ai.verdict === 'confirmed') s.push(`The image declares its own origin. ${f.ai.signals.find(x => x.strength === 'proof')?.label}. That is proof, not inference.`);
      else if (f.ai.verdict === 'likely') s.push(`The file carries the fingerprint of ${f.ai.generators[0] || 'an AI generator'}.`);
      else if (f.ai.weak.length) s.push(`Nothing in the file proves AI involvement. There are circumstantial hints (${f.ai.weak[0].toLowerCase()}), which on their own are only hints.`);
      if (f.notes.some(n => /re-saved/.test(n))) s.push(`The device signature says ${[f.exif.Make, f.exif.Model].filter(Boolean).join(' ')}, yet the last hand on the file was ${f.exif.Software}. The photograph is genuine in origin but has been through an editor, so its content may no longer be what the lens saw.`);
      if (f.hidden.some(h => /^GPS/.test(h))) s.push('Whoever shared this file also shared where it was taken. The GPS coordinates are still embedded.');
      if (f.earliest) s.push(`The file says it was ${f.earliest.what.toLowerCase()} on ${f.earliest.when.replace('T', ' at ')}, according to ${f.earliest.src}.`);
      else if (!Object.keys(f.exif).length) s.push('All camera metadata has been stripped. Either the image passed through a social platform or someone removed it deliberately. Either way, its age has to come from reverse search.');
    }
    if (!s.length) s.push('I see nothing that matches a known deception pattern. The absence of evidence is not evidence of absence, though. Verify the sender through a channel you already trust.');
    if ((c.offenders || []).length) s.unshift(`We have met this actor before. ${c.offenders[0].label} also appears in ${c.offenders[0].cases.length} earlier case file${c.offenders[0].cases.length > 1 ? 's' : ''}. Scammers change their stories, but they rarely change their wallets or numbers.`);
    if (strong.length >= 3) s.push('Taken together, the innocent explanation can no longer hold.');
    return s.join(' ');
  }
  function nextSteps(c) {
    const st = [], h = c.heuristics, f = c.forensics;
    if (f) st.push('Run Google Lens and TinEye on the image. Sort by oldest to find the first appearance.');
    if (f && f.c2pa) st.push('Verify the Content Credentials at contentcredentials.org/verify to see the signed edit history.');
    h.entities.wallets.forEach(w => st.push(`Trace ${w.chain} wallet on a block explorer (${w.addr.slice(0, 8)}…) to see how many victims have paid it.`));
    h.links.filter(l => l.host).slice(0, 3).forEach(l => st.push(`Check the domain age of ${l.host} (WHOIS / who.is) and look up its archive.org history. Phishing domains are often days old.`));
    h.entities.handles.slice(0, 3).forEach(x => st.push(`Search ${x} across platforms, for example with WhatsMyName. Look for clones and account-creation dates.`));
    h.entities.phones.slice(0, 2).forEach(p => st.push(`Search the phone number ${p} together with "scam" and check carrier lookups for VoIP.`));
    if (h.verdict === 'Misleading / manipulated') st.push('Search the core claim on fact-checkers such as Snopes, AFP Fact Check, Reuters Fact Check and Full Fact.');
    if (c.platform) st.push(`Report it in-app on ${c.platform}. Reports with screenshots from several users get faster takedowns.`);
    st.push('Archive the evidence now with screenshots and archive.today, before the post is deleted.');
    return st;
  }
  function adviceFor(v) {
    if (['Scam', 'Likely scam'].includes(v)) return 'Do not send money, codes, ID documents or seed phrases. Do not click the link. Block and report the account. If money was already sent, contact your bank or exchange immediately and file a report with your national fraud centre (in the US, reportfraud.ftc.gov and ic3.gov). Ignore anyone who offers to "recover" funds. That is a second scam.';
    if (v === 'Suspicious') return 'Pause. Contact the person or company through a channel you find yourself, such as their official website or a number you already have. Never use the contact details in the message.';
    if (v === 'Misleading / manipulated') return 'Do not share it. Look for the original source and established fact-checks first.';
    if (v === 'Coordinated / inauthentic') return 'Treat the testimonials as fake. Report the accounts as spam or a coordinated network.';
    if (v === 'Edited image') return 'Ask for the unedited original, then compare the two. Strip GPS and serial numbers before you share your own photos (on iPhone: Share › Options › Location off).';
    if (v === 'AI-generated content') return 'Do not treat the image as documentary evidence of a real event or person. Ask for the original file or other sources.';
    return 'No action is needed based on these signals, but verify independently before you pay or share anything.';
  }

  // ---------- Reports for local agents ----------
  function heuristicsReport(h) {
    const l = [`Risk score ${h.score}/100 → ${h.verdict} (${h.category}).`];
    if (h.hits.length) l.push('', 'Matched patterns:', ...h.hits.map(x => `• [${x.category}] ${x.label}`));
    if (h.links.length) l.push('', 'Links:', ...h.links.map(x => `• ${x.host || x.url}: ${x.flags.length ? x.flags.join('; ') : 'no structural red flags'}`));
    if (h.coordination.length) l.push('', 'Coordination:', ...h.coordination.map(x => '• ' + x));
    if (!h.hits.length && !h.links.length) l.push('No known scam or manipulation pattern matched.');
    return l.join('\n');
  }
  function metadataReport(f) {
    const l = [`${f.format} · ${f.width || '?'}×${f.height || '?'} · ${(f.size / 1024).toFixed(0)} KB${f.jpegQuality ? ' · JPEG q≈' + f.jpegQuality : ''}`, `AI involvement: ${f.ai.verdict}${f.ai.generators.length ? ' (' + f.ai.generators.join(', ') + ')' : ''}`, `C2PA Content Credentials: ${f.c2pa ? 'present' : 'absent'}`, `Earliest firm timestamp: ${f.earliest ? f.earliest.when + ' via ' + f.earliest.src : 'none'}`];
    if (f.editors.length) l.push(`Editing software: ${f.editors.join(', ')}`);
    if (f.platformMarks.length) l.push('', 'Platform fingerprints:', ...f.platformMarks.map(x => '• ' + x));
    if (f.hidden.length) l.push('', 'Exposed data:', ...f.hidden.map(x => '• ' + x));
    if (f.notes.length) l.push('', 'Anomalies:', ...f.notes.map(x => '• ' + x));
    return l.join('\n');
  }

  // ---------- Render ----------
  function renderAll(c) { renderVerdict(c); renderDeduction(c); renderAgents(c); renderImage(c); renderLinks(c); renderTimeline(c); renderNext(c); }
  const V = c => c.final || c.local || {};

  function renderVerdict(c) {
    const v = V(c); const color = VERDICT_COLOR[v.verdict] || 'var(--accent)';
    $('#verdict').style.setProperty('--v', color);
    $('#v-title').textContent = v.verdict || 'Analysing…';
    $('#v-headline').textContent = v.headline || '';
    $('#v-source').textContent = c.final ? `Final verdict · lead investigator after ${Object.keys(c.agents).length - 1} reports` : server.ai ? 'Preliminary · local engines, agents deliberating…' : 'Local engines · press “Investigate with Claude” for the agent team';
    const tags = [v.category, v.confidence != null && `confidence ${v.confidence}%`, c.platform, c.forensics && `AI: ${(v.ai_involvement || {}).assessment || c.forensics.ai.verdict}`].filter(Boolean);
    $('#v-tags').innerHTML = tags.map(t => `<span class="tag">${esc(t)}</span>`).join('');
    const risk = +v.risk || 0; $('#g-val').textContent = risk; $('#g-fg').style.strokeDashoffset = 314 - 314 * risk / 100;
  }

  function renderDeduction(c) {
    const v = V(c);
    const obs = (v.observations || []).map(o => `<div class="ob"><div><span class="k">Observation</span><p>${esc(o.fact)}</p></div><div><span class="k">Inference</span><p>${esc(o.inference)}</p></div><span class="w ${esc(o.weight)}">${esc(o.weight)}</span></div>`).join('');
    const boxes = [];
    if (v.image_dating) boxes.push(`<div class="box"><div class="k">Image dates back to</div><div class="big">${esc(v.image_dating.earliest || 'Unknown from file')}</div><p>${esc(v.image_dating.basis)}</p></div>`);
    if (v.ai_involvement) boxes.push(`<div class="box"><div class="k">AI involvement</div><div class="big">${esc(v.ai_involvement.assessment)}</div><p>${esc(v.ai_involvement.basis)}</p></div>`);
    panel('deduction').innerHTML = `
      <blockquote class="deduction">${esc(v.deduction || '')}</blockquote>
      ${boxes.length ? `<section><div class="grid2">${boxes.join('')}</div></section>` : ''}
      ${offenderHtml(c)}
      <section><h3>Evidence chain</h3><div class="obs">${obs}</div></section>
      ${(v.disagreements || []).length ? `<section><h3>Where the agents disagreed</h3><ul class="list">${v.disagreements.map(d => `<li>${esc(d)}</li>`).join('')}</ul></section>` : ''}
      ${(v.hidden_info || []).length ? `<section><h3>Hidden in the file</h3><ul class="list red">${v.hidden_info.map(d => `<li>${esc(d)}</li>`).join('')}</ul></section>` : ''}
      <section><div class="advice"><b>What to do now:</b> ${esc(v.advice || '')}</div></section>`;
  }

  function renderAgents(c) {
    const ids = Object.keys(c.agents).sort((a, b) => (a === 'lead') - (b === 'lead'));
    const done = ids.filter(i => c.agents[i].status === 'done').length;
    $('#agents-count').textContent = `${done}/${ids.length}`;
    const callout = server.ai ? '' : `<div class="callout handoff"><div><b>Run the full agent team without an API key.</b> “Investigate with Claude” packs this case, along with the Image Forensics, Fraud, OSINT, Fact-check and Lead Investigator roles, into one prompt and opens it in claude.ai on your own Claude plan. For free agents that run offline on your machine, install <a href="https://ollama.com" target="_blank" rel="noopener">Ollama</a> and run <code>ollama pull gemma3</code>. Scam Bunker detects it on the next start.</div><button type="button" class="primary sm" data-handoff>Investigate with Claude ↗</button></div>`;
    panel('agents').innerHTML = callout + `<div class="agents">${ids.map(id => {
      const a = c.agents[id], m = AGENT_META[id];
      const st = { run: 'Investigating', done: 'Reported', err: 'Failed', wait: 'Awaiting reports' }[a.status] || a.status;
      const body = a.status === 'run' || a.status === 'wait' ? '<div class="shimmer" style="width:92%"></div><div class="shimmer" style="width:76%"></div><div class="shimmer" style="width:84%"></div>' : esc(a.report || '');
      return `<article class="agent ${id === 'lead' ? 'lead' : ''}"><header><div class="av" style="color:${m.color};background:${m.bg}">${m.glyph}</div><div><h4>${m.name}</h4><div class="role">${m.role}</div></div><span class="st ${a.status === 'wait' ? 'off' : a.status}"><i></i>${st}</span></header><div class="body">${body}</div></article>`;
    }).join('')}</div>`;
  }

  function renderImage(c) {
    const f = c.forensics;
    if (!f) { panel('image').innerHTML = '<p class="empty">No image in this case. Drop one into the intake panel to date it, detect AI use, and pull out its hidden metadata.</p>'; return; }
    const rows = [['SHA-256', f.sha256], ['Format', `${f.format}${f.progressive ? ' (progressive)' : ''}`], ['Dimensions', `${f.width}×${f.height}`], ['JPEG quality', f.jpegQuality ? `≈ ${f.jpegQuality}` : '—'], ['C2PA credentials', f.c2pa ? `Present${f.c2paIssuers?.length ? ' · ' + f.c2paIssuers.join(', ') : ''}` : 'Absent'], ['ICC profile', f.icc || '—']];
    Object.entries(f.exif).forEach(([k, v]) => { if (k !== 'GPS') rows.push([k, typeof v === 'object' ? JSON.stringify(v) : v]); });
    Object.entries(f.xmpFields).forEach(([k, v]) => { if (k !== 'history') rows.push([k, v]); });
    Object.keys(f.textChunks).forEach(k => k !== 'parameters' && k !== 'prompt' && rows.push([`PNG:${k}`, String(f.textChunks[k]).slice(0, 240)]));
    const susColor = f.suspicion >= 60 ? 'var(--red)' : f.suspicion >= 30 ? 'var(--amber)' : 'var(--green)';
    const gps = f.exif.GPSDecimal;
    panel('image').innerHTML = `
      <section class="imglab">
        <figure class="imgframe" style="margin:0"><img src="${c.imagePreview}" alt="Original"><figcaption><span>Original</span><span>${esc(f.name)}</span></figcaption></figure>
        <figure class="imgframe" style="margin:0"><img src="${f.elaUrl || ''}" alt="Error level analysis"><figcaption><span>Error-level analysis</span><span>hotspots ${f.ela ? f.ela.hotspotPct + '%' : '—'}</span></figcaption></figure>
      </section>
      <section class="grid2">
        <div class="box"><div class="k">Integrity suspicion</div><div class="big">${f.suspicion}/100</div><div class="meter" style="--v:${susColor}"><i style="width:${f.suspicion}%"></i></div><p style="margin-top:8px">Bright, blocky regions in the ELA that don't match their surroundings can mean pasted-in content. A uniform glow is normal. ELA is a lead, not proof.</p></div>
        <div class="box"><div class="k">AI verdict</div><div class="big">${esc(f.ai.verdict)}</div><p>${f.ai.generators.length ? 'Generator: ' + esc(f.ai.generators.join(', ')) : 'No named generator.'} ${f.pixels ? `Noise ${f.pixels.noiseLevel} · saturation ${f.pixels.meanSaturation}` : ''}</p></div>
      </section>
      ${f.ai.signals.length || f.ai.weak.length ? `<section><h3>AI signals</h3><div class="obs">${f.ai.signals.map(s => `<div class="ob"><div><p>${esc(s.label)}</p></div><div></div><span class="w ${s.strength}">${s.strength}</span></div>`).join('')}${f.ai.weak.map(s => `<div class="ob"><div><p>${esc(s)}</p></div><div></div><span class="w weak">weak</span></div>`).join('')}</div></section>` : ''}
      ${f.prompt ? `<section><h3>Embedded generation prompt</h3><div class="prompt">${esc(f.prompt)}</div></section>` : ''}
      ${f.platformMarks.length ? `<section><h3>Where it has been</h3><ul class="list">${f.platformMarks.map(x => `<li>${esc(x)}</li>`).join('')}</ul></section>` : ''}
      ${f.hidden.length ? `<section><h3>Hidden information exposed</h3><ul class="list red">${f.hidden.map(x => `<li>${esc(x)}</li>`).join('')}</ul>${gps ? `<iframe class="map" loading="lazy" title="GPS location" src="https://www.openstreetmap.org/export/embed.html?bbox=${gps.lon - .01},${gps.lat - .006},${gps.lon + .01},${gps.lat + .006}&marker=${gps.lat},${gps.lon}"></iframe>` : ''}</section>` : ''}
      ${f.notes.length ? `<section><h3>Anomalies</h3><ul class="list red">${f.notes.map(x => `<li>${esc(x)}</li>`).join('')}</ul></section>` : ''}
      <section><h3>All extracted metadata</h3><div class="kv">${rows.map(([k, v]) => `<div>${esc(k)}</div><div>${esc(v)}</div>`).join('')}</div></section>
      <section><h3>Reverse image search</h3><div class="rev">${f.reverse.map(r => `<a href="${r.url}" target="_blank" rel="noopener"><b>${r.name} ↗</b><span>${esc(r.how)}</span></a>`).join('')}</div></section>`;
  }

  function offenderHtml(c) {
    const o = c.offenders || [];
    if (!o.length) return (c.indicators || []).length ? `<section><div class="callout">I added ${c.indicators.length} identifier${c.indicators.length > 1 ? 's' : ''} to your offender index (${[...new Set(c.indicators.map(i => i.type))].join(', ')}). If any reappear in a later case, Scam Bunker will connect them.</div></section>` : '';
    return `<section class="offender"><h3>Repeat offender</h3><p class="muted">These identifiers have appeared in earlier cases.</p>${o.map(x => `<div class="linkcard"><div class="top"><span class="tag">${esc(x.type)}</span><code>${esc(x.label)}</code><span class="w strong">${x.cases.length}× before</span></div><ul>${x.cases.slice(0, 5).map(p => `<li>${esc(new Date(p.at).toLocaleDateString())} · ${esc(p.verdict)}${p.platform ? ' · ' + esc(p.platform) : ''}: “${esc(p.snippet)}…”</li>`).join('')}</ul></div>`).join('')}</section>`;
  }

  function renderLinks(c) {
    const h = c.heuristics, e = h.entities;
    const mark = (ex, m) => esc(ex).replace(esc(m), `<mark>${esc(m)}</mark>`);
    const linkCards = h.links.map(l => { const col = l.risk >= 35 ? 'strong' : l.risk >= 15 ? 'moderate' : 'ok'; return `<div class="linkcard"><div class="top"><code>${esc(l.url)}</code><span class="w ${col}">risk ${l.risk}</span>${l.platform ? `<span class="tag">${esc(l.platform)}</span>` : ''}</div>${l.flags.length ? `<ul>${l.flags.map(f => `<li>${esc(f)}</li>`).join('')}</ul>` : '<ul><li>No structural red flags in the URL itself</li></ul>'}${l.tracking ? `<ul><li>Tracking parameters: ${esc(l.tracking.join(', '))}</li></ul>` : ''}</div>`; }).join('');
    const page = c.page && !c.page.error ? `<div class="linkcard"><div class="top"><b>Fetched page</b><span class="tag">${esc(c.page.via)}</span></div><ul><li>Title: ${esc(c.page.title || '—')}</li>${(c.page.redirects || []).length > 1 ? `<li>Redirect chain: ${c.page.redirects.map(r => esc(r.url) + ' (' + r.status + ')').join(' → ')}</li>` : ''}${c.pageHeuristics ? `<li>Page content scored ${c.pageHeuristics.score}/100 (${esc(c.pageHeuristics.verdict)})</li>` : ''}</ul></div>` : c.page?.error ? `<div class="linkcard"><b>Could not fetch the page:</b> ${esc(c.page.error)}. Facebook, Instagram and LinkedIn block anonymous fetches, so paste the post text instead.</div>` : '';
    const ent = [['Wallets', e.wallets.map(w => `<a href="${w.explorer}" target="_blank" rel="noopener">${esc(w.chain)}: ${esc(w.addr)}</a>`)], ['Handles', e.handles.map(esc)], ['Phones', e.phones.map(esc)], ['Emails', e.emails.map(esc)], ['Money amounts', e.money.map(esc)], ['Hashtags', e.hashtags.map(esc)]].filter(([, v]) => v.length);
    panel('links').innerHTML = `
      ${h.hits.length ? `<section><h3>Language patterns</h3>${h.hits.map(x => `<div class="hit"><b>${esc(x.label)}</b><span class="cat">${esc(x.category)} · +${x.weight}</span><q>${mark(x.excerpt, x.match)}</q></div>`).join('')}</section>` : ''}
      <section><h3>Links</h3>${linkCards || '<p class="empty">No links found.</p>'}${page}</section>
      ${ent.length ? `<section><h3>Extracted entities</h3><div class="ent">${ent.map(([k, v]) => `<div class="box"><div class="k">${k}</div><ul>${v.map(x => `<li>${x}</li>`).join('')}</ul></div>`).join('')}</div></section>` : ''}
      ${h.coordination.length ? `<section><h3>Coordination signals</h3><ul class="list">${h.coordination.map(x => `<li>${esc(x)}</li>`).join('')}</ul></section>` : ''}
      ${h.playbook.length ? `<section><h3>Known playbook on ${esc(h.platform)}</h3><ul class="list">${h.playbook.map(x => `<li>${esc(x)}</li>`).join('')}</ul></section>` : ''}
      ${(c.corroboration || []).length ? `<section><h3>Web corroboration</h3>${c.corroboration.filter(r => /^https?:\/\//i.test(r.url || "")).map(r => `<div class="linkcard"><a href="${esc(r.url)}" target="_blank" rel="noopener"><b>${esc(r.title)}</b></a><ul><li>${esc(r.description || '')}</li></ul></div>`).join('')}</section>` : ''}`;
  }

  function renderTimeline(c) {
    const f = c.forensics;
    const items = (f?.timeline || []).map(t => ({ ...t }));
    items.push({ when: c.at.slice(0, 19), what: 'Case opened in Scam Bunker', src: 'This investigation', trust: 'low' });
    items.sort((a, b) => a.when.localeCompare(b.when));
    panel('timeline').innerHTML = `${!f ? '<p class="empty">Add an image to rebuild its timeline from embedded timestamps.</p>' : !f.earliest ? '<div class="callout">The file has no surviving embedded timestamps, which is typical after social-media upload. To date it, run a reverse image search and use the earliest indexed copy (TinEye: sort by Oldest).</div>' : ''}
      <div class="tl">${items.map(t => `<div class="tl-item ${t.trust === 'low' ? 'low' : ''}"><time>${esc(t.when.replace('T', ' · '))}</time><p>${esc(t.what)}</p><small>${esc(t.src)} · trust ${esc(t.trust)}</small></div>`).join('')}</div>`;
  }

  function renderNext(c) {
    const v = V(c);
    panel('next').innerHTML = `<section><h3>Investigative pivots</h3><ul class="list">${(v.next_steps || []).map(s => `<li>${esc(s)}</li>`).join('')}</ul></section><section><div class="advice"><b>For the potential victim:</b> ${esc(v.advice || '')}</div></section>`;
  }

  // ---------- claude.ai handoff (no API key needed) ----------
  async function handoff() {
    const c = current; if (!c) return;
    let prompt;
    try {
      ({ prompt } = await post('/api/prompt', { hasImage: !!c.forensics, case: { persona: c.persona, platform: c.platform, url: c.url, text: c.text, heuristics: compactHeuristics(c.heuristics), forensics: c.forensics ? DeduceForensics.summarize(c.forensics) : null, page: c.page?.markdown || null, corroboration: c.corroboration } }));
    } catch (e) { toast('Could not build the prompt: ' + e.message); return; }
    let copied = false; try { await navigator.clipboard.writeText(prompt); copied = true; } catch { }
    const short = prompt.length < 7000;
    window.open(short ? 'https://claude.ai/new?q=' + encodeURIComponent(prompt) : 'https://claude.ai/new', '_blank', 'noopener');
    toast(short ? (c.forensics ? 'Opened in Claude. Attach the image there too, so Claude can examine it' : 'Opened in Claude') : copied ? 'Case copied. Paste it into the new Claude chat (⌘V)' + (c.forensics ? ', then attach the image' : '') : 'Clipboard blocked. Use Copy summary instead');
  }
  document.addEventListener('click', e => { if (e.target.closest('[data-handoff]')) handoff(); });

  // ---------- History ----------
  function saveCase(c) {
    const v = V(c); const list = store.get('scambunker.cases', []);
    list.unshift({ id: c.id, at: c.at, indicators: c.indicators || [], text: c.text.slice(0, 4000), url: c.url, platform: c.platform, verdict: v.verdict, risk: v.risk, headline: v.headline, final: c.final || null, local: c.local, heuristics: c.heuristics, agents: c.agents, provenance: c.provenance || null, forensics: c.forensics ? { ...DeduceForensics.summarize(c.forensics), elaUrl: null } : null });
    store.set('scambunker.cases', list.slice(0, 200));
  }
  $('#btn-history').addEventListener('click', () => {
    const list = store.get('scambunker.cases', []);
    const idx = {}; list.forEach(x => (x.indicators || []).forEach(i => { (idx[i.key] = idx[i.key] || { ...i, n: 0 }).n++; }));
    const repeat = Object.values(idx).filter(i => i.n > 1).sort((a, b) => b.n - a.n);
    $('#offender-index').innerHTML = repeat.length ? `<h4>Repeat offenders across your cases</h4><ul class="list red">${repeat.slice(0, 12).map(i => `<li><b>${esc(i.label)}</b> · ${esc(i.type)} · in ${i.n} cases</li>`).join('')}</ul>` : '';
    $('#history-list').innerHTML = list.length ? list.map(x => `<div class="hist" data-id="${x.id}"><span class="d" style="background:${VERDICT_COLOR[x.verdict] || 'var(--muted)'}"></span><div class="t"><b>${esc(x.verdict)} · ${x.risk}</b><span>${esc(x.text || x.url || 'Image case')}</span></div><small class="muted">${new Date(x.at).toLocaleDateString()}</small></div>`).join('') : '<p class="empty">No saved cases yet.</p>';
    $$('#history-list .hist').forEach(el => el.addEventListener('click', () => {
      const x = list.find(i => i.id === el.dataset.id); if (!x) return;
      current = { ...x, imagePreview: null, forensics: x.forensics ? { ...x.forensics, reverse: [], timeline: x.forensics.timeline || [], ai: x.forensics.ai, elaUrl: '' } : null };
      $('#text').value = x.text; $('#url').value = x.url || '';
      $('#placeholder').hidden = true; $('#report').hidden = false; renderAll(current); showTab('deduction'); $('#dlg-history').close();
    }));
    $('#dlg-history').showModal();
  });
  $('#history-clear').addEventListener('click', () => { store.set('scambunker.cases', []); $('#history-list').innerHTML = '<p class="empty">No saved cases yet.</p>'; });

  // ---------- Persona ----------
  $('#btn-persona').addEventListener('click', () => $('#dlg-persona').showModal());
  $('#persona-save').addEventListener('click', () => { store.set('scambunker.persona', $('#persona').value); toast('Profile saved. Agents will follow it on the next case'); });
  $('#persona-reset').addEventListener('click', () => { $('#persona').value = DEFAULT_PERSONA; });

  // ---------- Export ----------
  function summaryText(c) {
    const v = V(c);
    return [`DEDUCE CASE REPORT · ${new Date(c.at).toLocaleString()}`, `Verdict: ${v.verdict} (${v.category}) · risk ${v.risk}/100 · confidence ${v.confidence}%`, c.platform && `Platform: ${c.platform}`, c.url && `URL: ${c.url}`, '', v.headline, '', 'DEDUCTION', v.deduction, '', 'EVIDENCE', ...(v.observations || []).map(o => `- [${o.weight}] ${o.fact} → ${o.inference}`),
      v.image_dating && `\nIMAGE DATING: ${v.image_dating.earliest || 'unknown'}, ${v.image_dating.basis}`, v.ai_involvement && `AI INVOLVEMENT: ${v.ai_involvement.assessment}, ${v.ai_involvement.basis}`,
      (v.hidden_info || []).length && '\nHIDDEN INFO\n' + v.hidden_info.map(x => '- ' + x).join('\n'), ...(c.provenance?.reportLines || []), '\nNEXT STEPS', ...(v.next_steps || []).map(x => '- ' + x), '\nADVICE', v.advice].filter(x => x !== null && x !== undefined && x !== false).join('\n');
  }
  $('#btn-copy').addEventListener('click', async () => { try { await navigator.clipboard.writeText(summaryText(current)); toast('Summary copied'); } catch { toast('Clipboard blocked'); } });
  $('#btn-export').addEventListener('click', () => {
    const c = current; const blob = new Blob([`<!doctype html><meta charset="utf-8"><title>Scam Bunker case ${c.id}</title><style>body{font:15px/1.6 Georgia,serif;max-width:760px;margin:40px auto;padding:0 20px;color:#1b1d22}pre{white-space:pre-wrap;font:14px/1.6 Georgia,serif}</style><pre>${esc(summaryText(c))}</pre>`], { type: 'text/html' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `scam-bunker-case-${c.id}.html`; a.click();
  });

  function toast(m) { const t = $('#toast'); t.textContent = m; t.classList.add('show'); clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove('show'), 2600); }

  // Public API for feature modules (public/*.js) — see CONTRIBUTING.md
  window.ScamBunker = { get current() { return current; }, esc, post, toast, panel, showTab, store, renderAll: () => current && renderAll(current), server: () => server };

  init();
})();
