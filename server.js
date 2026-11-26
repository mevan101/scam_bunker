// Scam Bunker — investigation server. Zero dependencies: `node server.js`
// AI provider (first match wins): ANTHROPIC_API_KEY · LLM_BASE_URL (+LLM_API_KEY, LLM_MODEL) for any OpenAI-compatible API
// (Groq, OpenRouter, LM Studio…) · a local Ollama, detected automatically. With none, the claude.ai handoff still works.
// Optional: FIRECRAWL_API_KEY (web fetch + corroboration search)
const http = require('http');
const fs = require('fs');
const path = require('path');
const net = require('net');
const dns = require('dns').promises;

const PORT = process.env.PORT || 4400;
const HOST = process.env.HOST || '127.0.0.1'; // localhost only by default, so others on your network can't spend your API key
const PUB = path.join(__dirname, 'public');
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY || '';
const ANTHROPIC_URL = (process.env.ANTHROPIC_BASE_URL || 'https://api.anthropic.com').replace(/\/$/, '') + '/v1/messages';
const FIRECRAWL_KEY = process.env.FIRECRAWL_API_KEY || '';
const LLM_BASE_URL = (process.env.LLM_BASE_URL || '').replace(/\/$/, '');
const LLM_API_KEY = process.env.LLM_API_KEY || '';
const OLLAMA_URL = (process.env.OLLAMA_URL || 'http://127.0.0.1:11434').replace(/\/$/, '');

// Resolved at startup by detectProvider()
const provider = { kind: 'none', label: 'none', leadModel: '', agentModel: '', vision: false };
async function detectProvider() {
  if (ANTHROPIC_KEY) {
    Object.assign(provider, { kind: 'anthropic', label: 'Claude API', vision: true,
      leadModel: process.env.DEDUCE_LEAD_MODEL || 'claude-opus-5-5', agentModel: process.env.DEDUCE_AGENT_MODEL || 'claude-sonnet-5-5' });
  } else if (LLM_BASE_URL) {
    const m = process.env.LLM_MODEL || process.env.DEDUCE_AGENT_MODEL || '';
    Object.assign(provider, { kind: 'openai', label: new URL(LLM_BASE_URL).hostname, base: LLM_BASE_URL, key: LLM_API_KEY,
      leadModel: process.env.DEDUCE_LEAD_MODEL || m, agentModel: m, vision: process.env.LLM_VISION === '1' });
  } else {
    try {
      const r = await fetch(`${OLLAMA_URL}/api/tags`, { signal: AbortSignal.timeout(1500) });
      const models = ((await r.json()).models || []).map(x => x.name);
      if (models.length) {
        const pref = process.env.OLLAMA_MODEL || models.find(n => /vision|llava|gemma3|qwen2\.5vl|minicpm-v|llama4/i.test(n)) || models[0];
        Object.assign(provider, { kind: 'openai', label: `Ollama (${pref})`, base: `${OLLAMA_URL}/v1`, key: 'ollama',
          leadModel: pref, agentModel: pref, vision: /vision|llava|gemma3|vl|minicpm-v|llama4/i.test(pref) });
      }
    } catch { /* no local Ollama */ }
  }
}

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.json': 'application/json' };

// ---------- Agent roster ----------
const AGENTS = {
  forensics: {
    name: 'Image Forensics',
    brief: `You are the image forensics specialist. You receive extracted metadata (EXIF/XMP/IPTC/C2PA/PNG text chunks), pixel statistics, error-level-analysis stats and, when provided, the image itself.
Determine: (1) earliest defensible date the image existed and which evidence supports it, (2) whether it is AI-generated or AI-edited (name the generator if metadata or visual artifacts indicate one), (3) signs of manipulation or compositing, (4) signs it was re-uploaded from a social platform (stripped metadata, platform resize dimensions, FBMD markers), (5) what is hidden in metadata that the poster may not realise is exposed (GPS, device, software, author, prompts).
Visual AI tells to check: hands/fingers, text and signage, earrings/teeth/eyes symmetry, background geometry, skin that is too smooth, lighting inconsistent with shadows, repeating textures.
Be calibrated: absence of metadata is NOT proof of AI. Distinguish proof from weak signals.`,
  },
  scam: {
    name: 'Fraud Analyst',
    brief: `You are the fraud and scam analyst. Classify the post/message into a scheme type: phishing, investment/crypto, romance/pig-butchering, job/recruitment, giveaway/prize, impersonation (brand or person), marketplace/payment, tech-support, advance-fee, recovery-scam, account-takeover, or not-a-scam.
Explain the playbook stage (hook, trust-building, urgency, payment ask), the payment rails requested, and what the victim would lose. Rate confidence honestly.`,
  },
  osint: {
    name: 'OSINT & Platform Analyst',
    brief: `You are the OSINT and platform-behaviour analyst covering Facebook, Instagram, X/Twitter, LinkedIn, TikTok, Telegram, WhatsApp, Reddit, YouTube and forums.
Assess: how this kind of content is typically spread on the detected platform, account-authenticity signals (handle patterns, lookalike names, new accounts, link-in-bio redirection, off-platform moves to WhatsApp/Telegram), signs of coordinated inauthentic behaviour (copy-paste text, hashtag stuffing, engagement bait, bot amplification, co-posting networks), and what is hidden in links (redirect chains, shorteners, lookalike domains, tracking parameters).
List concrete pivots the investigator should run next (reverse image search, handle search across platforms, WHOIS/domain age, wallet lookups on block explorers, archive.org snapshots).`,
  },
  factcheck: {
    name: 'Fact Checker',
    brief: `You are the fact-checker. Extract every checkable factual claim. For each, state whether it is supported, contradicted, unverifiable, or missing context, using the corroboration search results when provided and your own knowledge (state your knowledge may be out of date). Flag manipulation techniques: false attribution, out-of-context media, fabricated quotes, misleading statistics, emotional manipulation, appeals to urgency ("share before it's deleted").`,
  },
};

const LEAD_BRIEF = `You are the lead investigator, a consulting detective in the tradition of Sherlock Holmes: observe precisely, separate observation from inference, reason from the smallest detail, eliminate the impossible, and never overstate certainty. You receive the case file and the written reports of your specialist agents. Cross-examine them: where they disagree, say who is right and why. Then deliver the verdict.

Respond with ONLY a JSON object, no prose outside it:
{
 "verdict": one of ["Scam","Likely scam","Suspicious","Misleading / manipulated","Coordinated / inauthentic","AI-generated content","Likely legitimate","Insufficient evidence"],
 "category": short scheme or content type,
 "confidence": integer 0-100,
 "risk": integer 0-100,
 "headline": one sentence a non-expert understands,
 "deduction": 3-6 sentence chain of reasoning in your voice, citing specific evidence,
 "observations": [ { "fact": string, "inference": string, "weight": "strong"|"moderate"|"weak" } ],
 "disagreements": [string],
 "image_dating": { "earliest": string or null, "basis": string },
 "ai_involvement": { "assessment": "none detected"|"possible"|"likely"|"confirmed", "basis": string },
 "hidden_info": [string],
 "next_steps": [string],
 "advice": string (what the person should do now)
}`;

// ---------- Helpers ----------
function send(res, code, body, type = 'application/json') {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}
function readBody(req, limit = 12 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > limit) { reject(new Error('Body too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}

// One call shape for every provider. content: [{type:'text',text}|{type:'image',dataUrl}]
async function llm({ lead = false, system, content, maxTokens = 1800 }) {
  const model = lead ? provider.leadModel : provider.agentModel;
  if (provider.kind === 'anthropic') return claude({ model, system, maxTokens, content: content.map(c => {
    if (c.type !== 'image') return c;
    const m = /^data:(image\/[a-z+]+);base64,(.*)$/.exec(c.dataUrl);
    return { type: 'image', source: { type: 'base64', media_type: m[1], data: m[2] } };
  }) });
  if (provider.kind !== 'openai') throw new Error('No AI provider configured');
  const call = async (withImages) => {
    const parts = content.filter(c => withImages || c.type !== 'image').map(c => c.type === 'image' ? { type: 'image_url', image_url: { url: c.dataUrl } } : { type: 'text', text: c.text });
    const r = await fetch(`${provider.base}/chat/completions`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...(provider.key ? { Authorization: `Bearer ${provider.key}` } : {}) },
      body: JSON.stringify({ model, max_tokens: maxTokens, temperature: 0.2, messages: [{ role: 'system', content: system }, { role: 'user', content: parts.length === 1 ? parts[0].text : parts }] }),
      signal: AbortSignal.timeout(300000),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j?.error?.message || j?.error || `${provider.label} ${r.status}`);
    return j.choices?.[0]?.message?.content || '';
  };
  const hasImage = content.some(c => c.type === 'image');
  if (hasImage && provider.vision) { try { return await call(true); } catch { /* model can't see images: fall back to text */ } }
  return call(false);
}

async function claude({ model, system, content, maxTokens = 1800 }) {
  const r = await fetch(ANTHROPIC_URL, {
    method: 'POST',
    headers: { 'x-api-key': ANTHROPIC_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model, max_tokens: maxTokens, system, messages: [{ role: 'user', content }] }),
  });
  const j = await r.json();
  if (!r.ok) throw new Error(j?.error?.message || `Anthropic API ${r.status}`);
  return (j.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n');
}

function caseFileText(c) {
  const parts = [];
  if (c.persona) parts.push(`INVESTIGATOR PROFILE (the person you work for, their focus and methods):\n${c.persona}`);
  if (c.platform) parts.push(`PLATFORM: ${c.platform}`);
  if (c.url) parts.push(`SOURCE URL: ${c.url}`);
  if (c.text) parts.push(`POST / MESSAGE TEXT:\n"""${c.text.slice(0, 12000)}"""`);
  if (c.page) parts.push(`FETCHED PAGE CONTENT (truncated):\n"""${String(c.page).slice(0, 8000)}"""`);
  if (c.heuristics) parts.push(`LOCAL HEURISTIC ENGINE RESULTS:\n${JSON.stringify(c.heuristics).slice(0, 6000)}`);
  if (c.forensics) parts.push(`IMAGE FORENSICS EXTRACTION:\n${JSON.stringify(c.forensics).slice(0, 9000)}`);
  if (c.corroboration) parts.push(`WEB CORROBORATION SEARCH RESULTS:\n${JSON.stringify(c.corroboration).slice(0, 5000)}`);
  return parts.join('\n\n');
}

// ---------- Routes ----------
async function handleAgent(req, res) {
  if (provider.kind === 'none') return send(res, 400, { error: 'No AI provider configured' });
  const body = await readBody(req);
  const agent = AGENTS[body.agent];
  if (!agent) return send(res, 400, { error: 'unknown agent' });
  const content = [];
  if (body.agent === 'forensics' && body.case?.imageData) {
    if (/^data:image\/[a-z+]+;base64,/.test(body.case.imageData)) content.push({ type: 'image', dataUrl: body.case.imageData });
  }
  content.push({ type: 'text', text: `CASE FILE\n\n${caseFileText(body.case || {})}\n\nWrite your specialist report: findings with evidence, confidence per finding, and open questions. Under 400 words. Plain text, short headed sections.` });
  const text = await llm({ system: agent.brief, content, maxTokens: 1400 });
  send(res, 200, { agent: body.agent, name: agent.name, report: text });
}

async function handleLead(req, res) {
  if (provider.kind === 'none') return send(res, 400, { error: 'No AI provider configured' });
  const body = await readBody(req);
  const reports = (body.reports || []).map(r => `=== ${r.name} ===\n${r.report}`).join('\n\n');
  const raw = await llm({
    lead: true, system: LEAD_BRIEF, maxTokens: 2500,
    content: [{ type: 'text', text: `CASE FILE\n\n${caseFileText(body.case || {})}\n\nSPECIALIST REPORTS\n\n${reports}` }],
  });
  let parsed = null;
  try { parsed = JSON.parse(raw.slice(raw.indexOf('{'), raw.lastIndexOf('}') + 1)); } catch { /* fall through */ }
  send(res, 200, parsed ? { verdict: parsed } : { raw });
}

// SSRF guard: only fetch public internet hosts, never localhost / LAN / cloud metadata.
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
  }
  const v = ip.toLowerCase();
  if (v.startsWith('::ffff:')) return isPrivateIp(v.slice(7));
  return v === '::' || v === '::1' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80');
}
async function assertPublicUrl(u) {
  const { protocol, hostname } = new URL(u);
  if (!/^https?:$/.test(protocol)) throw new Error('Only http(s) URLs can be fetched');
  const host = hostname.replace(/^\[|\]$/g, '');
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  if (!addrs.length || addrs.some(a => isPrivateIp(a.address))) throw new Error('Refusing to fetch a private or local network address');
}

// Builds a single self-contained prompt that runs the whole agent team inside one chat (claude.ai, or any assistant).
async function handlePrompt(req, res) {
  const body = await readBody(req);
  const roles = Object.values(AGENTS).map((a, i) => `### Specialist ${i + 1}: ${a.name}\n${a.brief}`).join('\n\n');
  const prompt = `You are running a multi-agent fraud & disinformation investigation called Scam Bunker. Play every role below in turn, then act as the lead investigator.

${roles}

### Lead investigator
${LEAD_BRIEF.split('Respond with ONLY')[0].trim()}

HOW TO ANSWER
1. Write each specialist's report under its own heading (under 200 words each). Where a specialist cannot see something (e.g. the image), say so and rely on the extracted data.
2. Then "## Cross-examination": where specialists disagree, decide who is right and why.
3. Then "## Verdict": one of Scam / Likely scam / Suspicious / Misleading / Coordinated / AI-generated / Likely legitimate / Insufficient evidence, plus category, risk 0-100, confidence 0-100.
4. Then "## Observation → Inference" table, "## Hidden information", "## Next pivots", "## What the person should do now".
${body.hasImage ? '\nIf I attach the image, examine it visually too (hands, text, lighting, shadows, textures, edges).\n' : ''}
CASE FILE

${caseFileText(body.case || {})}`;
  send(res, 200, { prompt });
}

async function handleFetch(req, res) {
  const { url } = await readBody(req);
  if (!/^https?:\/\//i.test(url || '')) return send(res, 400, { error: 'invalid url' });
  if (FIRECRAWL_KEY) {
    const r = await fetch('https://api.firecrawl.dev/v2/scrape', {
      method: 'POST', headers: { Authorization: `Bearer ${FIRECRAWL_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, formats: ['markdown', 'links'], onlyMainContent: true }),
    });
    const j = await r.json();
    if (r.ok && j.data) return send(res, 200, { via: 'firecrawl', title: j.data.metadata?.title, markdown: (j.data.markdown || '').slice(0, 20000), metadata: j.data.metadata, links: (j.data.links || []).slice(0, 80) });
  }
  // Plain fetch fallback: follow redirects manually so the chain is visible
  const chain = []; let cur = url; let html = ''; let status = 0;
  for (let i = 0; i < 8; i++) {
    await assertPublicUrl(cur); // re-checked on every redirect hop
    const r = await fetch(cur, { redirect: 'manual', headers: { 'User-Agent': 'Mozilla/5.0 (compatible; DeduceInvestigator/1.0)' }, signal: AbortSignal.timeout(12000) });
    status = r.status; chain.push({ url: cur, status });
    const loc = r.headers.get('location');
    if (status >= 300 && status < 400 && loc) { cur = new URL(loc, cur).href; continue; }
    html = (await r.text()).slice(0, 400000); break;
  }
  const meta = {};
  for (const m of html.matchAll(/<meta\s+[^>]*(?:property|name)=["']([^"']+)["'][^>]*content=["']([^"']*)["'][^>]*>/gi)) meta[m[1]] = m[2];
  const title = (/<title[^>]*>([^<]*)<\/title>/i.exec(html) || [])[1];
  const text = html.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 15000);
  send(res, 200, { via: 'direct', title, status, redirects: chain, metadata: meta, markdown: text });
}

async function handleSearch(req, res) {
  if (!FIRECRAWL_KEY) return send(res, 400, { error: 'FIRECRAWL_API_KEY not set' });
  const { query } = await readBody(req);
  const r = await fetch('https://api.firecrawl.dev/v2/search', {
    method: 'POST', headers: { Authorization: `Bearer ${FIRECRAWL_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: String(query).slice(0, 300), limit: 6 }),
  });
  const j = await r.json();
  const web = j?.data?.web || j?.data || [];
  send(res, 200, { results: (Array.isArray(web) ? web : []).map(w => ({ title: w.title, url: w.url, description: w.description })) });
}

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/api/status') return send(res, 200, { ai: provider.kind !== 'none', provider: provider.label, vision: provider.vision, firecrawl: !!FIRECRAWL_KEY, leadModel: provider.leadModel, agentModel: provider.agentModel, agents: Object.entries(AGENTS).map(([id, a]) => ({ id, name: a.name })) });
    if (req.method === 'POST' && u.pathname === '/api/agent') return await handleAgent(req, res);
    if (req.method === 'POST' && u.pathname === '/api/lead') return await handleLead(req, res);
    if (req.method === 'POST' && u.pathname === '/api/prompt') return await handlePrompt(req, res);
    if (req.method === 'POST' && u.pathname === '/api/fetch') return await handleFetch(req, res);
    if (req.method === 'POST' && u.pathname === '/api/search') return await handleSearch(req, res);
    let p = path.normalize(path.join(PUB, u.pathname === '/' ? 'index.html' : u.pathname));
    if (p !== PUB && !p.startsWith(PUB + path.sep)) return send(res, 403, 'forbidden', 'text/plain');
    fs.readFile(p, (err, data) => {
      if (err) return send(res, 404, 'not found', 'text/plain');
      res.writeHead(200, { 'Content-Type': MIME[path.extname(p)] || 'application/octet-stream' });
      res.end(data);
    });
  } catch (e) {
    send(res, 502, { error: e.cause?.code ? `${e.message} (${e.cause.code})` : e.message });
  }
});

detectProvider().then(() => server.listen(PORT, HOST, () => {
  console.log(`Scam Bunker running → http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log(`  Agent team: ${provider.kind === 'none' ? 'off: install Ollama, or set ANTHROPIC_API_KEY / LLM_BASE_URL (claude.ai handoff still works)' : provider.label + (provider.vision ? ' · vision' : '')}`);
  console.log(`  Firecrawl: ${FIRECRAWL_KEY ? 'ON' : 'off (optional)'}`);
}));
