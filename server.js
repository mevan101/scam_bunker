// Scam Bunker — investigation server. Zero dependencies: `node server.js`
// AI provider (first match wins): ANTHROPIC_API_KEY · LLM_BASE_URL (+LLM_API_KEY, LLM_MODEL) for any OpenAI-compatible API
// (Groq, OpenRouter, LM Studio…) · a local Ollama, detected automatically. With none, the claude.ai handoff still works.
// Optional: FIRECRAWL_API_KEY (web fetch + corroboration search) · SERPAPI_API_KEY (automatic reverse image search)
// · ETHERSCAN_API_KEY · TRONGRID_API_KEY / TRONSCAN_API_KEY (optional, wallet lookups in server/osint.js)
const http = require('http');
const fs = require('fs');
const path = require('path');
const { assertPublicUrl } = require('./server/net-guard');
const provenance = require('./server/provenance');
const factcheck = require('./server/factcheck');
const corroborate = require('./server/corroborate');
const events = require('./server/events');
const osint = require('./server/osint');

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
const { AGENTS, LEAD_BRIEF, caseFileText: sharedCaseFileText, buildHandoffPrompt } = require('./public/shared/prompt');


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

const caseFileText = (c) => sharedCaseFileText(c, factcheck.caseFileSections);

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

// SSRF guard (isPrivateIp / assertPublicUrl) lives in server/net-guard.js, shared with the provenance endpoints.

// Builds a single self-contained prompt that runs the whole agent team inside one chat (claude.ai, or any assistant).
async function handlePrompt(req, res) {
  const body = await readBody(req);
  send(res, 200, { prompt: buildHandoffPrompt(body, factcheck.caseFileSections) });
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

// ---------- Dev mode (`npm run dev`): live reload ----------
// The browser holds an SSE connection; any change under public/ tells it to reload. `node --watch` restarts the
// server on server-side changes, and the page reloads when it reconnects to a server with a new boot id.
const DEV = process.argv.includes('--dev');
const BOOT_ID = Date.now().toString(36);
const devClients = new Set();
if (DEV) {
  let t = null;
  try {
    fs.watch(PUB, { recursive: true }, () => { clearTimeout(t); t = setTimeout(() => devClients.forEach(r => r.write('data: reload\n\n')), 80); });
  } catch (e) { console.warn('  Live reload: file watching unavailable (' + e.message + ')'); }
}
const DEV_SNIPPET = `<script>(function(){var boot=null;function c(){var es=new EventSource('/__dev/reload');es.addEventListener('boot',function(e){if(boot&&boot!==e.data)location.reload();boot=e.data});es.onmessage=function(){location.reload()};es.onerror=function(){es.close();setTimeout(c,500)}}c()})();</script>`;

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://x');
    if (DEV && u.pathname === '/__dev/reload') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive' });
      res.write(`event: boot\ndata: ${BOOT_ID}\n\n`);
      devClients.add(res); req.on('close', () => devClients.delete(res));
      return;
    }
    if (u.pathname === '/api/status') return send(res, 200, { ai: provider.kind !== 'none', provider: provider.label, vision: provider.vision, firecrawl: !!FIRECRAWL_KEY, reverseSearch: provenance.reverseAvailable(), leadModel: provider.leadModel, agentModel: provider.agentModel, agents: Object.entries(AGENTS).map(([id, a]) => ({ id, name: a.name })) });
    if (req.method === 'POST' && u.pathname === '/api/agent') return await handleAgent(req, res);
    if (req.method === 'POST' && u.pathname === '/api/lead') return await handleLead(req, res);
    if (req.method === 'POST' && u.pathname === '/api/prompt') return await handlePrompt(req, res);
    if (req.method === 'POST' && u.pathname === '/api/fetch') return await handleFetch(req, res);
    if (req.method === 'POST' && u.pathname === '/api/search') return await handleSearch(req, res);
    if (req.method === 'POST' && osint.routes[u.pathname]) return await osint.routes[u.pathname](await readBody(req, 64 * 1024), res, send);
    if (req.method === 'POST' && factcheck.routes[u.pathname]) return send(res, 200, await factcheck.routes[u.pathname](await readBody(req)));
    if (req.method === 'POST' && u.pathname === '/api/events/extract') return send(res, 200, await events.extractFromUrl((await readBody(req)).url));
    if (req.method === 'POST' && provenance.routes[u.pathname]) return send(res, 200, await provenance.routes[u.pathname](await readBody(req)));
    if (req.method === 'POST' && corroborate.routes[u.pathname]) return send(res, 200, await corroborate.routes[u.pathname](await readBody(req)));
    let p = path.normalize(path.join(PUB, u.pathname === '/' ? 'index.html' : u.pathname));
    if (p !== PUB && !p.startsWith(PUB + path.sep)) return send(res, 403, 'forbidden', 'text/plain');
    fs.readFile(p, (err, data) => {
      if (err) return send(res, 404, 'not found', 'text/plain');
      const type = MIME[path.extname(p)] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': type, ...(DEV ? { 'Cache-Control': 'no-store' } : {}) });
      res.end(DEV && type.startsWith('text/html') ? data.toString().replace('</body>', DEV_SNIPPET + '</body>') : data);
    });
  } catch (e) {
    send(res, e.status || 502, { error: e.cause?.code ? `${e.message} (${e.cause.code})` : e.message, ...(e.code && typeof e.code === 'string' && e.status ? { code: e.code } : {}), ...(e.contentType ? { contentType: e.contentType } : {}) });
  }
});

detectProvider().then(() => server.listen(PORT, HOST, () => {
  console.log(`Scam Bunker running → http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log(`  Agent team: ${provider.kind === 'none' ? 'off: install Ollama, or set ANTHROPIC_API_KEY / LLM_BASE_URL (claude.ai handoff still works)' : provider.label + (provider.vision ? ' · vision' : '')}`);
  if (DEV) console.log('  Dev mode: live reload on — edit files under public/ and the page refreshes itself');
  console.log(`  Firecrawl: ${FIRECRAWL_KEY ? 'ON' : 'off (optional)'}`);
}));
