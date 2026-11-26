// Local API gate, connect-time SSRF guard, body caps and linear HTML scanning. Zero dependencies: node --test
// Hostnames are invented (*.test); every server is local.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http'), net = require('net'), path = require('path'), zlib = require('zlib');
const { spawn } = require('child_process');
const { guardedRequest } = require('../server/net-guard');
const osint = require('../server/osint');
const ev = require('../server/events');
const scan = require('../server/html-scan');

const freePort = () => new Promise(r => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const listen = handler => new Promise(r => { const s = http.createServer(handler); s.listen(0, '127.0.0.1', () => r(s)); });
// A stubbed resolver: name → address, with the dns.lookup callback shape guardedRequest uses.
const resolver = map => (host, opts, cb) => map[host] ? cb(null, [{ address: map[host], family: 4 }]) : cb(Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }));

async function startApp(env = {}, args = []) {
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js'), ...args], {
    env: { PATH: process.env.PATH, PORT: String(port), OLLAMA_URL: 'http://127.0.0.1:9', ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise((resolve, reject) => {
    let out = '';
    child.stdout.on('data', d => { out += d; if (out.includes('running')) resolve(); });
    child.on('exit', c => reject(new Error(`server exited ${c}: ${out}`)));
  });
  return { port, stop: () => child.kill() };
}
// Raw request so Host / Origin can be set to anything, as a rebinding page or a cross-site form would.
function req(port, { method = 'GET', path: p = '/api/status', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers, setHost: !('Host' in headers) }, res => {
      let data = ''; res.on('data', c => { data += c; if (res.headers['content-type'] === 'text/event-stream') res.destroy(); });
      const end = () => { let json = null; try { json = JSON.parse(data); } catch { /* not JSON */ } resolve({ status: res.statusCode, type: res.headers['content-type'], json }); };
      res.on('end', end); res.on('close', end);
    });
    r.on('error', reject); r.end(body);
  });
}

test('local API: foreign Host, foreign Origin and non-JSON POSTs are refused before routing', async () => {
  const app = await startApp();
  const own = `localhost:${app.port}`;
  try {
    for (const h of [own, `127.0.0.1:${app.port}`, `[::1]:${app.port}`]) assert.equal((await req(app.port, { headers: { Host: h } })).status, 200, h);
    for (const h of [`rebind.test:${app.port}`, 'localhost:9999', 'localhost', `127.0.0.1.rebind.test:${app.port}`, '']) {
      const r = await req(app.port, { headers: { Host: h } });
      assert.equal(r.status, 403, `Host ${h || '(empty)'}`); assert.equal(r.json.code, 'request_refused');
    }
    assert.equal((await req(app.port, { headers: { Host: own, Origin: `http://${own}` } })).status, 200, 'same origin');
    for (const o of ['http://evil.test', 'null', `https://${own}`, `http://127.0.0.1:${app.port}`]) assert.equal((await req(app.port, { headers: { Host: own, Origin: o } })).status, 403, `Origin ${o}`);
    const body = JSON.stringify({ case: { input: 'hello' } });
    for (const t of ['text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x', undefined]) {
      const r = await req(app.port, { method: 'POST', path: '/api/prompt', headers: { Host: own, ...(t ? { 'Content-Type': t } : {}) }, body });
      assert.equal(r.status, 415, `Content-Type ${t}`);
    }
    const ok = await req(app.port, { method: 'POST', path: '/api/prompt', headers: { Host: own, Origin: `http://${own}`, 'Content-Type': 'application/json; charset=utf-8' }, body });
    assert.equal(ok.status, 200); assert.equal(typeof ok.json.prompt, 'string');
    // Static files are still served; the gate covers /api/* and /__dev/*.
    assert.equal((await req(app.port, { path: '/', headers: { Host: own } })).status, 200);
    // /api/fetch to a loopback name is refused at connect time.
    const f = await req(app.port, { method: 'POST', path: '/api/fetch', headers: { Host: own, 'Content-Type': 'application/json' }, body: JSON.stringify({ url: `http://localhost:${app.port}/api/status` }) });
    assert.equal(f.status, 403); assert.match(f.json.error, /private or local/);
  } finally { app.stop(); }
});

test('local API: HOST=0.0.0.0 accepts any Host but still refuses cross-origin and non-JSON requests; dev reload stays same-origin', async () => {
  const lan = await startApp({ HOST: '0.0.0.0' });
  try {
    assert.equal((await req(lan.port, { headers: { Host: `192.0.2.10:${lan.port}` } })).status, 200);
    assert.equal((await req(lan.port, { headers: { Host: `192.0.2.10:${lan.port}`, Origin: 'http://evil.test' } })).status, 403);
    assert.equal((await req(lan.port, { method: 'POST', path: '/api/prompt', headers: { Host: `192.0.2.10:${lan.port}`, 'Content-Type': 'text/plain' }, body: '{}' })).status, 415);
  } finally { lan.stop(); }
  const dev = await startApp({}, ['--dev']);
  try {
    const own = `localhost:${dev.port}`;
    const live = await req(dev.port, { path: '/__dev/reload', headers: { Host: own, Origin: `http://${own}` } });
    assert.equal(live.status, 200); assert.equal(live.type, 'text/event-stream');
    assert.equal((await req(dev.port, { path: '/__dev/reload', headers: { Host: `rebind.test:${dev.port}` } })).status, 403);
  } finally { dev.stop(); }
});

test('rebinding: the address is checked at connect time, on every hop, whatever an earlier lookup said', async () => {
  let calls = 0;
  const flip = (host, opts, cb) => cb(null, [{ address: calls++ === 0 ? '93.184.216.34' : '127.0.0.1', family: 4 }]); // public first, then loopback
  flip('rebind.test', {}, () => {}); // a resolve-then-check pre-flight would have seen the public answer
  await assert.rejects(guardedRequest('http://rebind.test/', { resolve: flip }), e => e.code === 'ssrf_blocked');
  await assert.rejects(guardedRequest('http://rebind.test/', { resolve: resolver({ 'rebind.test': '169.254.169.254' }) }), e => e.code === 'ssrf_blocked');
  await assert.rejects(guardedRequest('http://[::ffff:7f00:1]/'), e => e.code === 'ssrf_blocked');
  // A public-looking first hop that redirects to a name resolving to a private address is refused on the second hop.
  const srv = await listen((q, s) => { s.writeHead(302, { Location: `http://inner.test:${srv.address().port}/` }); s.end(); });
  const port = srv.address().port;
  const opts = { resolve: resolver({ 'outer.test': '127.0.0.1', 'inner.test': '10.0.0.7' }), isBlocked: ip => ip.startsWith('10.') }; // test server stands in for a public host
  try {
    await assert.rejects(guardedRequest(`http://outer.test:${port}/`, opts), e => e.code === 'ssrf_blocked');
    await assert.rejects(osint.guardedFetch(`http://outer.test:${port}/`, opts), e => e.code === 'ssrf_blocked');
    await assert.rejects(ev.fetchFollow(`http://outer.test:${port}/`, { ...opts, guard: async () => {} }), e => e.code === 'ssrf_blocked');
    const hop = await osint.guardedFetch(`http://outer.test:${port}/`, { ...opts, maxRedirects: 0 });
    assert.equal(hop.tooManyRedirects, true); assert.deepEqual(hop.redirects, [{ url: `http://outer.test:${port}/`, status: 302 }]);
  } finally { srv.close(); }
  // Default resolver: localhost is refused even when the caller skips its own pre-check.
  await assert.rejects(osint.guardedFetch('http://localhost:1/'), e => e.code === 'ssrf_blocked');
});

test('body caps: streamed and gzip-decoded bodies stop at maxBytes instead of filling memory', async () => {
  const MB = 1024 * 1024; let sent = 0;
  const srv = await listen((q, s) => {
    if (q.url === '/gzip') { s.writeHead(200, { 'content-type': 'text/html', 'content-encoding': 'gzip' }); return s.end(zlib.gzipSync(Buffer.alloc(20 * MB, 0x61))); }
    s.writeHead(200, { 'content-type': 'text/html' }); // no content-length: the cap must work on the stream
    const chunk = Buffer.alloc(64 * 1024, 0x61);
    const pump = () => { while (sent < 50 * MB) { sent += chunk.length; if (!s.write(chunk)) return s.once('drain', pump); } s.end(); };
    pump();
  });
  const base = `http://127.0.0.1:${srv.address().port}`, open = { isBlocked: () => false };
  try {
    const t = await guardedRequest(base + '/', { ...open, maxBytes: 2 * MB, truncate: true });
    assert.equal(t.buffer.length, 2 * MB); assert.ok(sent < 20 * MB, `stopped reading early (${sent} bytes sent)`);
    await assert.rejects(guardedRequest(base + '/', { ...open, maxBytes: 2 * MB }), e => e.code === 'too_large');
    const g = await guardedRequest(base + '/gzip', { ...open, maxBytes: 2 * MB, truncate: true, decompress: true });
    assert.equal(g.buffer.length, 2 * MB, 'cap applies to the decoded body');
    assert.equal((await osint.guardedFetch(base + '/', open)).body.length, 256 * 1024);
    assert.equal((await ev.fetchFollow(base + '/gzip', { ...open, guard: async () => {}, maxBytes: 1500000 })).body.length, 1500000);
    await assert.rejects(guardedRequest(base + '/', { ...open, timeoutMs: 1, maxBytes: 100 * MB }), e => e.code === 'timeout' || e.code === 'too_large');
  } finally { srv.close(); }
});

test('HTML scanning is linear on pathological input (unclosed script/style/head/JSON-LD/meta)', () => {
  const N = 1500000;
  const hostile = {
    script: '<script'.repeat(N / 7), style: '<style>'.repeat(N / 7), head: '<head>'.repeat(N / 6), noscript: '<noscript>'.repeat(N / 10),
    jsonld: '<script type="application/ld+json">'.repeat(N / 36), meta: '<meta property="og:title" content="x" '.repeat(N / 40),
    anchors: '<a href="'.repeat(N / 9), lt: '<'.repeat(N), h1: '<h1>'.repeat(N / 4), title: '<title>'.repeat(N / 7),
  };
  for (const [name, html] of Object.entries(hostile)) {
    const t0 = Date.now();
    ev.extractFromHtml(html, { baseUrl: 'https://example.org/e/1' });
    scan.htmlText(html, { skip: ['script', 'style'] }); scan.tagsNamed(html, ['meta']); scan.firstElement(html, 'title');
    const ms = Date.now() - t0;
    assert.ok(ms < 3000, `${name}: ${ms} ms`);
  }
});

test('HTML scanning keeps the old results on ordinary pages', () => {
  const html = '<html><head><title>Prize &amp; draw</title><meta property="og:title" content="Win now"><meta name=description content=\'Claim it\'></head>' +
    '<body><script>var a = "</div>";</script><style>p{}</style><p>Pay the <b>fee</b></p><noscript>enable js</noscript>1 < 2</body></html>';
  assert.equal(scan.firstElement(html, 'title'), 'Prize &amp; draw');
  assert.deepEqual(scan.tagsNamed(html, ['meta']).map(t => scan.tagAttrs(t).content), ['Win now', 'Claim it']);
  assert.equal(scan.htmlText(html, { skip: ['script', 'style'] }).replace(/\s+/g, ' ').trim(), 'Prize &amp; draw Pay the fee enable js 1 < 2');
  assert.equal(scan.htmlText(html, { breaks: new Set(['p']) }).replace(/\s*\n\s*/g, '\n').replace(/ +/g, ' ').trim(), 'Pay the fee\n1 < 2');
  assert.equal(scan.htmlText('<script>a</script', { skip: ['script'] }).trim(), '');
  assert.deepEqual(scan.rawElements('<script type="application/ld+json">{"a":1}</script>', 'script'), [{ tag: '<script type="application/ld+json">', content: '{"a":1}', closed: true }]);
});

test('decoding: stacked Content-Encoding and raw or zlib deflate are decoded; unknown codings are left as is', async () => {
  const text = '<title>Decoded</title>'.repeat(50);
  const bodies = {
    '/stacked': ['gzip, br', zlib.brotliCompressSync(zlib.gzipSync(text))],
    '/raw': ['deflate', zlib.deflateRawSync(text)], '/zlib': ['deflate', zlib.deflateSync(text)],
    '/unknown': ['gzip, zstd', Buffer.from(text)],
  };
  const srv = await listen((q, s) => { const [enc, b] = bodies[q.url]; s.writeHead(200, { 'content-type': 'text/html', 'content-encoding': enc }); s.end(b); });
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    for (const p of Object.keys(bodies)) assert.equal((await guardedRequest(base + p, { isBlocked: () => false, decompress: true })).buffer.toString(), text, p);
  } finally { srv.close(); }
});
