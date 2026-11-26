// Zero-dependency tests for the installable/offline app: the Pages build injects a content-hash cache version and
// the app shell list into sw.js; sw.js parses and routes requests correctly (never /api/*, never cross-origin);
// manifest + icons are valid; pwa.js registers only in static mode on a secure origin. Run: npm test
const fs = require('fs'), path = require('path'), os = require('os'), vm = require('vm'), assert = require('assert');
const { build, buildVersion } = require('../scripts/build-pages');
const { render, ICONS } = require('../scripts/make-icons');

let failed = 0;
async function test(name, fn) {
  try { await fn(); console.log(`✓ ${name}`); } catch (e) { failed++; console.log(`✗ ${name}\n    ${e.stack.split('\n').slice(0, 4).join('\n    ')}`); }
}

const PUB = path.join(__dirname, '../public');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sb-pwa-'));
const out = path.join(tmp, 'site');
const built = build(out);
const builtSw = fs.readFileSync(path.join(out, 'sw.js'), 'utf8');
const srcSw = fs.readFileSync(path.join(PUB, 'sw.js'), 'utf8');

// ---- a minimal service-worker global scope ----
function swScope(src, { origin = 'https://example.test', scope = '/scam_bunker/', online = true } = {}) {
  const base = origin + scope, store = new Map(), handlers = {}, net = [];
  const key = (r) => typeof r === 'string' ? new URL(r, base).href : r.url;
  const cache = {
    match: async (r, o = {}) => { let k = key(r); if (o.ignoreSearch) k = k.split('?')[0]; const v = store.get(k); return v && v.clone(); },
    put: async (r, res) => { store.set(key(r), res); },
    addAll: async (rs) => { for (const r of rs) store.set(key(r), new Response('cached ' + key(r), { headers: { 'content-type': 'text/plain' } })); },
  };
  const Req = function (u, init) { return new Request(new URL(typeof u === 'string' ? u : u.url, base), init); };
  const self = {
    location: new URL(base + 'sw.js'), registration: { scope: base }, clients: { claim: async () => {} },
    skipWaiting: () => { self.skipped = true; }, addEventListener: (t, fn) => { handlers[t] = fn; },
  };
  const ctx = {
    self, Request: Req, Response, URL, Promise, console,
    caches: { open: async () => cache, keys: async () => [...ctx.cacheNames], delete: async (k) => { ctx.cacheNames.delete(k); return true; } },
    fetch: async (r) => { net.push(r.url); if (!online) throw new TypeError('offline'); const res = new Response('network ' + r.url); Object.defineProperty(res, 'type', { value: 'basic' }); return res; },
    cacheNames: new Set(),
  };
  vm.createContext(ctx); vm.runInContext(src, ctx);
  const fire = async (type, extra = {}) => {
    const waits = []; let responded = null;
    const ev = { ...extra, waitUntil: (p) => waits.push(p), respondWith: (p) => { responded = p; } };
    handlers[type](ev); await Promise.all(waits);
    const res = responded && await responded; await Promise.all(waits);
    return { responded: !!responded, res };
  };
  const req = (u, { mode, ...init } = {}) => { const r = new Request(new URL(u, base), init); if (mode === 'navigate') Object.defineProperty(r, 'mode', { value: 'navigate' }); return r; };
  return { ctx, self, store, net, handlers, fire, req, setOnline: (v) => { online = v; } };
}

(async () => {
  await test('source sw.js and built sw.js both parse', () => {
    new vm.Script(srcSw, { filename: 'public/sw.js' });
    new vm.Script(builtSw, { filename: '_site/sw.js' });
  });

  await test('build injects a 12-hex content-hash VERSION and the app shell ASSETS into sw.js', () => {
    assert.match(srcSw, /^const VERSION = 'dev';$/m);
    assert.match(built.version, /^[0-9a-f]{12}$/);
    assert.ok(builtSw.includes(`const VERSION = "${built.version}";`));
    const assets = JSON.parse(builtSw.match(/^const ASSETS = (.*);$/m)[1]);
    assert.deepStrictEqual(assets, built.assets);
    for (const f of ['./', './index.html', './app.js', './app.css', './shared/prompt.js', './manifest.webmanifest', './pwa.js', './icons/icon-192.png'])
      assert.ok(assets.includes(f), `${f} in app shell`);
    for (const f of fs.readdirSync(PUB).filter(f => /\.(js|css|html)$/.test(f) && f !== 'sw.js')) assert.ok(assets.includes('./' + f), `every public/${f} precached`);
    assert.ok(!assets.some(a => /404\.html|sw\.js|docs\/|\.nojekyll/.test(a)), 'no 404, sw.js, screenshots or .nojekyll');
  });

  await test('build refuses output dirs that would wipe the repo or its sources', () => {
    const repo = path.join(__dirname, '..');
    for (const d of [repo, path.join(repo, 'public'), path.join(repo, 'public/shared'), path.join(repo, 'test'), path.dirname(repo)])
      assert.throws(() => build(d), /refusing to wipe/, d);
    assert.throws(() => build('/'), /refusing to wipe/, 'filesystem root');
    const link = path.join(tmp, 'link-to-repo'); fs.symlinkSync(repo, link);
    for (const d of [link, path.join(link, 'public'), path.join(link, 'test', 'not-yet-there')]) assert.throws(() => build(d), /refusing to wipe/, 'via symlink ' + d);
    assert.doesNotThrow(() => build(path.join(link, '_site'))); fs.rmSync(path.join(repo, '_site'), { recursive: true, force: true });
    assert.ok(fs.existsSync(path.join(PUB, 'index.html')) && fs.existsSync(path.join(__dirname, 'pwa.test.js')), 'sources untouched');
  });

  await test('cache version is deterministic and changes when any file changes', () => {
    const copy = path.join(tmp, 'copy'); fs.cpSync(PUB, copy, { recursive: true });
    const v1 = buildVersion(copy);
    assert.strictEqual(buildVersion(copy), v1);
    fs.appendFileSync(path.join(copy, 'app.css'), '\n/* changed */');
    assert.notStrictEqual(buildVersion(copy), v1);
  });

  await test('fetch routing: /api/*, dev stream, POST, cross-origin and out-of-scope requests are never intercepted', async () => {
    const sw = swScope(builtSw);
    for (const [u, init] of [['/scam_bunker/api/status'], ['/api/status'], ['/scam_bunker/__dev/reload'], ['/scam_bunker/app.js', { method: 'POST', body: 'x' }],
      ['https://mempool.space/api/address/x'], ['https://fonts.googleapis.com/css2?family=IBM+Plex+Sans'], ['/other-site/index.html']]) {
      const r = await sw.fire('fetch', { request: sw.req(u, init) });
      assert.strictEqual(r.responded, false, `${u} must go straight to the network`);
    }
    // Also on a root-scoped deploy (local static server): /api/ is still excluded.
    const root = swScope(builtSw, { origin: 'http://localhost:8080', scope: '/' });
    assert.strictEqual((await root.fire('fetch', { request: root.req('/api/status') })).responded, false);
    assert.ok(![...sw.store.keys()].some(k => k.includes('/api/')));
  });

  await test('install precaches the shell; offline navigation falls back to cached index.html', async () => {
    const sw = swScope(builtSw, { online: false });
    await sw.fire('install');
    assert.ok(sw.store.has('https://example.test/scam_bunker/index.html'));
    assert.ok(sw.store.has('https://example.test/scam_bunker/shared/prompt.js'));
    const nav = await sw.fire('fetch', { request: sw.req('/scam_bunker/?case=1', { mode: 'navigate' }) });
    assert.ok(nav.responded); assert.match(await nav.res.text(), /^cached .*\/scam_bunker\/(index\.html)?$/);
    const deep = await sw.fire('fetch', { request: sw.req('/scam_bunker/some/deep/link', { mode: 'navigate' }) });
    assert.match(await deep.res.text(), /index\.html$/);
  });

  await test('HTML is network-first (and refreshes the cache); assets are stale-while-revalidate', async () => {
    const sw = swScope(builtSw);
    await sw.fire('install');
    const nav = await sw.fire('fetch', { request: sw.req('/scam_bunker/index.html', { mode: 'navigate' }) });
    assert.match(await nav.res.text(), /^network /);
    assert.match(await sw.store.get('https://example.test/scam_bunker/index.html').clone().text(), /^network /);
    const js = await sw.fire('fetch', { request: sw.req('/scam_bunker/app.js') });
    assert.match(await js.res.text(), /^cached /, 'served from cache first');
    assert.ok(sw.net.some(u => u.endsWith('/scam_bunker/app.js')), 'revalidated in the background');
    assert.match(await sw.store.get('https://example.test/scam_bunker/app.js').clone().text(), /^network /, 'cache updated for next time');
    const miss = await sw.fire('fetch', { request: sw.req('/scam_bunker/icons/new.png') });
    assert.match(await miss.res.text(), /^network /, 'cache miss goes to network');
  });

  await test('activate deletes only old scam-bunker caches; SKIP_WAITING message activates the waiting worker', async () => {
    const sw = swScope(builtSw);
    sw.ctx.cacheNames = new Set(['scam-bunker-old123', 'scam-bunker-' + built.version, 'someone-elses-cache']);
    await sw.fire('activate');
    assert.deepStrictEqual([...sw.ctx.cacheNames].sort(), ['scam-bunker-' + built.version, 'someone-elses-cache']);
    sw.handlers.message({ data: { type: 'other' } }); assert.ok(!sw.self.skipped);
    sw.handlers.message({ data: { type: 'SKIP_WAITING' } }); assert.ok(sw.self.skipped);
  });

  await test('manifest is valid and its icons exist with the declared sizes', () => {
    const m = JSON.parse(fs.readFileSync(path.join(PUB, 'manifest.webmanifest'), 'utf8'));
    for (const k of ['name', 'short_name', 'start_url', 'scope', 'display', 'theme_color', 'background_color']) assert.ok(m[k], k);
    assert.strictEqual(m.start_url, './'); assert.strictEqual(m.scope, './');
    const css = fs.readFileSync(path.join(PUB, 'app.css'), 'utf8');
    assert.ok(css.includes(`--bg: ${m.background_color};`), 'background_color comes from the --bg token');
    assert.ok(m.icons.some(i => i.sizes === '192x192' && i.type === 'image/png' && i.purpose === 'any'));
    assert.ok(m.icons.some(i => i.sizes === '512x512' && i.type === 'image/png' && i.purpose === 'any'));
    assert.ok(m.icons.some(i => i.purpose === 'maskable'));
    for (const i of m.icons) {
      const buf = fs.readFileSync(path.join(PUB, i.src));
      if (i.type !== 'image/png') { assert.match(buf.toString(), /^<svg /); continue; }
      assert.strictEqual(buf.subarray(1, 4).toString(), 'PNG');
      assert.strictEqual(`${buf.readUInt32BE(16)}x${buf.readUInt32BE(20)}`, i.sizes, i.src);
    }
  });

  await test('committed PNG icons match scripts/make-icons.js output', () => {
    for (const [name, size, opts] of ICONS) assert.ok(render(size, opts).equals(fs.readFileSync(path.join(PUB, 'icons', name))), `${name} is stale: run node scripts/make-icons.js`);
  });

  await test('index.html links the manifest, theme colours and pwa.js', () => {
    const html = fs.readFileSync(path.join(PUB, 'index.html'), 'utf8');
    assert.match(html, /<link rel="manifest" href="manifest\.webmanifest">/);
    assert.match(html, /<meta name="theme-color" content="#[0-9a-f]{6}" media="\(prefers-color-scheme: light\)">/);
    assert.match(html, /<meta name="theme-color" content="#[0-9a-f]{6}" media="\(prefers-color-scheme: dark\)">/);
    assert.match(html, /<script src="pwa\.js"><\/script>/);
  });

  // pwa.js under vm with a stubbed browser
  function runPwa({ dataStatic = false, secure = true, readyStatic = null, waiting = null } = {}) {
    const registered = [], listeners = {}, swListeners = {}, buttons = {}, state = { reloads: 0, appended: 0 };
    const reg = { waiting, addEventListener() {}, update: async () => {} };
    const el = () => ({ setAttribute() {}, remove() {}, querySelector: (sel) => (buttons[sel] = buttons[sel] || { addEventListener: (t, fn) => { buttons[sel].click = fn; } }) });
    const ctx = {
      window: { isSecureContext: secure }, console,
      navigator: { serviceWorker: { controller: waiting ? {} : null, addEventListener: (t, fn) => { swListeners[t] = fn; }, register: (u) => { registered.push(u); return Promise.resolve(reg); } } },
      document: { documentElement: { hasAttribute: (a) => a === 'data-static' && dataStatic }, addEventListener: (t, fn) => { listeners[t] = fn; }, createElement: el, body: { appendChild: () => state.appended++ } },
      location: { reload: () => state.reloads++ },
    };
    vm.createContext(ctx); vm.runInContext(fs.readFileSync(path.join(PUB, 'pwa.js'), 'utf8'), ctx);
    if (readyStatic !== null && listeners['sb:ready']) listeners['sb:ready']({ detail: { static: readyStatic } });
    return Object.assign(registered, { state, buttons, swListeners });
  }
  await test('pwa.js registers sw.js only in static mode on a secure origin (never for npm start / npm run dev)', () => {
    assert.deepStrictEqual([...runPwa({ readyStatic: false })], [], 'server mode: no service worker');
    assert.deepStrictEqual([...runPwa({ readyStatic: true })], ['sw.js'], 'static mode via sb:ready');
    assert.deepStrictEqual([...runPwa({ dataStatic: true })], ['sw.js'], 'static mode already detected');
    assert.deepStrictEqual([...runPwa({ readyStatic: true, secure: false })], [], 'insecure origin: no service worker');
  });

  await test('pwa.js reloads only the tab whose user clicked Reload', async () => {
    const posted = [];
    const other = runPwa({ dataStatic: true, waiting: { postMessage: (m) => posted.push(m) } });
    await new Promise(r => setImmediate(r));
    assert.strictEqual(other.state.appended, 1, 'update prompt shown');
    other.swListeners.controllerchange();
    assert.strictEqual(other.state.reloads, 0, 'Reload clicked in another tab (or first install) does not reload this tab');
    const me = runPwa({ dataStatic: true, waiting: { postMessage: (m) => posted.push(m) } });
    await new Promise(r => setImmediate(r));
    me.buttons['.pwa-reload'].click();
    assert.strictEqual(posted.at(-1).type, 'SKIP_WAITING');
    me.swListeners.controllerchange(); me.swListeners.controllerchange();
    assert.strictEqual(me.state.reloads, 1, 'accepted tab reloads exactly once');
  });

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(failed ? `\n${failed} PWA test(s) failed` : '\nAll PWA tests passed');
  process.exit(failed ? 1 : 0);
})();
