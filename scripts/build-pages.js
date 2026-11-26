// Builds the static site for GitHub Pages into _site/: the browser app as-is, plus .nojekyll and a 404 page.
// The service worker (sw.js) gets a content hash of the build as its cache version and the app shell file list,
// so each deploy that changes any file invalidates the offline cache and shows the "Update available" prompt.
// Usage: npm run build:pages [outDir]   (the Pages workflow runs this on every push to main)
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const root = path.join(__dirname, '..');

const walk = (d, base = d) => fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))
  .flatMap(e => e.isDirectory() ? walk(path.join(d, e.name), base) : [path.relative(base, path.join(d, e.name)).split(path.sep).join('/')]);

// App shell = what the page needs to boot offline. Screenshots and the 404 copy are left to the network.
const isShell = (f) => !f.startsWith('docs/') && f !== '404.html' && f !== 'sw.js' && f !== '.nojekyll';

function buildVersion(out) {
  const h = crypto.createHash('sha256');
  for (const f of walk(out)) { h.update(f + '\0'); h.update(fs.readFileSync(path.join(out, f))); h.update('\0'); }
  return h.digest('hex').slice(0, 12);
}

function injectServiceWorker(out) {
  const swPath = path.join(out, 'sw.js');
  const version = buildVersion(out);
  const assets = ['./', ...walk(out).filter(isShell).map(f => './' + f)];
  let sw = fs.readFileSync(swPath, 'utf8');
  const before = sw;
  sw = sw.replace(/^const VERSION = .*;$/m, `const VERSION = ${JSON.stringify(version)};`)
    .replace(/^const ASSETS = .*;$/m, `const ASSETS = ${JSON.stringify(assets)};`);
  if (sw === before || !sw.includes(version)) throw new Error('sw.js: VERSION / ASSETS lines not found');
  fs.writeFileSync(swPath, sw);
  return { version, assets };
}

// The output dir is wiped first: inside the repo only _site/ is allowed, and never the repo or one of its parents.
function assertSafeOutDir(out) {
  const within = (a, b) => a === b || a.startsWith(b + path.sep);
  if (within(root, out) || (within(out, root) && out !== path.join(root, '_site'))) throw new Error(`build-pages: refusing to wipe ${out}; use _site/ or a directory outside the repo`);
}

function build(out = path.join(root, '_site')) {
  out = path.resolve(out);
  assertSafeOutDir(out);
  fs.rmSync(out, { recursive: true, force: true });
  fs.cpSync(path.join(root, 'public'), out, { recursive: true });
  fs.writeFileSync(path.join(out, '.nojekyll'), '');
  fs.copyFileSync(path.join(out, 'index.html'), path.join(out, '404.html'));
  for (const f of ['docs/screenshot.png', 'docs/screenshot-dark.png', 'docs/screenshot-mobile.png']) {
    const src = path.join(root, f);
    if (fs.existsSync(src)) { fs.mkdirSync(path.join(out, 'docs'), { recursive: true }); fs.copyFileSync(src, path.join(out, f)); }
  }
  const sw = injectServiceWorker(out);
  return { out, files: walk(out).length, ...sw };
}

module.exports = { build, buildVersion, injectServiceWorker };

if (require.main === module) {
  const r = build(process.argv[2] ? path.resolve(process.argv[2]) : undefined);
  console.log(`Built ${path.relative(root, r.out) || r.out}/ (${r.files} files) for GitHub Pages · sw cache ${r.version} (${r.assets.length} shell files)`);
}
