// Serves the GitHub Pages build (_site/) under /scam_bunker/, like https://<user>.github.io/scam_bunker/.
// There is no /api here, so the app runs in static mode. Zero dependencies.
// Usage: node test/e2e/serve-static.js [port]   (run `npm run build:pages` first)
const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..', '_site');
const BASE = '/scam_bunker/';
const PORT = +(process.argv[2] || process.env.STATIC_PORT || 4411);
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.ico': 'image/x-icon' };

if (!fs.existsSync(path.join(ROOT, 'index.html'))) { console.error('No _site/index.html. Run `npm run build:pages` first.'); process.exit(1); }

http.createServer((req, res) => {
  const p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === BASE.slice(0, -1)) { res.writeHead(301, { Location: BASE }); return res.end(); }
  let file = null;
  if (p.startsWith(BASE)) {
    const rel = p.slice(BASE.length) || 'index.html';
    const f = path.resolve(ROOT, rel.endsWith('/') ? rel + 'index.html' : rel);
    if (f.startsWith(ROOT + path.sep) && fs.existsSync(f) && fs.statSync(f).isFile()) file = f;
  }
  if (!file) { // GitHub Pages answers unknown paths (including /api/*) with 404.html and status 404
    res.writeHead(404, { 'Content-Type': MIME['.html'] });
    return res.end(fs.readFileSync(path.join(ROOT, '404.html')));
  }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
  fs.createReadStream(file).pipe(res);
}).listen(PORT, '127.0.0.1', () => console.log(`Static build on http://127.0.0.1:${PORT}${BASE}`));
