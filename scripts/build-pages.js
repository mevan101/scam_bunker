// Builds the static site for GitHub Pages into _site/: the browser app as-is, plus .nojekyll and a 404 page.
// Usage: npm run build:pages   (the Pages workflow runs this on every push to main)
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');
const out = path.join(root, '_site');
fs.rmSync(out, { recursive: true, force: true });
fs.cpSync(path.join(root, 'public'), out, { recursive: true });
fs.writeFileSync(path.join(out, '.nojekyll'), '');
fs.copyFileSync(path.join(out, 'index.html'), path.join(out, '404.html'));
for (const f of ['docs/screenshot.png', 'docs/screenshot-dark.png', 'docs/screenshot-mobile.png']) {
  const src = path.join(root, f);
  if (fs.existsSync(src)) { fs.mkdirSync(path.join(out, 'docs'), { recursive: true }); fs.copyFileSync(src, path.join(out, f)); }
}
const count = (d) => fs.readdirSync(d, { withFileTypes: true }).reduce((n, e) => n + (e.isDirectory() ? count(path.join(d, e.name)) : 1), 0);
console.log(`Built _site/ (${count(out)} files) for GitHub Pages`);
