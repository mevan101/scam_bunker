// Precision / recall of the heuristic engine on the invented corpora (test/run.js cases + fixtures).
// Usage: node test/precision-report.js [path/to/other-scam.js]   (e.g. a copy of public/scam.js from main, to compare)
const fs = require('fs'), path = require('path'), vm = require('vm');
const load = f => { const ctx = { window: {}, URL }; vm.createContext(ctx); vm.runInContext(fs.readFileSync(f, 'utf8'), ctx); return ctx.window.DeduceHeuristics; };
const SCAM = require('./fixtures/scam-corpus.js'), BENIGN = require('./fixtures/benign-corpus.js');
const flagged = v => !['No strong red flags', 'Insufficient evidence'].includes(v.verdict), strong = v => ['Likely scam', 'Scam'].includes(v.verdict);
function report(name, H) {
  const s = SCAM.map(t => H.analyze({ text: t })), b = BENIGN.map(t => H.analyze({ text: t }));
  const row = (pred) => { const tp = s.filter(pred).length, fp = b.filter(pred).length; return `precision ${(tp / Math.max(1, tp + fp) * 100).toFixed(1)}% (${tp}/${tp + fp}), recall ${(tp / s.length * 100).toFixed(1)}% (${tp}/${s.length}), false positives ${fp}/${b.length}`; };
  console.log(`${name}\n  flagged (Suspicious+): ${row(flagged)}\n  Likely scam / Scam:    ${row(strong)}`);
  const phones = b.reduce((a, v) => a + v.entities.phones.length, 0), wallets = s.concat(b).reduce((a, v) => a + v.entities.wallets.length, 0);
  console.log(`  phone indicators extracted from benign corpus: ${phones}; wallet indicators (all corpora): ${wallets}`);
}
report('current public/scam.js', load(path.join(__dirname, '../public/scam.js')));
if (process.argv[2]) report(process.argv[2], load(process.argv[2]));
