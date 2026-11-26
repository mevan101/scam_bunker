// Per-rule unit tests: every rule needs >= 2 should-match and >= 2 should-not-match phrases. Run: npm test
const fs = require('fs'), path = require('path'), vm = require('vm');
const ctx = { window: {}, URL }; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../public/scam.js'), 'utf8'), ctx);
const { RULES } = ctx.window.DeduceHeuristics;
const CASES = require('./fixtures/rule-cases.js');
let fail = 0; const bad = msg => { fail++; console.log('✗ ' + msg); };
const ids = new Set();
for (const r of RULES) {
  if (!r.id) { bad(`rule without id: ${r.label}`); continue; }
  if (ids.has(r.id)) bad(`duplicate rule id ${r.id}`); ids.add(r.id);
  const c = CASES[r.id];
  if (!c || (c.pos || []).length < 2 || (c.neg || []).length < 2) { bad(`${r.id}: needs >= 2 should-match and >= 2 should-not-match phrases`); continue; }
  for (const s of c.pos) if (!r.test(s)) bad(`${r.id} should match: ${s}`);
  for (const s of c.neg) if (r.test(s)) bad(`${r.id} should NOT match: ${s}`);
}
for (const id of Object.keys(CASES)) if (!ids.has(id)) bad(`test cases for unknown rule id ${id}`);
console.log(`${fail ? '✗' : '✓'} ${RULES.length} rules, ${Object.values(CASES).reduce((a, c) => a + c.pos.length + c.neg.length, 0)} phrases`);
process.exit(fail ? 1 : 0);
