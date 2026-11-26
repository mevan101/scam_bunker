// Runs every test file so new features don't need to edit package.json:
// test/run.js and test/precision-report.js first, then every test/*.test.js in name order.
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const dir = __dirname;
const first = ['run.js', 'precision-report.js'].filter(f => fs.existsSync(path.join(dir, f)));
const rest = fs.readdirSync(dir).filter(f => f.endsWith('.test.js')).sort();
let failed = [];
for (const f of [...first, ...rest]) {
  console.log(`\n── ${f}`);
  const r = spawnSync(process.execPath, [path.join(dir, f)], { stdio: 'inherit' });
  if (r.status !== 0) failed.push(f);
}
console.log(failed.length ? `\n✗ ${failed.length} test file(s) failed: ${failed.join(', ')}` : `\n✓ all ${first.length + rest.length} test files passed`);
process.exit(failed.length ? 1 : 0);
