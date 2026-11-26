// Zero-dependency tests for the chain of custody: hash-chain build/verify, tamper detection, corrections and the
// self-verifying export package. The browser module runs under node's vm (no document → UI does not boot). Run: npm test
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');

let failed = 0;
async function test(name, fn) {
  try { await fn(); console.log(`✓ ${name}`); } catch (e) { failed++; console.log(`✗ ${name}\n    ${e.stack.split('\n').slice(0, 4).join('\n    ')}`); }
}

const SRC = fs.readFileSync(path.join(__dirname, '../public/custody.js'), 'utf8');
const ctx = { window: {}, crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa }; vm.createContext(ctx);
vm.runInContext(SRC, ctx);
const C = ctx.window.ScamBunkerCustody;
const clone = o => JSON.parse(JSON.stringify(o));
const kinds = r => Array.from(r.problems, p => p.kind); // main-realm array for deepStrictEqual

// Invented example case: no real people, accounts or wallets.
const T0 = Date.parse('2026-01-05T10:00:00.000Z');
const ts = i => new Date(T0 + i * 1000).toISOString();
async function sampleLog() {
  const log = [], id = 'case-demo-1';
  const text = 'Hello dear, I can be your mentor. Deposit 500 USDT to start. (invented sample)';
  const img = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4, 5, 0xff, 0xd9]);
  const outputs = {};
  const put = async (f, out) => { if (out !== undefined) { f.outputDigest = await C.outputDigest(out); outputs[f.outputDigest] = out; } return C.appendEntry(log, { caseId: id, ts: ts(log.length), ...f }); };
  await put({ action: 'case-created', input: { platform: 'Instagram', url: 'https://example.test/post/1', text: { sha256: await C.textDigest(text) } } });
  await put({ action: 'evidence-added', input: C.evidenceRecord({ kind: 'text', name: 'message.txt', size: C.utf8Length(text), sha256: await C.textDigest(text), acquiredAt: ts(0), sourceUrl: 'https://example.test/post/1', stored: true }) });
  await put({ action: 'evidence-added', input: C.evidenceRecord({ kind: 'image', name: 'screenshot.jpg', type: 'image/jpeg', size: img.length, sha256: await C.sha256Hex(img), acquiredAt: ts(0), sourceUrl: 'javascript:alert(1)', stored: true }) });
  await put({ action: 'analysis', input: { engines: ['heuristics'], verdict: 'Likely scam', risk: 78, rules: ['Guaranteed returns', 'Wrong-number opener'] } });
  await put({ action: 'agent-report', input: { agent: 'scam', status: 'completed' } }, 'Fraud Analyst: matches a pig-butchering script.');
  await put({ action: 'verdict', input: { source: 'Lead Investigator', verdict: 'Likely scam', category: 'Investment scam', risk: 78, confidence: 70 } }, { verdict: 'Likely scam', headline: 'Invented headline', observations: [{ fact: '“guaranteed”', inference: 'Guaranteed returns', weight: 'strong' }] });
  return { log, outputs, id, text, img };
}

(async () => {
  await test('sha256Hex matches the FIPS 180-2 "abc" vector', async () => {
    assert.strictEqual(await C.sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  await test('canonicalJSON sorts keys, drops undefined, is order-independent', () => {
    assert.strictEqual(C.canonicalJSON({ b: 1, a: [1, undefined, { d: 2, c: null }], u: undefined }), '{"a":[1,null,{"c":null,"d":2}],"b":1}');
    assert.strictEqual(C.canonicalJSON({ x: 1, y: 2 }), C.canonicalJSON({ y: 2, x: 1 }));
    assert.strictEqual(C.canonicalJSON(NaN), 'null');
  });

  await test('text is hashed as UTF-8 after NFC normalisation', async () => {
    assert.strictEqual(await C.textDigest('caf\u00e9'), await C.textDigest('cafe\u0301'));
    assert.strictEqual(C.utf8Length('caf\u00e9'), 5);
  });

  await test('chain links every entry to the previous hash and verifies', async () => {
    const { log } = await sampleLog();
    assert.strictEqual(log[0].prevHash, C.GENESIS);
    for (let i = 1; i < log.length; i++) assert.strictEqual(log[i].prevHash, log[i - 1].hash);
    log.forEach((e, i) => { assert.strictEqual(e.seq, i); assert.match(e.hash, /^[0-9a-f]{64}$/); assert.ok(!isNaN(Date.parse(e.ts)) && e.ts.endsWith('Z')); });
    assert.strictEqual(log[1].hash, await C.sha256Hex(log[1].prevHash + C.canonicalJSON((({ hash, ...b }) => b)(log[1]))));
    const r = await C.verifyChain(log);
    assert.ok(r.ok, JSON.stringify(r.problems)); assert.strictEqual(r.head, log[log.length - 1].hash); assert.strictEqual(r.length, 6);
    assert.ok((await C.verifyChain(log, { expectedHead: r.head.toUpperCase() })).ok, 'head comparison is case-insensitive');
    assert.ok((await C.verifyChain([])).ok);
  });

  await test('evidence records keep hash, size, name, acquisition time, and only http(s) source URLs', async () => {
    const { log, img } = await sampleLog();
    const ev = log[2].input;
    assert.strictEqual(ev.sha256, await C.sha256Hex(img)); assert.strictEqual(ev.size, img.length); assert.strictEqual(ev.name, 'screenshot.jpg');
    assert.strictEqual(ev.acquiredAt, ts(0)); assert.strictEqual(ev.sourceUrl, null, 'javascript: URL must be dropped');
    assert.strictEqual(log[1].input.sourceUrl, 'https://example.test/post/1');
    assert.throws(() => C.evidenceRecord({ name: 'x' }), /SHA-256/);
  });

  await test('tamper: editing an entry is detected at that entry', async () => {
    const { log } = await sampleLog(); const t = clone(log);
    t[3].input.risk = 5;
    const r = await C.verifyChain(t);
    assert.ok(!r.ok); assert.strictEqual(r.firstBad, 3); assert.deepStrictEqual(kinds(r), ['altered']);
  });

  await test('tamper: re-hashing an edited entry breaks the next link', async () => {
    const { log } = await sampleLog(); const t = clone(log);
    t[2].input.sha256 = 'f'.repeat(64); t[2].hash = await C.entryHash(t[2]);
    const r = await C.verifyChain(t);
    assert.ok(!r.ok); assert.strictEqual(r.firstBad, 3); assert.ok(kinds(r).includes('broken-link'));
  });

  await test('tamper: deleting, inserting or reordering entries is detected', async () => {
    const { log } = await sampleLog();
    const del = clone(log); del.splice(2, 1);
    assert.ok(kinds(await C.verifyChain(del)).includes('sequence'));
    assert.ok(kinds(await C.verifyChain(del)).includes('broken-link'));
    const swap = clone(log); [swap[3], swap[4]] = [swap[4], swap[3]];
    assert.ok(!(await C.verifyChain(swap)).ok);
    const ins = clone(log); ins.splice(1, 0, clone(log[1]));
    assert.ok(!(await C.verifyChain(ins)).ok);
  });

  await test('tamper: back-dated timestamp and foreign case id are detected', async () => {
    const { log } = await sampleLog();
    const t = clone(log); t[4].ts = '2020-01-01T00:00:00.000Z'; t[4].hash = await C.entryHash(t[4]); for (let i = 5; i < t.length; i++) { t[i].prevHash = t[i - 1].hash; t[i].hash = await C.entryHash(t[i]); }
    assert.deepStrictEqual(kinds(await C.verifyChain(t)), ['timestamp']);
    const u = clone(log); u[2].caseId = 'other'; u[2].hash = await C.entryHash(u[2]); for (let i = 3; i < u.length; i++) { u[i].prevHash = u[i - 1].hash; u[i].hash = await C.entryHash(u[i]); }
    assert.deepStrictEqual(kinds(await C.verifyChain(u)), ['case-mismatch']);
  });

  await test('tamper: tail truncation and full rebuild are caught against a separately kept head hash', async () => {
    const { log } = await sampleLog(); const head = log[log.length - 1].hash;
    const cut = clone(log).slice(0, 4);
    assert.ok((await C.verifyChain(cut)).ok, 'truncation alone is invisible to the chain');
    assert.deepStrictEqual(kinds(await C.verifyChain(cut, { expectedHead: head })), ['head']);
    const rebuilt = []; for (const e of clone(log)) await C.appendEntry(rebuilt, { caseId: e.caseId, ts: e.ts, action: e.action, input: e.action === 'verdict' ? { ...e.input, verdict: 'No strong red flags' } : e.input, outputDigest: e.outputDigest });
    assert.ok((await C.verifyChain(rebuilt)).ok);
    assert.ok(!(await C.verifyChain(rebuilt, { expectedHead: head })).ok);
  });

  await test('corrections: need a reason, are appended, and keep the original finding', async () => {
    assert.throws(() => C.correctionInput({ field: 'verdict', corrected: 'Likely legitimate', reason: '  ' }), /reason/);
    assert.throws(() => C.correctionInput({ corrected: 'x', reason: 'y' }), /which finding/);
    const { log, id } = await sampleLog(); const before = clone(log);
    const input = C.correctionInput({ field: 'verdict', previous: 'Likely scam', corrected: 'Likely legitimate', what: 'Recruiter confirmed by the company', reason: 'The company confirmed the account on its official site', rules: ['Wrong-number opener', 'Guaranteed returns', 'Guaranteed returns'], correctsSeq: 5 });
    assert.deepStrictEqual(Array.from(input.rules), ['Guaranteed returns', 'Wrong-number opener']);
    await C.appendEntry(log, { caseId: id, ts: ts(10), action: 'correction', input });
    assert.deepStrictEqual(clone(log.slice(0, before.length)), before, 'history is untouched');
    assert.ok((await C.verifyChain(log)).ok);
    const f = C.effectiveFindings(log);
    assert.strictEqual(f.original.verdict, 'Likely scam'); assert.strictEqual(f.current.verdict, 'Likely legitimate'); assert.strictEqual(f.current.risk, 78);
    assert.strictEqual(f.corrections.length, 1); assert.strictEqual(f.corrections[0].reason, 'The company confirmed the account on its official site'); assert.strictEqual(f.corrections[0].correctsSeq, 5);
    await C.appendEntry(log, { caseId: id, ts: ts(11), action: 'correction', input: C.correctionInput({ field: 'risk', previous: 78, corrected: 10, reason: 'Re-scored after the confirmation' }) });
    const g = C.effectiveFindings(log);
    assert.strictEqual(g.current.risk, 10); assert.strictEqual(g.current.verdict, 'Likely legitimate'); assert.strictEqual(g.corrections.length, 2);
    const erase = clone(log); erase.splice(6, 1);
    assert.ok(!(await C.verifyChain(erase)).ok, 'deleting a correction is detected');
    assert.match(C.summarizeEntry(log[6]), /Likely scam.*Likely legitimate.*Why: The company confirmed/);
  });

  await test('corrections feed per-rule false-positive counts (P2-6)', async () => {
    const logs = [];
    for (let k = 0; k < 3; k++) {
      const { log, id } = await sampleLog();
      if (k < 2) await C.appendEntry(log, { caseId: id, ts: ts(20), action: 'correction', input: C.correctionInput({ field: 'verdict', previous: 'Likely scam', corrected: 'Likely legitimate', reason: 'Invented test reason', rules: k === 0 ? ['Urgency'] : [] }) });
      logs.push(log);
    }
    const s = C.ruleStats(logs);
    assert.strictEqual(s['Guaranteed returns'].wrong, 2); assert.strictEqual(s['Wrong-number opener'].wrong, 2); assert.strictEqual(s['Urgency'].wrong, 1);
    const back = logs[0]; await C.appendEntry(back, { caseId: back[0].caseId, ts: ts(30), action: 'correction', input: C.correctionInput({ field: 'verdict', previous: 'Likely legitimate', corrected: 'Scam', reason: 'Further evidence' }) });
    assert.strictEqual(C.ruleStats(logs)['Guaranteed returns'].wrong, 1, 'a case corrected back to scam no longer counts');
  });

  await test('export package: self-contained HTML with manifest verifies intact', async () => {
    const { log, outputs, id, text, img } = await sampleLog();
    await C.appendEntry(log, { caseId: id, ts: ts(40), action: 'export', input: { format: C.FORMAT, embedsFiles: true, embedded: 2, evidence: 2 } });
    const files = { [await C.textDigest(text)]: new TextEncoder().encode(C.normText(text)), [await C.sha256Hex(img)]: img, ['0'.repeat(64)]: new Uint8Array([1]) };
    const { html, manifest } = await C.buildPackage({ entries: log, outputs, files, caseMeta: { platform: 'Instagram' } });
    assert.strictEqual(manifest.head, log[log.length - 1].hash); assert.strictEqual(manifest.length, log.length);
    assert.strictEqual(Object.keys(manifest.files).length, 2, 'only files that are recorded evidence get embedded');
    assert.match(manifest.sha256sums, new RegExp(`^${manifest.evidence[0].sha256}  message.txt$`, 'm'));
    assert.ok(!/<\/script>/i.test(html.match(/id="sb-manifest">([\s\S]*?)<\/script>/)[1]));
    const r = await C.verifyPackage(html, { expectedHead: manifest.head });
    assert.ok(r.ok, JSON.stringify(r.problems)); assert.strictEqual(r.report, 'match'); assert.strictEqual(r.checkedOutputs, 2);
    assert.deepStrictEqual(Array.from(r.evidence, e => e.status), ['match', 'match']);
    assert.ok((await C.verifyPackage(JSON.stringify(manifest))).ok, 'a bare manifest JSON also verifies');
    assert.ok(!/javascript:alert/.test(html), 'unsafe source URL never reaches the export');
  });

  await test('export package: tampering with log, files, outputs or report is reported', async () => {
    const { log, outputs, id, img } = await sampleLog();
    const sha = await C.sha256Hex(img);
    await C.appendEntry(log, { caseId: id, ts: ts(40), action: 'export', input: { evidence: 2, embeddedFiles: [sha] } });
    const { html, manifest } = await C.buildPackage({ entries: log, outputs, files: { [sha]: img } });
    const repack = m => html.replace(/(id="sb-manifest">)[\s\S]*?(<\/script>)/, (_, a, b) => a + JSON.stringify(m).replace(/</g, '\\u003c') + b);
    const m1 = clone(manifest); m1.log[5].input.verdict = 'No strong red flags';
    assert.ok(kinds(await C.verifyPackage(repack(m1))).includes('altered'));
    const m2 = clone(manifest); m2.files[sha] = C.bytesToB64(new Uint8Array([...img, 0]));
    const r2 = await C.verifyPackage(repack(m2)); assert.ok(kinds(r2).includes('file')); assert.strictEqual(r2.evidence.find(e => e.sha256 === sha).status, 'mismatch');
    const m3 = clone(manifest); m3.outputs[log[4].outputDigest] = 'Edited agent report';
    assert.ok(kinds(await C.verifyPackage(repack(m3))).includes('output'));
    const m4 = clone(manifest); m4.evidence[0].name = 'renamed.txt';
    assert.ok(kinds(await C.verifyPackage(repack(m4))).includes('manifest'));
    const r5 = await C.verifyPackage(html.replace('Invented headline', 'Edited headline'));
    assert.ok(kinds(r5).includes('report')); assert.strictEqual(r5.report, 'mismatch');
    assert.ok(kinds(await C.verifyPackage(html, { expectedHead: 'a'.repeat(64) })).includes('head'));
    const m6 = clone(manifest); delete m6.files[sha];
    const r6 = await C.verifyPackage(repack(m6)); assert.ok(kinds(r6).includes('file')); assert.strictEqual(r6.evidence.find(e => e.sha256 === sha).status, 'missing');
    const m7 = clone(manifest); delete m7.outputs[log[4].outputDigest];
    assert.ok(kinds(await C.verifyPackage(repack(m7))).includes('output'), 'stripped output bodies are reported');
    const edited = html.replace('Invented headline', 'Edited headline'), editedReport = edited.match(/<!--sb-report-start-->([\s\S]*?)<!--sb-report-end-->/)[1];
    const m8 = clone(manifest); m8.reportSha256 = await C.sha256Hex(editedReport);
    const r8 = await C.verifyPackage(edited.replace(/(id="sb-manifest">)[\s\S]*?(<\/script>)/, (_, a, b) => a + JSON.stringify(m8).replace(/</g, '\\u003c') + b), { expectedHead: manifest.head });
    assert.strictEqual(r8.report, 'mismatch', 'an edited report with a recomputed reportSha256 is still caught');
    const m9 = clone(manifest); m9.exportedAt = '2020-01-01T00:00:00.000Z';
    assert.ok(kinds(await C.verifyPackage(repack(m9))).includes('manifest'));
    assert.ok(!(await C.verifyPackage('<html>nothing here</html>')).ok);
  });

  await test('export package: the embedded verifier runs on its own (no Scam Bunker code needed)', async () => {
    const { log, outputs, id, img } = await sampleLog();
    await C.appendEntry(log, { caseId: id, ts: ts(40), action: 'export', input: { evidence: 2 } });
    const { html, manifest } = await C.buildPackage({ entries: log, outputs, files: { [await C.sha256Hex(img)]: img } });
    const script = html.match(/<script>([\s\S]*?)<\/script><\/body>/)[1];
    const json = html.match(/id="sb-manifest">([\s\S]*?)<\/script>/)[1];
    const sandbox = { window: {}, crypto: globalThis.crypto, TextEncoder, atob, document: { getElementById: id => id === 'sb-manifest' ? { textContent: json } : null } };
    vm.createContext(sandbox); vm.runInContext(script, sandbox);
    const ok = await sandbox.window.SBVerify(sandbox.window.SBManifest, { expectedHead: manifest.head });
    assert.ok(ok.ok, JSON.stringify(ok.problems));
    const report = html.match(/<!--sb-report-start-->([\s\S]*?)<!--sb-report-end-->/)[1];
    const same = x => y => y === x;
    assert.strictEqual((await sandbox.window.SBVerify(manifest, { sameReport: same(report) })).report, 'match');
    assert.strictEqual((await sandbox.window.SBVerify(manifest, { sameReport: same(report.replace('Invented headline', 'Edited')) })).report, 'mismatch');
    const bad = clone(manifest); bad.log[1].input.size = 1;
    assert.ok(!(await sandbox.window.SBVerify(bad, {})).ok);
  });

  await test('export package: zero-byte originals and malformed logs are handled', async () => {
    const log = [], id = 'case-demo-empty', none = new Uint8Array(0), sha = await C.sha256Hex(none);
    await C.appendEntry(log, { caseId: id, ts: ts(0), action: 'case-created', input: { platform: 'Other' } });
    await C.appendEntry(log, { caseId: id, ts: ts(1), action: 'evidence-added', input: C.evidenceRecord({ kind: 'image', name: 'empty.png', size: 0, sha256: sha }) });
    await C.appendEntry(log, { caseId: id, ts: ts(2), action: 'export', input: { evidence: 1, embeddedFiles: [sha] } });
    const { html, manifest } = await C.buildPackage({ entries: log, outputs: {}, files: { [sha]: none } });
    const r = await C.verifyPackage(html, { expectedHead: manifest.head });
    assert.ok(r.ok, JSON.stringify(r.problems)); assert.strictEqual(r.evidence[0].status, 'match');
    const bad = clone(manifest); bad.log.splice(1, 0, null);
    const rb = await C.verifyPackage(html.replace(/(id="sb-manifest">)[\s\S]*?(<\/script>)/, (_, a, b) => a + JSON.stringify(bad) + b));
    assert.ok(!rb.ok); assert.ok(kinds(rb).includes('report')); assert.ok(rb.problems.length > 1, 'chain problems are still reported');
  });

  await test('report escapes user content', async () => {
    const log = [];
    await C.appendEntry(log, { caseId: '<x>', ts: ts(0), action: 'case-created', input: { platform: '<img src=x onerror=alert(1)>' } });
    await C.appendEntry(log, { caseId: '<x>', ts: ts(1), action: 'evidence-added', input: C.evidenceRecord({ kind: 'text', name: '<script>alert(1)</script>', size: 1, sha256: 'a'.repeat(64) }) });
    const { html } = await C.buildPackage({ entries: log, outputs: {} });
    const report = html.match(/<!--sb-report-start-->([\s\S]*?)<!--sb-report-end-->/)[1];
    assert.ok(!/<script>alert|<img src=x/.test(report));
  });

  console.log(failed ? `\n${failed} custody test(s) failed` : '\nAll custody tests passed');
  process.exit(failed ? 1 : 0);
})();
