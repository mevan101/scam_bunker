// Scam Bunker — evidence locker, hash-chained case log, corrections log and verifiable export (chain of custody).
// METHODOLOGY section 8 (Berkeley Protocol, lightweight) and BACKLOG P1-4 / P2-6.
//
// Every case event (created, evidence added, analysis, agent report, verdict, correction, export) is appended to a
// per-case log. Each entry is { v, seq, caseId, ts, action, input, outputDigest, prevHash, hash } with
// hash = sha256(prevHash + canonicalJSON(entry without hash)), so any edit, insertion, removal or reordering of
// history breaks the chain. Corrections never delete anything: they are new entries that say what changed and why.
// The export is one HTML file: a readable report plus an embedded JSON manifest (log, hashes, optional originals)
// and a self-contained verifier. Logs and original files live in IndexedDB, with in-memory/localStorage fallbacks.
//
// The pure functions are exported on window.ScamBunkerCustody and unit-tested under node's vm
// (test/custody.test.js). The UI only boots when window.ScamBunker exists.
(() => {
  const GENESIS = '0'.repeat(64);
  const FORMAT = 'scam-bunker-evidence/1';
  const BENIGN = ['Likely legitimate', 'No strong red flags'];

  // ======================= Pure core =======================
  // Deterministic JSON: object keys sorted, undefined/function members dropped, non-finite numbers → null.
  function canonicalJSON(v) {
    if (v === undefined || typeof v === 'function') return 'null';
    if (v === null || typeof v !== 'object') return typeof v === 'number' && !isFinite(v) ? 'null' : JSON.stringify(v);
    if (typeof v.toJSON === 'function') return canonicalJSON(v.toJSON());
    if (Array.isArray(v)) return '[' + v.map(canonicalJSON).join(',') + ']';
    return '{' + Object.keys(v).filter(k => v[k] !== undefined && typeof v[k] !== 'function').sort().map(k => JSON.stringify(k) + ':' + canonicalJSON(v[k])).join(',') + '}';
  }

  async function sha256Hex(data) {
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : ArrayBuffer.isView(data) ? data : new Uint8Array(data);
    const h = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(h), b => b.toString(16).padStart(2, '0')).join('');
  }

  // Text evidence is hashed as UTF-8 after Unicode NFC normalisation, so visually identical text hashes the same.
  const normText = s => String(s == null ? '' : s).normalize('NFC');
  const textDigest = s => sha256Hex(normText(s));
  const utf8Length = s => new TextEncoder().encode(normText(s)).length;

  function entryBody(e) { const body = {}; for (const k of Object.keys(e)) if (k !== 'hash') body[k] = e[k]; return body; }
  function entryHash(e) { return sha256Hex(String(e.prevHash) + canonicalJSON(entryBody(e))); }

  async function makeEntry(log, f) {
    const prev = log.length ? log[log.length - 1] : null;
    const e = { v: 1, seq: log.length, caseId: f.caseId != null ? f.caseId : prev ? prev.caseId : null, ts: f.ts || new Date().toISOString(), action: String(f.action), input: f.input === undefined ? null : JSON.parse(JSON.stringify(f.input)), outputDigest: f.outputDigest || null, prevHash: prev ? prev.hash : GENESIS };
    e.hash = await entryHash(e);
    return e;
  }
  async function appendEntry(log, f) { const e = await makeEntry(log, f); log.push(e); return e; }
  const outputDigest = output => sha256Hex(canonicalJSON(output));

  // Re-checks every link. Tail truncation or a fully rebuilt chain can only be caught against a head hash kept elsewhere.
  async function verifyChain(log, opts) {
    opts = opts || {};
    const GEN = '0'.repeat(64);
    if (!Array.isArray(log)) return { ok: false, length: 0, head: null, problems: [{ seq: null, kind: 'malformed', message: 'The log is not a list of entries.' }], firstBad: null };
    const problems = [];
    const caseId = log[0] && log[0].caseId;
    let prevHash = GEN, prevT = -Infinity;
    for (let i = 0; i < log.length; i++) {
      const e = log[i];
      if (!e || typeof e !== 'object') { problems.push({ seq: i, kind: 'malformed', message: `Entry ${i} is not an object.` }); prevHash = null; continue; }
      if (e.seq !== i) problems.push({ seq: i, kind: 'sequence', message: `Entry at position ${i} is numbered #${e.seq}: an entry was removed, inserted or reordered.` });
      if (e.prevHash !== prevHash) problems.push({ seq: i, kind: 'broken-link', message: `Entry #${i} does not point to the hash of the entry before it.` });
      const h = await entryHash(e);
      if (h !== e.hash) problems.push({ seq: i, kind: 'altered', message: `Entry #${i} (${e.action}) was changed after it was recorded: its contents no longer match its hash.`, expected: e.hash, found: h });
      if (e.caseId !== caseId) problems.push({ seq: i, kind: 'case-mismatch', message: `Entry #${i} belongs to a different case (${e.caseId}).` });
      const t = Date.parse(e.ts);
      if (typeof e.ts !== 'string' || isNaN(t)) problems.push({ seq: i, kind: 'timestamp', message: `Entry #${i} has no valid ISO timestamp.` });
      else { if (t < prevT) problems.push({ seq: i, kind: 'timestamp', message: `Entry #${i} is timestamped before the entry it follows.` }); prevT = t; }
      prevHash = e.hash;
    }
    const head = log.length ? log[log.length - 1].hash : GEN;
    if (opts.expectedHead && String(opts.expectedHead).trim().toLowerCase() !== head) problems.push({ seq: null, kind: 'head', message: 'The last entry does not match the head hash you were given: entries were removed from the end, added, or the whole chain was rebuilt.' });
    if (opts.expectedLength != null && opts.expectedLength !== log.length) problems.push({ seq: null, kind: 'length', message: `Expected ${opts.expectedLength} entries but found ${log.length}.` });
    const bad = problems.find(p => p.seq != null);
    return { ok: !problems.length, length: log.length, head, problems, firstBad: bad ? bad.seq : null };
  }

  const safeUrl = u => /^https?:\/\//i.test(String(u || '')) ? String(u) : null;

  function evidenceRecord(x) {
    if (!/^[0-9a-f]{64}$/.test(String(x.sha256 || ''))) throw new Error('Evidence needs a SHA-256 digest.');
    return { kind: String(x.kind || 'file'), name: String(x.name || 'unnamed'), type: x.type ? String(x.type) : null, size: Number(x.size) || 0, sha256: x.sha256, acquiredAt: x.acquiredAt || new Date().toISOString(), sourceUrl: safeUrl(x.sourceUrl), note: x.note ? String(x.note) : null, original: x.stored ? 'stored' : 'not stored' };
  }

  // A correction records what changed and why. It never edits or removes earlier entries.
  function correctionInput(x) {
    const reason = String(x.reason || '').trim();
    if (!reason) throw new Error('A correction needs a reason.');
    if (!x.field) throw new Error('Say which finding is being corrected.');
    const fmt = v => v === undefined ? null : v;
    return { field: String(x.field), previous: fmt(x.previous), corrected: fmt(x.corrected), what: String(x.what || '').trim(), reason, rules: [...new Set((x.rules || []).map(String))].sort(), correctsSeq: Number.isInteger(x.correctsSeq) ? x.correctsSeq : null };
  }

  // Replays the log: the last recorded verdict, then every correction made after it, in order.
  function effectiveFindings(log) {
    let base = null, baseSeq = -1;
    for (const e of log) if (e.action === 'verdict') { base = e.input || {}; baseSeq = e.seq; }
    const current = base ? { ...base } : {};
    const corrections = log.filter(e => e.action === 'correction').map(e => ({ seq: e.seq, ts: e.ts, ...e.input }));
    for (const c of corrections) if (c.seq > baseSeq && ['verdict', 'category', 'risk'].includes(c.field)) current[c.field] = c.corrected;
    const analysis = [...log].reverse().find(e => e.action === 'analysis');
    return { caseId: log[0] ? log[0].caseId : null, original: base, current, corrections, rules: (analysis && analysis.input && analysis.input.rules) || [] };
  }

  // P2-6: count, per rule, the cases where the user re-labelled a flagged verdict as legitimate.
  function ruleStats(logs) {
    const out = {};
    for (const log of logs) {
      if (!Array.isArray(log) || !log.length) continue;
      const f = effectiveFindings(log);
      if (!f.original || BENIGN.includes(f.original.verdict) || !BENIGN.includes(f.current.verdict)) continue;
      const rules = new Set(f.rules);
      f.corrections.forEach(c => (c.rules || []).forEach(r => rules.add(r)));
      rules.forEach(r => { const s = out[r] = out[r] || { wrong: 0, cases: [] }; s.wrong++; s.cases.push(f.caseId); });
    }
    return out;
  }

  function bytesToB64(u8) { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); }
  function b64ToBytes(b64) { const s = atob(b64); const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; }

  // Checks a parsed manifest: the chain, the manifest summary against its own log, embedded originals and outputs,
  // and (when given the raw report text) the report digest. Self-contained so it can be embedded in the export.
  async function verifyManifest(m, opts) {
    opts = opts || {};
    const problems = [], notes = [];
    if (!m || typeof m !== 'object' || !Array.isArray(m.log)) return { ok: false, problems: [{ kind: 'malformed', message: 'No Scam Bunker manifest found.' }], notes, evidence: [], chain: null };
    if (m.format !== 'scam-bunker-evidence/1') notes.push(`Unknown manifest format "${m.format}"; checked as version 1.`);
    const chain = await verifyChain(m.log, { expectedHead: opts.expectedHead });
    problems.push(...chain.problems);
    if (m.head !== chain.head || m.length !== m.log.length) problems.push({ kind: 'manifest', message: 'The manifest summary (head hash or entry count) does not match its own log.' });
    if (m.log[0] && m.caseId !== m.log[0].caseId) problems.push({ kind: 'manifest', message: 'The manifest case id does not match the log.' });
    const fromLog = m.log.filter(e => e && e.action === 'evidence-added').map(e => ({ seq: e.seq, ...e.input }));
    if (canonicalJSON(fromLog) !== canonicalJSON(m.evidence || [])) problems.push({ kind: 'manifest', message: 'The evidence list in the manifest differs from the evidence recorded in the log.' });
    const files = m.files || {}, evidence = [];
    const lastExport = [...m.log].reverse().find(e => e && e.action === 'export');
    const mustEmbed = (lastExport && lastExport.input && Array.isArray(lastExport.input.embeddedFiles)) ? lastExport.input.embeddedFiles : [];
    for (const ev of fromLog) {
      if (typeof files[ev.sha256] !== 'string') {
        const removed = mustEmbed.includes(ev.sha256);
        evidence.push({ name: ev.name, sha256: ev.sha256, status: removed ? 'missing' : 'not included' });
        if (removed) problems.push({ kind: 'file', message: `The log says the original of "${ev.name}" was embedded at export, but it has been removed from the package.` });
        continue;
      }
      let got = null; try { got = await sha256Hex(b64ToBytes(files[ev.sha256])); } catch (e) { }
      const ok = got === ev.sha256;
      evidence.push({ name: ev.name, sha256: ev.sha256, status: ok ? 'match' : 'mismatch', found: got });
      if (!ok) problems.push({ kind: 'file', message: `The embedded copy of "${ev.name}" does not match its recorded SHA-256.` });
    }
    const outputs = m.outputs || {};
    let checkedOutputs = 0;
    for (const e of m.log) {
      if (!e || !e.outputDigest) continue;
      if (!(e.outputDigest in outputs)) { problems.push({ seq: e.seq, kind: 'output', message: `The stored output of entry #${e.seq} (${e.action}) has been removed from the package.` }); continue; }
      checkedOutputs++;
      if (await sha256Hex(canonicalJSON(outputs[e.outputDigest])) !== e.outputDigest) problems.push({ seq: e.seq, kind: 'output', message: `The stored output of entry #${e.seq} (${e.action}) was changed.` });
    }
    const last = m.log[m.log.length - 1];
    if (last && m.exportedAt !== last.ts) problems.push({ kind: 'manifest', message: 'The manifest export time does not match its log.' });
    if ((m.sha256sums || '') !== fromLog.map(x => `${x.sha256}  ${x.name}`).join('\n')) problems.push({ kind: 'manifest', message: 'The SHA256SUMS list differs from the evidence recorded in the log.' });
    // The readable report is a pure function of the checked manifest, so it is re-rendered and compared rather than trusted.
    let report = 'not checked';
    if (typeof opts.report === 'string' || typeof opts.sameReport === 'function') {
      let expected = null; try { expected = renderReport(m); } catch (e) { }
      if (expected === null) { report = 'mismatch'; problems.push({ kind: 'report', message: 'The readable report could not be rebuilt from the manifest because its log is malformed.' }); }
      else {
        report = (typeof opts.sameReport === 'function' ? opts.sameReport(expected) : opts.report === expected) ? 'match' : 'mismatch';
        if (report === 'mismatch') problems.push({ kind: 'report', message: 'The readable report was edited after export: it no longer matches the manifest.' });
      }
    }
    return { ok: !problems.length, problems, notes, evidence, chain, checkedOutputs, report, head: chain.head };
  }

  const MANIFEST_RE = /<script type="application\/json" id="sb-manifest">([\s\S]*?)<\/script>/;
  const REPORT_RE = /<!--sb-report-start-->([\s\S]*?)<!--sb-report-end-->/;
  function parsePackage(text) {
    text = String(text || '');
    if (/^\s*\{/.test(text)) return { manifest: JSON.parse(text), report: null };
    const m = MANIFEST_RE.exec(text); if (!m) throw new Error('No Scam Bunker manifest found in this file.');
    const r = REPORT_RE.exec(text);
    return { manifest: JSON.parse(m[1]), report: r ? r[1] : null };
  }
  async function verifyPackage(text, opts) {
    let p; try { p = parsePackage(text); } catch (e) { return { ok: false, problems: [{ kind: 'malformed', message: e.message }], notes: [], evidence: [], chain: null }; }
    return verifyManifest(p.manifest, { ...(opts || {}), report: p.report });
  }

  // ---------- Readable report ----------
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const val = v => v == null || v === '' ? '—' : typeof v === 'object' ? JSON.stringify(v) : String(v);
  const short = h => h ? String(h).slice(0, 12) + '…' : '—';
  const AGENT_NAMES = { heuristics: 'Pattern Engine', metadata: 'Metadata Engine', forensics: 'Image Forensics', scam: 'Fraud Analyst', osint: 'OSINT & Platform Analyst', factcheck: 'Fact Checker', lead: 'Lead Investigator' };
  const ACTION_LABEL = { 'case-created': 'Case opened', 'evidence-added': 'Evidence added', 'evidence-note': 'Evidence note', analysis: 'Local analysis', 'web-fetch': 'Page fetched', 'web-search': 'Web search', 'agent-report': 'Agent report', verdict: 'Verdict', correction: 'Correction', export: 'Export', 'log-started': 'Log started' };

  function summarizeEntry(e) {
    const i = e.input || {};
    switch (e.action) {
      case 'case-created': return ['Case opened', i.platform, i.url].filter(Boolean).join(' · ');
      case 'evidence-added': return `${i.kind} “${i.name}” · ${i.size} bytes · SHA-256 ${short(i.sha256)}`;
      case 'evidence-note': return `Note on ${short(i.sha256)}: ${i.note}`;
      case 'analysis': return `${(i.engines || []).join(' + ')}: ${val(i.verdict)} (risk ${val(i.risk)}) · ${(i.rules || []).length} rule${(i.rules || []).length === 1 ? '' : 's'} fired`;
      case 'web-fetch': return `${val(i.url)}: ${i.error ? 'failed (' + i.error + ')' : val(i.title)}`;
      case 'web-search': return `${i.results || 0} corroboration result${i.results === 1 ? '' : 's'}`;
      case 'agent-report': return `${AGENT_NAMES[i.agent] || i.agent}: ${i.status}`;
      case 'verdict': return `${i.source}: ${val(i.verdict)} · ${val(i.category)} · risk ${val(i.risk)}`;
      case 'correction': return `${i.field}: “${val(i.previous)}” → “${val(i.corrected)}”. Why: ${i.reason}`;
      case 'export': return `Evidence package exported (${i.evidence} item${i.evidence === 1 ? '' : 's'}${i.embedsFiles ? ', originals embedded' : ''})`;
      case 'log-started': return i.note || 'Log started';
      default: return e.action;
    }
  }

  function renderReport(m) {
    const f = effectiveFindings(m.log);
    const lastVerdict = [...m.log].reverse().find(e => e.action === 'verdict');
    const v = lastVerdict && m.outputs && m.outputs[lastVerdict.outputDigest] || null;
    const agents = m.log.filter(e => e.action === 'agent-report' && m.outputs && typeof m.outputs[e.outputDigest] === 'string');
    const row = cells => `<tr>${cells.map(c => `<td>${c}</td>`).join('')}</tr>`;
    return `<header><p class="eyebrow">Scam Bunker · evidence package</p><h1>Case ${esc(m.caseId)}</h1>
<p>Exported ${esc(m.exportedAt)} (UTC) · ${m.length} log entries · head hash <code>${esc(m.head)}</code></p>
<p class="note">Findings are leads, not verdicts. Each was produced by automated engines and, where noted, AI agents, and is labelled with its strength. Verify independently before acting.</p></header>
<section><h2>Findings</h2>${f.original ? `<p><b>Current finding:</b> ${esc(val(f.current.verdict))} · ${esc(val(f.current.category))} · risk ${esc(val(f.current.risk))}</p>
${f.corrections.length ? `<p><b>Originally recorded:</b> ${esc(val(f.original.verdict))} · ${esc(val(f.original.category))} · risk ${esc(val(f.original.risk))} (${esc(f.original.source)}). Corrected ${f.corrections.length} time${f.corrections.length === 1 ? '' : 's'}; see below.</p>` : ''}` : '<p>No verdict was recorded.</p>'}
${v && v.headline ? `<p>${esc(v.headline)}</p>` : ''}${v && v.deduction ? `<p>${esc(v.deduction)}</p>` : ''}
${v && (v.observations || []).length ? `<ul>${v.observations.map(o => `<li>[${esc(o.weight)}] ${esc(o.fact)} → ${esc(o.inference)}</li>`).join('')}</ul>` : ''}</section>
<section><h2>Evidence (SHA256SUMS)</h2><table><thead><tr><th>#</th><th>Kind</th><th>Name</th><th>SHA-256</th><th>Bytes</th><th>Acquired (UTC)</th><th>Source</th><th>Original</th></tr></thead><tbody>
${(m.evidence || []).map(x => row([x.seq, esc(x.kind), esc(x.name), `<code>${esc(x.sha256)}</code>`, esc(x.size), esc(x.acquiredAt), esc(x.sourceUrl || '—'), esc(m.files && typeof m.files[x.sha256] === 'string' ? 'embedded' : x.original)])).join('')}</tbody></table>
<pre>${esc(m.sha256sums || '')}</pre></section>
<section><h2>Corrections</h2>${f.corrections.length ? `<table><thead><tr><th>#</th><th>When (UTC)</th><th>Field</th><th>Was</th><th>Now</th><th>What changed</th><th>Why</th></tr></thead><tbody>${f.corrections.map(c => row([c.seq, esc(c.ts), esc(c.field), esc(val(c.previous)), esc(val(c.corrected)), esc(c.what || '—'), esc(c.reason)])).join('')}</tbody></table>` : '<p>No corrections.</p>'}</section>
${agents.length ? `<section><h2>Agent reports</h2>${agents.map(e => `<h3>${esc(AGENT_NAMES[e.input.agent] || e.input.agent)}</h3><pre>${esc(m.outputs[e.outputDigest])}</pre>`).join('')}</section>` : ''}
<section><h2>Case log</h2><table><thead><tr><th>#</th><th>When (UTC)</th><th>Action</th><th>Detail</th><th>Output digest</th><th>Entry hash</th></tr></thead><tbody>
${m.log.map(e => row([e.seq, esc(e.ts), esc(ACTION_LABEL[e.action] || e.action), esc(summarizeEntry(e)), `<code>${esc(short(e.outputDigest))}</code>`, `<code title="${esc(e.hash)}">${esc(short(e.hash))}</code>`])).join('')}</tbody></table></section>`;
  }

  const PACKAGE_CSS = 'body{font:15px/1.55 Georgia,serif;max-width:980px;margin:32px auto;padding:0 20px;color:#1b1d22;background:#fffdf8}h1,h2,h3{font-family:Georgia,serif;line-height:1.2}h2{margin-top:32px;border-bottom:1px solid #d2c9b5;padding-bottom:4px}table{border-collapse:collapse;width:100%;font:13px/1.4 system-ui,sans-serif}th,td{border:1px solid #d2c9b5;padding:6px 8px;text-align:left;vertical-align:top;overflow-wrap:break-word}th{background:#f2ede2}code,pre{font:12.5px/1.5 ui-monospace,monospace;overflow-wrap:anywhere;white-space:pre-wrap}.eyebrow{font:600 12px system-ui,sans-serif;letter-spacing:.1em;text-transform:uppercase;color:#5f6673}.note{border-left:4px solid #94570a;padding:8px 12px;background:#f7f3ea}#sb-verify-box{margin-top:40px;padding:16px;border:2px solid #94570a;border-radius:10px}button{font:600 14px system-ui,sans-serif;padding:8px 14px;border-radius:8px;border:1px solid #94570a;background:#94570a;color:#fff;cursor:pointer}button:focus-visible,input:focus-visible{outline:3px solid #2259b8;outline-offset:2px}input{font:13px ui-monospace,monospace;padding:6px;width:100%;max-width:640px;box-sizing:border-box}.ok{color:#146b46;font-weight:700}.bad{color:#a8241d;font-weight:700}@media print{#sb-verify-box{display:none}}';

  function embeddedVerifier() {
    const fns = [canonicalJSON, sha256Hex, entryBody, entryHash, verifyChain, b64ToBytes, effectiveFindings, summarizeEntry, renderReport, verifyManifest].map(f => f.toString()).join('\n')
      + `\nconst esc = ${esc.toString()};\nconst val = ${val.toString()};\nconst short = ${short.toString()};\nconst AGENT_NAMES = ${JSON.stringify(AGENT_NAMES)};\nconst ACTION_LABEL = ${JSON.stringify(ACTION_LABEL)};`;
    const boot = function () {
      const m = JSON.parse(document.getElementById('sb-manifest').textContent);
      window.SBVerify = verifyManifest; window.SBManifest = m;
      const btn = document.getElementById('sb-verify'), out = document.getElementById('sb-verify-out'), head = document.getElementById('sb-head');
      if (!btn) return;
      btn.addEventListener('click', async () => {
        out.textContent = 'Checking…';
        try {
          const shown = document.getElementById('sb-report');
          const sameReport = html => { const t = document.createElement('div'); t.innerHTML = '<!--sb-report-start-->' + html + '<!--sb-report-end-->'; return !!shown && t.innerHTML === shown.innerHTML; };
          const r = await verifyManifest(m, { expectedHead: head.value.trim() || null, sameReport });
          out.textContent = '';
          const p = document.createElement('p'); p.className = r.ok ? 'ok' : 'bad';
          p.textContent = r.ok ? `Intact: ${r.chain.length} entries re-hashed, ${r.evidence.filter(e => e.status === 'match').length} embedded files match their SHA-256.` : `Tampering detected: ${r.problems.length} problem${r.problems.length === 1 ? '' : 's'}.`;
          out.appendChild(p);
          const ul = document.createElement('ul');
          r.problems.concat(r.notes.map(n => ({ message: n }))).forEach(x => { const li = document.createElement('li'); li.textContent = x.message; ul.appendChild(li); });
          if (!head.value.trim()) { const li = document.createElement('li'); li.textContent = 'No head hash entered: removal of the newest entries, or a fully rebuilt chain, can only be detected against a head hash you received separately.'; ul.appendChild(li); }
          out.appendChild(ul);
        } catch (e) { out.textContent = 'This browser could not run the check (' + e.message + '). Open the file in a current browser, or use “Verify a package” in Scam Bunker.'; }
      });
    };
    return `${fns}\n(${boot.toString()})();`;
  }

  const jsonForScript = o => JSON.stringify(o).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');

  // entries must already end with the 'export' entry. files: { sha256: Uint8Array } of originals to embed.
  async function buildPackage({ entries, outputs, files, caseMeta }) {
    const last = entries[entries.length - 1];
    const evidence = entries.filter(e => e.action === 'evidence-added').map(e => ({ seq: e.seq, ...e.input }));
    const used = {}; entries.forEach(e => { if (e.outputDigest && outputs && e.outputDigest in outputs) used[e.outputDigest] = outputs[e.outputDigest]; });
    const embedded = {}; for (const [sha, bytes] of Object.entries(files || {})) if (evidence.some(x => x.sha256 === sha)) embedded[sha] = bytesToB64(bytes);
    const m = { format: FORMAT, generator: 'Scam Bunker', caseId: last.caseId, exportedAt: last.ts, head: last.hash, length: entries.length, case: caseMeta || {}, evidence, sha256sums: evidence.map(x => `${x.sha256}  ${x.name}`).join('\n'), log: entries, outputs: used, files: embedded };
    const report = renderReport(m);
    m.reportSha256 = await sha256Hex(report);
    const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Scam Bunker evidence package · case ${esc(m.caseId)}</title><style>${PACKAGE_CSS}</style></head><body><main>
<div id="sb-report"><!--sb-report-start-->${report}<!--sb-report-end--></div>
<section id="sb-verify-box" aria-labelledby="sb-verify-h"><h2 id="sb-verify-h">Verify this package</h2>
<p>This file contains its own manifest. The check re-hashes every log entry, the link to the entry before it, and every embedded original file, and checks the readable report above against the manifest, entirely inside your browser. For a check that does not rely on code inside this file, use “Verify a package” in Scam Bunker.</p>
<p><label for="sb-head">Head hash received separately from the sender (optional, recommended)</label><br><input id="sb-head" autocomplete="off" spellcheck="false" placeholder="64 hex characters"></p>
<button type="button" id="sb-verify">Check integrity</button><div id="sb-verify-out" role="status" aria-live="polite"></div></section></main>
<script type="application/json" id="sb-manifest">${jsonForScript(m)}</script>
<script>${embeddedVerifier()}</script></body></html>`;
    return { html, manifest: m, report };
  }

  // The case a custody action concerns: the one the panel shows, never whatever case happens to be current.
  function caseForPanel(panelCaseId, current, saved) {
    if (!panelCaseId) return null;
    if (current && current.id === panelCaseId) return current;
    return (Array.isArray(saved) ? saved : []).find(x => x && x.id === panelCaseId) || null;
  }

  const api = { GENESIS, FORMAT, BENIGN, canonicalJSON, sha256Hex, textDigest, normText, utf8Length, entryHash, makeEntry, appendEntry, outputDigest, verifyChain, evidenceRecord, correctionInput, effectiveFindings, ruleStats, bytesToB64, b64ToBytes, verifyManifest, parsePackage, verifyPackage, summarizeEntry, renderReport, buildPackage, embeddedVerifier, caseForPanel };
  if (typeof window !== 'undefined') window.ScamBunkerCustody = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof document === 'undefined' || typeof window === 'undefined' || !window.ScamBunker) return;

  // ======================= Browser: storage =======================
  const SB = window.ScamBunker;
  const LS = 'scambunker.custody.';
  const Store = (() => {
    let dbp = null;
    const mem = new Map(), memFiles = new Map();
    let mode = 'IndexedDB';
    function open() {
      if (!dbp) dbp = new Promise((res, rej) => {
        try {
          const r = indexedDB.open('scambunker-custody', 1);
          r.onupgradeneeded = () => { const db = r.result; if (!db.objectStoreNames.contains('logs')) db.createObjectStore('logs', { keyPath: 'caseId' }); if (!db.objectStoreNames.contains('files')) db.createObjectStore('files', { keyPath: 'sha256' }); };
          r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); r.onblocked = () => rej(new Error('IndexedDB blocked'));
        } catch (e) { rej(e); }
      }).catch(() => { mode = 'browser storage (IndexedDB unavailable)'; return null; });
      return dbp;
    }
    const req = (db, store, op, arg) => new Promise((res, rej) => {
      try { const t = db.transaction(store, op.startsWith('get') ? 'readonly' : 'readwrite'); const r = t.objectStore(store)[op](arg); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); t.onabort = () => rej(t.error); } catch (e) { rej(e); }
    });
    const lsIndex = () => SB.store.get(LS + 'index', []);
    return {
      mode: () => mode,
      // A failed IndexedDB write falls back to localStorage, then to memory, so the copy with the most entries is the newest.
      async getLog(id) {
        const db = await open();
        let idb = null;
        if (db) try { idb = await req(db, 'logs', 'get', id); } catch { }
        const all = [idb, SB.store.get(LS + id, null), mem.get(id)].filter(r => r && Array.isArray(r.entries));
        return all.reduce((a, r) => (!a || r.entries.length > a.entries.length ? r : a), null);
      },
      // Memory holds a log only when nothing persistent accepted it, so it cannot resurrect a log another tab cleared.
      async putLog(rec) {
        const db = await open();
        if (db) try { await req(db, 'logs', 'put', rec); mem.delete(rec.caseId); return; } catch { mode = 'browser storage (IndexedDB write failed)'; }
        try {
          localStorage.setItem(LS + rec.caseId, JSON.stringify(rec));
          const idx = lsIndex(); if (!idx.includes(rec.caseId)) localStorage.setItem(LS + 'index', JSON.stringify([rec.caseId, ...idx].slice(0, 200)));
          mem.delete(rec.caseId);
        } catch { mode = 'this tab only (browser storage unavailable)'; mem.set(rec.caseId, rec); }
      },
      async allLogs() {
        const out = new Map();
        const db = await open();
        if (db) try { (await req(db, 'logs', 'getAll')).forEach(r => out.set(r.caseId, r)); } catch { }
        lsIndex().forEach(id => { if (!out.has(id)) { const r = SB.store.get(LS + id, null); if (r) out.set(id, r); } });
        mem.forEach((r, id) => out.set(id, r));
        return [...out.values()];
      },
      async putFile(f) {
        const db = await open();
        if (db) try { await req(db, 'files', 'put', f); return true; } catch { }
        memFiles.set(f.sha256, f); return false;
      },
      forgetLocal() { mem.clear(); memFiles.clear(); },
      async clear() {
        mem.clear(); memFiles.clear();
        lsIndex().forEach(id => { try { localStorage.removeItem(LS + id); } catch { } });
        try { localStorage.removeItem(LS + 'index'); } catch { }
        const db = await open();
        if (db) for (const s of ['logs', 'files']) try { await req(db, s, 'clear'); } catch { }
        try { localStorage.setItem(LS + 'cleared', String(Date.now())); } catch { }
      },
      async getFile(sha) {
        const db = await open();
        if (db) try { const r = await req(db, 'files', 'get', sha); if (r) return r; } catch { }
        return memFiles.get(sha) || null;
      },
    };
  })();

  // One promise chain per case, plus a Web Lock across tabs, so concurrent appends never extend the same head.
  const queues = new Map();
  function caseTask(id, fn) {
    const locked = () => (navigator.locks && navigator.locks.request) ? navigator.locks.request('scambunker-custody:' + id, fn) : fn();
    const p = (queues.get(id) || Promise.resolve()).then(locked).catch(e => { console.warn('[custody]', e); SB.toast('Custody log: ' + e.message); });
    queues.set(id, p);
    return p;
  }
  async function loadRecord(id) { const r = await Store.getLog(id); return r ? { outputs: {}, ...r } : { caseId: id, entries: [], outputs: {} }; }
  async function add(rec, fields, output) {
    if (output !== undefined && output !== null) {
      const clean = JSON.parse(JSON.stringify(output));
      fields.outputDigest = await outputDigest(clean);
      rec.outputs[fields.outputDigest] = clean;
    }
    const e = await appendEntry(rec.entries, { caseId: rec.caseId, ...fields });
    await Store.putLog(rec);
    return e;
  }

  const V = c => c.final || c.local || {};
  const rulesOf = c => [...new Set(((c.heuristics && c.heuristics.hits) || []).map(h => h.label))];
  const verdictInput = (c, source) => { const v = V(c); return { source, verdict: v.verdict || null, category: v.category || null, risk: v.risk != null ? v.risk : null, confidence: v.confidence != null ? v.confidence : null }; };

  async function addTextEvidence(rec, c, note) {
    const t = normText(c.text), sha = await textDigest(t);
    const stored = await Store.putFile({ sha256: sha, name: 'message.txt', type: 'text/plain; charset=utf-8', size: utf8Length(t), blob: new Blob([t], { type: 'text/plain;charset=utf-8' }) });
    await add(rec, { action: 'evidence-added', input: evidenceRecord({ kind: 'text', name: 'message.txt', type: 'text/plain; charset=utf-8', size: utf8Length(t), sha256: sha, acquiredAt: c.at, sourceUrl: c.url, note, stored }) });
  }

  async function intake(c) {
    const rec = await loadRecord(c.id);
    if (rec.entries.length) return;
    await add(rec, { action: 'case-created', input: { platform: c.platform || null, url: safeUrl(c.url), openedAt: c.at, text: c.text ? { sha256: await textDigest(c.text), chars: normText(c.text).length } : null, image: !!c.forensics } });
    if (c.text) await addTextEvidence(rec, c, 'Text pasted into the intake form; hashed as UTF-8 after NFC normalisation');
    if (safeUrl(c.url)) await add(rec, { action: 'evidence-added', input: evidenceRecord({ kind: 'link', name: c.url, type: 'text/uri-list', size: utf8Length(c.url), sha256: await textDigest(c.url), acquiredAt: c.at, sourceUrl: c.url, note: 'Link entered by the investigator (the URL string is hashed, not the page)' }) });
    if (c.forensics) {
      const f = c.forensics;
      let stored = false, note = 'Original file as received; hashed on intake';
      try {
        if (/^blob:/.test(c.imagePreview || '')) {
          const blob = await (await fetch(c.imagePreview)).blob();
          const sha = await sha256Hex(new Uint8Array(await blob.arrayBuffer()));
          if (sha === f.sha256) stored = await Store.putFile({ sha256: sha, name: f.name, type: f.type, size: blob.size, blob });
          else note += '; the preview copy did not match the intake hash, so it was not stored';
        }
      } catch { }
      await add(rec, { action: 'evidence-added', input: evidenceRecord({ kind: 'image', name: f.name || 'image', type: f.type, size: f.size, sha256: f.sha256, acquiredAt: c.at, sourceUrl: c.url, note, stored }) });
    }
    await add(rec, { action: 'analysis', input: { engines: ['heuristics'].concat(c.forensics ? ['metadata'] : []), verdict: V(c).verdict || null, risk: V(c).risk != null ? V(c).risk : null, rules: rulesOf(c) } }, c.local || null);
  }

  async function complete(c) {
    const rec = await loadRecord(c.id);
    if (!rec.entries.length) return;
    if (c.page) await add(rec, { action: 'web-fetch', input: { url: safeUrl(c.url), via: c.page.via || null, error: c.page.error || null, title: c.page.title || null, redirects: (c.page.redirects || []).length, contentSha256: c.page.markdown ? await textDigest(c.page.markdown) : null } });
    if ((c.corroboration || []).length) await add(rec, { action: 'web-search', input: { results: c.corroboration.length, urls: c.corroboration.map(r => safeUrl(r.url)).filter(Boolean).slice(0, 20) } });
    for (const [k, a] of Object.entries(c.agents || {})) {
      if (k === 'heuristics' || k === 'metadata' || !a || !['done', 'err'].includes(a.status)) continue;
      await add(rec, { action: 'agent-report', input: { agent: k, status: a.status === 'done' ? 'completed' : 'failed' } }, typeof a.report === 'string' ? a.report : a.report || null);
    }
    await add(rec, { action: 'verdict', input: verdictInput(c, c.final ? 'Lead Investigator' : 'Local engines') }, V(c));
  }

  // Saved cases from before the locker existed: start a log honestly marked as reconstructed.
  async function startLate(c) {
    const rec = await loadRecord(c.id);
    if (rec.entries.length) return;
    await add(rec, { action: 'log-started', input: { note: 'Log started after the fact from a saved case. Earlier actions were not logged, saved text may be truncated to 4,000 characters and the original image was not kept.', openedAt: c.at } });
    if (c.text) await addTextEvidence(rec, c, 'Reconstructed from the saved case (may be truncated)');
    if (c.forensics && c.forensics.sha256) await add(rec, { action: 'evidence-added', input: evidenceRecord({ kind: 'image', name: c.forensics.name || 'image', type: c.forensics.type, size: c.forensics.size, sha256: c.forensics.sha256, acquiredAt: c.at, sourceUrl: c.url, note: 'Hash recorded at the original intake; the file itself was not kept', stored: false }) });
    if (c.local || c.final) await add(rec, { action: 'verdict', input: verdictInput(c, c.final ? 'Lead Investigator (saved)' : 'Local engines (saved)') }, V(c));
  }

  // Keep the saved case (localStorage) in step with corrections, additively; the original fields are untouched.
  function markSavedCase(id, current, reason) {
    const list = SB.store.get('scambunker.cases', []);
    const x = list.find(i => i.id === id); if (!x) return;
    x.correction = { verdict: current.verdict, category: current.category, risk: current.risk, reason, at: new Date().toISOString() };
    SB.store.set('scambunker.cases', list);
  }

  // ======================= UI =======================
  const $ = s => document.querySelector(s);
  const escH = SB.esc;
  const VERDICTS = ['Scam', 'Likely scam', 'Suspicious', 'Misleading / manipulated', 'Coordinated / inauthentic', 'AI-generated content', 'Edited image', 'Likely legitimate', 'No strong red flags', 'Insufficient evidence'];
  const kb = n => n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : n > 1024 ? Math.round(n / 1024) + ' KB' : n + ' B';
  const linkOrDash = u => safeUrl(u) ? `<a href="${escH(u)}" target="_blank" rel="noopener noreferrer">${escH(u)}</a>` : '—';
  let renderToken = 0, statusMsg = '', verifyHtml = '';

  const style = document.createElement('style');
  style.textContent = `
.cust-scroll{overflow-x:auto;border:1px solid var(--line);border-radius:12px}
.cust-table{width:100%;border-collapse:collapse;font-size:13px}
.cust-table th,.cust-table td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;overflow-wrap:break-word}
.cust-table th{font:600 11.5px var(--mono);color:var(--muted);background:var(--bg-2);text-transform:uppercase;letter-spacing:.04em}
.cust-table tr:last-child td{border-bottom:0}
.cust-table td.cust-nw{white-space:nowrap;overflow-wrap:normal}
.cust-table code{font:12px var(--mono);color:var(--ink-2);overflow-wrap:anywhere}
.cust-table a{color:var(--accent)}
.cust-chain{display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:12px 14px;border-radius:12px;border:1px solid var(--line);margin-bottom:14px}
.cust-chain.ok{border-color:color-mix(in srgb,var(--green) 45%,var(--line));background:var(--green-soft)}
.cust-chain.bad{border-color:color-mix(in srgb,var(--red) 45%,var(--line));background:var(--red-soft)}
.cust-chain b{color:var(--ink)} .cust-chain.ok b{color:var(--green)} .cust-chain.bad b{color:var(--red)}
.cust-chain code{font:12px var(--mono);overflow-wrap:anywhere}
.cust-form{display:grid;gap:0;margin-top:8px}
.cust-form select,.cust-form input,.cust-form textarea{width:100%}
.cust-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.cust-actions label{display:flex;gap:8px;align-items:center;font-size:13.5px;color:var(--ink-2)}
.cust-result ul{margin:6px 0 0;padding-left:20px;font-size:13.5px}
`;
  document.head.appendChild(style);

  function problemsHtml(r) {
    const items = r.problems.concat((r.notes || []).map(n => ({ message: n })));
    return items.length ? `<ul>${items.map(p => `<li>${escH(p.message)}</li>`).join('')}</ul>` : '';
  }

  async function render(c) {
    const el = SB.panel('custody'); if (!el) return;
    const token = ++renderToken;
    if (!c) { el.innerHTML = '<p class="empty">Open a case to start its custody log.</p>'; return; }
    const same = el.dataset.caseId === c.id;
    const keep = id => same && document.getElementById(id) ? document.getElementById(id).value : '';
    const form = { field: keep('cust-field') || 'verdict', corrected: keep('cust-corrected'), what: keep('cust-what'), reason: keep('cust-reason'), finding: keep('cust-finding'), head: keep('cust-head') };
    const embedChecked = same && $('#cust-embed') ? $('#cust-embed').checked : true;
    if (!same) { statusMsg = ''; verifyHtml = ''; }
    const focusId = el.contains(document.activeElement) && document.activeElement.id;
    const rec = await loadRecord(c.id);
    const all = await Store.allLogs();
    if (token !== renderToken) return;
    el.dataset.caseId = c.id;
    const log = rec.entries;
    if (!log.length) {
      el.innerHTML = `<section><div class="callout">No custody log exists for this case yet. It was probably saved before the evidence locker was added. Starting one now records the saved text and the image hash taken at intake, and marks the log as started after the fact.</div><button type="button" class="primary sm" id="cust-start">Start custody log</button></section>`;
      return;
    }
    const chain = await verifyChain(log);
    if (token !== renderToken) return;
    const f = effectiveFindings(log);
    const evidence = log.filter(e => e.action === 'evidence-added');
    const lastVerdict = [...log].reverse().find(e => e.action === 'verdict');
    const obs = (lastVerdict && rec.outputs[lastVerdict.outputDigest] && rec.outputs[lastVerdict.outputDigest].observations) || [];
    const stats = ruleStats(all.filter(r => r.caseId !== c.id).map(r => r.entries));
    const myRules = (f.rules.length ? f.rules : rulesOf(c)).map(r => [r, stats[r]]).filter(([, s]) => s);
    const prev = { verdict: f.current.verdict, category: f.current.category, risk: f.current.risk };
    el.innerHTML = `
      <section aria-labelledby="cust-chain-h"><h3 id="cust-chain-h" class="sr-only">Chain status</h3>
        <div class="cust-chain ${chain.ok ? 'ok' : 'bad'}"><b>${chain.ok ? 'Chain intact' : 'Chain broken'}</b><span>${log.length} entries · stored in ${escH(Store.mode())}</span><span>Head <code>${escH(chain.head)}</code></span><button type="button" class="ghost" id="cust-recheck">Re-check chain and files</button></div>
        ${chain.ok ? '' : `<div class="callout">${problemsHtml(chain)}</div>`}
        <p class="muted" id="cust-recheck-out" role="status" aria-live="polite">${verifyHtml.startsWith('local:') ? verifyHtml.slice(6) : ''}</p>
      </section>
      <section aria-labelledby="cust-ev-h"><h3 id="cust-ev-h">Evidence locker</h3>
        <div class="cust-scroll" role="region" aria-label="Evidence locker table" tabindex="0"><table class="cust-table"><thead><tr><th scope="col">Item</th><th scope="col">SHA-256</th><th scope="col">Size</th><th scope="col">Acquired (UTC)</th><th scope="col">Source</th><th scope="col">Original</th></tr></thead><tbody>
        ${evidence.map(e => { const x = e.input; const notes = log.filter(n => n.action === 'evidence-note' && n.input.sha256 === x.sha256).map(n => n.input.note); return `<tr><td><b>${escH(x.kind)}</b> ${escH(x.name)}${x.note ? `<br><span class="muted">${escH(x.note)}</span>` : ''}${notes.map(n => `<br><span class="muted">Where I got this: ${escH(n)}</span>`).join('')}</td><td><code>${escH(x.sha256)}</code></td><td class="cust-nw">${escH(kb(x.size))}</td><td>${escH(x.acquiredAt)}</td><td>${linkOrDash(x.sourceUrl)}</td><td class="cust-nw">${escH(x.original)}</td></tr>`; }).join('') || '<tr><td colspan="6">No evidence recorded.</td></tr>'}
        </tbody></table></div>
        ${evidence.length ? `<div class="row" style="margin-top:12px"><label class="field grow"><span>Where I got this (recorded as a new log entry)</span><input id="cust-note" type="text" placeholder="e.g. Screenshot sent to me in a WhatsApp group on 2 May"></label>
        <label class="field"><span>Item</span><select id="cust-note-item">${evidence.map(e => `<option value="${escH(e.input.sha256)}">${escH(e.input.kind)}: ${escH(e.input.name.slice(0, 40))}</option>`).join('')}</select></label></div>
        <button type="button" class="ghost" id="cust-note-add">Record note</button>` : ''}
      </section>
      <section aria-labelledby="cust-corr-h"><h3 id="cust-corr-h">Correct a finding</h3>
        <p class="muted">Corrections are added to the log. Nothing earlier is edited or deleted, so the original finding stays visible.</p>
        ${f.original ? `<p>Current finding: <b>${escH(val(f.current.verdict))}</b> · ${escH(val(f.current.category))} · risk ${escH(val(f.current.risk))}${f.corrections.length ? ` <span class="muted">(originally ${escH(val(f.original.verdict))}, ${escH(f.original.source)})</span>` : ''}</p>` : '<p class="muted">No verdict has been recorded yet. It is logged when the investigation finishes.</p>'}
        <div class="cust-form">
          <div class="row"><label class="field"><span>What to correct</span><select id="cust-field">${[['verdict', 'Verdict'], ['category', 'Category'], ['risk', 'Risk score'], ['finding', 'A specific finding'], ['other', 'Something else']].map(([v, l]) => `<option value="${v}"${form.field === v ? ' selected' : ''}>${l}</option>`).join('')}</select></label>
          <label class="field grow" id="cust-finding-wrap"${form.field === 'finding' ? '' : ' hidden'}><span>Finding</span><select id="cust-finding">${obs.length ? obs.map((o, i) => `<option value="${i}"${form.finding === String(i) ? ' selected' : ''}>${escH(`[${o.weight}] ${o.fact} → ${o.inference}`.slice(0, 120))}</option>`).join('') : '<option value="">No findings recorded</option>'}</select></label></div>
          <label class="field"><span>Corrected value</span><input id="cust-corrected" type="text" list="cust-verdicts" value="${escH(form.corrected)}" placeholder="e.g. Likely legitimate"></label>
          <datalist id="cust-verdicts">${VERDICTS.map(v => `<option value="${escH(v)}"></option>`).join('')}</datalist>
          <label class="field"><span>What changed (optional)</span><textarea id="cust-what" rows="2" placeholder="e.g. The recruiter's domain belongs to the real company">${escH(form.what)}</textarea></label>
          <label class="field"><span>Why (required)</span><textarea id="cust-reason" rows="2" required aria-required="true" placeholder="The evidence that changed your mind, and where it came from">${escH(form.reason)}</textarea></label>
          <div class="cust-actions"><button type="button" class="primary sm" id="cust-correct">Record correction</button></div>
        </div>
        ${f.corrections.length ? `<h3 style="margin-top:18px">Corrections log</h3><ul class="list">${f.corrections.map(x => `<li><b>${escH(x.field)}</b>: “${escH(val(x.previous))}” → “${escH(val(x.corrected))}”${x.what ? `. ${escH(x.what)}` : ''}. <span class="muted">Why: ${escH(x.reason)} · ${escH(x.ts)}</span></li>`).join('')}</ul>` : ''}
        <h3 style="margin-top:18px">How reliable were these rules before?</h3>
        ${myRules.length ? `<ul class="list red">${myRules.map(([r, s]) => `<li><b>${escH(r)}</b>: this rule has been wrong ${s.wrong} time${s.wrong === 1 ? '' : 's'} in your cases (later corrected to legitimate).</li>`).join('')}</ul>` : `<p class="muted">None of the rules that fired here has been corrected as a false alarm in your other cases.</p>`}
      </section>
      <section aria-labelledby="cust-exp-h"><h3 id="cust-exp-h">Export evidence package</h3>
        <p class="muted">One HTML file: the readable report, the full log, every hash and a built-in integrity check. Send the head hash shown after export through a separate channel (for example in the body of your email), so the recipient can detect a rebuilt chain.</p>
        <div class="cust-actions"><button type="button" class="primary sm" id="cust-export">Export evidence package</button><label><input type="checkbox" id="cust-embed"${embedChecked ? ' checked' : ''}> Embed original files so the recipient can re-hash them</label></div>
        <p class="muted" id="cust-status" role="status" aria-live="polite">${statusMsg}</p>
      </section>
      <section aria-labelledby="cust-ver-h"><h3 id="cust-ver-h">Verify a package</h3>
        <div class="row"><label class="field grow"><span>Evidence package (.html or manifest .json)</span><input type="file" id="cust-verify-file" accept=".html,.htm,.json,text/html,application/json"></label>
        <label class="field grow"><span>Head hash received separately (optional)</span><input type="text" id="cust-head" spellcheck="false" autocomplete="off" value="${escH(form.head)}" placeholder="64 hex characters"></label></div>
        <div class="cust-result" id="cust-verify-out" role="status" aria-live="polite">${verifyHtml.startsWith('pkg:') ? verifyHtml.slice(4) : ''}</div>
      </section>
      <section aria-labelledby="cust-log-h"><h3 id="cust-log-h">Case log</h3>
        <div class="cust-scroll" role="region" aria-label="Case log table" tabindex="0"><table class="cust-table"><thead><tr><th scope="col">#</th><th scope="col">When (UTC)</th><th scope="col">Action</th><th scope="col">Detail</th><th scope="col">Entry hash</th></tr></thead><tbody>
        ${log.map(e => `<tr><td>${e.seq}</td><td>${escH(e.ts)}</td><td class="cust-nw">${escH(ACTION_LABEL[e.action] || e.action)}</td><td>${escH(summarizeEntry(e))}</td><td><code title="${escH(e.hash)}">${escH(short(e.hash))}</code></td></tr>`).join('')}
        </tbody></table></div>
      </section>`;
    el.dataset.prev = JSON.stringify(prev);
    if (focusId && document.getElementById(focusId)) document.getElementById(focusId).focus();
  }

  function download(name, text, type) {
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  }

  async function exportPackage(c) {
    const embed = $('#cust-embed') ? $('#cust-embed').checked : true;
    let out = null;
    await caseTask(c.id, async () => {
      const rec = await loadRecord(c.id);
      if (!rec.entries.length) throw new Error('No custody log for this case');
      const evidence = rec.entries.filter(e => e.action === 'evidence-added').map(e => e.input);
      const files = {}; let missing = 0, total = 0;
      if (embed) for (const x of evidence) {
        if (x.kind === 'link') continue;
        const fi = await Store.getFile(x.sha256);
        if (!fi || !fi.blob || total + fi.blob.size > 40 * 1048576) { missing++; continue; }
        files[x.sha256] = new Uint8Array(await fi.blob.arrayBuffer()); total += fi.blob.size;
      }
      await add(rec, { action: 'export', input: { format: FORMAT, embedsFiles: Object.keys(files).length > 0, embedded: Object.keys(files).length, embeddedFiles: Object.keys(files).sort(), evidence: evidence.length } });
      const v = V(c);
      out = await buildPackage({ entries: rec.entries, outputs: rec.outputs, files, caseMeta: { platform: c.platform || null, url: safeUrl(c.url), openedAt: c.at, verdictAtExport: v.verdict || null } });
      out.missing = missing;
    });
    if (!out) return;
    download(`scam-bunker-evidence-${c.id}.html`, out.html, 'text/html');
    statusMsg = `Exported. Head hash: <code>${escH(out.manifest.head)}</code>${out.missing ? ` · ${out.missing} original${out.missing === 1 ? ' was' : 's were'} not available to embed (only the hash is included)` : ''}`;
    SB.toast('Evidence package exported');
    await render(SB.current);
  }

  async function recheck(c) {
    const rec = await loadRecord(c.id);
    const chain = await verifyChain(rec.entries);
    const lines = [];
    for (const e of rec.entries.filter(x => x.action === 'evidence-added' && x.input.kind !== 'link')) {
      const fi = await Store.getFile(e.input.sha256);
      if (!fi || !fi.blob) { lines.push(`${e.input.name}: original not stored on this device`); continue; }
      const got = await sha256Hex(new Uint8Array(await fi.blob.arrayBuffer()));
      lines.push(`${e.input.name}: ${got === e.input.sha256 ? 'stored original matches its SHA-256' : 'stored original does NOT match its SHA-256'}`);
    }
    verifyHtml = 'local:' + escH(`${chain.ok ? 'Chain intact' : 'Chain broken'} (${chain.length} entries re-hashed). ${lines.join('. ')}${lines.length ? '.' : ''}`);
    const o = $('#cust-recheck-out'); if (o) o.innerHTML = verifyHtml.slice(6);
  }

  async function verifyFile(file) {
    const o = $('#cust-verify-out'); if (o) o.textContent = 'Checking…';
    const r = await verifyPackage(await file.text(), { expectedHead: ($('#cust-head') && $('#cust-head').value.trim()) || null });
    const ev = (r.evidence || []).map(e => `<li>${escH(e.name)}: ${escH(e.status === 'match' ? 'embedded file matches its SHA-256' : e.status === 'mismatch' ? 'embedded file does NOT match its SHA-256' : e.status === 'missing' ? 'embedded original was removed from the package' : 'original not embedded (hash only)')}</li>`).join('');
    verifyHtml = 'pkg:' + `<div class="cust-chain ${r.ok ? 'ok' : 'bad'}"><b>${r.ok ? 'Package intact' : 'Tampering detected'}</b><span>${escH(file.name)}${r.chain ? ` · ${r.chain.length} entries · report ${escH(r.report)}` : ''}</span></div>${problemsHtml(r)}${ev ? `<ul>${ev}</ul>` : ''}${!($('#cust-head') && $('#cust-head').value.trim()) && r.chain ? '<p class="muted">Without a head hash from the sender, removal of the newest entries or a fully rebuilt chain cannot be detected.</p>' : ''}`;
    if (o) o.innerHTML = verifyHtml.slice(4);
  }

  async function correct(c) {
    const field = $('#cust-field').value, reason = $('#cust-reason').value, what = $('#cust-what').value;
    let corrected = $('#cust-corrected').value.trim();
    const prev = JSON.parse(SB.panel('custody').dataset.prev || '{}');
    let previous = prev[field] != null ? prev[field] : null, correctsSeq = null;
    let input;
    try {
      if (!reason.trim()) throw new Error('Say why the finding is being corrected.');
      if (field === 'risk') { const n = Number(corrected); if (corrected === '' || !isFinite(n) || n < 0 || n > 100) throw new Error('Risk must be a number from 0 to 100.'); corrected = n; }
      else if (!corrected && field !== 'finding') throw new Error('Enter the corrected value.');
      const rec0 = await loadRecord(c.id);
      const lastVerdict = [...rec0.entries].reverse().find(e => e.action === 'verdict');
      if (['verdict', 'category', 'risk', 'finding'].includes(field)) {
        if (!lastVerdict) throw new Error('Wait until the verdict is logged, then correct it.');
        correctsSeq = lastVerdict.seq;
      }
      if (field === 'finding') {
        const obs = (lastVerdict && rec0.outputs[lastVerdict.outputDigest] && rec0.outputs[lastVerdict.outputDigest].observations) || [];
        const o = obs[Number($('#cust-finding').value)];
        if (!o) throw new Error('There is no recorded finding to correct.');
        previous = `[${o.weight}] ${o.fact} → ${o.inference}`;
        if (!corrected) corrected = 'withdrawn';
      }
      input = correctionInput({ field, previous, corrected, what, reason, rules: rulesOf(c), correctsSeq });
    } catch (e) { SB.toast(e.message); ($('#cust-reason').value.trim() ? $('#cust-corrected') : $('#cust-reason')).focus(); return; }
    await caseTask(c.id, async () => {
      const rec = await loadRecord(c.id);
      await add(rec, { action: 'correction', input });
      const fnd = effectiveFindings(rec.entries);
      if (['verdict', 'category', 'risk'].includes(field)) markSavedCase(c.id, fnd.current, input.reason);
    });
    ['cust-corrected', 'cust-what', 'cust-reason'].forEach(id => { const x = document.getElementById(id); if (x) x.value = ''; });
    SB.toast('Correction recorded. The original finding stays in the log');
    await render(SB.current);
    const h = $('#cust-corr-h'); if (h) { h.tabIndex = -1; h.focus(); }
  }

  // ---------- Events ----------
  document.addEventListener('sb:case', e => { const c = e.detail; caseTask(c.id, () => intake(c)).then(() => SB.current === c && render(c)); });
  document.addEventListener('sb:case-complete', e => { const c = e.detail; caseTask(c.id, () => complete(c)).then(() => SB.current === c && render(c)); });
  document.addEventListener('sb:case-open', () => render(SB.current));
  // The clearing tab already emptied shared storage; other tabs only drop their tab-local copies.
  window.addEventListener('storage', e => { if (e.key === LS + 'cleared') { Store.forgetLocal(); render(SB.current); } });
  document.addEventListener('click', e => {
    if (e.target.closest('#history-list .hist')) { setTimeout(() => render(SB.current), 0); return; }
    if (e.target.closest('#btn-history')) { setTimeout(annotateHistory, 0); return; }
    if (e.target.closest('#history-clear')) { Store.clear().then(() => render(SB.current)); return; }
    if (!e.target.closest('[id^="cust-"]')) return;
    const c = caseForPanel(SB.panel('custody')?.dataset.caseId, SB.current, SB.store.get('scambunker.cases', [])); if (!c) return;
    if (e.target.closest('#cust-start')) { caseTask(c.id, () => startLate(c)).then(() => render(SB.current)); return; }
    if (e.target.closest('#cust-export')) { exportPackage(c); return; }
    if (e.target.closest('#cust-recheck')) { recheck(c); return; }
    if (e.target.closest('#cust-correct')) { correct(c); return; }
    if (e.target.closest('#cust-note-add')) {
      const note = $('#cust-note').value.trim(), sha = $('#cust-note-item').value;
      if (!note) { SB.toast('Write where you got it first'); $('#cust-note').focus(); return; }
      caseTask(c.id, async () => { const rec = await loadRecord(c.id); await add(rec, { action: 'evidence-note', input: { sha256: sha, note } }); }).then(() => { SB.toast('Note recorded'); return render(SB.current); });
    }
  });
  document.addEventListener('change', e => {
    if (e.target.id === 'cust-field') { const w = $('#cust-finding-wrap'); if (w) w.hidden = e.target.value !== 'finding'; }
    if (e.target.id === 'cust-verify-file' && e.target.files[0]) verifyFile(e.target.files[0]).catch(err => { const o = $('#cust-verify-out'); if (o) o.textContent = 'Could not read the file: ' + err.message; });
  });

  function annotateHistory() {
    const list = SB.store.get('scambunker.cases', []);
    document.querySelectorAll('#history-list .hist').forEach(el => {
      const x = list.find(i => i.id === el.dataset.id);
      if (!x || !x.correction || el.querySelector('.cust-corrected')) return;
      const t = el.querySelector('.t b'); if (!t) return;
      const s = document.createElement('span'); s.className = 'tag cust-corrected'; s.style.marginLeft = '6px'; s.textContent = 'corrected → ' + x.correction.verdict;
      t.after(s);
    });
  }

  render(SB.current);
})();
