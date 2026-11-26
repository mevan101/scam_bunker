// Linear-time HTML scanning for remote pages. Regexes such as /<script[\s\S]*?<\/script>/ or /<meta[^>]*>/ rescan to the
// end of the input for every unclosed opener, which is quadratic on hostile pages. Everything here moves forward only.
const RAW_TEXT = new Set(['script', 'style', 'noscript', 'title', 'textarea']);
const isNameStart = c => (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
const isNameChar = c => isNameStart(c) || (c >= 48 && c <= 57) || c === 45 || c === 58 || c === 95; // - : _

// Memoised forward search for the next "</name" so repeated openers cannot rescan the same text.
function closeFinder(html) {
  const memo = new Map();
  return (name, from) => {
    const m = memo.get(name);
    if (m && m.from <= from && (m.at === -1 || m.at >= from)) return m.at;
    const re = new RegExp(`</${name}(?![\\w:-])`, 'gi'); re.lastIndex = from;
    const hit = re.exec(html); const at = hit ? hit.index : -1;
    memo.set(name, { from, at });
    return at;
  };
}

// Memoised indexOf for single characters: each search resumes where the last one ended, so the total work stays linear.
function charFinder(html) {
  const memo = new Map();
  return (ch, from) => {
    const m = memo.get(ch);
    if (m && m.from <= from && (m.at === -1 || m.at >= from)) return m.at;
    const at = html.indexOf(ch, from);
    memo.set(ch, { from, at });
    return at;
  };
}

// Tokens: { type: 'text', text } | { type: 'tag', name, closing, raw, start, end } | { type: 'raw', name, raw, content }
// Raw-text elements (script, style, noscript, title, textarea) are returned whole, with content up to their close tag
// (or the end of the input when unclosed, as browsers do).
function* tokens(html) {
  html = String(html ?? '');
  const n = html.length, findClose = closeFinder(html), next = charFinder(html);
  // End of a tag: the first '>' outside a quoted attribute value (a quote right after '='). An unclosed quote falls back
  // to the first '>'.
  const tagEnd = from => {
    let j = from;
    for (;;) {
      const gt = next('>', j), dq = next('"', j), sq = next("'", j);
      const q = dq === -1 ? sq : sq === -1 ? dq : Math.min(dq, sq);
      if (q === -1 || gt === -1 || gt < q) return gt;
      let b = q - 1; while (b > j && (html.charCodeAt(b) === 32 || html.charCodeAt(b) === 9 || html.charCodeAt(b) === 10 || html.charCodeAt(b) === 13)) b--;
      if (html[b] !== '=') { j = q + 1; continue; } // a quote only opens an attribute value right after '='
      const close = next(html[q], q + 1);
      if (close === -1) return next('>', from);
      j = close + 1;
    }
  };
  let i = 0;
  while (i < n) {
    const lt = html.indexOf('<', i);
    if (lt === -1) { yield { type: 'text', text: html.slice(i) }; return; }
    if (lt > i) yield { type: 'text', text: html.slice(i, lt) };
    if (html.startsWith('<!--', lt)) { const e = html.indexOf('-->', lt + 4); if (e === -1) return; i = e + 3; continue; }
    const c1 = html.charCodeAt(lt + 1), closing = c1 === 47;
    const ns = closing ? lt + 2 : lt + 1;
    if (c1 === 33 || c1 === 63) { const e = html.indexOf('>', lt); if (e === -1) return; i = e + 1; continue; } // <!doctype, <?xml
    if (!isNameStart(html.charCodeAt(ns))) { yield { type: 'text', text: '<' }; i = lt + 1; continue; }
    let ne = ns + 1; while (ne < n && isNameChar(html.charCodeAt(ne))) ne++;
    const gt = tagEnd(ne);
    if (gt === -1) { yield { type: 'text', text: html.slice(lt) }; return; }
    const name = html.slice(ns, ne).toLowerCase(), raw = html.slice(lt, gt + 1);
    if (!closing && RAW_TEXT.has(name) && html.charCodeAt(gt - 1) === 47) { yield { type: 'raw', name, raw, content: '', closed: true }; i = gt + 1; continue; } // XHTML <script …/>
    if (!closing && RAW_TEXT.has(name)) {
      const at = findClose(name, gt + 1);
      if (at === -1) { yield { type: 'raw', name, raw, content: html.slice(gt + 1), closed: false }; return; }
      yield { type: 'raw', name, raw, content: html.slice(gt + 1, at), closed: true };
      const e = html.indexOf('>', at); if (e === -1) return; i = e + 1; continue;
    }
    yield { type: 'tag', name, closing, raw, start: lt, end: gt + 1 };
    i = gt + 1;
  }
}

// Visible text. skip: elements whose whole content is dropped (head is skipped only when it is closed).
// breaks: closing tags (and <br>) that become a newline instead of a space.
function htmlText(html, { skip = ['head', 'script', 'style', 'noscript'], breaks = null } = {}) {
  html = String(html ?? '');
  const drop = new Set(skip), out = [], findClose = closeFinder(html);
  let skipping = null;
  for (const t of tokens(html)) {
    if (skipping) { if (t.type === 'tag' && t.closing && t.name === skipping) { skipping = null; out.push(' '); } continue; }
    if (t.type === 'text') { out.push(t.text); continue; }
    if (t.type === 'raw') { out.push(drop.has(t.name) ? ' ' : ` ${t.content} `); continue; }
    if (!t.closing && drop.has(t.name) && findClose(t.name, t.end) !== -1) { skipping = t.name; out.push(' '); continue; }
    out.push(breaks && ((t.closing && breaks.has(t.name)) || (!t.closing && t.name === 'br')) ? '\n' : ' ');
  }
  return out.join('');
}

// Open tags with the given names, e.g. tagsNamed(html, ['meta']) → ['<meta property="og:title" content="…">', …]
function tagsNamed(html, names) {
  const want = new Set(names), out = [];
  for (const t of tokens(html)) if (t.type === 'tag' && !t.closing && want.has(t.name)) out.push(t.raw);
  return out;
}
// Raw-text elements (script, style, title…) with their opening tag and content.
function rawElements(html, name) {
  const out = [];
  for (const t of tokens(html)) if (t.type === 'raw' && t.name === name) out.push({ tag: t.raw, content: t.content, closed: t.closed });
  return out;
}
// Inner HTML of the first <name> element that has a closing tag (one forward search).
function firstElement(html, name) {
  html = String(html ?? '');
  for (const t of tokens(html)) {
    if (t.type === 'raw' && t.name === name) return t.closed ? t.content : null;
    if (t.type === 'tag' && !t.closing && t.name === name) {
      const at = closeFinder(html)(name, t.end);
      return at === -1 ? null : html.slice(t.end, at);
    }
  }
  return null;
}

// Attributes of one tag, lower-cased names, raw (undecoded) values. Single forward pass.
function tagAttrs(tag) {
  const s = String(tag), n = s.length, o = {};
  let i = 1;
  if (s.charCodeAt(i) === 47) i++;
  while (i < n && isNameChar(s.charCodeAt(i))) i++;
  const ws = c => c === 32 || c === 9 || c === 10 || c === 12 || c === 13;
  while (i < n) {
    while (i < n && (ws(s.charCodeAt(i)) || s[i] === '/')) i++;
    if (i >= n || s[i] === '>') break;
    const ks = i; while (i < n && !ws(s.charCodeAt(i)) && s[i] !== '=' && s[i] !== '>' && s[i] !== '/') i++;
    const key = s.slice(ks, i).toLowerCase();
    if (i === ks) { i++; continue; }
    while (i < n && ws(s.charCodeAt(i))) i++;
    let val = '';
    if (s[i] === '=') {
      i++; while (i < n && ws(s.charCodeAt(i))) i++;
      const q = s[i];
      if (q === '"' || q === "'") { const e = s.indexOf(q, i + 1); const end = e === -1 ? n : e; val = s.slice(i + 1, end); i = end + 1; }
      else { const vs = i; while (i < n && !ws(s.charCodeAt(i)) && s[i] !== '>') i++; val = s.slice(vs, i); }
    }
    if (key && !(key in o)) o[key] = val;
  }
  return o;
}

module.exports = { tokens, htmlText, tagsNamed, rawElements, firstElement, tagAttrs };
