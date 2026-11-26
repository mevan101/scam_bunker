// SSRF guard shared by every server-side fetch of a user-supplied URL.
// Only public internet hosts may be fetched: never localhost, LAN, link-local or cloud metadata addresses.
const net = require('net');
const dns = require('dns');
const http = require('http');
const https = require('https');

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
  }
  const v = ip.toLowerCase();
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(v); // ::ffff:7f00:1 is how URL() normalises ::ffff:127.0.0.1
  if (mapped) { const hi = parseInt(mapped[1], 16), lo = parseInt(mapped[2], 16); return isPrivateIp(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`); }
  if (v.startsWith('::ffff:')) return isPrivateIp(v.slice(7));
  return v === '::' || v === '::1' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80');
}

function httpError(status, message, code) { const e = new Error(message); e.status = status; if (code) e.code = code; return e; }

// Resolve-then-check. Used by callers that go through global fetch() (which resolves again: see guardedRequest for the
// stricter variant that checks the address the socket actually connects to).
async function assertPublicUrl(u) {
  const { protocol, hostname } = new URL(u);
  if (!/^https?:$/.test(protocol)) throw httpError(400, 'Only http(s) URLs can be fetched');
  const host = hostname.replace(/^\[|\]$/g, '');
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.promises.lookup(host, { all: true });
  if (!addrs.length || addrs.some(a => isPrivateIp(a.address))) throw httpError(403, 'Refusing to fetch a private or local network address', 'ssrf_blocked');
}

// GET a public URL with the guard applied at connect time (custom DNS lookup), on every redirect hop.
// Options: maxBytes, timeoutMs (whole request incl. redirects), maxRedirects, accept (RegExp on Content-Type),
// truncate (stop at maxBytes instead of failing), headers, isBlocked (ip => bool; tests only).
function guardedRequest(url, opts = {}) {
  const { maxBytes = 15 * 1024 * 1024, timeoutMs = 15000, maxRedirects = 5, accept = null, truncate = false, headers = {}, isBlocked = isPrivateIp } = opts;
  const deadline = Date.now() + timeoutMs;
  const redirects = [];

  const lookup = (hostname, options, cb) => {
    dns.lookup(hostname, { ...options, all: true }, (err, addrs) => {
      if (err) return cb(err);
      if (!addrs.length || addrs.some(a => isBlocked(a.address))) return cb(httpError(403, 'Refusing to fetch a private or local network address', 'ssrf_blocked'));
      if (options && options.all) return cb(null, addrs);
      cb(null, addrs[0].address, addrs[0].family);
    });
  };

  const hop = (cur, n) => new Promise((resolve, reject) => {
    let u;
    try { u = new URL(cur); } catch { return reject(httpError(400, 'Invalid URL')); }
    if (!/^https?:$/.test(u.protocol)) return reject(httpError(400, 'Only http(s) URLs can be fetched'));
    if (u.username || u.password) return reject(httpError(400, 'URLs with embedded credentials are not fetched'));
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(host) && isBlocked(host)) return reject(httpError(403, 'Refusing to fetch a private or local network address', 'ssrf_blocked'));
    const left = deadline - Date.now();
    if (left <= 0) return reject(httpError(504, 'Timed out', 'timeout'));
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.get(u, { lookup, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ScamBunkerProvenance/1.0)', 'Accept-Encoding': 'identity', ...headers } }, res => {
      const status = res.statusCode;
      redirects.push({ url: cur, status });
      const loc = res.headers.location;
      if (status >= 300 && status < 400 && loc) {
        res.resume(); clearTimeout(timer);
        if (n >= maxRedirects) return reject(httpError(502, 'Too many redirects', 'redirects'));
        return resolve(hop(new URL(loc, cur).href, n + 1)); // re-checked by lookup / IP check on the next hop
      }
      const done = (err, val) => { clearTimeout(timer); err ? reject(err) : resolve(val); };
      if (status < 200 || status >= 300) { res.resume(); return done(httpError(502, `Remote server answered HTTP ${status}`, 'http_status')); }
      const type = String(res.headers['content-type'] || '').toLowerCase();
      if (accept && !accept.test(type)) { res.destroy(); return done(Object.assign(httpError(415, `Not an accepted content type (${type || 'none'})`, 'bad_type'), { contentType: type, finalUrl: cur })); }
      const declared = +res.headers['content-length'];
      if (!truncate && declared > maxBytes) { res.destroy(); return done(httpError(413, `File is larger than ${Math.round(maxBytes / 1048576)} MB`, 'too_large')); }
      const chunks = []; let size = 0;
      res.on('data', c => {
        size += c.length;
        if (size > maxBytes) {
          if (truncate) { chunks.push(c.subarray(0, c.length - (size - maxBytes))); size = maxBytes; res.destroy(); finish(); }
          else { res.destroy(); done(httpError(413, `File is larger than ${Math.round(maxBytes / 1048576)} MB`, 'too_large')); }
          return;
        }
        chunks.push(c);
      });
      let finished = false;
      const finish = () => { if (finished) return; finished = true; done(null, { status, finalUrl: cur, redirects, headers: res.headers, contentType: type, buffer: Buffer.concat(chunks) }); };
      res.on('end', finish);
      res.on('error', e => done(e));
    });
    const timer = setTimeout(() => req.destroy(httpError(504, 'Timed out', 'timeout')), left);
    req.on('error', e => { clearTimeout(timer); reject(e.status ? e : httpError(502, `Could not fetch: ${e.code || e.message}`, 'network')); });
  });
  return hop(url, 0);
}

module.exports = { isPrivateIp, assertPublicUrl, guardedRequest, httpError };
