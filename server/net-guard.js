// SSRF guard shared by every server-side fetch of a user-supplied URL.
// Only public internet hosts may be fetched: never localhost, LAN, link-local or cloud metadata addresses.
const net = require('net');
const dns = require('dns');
const http = require('http');
const https = require('https');
const zlib = require('zlib');

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

// Resolve-then-check only. Never use it as the guard for a fetch of a user or remote URL: the socket resolves again and a
// rebinding DNS server can answer differently. Use guardedRequest, which checks the address the socket connects to.
async function assertPublicUrl(u) {
  const { protocol, hostname } = new URL(u);
  if (!/^https?:$/.test(protocol)) throw httpError(400, 'Only http(s) URLs can be fetched');
  const host = hostname.replace(/^\[|\]$/g, '');
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.promises.lookup(host, { all: true });
  if (!addrs.length || addrs.some(a => isPrivateIp(a.address))) throw httpError(403, 'Refusing to fetch a private or local network address', 'ssrf_blocked');
}

// GET a public URL with the guard applied at connect time (custom DNS lookup), on every redirect hop.
// Options: maxBytes, timeoutMs (whole request incl. redirects and body), maxRedirects, accept (RegExp on Content-Type),
// truncate (stop at maxBytes instead of failing), headers, anyStatus (return non-2xx bodies instead of failing),
// followRedirects (false: return the 3xx response itself), decompress (gzip/deflate/br, maxBytes applies to the
// decoded body), isBlocked (ip => bool) and resolve (dns.lookup-compatible): test seams only.
const DECODERS = new Map([['gzip', zlib.createGunzip], ['x-gzip', zlib.createGunzip], ['deflate', zlib.createInflate], ['br', zlib.createBrotliDecompress]]);
function guardedRequest(url, opts = {}) {
  const { maxBytes = 15 * 1024 * 1024, timeoutMs = 15000, maxRedirects = 5, accept = null, truncate = false, headers = {}, isBlocked = isPrivateIp,
    anyStatus = false, followRedirects = true, decompress = false, resolve: resolveHost = dns.lookup } = opts;
  const deadline = Date.now() + timeoutMs;
  const redirects = [];

  const lookup = (hostname, options, cb) => {
    resolveHost(hostname, { ...options, all: true }, (err, addrs) => {
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
    const reqHeaders = { 'User-Agent': 'Mozilla/5.0 (compatible; ScamBunkerProvenance/1.0)', ...headers, 'Accept-Encoding': decompress ? 'gzip, deflate, br' : 'identity' };
    const req = lib.get(u, { lookup, headers: reqHeaders }, res => {
      const status = res.statusCode;
      redirects.push({ url: cur, status });
      const loc = res.headers.location;
      if (status >= 300 && status < 400 && loc && followRedirects) {
        res.resume(); clearTimeout(timer);
        if (n >= maxRedirects) return reject(Object.assign(httpError(502, 'Too many redirects', 'redirects'), { finalUrl: cur, redirects }));
        let next; try { next = new URL(loc, cur).href; } catch { return reject(httpError(502, 'Invalid redirect location', 'redirects')); }
        return resolve(hop(next, n + 1)); // re-checked by lookup / IP check on the next hop
      }
      let settled = false;
      const done = (err, val) => { if (settled) return; settled = true; clearTimeout(timer); err ? reject(err) : resolve(val); };
      const result = buffer => ({ status, finalUrl: cur, redirects, headers: res.headers, contentType: type, location: loc || null, buffer });
      const type = String(res.headers['content-type'] || '').toLowerCase();
      if (status >= 300 && status < 400 && loc) { res.resume(); return done(null, result(Buffer.alloc(0))); }
      if (!anyStatus && (status < 200 || status >= 300)) { res.resume(); return done(httpError(502, `Remote server answered HTTP ${status}`, 'http_status')); }
      if (accept && !accept.test(type)) { res.destroy(); return done(Object.assign(httpError(415, `Not an accepted content type (${type || 'none'})`, 'bad_type'), { contentType: type, finalUrl: cur })); }
      const enc = String(res.headers['content-encoding'] || '').toLowerCase().trim();
      const makeDecoder = decompress ? DECODERS.get(enc) : null;
      const declared = +res.headers['content-length'];
      if (!truncate && !makeDecoder && declared > maxBytes) { res.destroy(); return done(httpError(413, `File is larger than ${Math.round(maxBytes / 1048576)} MB`, 'too_large')); }
      const stream = makeDecoder ? res.pipe(makeDecoder()) : res;
      const stop = () => { res.destroy(); if (stream !== res) stream.destroy(); };
      const chunks = []; let size = 0;
      const finish = () => done(null, result(Buffer.concat(chunks)));
      stream.on('data', c => {
        if (settled) return;
        size += c.length;
        if (size > maxBytes) {
          if (truncate) { chunks.push(c.subarray(0, c.length - (size - maxBytes))); size = maxBytes; stop(); finish(); }
          else { stop(); done(httpError(413, `File is larger than ${Math.round(maxBytes / 1048576)} MB`, 'too_large')); }
          return;
        }
        chunks.push(c);
      });
      stream.on('end', finish);
      stream.on('error', e => done(e.status ? e : httpError(502, `Could not read response: ${e.code || e.message}`, 'network')));
      res.on('close', () => { if (!res.complete) done(httpError(502, 'Connection closed before the response ended', 'network')); });
      if (stream !== res) res.on('error', e => { stream.destroy(); done(e.status ? e : httpError(502, `Could not read response: ${e.code || e.message}`, 'network')); });
    });
    const timer = setTimeout(() => req.destroy(httpError(504, 'Timed out', 'timeout')), left);
    req.on('error', e => { clearTimeout(timer); reject(e.status ? e : httpError(502, `Could not fetch: ${e.code || e.message}`, 'network')); });
  });
  return hop(url, 0);
}

module.exports = { isPrivateIp, assertPublicUrl, guardedRequest, httpError };
