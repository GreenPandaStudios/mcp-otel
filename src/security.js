import crypto from 'node:crypto';
import https from 'node:https';
import dns from 'node:dns/promises';
import ipaddr from 'ipaddr.js';

export const random = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
export const hash = value => crypto.createHash('sha256').update(value).digest('hex');
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
export function equal(a, b) {
  const aa = Buffer.from(String(a)), bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
export function secretKey(value) {
  if (typeof value !== 'string' || !/^whsec_[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error('Invalid signing secret');
  const key = Buffer.from(value.slice(6), 'base64');
  if (key.length < 24 || key.length > 64 || key.toString('base64') !== value.slice(6)) throw new Error('Invalid signing secret');
  return key;
}
export function signature(secret, id, timestamp, body) {
  return `v1,${crypto.createHmac('sha256', secretKey(secret)).update(`${id}.${timestamp}.${body}`).digest('base64')}`;
}
export function verifySignature(secret, headers, body, now = Date.now()) {
  const ts = Number(headers['webhook-timestamp']);
  if (!Number.isSafeInteger(ts) || Math.abs(now / 1000 - ts) > 300) return false;
  const want = signature(secret, headers['webhook-id'], ts, body);
  return String(headers['webhook-signature'] ?? '').split(' ').some(s => equal(s, want));
}
export function cipher(keyBase64) {
  const key = Buffer.from(keyBase64 ?? '', 'base64');
  if (key.length !== 32) throw new Error('ENCRYPTION_KEY must be 32 random bytes encoded as base64');
  return {
    seal(value) {
      const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv);
      const data = Buffer.concat([c.update(JSON.stringify(value)), c.final()]);
      return Buffer.concat([iv, c.getAuthTag(), data]).toString('base64');
    },
    open(value) {
      const b = Buffer.from(value, 'base64'), c = crypto.createDecipheriv('aes-256-gcm', key, b.subarray(0, 12));
      c.setAuthTag(b.subarray(12, 28));
      return JSON.parse(Buffer.concat([c.update(b.subarray(28)), c.final()]).toString());
    }
  };
}
const sensitive = /^(authorization|cookie|set-cookie|password|passwd|secret|token|access_token|refresh_token|api[_-]?key|.*message[_-]?body|prompt|completion|transcript|messages)$/i;
export function redact(value, depth = 0) {
  if (depth > 14) return '[depth limit]';
  if (typeof value === 'string') return value.slice(0, 16384)
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9+/_=.:-]+/gi, '$1 [REDACTED]')
    .replace(/\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g, '[REDACTED]')
    .replace(/(["']?(?:password|secret|token|api[_-]?key)["']?\s*[=:]\s*["']?)[^"'\s,;}]+/gi, '$1[REDACTED]')
    .replace(/(["']?(?:prompt|completion|transcript|message_body|messages)["']?\s*:\s*).*/gi, '$1[WITHHELD]')
    .replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@]+:[^\s/@]+@/gi, '$1[REDACTED]@');
  if (Array.isArray(value)) return value.slice(0, 1000).map(v => redact(v, depth + 1));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) => [k, sensitive.test(k) ? '[REDACTED]' : redact(v, depth + 1)]));
  return value;
}
export const escapeHtml = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function isPublicIP(address) {
  try { return ipaddr.process(address).range() === 'unicast'; } catch { return false; }
}
export function callbackURL(value, hosts = []) {
  const u = new URL(value);
  if (u.protocol !== 'https:' || u.username || u.password || u.hash || (u.port && u.port !== '443') || value.length > 2048) throw new Error('Callback requires HTTPS on port 443');
  if (hosts.length && !hosts.some(h => h.startsWith('*.') ? u.hostname.endsWith(h.slice(1)) : u.hostname === h)) throw new Error('Callback host not allowed');
  return u;
}
// DNS is resolved anew for every connection and pinned by lookup. No redirects,
// proxies, connection pooling, cookies, or credentials cross this boundary.
export async function publicPost(url, body, headers = {}, hosts = [], resolve = dns.lookup) {
  const u = callbackURL(url, hosts);
  const addresses = await resolve(u.hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(a => !isPublicIP(a.address))) throw new Error('Callback resolves to non-public address');
  const chosen = addresses[0];
  return new Promise((resolve, reject) => {
    const req = https.request(u, {
      method: 'POST', agent: false, timeout: 10000, maxHeaderSize: 16384,
      lookup: (_name, options, done) => options.all ? done(null, [chosen]) : done(null, chosen.address, chosen.family),
      headers: { ...headers, 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }
    }, res => {
      const chunks = []; let size = 0;
      res.on('data', b => { size += b.length; if (size > 262144) res.destroy(new Error('Callback response too large')); else chunks.push(b); });
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on('timeout', () => req.destroy(new Error('Callback timeout')));
    req.on('error', reject); req.end(body);
  });
}
