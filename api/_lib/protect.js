import { S } from './store.js';

function normalizeIp(value) {
  if (!value || typeof value !== 'string') return 'unknown';
  const candidates = value.split(',').map(v => v.trim()).filter(Boolean);
  const first = candidates[0] || value.trim();
  return first === 'unknown' ? 'unknown' : first;
}

function sanitizeText(value, fallback = '-') {
  if (value == null) return fallback;
  const text = String(value).replace(/[\u0000-\u001F\u007F]/g, '').trim();
  return text ? text.slice(0, 256) : fallback;
}

export function clientInfo(req) {
  const fwd = req.headers['x-forwarded-for'];
  const ip = normalizeIp(fwd || req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown');
  const city = sanitizeText(req.headers['x-vercel-ip-city'] ? decodeURIComponent(req.headers['x-vercel-ip-city']) : '-', '-');
  const country = sanitizeText(req.headers['x-vercel-ip-country'] || '-', '-');
  const ua = sanitizeText(req.headers['user-agent'] || '-', '-');
  const method = sanitizeText(req.method || 'GET', 'GET');
  const path = sanitizeText(req.url?.split('?')[0] || '/', '/');
  return { ip, city, country, ua, method, path };
}

export function checkLimit(ip) {
  const key = normalizeIp(ip);
  if (!S.config.protection) return { blocked: false };
  if (S.blockedIps.has(key)) return { blocked: true, reason: 'IP banned' };
  let b = S.buckets.get(key);
  const now = Date.now(), rps = S.config.rps, burst = S.config.burst;
  if (!b) { b = { tokens: burst, last: now, violations: 0 }; S.buckets.set(key, b); }
  const elapsed = (now - b.last) / 1000;
  b.tokens = Math.min(burst, b.tokens + elapsed * rps);
  b.last = now;
  if (b.tokens < 1) {
    b.violations++;
    if (b.violations > 8) S.blockedIps.add(key);
    return { blocked: true, reason: `Rate ${rps}/s exceeded` };
  }
  b.tokens -= 1;
  // decay violations when well behaved would need track, skip — ponytail: add sliding window in Redis
  return { blocked: false };
}
