const g = globalThis;
if (!g.__LAB__) {
  g.__LAB__ = {
    start: Date.now(),
    total: 0, blocked: 0,
    perSec: new Map(), // sec -> count
    perSecBlocked: new Map(),
    mrps: [], // {ts, rps, blocked}
    ips: new Map(), // ip -> {hits, blocked, last, ua, country, city, pathCounts:Map, methods:Map, statuses:Map}
    blockedIps: new Set(),
    paths: new Map(),
    methods: new Map(),
    statuses: new Map(),
    uas: new Map(),
    countries: new Map(),
    latencies: [], // ms
    requests: [], // last 500 {ts,ip,country,city,method,path,status,blocked,reason,ua,latency,size}
    config: { protection: true, rps: 25, burst: 50 },
    buckets: new Map(), // ip -> {tokens, last}
  };
}
export const S = g.__LAB__;

function sanitizeText(value, fallback = '-') {
  if (value == null) return fallback;
  const text = String(value).replace(/[\u0000-\u001F\u007F]/g, '').trim();
  return text ? text.slice(0, 256) : fallback;
}

export function record(entry) {
  const clean = {
    ts: Number(entry.ts) || Date.now(),
    ip: sanitizeText(entry.ip || 'unknown', 'unknown'),
    country: sanitizeText(entry.country || '-', '-'),
    city: sanitizeText(entry.city || '-', '-'),
    method: sanitizeText(entry.method || 'GET', 'GET'),
    path: sanitizeText(entry.path || '/', '/'),
    status: Number(entry.status) || 200,
    blocked: !!entry.blocked,
    reason: sanitizeText(entry.reason || '', ''),
    ua: sanitizeText(entry.ua || '-', '-'),
    latency: Number(entry.latency) || 0,
    size: Number(entry.size) || 0,
  };

  const sec = Math.floor(clean.ts / 1000);
  S.perSec.set(sec, (S.perSec.get(sec) || 0) + 1);
  if (clean.blocked) S.perSecBlocked.set(sec, (S.perSecBlocked.get(sec) || 0) + 1);
  for (const k of S.perSec.keys()) if (k < sec - 300) { S.perSec.delete(k); S.perSecBlocked.delete(k); }

  S.total++; if (clean.blocked) S.blocked++;
  const last = S.mrps.at(-1);
  if (!last || last.ts !== sec) {
    S.mrps.push({ ts: sec, rps: S.perSec.get(sec), blocked: S.perSecBlocked.get(sec) || 0 });
    if (S.mrps.length > 300) S.mrps.shift();
  } else { last.rps = S.perSec.get(sec); last.blocked = S.perSecBlocked.get(sec) || 0; }

  S.requests.unshift(clean);
  if (S.requests.length > 500) S.requests.pop();
  if (clean.latency != null) { S.latencies.push(clean.latency); if (S.latencies.length > 1000) S.latencies.shift(); }

  // aggregates
  const ip = S.ips.get(clean.ip) || { hits: 0, blocked: 0, last: 0, ua: clean.ua, country: clean.country, city: clean.city, pathCounts: new Map(), methods: new Map(), statuses: new Map() };
  ip.hits++; if (clean.blocked) ip.blocked++; ip.last = clean.ts; ip.ua = clean.ua; ip.country = clean.country; ip.city = clean.city;
  ip.pathCounts.set(clean.path, (ip.pathCounts.get(clean.path) || 0) + 1);
  ip.methods.set(clean.method, (ip.methods.get(clean.method) || 0) + 1);
  ip.statuses.set(clean.status, (ip.statuses.get(clean.status) || 0) + 1);
  S.ips.set(clean.ip, ip);

  S.paths.set(clean.path, (S.paths.get(clean.path) || 0) + 1);
  S.methods.set(clean.method, (S.methods.get(clean.method) || 0) + 1);
  S.statuses.set(clean.status, (S.statuses.get(clean.status) || 0) + 1);
  const uaKey = (clean.ua || '-').slice(0, 80);
  S.uas.set(uaKey, (S.uas.get(uaKey) || 0) + 1);
  if (clean.country && clean.country !== '-') S.countries.set(clean.country, (S.countries.get(clean.country) || 0) + 1);
}

export function getStats() {
  const nowSec = Math.floor(Date.now() / 1000);
  const curRps = S.perSec.get(nowSec) || 0;
  const curBlocked = S.perSecBlocked.get(nowSec) || 0;
  // 10s / 60s averages
  const sum = (m, n) => [...m.entries()].filter(([s]) => s > nowSec - n).reduce((a, [, c]) => a + c, 0);
  const rps10 = sum(S.perSec, 10) / 10, rps60 = sum(S.perSec, 60) / 60;
  const blocked10 = sum(S.perSecBlocked, 10), blocked60 = sum(S.perSecBlocked, 60);
  const unique = S.ips.size;
  const peak = S.mrps.length ? Math.max(...S.mrps.map(x => x.rps)) : 0;
  const avgLat = S.latencies.length ? S.latencies.reduce((a, b) => a + b, 0) / S.latencies.length : 0;
  const sorted = [...S.latencies].sort((a, b) => a - b);
  const p = q => sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * q))] : 0;

  // power meter: rps + unique factor capped 100
  const power = Math.min(100, Math.round((curRps / 80) * 70 + (unique / 50) * 20 + (curBlocked > 0 ? 10 : 0)));
  const level = power < 25 ? 'CALM' : power < 50 ? 'WARM' : power < 75 ? 'HOT' : power < 90 ? 'CRITICAL' : 'NUKED';
  const underAttack = power >= 50 || curRps > 40;

  const topIps = [...S.ips.entries()].sort((a, b) => b[1].hits - a[1].hits).slice(0, 12).map(([ip, v]) => ({
    ip, hits: v.hits, blocked: v.blocked, last: v.last, country: v.country, city: v.city, ua: v.ua,
    banned: S.blockedIps.has(ip),
    topPath: [...v.pathCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || '-',
  }));
  const topPaths = [...S.paths.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  const topUas = [...S.uas.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  const topCountries = [...S.countries.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  const byMethod = [...S.methods.entries()], byStatus = [...S.statuses.entries()];

  return {
    total: S.total, blocked: S.blocked, unique, curRps, curBlocked, rps10: +rps10.toFixed(1), rps60: +rps60.toFixed(1),
    blocked10, blocked60, peak, uptime: Date.now() - S.start,
    latency: { avg: +avgLat.toFixed(1), p50: +p(0.5).toFixed(1), p95: +p(0.95).toFixed(1), p99: +p(0.99).toFixed(1) },
    power, level, underAttack,
    history: S.mrps.slice(-120),
    topIps, topPaths, topUas, topCountries, byMethod, byStatus,
    config: S.config,
  };
}
