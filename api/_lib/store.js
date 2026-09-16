const g = globalThis;
if (!g.__LAB__) {
  g.__LAB__ = {
    start: Date.now(),
    total: 0,
    blocked: 0,
    perSec: new Map(),
    perSecBlocked: new Map(),
    mrps: [],
    ips: new Map(),
    blockedIps: new Set(),
    paths: new Map(),
    methods: new Map(),
    statuses: new Map(),
    uas: new Map(),
    countries: new Map(),
    latencies: [],
    requests: [],
    config: { protection: true, rps: 25, burst: 50 },
    buckets: new Map(),
  };
}
export const S = g.__LAB__;

// limits
const MAX_STORED_REQUESTS = 500;
const MAX_LATENCIES = 1000;
const RETENTION_SECS = 300;
const MAX_HISTORY = 300;

// power model
const POWER_RPS_NORM = 80;
const POWER_UNIQUE_NORM = 50;

export function sanitizeText(value, fallback = "-") {
  if (value == null) return fallback;
  const text = String(value).replace(/[\u0000-\u001F\u007F]/g, "").trim();
  return text ? text.slice(0, 256) : fallback;
}

export function normalizeIp(value) {
  if (!value || typeof value !== "string") return "unknown";
  const first = value.split(",").map((v) => v.trim()).filter(Boolean)[0] || value.trim();
  return first || "unknown";
}

export function record(entry) {
  const clean = {
    ts: Number(entry.ts) || Date.now(),
    ip: sanitizeText(entry.ip, "unknown"),
    country: sanitizeText(entry.country),
    city: sanitizeText(entry.city),
    method: sanitizeText(entry.method, "GET"),
    path: sanitizeText(entry.path, "/"),
    status: Number(entry.status) || 200,
    blocked: !!entry.blocked,
    reason: sanitizeText(entry.reason, ""),
    ua: sanitizeText(entry.ua),
    latency: Number(entry.latency) || 0,
    size: Number(entry.size) || 0,
  };

  const sec = Math.floor(clean.ts / 1000);
  S.perSec.set(sec, (S.perSec.get(sec) || 0) + 1);
  if (clean.blocked) S.perSecBlocked.set(sec, (S.perSecBlocked.get(sec) || 0) + 1);
  for (const k of S.perSec.keys()) if (k < sec - RETENTION_SECS) { S.perSec.delete(k); S.perSecBlocked.delete(k); }

  S.total++;
  if (clean.blocked) S.blocked++;

  const last = S.mrps.at(-1);
  if (!last || last.ts !== sec) {
    S.mrps.push({ ts: sec, rps: S.perSec.get(sec), blocked: S.perSecBlocked.get(sec) || 0 });
    if (S.mrps.length > MAX_HISTORY) S.mrps.shift();
  } else {
    last.rps = S.perSec.get(sec);
    last.blocked = S.perSecBlocked.get(sec) || 0;
  }

  S.requests.unshift(clean);
  if (S.requests.length > MAX_STORED_REQUESTS) S.requests.pop();

  S.latencies.push(clean.latency);
  if (S.latencies.length > MAX_LATENCIES) S.latencies.shift();

  let ipEntry = S.ips.get(clean.ip);
  if (!ipEntry) {
    ipEntry = { hits: 0, blocked: 0, last: 0, ua: clean.ua, country: clean.country, city: clean.city, pathCounts: new Map(), methods: new Map(), statuses: new Map() };
    S.ips.set(clean.ip, ipEntry);
  }
  ipEntry.hits++;
  if (clean.blocked) ipEntry.blocked++;
  ipEntry.last = clean.ts;
  ipEntry.ua = clean.ua;
  ipEntry.country = clean.country;
  ipEntry.city = clean.city;
  ipEntry.pathCounts.set(clean.path, (ipEntry.pathCounts.get(clean.path) || 0) + 1);
  ipEntry.methods.set(clean.method, (ipEntry.methods.get(clean.method) || 0) + 1);
  ipEntry.statuses.set(clean.status, (ipEntry.statuses.get(clean.status) || 0) + 1);

  S.paths.set(clean.path, (S.paths.get(clean.path) || 0) + 1);
  S.methods.set(clean.method, (S.methods.get(clean.method) || 0) + 1);
  S.statuses.set(clean.status, (S.statuses.get(clean.status) || 0) + 1);
  const uaKey = clean.ua.slice(0, 80);
  S.uas.set(uaKey, (S.uas.get(uaKey) || 0) + 1);
  if (clean.country !== "-") S.countries.set(clean.country, (S.countries.get(clean.country) || 0) + 1);
}

export function getStats() {
  const nowSec = Math.floor(Date.now() / 1000);
  const curRps = S.perSec.get(nowSec) || 0;
  const curBlocked = S.perSecBlocked.get(nowSec) || 0;

  const sum = (m, n) => [...m.entries()].filter(([s]) => s > nowSec - n).reduce((a, [, c]) => a + c, 0);
  const rps10 = sum(S.perSec, 10) / 10;
  const rps60 = sum(S.perSec, 60) / 60;
  const blocked10 = sum(S.perSecBlocked, 10);
  const blocked60 = sum(S.perSecBlocked, 60);
  const unique = S.ips.size;
  const peak = S.mrps.length ? Math.max(...S.mrps.map((x) => x.rps)) : 0;

  const avgLat = S.latencies.length ? S.latencies.reduce((a, b) => a + b, 0) / S.latencies.length : 0;
  const sorted = [...S.latencies].sort((a, b) => a - b);
  const percentile = (q) => sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * q))] : 0;

  const power = Math.min(100, Math.round((curRps / POWER_RPS_NORM) * 70 + (unique / POWER_UNIQUE_NORM) * 20 + (curBlocked > 0 ? 10 : 0)));
  const level = power < 25 ? "CALM" : power < 50 ? "WARM" : power < 75 ? "HOT" : power < 90 ? "CRITICAL" : "NUKED";
  const underAttack = power >= 50 || curRps > 40;

  const topIps = [...S.ips.entries()]
    .sort((a, b) => b[1].hits - a[1].hits)
    .slice(0, 12)
    .map(([ip, v]) => ({
      ip,
      hits: v.hits,
      blocked: v.blocked,
      last: v.last,
      country: v.country,
      city: v.city,
      ua: v.ua,
      banned: S.blockedIps.has(ip),
      topPath: [...v.pathCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || "-",
    }));

  return {
    total: S.total,
    blocked: S.blocked,
    unique,
    curRps,
    curBlocked,
    rps10: +rps10.toFixed(1),
    rps60: +rps60.toFixed(1),
    blocked10,
    blocked60,
    peak,
    uptime: Date.now() - S.start,
    latency: { avg: +avgLat.toFixed(1), p50: +percentile(0.5).toFixed(1), p95: +percentile(0.95).toFixed(1), p99: +percentile(0.99).toFixed(1) },
    power,
    level,
    underAttack,
    history: S.mrps.slice(-120),
    topIps,
    topPaths: [...S.paths.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8),
    topUas: [...S.uas.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6),
    topCountries: [...S.countries.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8),
    byMethod: [...S.methods.entries()],
    byStatus: [...S.statuses.entries()],
    config: S.config,
  };
}
