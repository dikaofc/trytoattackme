import { S, sanitizeText, normalizeIp } from "./store.js";

const VIOLATIONS_TO_BAN = 8;

export function clientInfo(req) {
  const fwd = req.headers["x-forwarded-for"];
  const ip = normalizeIp(fwd || req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown");
  const city = sanitizeText(req.headers["x-vercel-ip-city"] ? decodeURIComponent(req.headers["x-vercel-ip-city"]) : "-", "-");
  const country = sanitizeText(req.headers["x-vercel-ip-country"] || "-", "-");
  const ua = sanitizeText(req.headers["user-agent"] || "-", "-");
  const method = sanitizeText(req.method || "GET", "GET");
  const path = sanitizeText(req.url?.split("?")[0] || "/", "/");
  return { ip, city, country, ua, method, path };
}

export function checkLimit(ip) {
  const key = normalizeIp(ip);
  if (!S.config.protection) return { blocked: false };
  if (S.blockedIps.has(key)) return { blocked: true, reason: "IP banned" };

  const now = Date.now();
  const { rps, burst } = S.config;
  let bucket = S.buckets.get(key);
  if (!bucket) {
    bucket = { tokens: burst, last: now, violations: 0 };
    S.buckets.set(key, bucket);
  }

  const elapsed = (now - bucket.last) / 1000;
  bucket.tokens = Math.min(burst, bucket.tokens + elapsed * rps);
  bucket.last = now;

  if (bucket.tokens < 1) {
    bucket.violations += 1;
    if (bucket.violations > VIOLATIONS_TO_BAN) S.blockedIps.add(key);
    return { blocked: true, reason: `Rate ${rps}/s exceeded` };
  }

  bucket.tokens -= 1;
  return { blocked: false };
}
