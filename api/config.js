import { S } from "./_lib/store.js";

const MAX_RPS = 1000;
const MAX_BURST = 2000;

function parseBody(req) {
  let body = req.body;
  if (typeof body === "string") { try { body = JSON.parse(body); } catch { return {}; } }
  return body && typeof body === "object" ? body : {};
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

export default function handler(req, res) {
  if (req.method === "POST") {
    const b = parseBody(req);
    if (typeof b.rps === "number") S.config.rps = clamp(Math.floor(b.rps), 1, MAX_RPS);
    if (typeof b.burst === "number") S.config.burst = clamp(Math.floor(b.burst), 1, MAX_BURST);
    if (typeof b.protection === "boolean") S.config.protection = b.protection;

    if (b.action === "clear") {
      S.requests.length = 0;
      S.latencies.length = 0;
      S.mrps.length = 0;
      S.ips.clear();
      S.paths.clear();
      S.methods.clear();
      S.statuses.clear();
      S.uas.clear();
      S.countries.clear();
      S.perSec.clear();
      S.perSecBlocked.clear();
      S.blockedIps.clear();
      S.buckets.clear();
      S.total = 0;
      S.blocked = 0;
    }
    if (b.action === "block" && typeof b.ip === "string" && b.ip) S.blockedIps.add(b.ip.trim());
    if (b.action === "unblock" && typeof b.ip === "string" && b.ip) {
      S.blockedIps.delete(b.ip.trim());
      const bucket = S.buckets.get(b.ip.trim());
      if (bucket) bucket.violations = 0;
    }
  }

  res.setHeader("Cache-Control", "no-store");
  res.status(200).json({ config: S.config, blockedIps: [...S.blockedIps] });
}
