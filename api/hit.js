import { record } from "./_lib/store.js";
import { clientInfo, checkLimit } from "./_lib/protect.js";

export default function handler(req, res) {
  const t0 = Date.now();
  const info = clientInfo(req);

  let bodySize = 0;
  if (req.body) {
    try { bodySize = JSON.stringify(req.body).length; } catch { bodySize = 0; }
  }

  const check = checkLimit(info.ip);
  const blocked = check.blocked;
  const status = blocked ? 429 : 200;

  record({
    ts: t0,
    ip: info.ip,
    country: info.country,
    city: info.city,
    method: info.method,
    path: info.path,
    status,
    blocked,
    reason: check.reason || "",
    ua: info.ua,
    latency: Date.now() - t0,
    size: bodySize + (req.url?.length || 0),
  });

  res.setHeader("x-lab-status", blocked ? "blocked" : "passed");
  if (blocked) {
    res.setHeader("Retry-After", "2");
    return res.status(429).json({ blocked: true, reason: check.reason, ip: info.ip });
  }
  res.status(200).json({ ok: true, ip: info.ip, ts: t0, method: info.method, path: info.path });
}
