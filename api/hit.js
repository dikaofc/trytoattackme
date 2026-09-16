import { S, record } from './_lib/store.js';
import { clientInfo, checkLimit } from './_lib/protect.js';

// single endpoint — semua serangan kesini, mau GET POST apapun
export default async function handler(req, res) {
  const t0 = Date.now();
  const info = clientInfo(req);
  // read body size without heavy parse
  let size = 0;
  if (req.body) { try { size = JSON.stringify(req.body).length; } catch { size = 0; } }
  // query length
  const qlen = req.url?.length || 0;

  const chk = checkLimit(info.ip);
  const blocked = chk.blocked;
  const status = blocked ? 429 : 200;
  const latency = Date.now() - t0;

  record({
    ts: t0, ip: info.ip, country: info.country, city: info.city,
    method: info.method, path: info.path, status, blocked,
    reason: chk.reason || '', ua: info.ua, latency, size: size + qlen,
  });

  // headers biar tool ukur kelihatan
  res.setHeader('x-lab-status', blocked ? 'blocked' : 'passed');
  if (blocked) {
    res.setHeader('Retry-After', '2');
    return res.status(429).json({ blocked: true, reason: chk.reason, ip: info.ip, power: 'shielded' });
  }
  // echo back buat verifikasi tool
  res.status(200).json({ ok: true, ip: info.ip, ts: t0, method: info.method, path: info.path, shield: 'active' });
}
