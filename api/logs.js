import { S } from "./_lib/store.js";

const DEFAULT_LIMIT = 150;
const MAX_LIMIT = 500;

export default function handler(req, res) {
  const filter = req.query.filter || "all";
  const limit = Math.min(Number.parseInt(req.query.limit || String(DEFAULT_LIMIT), 10) || DEFAULT_LIMIT, MAX_LIMIT);

  let logs = S.requests;
  if (filter === "blocked") logs = logs.filter((r) => r.blocked);
  if (filter === "allowed") logs = logs.filter((r) => !r.blocked);

  res.setHeader("Cache-Control", "no-store");
  res.status(200).json({ total: S.requests.length, logs: logs.slice(0, limit) });
}
