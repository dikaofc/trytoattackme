import { S } from './_lib/store.js';
export default function handler(req,res){
  const f=req.query.filter||'all';
  const limit=Math.min(parseInt(req.query.limit||'150'),500);
  let list=S.requests;
  if(f==='blocked') list=list.filter(r=>r.blocked);
  if(f==='allowed') list=list.filter(r=>!r.blocked);
  res.setHeader('Cache-Control','no-store');
  res.status(200).json({ total: S.requests.length, logs: list.slice(0,limit) });
}
