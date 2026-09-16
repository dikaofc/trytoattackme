import { S } from './_lib/store.js';
// public config — no auth per request (semua keliatan public)
export default function handler(req,res){
  if(req.method==='POST'){
    let b=req.body; if(typeof b==='string') try{b=JSON.parse(b)}catch{}
    if(typeof b?.rps==='number') S.config.rps=Math.max(1,Math.min(1000,b.rps));
    if(typeof b?.burst==='number') S.config.burst=Math.max(1,Math.min(2000,b.burst));
    if(typeof b?.protection==='boolean') S.config.protection=b.protection;
    if(b?.action==='clear'){ S.requests=[]; S.ips.clear(); S.paths.clear(); S.methods.clear(); S.statuses.clear(); S.uas.clear(); S.countries.clear(); S.perSec.clear(); S.perSecBlocked.clear(); S.mrps=[]; S.latencies=[]; S.total=0; S.blocked=0; S.blockedIps.clear(); S.buckets.clear(); }
    if(b?.action==='unblock'&&b.ip){ S.blockedIps.delete(b.ip); const buck=S.buckets.get(b.ip); if(buck) buck.violations=0; }
    if(b?.action==='block'&&b.ip) S.blockedIps.add(b.ip);
  }
  res.setHeader('Cache-Control','no-store');
  res.status(200).json({ config: S.config, blockedIps: [...S.blockedIps] });
}
