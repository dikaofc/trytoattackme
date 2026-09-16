import { getStats } from './_lib/store.js';
export default function handler(req,res){
  res.setHeader('Cache-Control','no-store');
  res.setHeader('Access-Control-Allow-Origin','*');
  res.status(200).json(getStats());
}
