const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}});
const now=()=>new Date().toISOString(), enc=new TextEncoder();
const b64u=b=>btoa(String.fromCharCode(...b)).replace(/=/g,'').replace(/\\+/g,'-').replace(/\\//g,'_');
const unb64u=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
async function mac(secret,data){const k=await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);return new Uint8Array(await crypto.subtle.sign('HMAC',k,enc.encode(data)))}
async function sessionToken(secret){const payload=b64u(enc.encode(JSON.stringify({sub:'owner',exp:Date.now()+12*60*60*1000})));return payload+'.'+b64u(await mac(secret,payload))}
async function validSession(req,secret){try{const raw=(req.headers.get('Cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('qla_session='))?.slice(12);if(!raw)return false;const [p,s]=raw.split('.');if(!p||!s)return false;const k=await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['verify']);if(!await crypto.subtle.verify('HMAC',k,unb64u(s),enc.encode(p)))return false;const data=JSON.parse(new TextDecoder().decode(unb64u(p)));return data.sub==='owner'&&data.exp>Date.now()}catch{return false}}
function sameOrigin(req,url){const origin=req.headers.get('Origin');return !origin||origin===url.origin}
async function log(env,event,detail=''){await env.DB.prepare('INSERT INTO activity(id,event,detail,created_at) VALUES(?,?,?,?)').bind(crypto.randomUUID(),event,String(detail).slice(0,240),now()).run()}
export default {async fetch(req,env){
 const u=new URL(req.url),p=u.pathname,m=req.method;
 if(p==='/api/health'&&m==='GET')return json({ok:true,app:'Quantum Leads AI',version:'1.1-secure'});
 if(!p.startsWith('/api/'))return env.ASSETS.fetch(req);
 if(!env.DB)return json({error:'Database is not configured.'},503);
 if(p==='/api/auth/login'&&m==='POST'){
  if(!sameOrigin(req,u))return json({error:'Invalid request origin.'},403);
  if(!env.OWNER_PASSWORD||!env.SESSION_SECRET||env.SESSION_SECRET.length<32)return json({error:'Owner authentication is not configured securely.'},503);
  let x;try{x=await req.json()}catch{return json({error:'Invalid request.'},400)}
  const a=enc.encode(String(x.password||'')),b=enc.encode(env.OWNER_PASSWORD);let diff=a.length^b.length;for(let i=0;i<Math.max(a.length,b.length);i++)diff|=(a[i]||0)^(b[i]||0);
  if(diff!==0){await log(env,'auth.failed','Owner login rejected');return json({error:'Incorrect password.'},401)}
  const token=await sessionToken(env.SESSION_SECRET);await log(env,'auth.login','Owner signed in');
  return json({ok:true},{status:200,headers:{'set-cookie':'qla_session='+token+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200'}});
 }
 if(p==='/api/auth/logout'&&m==='POST')return json({ok:true},{status:200,headers:{'set-cookie':'qla_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'}});
 if(!await validSession(req,env.SESSION_SECRET||''))return json({error:'Authentication required.'},401);
 if(['POST','PUT','PATCH','DELETE'].includes(m)&&!sameOrigin(req,u))return json({error:'Invalid request origin.'},403);
 if(p==='/api/auth/me'&&m==='GET')return json({authenticated:true});
 if(p==='/api/leads'&&m==='GET'){const {results}=await env.DB.prepare('SELECT * FROM leads ORDER BY created_at DESC LIMIT 1000').all();return json(results)}
 if(p==='/api/leads'&&m==='POST'){let x;try{x=await req.json()}catch{return json({error:'Invalid JSON.'},400)}if(!x.name?.trim())return json({error:'Lead name is required.'},400);const id=crypto.randomUUID(),t=now();await env.DB.prepare('INSERT INTO leads(id,name,company,email,source,status,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)').bind(id,x.name.trim().slice(0,160),String(x.company||'').slice(0,200),String(x.email||'').slice(0,254),String(x.source||'').slice(0,120),String(x.status||'New').slice(0,32),String(x.notes||'').slice(0,4000),t,t).run();await log(env,'lead.created',x.name);return json({id,...x,created_at:t},201)}
 const lm=p.match(/^\\/api\\/leads\\/([\\w-]+)$/);if(lm){const id=lm[1];if(m==='PUT'){const x=await req.json();if(!x.name?.trim())return json({error:'Lead name is required.'},400);await env.DB.prepare('UPDATE leads SET name=?,company=?,email=?,source=?,status=?,notes=?,updated_at=? WHERE id=?').bind(x.name.trim().slice(0,160),String(x.company||'').slice(0,200),String(x.email||'').slice(0,254),String(x.source||'').slice(0,120),String(x.status||'New').slice(0,32),String(x.notes||'').slice(0,4000),now(),id).run();return json({ok:true})}if(m==='DELETE'){await env.DB.prepare('DELETE FROM leads WHERE id=?').bind(id).run();await log(env,'lead.deleted',id);return json({ok:true})}}
 if(p==='/api/campaigns'&&m==='GET'){const {results}=await env.DB.prepare('SELECT * FROM campaigns ORDER BY created_at DESC').all();return json(results)}
 if(p==='/api/campaigns'&&m==='POST'){const x=await req.json();if(!x.name?.trim())return json({error:'Campaign name is required.'},400);const id=crypto.randomUUID(),t=now();await env.DB.prepare('INSERT INTO campaigns(id,name,audience,message,approved,created_at,updated_at) VALUES(?,?,?,?,0,?,?)').bind(id,x.name.trim().slice(0,160),String(x.audience||'').slice(0,2000),String(x.message||'').slice(0,6000),t,t).run();return json({id,...x,approved:0,created_at:t},201)}
 const cm=p.match(/^\\/api\\/campaigns\\/([\\w-]+)\\/(approve|delete)$/);if(cm&&m==='POST'){if(cm[2]==='approve'){await env.DB.prepare('UPDATE campaigns SET approved=1,updated_at=? WHERE id=?').bind(now(),cm[1]).run();await log(env,'campaign.approved',cm[1]);return json({ok:true,note:'Approved for a future connected channel; nothing is sent.'})}await env.DB.prepare('DELETE FROM campaigns WHERE id=?').bind(cm[1]).run();return json({ok:true})}
 if(p==='/api/activity'&&m==='GET'){const {results}=await env.DB.prepare('SELECT * FROM activity ORDER BY created_at DESC LIMIT 100').all();return json(results)}
 if(p==='/api/ai'&&m==='POST'){if(!env.AI)return json({error:'Workers AI binding is not enabled.'},503);const x=await req.json();const prompt=`You are Quantum Leads AI, a careful B2B growth assistant. Task: ${String(x.task||'qualify').slice(0,40)}. Business: ${String(x.business||'').slice(0,100)}. Context: ${String(x.context||'').slice(0,3000)}. Provide useful, factual, concise guidance. Do not invent verified facts, personal contact details, or claim to have searched websites. Respect privacy and opt-out requirements.`;try{const out=await env.AI.run('@cf/meta/llama-3.1-8b-instruct',{messages:[{role:'system',content:'You are a practical business growth assistant. Clearly label assumptions and never claim external research was performed.'},{role:'user',content:prompt}]});return json({result:out.response||out})}catch{return json({error:'AI request failed.'},502)}}
 return json({error:'API route not found.'},404);
}};