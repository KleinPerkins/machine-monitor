import {APP, TOKEN, ID, origin, manifest, sha256, parts} from './contract.mjs';
import {PAGE, CLIENT} from './web.mjs';
const POLICY = {
  'Cache-Control':'private, no-store, max-age=0', 'CDN-Cache-Control':'no-store',
  'Cloudflare-CDN-Cache-Control':'no-store', 'Pragma':'no-cache',
  'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'no-referrer',
  'Cross-Origin-Resource-Policy':'same-origin', 'Vary':'Authorization, Origin',
  'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security':'max-age=31536000',
};
const reply = (value, status=200, headers={}) => new Response(JSON.stringify(value), {status, headers:{...POLICY,'Content-Type':'application/json',...headers}});
const deny = () => reply({error:'access_denied'},401);
const READ_MS=30000;
async function timed(operation, cancel=()=>{}) {
  let timer;
  try {return await Promise.race([operation,new Promise((_,reject)=>{timer=setTimeout(()=>{reject(new Error('timeout'));cancel();},READ_MS);})]);}
  finally {clearTimeout(timer);}
}
async function asset(env, approved, part, method, signal) {
  // Construct a fresh internal request: never forward bearer/override/cookie headers.
  const abort=new AbortController();
  const cancel=()=>abort.abort(); signal?.addEventListener('abort',cancel,{once:true});
  try {
    if(signal?.aborted)throw new Error('cancelled');
    const response=await timed(env.ASSETS.fetch(new Request(approved+part.path,{method,signal:abort.signal})),cancel);
    // Static Assets may omit Content-Length. Reject an inconsistent declaration;
    // multipart() always enforces the immutable size on the actual streamed body.
    const length=response.headers.get('Content-Length');
    if(response.status!==200 || (length!==null && length!==String(part.size)) || response.headers.get('Content-Encoding')) {
      await response.body?.cancel();throw new Error('asset');
    }
    return response;
  }finally {signal?.removeEventListener('abort',cancel);}
}
async function multipart(env, approved, ordered, signal, ctx) {
  const first=await asset(env,approved,ordered[0],'GET',signal);
  if(!first.body)throw new Error('asset');
  const output=new FixedLengthStream(ordered.reduce((size,part)=>size+part.size,0));
  const writer=output.writable.getWriter();
  let reader=null,cancelled=false,buffer;
  const cancel=()=>{cancelled=true;reader?.cancel().catch(()=>{});};
  const abort=()=>{cancel();writer.abort(new Error('cancelled')).catch(()=>{});};
  signal?.addEventListener('abort',abort,{once:true});writer.closed.catch(cancel);
  const task=(async()=>{
    for(let index=0;index<ordered.length;index++) {
      const response=index===0?first:await asset(env,approved,ordered[index],'GET',signal);
      if(!response.body)throw new Error('asset');
      let byob=false;
      try {reader=response.body.getReader({mode:'byob'});byob=true;}catch {reader=response.body.getReader();}
      const native=byob&&typeof reader.readAtLeast==='function';let consumed=0;
      while(consumed<ordered[index].size) {
        if(cancelled||signal?.aborted)throw new Error('cancelled');
        let operation;
        if(native) {buffer??=new Uint8Array(4*1024*1024);operation=reader.readAtLeast(Math.min(buffer.length,ordered[index].size-consumed),buffer);}
        else if(byob) {const bytes=new Uint8Array(4*1024*1024);operation=reader.read(bytes,{min:Math.min(bytes.length,ordered[index].size-consumed)});}
        else operation=reader.read();
        const item=await timed(operation,cancel);
        if(cancelled||!item.value?.byteLength||consumed+item.value.byteLength>ordered[index].size)throw new Error('length');
        consumed+=item.value.byteLength;
        if(item.done&&consumed!==ordered[index].size)throw new Error('length');
        if(consumed===ordered[index].size&&!item.done) {
          // Check EOF before publishing this part's last bytes. Extra data must
          // never appear to be a valid complete response merely by its prefix.
          const end=await timed(native?reader.readAtLeast(1,new Uint8Array(1)):byob?reader.read(new Uint8Array(1),{min:1}):reader.read(),cancel);
          if(cancelled||signal?.aborted||!end.done||end.value?.byteLength)throw new Error('length');
        }
        if(cancelled||signal?.aborted)throw new Error('cancelled');
        await timed(writer.write(item.value),abort);
        // Workerd identity writes copy their bytes and settle on consumption.
        // Reuse only on its native BYOB path; generic streams get fresh buffers.
        if(native)buffer=new Uint8Array(item.value.buffer);
      }
      reader.releaseLock();reader=null;
    }
    await writer.close();
  })().catch(async()=>{await writer.abort(new Error('incomplete artifact')).catch(()=>{});}).finally(async()=>{
    signal?.removeEventListener('abort',abort);
    if(reader){await reader.cancel().catch(()=>{});reader.releaseLock();reader=null;}
    writer.releaseLock();
  });
  ctx?.waitUntil(task);
  return output.readable;
}
const auth = `FROM grants g JOIN entitlements e ON e.grant_id=g.grant_id
 WHERE g.token_hash=? AND e.app_id=? AND e.channel=? AND g.revoked_at IS NULL
 AND g.expires_at>? AND (e.channel!='qualification' OR g.is_owner=1)`;
// Exactly one primary read joins authorization and the release: a session's later
// reads may route to replicas, so do not reuse a session for the next request.
async function primary(env, sql, values) {
  return env.DB.withSession('first-primary').prepare(sql).bind(...values).first();
}
async function smallJSON(request) {
  if (request.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json') throw new Error('body');
  const reader=request.body?.getReader(); if (!reader) throw new Error('body');
  let size=0, chunks=[];
  try { while (true) {const {done,value}=await reader.read(); if(done)break; size+=value.length;if(size>1024)throw new Error('body');chunks.push(value);}}
  finally {await reader.cancel().catch(()=>{});reader.releaseLock();}
  const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}
export default {async fetch(request, env, ctx) {
  try {
    const approved=origin(env.UPDATE_ORIGIN), url=new URL(request.url);
    if(url.origin!==approved || url.search || url.username || url.password) return reply({error:'invalid_request'},400);
    if(request.headers.has('Cloudflare-Workers-Version-Overrides'))return reply({error:'version_override_denied'},403);
    const requestedOrigin=request.headers.get('Origin');
    if((requestedOrigin && requestedOrigin!==approved) || request.headers.get('Sec-Fetch-Site')==='cross-site') return reply({error:'cross_origin_denied'},403);
    if(request.method==='GET' && url.pathname==='/') return new Response(PAGE,{headers:{...POLICY,'Content-Type':'text/html; charset=utf-8'}});
    if(request.method==='GET' && url.pathname==='/download.js') return new Response(CLIENT,{headers:{...POLICY,'Content-Type':'text/javascript; charset=utf-8'}});
    const accessRoute=url.pathname==='/v1/access/check';
    const m=url.pathname.match(/^\/v1\/apps\/([A-Za-z0-9._-]+)\/channels\/(stable|qualification)\/manifest$/);
    const a=url.pathname.match(/^\/v1\/apps\/([A-Za-z0-9._-]+)\/releases\/([A-Za-z0-9._-]+)\/(archive|package)$/);
    if(!accessRoute&&!m&&!a) return reply({error:'not_found'},404);
    if((accessRoute&&request.method!=='POST')||(m&&request.method!=='GET')||(a&&!['GET','HEAD'].includes(request.method)))return reply({error:'method_not_allowed'},405);
    const match=request.headers.get('Authorization')?.match(/^Bearer ([A-Za-z0-9_-]{43})$/);
    if(!match || !TOKEN.test(match[1]))return deny();
    const hash=await sha256(new TextEncoder().encode(match[1])),now=Math.floor(Date.now()/1000);
    if(accessRoute){
      let body;try{body=await smallJSON(request);}catch{return reply({error:'invalid_request'},400);}
      if(body.app_id!==APP || !['stable','qualification'].includes(body.channel) || Object.keys(body).sort().join(',')!=='app_id,channel')return deny();
      const row=await primary(env,`SELECT g.grant_id,g.expires_at ${auth}`,[hash,body.app_id,body.channel,now]);
      return row?reply({schema:'machine-monitor/access-status/v1',app_id:body.app_id,channel:body.channel,grant_id:row.grant_id,expires_at:row.expires_at}):deny();
    }
    if((m||a)[1]!==APP)return deny();
    let row;
    if(m){
      row=await primary(env,`SELECT r.* FROM channels c JOIN releases r USING(app_id,release_id,channel)
        WHERE c.app_id=? AND c.channel=? AND EXISTS(SELECT 1 ${auth})`,[m[1],m[2],hash,m[1],m[2],now]);
    }else{
      if(!ID.test(a[2]))return deny();
      row=await primary(env,`SELECT r.*,p.parts_json FROM releases r LEFT JOIN artifact_parts p
        ON p.app_id=r.app_id AND p.release_id=r.release_id AND p.kind='${a[3]}'
        AND p.artifact_sha256=json_extract(r.manifest_json,'$.${a[3]==='package'?'first_install':'archive'}.sha256')
        WHERE r.app_id=? AND r.release_id=?
        AND EXISTS(SELECT 1 FROM grants g JOIN entitlements e ON e.grant_id=g.grant_id
          WHERE g.token_hash=? AND e.app_id=r.app_id AND e.channel=r.channel AND g.revoked_at IS NULL
          AND g.expires_at>? AND (r.channel!='qualification' OR g.is_owner=1))
        ORDER BY CASE r.channel WHEN 'stable' THEN 0 ELSE 1 END LIMIT 1`,[a[1],a[2],hash,now]);
    }
    if(!row)return deny();
    if(typeof row.manifest_json!=='string'||row.manifest_json.length>16384)throw new Error('manifest');
    const release=manifest(JSON.parse(row.manifest_json),APP,m?.[2],row.release_id);
    if(release.channel!==row.channel || release.archive.sha256!==row.archive_sha256 || release.archive.size!==row.archive_size ||
       row.object_key!==`${APP}/${release.archive.sha256}.zip`)throw new Error('manifest');
    if(m)return reply(release);
    const artifact=a[3]==='package'?release.first_install:release.archive;
    const ordered=parts(JSON.parse(row.parts_json),APP,row.release_id,a[3],artifact);
    // Conditional/range requests authorize first; never return a cached 304.
    if(request.headers.has('Range'))return reply({error:'ranges_unsupported'},416,{'Accept-Ranges':'none'});
    if([...request.headers.keys()].some(k=>k.startsWith('if-')))return reply({error:'conditions_unsupported'},400);
    let body=null;
    if(request.method==='HEAD') {
      for(const part of ordered)await asset(env,approved,part,'HEAD',request.signal);
    } else body=await multipart(env,approved,ordered,request.signal,ctx);
    return new Response(body,{headers:{...POLICY,
      'Content-Type':'application/zip','Content-Length':String(artifact.size),
      'Content-Disposition':'attachment; filename="Machine-Monitor.zip"','Accept-Ranges':'none'}});
  } catch {return reply({error:'service_unavailable'},503,{'Retry-After':'30'});}
}};
