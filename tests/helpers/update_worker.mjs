// Actual Worker over in-memory SQLite and private synthetic Static Assets. No live bindings.
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import {randomBytes,createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import worker from '../../delivery/worker.mjs';
import {APP,manifest,PART_SIZE,parts} from '../../delivery/contract.mjs';
// Workers runtime primitive; Node's Fetch implementation does not provide it.
globalThis.FixedLengthStream ??= class extends TransformStream {
  constructor(length) {
    let consumed=0;
    // Workerd identity writes copy bytes; generic TransformStream does not.
    super({transform(chunk,controller){consumed+=chunk.byteLength;if(consumed>length)throw new Error('length');controller.enqueue(new Uint8Array(chunk));},flush(){if(consumed!==length)throw new Error('length');}});
  }
};
export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export function fixture(origin='https://download.example.invalid') {
  const db=new DatabaseSync(':memory:');db.exec(readFileSync(new URL('../../delivery/schema.sql',import.meta.url),'utf8'));
  const archive=Buffer.from('Synthetic updater archive; never an application.');
  const first=Buffer.from('Synthetic first-install package containing fixture main and Recovery.');
  const makeRelease=(channel,release='release-2')=>({schema:'machine-monitor/release/v1',app_id:APP,bundle_id:APP,team_id:'J2V7GRV5CM',channel,version:'1.2',build:2,minimum_macos:'26.0',architecture:'arm64',data_schema_version:1,source_revision:'a'.repeat(40),qualification_id:'fixture-qualification',qualified:channel==='stable',
    archive:{path:`/v1/apps/${APP}/releases/${release}/archive`,size:archive.length,sha256:hash(archive),ed25519_signature:Buffer.alloc(64).toString('base64')},
    first_install:{path:`/v1/apps/${APP}/releases/${release}/package`,size:first.length,sha256:hash(first),ed25519_signature:Buffer.alloc(64).toString('base64')}});
  const objects=new Map();
  const partRows=(value,kind,bytes)=>{const release=value.archive.path.split('/').at(-2),desc=kind==='archive'?value.archive:value.first_install;const ordered=[];for(let offset=0;offset<bytes.length;offset+=PART_SIZE){const chunk=bytes.subarray(offset,offset+PART_SIZE),index=ordered.length,digest=hash(chunk),path=`/_private/${APP}/${release}/${kind}/${desc.sha256}/${index}-${digest}.part`;objects.set(path,chunk);ordered.push({index,path,size:chunk.length,sha256:digest});}db.prepare('INSERT OR IGNORE INTO artifact_parts VALUES(?,?,?,?,?)').run(APP,release,kind,desc.sha256,JSON.stringify(ordered));return ordered;};
  const put=(value)=>{partRows(value,'archive',archive);partRows(value,'package',first);const r=value.archive.path.split('/').at(-2);db.prepare('INSERT INTO releases VALUES(?,?,?,?,?,?,?,?,?)').run(APP,r,value.channel,JSON.stringify(value),value.archive.sha256,value.archive.size,`${APP}/${value.archive.sha256}.zip`,value.qualification_id,'{}');db.prepare('INSERT OR REPLACE INTO channels VALUES(?,?,?)').run(APP,value.channel,r);};
  put(makeRelease('stable'));put(makeRelease('qualification','owner-3'));
  const addGrant=(name,owner=false,channel='stable',expiry=Math.floor(Date.now()/1000)+3600)=>{
    const token=randomBytes(32).toString('base64url');
    db.prepare('INSERT INTO grants VALUES(?,?,?,?,?,?,?)').run(name,hash(token),name,Number(owner),expiry,null,Math.floor(Date.now()/1000));
    db.prepare('INSERT INTO entitlements VALUES(?,?,?)').run(name,APP,channel);return token;
  };
  const friend=addGrant('friend'),owner=addGrant('owner',true,'qualification'),expired=addGrant('expired',false,'stable',1),revoked=addGrant('revoked');
  db.prepare('UPDATE grants SET revoked_at=1 WHERE grant_id=?').run('revoked');
  let primaryReads=0,assetReads=0;
  // The real Static Assets binding may omit Content-Length, including on HEAD.
  const env={UPDATE_ORIGIN:origin,DB:{withSession(mode){assert.equal(mode,'first-primary');primaryReads++;return{prepare(sql){return{bind(...params){return{async first(){return db.prepare(sql).get(...params)||null;}};}};}};}},ASSETS:{async fetch(request){assetReads++;assert.equal(request.headers.get('Authorization'),null);assert.equal(request.headers.get('Cloudflare-Workers-Version-Overrides'),null);const b=objects.get(new URL(request.url).pathname);return b?new Response(request.method==='HEAD'?null:new ReadableStream({start(controller){controller.enqueue(b);controller.close();}})):new Response(null,{status:404});}}};
  const request=async(path,token=friend,options={})=>{const headers=new Headers(options.headers);if(token)headers.set('Authorization','Bearer '+token);return worker.fetch(new Request(origin+path,{...options,headers}),env);};
  return {db,env,friend,owner,expired,revoked,archive,first,objects,makeRelease,put,partRows,addGrant,request,get primaryReads(){return primaryReads;},get assetReads(){return assetReads;},close(){db.close();}};
}
async function run(){
 const f=fixture();let assertions=0;
 const expect=async(path,token,status,options)=>{const r=await f.request(path,token,options);assert.equal(r.status,status);assert.match(r.headers.get('Cache-Control'),/private.*no-store/);assert.equal(r.headers.get('Access-Control-Allow-Origin'),null);assert.equal(r.headers.get('Location'),null);assert.equal(r.headers.get('Cloudflare-CDN-Cache-Control'),'no-store');assertions++;return r;};
 const feed=`/v1/apps/${APP}/channels/stable/manifest`,archive=`/v1/apps/${APP}/releases/release-2/archive`,pkg=`/v1/apps/${APP}/releases/release-2/package`,qual=`/v1/apps/${APP}/channels/qualification/manifest`;
 try{
   for(const token of [null,'bad',f.expired,f.revoked]){await expect(feed,token,401);await expect(archive,token,401);await expect(pkg,token,401,{method:'HEAD'});}
   assert.equal(f.assetReads,0);
   const current=manifest(await(await expect(feed,f.friend,200)).json());assert.equal(current.build,2);
   assert.equal(await(await expect(archive,f.friend,200)).text(),f.archive.toString());
   assert.equal(await(await expect(pkg,f.friend,200)).text(),f.first.toString());
   const head=await expect(pkg,f.friend,200,{method:'HEAD'});assert.equal(head.headers.get('Content-Length'),String(f.first.length));assert.equal(await head.text(),'');
   await expect(archive,f.friend,416,{headers:{Range:'bytes=0-2'}});
   await expect(archive,f.revoked,401,{headers:{Range:'bytes=0-2'}});
   await expect(feed,f.friend,403,{headers:{Origin:'https://attacker.invalid'}});
   await expect(feed,f.friend,403,{headers:{'Sec-Fetch-Site':'cross-site'}});
   await expect(feed+'?token=ignored',f.friend,400);
   await expect(feed,f.friend,405,{method:'OPTIONS'});
   await expect('/'+APP+'/'+hash(f.archive)+'.zip',null,404);
   await expect('/v1/apps/other.app/channels/stable/manifest',f.friend,401);
   await expect(qual,f.friend,401);await expect(`/v1/apps/${APP}/releases/owner-3/archive`,f.friend,401);await expect(`/v1/apps/${APP}/releases/owner-3/package`,f.friend,401);
   await expect(qual,f.owner,200);await(await expect(`/v1/apps/${APP}/releases/owner-3/archive`,f.owner,200)).body.cancel();
   await expect(feed,f.owner,401);
   assert.throws(()=>f.db.prepare('INSERT INTO entitlements VALUES(?,?,?)').run('friend',APP,'qualification'));
   const check=await expect('/v1/access/check',f.friend,200,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({app_id:APP,channel:'stable'})});
   const access=await check.json();assert.equal(access.schema,'machine-monitor/access-status/v1');assert.equal(access.grant_id,'friend');assert.equal(typeof access.expires_at,'number');assert(!JSON.stringify(access).includes(f.friend));
   await expect('/v1/access/check',f.friend,400,{method:'POST',headers:{'Content-Type':'application/json'},body:'x'.repeat(2048)});
   await expect('/v1/access/check',f.friend,401,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({app_id:APP,channel:'qualification'})});
   const reads=f.primaryReads;await expect(feed,f.friend,200);assert.equal(f.primaryReads,reads+1);
   await expect(archive,f.friend,400,{headers:{'If-None-Match':'anything'}});
   await expect(archive,f.friend,403,{headers:{'Cloudflare-Workers-Version-Overrides':'monitor="unsafe"'}});
   const partPath=[...f.objects.keys()][0];await expect(partPath,f.friend,404);await expect(partPath,null,404);
   const multi=Buffer.alloc(PART_SIZE+7,9),multiRelease=f.makeRelease('stable','multi-7');multiRelease.archive.size=multi.length;multiRelease.archive.sha256=hash(multi);
   // Actual SQL authorization remains unchanged; only immutable part fixture bytes vary.
   // put() inserted the original fixture bytes: replace the whole fixture row using
   // a distinct valid identity, leaving immutable production triggers intact.
   const mr=f.makeRelease('stable','multipart-8');mr.archive.size=multi.length;mr.archive.sha256=hash(multi);f.partRows(mr,'archive',multi);
   f.db.prepare('INSERT INTO releases VALUES(?,?,?,?,?,?,?,?,?)').run(APP,'multipart-8','stable',JSON.stringify(mr),mr.archive.sha256,mr.archive.size,`${APP}/${mr.archive.sha256}.zip`,mr.qualification_id,'{}');
   const multiPath=`/v1/apps/${APP}/releases/multipart-8/archive`;
   const streamed=await expect(multiPath,f.friend,200);assert.equal(hash(Buffer.from(await streamed.arrayBuffer())),hash(multi));
   assertions++;
   const mp=JSON.parse(f.db.prepare("SELECT parts_json FROM artifact_parts WHERE release_id='multipart-8' AND kind='archive'").get().parts_json);
   for(const bad of [[...mp].reverse(),[mp[0],mp[0]],mp.map((p,i)=>({...p,index:i+1})),mp.map(p=>({...p,path:p.path.replace('/archive/','/package/')})),mp.map(p=>({...p,size:p.size+1}))]){assert.throws(()=>parts(bad,APP,'multipart-8','archive',mr.archive));assertions++;}
   const second=f.objects.get(mp[1].path);f.objects.delete(mp[1].path);const incomplete=await expect(multiPath,f.friend,200);await assert.rejects(()=>incomplete.arrayBuffer());assertions++;f.objects.set(mp[1].path,second);
   const realAssets=f.env.ASSETS;f.env.ASSETS={fetch:async()=>new Response(null,{status:429})};await expect(archive,f.friend,503);const before=f.assetReads;await expect(archive,f.revoked,401);assert.equal(f.assetReads,before);f.env.ASSETS=realAssets;
   const actualAssets=f.env.ASSETS;
   for(const headers of [{'Content-Length':String(f.archive.length-1)},{'Content-Length':'invalid'},{'Content-Encoding':'gzip'}]) {
     let cancelledBody=0;
     f.env.ASSETS={fetch:async()=>new Response(new ReadableStream({cancel(){cancelledBody++;}}),{headers})};
     await expect(archive,f.friend,503);assert.equal(cancelledBody,1);assertions++;
     await expect(archive,f.friend,503,{method:'HEAD'});assertions++;
   }
   // Headerless bodies still must match the immutable part's exact byte count.
   for(const delta of [-1,1]) {
     f.env.ASSETS={fetch:async()=>new Response(new ReadableStream({start(c){c.enqueue(Buffer.alloc(f.archive.length+delta));c.close();}}))};
     const broken=await expect(archive,f.friend,200);await assert.rejects(()=>broken.arrayBuffer());assertions++;
   }
   for(const delta of [-1,1]) {
     f.env.ASSETS={fetch:async()=>new Response(Buffer.alloc(f.archive.length+delta),{headers:{'Content-Length':String(f.archive.length)}})};
     const broken=await expect(archive,f.friend,200);await assert.rejects(()=>broken.arrayBuffer());assertions++;
   }
   f.env.ASSETS={fetch:async()=>new Response(Buffer.alloc(f.archive.length,3),{headers:{'Content-Length':String(f.archive.length)}})};
   const tampered=await expect(archive,f.friend,200);assert.notEqual(hash(Buffer.from(await tampered.arrayBuffer())),hash(f.archive));assertions++;
   const originalTimer=globalThis.setTimeout;
   try {
     globalThis.setTimeout=(fn,ms,...args)=>originalTimer(fn,ms===30000?1:ms,...args);
     f.env.ASSETS={fetch:()=>new Promise(()=>{})};await expect(archive,f.friend,503);assertions++;
     let timeoutCancelled=0;
     f.env.ASSETS={fetch:async()=>new Response(new ReadableStream({cancel(){timeoutCancelled++;}}),{headers:{'Content-Length':String(f.archive.length)}})};
     const timeout=await expect(archive,f.friend,200);await assert.rejects(()=>timeout.arrayBuffer());assert.equal(timeoutCancelled,1);assertions++;
     let stalledEOFCancelled=0;
     f.env.ASSETS={fetch:async()=>new Response(new ReadableStream({start(c){c.enqueue(f.archive);},cancel(){stalledEOFCancelled++;}}))};
     const stalledEOF=await expect(archive,f.friend,200);await assert.rejects(()=>stalledEOF.arrayBuffer());assert.equal(stalledEOFCancelled,1);assertions++;
   } finally {globalThis.setTimeout=originalTimer;f.env.ASSETS=actualAssets;}
   const realFetch=f.env.ASSETS.fetch;let cancelled=0,streamReads=0;
   f.env.ASSETS.fetch=async req=>{const response=await realFetch(req);return new Response(new ReadableStream({pull(c){streamReads++;c.enqueue(Buffer.from([1]));},cancel(){cancelled++;}}),{headers:response.headers});};
   const cancelResponse=await expect(archive,f.friend,200);assert(streamReads<=2);await cancelResponse.body.cancel();await new Promise(resolve=>setTimeout(resolve,0));assert.equal(cancelled,1);f.env.ASSETS.fetch=realFetch;assertions++;
   let pendingCancelled=0;
   f.env.ASSETS.fetch=async()=>new Response(new ReadableStream({pull(){return new Promise(()=>{});},cancel(){pendingCancelled++;}}));
   const pending=await expect(archive,f.friend,200);await pending.body.cancel();await new Promise(resolve=>setTimeout(resolve,0));assert.equal(pendingCancelled,1);assertions++;
   const aborted=new AbortController();
   const interrupted=await expect(archive,f.friend,200,{signal:aborted.signal});aborted.abort();
   await assert.rejects(()=>interrupted.arrayBuffer());assert.equal(pendingCancelled,2);assertions++;f.env.ASSETS.fetch=realFetch;
   // Exercise Workers' readAtLeast API and reused buffers with distinct data
   // across read and part boundaries. Standard Node BYOB uses its min option.
   const patterned=Buffer.alloc(PART_SIZE+19);for(let i=0;i<patterned.length;i++)patterned[i]=i%251;
   const native=f.makeRelease('stable','native-byob');native.archive.size=patterned.length;native.archive.sha256=hash(patterned);
   const nativeParts=f.partRows(native,'archive',patterned);
   f.db.prepare('INSERT INTO releases VALUES(?,?,?,?,?,?,?,?,?)').run(APP,'native-byob','stable',JSON.stringify(native),native.archive.sha256,native.archive.size,`${APP}/${native.archive.sha256}.zip`,native.qualification_id,'{}');
   let nativeReads=0,maximumBuffer=0;
   f.env.ASSETS.fetch=async request=>{
     const bytes=f.objects.get(new URL(request.url).pathname);
     const response=new Response(new ReadableStream({type:'bytes',start(c){c.enqueue(new Uint8Array(bytes));c.close();}}));
     const get=response.body.getReader.bind(response.body);
     response.body.getReader=options=>{const r=get(options);r.readAtLeast=(min,view)=>{nativeReads++;maximumBuffer=Math.max(maximumBuffer,view.byteLength);return r.read(view,{min});};return r;};
     return response;
   };
   const nativePath=`/v1/apps/${APP}/releases/native-byob/archive`;let retained;
   const nativeResponse=await worker.fetch(new Request('https://download.example.invalid'+nativePath,{headers:{Authorization:'Bearer '+f.friend}}),f.env,{waitUntil(task){retained=task;}});
   const chunks=[];for await(const chunk of nativeResponse.body)chunks.push(chunk);
   await retained;assert.equal(hash(Buffer.concat(chunks)),hash(patterned));assert.equal(nativeReads,8);assert.equal(maximumBuffer,4*1024*1024);assertions++;
   const nativeFirst=f.objects.get(nativeParts[0].path);f.objects.set(nativeParts[0].path,Buffer.concat([nativeFirst,Buffer.from([1])]));
   const extra=await expect(nativePath,f.friend,200);await assert.rejects(()=>extra.arrayBuffer());assertions++;f.objects.set(nativeParts[0].path,nativeFirst);
   f.objects.set(nativeParts[1].path,Buffer.alloc(18));const short=await expect(nativePath,f.friend,200);await assert.rejects(()=>short.arrayBuffer());assertions++;
   f.env.ASSETS=actualAssets;
   f.db.prepare('UPDATE grants SET revoked_at=? WHERE grant_id=?').run(Math.floor(Date.now()/1000),'friend');
   await expect(archive,f.friend,401);await expect(pkg,f.friend,401,{method:'HEAD'});
   const good=f.env.DB;f.env.DB={withSession(){throw new Error('private database failure');}};
   const err=await expect(feed,f.owner,503);assert.equal(await err.text(),'{"error":"service_unavailable"}');f.env.DB=good;
   const outsider=f.addGrant('outsider');f.db.prepare('UPDATE entitlements SET app_id=? WHERE grant_id=?').run('other.app','outsider');await expect(feed,outsider,401);
   for(const modify of [m=>m.archive.path='https://attacker.invalid/file',m=>m.first_install.path='/unsafe',m=>m.team_id='WRONG',m=>m.bundle_id='bad',m=>m.architecture='x86_64',m=>m.minimum_macos='25.0',m=>m.qualified=false,m=>m.archive.size=0,m=>m.archive.size=536870913,m=>m.build=1.5,m=>m.source_revision='no',m=>m.archive.ed25519_signature='bad']){const m=f.makeRelease('stable');modify(m);assert.throws(()=>manifest(m));assertions++;}
   const malformed=f.makeRelease('stable','bad-4');malformed.archive.path='https://attacker.invalid/object';f.put(malformed);const fresh=f.addGrant('fresh');await expect(feed,fresh,503);
   assert.throws(()=>f.db.prepare('UPDATE releases SET archive_size=1').run());
   const base=f.makeRelease('stable','missing-5');f.put(base);f.objects.clear();await expect(`/v1/apps/${APP}/releases/missing-5/archive`,fresh,503);
   const owned=fixture('https://monitor.owned-fixture.workers.dev');
   try {
     assert.equal((await owned.request(feed,owned.friend)).status,200);
     for(const host of ['alias.monitor.owned-fixture.workers.dev','other.owned-fixture.workers.dev','monitor.foreign.workers.dev']) {
       const response=await worker.fetch(new Request('https://'+host+feed,{headers:{Authorization:'Bearer '+owned.friend}}),owned.env);
       assert.equal(response.status,400);assert.match(response.headers.get('Cache-Control'),/no-store/);
       assertions++;
     }
   }finally{owned.close();}
   const noOrigin={...f.env,UPDATE_ORIGIN:'http://insecure.invalid'};assert.equal((await worker.fetch(new Request('http://insecure.invalid/'),noOrigin)).status,503);
   console.log(JSON.stringify({passed:true,assertions,primary_reads:f.primaryReads,asset_reads:f.assetReads}));
 }finally{f.close();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)await run();
