// Actual Worker over in-memory SQLite and private synthetic Static Assets. No live bindings.
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import {randomBytes,createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import worker from '../../delivery/worker.mjs';
import {APP,manifest,PIECE_SIZE as PART_SIZE,parts,pieceDescriptor,parseWireJSON} from '../../delivery/contract.mjs';
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
 const expect=async(path,token,status,options)=>{const r=await f.request(path,token,options);assert.equal(r.status,status,path);assert.match(r.headers.get('Cache-Control'),/private.*no-store/);assert.equal(r.headers.get('Access-Control-Allow-Origin'),null);assert.equal(r.headers.get('Location'),null);assert.equal(r.headers.get('Cloudflare-CDN-Cache-Control'),'no-store');assertions++;return r;};
 const feed=`/v1/apps/${APP}/channels/stable/manifest`,archive=`/v1/apps/${APP}/releases/release-2/archive`,pkg=`/v1/apps/${APP}/releases/release-2/package`,qual=`/v1/apps/${APP}/channels/qualification/manifest`,piece=archive+'/parts/0';
 const download=async(path,token)=>{const desc=await(await expect(path+'/parts',token,200)).json(),chunks=[];for(const p of desc.parts){const r=await expect(path+'/parts/'+p.index,token,200),b=Buffer.from(await r.arrayBuffer());assert.equal(b.length,p.size);assert.equal(hash(b),p.sha256);chunks.push(b);}return Buffer.concat(chunks);};
 try{
  for(const token of [null,'bad',f.expired,f.revoked])for(const path of [feed,archive+'/parts',piece,pkg+'/parts/0'])await expect(path,token,401);
  assert.equal(f.assetReads,0);manifest(await(await expect(feed,f.friend,200)).json());
  await expect(archive,f.friend,503);await expect(pkg,f.friend,503,{method:'HEAD'});assert.equal(f.assetReads,0);
  assert.equal((await download(archive,f.friend)).toString(),f.archive.toString());assert.equal((await download(pkg,f.friend)).toString(),f.first.toString());
  const head=await expect(piece,f.friend,200,{method:'HEAD'});assert.equal(head.headers.get('Content-Length'),String(f.archive.length));assert.equal(await head.text(),'');
  await expect(archive+'/parts',f.friend,405,{method:'HEAD'});await expect(archive+'/parts/1',f.friend,400);
  await expect(piece,f.friend,416,{headers:{Range:'bytes=0-2'}});await expect(piece,f.revoked,401,{headers:{Range:'bytes=0-2'}});
  await expect(piece,f.friend,400,{headers:{'If-None-Match':'anything'}});await expect(piece,f.friend,403,{headers:{'Cloudflare-Workers-Version-Overrides':'monitor="unsafe"'}});
  for(const path of [feed,archive+'/parts',piece]){await expect(path,f.friend,403,{headers:{Origin:'https://attacker.invalid'}});await expect(path,f.friend,403,{headers:{'Sec-Fetch-Site':'cross-site'}});}
  await expect(feed+'?token=ignored',f.friend,400);await expect(feed,f.friend,405,{method:'OPTIONS'});await expect('/v1/apps/other.app/channels/stable/manifest',f.friend,401);
  for(const path of [qual,`/v1/apps/${APP}/releases/owner-3/archive/parts`,`/v1/apps/${APP}/releases/owner-3/package/parts/0`])await expect(path,f.friend,401);
  await expect(qual,f.owner,200);await expect(`/v1/apps/${APP}/releases/owner-3/archive/parts/0`,f.owner,200);await expect(feed,f.owner,401);
  assert.throws(()=>f.db.prepare('INSERT INTO entitlements VALUES(?,?,?)').run('friend',APP,'qualification'));
  const checked=await(await expect('/v1/access/check',f.friend,200,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({app_id:APP,channel:'stable'})})).json();assert.equal(checked.grant_id,'friend');assert(!JSON.stringify(checked).includes(f.friend));
  await expect('/v1/access/check',f.friend,400,{method:'POST',headers:{'Content-Type':'application/json'},body:'x'.repeat(2048)});
  await expect('/v1/access/check',f.friend,401,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({app_id:APP,channel:'qualification'})});
  for(const path of f.objects.keys()){await expect(path,f.friend,404);await expect(path,null,404);}
  const before=f.primaryReads;await expect(piece,f.friend,200);assert.equal(f.primaryReads,before+1);
  const multi=Buffer.alloc(PART_SIZE+7);for(let i=0;i<multi.length;i++)multi[i]=i%251;
  const mr=f.makeRelease('stable','multipart-8');mr.archive.size=multi.length;mr.archive.sha256=hash(multi);const mp=f.partRows(mr,'archive',multi);
  f.db.prepare('INSERT INTO releases VALUES(?,?,?,?,?,?,?,?,?)').run(APP,'multipart-8','stable',JSON.stringify(mr),mr.archive.sha256,mr.archive.size,`${APP}/${mr.archive.sha256}.zip`,mr.qualification_id,'{}');
  const path=`/v1/apps/${APP}/releases/multipart-8/archive`;assert.equal(hash(await download(path,f.friend)),hash(multi));assertions++;
  const table=pieceDescriptor(await(await expect(path+'/parts',f.friend,200)).json(),mr.archive);
  const stored=JSON.stringify(mp),database=f.env.DB;let storedOverride=null;
  // Inject a corrupt D1 result without disabling the real immutable-row trigger.
  f.env.DB={withSession(mode){const session=database.withSession(mode);return{prepare(sql){const statement=session.prepare(sql);return{bind(...params){const bound=statement.bind(...params);return{async first(){const row=await bound.first();return row?.release_id==='multipart-8'&&storedOverride!==null?{...row,parts_json:storedOverride}:row;}};}};}};}};
  // Publication uses compact scalar JSON. Reject duplicates, escaped aliases,
  // noncanonical encodings and nested values before any private asset read.
  for(const bad of [stored.replace('"index":0','"index":0,"index":0'),stored.replace('"index":0','"index":0,"\\u0069ndex":0'),
      ' '+stored,stored.replace('"index":0','"index":0.0'),stored.replace('"path"','"\\u0070ath"'),
      JSON.stringify(mp.map(p=>({...p,sha256:[p.sha256]}))),JSON.stringify(mp.map(p=>({...p,sha256:{nested:p.sha256}})))]){
   storedOverride=bad;const before=f.assetReads;await expect(path+'/parts/0',f.friend,503);await expect(path+'/parts/0',f.friend,503,{method:'HEAD'});await expect(path+'/parts',f.friend,503);assert.equal(f.assetReads,before);assertions++;
  }
  storedOverride=stored;await expect(path+'/parts/0',f.friend,200);await expect(path+'/parts/0',f.friend,200,{method:'HEAD'});f.env.DB=database;
  for(const change of [{extra:true},{part_size:20*PART_SIZE},{artifact_size:true},{artifact_sha256:'b'.repeat(64)},{kind:'package'},{release_id:'other'},{parts:[...table.parts].reverse()},{parts:[table.parts[0],table.parts[0]]},{parts:[]},{parts:table.parts.map(p=>({...p,index:true}))},{parts:table.parts.map(p=>({...p,size:p.size+1}))},{parts:table.parts.map(p=>({...p,url:'https://attacker.invalid'}))}]){assert.throws(()=>pieceDescriptor({...table,...change},mr.archive));assertions++;}
  for(const text of ['{"a":1,"a":2}','{"a":1,"\\u0061":2}','{"x":[{"b":1,"b":2}]}']){assert.throws(()=>parseWireJSON(text));assertions++;}assert.deepEqual(parseWireJSON('{"ok":[1,{"b":true}]}'),{ok:[1,{b:true}]});
  for(const bad of [[...mp].reverse(),[mp[0],mp[0]],mp.map((p,i)=>({...p,index:i+1})),mp.map(p=>({...p,path:p.path.replace('/archive/','/package/')}))]){assert.throws(()=>parts(bad,APP,'multipart-8','archive',mr.archive));assertions++;}
  await expect(path+'/parts/0',f.friend,200);const assetsBeforeRevoke=f.assetReads;f.db.prepare("UPDATE grants SET revoked_at=1 WHERE grant_id='friend'").run();await expect(path+'/parts/1',f.friend,401);assert.equal(f.assetReads,assetsBeforeRevoke);f.db.prepare("UPDATE grants SET revoked_at=NULL WHERE grant_id='friend'").run();
  const second=f.objects.get(mp[1].path);f.objects.delete(mp[1].path);await expect(path+'/parts/1',f.friend,503);f.objects.set(mp[1].path,second);
  const real=f.env.ASSETS;
  for(const headers of [{'Content-Length':String(f.archive.length-1)},{'Content-Length':'invalid'},{'Content-Encoding':'gzip'}]){let cancelled=0;f.env.ASSETS={fetch:async()=>new Response(new ReadableStream({cancel(){cancelled++;}}),{headers})};await expect(piece,f.friend,503);assert.equal(cancelled,1);assertions++;}
  for(const delta of [-1,1]){f.env.ASSETS={fetch:async()=>new Response(Buffer.alloc(f.archive.length+delta))};await expect(piece,f.friend,503);assertions++;}
  f.env.ASSETS={fetch:async()=>new Response(null,{status:429})};await expect(piece,f.friend,503);await expect(piece,f.revoked,401);
  f.env.ASSETS={fetch:async()=>new Response(Buffer.alloc(f.archive.length,3))};const tampered=await expect(piece,f.friend,200);assert.notEqual(hash(Buffer.from(await tampered.arrayBuffer())),hash(f.archive));assertions++;
  const timer=globalThis.setTimeout;try{
   globalThis.setTimeout=(fn,ms,...args)=>timer(fn,ms===30000?2:ms,...args);
   f.env.ASSETS={fetch:()=>new Promise(()=>{})};await expect(piece,f.friend,503);
   let cancelled=0;f.env.ASSETS={fetch:async()=>new Response(new ReadableStream({start(c){c.enqueue(f.archive);},cancel(){cancelled++;}}))};await expect(piece,f.friend,503);assert.equal(cancelled,1);assertions++;
  }finally{globalThis.setTimeout=timer;}
  let cancelled=0,started;const ready=new Promise(r=>started=r);f.env.ASSETS={fetch:async()=>new Response(new ReadableStream({start(){started();},cancel(){cancelled++;}}))};const abort=new AbortController();const pending=f.request(piece,f.friend,{signal:abort.signal});await ready;abort.abort();assert.equal((await pending).status,503);assert.equal(cancelled,1);assertions++;
  f.env.ASSETS=real;
  // Exercise the native bounded BYOB path, including the mandatory EOF probe.
  for(const transfer of [false,true]){let readCount=0,position=0;const data=f.archive;f.env.ASSETS={fetch:async()=>({status:200,headers:new Headers(),body:{getReader({mode}={}){assert.equal(mode,'byob');return{async readAtLeast(min,view){readCount++;const n=Math.min(view.length,data.length-position);view.set(data.subarray(position,position+n));position+=n;const offset=view.byteOffset;const result=transfer?new Uint8Array(structuredClone(view.buffer,{transfer:[view.buffer]}),offset,n):view.subarray(0,n);return{value:result,done:n===0};},async cancel(){},releaseLock(){}};}}})};assert.equal((await(await expect(piece,f.friend,200)).text()),data.toString());assert.equal(readCount,2);assertions++;}
  f.env.ASSETS=real;
  // A full-size read is not EOF. No response may escape while its final probe
  // is pending, and an extra byte on that probe must fail before delivery.
  for(const extra of [false,true]){
   let releaseEOF,probeStarted,reads=0,settled=false;
   const eof=new Promise(r=>releaseEOF=r),ready=new Promise(r=>probeStarted=r);
   const data=f.objects.get(mp[0].path);
   f.env.ASSETS={fetch:async()=>({status:200,headers:new Headers(),body:{getReader(){return{
    async readAtLeast(min,view){
     if(reads++===0){view.set(data);return{value:view.subarray(0,data.length),done:false};}
     probeStarted();await eof;
     if(extra){view[0]=1;return{value:view.subarray(0,1),done:false};}
     return{value:view.subarray(0,0),done:true};
    },async cancel(){},releaseLock(){}
   };}}})};
   const pending=f.request(path+'/parts/0',f.friend).then(r=>{settled=true;return r;});
   try{await ready;await new Promise(r=>setTimeout(r,0));assert.equal(settled,false);assertions++;}
   finally{releaseEOF();}
   const response=await pending;assert.equal(response.status,extra?503:200);
   if(!extra){const bytes=Buffer.from(await response.arrayBuffer());assert.equal(bytes.length,PART_SIZE);assert.equal(hash(bytes),mp[0].sha256);}
   assertions++;
  }
  f.env.ASSETS=real;
  // Legacy immutable20MiB metadata remains valid for retention, but not new delivery.
  const legacy=f.makeRelease('stable','legacy-9');legacy.archive.size=20*PART_SIZE+1;legacy.archive.sha256='b'.repeat(64);const lp=[20*PART_SIZE,1].map((size,index)=>({index,size,sha256:'c'.repeat(64),path:`/_private/${APP}/legacy-9/archive/${legacy.archive.sha256}/${index}-${'c'.repeat(64)}.part`}));parts(lp,APP,'legacy-9','archive',legacy.archive);f.db.prepare('INSERT INTO artifact_parts VALUES(?,?,?,?,?)').run(APP,'legacy-9','archive',legacy.archive.sha256,JSON.stringify(lp));f.db.prepare('INSERT INTO releases VALUES(?,?,?,?,?,?,?,?,?)').run(APP,'legacy-9','stable',JSON.stringify(legacy),legacy.archive.sha256,legacy.archive.size,`${APP}/${legacy.archive.sha256}.zip`,legacy.qualification_id,'{}');const n=f.assetReads;await expect(`/v1/apps/${APP}/releases/legacy-9/archive/parts`,f.friend,503);assert.equal(f.assetReads,n);
  const legacyAssets=f.assetReads;await expect(`/v1/apps/${APP}/releases/legacy-9/archive/parts/0`,f.friend,503);await expect(`/v1/apps/${APP}/releases/legacy-9/archive/parts/0`,f.friend,503,{method:'HEAD'});assert.equal(f.assetReads,legacyAssets);
  console.log(JSON.stringify({passed:true,assertions,primary_reads:f.primaryReads,asset_reads:f.assetReads}));
 }finally{f.close();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)await run();
