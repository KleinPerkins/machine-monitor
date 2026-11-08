// Actual Worker over in-memory SQLite and private synthetic R2. No live bindings.
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import {randomBytes,createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import worker from '../../delivery/worker.mjs';
import {APP,manifest} from '../../delivery/contract.mjs';
export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export function fixture(origin='https://download.example.invalid') {
  const db=new DatabaseSync(':memory:');db.exec(readFileSync(new URL('../../delivery/schema.sql',import.meta.url),'utf8'));
  const archive=Buffer.from('Synthetic updater archive; never an application.');
  const first=Buffer.from('Synthetic first-install package containing fixture main and Recovery.');
  const makeRelease=(channel,release='release-2')=>({schema:'machine-monitor/release/v1',app_id:APP,bundle_id:APP,team_id:'J2V7GRV5CM',channel,version:'1.2',build:2,minimum_macos:'26.0',architecture:'arm64',data_schema_version:1,source_revision:'a'.repeat(40),qualification_id:'fixture-qualification',qualified:channel==='stable',
    archive:{path:`/v1/apps/${APP}/releases/${release}/archive`,size:archive.length,sha256:hash(archive),ed25519_signature:Buffer.alloc(64).toString('base64')},
    first_install:{path:`/v1/apps/${APP}/releases/${release}/package`,size:first.length,sha256:hash(first),ed25519_signature:Buffer.alloc(64).toString('base64')}});
  const put=(value)=>{const r=value.archive.path.split('/').at(-2);db.prepare('INSERT INTO releases VALUES(?,?,?,?,?,?,?,?,?)').run(APP,r,value.channel,JSON.stringify(value),value.archive.sha256,value.archive.size,`${APP}/${value.archive.sha256}.zip`,value.qualification_id,'{}');db.prepare('INSERT OR REPLACE INTO channels VALUES(?,?,?)').run(APP,value.channel,r);};
  put(makeRelease('stable'));put(makeRelease('qualification','owner-3'));
  const addGrant=(name,owner=false,channel='stable',expiry=Math.floor(Date.now()/1000)+3600)=>{
    const token=randomBytes(32).toString('base64url');
    db.prepare('INSERT INTO grants VALUES(?,?,?,?,?,?,?)').run(name,hash(token),name,Number(owner),expiry,null,Math.floor(Date.now()/1000));
    db.prepare('INSERT INTO entitlements VALUES(?,?,?)').run(name,APP,channel);return token;
  };
  const friend=addGrant('friend'),owner=addGrant('owner',true,'qualification'),expired=addGrant('expired',false,'stable',1),revoked=addGrant('revoked');
  db.prepare('UPDATE grants SET revoked_at=1 WHERE grant_id=?').run('revoked');
  let primaryReads=0,r2Reads=0;
  const objects=new Map([[`${APP}/${hash(archive)}.zip`,archive],[`${APP}/${hash(first)}.package.zip`,first]]);
  const env={UPDATE_ORIGIN:origin,DB:{withSession(mode){assert.equal(mode,'first-primary');primaryReads++;return{prepare(sql){return{bind(...params){return{async first(){return db.prepare(sql).get(...params)||null;}};}};}};}},ARCHIVES:{async head(key){r2Reads++;const b=objects.get(key);return b?{size:b.length}:null;},async get(key){r2Reads++;const b=objects.get(key);return b?{size:b.length,body:new ReadableStream({start(controller){controller.enqueue(b);controller.close();}})}:null;}}};
  const request=async(path,token=friend,options={})=>{const headers=new Headers(options.headers);if(token)headers.set('Authorization','Bearer '+token);return worker.fetch(new Request(origin+path,{...options,headers}),env);};
  return {db,env,friend,owner,expired,revoked,archive,first,objects,makeRelease,put,addGrant,request,get primaryReads(){return primaryReads;},get r2Reads(){return r2Reads;},close(){db.close();}};
}
async function run(){
 const f=fixture();let assertions=0;
 const expect=async(path,token,status,options)=>{const r=await f.request(path,token,options);assert.equal(r.status,status);assert.match(r.headers.get('Cache-Control'),/private.*no-store/);assert.equal(r.headers.get('Access-Control-Allow-Origin'),null);assert.equal(r.headers.get('Location'),null);assert.equal(r.headers.get('Cloudflare-CDN-Cache-Control'),'no-store');assertions++;return r;};
 const feed=`/v1/apps/${APP}/channels/stable/manifest`,archive=`/v1/apps/${APP}/releases/release-2/archive`,pkg=`/v1/apps/${APP}/releases/release-2/package`,qual=`/v1/apps/${APP}/channels/qualification/manifest`;
 try{
   for(const token of [null,'bad',f.expired,f.revoked]){await expect(feed,token,401);await expect(archive,token,401);await expect(pkg,token,401,{method:'HEAD'});}
   assert.equal(f.r2Reads,0);
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
   await expect(qual,f.owner,200);await expect(`/v1/apps/${APP}/releases/owner-3/archive`,f.owner,200);
   await expect(feed,f.owner,401);
   assert.throws(()=>f.db.prepare('INSERT INTO entitlements VALUES(?,?,?)').run('friend',APP,'qualification'));
   const check=await expect('/v1/access/check',f.friend,200,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({app_id:APP,channel:'stable'})});
   const access=await check.json();assert.equal(access.schema,'machine-monitor/access-status/v1');assert.equal(access.grant_id,'friend');assert.equal(typeof access.expires_at,'number');assert(!JSON.stringify(access).includes(f.friend));
   await expect('/v1/access/check',f.friend,400,{method:'POST',headers:{'Content-Type':'application/json'},body:'x'.repeat(2048)});
   await expect('/v1/access/check',f.friend,401,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({app_id:APP,channel:'qualification'})});
   const reads=f.primaryReads;await expect(feed,f.friend,200);assert.equal(f.primaryReads,reads+1);
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
   console.log(JSON.stringify({passed:true,assertions,primary_reads:f.primaryReads,r2_reads:f.r2Reads}));
 }finally{f.close();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)await run();
