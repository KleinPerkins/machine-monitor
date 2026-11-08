import https from 'node:https';
import {readFileSync} from 'node:fs';
import {fixture} from './update_worker.mjs';
import worker from '../../delivery/worker.mjs';
const f=fixture();let mode='normal',received=0,aborted=0;
const pending=new Set();
const realGet=f.env.ARCHIVES.get.bind(f.env.ARCHIVES);
f.env.ARCHIVES.get=async key=>{
  const object=await realGet(key);if(!object)return object;
  if(mode==='tamper')return {...object,body:new ReadableStream({start(c){c.enqueue(Buffer.alloc(object.size,1));c.close();}})};
  if(mode==='short')return {...object,size:object.size-1};
  if(mode==='slow'){
    const bytes=f.objects.get(key);let timer;
    return {...object,body:new ReadableStream({start(c){c.enqueue(bytes.subarray(0,3));timer=setTimeout(()=>{pending.delete(timer);c.enqueue(bytes.subarray(3));c.close();},1500);pending.add(timer);},cancel(){clearTimeout(timer);pending.delete(timer);aborted++;}})};
  }
  return object;
};
const server=https.createServer({key:readFileSync(process.argv[2]),cert:readFileSync(process.argv[3])},async(req,res)=>{
  try{
    if(req.url==='/fixture-state'){
      let text='';for await(const c of req)text+=c;
      if(req.method==='POST'){const value=JSON.parse(text);mode=value.mode||'normal';f.db.prepare('UPDATE grants SET revoked_at=? WHERE grant_id=?').run(mode==='revoked'?1:null,'friend');}
      res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({mode,received,aborted}));return;
    }
    const port=server.address().port,base=`https://127.0.0.1:${port}`;f.env.UPDATE_ORIGIN=base;
    const protectedPath=req.url.startsWith('/v1/');if(protectedPath)received++;
    if(protectedPath&&mode==='offline'){res.destroy();return;}
    if(protectedPath&&mode==='redirect'){res.writeHead(302,{Location:'https://forbidden.example.invalid/'});res.end();return;}
    if(req.url==='/favicon.ico'){res.writeHead(404);res.end();return;}
    const chunks=[];for await(const c of req)chunks.push(c);const body=Buffer.concat(chunks);
    const request=new Request(base+req.url,{method:req.method,headers:req.headers,...(body.length?{body}: {})});
    const response=await worker.fetch(request,f.env);
    if(res.destroyed)return;res.writeHead(response.status,Object.fromEntries(response.headers));
    if(!response.body){res.end();return;}
    const reader=response.body.getReader();let closed=false;
    res.on('close',()=>{closed=true;reader.cancel().catch(()=>{});});
    try{while(!closed){const {done,value}=await reader.read();if(done)break;res.write(value);}}finally{reader.releaseLock();}
    if(!closed)res.end();
  }catch{if(!res.destroyed){res.writeHead(500);res.end();}}
});
server.listen(0,'127.0.0.1',()=>{const origin=`https://127.0.0.1:${server.address().port}`;console.log(JSON.stringify({origin,access:{schema:'machine-monitor/access/v1',app_id:'com.kleinperkins.machine-monitor',origin,token:f.friend}}));});
function stop(){for(const t of pending)clearTimeout(t);pending.clear();server.closeAllConnections();server.close(()=>{f.close();process.exit(0);});}
process.on('SIGTERM',stop);process.on('SIGINT',stop);
