import {APP, MAX_ARCHIVE, TOKEN, ID, PIECE_SIZE, MAX_PIECES, WIRE_LIMIT, origin, access, manifest, validateDescriptor, pieceDescriptor, parseWireJSON, sha256} from './contract.mjs';
export const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Machine Monitor · Private download</title><style>
:root{color-scheme:light dark;--bg:#eff5f4;--card:#fff;--text:#163934;--muted:#3f5f59;--line:#aac5bf;--accent:#006c5c}*{box-sizing:border-box}[hidden]{display:none!important}body{margin:0;background:var(--bg);color:var(--text);font:17px/1.6 system-ui,sans-serif}main{max-width:700px;margin:7vh auto;padding:36px;background:var(--card);border:1px solid var(--line);border-radius:20px}small,.eyebrow{color:var(--muted)}h1{font-size:clamp(28px,6vw,40px);line-height:1.15;letter-spacing:-.04em;margin:8px 0 20px}h2{font-size:20px}.eyebrow{text-transform:uppercase;font-size:12px;font-weight:700;letter-spacing:.12em}label{display:block;font-weight:650;margin:24px 0 8px}input{display:block;width:100%;min-width:0;padding:12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);font:inherit}button,.download{font:inherit;font-weight:650;cursor:pointer;border-radius:8px;padding:12px 18px;border:1px solid var(--accent);min-height:48px}button{background:var(--accent);color:#fff}.secondary{background:transparent;color:var(--text);border-color:var(--line)}button:disabled{opacity:.5;cursor:default}.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px}.actions>button{flex:1}button:focus-visible,input:focus-visible,a:focus-visible{outline:3px solid #b35e00;outline-offset:4px}.status{min-height:128px;padding-top:16px}#status{margin:0}progress{display:block;width:100%;height:14px;margin-top:12px;accent-color:var(--accent)}#save{display:inline-block;color:var(--text);margin-top:12px}ol{padding-left:24px}footer{border-top:1px solid var(--line);margin-top:28px;padding-top:16px}a{overflow-wrap:anywhere}@media(max-width:600px){main{margin:16px;border-radius:12px;padding:24px 20px}.actions{flex-direction:column}.actions>button{width:100%}}@media(prefers-color-scheme:dark){:root{--bg:#102723;--card:#16332d;--text:#e2f5ef;--muted:#b2cfc6;--line:#56796f;--accent:#007f6d}}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
</style><script src="/download.js" defer></script></head><body><main><div class="eyebrow">Private personal-use download</div><h1>A clear view of your Mac.</h1><p>Machine Monitor runs locally on <strong>Apple Silicon · macOS 26 or later</strong>. Your metrics and process details stay on your Mac.</p><label for="access">Choose your access file</label><input id="access" type="file" accept=".machine-monitor-access,application/json" aria-describedby="file-help"><small id="file-help">Use the private .machine-monitor-access file you received from the owner. Keep it private.</small><div class="actions"><button id="download" disabled>Download Machine Monitor</button><button id="reset" class="secondary">Clear access</button></div><div class="status"><p id="status" role="status" aria-live="polite" aria-atomic="true">Choose your access file to begin.</p><progress id="progress" hidden aria-label="Download progress" max="100" value="0"></progress><a id="save" hidden download="Machine-Monitor.zip">Save verified download</a></div><h2>Install in a few steps</h2><ol><li>Download and unzip the package.</li><li>Move Machine Monitor and the separate Machine Monitor Recovery app to Applications. Keep Recovery available if the main app cannot open.</li><li>Open Machine Monitor, then import the same access file once in Update Settings to enable private updates.</li></ol><footer><small>The source is proprietary and source-visible. This private download gives authorized recipients personal-use permission only; it grants no redistribution rights. Third-party components retain their own notices. Your access file stays in browser memory during this visit; Clear access or closing this page releases the page’s references. Revocation stops future requests and cannot remove bytes already downloaded.</small></footer></main></body></html>`;
export const CLIENT = [
  `const APP=${JSON.stringify(APP)}, MAX_ARCHIVE=${MAX_ARCHIVE}, TOKEN=${TOKEN}, ID=${ID}, PIECE_SIZE=${PIECE_SIZE}, MAX_PIECES=${MAX_PIECES}, WIRE_LIMIT=${WIRE_LIMIT};`,
  origin.toString(), access.toString(), manifest.toString(), validateDescriptor.toString(), pieceDescriptor.toString(), parseWireJSON.toString(), sha256.toString(), String.raw`
'use strict';
(() => {
  const file=document.querySelector('#access'),button=document.querySelector('#download'),reset=document.querySelector('#reset'),status=document.querySelector('#status'),progress=document.querySelector('#progress'),save=document.querySelector('#save');
  let credential=null,generation=0,controller=null,objectURL=null,busy=false,deadline=Infinity;
  const show=(text)=>{status.textContent=text;};
  function clearDownload(){if(objectURL)URL.revokeObjectURL(objectURL);objectURL=null;save.removeAttribute('href');save.hidden=true;progress.hidden=true;progress.value=0;}
  function clear(){generation++;controller?.abort();controller=null;credential=null;deadline=Infinity;file.value='';busy=false;button.textContent='Download Machine Monitor';button.disabled=true;file.disabled=false;clearDownload();show('Choose your access file to begin.');}
  function current(g){if(g!==generation||Date.now()>=deadline)throw new DOMException('Access changed or deadline exceeded','AbortError');}
  async function request(path,options,g,timeout=20000){
    current(g);controller=new AbortController();const local=controller;
    const timer=setTimeout(()=>local.abort(),Math.min(timeout,deadline-Date.now()));
    try {
      const response=await fetch(path,{...options,signal:local.signal,redirect:'error',cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});current(g);
      if(!response.ok)throw new Error([401,403].includes(response.status)?'access':response.status===503?'service':'network');
      return {response,finish:()=>{clearTimeout(timer);if(controller===local)controller=null;}};
    }catch(e){clearTimeout(timer);if(controller===local)controller=null;throw e;}
  }
  async function json(path,options,g,limit=16384){const {response,finish}=await request(path,options,g);try{
    const reader=response.body.getReader();let length=0,parts=[];
    try {while(true){const {done,value}=await reader.read();current(g);if(done)break;length+=value.length;if(length>limit)throw new Error('verification');parts.push(value);}}finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
    const bytes=new Uint8Array(length);let offset=0;for(const p of parts){bytes.set(p,offset);offset+=p.length;}return parseWireJSON(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
  }finally{finish();}}
  file.addEventListener('change',async()=>{
    const selected=file.files[0];clear();if(!selected)return;const g=generation;
    try{if(selected.size>4096||selected.size<1)throw new Error('file');const text=await selected.text();current(g);credential=access(JSON.parse(text),location.origin);button.disabled=false;show('Access file selected. Download will check your access.');}
    catch(e){if(g!==generation)return;credential=null;show('Invalid access file. Choose the file from the owner for this download site.');}
  });
  button.addEventListener('click',async()=>{
    if(!credential||busy)return;const g=++generation;deadline=Date.now()+300000;busy=true;button.disabled=true;file.disabled=true;clearDownload();
    const headers={Authorization:'Bearer '+credential.token};
    try{
      show('Checking your access…');
      const checked=await json('/v1/access/check',{method:'POST',headers:{...headers,'Content-Type':'application/json'},body:JSON.stringify({app_id:APP,channel:'stable'})},g);current(g);
      if(checked.schema!=='machine-monitor/access-status/v1'||checked.app_id!==APP||checked.channel!=='stable'||typeof checked.grant_id!=='string'||!Number.isSafeInteger(checked.expires_at)||checked.expires_at<=Date.now()/1000)throw new Error('verification');
      show('Finding the current release…');
      const release=manifest(await json('/v1/apps/'+APP+'/channels/stable/manifest',{headers},g),APP,'stable');current(g);
      const artifact=release.first_install;
      show('Downloading Machine Monitor…');progress.hidden=false;progress.value=0;
      let table;
      try{table=pieceDescriptor(await json(artifact.path+'/parts',{headers},g,WIRE_LIMIT),artifact);}catch(e){if(['access','service','network'].includes(e.message)||e.name==='AbortError')throw e;throw new Error('verification');}
      let parts=[],length=0;
      for(const part of table.parts){
        current(g);const {response,finish}=await request(artifact.path+'/parts/'+part.index,{headers},g,30000);
        const bytes=new Uint8Array(part.size);let count=0;
        try{
          if(response.headers.get('Content-Length')!==String(part.size))throw new Error('verification');
          const reader=response.body.getReader();try{while(true){const {done,value}=await reader.read();current(g);if(done)break;if(count+value.length>part.size)throw new Error('verification');bytes.set(value,count);count+=value.length;}}
          finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
        }finally{finish();}
        if(count!==part.size||await sha256(bytes)!==part.sha256)throw new Error('verification');current(g);
        parts.push(bytes);length+=count;progress.value=100*length/artifact.size;
      }
      if(length!==artifact.size)throw new Error('verification');show('Verifying download…');
      const bytes=new Uint8Array(length);let offset=0;for(const p of parts){bytes.set(p,offset);offset+=p.length;}parts=[];
      if(await sha256(bytes)!==artifact.sha256)throw new Error('verification');current(g);
      const blob=new Blob([bytes],{type:'application/zip'});current(g);objectURL=URL.createObjectURL(blob);current(g);save.href=objectURL;save.hidden=false;
      show('Download verified. Save the package, then follow the installation steps below.');save.focus();
    }catch(e){
      if(g!==generation)return;clearDownload();
      show(e.message==='access'?'Access expired or revoked. Ask the owner for a new access file.':e.message==='verification'?'Download verification failed. Retry; if it repeats, contact the owner.':e.message==='service'?'The download service is temporarily unavailable. Retry shortly.':'Download interrupted or unavailable. Check your connection and retry.');
    }finally{if(g===generation){deadline=Infinity;busy=false;button.disabled=!credential;file.disabled=false;button.textContent='Retry download';}}
  });
  reset.addEventListener('click',clear);window.addEventListener('pagehide',clear);
})();`].join('\n');
