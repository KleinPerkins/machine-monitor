// Shared, import-safe wire validation. No field may select a different trust origin.
export const APP = 'com.kleinperkins.machine-monitor';
export const MAX_ARCHIVE = 512 * 1024 * 1024;
export const TOKEN = /^[A-Za-z0-9_-]{43}$/;
export const ID = /^[A-Za-z0-9_-]{1,128}$/;
export function origin(value) {
  const u = new URL(value);
  if (u.protocol !== 'https:' || u.username || u.password || u.origin !== value || u.hostname.endsWith('.r2.dev')) throw new Error('invalid origin');
  return value;
}
export function access(value, expectedOrigin) {
  if (!value || Object.keys(value).sort().join(',') !== 'app_id,origin,schema,token' ||
      value.schema !== 'machine-monitor/access/v1' || value.app_id !== APP ||
      origin(value.origin) !== expectedOrigin || !TOKEN.test(value.token) ||
      // Canonical base64url: the last character encodes only four significant bits.
      !'AEIMQUYcgkosw048'.includes(value.token.at(-1))) throw new Error('invalid access file');
  return value;
}
export function manifest(value, app = APP, channel, release) {
  const fields='app_id,architecture,archive,build,bundle_id,channel,data_schema_version,first_install,minimum_macos,qualification_id,qualified,schema,source_revision,team_id,version';
  if (!value || typeof value !== 'object' || Object.keys(value).sort().join(',')!==fields || value.schema !== 'machine-monitor/release/v1' ||
      value.app_id !== app || app !== APP || value.bundle_id !== APP || value.team_id !== 'J2V7GRV5CM' ||
      !['stable', 'qualification'].includes(value.channel) || (channel && value.channel !== channel) ||
      typeof value.version !== 'string' || !/^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,3}$/.test(value.version) ||
      !Number.isSafeInteger(value.build) || value.build < 1 || value.minimum_macos !== '26.0' ||
      value.architecture !== 'arm64' || value.data_schema_version !== 1 ||
      !/^[a-f0-9]{40}$/.test(value.source_revision) || !ID.test(value.qualification_id) ||
      typeof value.qualified !== 'boolean' || (value.channel === 'stable' && value.qualified !== true)) throw new Error('invalid manifest');
  validateDescriptor(value.archive, app, release, 'archive');
  validateDescriptor(value.first_install, app, release, 'package');
  if (value.archive.path.split('/').at(-2) !== value.first_install.path.split('/').at(-2)) throw new Error('release mismatch');
  return value;
}
export function validateDescriptor(a, app, release, kind) {
  const prefix = `/v1/apps/${app}/releases/`;
  if (!a || Object.keys(a).sort().join(',')!=='ed25519_signature,path,sha256,size' || typeof a.path !== 'string' || !a.path.startsWith(prefix) || !a.path.endsWith('/'+kind) ||
      !ID.test(a.path.slice(prefix.length, -(kind.length+1))) || (release && a.path !== `${prefix}${release}/${kind}`) ||
      !Number.isSafeInteger(a.size) || a.size < 1 || a.size > MAX_ARCHIVE || !/^[a-f0-9]{64}$/.test(a.sha256) ||
      typeof a.ed25519_signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(a.ed25519_signature) ||
      !'AQgw'.includes(a.ed25519_signature.at(-3))) throw new Error('invalid archive');
}
export async function sha256(bytes) {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), x => x.toString(16).padStart(2,'0')).join('');
}

// Immutable publication-only metadata. Full archive hashes/signatures stay on wire.
export const PART_SIZE=20*1024*1024;
export const PIECE_SIZE=1024*1024;
export function parts(value,app,release,kind,descriptor) {
  if(!Array.isArray(value)||value.length<1||value.length>512)throw new Error('parts');
  const stride=value[0]?.size;
  if(value.length>1&&![PART_SIZE,PIECE_SIZE].includes(stride))throw new Error('parts');
  let total=0;
  value.forEach((part,index)=>{
    if(!part || Object.keys(part).sort().join(',')!=='index,path,sha256,size' || part.index!==index ||
      !Number.isSafeInteger(part.size)||part.size<1||part.size>PART_SIZE ||
      (index<value.length-1&&part.size!==stride) || !/^[a-f0-9]{64}$/.test(part.sha256) ||
      part.path!==`/_private/${app}/${release}/${kind}/${descriptor.sha256}/${index}-${part.sha256}.part`)throw new Error('parts');
    total+=part.size;
  });
  if(total!==descriptor.size)throw new Error('parts');
  return value;
}

export function pieceDescriptor(value,descriptor) {
  const kind=descriptor.path.split('/').at(-1),release=descriptor.path.split('/').at(-2);
  validateDescriptor(descriptor,APP,release,kind);
  if(!['archive','package'].includes(kind)||!value||Object.keys(value).sort().join(',')!=='app_id,artifact_sha256,artifact_size,kind,part_size,parts,release_id,schema'||
     value.schema!=='machine-monitor/artifact-parts/v1'||value.app_id!==APP||value.release_id!==release||value.kind!==kind||
     value.artifact_sha256!==descriptor.sha256||value.artifact_size!==descriptor.size||value.part_size!==PIECE_SIZE||
     !Array.isArray(value.parts)||value.parts.length!==Math.ceil(descriptor.size/PIECE_SIZE)||value.parts.length>512)throw new Error('pieces');
  let total=0;
  value.parts.forEach((p,i)=>{
    if(!p||Object.keys(p).sort().join(',')!=='index,sha256,size'||!Number.isSafeInteger(p.index)||p.index!==i||
       !Number.isSafeInteger(p.size)||p.size<1||p.size>PIECE_SIZE||(i<value.parts.length-1&&p.size!==PIECE_SIZE)||
       !/^[a-f0-9]{64}$/.test(p.sha256))throw new Error('pieces');
    total+=p.size;
  });
  if(total!==descriptor.size)throw new Error('pieces');
  return value;
}

// Reject duplicate keys, including escaped aliases, before JSON.parse can hide them.
export function parseWireJSON(text) {
  let i=0;
  const ws=()=>{while(/[\t\n\r ]/.test(text[i]??'x'))i++;};
  const string=()=>{const start=i;if(text[i++]!=='"')throw new Error('json');let escaped=false;while(i<text.length){const c=text[i++];if(c==='"'&&!escaped)return JSON.parse(text.slice(start,i));if(c.charCodeAt(0)<32)throw new Error('json');if(escaped)escaped=false;else if(c==='\\')escaped=true;}throw new Error('json');};
  function value(depth){ws();if(depth>24)throw new Error('json');const c=text[i];
    if(c==='{'){i++;ws();const keys=new Set();if(text[i]==='}'){i++;return;}while(true){ws();const key=string();if(keys.has(key))throw new Error('json');keys.add(key);ws();if(text[i++]!==':')throw new Error('json');value(depth+1);ws();if(text[i]==='}'){i++;return;}if(text[i++]!==',')throw new Error('json');}}
    else if(c==='['){i++;ws();if(text[i]===']'){i++;return;}while(true){value(depth+1);ws();if(text[i]===']'){i++;return;}if(text[i++]!==',')throw new Error('json');}}
    else if(c==='"')string();else{const start=i;while(i<text.length&&!/[\t\n\r ,}\]]/.test(text[i]))i++;if(start===i)throw new Error('json');JSON.parse(text.slice(start,i));}}
  value(0);ws();if(i!==text.length)throw new Error('json');return JSON.parse(text);
}
