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
