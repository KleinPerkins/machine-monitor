#!/usr/bin/env python3
"""Owner-only Cloudflare delivery administration. Importing this module does no I/O.

Secrets are captured in memory from pinned Wrangler's original owner auth and are
never printed, placed in argv, written to config, or passed to recipient apps.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
APP = 'com.kleinperkins.machine-monitor'
WRANGLER = '4.158.0'
MAX_ARCHIVE = 512 * 1024 * 1024
CHECKS = ('ci_required', 'merged_source', 'developer_id', 'notarization',
          'stapled_ticket', 'gatekeeper', 'archive_signature', 'recovery_packaged')

class DeliveryError(Exception):
    """Safe, credential-free user-facing failure."""


def bounded_json(path, maximum=65536):
    with Path(path).open('rb') as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise DeliveryError('JSON input exceeds its size limit.')
    try:
        return json.loads(data)
    except (ValueError, UnicodeError):
        raise DeliveryError('Invalid JSON input.') from None


def outside_git(path):
    path = Path(path).absolute()
    if path != path.resolve():
        raise DeliveryError('Private files must use canonical paths without symlinks.')
    parent = path.parent
    if not parent.is_dir():
        raise DeliveryError('Create the private output directory first.')
    result = subprocess.run(['git', '-C', str(parent), 'rev-parse', '--show-toplevel'],
                            capture_output=True, timeout=10)
    if result.returncode == 0:
        raise DeliveryError('Private configuration/access files must be outside Git repositories.')
    return path


def private_write(path, value):
    path = outside_git(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, separators=(',', ':'))
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def load_config(path):
    path = outside_git(path)
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise DeliveryError('Private configuration must be an owner-owned mode-0600 regular file.')
    config = bounded_json(path)
    required = {'origin', 'account_id', 'database_id', 'database_name', 'bucket_name', 'worker_name', 'wrangler'}
    if set(config) != required:
        raise DeliveryError('Private configuration keys do not match the template.')
    parsed = urllib.parse.urlsplit(config['origin'])
    if (parsed.scheme != 'https' or parsed.username or parsed.password or parsed.query or parsed.fragment or
        parsed.path or not parsed.hostname or parsed.hostname.endswith('.r2.dev') or
        parsed.netloc != parsed.hostname):
        raise DeliveryError('Select a canonical HTTPS download hostname (default port).')
    if not re.fullmatch(r'[a-f0-9]{32}', config['account_id']) or not re.fullmatch(r'[a-f0-9-]{36}', config['database_id']):
        raise DeliveryError('Invalid explicit account/database binding.')
    for key in ('database_name', 'bucket_name', 'worker_name'):
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', config[key]):
            raise DeliveryError('Invalid private resource name.')
    binary = Path(config['wrangler'])
    if not binary.is_absolute() or not binary.is_file():
        raise DeliveryError('Configure the absolute path of preinstalled pinned Wrangler.')
    return config


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise DeliveryError('Cloudflare API redirect refused.')


class Cloudflare:
    def __init__(self, config):
        self.config = config
        # Keep HOME/auth unchanged. Never run login or activate a plan here.
        version = self.wrangler('--version').strip()
        if version != WRANGLER:
            raise DeliveryError('Wrangler must be exactly ' + WRANGLER + '.')
        try:
            auth = json.loads(self.wrangler('auth', 'token', '--json'))
        except (ValueError, UnicodeError):
            raise DeliveryError('Owner Wrangler authentication is unavailable.') from None
        if auth.get('type') not in ('oauth', 'api_token') or not isinstance(auth.get('token'), str):
            raise DeliveryError('Use the original owner OAuth/API-token authentication.')
        self._authorization = 'Bearer ' + auth['token']
        self._opener = urllib.request.build_opener(NoRedirect)

    def wrangler(self, *args, timeout=60):
        # Capture all output: even upstream diagnostics must never expose credentials.
        environment = dict(os.environ, WRANGLER_SEND_METRICS='false', WRANGLER_SEND_ERROR_REPORTS='false',
                           WRANGLER_WRITE_LOGS='false', WRANGLER_LOG='none', WRANGLER_LOG_SANITIZE='true',
                           CLOUDFLARE_API_BASE_URL='https://api.cloudflare.com/client/v4',
                           CF_API_BASE_URL='https://api.cloudflare.com/client/v4', CI='true', NO_COLOR='1')
        for name in ('WRANGLER_OUTPUT_FILE_PATH', 'WRANGLER_OUTPUT_FILE_DIRECTORY', 'CLOUDFLARE_ENV'):
            environment.pop(name, None)
        if self.config.get('account_id'):
            environment['CLOUDFLARE_ACCOUNT_ID'] = self.config['account_id']
        try:
            result = subprocess.run([self.config['wrangler'], *args], stdin=subprocess.DEVNULL,
                                    capture_output=True, env=environment, cwd=ROOT, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise DeliveryError('Pinned Wrangler operation failed or timed out.') from None
        if result.returncode:
            raise DeliveryError('Pinned Wrangler operation failed. Check owner authentication/resource permissions privately.')
        return result.stdout.decode('utf-8')

    def api(self, suffix, body=None, method=None):
        account = self.config['account_id']
        url = 'https://api.cloudflare.com/client/v4/accounts/' + account + suffix
        payload = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(url, data=payload, method=method or ('POST' if body is not None else 'GET'),
            headers={'Authorization': self._authorization, 'Content-Type': 'application/json'})
        try:
            with self._opener.open(request, timeout=60) as response:
                data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise DeliveryError('Cloudflare response exceeded its size limit.')
            parsed = json.loads(data)
            if parsed.get('success') is not True:
                raise DeliveryError('Cloudflare refused the operation.')
            return parsed['result']
        except (urllib.error.URLError, ValueError, KeyError):
            raise DeliveryError('Cloudflare API operation failed; no public fallback was used.') from None

    def query(self, sql, params=()):
        result = self.api('/d1/database/' + self.config['database_id'] + '/query', {'sql': sql, 'params': list(params)})
        if not isinstance(result, list) or not result or any(row.get('success') is not True for row in result):
            raise DeliveryError('D1 query failed.')
        return result[-1].get('results', [])

    def privacy(self):
        base = '/r2/buckets/' + self.config['bucket_name'] + '/domains/'
        managed = self.api(base + 'managed')
        custom = self.api(base + 'custom')
        if managed.get('enabled') is not False or custom.get('domains') != []:
            raise DeliveryError('R2 must have r2.dev disabled and no custom domains. No settings were changed.')

    def put_checked(self, snapshot, key, digest):
        # Content-addressed names are never used for different bytes. Readback is
        # mandatory before D1 publication; R2 is strongly consistent.
        object_path = self.config['bucket_name'] + '/' + key
        self.wrangler('r2', 'object', 'put', object_path, '--remote', '--file', str(snapshot), timeout=300)
        self.readback(key, digest, snapshot.stat().st_size)

    def readback(self, key, digest, size):
        object_path = self.config['bucket_name'] + '/' + key
        with tempfile.TemporaryDirectory(prefix='monitor-readback-') as folder:
            downloaded = Path(folder) / 'artifact.zip'
            self.wrangler('r2', 'object', 'get', object_path, '--remote', '--file', str(downloaded), timeout=300)
            if file_digest(downloaded) != (digest, size):
                raise DeliveryError('R2 readback hash/length mismatch; release was not published.')


def file_digest(path):
    digest, size = hashlib.sha256(), 0
    with Path(path).open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_ARCHIVE:
                raise DeliveryError('Archive exceeds the 512-MiB delivery bound.')
            digest.update(chunk)
    return digest.hexdigest(), size


def validate_manifest(value):
    # Run the actual wire validator, not a second divergent Python implementation.
    binary = os.environ.get('MONITOR_NODE', 'node')
    try:
        version = subprocess.run([binary, '--version'], capture_output=True, check=True, timeout=10).stdout.strip()
        if version != b'v26.4.0':
            raise DeliveryError('Node must be exactly 26.4.0 for contract validation.')
        script = "import {manifest} from './delivery/contract.mjs'; let s=''; for await(const c of process.stdin)s+=c; manifest(JSON.parse(s));"
        result = subprocess.run([binary, '--input-type=module', '-e', script], input=json.dumps(value).encode(),
                                capture_output=True, cwd=ROOT, timeout=10)
        if result.returncode:
            raise DeliveryError('Invalid release manifest.')
    except (OSError, subprocess.SubprocessError):
        raise DeliveryError('Pinned Node contract validation failed.') from None
    return value


def validate_receipt(manifest, receipt, stable=False):
    expected = {'schema': 'machine-monitor/qualification/v1', 'app_id': APP,
        'qualification_id': manifest['qualification_id'], 'source_revision': manifest['source_revision'],
        'build': manifest['build'], 'archive_sha256': manifest['archive']['sha256'],
        'archive_size': manifest['archive']['size'], 'first_install_sha256': manifest['first_install']['sha256'],
        'first_install_size': manifest['first_install']['size']}
    if any(receipt.get(k) != v for k, v in expected.items()) or any(receipt.get('checks', {}).get(k) is not True for k in CHECKS):
        raise DeliveryError('Qualification receipt does not bind every required gate to these exact artifacts.')
    if stable and receipt.get('checks', {}).get('private_upgrade') is not True:
        raise DeliveryError('Stable promotion requires actual exact-artifact private-upgrade evidence.')


def create_grant(api, config, label, output, expires_at, owner=False, channel='stable'):
    output = outside_git(output)
    if output.exists() or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', label):
        raise DeliveryError('Use a new access-file path and an opaque non-personal label.')
    if not isinstance(expires_at, int) or expires_at <= int(time.time()) or (channel == 'qualification' and not owner):
        raise DeliveryError('Future expiry and owner authority for qualification are required.')
    token = secrets.token_urlsafe(32)
    grant = str(uuid.uuid4())
    api.query('INSERT INTO grants(grant_id,token_hash,label,is_owner,expires_at,created_at) VALUES(?,?,?,?,?,?)',
              (grant, hashlib.sha256(token.encode()).hexdigest(), label, int(owner), expires_at, int(time.time())))
    try:
        api.query('INSERT INTO entitlements(grant_id,app_id,channel) VALUES(?,?,?)', (grant, APP, channel))
        private_write(output, {'schema': 'machine-monitor/access/v1', 'app_id': APP, 'origin': config['origin'], 'token': token})
    except BaseException:
        api.query('UPDATE grants SET revoked_at=? WHERE grant_id=?', (int(time.time()), grant))
        raise
    return grant


def publish(api, value, receipt, archive=None, package=None):
    value = validate_manifest(value)
    stable = value['channel'] == 'stable'
    validate_receipt(value, receipt, stable)
    api.privacy()
    release_id = value['archive']['path'].split('/')[-2]
    if value['first_install']['path'].split('/')[-2] != release_id:
        raise DeliveryError('Package and update must share the exact release identity.')
    if stable:
        rows = api.query("SELECT manifest_json FROM releases WHERE app_id=? AND release_id=? AND channel='qualification'", (APP, release_id))
        if len(rows) != 1:
            raise DeliveryError('Publish and privately qualify this exact qualification release first.')
        prior = json.loads(rows[0]['manifest_json'])
        expected = dict(value, channel='qualification', qualified=prior['qualified'])
        if prior != expected:
            raise DeliveryError('Stable promotion must preserve the exact qualification manifest and hashes.')
        if archive or package:
            raise DeliveryError('Promotion reuses qualified bytes; do not supply new archives.')
        for descriptor, suffix in ((value['archive'], '.zip'), (value['first_install'], '.package.zip')):
            api.readback(APP + '/' + descriptor['sha256'] + suffix, descriptor['sha256'], descriptor['size'])
    else:
        if not archive or not package:
            raise DeliveryError('Qualification publication requires both update and first-install archives.')
        with tempfile.TemporaryDirectory(prefix='monitor-publish-') as folder:
            for descriptor, source, suffix in ((value['archive'], archive, '.zip'), (value['first_install'], package, '.package.zip')):
                snapshot = Path(folder) / ('artifact' + suffix)
                with Path(source).open('rb') as original, snapshot.open('xb') as target:
                    os.chmod(snapshot, 0o600)
                    # Bounded streaming snapshot prevents a later source-path swap.
                    size = 0
                    while chunk := original.read(1024 * 1024):
                        size += len(chunk)
                        if size > MAX_ARCHIVE:
                            raise DeliveryError('Archive exceeds the delivery bound.')
                        target.write(chunk)
                if file_digest(snapshot) != (descriptor['sha256'], descriptor['size']):
                    raise DeliveryError('Archive hash or length differs from the qualified manifest.')
                api.put_checked(snapshot, APP + '/' + descriptor['sha256'] + suffix, descriptor['sha256'])
    serialized = json.dumps(value, sort_keys=True, separators=(',', ':'))
    api.query('INSERT OR IGNORE INTO releases(app_id,release_id,channel,manifest_json,archive_sha256,archive_size,object_key,qualification_id,evidence_json) VALUES(?,?,?,?,?,?,?,?,?)',
        (APP, release_id, value['channel'], serialized, value['archive']['sha256'], value['archive']['size'],
         APP + '/' + value['archive']['sha256'] + '.zip', value['qualification_id'], json.dumps(receipt, sort_keys=True)))
    existing = api.query('SELECT manifest_json FROM releases WHERE app_id=? AND release_id=? AND channel=?', (APP, release_id, value['channel']))
    if len(existing) != 1 or existing[0]['manifest_json'] != serialized:
        raise DeliveryError('Immutable release identity already contains different metadata.')
    api.query('''INSERT INTO channels(app_id,channel,release_id) VALUES(?,?,?)
        ON CONFLICT(app_id,channel) DO UPDATE SET release_id=excluded.release_id
        WHERE CAST(json_extract((SELECT manifest_json FROM releases WHERE app_id=excluded.app_id AND channel=excluded.channel AND release_id=excluded.release_id),'$.build') AS INTEGER)
        > CAST(json_extract((SELECT manifest_json FROM releases WHERE app_id=channels.app_id AND channel=channels.channel AND release_id=channels.release_id),'$.build') AS INTEGER)''',
        (APP, value['channel'], release_id))
    rows = api.query('SELECT release_id FROM channels WHERE app_id=? AND channel=?', (APP, value['channel']))
    if len(rows) != 1 or rows[0]['release_id'] != release_id:
        raise DeliveryError('Immutable release retained, but channel did not advance: build must increase.')


def deployment_config(config, api=None):
    result = json.loads((ROOT / 'delivery/wrangler.template.json').read_text())
    result.update(name=config['worker_name'], main=str(ROOT / 'delivery/worker.mjs'), account_id=config['account_id'])
    hostname = urllib.parse.urlsplit(config['origin']).hostname
    if hostname == 'workers.dev' or hostname.endswith('.workers.dev'):
        # Read-only ownership proof: never create or claim an account subdomain.
        if api is None:
            raise DeliveryError('Account-owned workers.dev origin requires current subdomain verification.')
        ownership = api.api('/workers/subdomain')
        subdomain = ownership.get('subdomain') if isinstance(ownership, dict) else None
        label = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
        if (not isinstance(subdomain, str) or not re.fullmatch(label, subdomain) or
            not re.fullmatch(label, config['worker_name']) or
            hostname != config['worker_name'] + '.' + subdomain + '.workers.dev'):
            raise DeliveryError('Configured origin does not match this worker and the account-owned workers.dev subdomain.')
        result['workers_dev'] = True
        result['routes'] = []
    else:
        result['workers_dev'] = False
        result['routes'] = [{'pattern': hostname, 'custom_domain': True}]
    result['preview_urls'] = False
    result['vars'] = {'UPDATE_ORIGIN': config['origin']}
    result['d1_databases'] = [{'binding': 'DB', 'database_name': config['database_name'], 'database_id': config['database_id']}]
    result['r2_buckets'] = [{'binding': 'ARCHIVES', 'bucket_name': config['bucket_name']}]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    subs = parser.add_subparsers(dest='command', required=True)
    create = subs.add_parser('create-grant')
    create.add_argument('--label', required=True)
    create.add_argument('--output', required=True, type=Path)
    create.add_argument('--expires-at', required=True, type=int, help='Unix seconds')
    create.add_argument('--owner', action='store_true')
    create.add_argument('--channel', choices=('stable', 'qualification'), default='stable')
    revoke = subs.add_parser('revoke-grant')
    revoke.add_argument('--grant-id', required=True, type=uuid.UUID)
    subs.add_parser('check-privacy')
    subs.add_parser('deploy')
    release = subs.add_parser('publish')
    release.add_argument('--manifest', required=True, type=Path)
    release.add_argument('--receipt', required=True, type=Path)
    release.add_argument('--archive', type=Path)
    release.add_argument('--package', type=Path)
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        api = Cloudflare(config)
        if args.command == 'create-grant':
            grant = create_grant(api, config, args.label, args.output, args.expires_at, args.owner, args.channel)
            print('Created grant ' + grant + '; private access file written with mode 0600.')
        elif args.command == 'revoke-grant':
            rows = api.query('UPDATE grants SET revoked_at=? WHERE grant_id=? RETURNING grant_id', (int(time.time()), str(args.grant_id)))
            if len(rows) != 1:
                raise DeliveryError('Grant was not found.')
            print('Grant revoked. Subsequent requests will be denied; already downloaded bytes remain available.')
        elif args.command == 'check-privacy':
            api.privacy()
            print('R2 public access disabled; no bucket custom domains.')
        elif args.command == 'deploy':
            api.privacy()
            # Ownership/configuration must pass before any deployment/schema write.
            configured = deployment_config(config, api)
            # Explicit existing resources only. No create/upgrade/pay command exists.
            api.query((ROOT / 'delivery/schema.sql').read_text())
            with tempfile.TemporaryDirectory(prefix='monitor-deploy-') as folder:
                filename = Path(folder).resolve() / 'wrangler.json'
                private_write(filename, configured)
                api.wrangler('deploy', '--config', str(filename), timeout=180)
            api.privacy()
            print('Worker deployment completed. Binary publication and live qualification remain separate.')
        else:
            publish(api, bounded_json(args.manifest), bounded_json(args.receipt), args.archive, args.package)
            print('Immutable release published and channel pointer verified.')
    except DeliveryError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        # Never interpolate third-party errors or malformed inputs into diagnostics.
        print('Delivery operation failed. Check explicit configuration, permissions, privacy and exact qualification evidence privately.', file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
