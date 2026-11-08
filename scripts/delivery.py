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
PART_SIZE = 20 * 1024 * 1024
MAX_FILES = 20000
FREE_PROOF_MAX_AGE = 3600
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
    if not Path(path).is_absolute():
        raise DeliveryError('Private paths must be explicit absolute canonical paths.')
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
    required = {'origin', 'account_id', 'database_id', 'database_name', 'worker_name', 'wrangler', 'assets_directory', 'free_plan_proof', 'deployment_state'}
    if set(config) != required:
        raise DeliveryError('Private configuration keys do not match the template.')
    parsed = urllib.parse.urlsplit(config['origin'])
    if (parsed.scheme != 'https' or parsed.username or parsed.password or parsed.query or parsed.fragment or
        parsed.path or not parsed.hostname or parsed.hostname.endswith('.r2.dev') or
        parsed.netloc != parsed.hostname):
        raise DeliveryError('Select a canonical HTTPS download hostname (default port).')
    if not re.fullmatch(r'[a-f0-9]{32}', config['account_id']) or not re.fullmatch(r'[a-f0-9-]{36}', config['database_id']):
        raise DeliveryError('Invalid explicit account/database binding.')
    for key in ('database_name', 'worker_name'):
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', config[key]):
            raise DeliveryError('Invalid private resource name.')
    binary = Path(config['wrangler'])
    if not binary.is_absolute() or not binary.is_file():
        raise DeliveryError('Configure the absolute path of preinstalled pinned Wrangler.')
    private_directory(config['assets_directory'])
    outside_git(config['free_plan_proof'])
    outside_git(config['deployment_state'])
    return config


def private_json(path):
    path = outside_git(path)
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise DeliveryError('Private evidence must be an owner-owned mode-0600 regular file.')
    return bounded_json(path, 16 * 1024 * 1024)


def require_free(config, now=None):
    # An explicit owner observation, not an independent provider/API assertion.
    try:
        proof = private_json(config['free_plan_proof'])
        current = int(time.time()) if now is None else now
        if (set(proof) != {'schema', 'account_id', 'observed_plan', 'source', 'source_reference', 'observed_at', 'expires_at'} or
            proof['schema'] != 'machine-monitor/free-plan-observation/v1' or
            proof['account_id'] != config['account_id'] or proof['observed_plan'] != 'Workers Free' or
            proof['source'] != 'owner-dashboard-observation' or
            not isinstance(proof['source_reference'], str) or not 1 <= len(proof['source_reference'].strip()) <= 512 or
            type(proof['observed_at']) is not int or type(proof['expires_at']) is not int or
            not proof['observed_at'] <= current < proof['expires_at'] or
            not 0 < proof['expires_at'] - proof['observed_at'] <= FREE_PROOF_MAX_AGE):
            raise DeliveryError('Current account-bound Workers Free owner observation required; no operation performed.')
    except (OSError, KeyError, ValueError, TypeError):
        raise DeliveryError('Current account-bound Workers Free owner observation required; no operation performed.') from None
    return proof


def private_directory(path):
    root = outside_git(path)
    info = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise DeliveryError('Assets require an explicit owner-owned mode-0700 directory outside Git.')
    return root


def asset_inventory(config):
    root = private_directory(config['assets_directory'])
    inventory = {}
    for path in root.rglob('*'):
        info = path.lstat()
        if path.is_symlink() or info.st_uid != os.getuid():
            raise DeliveryError('Asset symlinks/foreign ownership are forbidden.')
        if path.is_dir():
            if stat.S_IMODE(info.st_mode) != 0o700:
                raise DeliveryError('Private asset directories must have mode 0700.')
            continue
        relative = '/' + path.relative_to(root).as_posix()
        pattern = r'/_private/' + re.escape(APP) + r'/[A-Za-z0-9_-]{1,128}/(?:archive|package)/[a-f0-9]{64}/(?:0|[1-9][0-9]?)-([a-f0-9]{64})\.part'
        match = re.fullmatch(pattern, relative)
        if (not match or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or
            not 0 < info.st_size <= PART_SIZE):
            raise DeliveryError('Only bounded private immutable part files may be deployed; no routing/control files.')
        digest, size = file_digest(path)
        if digest != match[1]:
            raise DeliveryError('Retained asset hash mismatch.')
        inventory[relative] = {'sha256': digest, 'size': size}
        if len(inventory) > MAX_FILES:
            raise DeliveryError('Complete retained asset set exceeds Workers Free file-count bound.')
    return inventory


def stage_artifact(config, source, release_id, kind, descriptor):
    require_free(config)
    if (not isinstance(descriptor, dict) or not re.fullmatch(r'[a-f0-9]{64}', descriptor.get('sha256', '')) or
        type(descriptor.get('size')) is not int or not 0 < descriptor['size'] <= MAX_ARCHIVE):
        raise DeliveryError('Invalid bounded artifact descriptor.')
    root = private_directory(config['assets_directory'])
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', release_id) or kind not in ('archive', 'package'):
        raise DeliveryError('Invalid immutable artifact identity.')
    parts, digest, total = [], hashlib.sha256(), 0
    with Path(source).open('rb') as stream:
        while chunk := stream.read(PART_SIZE):
            total += len(chunk)
            if total > MAX_ARCHIVE:
                raise DeliveryError('Archive exceeds the delivery bound.')
            digest.update(chunk)
            part_hash = hashlib.sha256(chunk).hexdigest()
            path = f'/_private/{APP}/{release_id}/{kind}/{descriptor["sha256"]}/{len(parts)}-{part_hash}.part'
            destination = root / path.lstrip('/')
            directory = root
            for component in destination.relative_to(root).parts[:-1]:
                directory = directory / component
                if not directory.exists(): directory.mkdir(mode=0o700)
                info = directory.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise DeliveryError('Asset directory ownership/mode/symlink refused.')
            if destination.exists():
                if file_digest(destination) != (part_hash, len(chunk)):
                    raise DeliveryError('Existing immutable part differs.')
            else:
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as target:
                    target.write(chunk); target.flush(); os.fsync(target.fileno())
            parts.append(dict(index=len(parts), path=path, size=len(chunk), sha256=part_hash))
    if (digest.hexdigest(), total) != (descriptor['sha256'], descriptor['size']):
        raise DeliveryError('Archive hash or length differs from the qualified manifest.')
    return parts


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise DeliveryError('Cloudflare API redirect refused.')


class Cloudflare:
    def __init__(self, config):
        self.config = config
        self.node = pinned_node()
        if not Path(config['wrangler']).is_absolute() or not config['wrangler'].endswith('.js'):
            raise DeliveryError('Select the pinned Wrangler JavaScript entry point with an absolute path.')
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

    def require_free(self):
        return require_free(self.config)

    def wrangler(self, *args, timeout=60):
        if args not in (('--version',), ('auth', 'token', '--json')):
            self.require_free()
            if len(args) != 3 or args[:2] != ('deploy', '--config'):
                raise DeliveryError('Only the fixed Free-only deployment command is supported.')
            configured = private_json(args[2])
            validate_deployment_config(configured)
            if configured != deployment_config(self.config, self):
                raise DeliveryError('Deployment bindings differ from the explicit private configuration.')
            state_path = outside_git(self.config['deployment_state'])
            if state_path.exists():
                audit_deployment(self, require_current_source=False)
            elif self.api('/workers/scripts/' + self.config['worker_name'] + '/deployments', allow_not_found=True) is not None:
                raise DeliveryError('Existing Worker has no known private deployment receipt.')
            self.preflight_retention(asset_inventory(self.config))
        # Capture all output: even upstream diagnostics must never expose credentials.
        environment = dict(os.environ, WRANGLER_SEND_METRICS='false', WRANGLER_SEND_ERROR_REPORTS='false',
                           WRANGLER_WRITE_LOGS='false', WRANGLER_LOG='log', WRANGLER_LOG_SANITIZE='true',
                           CLOUDFLARE_API_BASE_URL='https://api.cloudflare.com/client/v4',
                           CF_API_BASE_URL='https://api.cloudflare.com/client/v4', CI='true', NO_COLOR='1')
        for name in ('WRANGLER_OUTPUT_FILE_PATH', 'WRANGLER_OUTPUT_FILE_DIRECTORY', 'CLOUDFLARE_ENV'):
            environment.pop(name, None)
        if self.config.get('account_id'):
            environment['CLOUDFLARE_ACCOUNT_ID'] = self.config['account_id']
        try:
            result = subprocess.run([self.node, self.config['wrangler'], *args], stdin=subprocess.DEVNULL,
                                    capture_output=True, env=environment, cwd=ROOT, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise DeliveryError('Pinned Wrangler operation failed or timed out.') from None
        if result.returncode:
            raise DeliveryError('Pinned Wrangler operation failed. Check owner authentication/resource permissions privately.')
        return result.stdout.decode('utf-8')

    def api(self, suffix, body=None, method=None, *, allow_not_found=False):
        effective_method = method or ('POST' if body is not None else 'GET')
        # D1 query uses POST even for SELECT; conservatively guard every POST.
        if effective_method != 'GET':
            self.require_free()
            allowed = (suffix == '/d1/database' and effective_method == 'POST' and isinstance(body, dict) and set(body) == {'name'}) or (suffix == '/workers/subdomain' and effective_method == 'PUT' and isinstance(body, dict) and set(body) == {'subdomain'}) or bool(re.fullmatch(r'/d1/database/[a-f0-9-]{36}/query', suffix) and effective_method == 'POST')
            if not allowed:
                raise DeliveryError('Provider mutation is outside the fixed Free-only interface.')
        if not suffix.startswith('/') or '?' in suffix or '#' in suffix or '..' in suffix:
            raise DeliveryError('Invalid account API path.')
        account = self.config['account_id']
        if not isinstance(account, str) or not re.fullmatch(r'[a-f0-9]{32}', account):
            raise DeliveryError('Invalid explicit account identity.')
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
        except urllib.error.HTTPError as error:
            absent=False
            try:
                if (allow_not_found and error.code == 404 and effective_method == 'GET' and
                    (suffix=='/workers/subdomain' or re.fullmatch(r'/workers/scripts/[a-z0-9][a-z0-9_-]{0,62}/deployments', suffix))):
                    data=error.read(65537)
                    if len(data)<=65536:
                        missing=json.loads(data)
                        absent=(isinstance(missing,dict) and missing.get('success') is False and
                            isinstance(missing.get('errors'),list) and len(missing['errors'])==1 and
                            missing['errors'][0].get('code')==10007)
            except (ValueError,UnicodeError,AttributeError,TypeError):pass
            finally:error.close()
            if absent:return None
            raise DeliveryError('Cloudflare API operation failed; no public fallback was used.') from None
        except (urllib.error.URLError, ValueError, KeyError):
            raise DeliveryError('Cloudflare API operation failed; no public fallback was used.') from None

    def query(self, sql, params=()):
        result = self.api('/d1/database/' + self.config['database_id'] + '/query', {'sql': sql, 'params': list(params)})
        if not isinstance(result, list) or not result or any(row.get('success') is not True for row in result):
            raise DeliveryError('D1 query failed.')
        return result[-1].get('results', [])

    def zone_routes(self):
        # Zone routes are distinct from account custom domains. Enumerate every
        # account-owned zone, including pages, and refuse any route to this Worker.
        routes = []
        for page in range(1, 101):
            query = urllib.parse.urlencode({'account.id': self.config['account_id'], 'per_page': 50, 'page': page})
            zones = self._zone_read('/zones?' + query)
            if not isinstance(zones, list) or len(zones) > 50:
                raise DeliveryError('Account zone inventory is unknown.')
            for zone in zones:
                identity = zone.get('id')
                if not isinstance(identity, str) or not re.fullmatch(r'[a-f0-9]{32}', identity):
                    raise DeliveryError('Invalid account zone identity.')
                found = self._zone_read('/zones/' + identity + '/workers/routes')
                if not isinstance(found, list): raise DeliveryError('Zone route inventory is unknown.')
                routes.extend(found)
            if len(zones) < 50: return routes
        raise DeliveryError('Zone inventory exceeds the bounded read limit.')

    def _zone_read(self, suffix):
        # Internal read-only path; account/auth stay unchanged and redirects deny.
        listing = '/zones?' + urllib.parse.urlencode({'account.id': self.config['account_id'], 'per_page': 50, 'page': 1})
        if not (re.fullmatch(r'/zones/[a-f0-9]{32}/workers/routes', suffix) or
                re.fullmatch(re.escape(listing.rsplit('=', 1)[0]) + r'=(?:[1-9][0-9]?|100)', suffix)):
            raise DeliveryError('Unsupported zone read.')
        request = urllib.request.Request('https://api.cloudflare.com/client/v4' + suffix,
                                         headers={'Authorization': self._authorization})
        try:
            with self._opener.open(request, timeout=30) as response:
                data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024: raise DeliveryError('Zone inventory too large.')
            result = json.loads(data)
            if result.get('success') is not True: raise DeliveryError('Zone inventory unavailable.')
            return result['result']
        except (OSError, ValueError, KeyError):
            raise DeliveryError('Fail-closed route readback is unavailable.') from None

    def create_database(self, name):
        self.require_free()
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', name): raise DeliveryError('Invalid database name.')
        databases = self.api('/d1/database')
        if not isinstance(databases, list) or len(databases) >= 10 or any(d.get('name') == name for d in databases):
            raise DeliveryError('Explicit new Free database requires known available capacity and a unique name.')
        return self.api('/d1/database', {'name': name}, 'POST')

    def create_subdomain(self, name):
        self.require_free()
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', name): raise DeliveryError('Invalid subdomain.')
        current = self.api('/workers/subdomain',allow_not_found=True)
        if current is not None:
            raise DeliveryError('Existing subdomain must be retained; no replacement is supported.')
        created=self.api('/workers/subdomain', {'subdomain': name}, 'PUT')
        if not isinstance(created,dict) or created.get('subdomain')!=name:
            raise DeliveryError('Created subdomain readback differs; inspect privately before continuing.')
        return created

    def privacy(self):
        return audit_deployment(self)

    def preflight_retention(self, inventory):
        path = outside_git(self.config['deployment_state'])
        if path.exists():
            prior = private_json(path)
            for name, details in prior['assets'].items():
                if inventory.get(name) != details:
                    raise DeliveryError('Deployment would drop/change retained parts.')
        for row in self.query('SELECT parts_json FROM artifact_parts'):
            for part in json.loads(row['parts_json']):
                if inventory.get(part['path']) != {k: part[k] for k in ('sha256', 'size')}:
                    raise DeliveryError('Deployment would drop/change published or rollback parts.')

    def deploy(self):
        self.require_free()
        configured = deployment_config(self.config, self)
        inventory = asset_inventory(self.config)
        state_path = outside_git(self.config['deployment_state'])
        prior = private_json(state_path) if state_path.exists() else None
        if not prior:
            existing = self.api('/workers/scripts/' + self.config['worker_name'] + '/deployments', allow_not_found=True)
            if existing is not None:
                raise DeliveryError('An existing Worker without its private deployment receipt must be investigated; no replacement performed.')
        if prior:
            audit_deployment(self, require_current_source=False)
            for path, details in prior['assets'].items():
                if inventory.get(path) != details:
                    raise DeliveryError('Deployment would drop/change previously retained parts; no deletion is supported.')
        # Additive schema only, after all local/config/Free gates.
        self.query((ROOT / 'delivery/schema.sql').read_text())
        for row in self.query('SELECT parts_json FROM artifact_parts'):
            for part in json.loads(row['parts_json']):
                if inventory.get(part['path']) != {k: part[k] for k in ('sha256', 'size')}:
                    raise DeliveryError('Deployment would drop/change published or rollback parts.')
        with tempfile.TemporaryDirectory(prefix='monitor-deploy-') as folder:
            filename = Path(folder).resolve() / 'wrangler.json'
            private_write(filename, configured)
            output = self.wrangler('deploy', '--config', str(filename), timeout=300)
        match = re.search(r'Current Version ID:\s*([a-f0-9-]{36})', output)
        if not match:
            raise DeliveryError('Deployment version identity unavailable; publication blocked pending private investigation.')
        version_id = match[1]
        base = '/workers/scripts/' + self.config['worker_name']
        deployed = current_version(self.api(base + '/deployments'))
        if deployed != version_id:
            raise DeliveryError('Deployment is not the single reviewed version at 100 percent.')
        detail = self.api(base + '/versions/' + version_id)
        etag = detail.get('resources', {}).get('script', {}).get('etag')
        if not isinstance(etag, str) or not etag:
            raise DeliveryError('Provider version source identity unavailable.')
        state = dict(schema='machine-monitor/private-deployment/v1', account_id=self.config['account_id'],
                     worker_name=self.config['worker_name'], version_id=version_id, etag=etag,
                     source_sha256=source_digest(), config=configured, assets=inventory)
        # Atomically replace only this tool's explicit state file, never asset data.
        temporary = state_path.with_name(state_path.name + '.' + secrets.token_hex(8))
        private_write(temporary, state)
        os.replace(temporary, state_path)
        audit_deployment(self)

    def readback(self, release_id, descriptor, kind):
        # Owner-only short-lived qualification grant stays in process memory.
        self.require_free()
        token, grant = secrets.token_urlsafe(32), str(uuid.uuid4())
        now = int(time.time())
        self.query('INSERT INTO grants(grant_id,token_hash,label,is_owner,expires_at,created_at) VALUES(?,?,?,?,?,?)',
                   (grant, hashlib.sha256(token.encode()).hexdigest(), 'publication-readback', 1, now + 600, now))
        try:
            self.query('INSERT INTO entitlements(grant_id,app_id,channel) VALUES(?,?,?)', (grant, APP, 'qualification'))
            path = f'/v1/apps/{APP}/releases/{release_id}/{kind}'
            request = urllib.request.Request(self.config['origin'] + path, headers={'Authorization': 'Bearer ' + token})
            digest, size = hashlib.sha256(), 0
            try:
                with self._opener.open(request, timeout=30) as response:
                    if response.status != 200 or response.headers.get('Content-Length') != str(descriptor['size']):
                        raise DeliveryError('Private remote readback failed.')
                    while chunk := response.read(1024 * 1024):
                        size += len(chunk)
                        if size > descriptor['size']: raise DeliveryError('Remote readback length exceeded.')
                        digest.update(chunk)
            except (OSError, urllib.error.URLError):
                raise DeliveryError('Private remote readback failed; channel was not advanced.') from None
            if (digest.hexdigest(), size) != (descriptor['sha256'], descriptor['size']):
                raise DeliveryError('Remote readback hash/length mismatch; channel was not advanced.')
        finally:
            self.query('UPDATE grants SET revoked_at=? WHERE grant_id=?', (int(time.time()), grant))


def source_digest():
    digest = hashlib.sha256()
    for name in ('worker.mjs', 'contract.mjs', 'web.mjs'):
        digest.update(name.encode()); digest.update((ROOT / 'delivery' / name).read_bytes())
    return digest.hexdigest()


def current_version(deployments):
    entries = deployments.get('deployments') if isinstance(deployments, dict) else None
    if not isinstance(entries, list) or not entries:
        raise DeliveryError('Current active deployment is unknown.')
    versions = entries[0].get('versions')
    # Include 0-percent versions: caller version overrides can select them.
    if not isinstance(versions, list) or len(versions) != 1 or versions[0].get('percentage') != 100:
        raise DeliveryError('Require exactly one reviewed active version at 100 percent, including zero-percent entries.')
    version = versions[0].get('version_id')
    if not isinstance(version, str) or not re.fullmatch(r'[a-f0-9-]{36}', version):
        raise DeliveryError('Invalid deployed version identity.')
    return version


def audit_deployment(api, require_current_source=True):
    config = api.config
    require_free(config)
    state = private_json(config['deployment_state'])
    expected = deployment_config(config, api)
    if (state.get('schema') != 'machine-monitor/private-deployment/v1' or state.get('account_id') != config['account_id'] or
        state.get('worker_name') != config['worker_name'] or (require_current_source and state.get('source_sha256') != source_digest()) or state.get('config') != expected):
        raise DeliveryError('Deployment does not match this exact reviewed source/configuration.')
    base = '/workers/scripts/' + config['worker_name']
    version = current_version(api.api(base + '/deployments'))
    if version != state.get('version_id'):
        raise DeliveryError('Unrecognized active version; publication blocked.')
    detail = api.api(base + '/versions/' + version)
    if detail.get('resources', {}).get('script', {}).get('etag') != state.get('etag'):
        raise DeliveryError('Active version source readback mismatch.')
    subdomain = api.api(base + '/subdomain')
    if subdomain.get('enabled') is not True or subdomain.get('previews_enabled') is not False:
        raise DeliveryError('Default/preview route configuration is unsafe or unknown.')
    # The supported workers.dev-only profile cannot have custom routes/domains.
    domains = api.api('/workers/domains')
    if not isinstance(domains, list) or any(not isinstance(d, dict) or
            not isinstance(d.get('service'), str) or not d['service'] or
            d['service'] == config['worker_name'] for d in domains):
        raise DeliveryError('Custom routes/domains require separately qualified fail-closed routing.')
    routes = api.zone_routes()
    if not isinstance(routes, list) or any(not isinstance(r, dict) or 'script' not in r or
            (r['script'] is not None and (not isinstance(r['script'], str) or not r['script'])) or
            r['script'] == config['worker_name'] for r in routes):
        raise DeliveryError('Any custom zone route requires separately qualified fail-closed routing.')
    return state


def file_digest(path):
    digest, size = hashlib.sha256(), 0
    with Path(path).open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_ARCHIVE:
                raise DeliveryError('Archive exceeds the 512-MiB delivery bound.')
            digest.update(chunk)
    return digest.hexdigest(), size


def pinned_node():
    binary = os.environ.get('MONITOR_NODE', 'node')
    try:
        version = subprocess.run([binary, '--version'], capture_output=True, check=True, timeout=10).stdout.strip()
        if version != b'v26.4.0':
            raise DeliveryError('Node must be exactly 26.4.0.')
    except (OSError, subprocess.SubprocessError):
        raise DeliveryError('Pinned Node runtime unavailable.') from None
    return binary


def validate_manifest(value):
    # Run the actual wire validator, not a second divergent Python implementation.
    binary = pinned_node()
    try:
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
    api.require_free()
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
    api.require_free()
    value = validate_manifest(value)
    stable = value['channel'] == 'stable'
    validate_receipt(value, receipt, stable)
    release_id = value['archive']['path'].split('/')[-2]
    prepared = []
    if stable:
        api.privacy()
        rows = api.query("SELECT manifest_json FROM releases WHERE app_id=? AND release_id=? AND channel='qualification'", (APP, release_id))
        if len(rows) != 1:
            raise DeliveryError('Publish and privately qualify this exact qualification release first.')
        prior = json.loads(rows[0]['manifest_json'])
        if prior != dict(value, channel='qualification', qualified=prior['qualified']):
            raise DeliveryError('Stable promotion must preserve the exact qualification manifest and hashes.')
        if archive or package:
            raise DeliveryError('Promotion reuses qualified bytes; do not supply new archives.')
        for kind, descriptor in (('archive', value['archive']), ('package', value['first_install'])):
            api.readback(release_id, descriptor, kind)
    else:
        if not archive or not package:
            raise DeliveryError('Qualification publication requires both update and first-install archives.')
        for descriptor, source, kind in ((value['archive'], archive, 'archive'), (value['first_install'], package, 'package')):
            prepared.append((kind, descriptor, stage_artifact(api.config, source, release_id, kind, descriptor)))
        api.deploy()  # complete retained set BEFORE any release/channel publication
        for kind, descriptor, parts in prepared:
            serialized_parts = json.dumps(parts, sort_keys=True, separators=(',', ':'))
            api.query('INSERT OR IGNORE INTO artifact_parts VALUES(?,?,?,?,?)', (APP, release_id, kind, descriptor['sha256'], serialized_parts))
            existing = api.query('SELECT parts_json FROM artifact_parts WHERE app_id=? AND release_id=? AND kind=? AND artifact_sha256=?', (APP, release_id, kind, descriptor['sha256']))
            if len(existing) != 1 or existing[0]['parts_json'] != serialized_parts:
                raise DeliveryError('Immutable part identity already differs.')
    serialized = json.dumps(value, sort_keys=True, separators=(',', ':'))
    api.query('INSERT OR IGNORE INTO releases(app_id,release_id,channel,manifest_json,archive_sha256,archive_size,object_key,qualification_id,evidence_json) VALUES(?,?,?,?,?,?,?,?,?)',
        (APP, release_id, value['channel'], serialized, value['archive']['sha256'], value['archive']['size'],
         APP + '/' + value['archive']['sha256'] + '.zip', value['qualification_id'], json.dumps(receipt, sort_keys=True)))
    existing = api.query('SELECT manifest_json FROM releases WHERE app_id=? AND release_id=? AND channel=?', (APP, release_id, value['channel']))
    if len(existing) != 1 or existing[0]['manifest_json'] != serialized:
        raise DeliveryError('Immutable release identity already contains different metadata.')
    # Qualification row is reachable by owner before its channel advances.
    api.privacy()
    if not stable:
        for kind, descriptor in (('archive', value['archive']), ('package', value['first_install'])):
            api.readback(release_id, descriptor, kind)
    api.require_free()
    api.query('''INSERT INTO channels(app_id,channel,release_id) VALUES(?,?,?)
        ON CONFLICT(app_id,channel) DO UPDATE SET release_id=excluded.release_id
        WHERE CAST(json_extract((SELECT manifest_json FROM releases WHERE app_id=excluded.app_id AND channel=excluded.channel AND release_id=excluded.release_id),'$.build') AS INTEGER)
        > CAST(json_extract((SELECT manifest_json FROM releases WHERE app_id=channels.app_id AND channel=channels.channel AND release_id=channels.release_id),'$.build') AS INTEGER)''',
        (APP, value['channel'], release_id))
    rows = api.query('SELECT release_id FROM channels WHERE app_id=? AND channel=?', (APP, value['channel']))
    if len(rows) != 1 or rows[0]['release_id'] != release_id:
        raise DeliveryError('Immutable release retained, but channel did not advance: build must increase.')


def deployment_config(config, api=None):
    parsed = urllib.parse.urlsplit(config['origin'])
    if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or parsed.netloc != parsed.hostname:
        raise DeliveryError('Select a canonical HTTPS download hostname.')
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
        raise DeliveryError('Custom routes require separately qualified fail-closed routing; use exact account-owned workers.dev.')
    result['preview_urls'] = False
    result['vars'] = {'UPDATE_ORIGIN': config['origin']}
    result['d1_databases'] = [{'binding': 'DB', 'database_name': config['database_name'], 'database_id': config['database_id']}]
    result['assets'] = {'directory': str(private_directory(config['assets_directory'])), 'binding': 'ASSETS', 'run_worker_first': True, 'html_handling': 'none', 'not_found_handling': 'none'}
    validate_deployment_config(result)
    return result


def validate_deployment_config(value):
    allowed = {'name', 'main', 'account_id', 'compatibility_date', 'workers_dev', 'preview_urls', 'observability', 'routes', 'vars', 'd1_databases', 'assets'}
    if (set(value) != allowed or value.get('workers_dev') is not True or value.get('preview_urls') is not False or value.get('routes') != [] or
        value.get('observability') != {'enabled': False} or
        value.get('assets') != {'directory': value.get('assets', {}).get('directory'), 'binding': 'ASSETS', 'run_worker_first': True, 'html_handling': 'none', 'not_found_handling': 'none'}):
        raise DeliveryError('Only unconditional worker-first private static assets with no routing fallback are supported.')


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
            print('Exact reviewed active version, private origin and preview restrictions verified; live quota/upgrade qualification remains separate.')
        elif args.command == 'deploy':
            api.deploy()
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
