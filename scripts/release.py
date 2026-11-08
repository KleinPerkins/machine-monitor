#!/usr/bin/env python3
"""Owner-local release preparation; never installs, publishes, or promotes.

Run with the pinned requirements-dev.txt and requirements-build.txt environment.
Only public update configuration enters bundles. Signing identity is a certificate
SHA, notary profile and Sparkle account are opaque Keychain references, never keys.
Importing this module performs no I/O. Tests inject command/API functions in-process;
there is deliberately no CLI/environment qualification bypass.
"""
import argparse
import base64
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'KleinPerkins/machine-monitor'
REPOSITORY_ID = 1449284973
REMOTE = 'https://github.com/' + REPOSITORY + '.git'
APP = 'com.kleinperkins.machine-monitor'
TEAM = 'J2V7GRV5CM'
ACTIONS_APP = 15368
MAX_ARCHIVE = 512 * 1024**2
CHECKS = ('ci_required', 'merged_source', 'developer_id', 'notarization',
          'stapled_ticket', 'gatekeeper', 'archive_signature', 'recovery_packaged')
MACH_MAGIC = {bytes.fromhex(s) for s in ('feedface', 'feedfacf', 'cefaedfe', 'cffaedfe',
                                      'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca')}


class ReleaseError(Exception):
    """Credential-free diagnostic safe for a terminal or public CI."""


def require(condition, message):
    if not condition:
        raise ReleaseError(message)


def command(args, *, cwd=None, input=None, timeout=60):
    # Suppress raw diagnostics, including from dependencies and Keychain tools.
    environment = dict(os.environ, GIT_TERMINAL_PROMPT='0', PYTHONDONTWRITEBYTECODE='1',
                       MONITOR_OWNED_SHARD_GROUP='1')
    process = None
    selector = selectors.DefaultSelector()
    previous = signal.getsignal(signal.SIGTERM)
    def terminated(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminated)
    try:
        process = subprocess.Popen([str(a) for a in args], cwd=cwd, env=environment,
            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        output = {name:bytearray() for name in ('stdout','stderr')}
        for name in output:
            stream=getattr(process,name);os.set_blocking(stream.fileno(),False)
            selector.register(stream,selectors.EVENT_READ,name)
        pending=memoryview(input or b'')
        if process.stdin:
            if pending:
                os.set_blocking(process.stdin.fileno(),False)
                selector.register(process.stdin,selectors.EVENT_WRITE,'stdin')
            else:process.stdin.close()
        deadline=time.monotonic()+timeout
        while selector.get_map():
            remaining=deadline-time.monotonic()
            require(remaining>0,'Release operation timed out; no qualification was issued.')
            for key,_ in selector.select(min(remaining,.1)):
                stream=key.fileobj
                if key.data=='stdin':
                    try:pending=pending[os.write(stream.fileno(),pending[:65536]):]
                    except BrokenPipeError:pending=pending[:0]
                    if not pending:selector.unregister(stream);stream.close()
                else:
                    chunk=os.read(stream.fileno(),65536)
                    if not chunk:selector.unregister(stream);stream.close();continue
                    require(len(output[key.data])+len(chunk)<=8*1024**2,'Release output exceeded its bound.')
                    output[key.data].extend(chunk)
        try:process.wait(timeout=max(.001,deadline-time.monotonic()))
        except subprocess.TimeoutExpired:raise ReleaseError('Release operation timed out; no qualification was issued.') from None
        require(process.returncode == 0,'Release operation failed; inspect owner prerequisites privately.')
        return bytes(output['stdout'])
    except OSError:
        raise ReleaseError('Required release tool is unavailable.') from None
    finally:
        # Build helpers inherit this owned group, including their nested tools.
        # Never communicate() without a deadline after cancellation or overflow.
        deferred=[]
        def defer(signum,frame):deferred.append(signum)
        handlers={sig:signal.getsignal(sig) for sig in (signal.SIGINT,signal.SIGTERM)}
        for sig in handlers:signal.signal(sig,defer)
        try:
            if process is not None:
                from scripts.processes import send_group,group_stopped
                send_group(process.pid,signal.SIGTERM)
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    send_group(process.pid,signal.SIGKILL);process.wait(timeout=5)
                send_group(process.pid,signal.SIGKILL)
                cleanup_deadline=time.monotonic()+3
                while not group_stopped(process.pid) and time.monotonic()<cleanup_deadline:time.sleep(.05)
                require(group_stopped(process.pid),'Release child cleanup could not be verified.')
                for stream in (process.stdin,process.stdout,process.stderr):
                    if stream and not stream.closed:stream.close()
        finally:
            selector.close()
            for sig,handler in handlers.items():signal.signal(sig,handler)
            signal.signal(signal.SIGTERM,previous)
        if deferred:raise SystemExit(128+deferred[0])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ReleaseError('Public source API redirect refused.')


def github(path):
    """Public, unauthenticated API: no owner token is read or propagated."""
    require(path.startswith('repos/' + REPOSITORY), 'Unexpected repository API path.')
    request = urllib.request.Request('https://api.github.com/' + path, headers={
        'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'machine-monitor-private-release'})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=40) as response:
            payload = response.read(8 * 1024**2 + 1)
        require(len(payload) <= 8 * 1024**2, 'Source API response exceeded its bound.')
        return json.loads(payload)
    except (OSError, ValueError):
        raise ReleaseError('Public GitHub evidence unavailable; release refused.') from None


def pages(api, path, key=None):
    result = []
    for page in range(1, 21):
        value = api(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
        rows = value.get(key) if key and isinstance(value, dict) else value
        require(isinstance(rows, list), 'Malformed source evidence.')
        result.extend(rows)
        if len(rows) < 100:
            return result
    raise ReleaseError('Source evidence pagination exceeded its bound.')


def observe_source(sha, api=github):
    require(isinstance(sha, str) and re.fullmatch(r'[a-f0-9]{40}', sha), 'Use a complete source SHA.')
    base = 'repos/' + REPOSITORY
    repo = api(base)
    require(repo.get('id') == REPOSITORY_ID and repo.get('full_name') == REPOSITORY
            and repo.get('default_branch') == 'main' and repo.get('private') is False,
            'Canonical public repository identity changed.')
    require(api(base + '/git/ref/heads/main').get('object', {}).get('sha') == sha,
            'Source must be the current intended main revision.')
    prs = pages(api, base + '/commits/' + sha + '/pulls')
    require(any(p.get('merged_at') and p.get('merge_commit_sha') == sha
                and p.get('base', {}).get('ref') == 'main'
                and p.get('base', {}).get('repo', {}).get('id') == REPOSITORY_ID for p in prs),
            'Source has no exact merged-main pull request evidence.')
    workflow = api(base + '/actions/workflows/ci.yml')
    require(workflow.get('path') == '.github/workflows/ci.yml' and workflow.get('state') == 'active'
            and type(workflow.get('id')) is int, 'Canonical CI workflow is unavailable.')
    runs = pages(api, base + f'/actions/workflows/{workflow["id"]}/runs?branch=main&head_sha={sha}', 'workflow_runs')
    matching = [r for r in runs if r.get('head_sha') == sha and r.get('head_branch') == 'main'
                and r.get('workflow_id') == workflow['id'] and r.get('event') in ('push', 'workflow_dispatch')]
    require(matching, 'No current-source CI workflow run.')
    run = max(matching, key=lambda r: (r.get('run_number', 0), r.get('run_attempt', 0), r.get('id', 0)))
    require(run.get('status') == 'completed' and run.get('conclusion') == 'success',
            'Latest current-source CI workflow has not passed.')
    require(type(run.get('run_attempt')) is int and type(run.get('id')) is int,
            'CI run lacks attempt identity.')
    jobs = pages(api, base + f'/actions/runs/{run["id"]}/attempts/{run["run_attempt"]}/jobs', 'jobs')
    gates = [j for j in jobs if j.get('name') == 'ci-required']
    require(len(gates) == 1 and gates[0].get('status') == 'completed'
            and gates[0].get('conclusion') == 'success', 'Latest workflow attempt lacks a successful gate.')
    checks = pages(api, base + f'/commits/{sha}/check-runs?check_name=ci-required&filter=all', 'check_runs')
    matching_checks = [c for c in checks if c.get('name') == 'ci-required'
                       and c.get('app', {}).get('id') == ACTIONS_APP]
    require(matching_checks, 'GitHub Actions ci-required evidence missing.')
    check = max(matching_checks, key=lambda c: c.get('id', 0))
    require(check.get('head_sha') == sha and check.get('status') == 'completed'
            and check.get('conclusion') == 'success'
            and check.get('check_suite', {}).get('id') == run.get('check_suite_id')
            and gates[0].get('check_run_url') == f'https://api.github.com/{base}/check-runs/{check.get("id")}',
            'Latest ci-required does not match the current CI workflow attempt.')
    return {'source_revision': sha, 'repository_id': REPOSITORY_ID,
            'workflow_id': workflow['id'], 'run_id': run['id'], 'run_attempt': run['run_attempt'],
            'check_run_id': check['id'], 'observed_at': int(time.time())}


def private_directory(path):
    path = Path(path).absolute()
    require(path == path.resolve() and path.is_dir(), 'Output must be an existing canonical directory.')
    info = path.stat()
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'Output directory must be owner-owned and mode 0700.')
    require(not any((parent / '.git').exists() for parent in (path, *path.parents)),
            'Private release output must be outside Git.')
    return path


def public_settings(path):
    # Share the builder's closed schema; no access file or token is accepted.
    from build_mac_app import update_settings
    try:
        settings = update_settings(path)
    except (OSError, ValueError, TypeError, KeyError):
        raise ReleaseError('Invalid public update configuration.') from None
    require(bool(settings), 'Public update configuration is required.')
    return settings


def dependencies(source):
    require(sys.version_info[:3] == (3, 14, 6), 'Release requires pinned Python 3.14.6.')
    checked = {}
    for name in ('requirements.txt', 'requirements-dev.txt', 'requirements-build.txt'):
        for line in (source / name).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '-r ')):
                continue
            require(re.fullmatch(r'[A-Za-z0-9_-]+==[A-Za-z0-9.]+', line), 'Build dependency is not pinned.')
            package, version = line.split('==')
            try:
                actual = importlib.metadata.version(package)
            except importlib.metadata.PackageNotFoundError:
                raise ReleaseError('Pinned release dependencies are missing.') from None
            require(actual == version, 'Installed release dependency differs from its pin.')
            checked[package] = version
    return checked


def fetch_source(sha, target, run=command):
    # An owned fresh checkout carries .git, preserving the builder's actual HEAD.
    # No local primary/worktree bytes or credential helpers participate.
    git = ['git', '-c', 'credential.helper=', '-c', 'core.hooksPath=/dev/null']
    run(git + ['init', str(target)])
    run(git + ['-C', str(target), 'remote', 'add', 'origin', REMOTE])
    run(git + ['-C', str(target), 'fetch', '--depth=1', 'origin', sha], timeout=300)
    run(git + ['-C', str(target), 'checkout', '--detach', 'FETCH_HEAD'])
    require(run(git + ['-C', str(target), 'rev-parse', 'HEAD']).decode().strip() == sha,
            'Fetched source revision differs.')
    require(not run(git + ['-C', str(target), 'status', '--porcelain', '--untracked-files=all']).strip(),
            'Fetched release source is not clean.')


def verify_launcher(source):
    # The isolated builder must not be qualified by modified or stale helper code
    # imported from the invoking checkout. Unrelated local files never enter it.
    for name in ('scripts/release.py', 'scripts/sparkle.py', 'scripts/toolchain.py','scripts/processes.py',
                 'build_mac_app.py', 'update_contract.py', 'update_preflight.py'):
        require((ROOT / name).read_bytes() == (source / name).read_bytes(),
                'Invoke release tooling whose helpers match the exact merged source.')


def mach_files(app):
    result = []
    for path in app.rglob('*'):
        if path.is_file() and not path.is_symlink():
            with path.open('rb') as stream:
                if stream.read(4) in MACH_MAGIC:
                    result.append(path)
    return result


def entitlements(path, run):
    value = run(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(path)])
    if not value.strip():
        return {}
    try:
        parsed = plistlib.loads(value)
        require(isinstance(parsed, dict), 'Invalid upstream helper entitlements.')
        return parsed
    except (ValueError, plistlib.InvalidFileException):
        raise ReleaseError('Cannot read pinned upstream helper entitlements.') from None


def sign_app(app, identity, upstream, scratch, run=command):
    framework = app / 'Contents/Frameworks/Sparkle.framework'
    files = mach_files(app)
    bundles = [p for p in app.rglob('*') if p.is_dir() and not p.is_symlink()
               and p.suffix in ('.app', '.xpc', '.framework')]
    targets = sorted(set(files + bundles + [app]), key=lambda p: (-len(p.parts), str(p)))
    for number, target in enumerate(targets):
        args = ['/usr/bin/codesign', '--force', '--sign', identity, '--options', 'runtime', '--timestamp']
        # The builder's ad-hoc signing can discard entitlements. Read only the
        # verified, pinned upstream originals, never infer them from our copy.
        if target.is_relative_to(framework) and target.suffix != '.framework':
            original = upstream / 'Sparkle.framework' / target.relative_to(framework)
            values = entitlements(original, run)
            if values:
                file = scratch / f'entitlements-{number}.plist'
                file.write_bytes(plistlib.dumps(values))
                args += ['--entitlements', str(file)]
        run(args + [str(target)])
    verify_code(app, run)


def verify_code(app, run=command):
    requirement = ('anchor apple generic and certificate leaf[subject.OU] = "' + TEAM +
                   '" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists')
    for target in [*mach_files(app), app]:
        run(['/usr/bin/codesign', '--verify', '--strict', '-R', requirement, str(target)])
        # codesign displays metadata on stderr, so command output selection is
        # handled by display_code below instead of trusting the process exit.
        display_code(target, run)
    bundle_id = APP + ('.recovery' if app.name == 'Machine Monitor Recovery.app' else '')
    run(['/usr/bin/codesign', '--verify', '--deep', '--strict', '-R',
         requirement + ' and identifier "' + bundle_id + '"', str(app)])


def display_code(target, run):
    # codesign's display diagnostics are stderr. A small fixed Python bridge
    # returns only the public signature metadata to the captured command runner.
    bridge = ('import subprocess,sys; p=subprocess.run(sys.argv[1:],capture_output=True); '
              'sys.stdout.buffer.write(p.stderr); sys.exit(p.returncode)')
    output = run([sys.executable, '-c', bridge, '/usr/bin/codesign', '-d', '--verbose=4', str(target)]).decode()
    flags=re.search(r'(?:^|\s)flags=0x([0-9a-fA-F]+)\(([^)\n]*)\)',output)
    require('TeamIdentifier=' + TEAM in output and 'Authority=Developer ID Application:' in output
            and flags and int(flags[1],16)&0x10000 and 'runtime' in flags[2].split(',') and re.search(r'^Timestamp=.+', output, re.M),
            'Nested code lacks Developer ID, hardened runtime, or secure timestamp.')


def verify_metadata(app, version, build, sha, settings=None, run=command):
    try:
        info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    except (OSError, ValueError):
        raise ReleaseError('Missing or malformed app metadata.') from None
    expected = {'CFBundleIdentifier': APP + ('.recovery' if app.name == 'Machine Monitor Recovery.app' else ''),
                'CFBundleVersion': str(build), 'CFBundleShortVersionString': version,
                'LSMinimumSystemVersion': '26.0', 'MachineMonitorDataSchemaVersion': 1,
                'MachineMonitorSourceRevision': sha}
    if settings:
        expected.update(settings)
    require(all(info.get(k) == v for k, v in expected.items()), 'Built app identity/provenance differs.')
    executable = info.get('CFBundleExecutable')
    require(isinstance(executable, str) and '/' not in executable and executable not in ('', '.', '..'),
            'Unsafe bundle executable name.')
    files = mach_files(app)
    require(app / 'Contents/MacOS' / executable in files, 'Main executable missing.')
    load_commands = run(['/usr/bin/otool', '-l', str(app / 'Contents/MacOS' / executable)]).decode()
    require(re.search(r'cmd LC_BUILD_VERSION\s+cmdsize \d+\s+platform (?:1|macos)\s+minos 26(?:\.0){1,2}\s',
                      load_commands, re.I), 'Main executable minimum macOS differs from sealed metadata.')
    for path in files:
        require(run(['/usr/bin/lipo', '-archs', str(path)]).decode().split() == ['arm64'],
                'Every shipped executable must be arm64 only.')


def package(paths, output):
    """ZIP entries preserve POSIX modes and relative links; no AppleDouble roots."""
    require(not output.exists(), 'Archive output already exists.')
    # Stored entries avoid decompression-ratio refusals for legitimate zero-filled binaries.
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_STORED) as archive:
        count, expanded = 0, 0
        for root in paths:
            require(not root.is_symlink(), 'Package roots cannot be symlinks.')
            entries = [root, *sorted(root.rglob('*'))] if root.is_dir() else [root]
            for path in entries:
                count += 1
                require(count <= 20000, 'Package has too many entries.')
                mode = path.lstat().st_mode
                require(stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode), 'Special file in package.')
                name = path.relative_to(root.parent).as_posix()
                require('__MACOSX' not in Path(name).parts and not any(p.startswith('._') for p in Path(name).parts),
                        'Unexpected archive metadata.')
                entry = zipfile.ZipInfo(name + ('/' if stat.S_ISDIR(mode) else ''))
                entry.create_system = 3
                entry.external_attr = mode << 16
                entry.compress_type = zipfile.ZIP_STORED
                if stat.S_ISLNK(mode):
                    require(path.resolve(strict=True).is_relative_to(root.resolve()), 'Escaping package symlink.')
                    payload = os.readlink(path).encode()
                    require(not os.path.isabs(os.readlink(path)), 'Absolute package symlink.')
                    archive.writestr(entry, payload)
                    expanded += len(payload)
                elif stat.S_ISDIR(mode):
                    archive.writestr(entry, b'')
                else:
                    # Stream bounded file data rather than loading full apps.
                    with path.open('rb') as source, archive.open(entry, 'w') as sink:
                        while chunk := source.read(1024**2):
                            expanded += len(chunk)
                            require(expanded <= 2 * 1024**3, 'Expanded package exceeds bound.')
                            sink.write(chunk)
    output.chmod(0o600)
    require(0 < output.stat().st_size <= MAX_ARCHIVE, 'Archive exceeds 512 MiB.')


def notarize(apps, scratch, profile, run=command):
    upload = scratch / 'notary-upload.zip'
    package(apps, upload)
    result = run(['xcrun', 'notarytool', 'submit', str(upload), '--keychain-profile', profile,
                  '--wait', '--timeout', '30m', '--output-format', 'json'], timeout=1900)
    try:
        value = json.loads(result)
    except ValueError:
        raise ReleaseError('Notary response is not valid JSON.') from None
    require(value.get('status') == 'Accepted' and re.fullmatch(r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}', value.get('id', '')),
            'Apple notarization was not Accepted.')
    for app in apps:
        run(['xcrun', 'stapler', 'staple', str(app)], timeout=180)
        run(['xcrun', 'stapler', 'validate', str(app)], timeout=180)
        verify_code(app, run)
        run(['/usr/sbin/spctl', '--assess', '--type', 'execute', str(app)], timeout=120)
    return value['id']


def signature(path, signer, account, public_key, node, run=command):
    help_text = run([str(signer), '--help']).decode()
    require(all(flag in help_text for flag in ('--account', '--verify', '-p')), 'Unexpected pinned signing interface.')
    signature = run([str(signer), '--account', account, '-p', str(path)]).decode().strip()
    try:
        raw = base64.b64decode(signature, validate=True)
    except ValueError:
        raise ReleaseError('Invalid archive signature output.') from None
    require(len(raw) == 64 and base64.b64encode(raw).decode() == signature, 'Invalid archive signature size.')
    run([str(signer), '--account', account, '--verify', str(path), signature])
    # Stock verify above checks the app-specific Keychain account; independently
    # check the compiled public key, preventing a mistaken account/key pairing.
    js = """const {readFileSync}=require('node:fs');const {createPublicKey,verify}=require('node:crypto');
const [p,k,s]=process.argv.slice(1);const key=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(k,'base64')]),format:'der',type:'spki'});
if(!verify(null,readFileSync(p),key,Buffer.from(s,'base64')))process.exit(1);"""
    require(run([str(node), '--version']).strip() == b'v26.4.0', 'Signature verification requires Node 26.4.0.')
    run([str(node), '-e', js, str(path), public_key, signature])
    return signature


def descriptor(path, signature_value, release_id, kind):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(1024**2):
            digest.update(chunk)
    size = path.stat().st_size
    require(0 < size <= MAX_ARCHIVE, 'Archive size is invalid.')
    return {'path': f'/v1/apps/{APP}/releases/{release_id}/{kind}', 'size': size,
            'sha256': digest.hexdigest(), 'ed25519_signature': signature_value}


def records(version, build, sha, release_id, qualification_id, archive, first_install, evidence):
    from update_contract import validate_manifest
    manifest = {'schema': 'machine-monitor/release/v1', 'app_id': APP, 'bundle_id': APP,
                'team_id': TEAM, 'channel': 'qualification', 'qualified': False, 'version': version,
                'build': build, 'minimum_macos': '26.0', 'architecture': 'arm64', 'data_schema_version': 1,
                'source_revision': sha, 'qualification_id': qualification_id,
                'archive': archive, 'first_install': first_install}
    validate_manifest(manifest)
    require(all(evidence.get(k) is True for k in CHECKS), 'Missing observed qualification checks.')
    require(all(d['path'].split('/')[-2] == release_id for d in (archive, first_install)), 'Release identity differs.')
    receipt = {'schema': 'machine-monitor/qualification/v1', 'app_id': APP,
               'qualification_id': qualification_id, 'source_revision': sha, 'build': build,
               'archive_sha256': archive['sha256'], 'archive_size': archive['size'],
               'first_install_sha256': first_install['sha256'], 'first_install_size': first_install['size'],
               'checks': {k: True for k in CHECKS}}
    return manifest, receipt


def write_json(path, value):
    with path.open('x') as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def prepare(options, *, run=command, api=github):
    from scripts.sparkle import distribution
    from scripts.toolchain import node
    from update_contract import version_tuple
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'Release requires Apple Silicon macOS.')
    version_tuple(options.version)
    require(type(options.build_number) is int and 1 <= options.build_number < 2**31, 'Invalid build number.')
    for value in (options.release_id, options.qualification_id):
        require(re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value), 'Invalid release/qualification identifier.')
    require(re.fullmatch(r'[a-fA-F0-9]{40}', options.signing_identity), 'Use the selected Developer ID certificate SHA.')
    require(re.fullmatch(re.escape(APP) + r'[A-Za-z0-9._-]{0,96}', options.sparkle_account),
            'Sparkle account must be explicitly scoped to this application.')
    require(re.fullmatch(r'[A-Za-z0-9._-]{1,128}', options.notary_profile), 'Use an opaque notary Keychain profile name.')
    output = private_directory(options.output)
    final = output / options.release_id
    require(not final.exists(), 'Release output identity already exists.')
    evidence = observe_source(options.source_revision, api)
    checks = {'ci_required': True, 'merged_source': True}
    with tempfile.TemporaryDirectory(prefix='.release-', dir=output) as temporary:
        scratch = Path(temporary)
        source = scratch / 'source'
        fetch_source(options.source_revision, source, run)
        verify_launcher(source)
        settings = public_settings(options.update_config)
        pins = dependencies(source)
        public = scratch / 'update-config.json'
        write_json(public, {'origin': settings['MachineMonitorUpdateOrigin'],
                           'channel': settings['MachineMonitorUpdateChannel'],
                           'public_ed25519_key': settings['SUPublicEDKey']})
        run([sys.executable, str(source / 'build_mac_app.py'), '--version', options.version,
             '--build-number', str(options.build_number), '--update-config', str(public)], cwd=source, timeout=1800)
        upstream = distribution(source / 'build/toolchains')
        apps = [source / 'dist/Machine Monitor.app', source / 'dist/Machine Monitor Recovery.app']
        for app in apps:
            verify_metadata(app, options.version, options.build_number, options.source_revision,
                            settings if app == apps[0] else None, run)
            sign_app(app, options.signing_identity, upstream, scratch, run)
        checks['developer_id'] = True
        notary_id = notarize(apps, scratch, options.notary_profile, run)
        checks.update(notarization=True, stapled_ticket=True, gatekeeper=True)
        results = scratch / 'result'
        results.mkdir(mode=0o700)
        archive = results / 'Machine-Monitor.zip'
        package(apps[:1], archive)
        instructions = scratch / 'Install.txt'
        instructions.write_text('Machine Monitor requires Apple Silicon and macOS 26 or later.\n\n'
            'In Finder, copy BOTH Machine Monitor.app and Machine Monitor Recovery.app to a folder you own '
            '(for example ~/Applications). Keep Recovery separate from the main app. Open Machine Monitor '
            'normally; do not bypass Gatekeeper. Open the supplied access file to enable private updates.\n\n'
            'If an interrupted update prevents opening the main app, restart your Mac and open Recovery '
            'before opening Machine Monitor. Recovery asks before restoring a verified saved version. '
            'Keep your original application backup. No telemetry is uploaded.\n')
        first_install = results / 'Machine-Monitor-Install.zip'
        package([*apps, instructions, source / 'PRIVATE-BINARY-LICENSE', source / 'THIRD-PARTY-NOTICES.md', source / 'LICENSE'], first_install)
        checks['recovery_packaged'] = True
        signer = upstream / 'bin/sign_update'
        verifier = node(source / 'build/toolchains')
        descriptors = [descriptor(path, signature(path, signer, options.sparkle_account,
                       settings['SUPublicEDKey'], verifier, run), options.release_id, kind)
                       for path, kind in ((archive, 'archive'), (first_install, 'package'))]
        checks['archive_signature'] = True
        # Exercise the actual bounded updater extractor against final stapled bytes.
        # Native code identity is checked above and again by the extractor's normal
        # verifier; this is not a fixture override or an installation.
        manifest, receipt = records(options.version, options.build_number, options.source_revision,
                                    options.release_id, options.qualification_id, *descriptors,
                                    checks)
        from update_preflight import extract_archive
        extract_archive(archive, scratch / 'preflight', manifest)
        latest = observe_source(options.source_revision, api)
        require(all(latest[k] == evidence[k] for k in ('run_id', 'run_attempt', 'check_run_id')),
                'CI evidence changed during release preparation.')
        write_json(results / 'manifest.json', manifest)
        write_json(results / 'qualification.json', receipt)
        write_json(results / 'provenance.json', {'source': latest, 'dependencies': pins,
                   'python': platform.python_version(), 'sparkle': '2.10.1', 'notary_submission_id': notary_id,
                   'runtime_channel': settings['MachineMonitorUpdateChannel'], 'distribution_channel': 'qualification'})
        results.rename(final)
    return final


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--build-number', required=True, type=int)
    parser.add_argument('--release-id', required=True)
    parser.add_argument('--qualification-id', required=True)
    parser.add_argument('--update-config', required=True, type=Path, help='Public origin, runtime channel, Ed25519 public key only')
    parser.add_argument('--signing-identity', required=True, help='Selected Developer ID certificate SHA')
    parser.add_argument('--notary-profile', required=True, help='Opaque existing notarytool Keychain profile')
    parser.add_argument('--sparkle-account', required=True, help='Existing app-specific Sparkle Keychain account')
    parser.add_argument('--output', required=True, type=Path, help='Existing private mode-0700 directory outside Git')
    try:
        output = prepare(parser.parse_args(argv))
    except ReleaseError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (ValueError, OSError):
        print('Release preparation refused or failed; no qualification output was published. Check source, toolchain and owner prerequisites privately.', file=sys.stderr)
        return 1
    print('Prepared private qualification artifacts: ' + str(output))
    print('No publication, private upgrade, stable promotion, or installation was performed.')
    return 0


if __name__ == '__main__':
    # Direct script execution needs the source root, without changing import-time state.
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())
