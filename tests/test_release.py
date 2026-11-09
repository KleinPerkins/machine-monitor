"""Synthetic release-tool gates; no real signing, Keychain, network, or installation."""
import argparse
import base64
from contextlib import ExitStack
import copy
import importlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import time
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts import release as r
from update_preflight import extract_archive

SHA = 'a' * 40
PUBLIC = base64.b64encode(b'k' * 32).decode()
SIGNATURE = base64.b64encode(b's' * 64).decode()


def source_fixture():
    base = 'repos/' + r.REPOSITORY
    return {
        base: {'id': r.REPOSITORY_ID, 'full_name': r.REPOSITORY, 'default_branch': 'main', 'private': False},
        base + '/git/ref/heads/main': {'object': {'sha': SHA}},
        base + '/commits/' + SHA + '/pulls': [{'merged_at': '2026-01-01', 'merge_commit_sha': SHA,
            'base': {'ref': 'main', 'repo': {'id': r.REPOSITORY_ID}}}],
        base + '/actions/workflows/ci.yml': {'id': 10, 'path': '.github/workflows/ci.yml', 'state': 'active'},
        base + '/actions/workflows/10/runs': {'workflow_runs': [{'head_sha': SHA, 'head_branch': 'main',
            'workflow_id': 10, 'event': 'push', 'run_number': 5, 'run_attempt': 2, 'id': 20,
            'status': 'completed', 'conclusion': 'success', 'check_suite_id': 30}]},
        base + '/actions/runs/20/attempts/2/jobs': {'jobs': [{'name': 'ci-required', 'status': 'completed',
            'conclusion': 'success', 'check_run_url': f'https://api.github.com/{base}/check-runs/40'}]},
        base + '/commits/' + SHA + '/check-runs': {'check_runs': [{'name': 'ci-required', 'app': {'id': r.ACTIONS_APP},
            'head_sha': SHA, 'status': 'completed', 'conclusion': 'success', 'id': 40, 'check_suite': {'id': 30}}]},
    }


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.values = source_fixture()
        self.base = 'repos/' + r.REPOSITORY
        self.api = lambda path: copy.deepcopy(self.values[path.split('?')[0]])

    def test_exact_latest_workflow_evidence(self):
        self.assertEqual(r.observe_source(SHA, self.api)['run_attempt'], 2)

    def test_current_main_repository_and_exact_merge_are_required(self):
        for path, replacement in (
            (self.base, dict(self.values[self.base], id=1)),
            (self.base + '/git/ref/heads/main', {'object': {'sha': 'b' * 40}}),
            (self.base + '/commits/' + SHA + '/pulls', []),
            (self.base + '/actions/workflows/ci.yml', {'id': 10, 'path': 'wrong', 'state': 'active'}),
        ):
            with self.subTest(path=path):
                original = self.values[path]
                self.values[path] = replacement
                with self.assertRaises(r.ReleaseError):
                    r.observe_source(SHA, self.api)
                self.values[path] = original

    def test_newer_failed_pending_or_rerun_blocks_older_success(self):
        path = self.base + '/actions/workflows/10/runs'
        old = self.values[path]['workflow_runs'][0]
        for updates in ({'run_number': 6, 'status': 'in_progress', 'conclusion': None},
                        {'run_number': 6, 'conclusion': 'failure'},
                        {'run_attempt': 3, 'status': 'queued', 'conclusion': None}):
            with self.subTest(updates=updates):
                self.values[path]['workflow_runs'] = [old, dict(old, **updates)]
                with self.assertRaises(r.ReleaseError):
                    r.observe_source(SHA, self.api)

    def test_check_cannot_come_from_other_app_workflow_attempt_or_sha(self):
        path = self.base + '/commits/' + SHA + '/check-runs'
        original = self.values[path]['check_runs'][0]
        for updates in ({'app': {'id': 123}}, {'check_suite': {'id': 99}},
                        {'head_sha': 'b' * 40}, {'conclusion': 'failure'}, {'id': 41}):
            with self.subTest(updates=updates):
                self.values[path]['check_runs'] = [dict(original, **updates)]
                with self.assertRaises(r.ReleaseError):
                    r.observe_source(SHA, self.api)

    def test_latest_failed_check_blocks_prior_pass(self):
        checks = self.values[self.base + '/commits/' + SHA + '/check-runs']['check_runs']
        checks.append(dict(checks[0], id=41, conclusion='failure'))
        with self.assertRaises(r.ReleaseError):
            r.observe_source(SHA, self.api)

    def test_pagination_is_bounded(self):
        with self.assertRaises(r.ReleaseError):
            r.pages(lambda p: [0] * 100, self.base)

    def test_fetch_preserves_git_head_and_rejects_dirty_source(self):
        calls = []
        def run(args, **kw):
            calls.append(args)
            if 'rev-parse' in args:
                return SHA.encode()
            if 'status' in args:
                return b'?? unrelated.txt'
            return b''
        with self.assertRaises(r.ReleaseError):
            r.fetch_source(SHA, Path('/synthetic/checkout'), run)
        self.assertTrue(any(r.REMOTE in call for call in calls))
        self.assertTrue(any('checkout' in call and '--detach' in call for call in calls))
        self.assertFalse(any('archive' in call for call in calls))


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='monitor-release-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.app = self.root / 'Machine Monitor.app'
        (self.app / 'Contents/MacOS').mkdir(parents=True)
        self.executable = self.app / 'Contents/MacOS/Machine Monitor'
        self.executable.write_bytes(bytes.fromhex('cffaedfe') + b'x' * 50)
        self.executable.chmod(0o755)
        self.info = {'CFBundleIdentifier': r.APP, 'CFBundleExecutable': 'Machine Monitor',
            'CFBundleVersion': '2', 'CFBundleShortVersionString': '1.1.0',
            'MachineMonitorSourceRevision': SHA, 'MachineMonitorDataSchemaVersion': 1,
            'LSMinimumSystemVersion': '26.0'}
        (self.app / 'Contents/Info.plist').write_bytes(plistlib.dumps(self.info))

    def test_launcher_refuses_modified_helpers(self):
        launcher, source = self.root / 'launcher', self.root / 'source'
        names = ('scripts/release.py', 'scripts/sparkle.py', 'scripts/toolchain.py',
                 'scripts/processes.py','build_mac_app.py', 'update_contract.py', 'update_preflight.py')
        for root in (launcher, source):
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('synthetic trusted source')
        with patch.object(r, 'ROOT', launcher):
            r.verify_launcher(source)
            (launcher / 'update_preflight.py').write_text('modified source')
            with self.assertRaises(r.ReleaseError): r.verify_launcher(source)

    def test_dependencies_refuse_unpinned_or_different_runtime(self):
        for name in ('requirements.txt', 'requirements-dev.txt', 'requirements-build.txt'):
            (self.root / name).write_text('fixture==1.0\n')
        with patch.object(r.sys, 'version_info', (3, 14, 6)), \
             patch.object(r.importlib.metadata, 'version', return_value='2.0'):
            with self.assertRaises(r.ReleaseError): r.dependencies(self.root)
        (self.root / 'requirements.txt').write_text('fixture>=1.0\n')
        with patch.object(r.sys, 'version_info', (3, 14, 6)):
            with self.assertRaises(r.ReleaseError): r.dependencies(self.root)

    def test_private_output_rejects_git_symlink_and_loose_mode(self):
        self.assertEqual(r.private_directory(self.root), self.root)
        self.root.chmod(0o755)
        with self.assertRaises(r.ReleaseError): r.private_directory(self.root)
        self.root.chmod(0o700)
        link = self.root / 'alias'
        link.symlink_to(self.root)
        with self.assertRaises(r.ReleaseError): r.private_directory(link)
        (self.root / '.git').mkdir()
        with self.assertRaises(r.ReleaseError): r.private_directory(self.root)

    def test_public_config_rejects_access_token(self):
        path = self.root / 'config.json'
        value = {'origin': 'https://updates.example.com', 'channel': 'stable', 'public_ed25519_key': PUBLIC}
        path.write_text(json.dumps(value))
        self.assertEqual(r.public_settings(path)['MachineMonitorUpdateChannel'], 'stable')
        path.write_text(json.dumps(dict(value, token='secret-fixture')))
        with self.assertRaises(r.ReleaseError): r.public_settings(path)

    def test_metadata_checks_actual_identity_architecture_source_and_build(self):
        runner = lambda args, **k: (b'cmd LC_BUILD_VERSION\ncmdsize 32\nplatform 1\nminos 26.0\nsdk 26.0' if 'otool' in args[0] else b'arm64')
        r.verify_metadata(self.app, '1.1.0', 2, SHA, run=runner)
        for key, value in (('CFBundleIdentifier', 'other'), ('CFBundleVersion', '1'),
                           ('MachineMonitorSourceRevision', 'b' * 40), ('LSMinimumSystemVersion', '25.0')):
            with self.subTest(key=key):
                (self.app / 'Contents/Info.plist').write_bytes(plistlib.dumps(dict(self.info, **{key: value})))
                with self.assertRaises(r.ReleaseError):
                    r.verify_metadata(self.app, '1.1.0', 2, SHA, run=lambda *a, **k: b'arm64')
        (self.app / 'Contents/Info.plist').write_bytes(plistlib.dumps(self.info))
        with self.assertRaises(r.ReleaseError):
            r.verify_metadata(self.app, '1.1.0', 2, SHA, run=lambda args, **k: runner(args).replace(b'26.0', b'25.0'))
        with self.assertRaises(r.ReleaseError):
            r.verify_metadata(self.app, '1.1.0', 2, SHA, run=lambda args, **k: runner(args) if 'otool' in args[0] else b'x86_64 arm64')

    def test_inside_out_signing_preserves_upstream_entitlements_without_deep(self):
        helper = self.app / 'Contents/Frameworks/Sparkle.framework/Versions/B/Updater.app'
        (helper / 'Contents/MacOS').mkdir(parents=True)
        binary = helper / 'Contents/MacOS/Updater'
        binary.write_bytes(bytes.fromhex('cffaedfe'))
        calls = []
        def run(args, **kw):
            calls.append(args)
            if '--entitlements' in args and '-d' in args:
                return plistlib.dumps({'synthetic.helper.entitlement': True})
            return b''
        with patch.object(r, 'verify_code') as verify:
            r.sign_app(self.app, 'a' * 40, self.root / 'upstream', self.root, run)
        signed = [c for c in calls if '--sign' in c]
        self.assertEqual(signed[-1][-1], str(self.app))
        self.assertLess(next(i for i,c in enumerate(signed) if c[-1] == str(binary)),
                        next(i for i,c in enumerate(signed) if c[-1] == str(helper)))
        self.assertTrue(all('--deep' not in c and '--timestamp' in c and 'runtime' in c for c in signed))
        self.assertTrue(any('--entitlements' in c for c in signed))
        verify.assert_called_once()

    def test_signature_metadata_requires_team_timestamp_and_runtime(self):
        good = f'TeamIdentifier={r.TEAM}\nAuthority=Developer ID Application: Fixture\nCodeDirectory v=20500 size=100 flags=0x10000(runtime) hashes=1+5 location=embedded\nTimestamp=Jan 1\n'
        r.display_code(self.app, lambda *a, **k: good.encode())
        for absent in (r.TEAM, 'runtime', 'Timestamp=Jan 1', 'Authority=Developer ID Application:'):
            with self.assertRaises(r.ReleaseError):
                r.display_code(self.app, lambda *a, **k: good.replace(absent, '').encode())
        for flags in ('flags=0x0(none)','flags=0x0(runtime)','flags=0x10000(none)','flags=runtime'):
            bad='Executable=/private/tmp/runtime/Machine Monitor\n'+good.replace('flags=0x10000(runtime)',flags)
            with self.assertRaises(r.ReleaseError):r.display_code(self.app,lambda *a,**k:bad.encode())
        for bad in ('Executable=/private/tmp/release flags=0x10000(runtime)/Machine Monitor\n'+good.replace('flags=0x10000(runtime)','flags=0x0(none)'),
                    good+good,good.replace('CodeDirectory','AbsentDirectory')):
            with self.assertRaises(r.ReleaseError):r.display_code(self.app,lambda *a,**k:bad.encode())

    def test_all_apple_verification_requirements_are_inline_expressions(self):
        calls=[]
        with patch.object(r,'display_code'):
            r.verify_code(self.app,lambda args,**kw:calls.append(args) or b'')
        self.assertGreaterEqual(len(calls),2)
        for args in calls:
            requirement=args[args.index('-R')+1]
            self.assertTrue(requirement.startswith('=anchor apple generic'))
            self.assertIn('certificate leaf[subject.OU] = "'+r.TEAM+'"',requirement)
            self.assertIn('certificate leaf[field.1.2.840.113635.100.6.1.13] exists',requirement)
        self.assertIn('identifier "'+r.APP+'"',calls[-1][-2])

    def test_notary_rejection_never_staples(self):
        for status in ('Invalid', 'In Progress', 'Rejected', None):
            calls = []
            def run(args, **kw):
                calls.append(args)
                return json.dumps({'id': 'a' * 36, 'status': status}).encode()
            with patch.object(r, 'package'):
                with self.assertRaises(r.ReleaseError):
                    r.notarize([self.app], self.root, 'fixture-profile', run)
            self.assertEqual(len(calls), 1)
            self.assertIn('--keychain-profile', calls[0])
            self.assertNotIn('--password', calls[0])

    def test_notary_acceptance_requires_staple_validate_gatekeeper_both_apps(self):
        calls = []
        recovery = self.root / 'Machine Monitor Recovery.app'
        def run(args, **kw):
            calls.append(args)
            return json.dumps({'id': '11111111-1111-1111-1111-111111111111', 'status': 'Accepted'}).encode()
        with patch.object(r, 'package'), patch.object(r, 'verify_code') as verify:
            r.notarize([self.app, recovery], self.root, 'fixture-profile', run)
        self.assertEqual(verify.call_count, 2)
        for app in (self.app, recovery):
            self.assertIn(['xcrun', 'stapler', 'staple', str(app)], calls)
            self.assertIn(['xcrun', 'stapler', 'validate', str(app)], calls)
            self.assertIn(['/usr/sbin/spctl', '--assess', '--type', 'execute', str(app)], calls)

    def test_staple_failure_cannot_reach_gatekeeper(self):
        calls = []
        def run(args, **kw):
            calls.append(args)
            if 'staple' in args: raise r.ReleaseError('synthetic staple refusal')
            return json.dumps({'id': '11111111-1111-1111-1111-111111111111', 'status': 'Accepted'}).encode()
        with patch.object(r, 'package'):
            with self.assertRaises(r.ReleaseError): r.notarize([self.app], self.root, 'fixture-profile', run)
        self.assertFalse(any('spctl' in ' '.join(c) for c in calls))

    def test_final_package_is_preflight_compatible_and_preserves_symlinks(self):
        (self.app / 'Contents/link').symlink_to('MacOS/Machine Monitor')
        (self.app / 'Contents/zeros').write_bytes(b'\0' * 100000)
        output = self.root / 'update.zip'
        r.package([self.app], output)
        descriptor = r.descriptor(output, SIGNATURE, 'release2', 'archive')
        install = dict(descriptor, path=descriptor['path'].replace('/archive', '/package'))
        manifest, receipt = r.records('1.1.0', 2, SHA, 'release2', 'q2', descriptor, install,
                                      {k: True for k in r.CHECKS})
        result = extract_archive(output, self.root / 'extract', manifest, verifier=lambda app, expected: {'synthetic': True})
        extracted = Path(result['app_path'])
        self.assertTrue((extracted / 'Contents/link').is_symlink())
        self.assertEqual((extracted / 'Contents/MacOS/Machine Monitor').stat().st_mode & 0o777, 0o755)
        with zipfile.ZipFile(output) as archive:
            self.assertEqual({p.split('/')[0] for p in archive.namelist()}, {'Machine Monitor.app'})
        self.assertFalse(manifest['qualified'])
        self.assertEqual(manifest['channel'], 'qualification')
        self.assertNotIn('private_upgrade', receipt['checks'])
        from scripts.toolchain import node
        js = "import {manifest} from './delivery/contract.mjs'; let s='';for await(const c of process.stdin)s+=c;manifest(JSON.parse(s));"
        r.command([node(), '--input-type=module', '-e', js], cwd=r.ROOT, input=json.dumps(manifest).encode())

    def test_package_rejects_symlink_escape_and_appledouble(self):
        link = self.app / 'Contents/escape'
        link.symlink_to('../../outside')
        (self.root / 'outside').write_text('fixture')
        with self.assertRaises(r.ReleaseError): r.package([self.app], self.root / 'bad.zip')
        link.unlink()
        (self.app / 'Contents/._secret').write_text('fixture')
        with self.assertRaises(r.ReleaseError): r.package([self.app], self.root / 'bad2.zip')

    def test_records_require_all_observed_checks(self):
        output = self.root / 'small.zip'
        output.write_bytes(b'fixture')
        descriptor = r.descriptor(output, SIGNATURE, 'release2', 'archive')
        install = dict(descriptor, path=descriptor['path'].replace('/archive', '/package'))
        for key in r.CHECKS:
            with self.subTest(key=key):
                checks = {k: True for k in r.CHECKS}
                checks[key] = False
                with self.assertRaises(r.ReleaseError):
                    r.records('1.1.0', 2, SHA, 'release2', 'q2', descriptor, install, checks)

    def test_embedded_public_key_mismatch_rejects_stock_signature(self):
        from scripts.toolchain import node
        binary = node()
        archive = self.root / 'synthetic.zip'
        archive.write_bytes(b'synthetic archive fixture')
        js = "const c=require('node:crypto'),f=require('node:fs');const k=c.generateKeyPairSync('ed25519');console.log(JSON.stringify({key:k.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64'),signature:c.sign(null,f.readFileSync(process.argv[1]),k.privateKey).toString('base64')}));"
        values = json.loads(r.command([binary, '-e', js, str(archive)]))
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            if args[0] == '/synthetic/sign_update':
                if '--help' in args: return b'--account --verify -p'
                return values['signature'].encode() if '-p' in args else b''
            return r.command(args, **kwargs)
        self.assertEqual(r.signature(archive, Path('/synthetic/sign_update'), r.APP,
                                    values['key'], binary, run), values['signature'])
        self.assertTrue(any('--verify' in c for c in calls))
        with self.assertRaises(r.ReleaseError):
            r.signature(archive, Path('/synthetic/sign_update'), r.APP, PUBLIC, binary, run)
        archive.write_bytes(b'tampered')
        with self.assertRaises(r.ReleaseError):
            r.signature(archive, Path('/synthetic/sign_update'), r.APP, values['key'], binary, run)

    def test_prepare_repackages_stapled_bytes_and_cleans_failed_attempt(self):
        config = self.root / 'public.json'
        config.write_text(json.dumps({'origin': 'https://updates.example.com', 'channel': 'stable',
                                      'public_ed25519_key': PUBLIC}))
        options = argparse.Namespace(source_revision=SHA, version='1.1.0', build_number=2,
            release_id='release2', qualification_id='q2', signing_identity='a' * 40,
            notary_profile='fixture-profile', sparkle_account=r.APP, output=self.root, update_config=config,
            sparkle_archive=self.root / 'official-sparkle.tar.xz')
        sequence = []
        status = ['Invalid']
        uploaded = []
        def fetch(sha, target, run):
            sequence.append('fetch')
            target.mkdir()
        def upstream(cache=None, *, archive=None):
            sequence.append('seed' if archive is not None else 'verify-cache')
            if archive is not None:
                self.assertEqual(archive, options.sparkle_archive)
                self.assertEqual(sequence[-2], 'verify-source')
            return self.root / 'upstream'
        def run(args, **kwargs):
            args = list(map(str, args))
            if len(args) > 1 and args[1].endswith('build_mac_app.py'):
                self.assertEqual(sequence[-1], 'seed')
                sequence.append('build')
                source = Path(args[1]).parent
                settings = json.loads(Path(args[-1]).read_text())
                for name in ('Machine Monitor.app', 'Machine Monitor Recovery.app'):
                    app = source / 'dist' / name
                    shutil.copytree(self.app, app)
                    info = dict(self.info)
                    if 'Recovery' in name:
                        info['CFBundleIdentifier'] += '.recovery'
                    else:
                        info.update(MachineMonitorUpdateOrigin=settings['origin'],
                            MachineMonitorUpdateChannel=settings['channel'], SUPublicEDKey=settings['public_ed25519_key'])
                    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
                for name in ('LICENSE', 'PRIVATE-BINARY-LICENSE', 'THIRD-PARTY-NOTICES.md'):
                    (source / name).write_text('Synthetic terms')
            if 'otool' in args[0]:
                return b'cmd LC_BUILD_VERSION\ncmdsize 32\nplatform 1\nminos 26.0\nsdk 26.0'
            if 'lipo' in args[0]: return b'arm64'
            if '-c' in args:
                return f'TeamIdentifier={r.TEAM}\nAuthority=Developer ID Application: Fixture\nCodeDirectory v=20500 size=100 flags=0x10000(runtime) hashes=1+5 location=embedded\nTimestamp=fixture\n'.encode()
            if 'notarytool' in args:
                with zipfile.ZipFile(args[3]) as archive:
                    uploaded.append(archive.namelist())
                return json.dumps({'id': '11111111-1111-1111-1111-111111111111', 'status': status[0]}).encode()
            if 'staple' in args:
                (Path(args[-1]) / 'Contents/stapled-fixture').write_text('Synthetic ticket')
            return b''
        with ExitStack() as stack:
            stack.enter_context(patch.object(r, 'fetch_source', fetch))
            stack.enter_context(patch.object(r, 'verify_launcher', side_effect=lambda source: sequence.append('verify-source')))
            stack.enter_context(patch.object(r, 'dependencies', return_value={'fixture': '1'}))
            stack.enter_context(patch.object(r, 'signature', return_value=SIGNATURE))
            stack.enter_context(patch.object(r.platform, 'system', return_value='Darwin'))
            stack.enter_context(patch.object(r.platform, 'machine', return_value='arm64'))
            stack.enter_context(patch('scripts.sparkle.distribution', side_effect=upstream))
            stack.enter_context(patch('scripts.toolchain.node', return_value=Path('/synthetic/node')))
            stack.enter_context(patch('update_preflight.extract_archive', side_effect=lambda a,d,m:
                extract_archive(a,d,m,verifier=lambda app, expected: {'synthetic': True})))
            api = lambda path: copy.deepcopy(source_fixture()[path.split('?')[0]])
            with self.assertRaises(r.ReleaseError): r.prepare(options, run=run, api=api)
            self.assertFalse((self.root / 'release2').exists())
            self.assertFalse(list(self.root.glob('.release-*')))
            status[0] = 'Accepted'
            final = r.prepare(options, run=run, api=api)
        self.assertFalse(list(self.root.glob('.release-*')))
        self.assertTrue(all(not any('stapled-fixture' in n for n in names) for names in uploaded))
        with zipfile.ZipFile(final / 'Machine-Monitor.zip') as archive:
            self.assertIn('Machine Monitor.app/Contents/stapled-fixture', archive.namelist())
        with zipfile.ZipFile(final / 'Machine-Monitor-Install.zip') as archive:
            self.assertIn('Machine Monitor Recovery.app/Contents/stapled-fixture', archive.namelist())
            self.assertIn('Install.txt', archive.namelist())
        manifest = json.loads((final / 'manifest.json').read_text())
        receipt = json.loads((final / 'qualification.json').read_text())
        provenance = json.loads((final / 'provenance.json').read_text())
        self.assertEqual(provenance['runtime_channel'], 'stable')
        self.assertEqual(provenance['distribution_channel'], 'qualification')
        self.assertEqual(provenance['sparkle_archive_input'], 'locally-supplied-pinned-archive')
        self.assertFalse(manifest['qualified'])
        self.assertNotIn('private_upgrade', receipt['checks'])
        self.assertEqual(receipt['archive_sha256'], manifest['archive']['sha256'])
        self.assertEqual(receipt['first_install_sha256'], manifest['first_install']['sha256'])

    def test_import_is_side_effect_free(self):
        with patch('subprocess.Popen', side_effect=AssertionError('process on import')), \
             patch('urllib.request.build_opener', side_effect=AssertionError('network on import')), \
             patch('builtins.open', side_effect=AssertionError('file I/O on import')):
            importlib.reload(r)

    def test_no_cli_qualification_bypass(self):
        with self.assertRaises(SystemExit) as result, patch('sys.stderr'):
            r.main(['--assume-qualified'])
        self.assertEqual(result.exception.code, 2)


class CommandTests(unittest.TestCase):
    def test_failure_names_tool_and_status_without_revealing_diagnostics(self):
        with self.assertRaisesRegex(r.ReleaseError,'status 7') as caught:
            r.command([sys.executable,'-c','import sys;sys.stderr.write("SYNTHETIC_PRIVATE_MESSAGE");sys.exit(7)'])
        self.assertIn(Path(sys.executable).name,str(caught.exception))
        self.assertNotIn('SYNTHETIC_PRIVATE_MESSAGE',str(caught.exception))

    def test_captured_input_and_binary_output(self):
        self.assertEqual(r.command([sys.executable,'-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read());sys.stderr.write("private")'],input=b'bounded\x00bytes'),b'bounded\x00bytes')

    def test_overflow_stops_child_before_later_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            marker=Path(directory)/'continued'
            for stream in ('stdout','stderr'):
                script='import sys,time;from pathlib import Path;sys.'+stream+'.buffer.write(b"x"*(9*1024**2));sys.'+stream+'.flush();time.sleep(2);Path(sys.argv[1]).write_text("continued")'
                with self.subTest(stream=stream),self.assertRaisesRegex(r.ReleaseError,'output exceeded'):
                    r.command([sys.executable,'-c',script,str(marker)],timeout=10)
                self.assertFalse(marker.exists())

    def test_timeout_stops_nested_builder_group_and_bounds_pipe_drain(self):
        from scripts.processes import group_stopped
        with tempfile.TemporaryDirectory() as directory:
            identity=Path(directory)/'identity.json'
            leaf='import os,sys,time,json;from pathlib import Path;Path(sys.argv[1]).write_text(json.dumps([os.getpid(),os.getpgrp()]));time.sleep(30)'
            builder='import os,sys;assert os.environ["MONITOR_OWNED_SHARD_GROUP"]=="1";from scripts.processes import run_build;run_build([sys.executable,"-c",sys.argv[1],sys.argv[2]],timeout=60)'
            started=time.monotonic()
            with self.assertRaisesRegex(r.ReleaseError,'timed out'):
                r.command([sys.executable,'-c',builder,leaf,str(identity)],cwd=r.ROOT,timeout=1)
            self.assertLess(time.monotonic()-started,10)
            pid,pgid=json.loads(identity.read_text());self.assertTrue(group_stopped(pgid))


if __name__ == '__main__':
    unittest.main()
