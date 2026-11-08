"""Credential-free Worker/API and owner administration contract checks."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('owner_delivery', ROOT / 'scripts/delivery.py')
delivery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(delivery)


def node():
    binary = os.environ.get('MONITOR_NODE', 'node')
    version = subprocess.run([binary, '--version'], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    if version != 'v26.4.0':
        raise AssertionError('Required Node runtime is 26.4.0; no test can be skipped.')
    return binary


class MemoryAPI:
    def __init__(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        self.db.executescript((ROOT / 'delivery/schema.sql').read_text())
        self.calls = []
        self.uploads = []
        self.checked_privacy = False
        self.readbacks = []

    def query(self, sql, params=()):
        self.calls.append((sql, params))
        cursor = self.db.execute(sql, params)
        return [dict(row) for row in cursor.fetchall()]

    def privacy(self):
        self.checked_privacy = True

    def readback(self, key, digest, size):
        self.readbacks.append((key, digest, size))

    def put_checked(self, path, key, digest):
        self.uploads.append((key, delivery.file_digest(path)))
        assert self.uploads[-1][1][0] == digest


def release(channel='qualification'):
    sig = __import__('base64').b64encode(bytes(64)).decode()
    artifact = {'size': 4, 'sha256': hashlib.sha256(b'test').hexdigest(), 'ed25519_signature': sig}
    return dict(schema='machine-monitor/release/v1', app_id=delivery.APP, bundle_id=delivery.APP,
        team_id='J2V7GRV5CM', channel=channel, version='1.2', build=2, minimum_macos='26.0', architecture='arm64',
        data_schema_version=1, source_revision='a' * 40, qualification_id='fixture-q', qualified=channel == 'stable',
        archive=dict(artifact, path=f'/v1/apps/{delivery.APP}/releases/release-2/archive'),
        first_install=dict(artifact, path=f'/v1/apps/{delivery.APP}/releases/release-2/package'))


def receipt(value):
    return dict(schema='machine-monitor/qualification/v1', app_id=delivery.APP,
        qualification_id=value['qualification_id'], source_revision=value['source_revision'], build=value['build'],
        archive_sha256=value['archive']['sha256'], archive_size=value['archive']['size'],
        first_install_sha256=value['first_install']['sha256'], first_install_size=value['first_install']['size'],
        checks=dict.fromkeys(delivery.CHECKS, True))


class ChannelTests(unittest.TestCase):
    def setUp(self):
        self.api = MemoryAPI()
        self.addCleanup(self.api.db.close)

    def test_actual_worker_primary_reads_auth_cache_isolation_and_errors(self):
        result = subprocess.run([node(), str(ROOT / 'tests/helpers/update_worker.mjs')], cwd=ROOT,
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertTrue(evidence['passed'])
        self.assertGreaterEqual(evidence['assertions'], 45)
        self.assertGreater(evidence['primary_reads'], 20)

    def test_closed_wire_contract_rejects_cross_release_and_unknown_fields(self):
        value = release()
        delivery.validate_manifest(value)
        for version in ('1', '0.1', '2.10.1', '1.2.3.4'):
            delivery.validate_manifest(dict(value, version=version))
        for bad in (dict(value, version='01.2'), dict(value, version='1.2.3.4.5'),
                    dict(value, unexpected='no'), dict(value, qualification_id='dots.are.invalid')):
            with self.assertRaises(delivery.DeliveryError):
                delivery.validate_manifest(bad)
        bad = release()
        bad['first_install']['path'] = bad['first_install']['path'].replace('release-2', 'release-3')
        with self.assertRaises(delivery.DeliveryError):
            delivery.validate_manifest(bad)
        bad = release()
        bad['archive']['url'] = 'https://elsewhere.invalid/'
        with self.assertRaises(delivery.DeliveryError):
            delivery.validate_manifest(bad)

    def test_grant_credential_256_bits_hashed_at_rest_and_private_output(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder).resolve() / 'friend.machine-monitor-access'
            capture = io.StringIO()
            with contextlib.redirect_stdout(capture):
                grant = delivery.create_grant(self.api, {'origin': 'https://download.example.invalid'}, 'friend-opaque', path, int(time.time()) + 3600)
            data = json.loads(path.read_text())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(__import__('base64').urlsafe_b64decode(data['token'] + '=')), 32)
            self.assertNotIn(data['token'], repr(self.api.calls))
            self.assertNotIn(data['token'], capture.getvalue())
            row = self.api.query('SELECT * FROM grants WHERE grant_id=?', (grant,))[0]
            self.assertEqual(row['token_hash'], hashlib.sha256(data['token'].encode()).hexdigest())
            self.assertEqual(row['is_owner'], 0)
            with self.assertRaises(delivery.DeliveryError):
                delivery.create_grant(self.api, {'origin': 'https://download.example.invalid'}, 'friend-opaque', path, int(time.time()) + 3600)

    def test_access_file_and_config_cannot_be_written_under_git_or_symlinks(self):
        with self.assertRaises(delivery.DeliveryError):
            delivery.private_write(ROOT / 'delivery' / 'forbidden.machine-monitor-access', {})
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            actual = root / 'actual'
            actual.write_text('preserve')
            link = root / 'link'
            link.symlink_to(actual)
            with self.assertRaises(delivery.DeliveryError):
                delivery.private_write(link, {})
            self.assertEqual(actual.read_text(), 'preserve')
            config = root / 'config.json'
            config.write_text('{}')
            config.chmod(0o644)
            with self.assertRaises(delivery.DeliveryError):
                delivery.load_config(config)

    def test_qualification_grants_are_owner_only_and_finite(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder).resolve() / 'fixture.machine-monitor-access'
            for owner, expiry in ((False, int(time.time()) + 3600), (True, 1)):
                with self.assertRaises(delivery.DeliveryError):
                    delivery.create_grant(self.api, {'origin': 'https://download.example.invalid'}, 'fixture', path, expiry, owner, 'qualification')
            self.assertEqual(self.api.query('SELECT * FROM grants'), [])

    def test_exact_qualification_then_stable_promotion_and_downgrade_refusal(self):
        value = release()
        proof = receipt(value)
        with tempfile.TemporaryDirectory() as folder:
            artifact = Path(folder) / 'artifact'
            artifact.write_bytes(b'test')
            delivery.publish(self.api, value, proof, artifact, artifact)
        self.assertTrue(self.api.checked_privacy)
        self.assertEqual(len(self.api.uploads), 2)
        stable = dict(value, channel='stable', qualified=True)
        with self.assertRaises(delivery.DeliveryError):
            delivery.publish(self.api, stable, proof)
        proof['checks']['private_upgrade'] = True
        tampered = dict(stable, source_revision='b' * 40)
        with self.assertRaises(delivery.DeliveryError):
            delivery.publish(self.api, tampered, receipt(tampered))
        delivery.publish(self.api, stable, proof)
        self.assertEqual(len(self.api.uploads), 2, 'stable cannot upload different bytes')
        self.assertEqual(len(self.api.readbacks), 2, 'stable must reverify retained bytes')
        delivery.publish(self.api, stable, proof)  # exact retry is idempotent
        self.assertEqual(self.api.query("SELECT release_id FROM channels WHERE channel='stable'")[0]['release_id'], 'release-2')
        older = release()
        older['build'] = 1
        older['archive']['path'] = older['archive']['path'].replace('release-2', 'release-1')
        older['first_install']['path'] = older['first_install']['path'].replace('release-2', 'release-1')
        with tempfile.TemporaryDirectory() as folder:
            artifact = Path(folder) / 'artifact'
            artifact.write_bytes(b'test')
            with self.assertRaises(delivery.DeliveryError):
                delivery.publish(self.api, older, receipt(older), artifact, artifact)
        self.assertEqual(self.api.query("SELECT release_id FROM channels WHERE channel='qualification'")[0]['release_id'], 'release-2')

    def test_unqualified_or_mismatched_artifact_never_published(self):
        value = release()
        for key in delivery.CHECKS:
            bad = receipt(value)
            bad['checks'][key] = False
            with self.assertRaises(delivery.DeliveryError):
                delivery.publish(self.api, value, bad)
        with tempfile.TemporaryDirectory() as folder:
            artifact = Path(folder) / 'wrong'
            artifact.write_bytes(b'wrong')
            with self.assertRaises(delivery.DeliveryError):
                delivery.publish(self.api, value, receipt(value), artifact, artifact)
        self.assertEqual(self.api.query('SELECT * FROM releases'), [])
        self.assertEqual(self.api.uploads, [])

    def test_privacy_api_denies_public_buckets_and_all_api_redirects(self):
        api = delivery.Cloudflare.__new__(delivery.Cloudflare)
        api.config = {'bucket_name': 'fixture'}
        for managed, custom in (({'enabled': True}, {'domains': []}), ({'enabled': False}, {'domains': [{'domain': 'public.invalid'}]}), ({}, {})):
            with patch.object(api, 'api', side_effect=[managed, custom]), self.assertRaises(delivery.DeliveryError):
                api.privacy()
        with patch.object(api, 'api', side_effect=[{'enabled': False}, {'domains': []}]):
            api.privacy()
        with self.assertRaises(delivery.DeliveryError):
            delivery.NoRedirect().redirect_request(None, None, None, None, None, None)

    def test_deployment_supports_exact_owned_workers_dev_primary_origin(self):
        config = dict(origin='https://monitor.owned-fixture.workers.dev', worker_name='monitor',
                      account_id='a' * 32, database_name='fixture', database_id='b' * 36,
                      bucket_name='fixture', wrangler='/fixture/wrangler')
        api = delivery.Cloudflare.__new__(delivery.Cloudflare)
        api.config = config
        with patch.object(api, 'api', return_value={'subdomain': 'owned-fixture'}) as current:
            result = delivery.deployment_config(config, api)
            current.assert_called_once_with('/workers/subdomain')
        self.assertTrue(result['workers_dev'])
        self.assertFalse(result['preview_urls'])
        self.assertEqual(result['routes'], [])
        self.assertEqual(result['vars']['UPDATE_ORIGIN'], config['origin'])
        self.assertEqual(result['d1_databases'][0]['binding'], 'DB')
        self.assertEqual(result['r2_buckets'][0]['binding'], 'ARCHIVES')
        with self.assertRaises(delivery.DeliveryError):
            delivery.deployment_config(config)
        for ownership in ({}, None, {'subdomain': 'foreign'}, {'subdomain': 'owned-fixture.workers.dev'},
                          {'subdomain': 'owned-fixture/unsafe'}, {'subdomain': 'Owned-fixture'}):
            with patch.object(api, 'api', return_value=ownership), self.assertRaises(delivery.DeliveryError):
                delivery.deployment_config(config, api)
        for host in ('other.owned-fixture.workers.dev', 'alias.monitor.owned-fixture.workers.dev',
                     'monitor.foreign.workers.dev', 'workers.dev'):
            with patch.object(api, 'api', return_value={'subdomain': 'owned-fixture'}), self.assertRaises(delivery.DeliveryError):
                delivery.deployment_config(dict(config, origin='https://' + host), api)
        with patch.object(api, 'api', side_effect=delivery.DeliveryError('Provider unavailable.')), self.assertRaises(delivery.DeliveryError):
            delivery.deployment_config(config, api)

    def test_workers_dev_config_is_explicit_and_ownership_failure_precedes_writes(self):
        config = dict(origin='https://monitor.owned-fixture.workers.dev', worker_name='monitor',
                      account_id='a' * 32, database_name='fixture', database_id='b' * 36,
                      bucket_name='fixture', wrangler='/fixture/wrangler')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            binary = root / 'fixture-wrangler'
            binary.write_text('not executed')
            config['wrangler'] = str(binary)
            filename = root / 'owner.json'
            delivery.private_write(filename, config)
            self.assertEqual(delivery.load_config(filename), config)
        api = MagicMock()
        api.api.return_value = {'subdomain': 'foreign-account'}
        with patch.object(delivery, 'load_config', return_value=config), patch.object(delivery, 'Cloudflare', return_value=api), patch.object(delivery.sys, 'argv', ['delivery.py', '--config', '/unused/owner.json', 'deploy']), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(delivery.main(), 1)
        api.api.assert_called_once_with('/workers/subdomain')
        api.query.assert_not_called()
        api.wrangler.assert_not_called()

    def test_custom_domain_deployment_disables_workers_dev_without_ownership_read(self):
        config = dict(origin='https://download.example.invalid', worker_name='monitor',
                      account_id='a' * 32, database_name='fixture', database_id='b' * 36,
                      bucket_name='fixture', wrangler='/fixture/wrangler')
        api = delivery.Cloudflare.__new__(delivery.Cloudflare)
        with patch.object(api, 'api', side_effect=AssertionError('Custom hostname needs no workers.dev read')):
            result = delivery.deployment_config(config, api)
        self.assertFalse(result['workers_dev'])
        self.assertFalse(result['preview_urls'])
        self.assertEqual(result['routes'], [{'pattern': 'download.example.invalid', 'custom_domain': True}])
        self.assertEqual(result['vars']['UPDATE_ORIGIN'], config['origin'])

    def test_pinned_wrangler_auth_is_captured_without_argv_secrets(self):
        secret = 'fixture-owner-token'
        seen = []
        def fake(args, **kwargs):
            seen.append((args, kwargs))
            if args[-1] == '--version':
                return subprocess.CompletedProcess(args, 0, b'4.158.0\n', b'')
            return subprocess.CompletedProcess(args, 0, json.dumps({'type': 'oauth', 'token': secret}).encode(), b'')
        with patch.object(delivery.subprocess, 'run', side_effect=fake):
            api = delivery.Cloudflare({'wrangler': '/fixture/wrangler'})
        self.assertEqual(api._authorization, 'Bearer ' + secret)
        for args, kwargs in seen:
            self.assertNotIn(secret, repr(args))
            self.assertEqual(kwargs['env']['WRANGLER_SEND_METRICS'], 'false')
            self.assertEqual(kwargs['env']['WRANGLER_WRITE_LOGS'], 'false')
            self.assertEqual(kwargs['env']['WRANGLER_LOG'], 'none')
            self.assertEqual(kwargs['env']['WRANGLER_LOG_SANITIZE'], 'true')
            self.assertEqual(kwargs['env']['WRANGLER_SEND_ERROR_REPORTS'], 'false')
            self.assertEqual(kwargs['env']['CLOUDFLARE_API_BASE_URL'], 'https://api.cloudflare.com/client/v4')
            self.assertNotIn('WRANGLER_OUTPUT_FILE_PATH', kwargs['env'])
            self.assertNotIn('WRANGLER_OUTPUT_FILE_DIRECTORY', kwargs['env'])
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        with patch.object(delivery.Cloudflare, 'wrangler', return_value='4.0.0'), self.assertRaises(delivery.DeliveryError):
            delivery.Cloudflare({'wrangler': '/fixture/wrangler'})


if __name__ == '__main__':
    unittest.main()
