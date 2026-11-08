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
import urllib.error
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
        self.events = []
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name).resolve()
        self.assets = self.root / 'assets'
        self.assets.mkdir(mode=0o700)
        self.config = config_fixture(self.root)
        self.uploads = []

    def query(self, sql, params=()):
        self.calls.append((sql, params))
        self.events.append(sql.split()[0] + ':' + ('channels' if 'INTO channels' in sql else 'releases' if 'INTO releases' in sql else 'query'))
        cursor = self.db.execute(sql, params)
        return [dict(row) for row in cursor.fetchall()]

    def privacy(self):
        self.checked_privacy = True

    def require_free(self):
        return delivery.require_free(self.config)

    def deploy(self):
        self.require_free()
        self.events.append('deploy')
        self.uploads = list(delivery.asset_inventory(self.config))

    def readback(self, release_id, descriptor, kind):
        self.events.append('readback')
        self.readbacks.append((release_id, descriptor, kind))


def config_fixture(root):
    assets = root / 'assets'
    assets.mkdir(mode=0o700, exist_ok=True)
    now = int(time.time())
    proof = dict(schema='machine-monitor/free-plan-observation/v1', account_id='a' * 32,
                 observed_plan='Workers Free', source='owner-dashboard-observation',
                 source_reference='owner-chat:synthetic-fixture-not-live-evidence', observed_at=now - 1, expires_at=now + 300)
    filename = root / 'free.json'
    if not filename.exists(): delivery.private_write(filename, proof)
    return dict(origin='https://monitor.owned-fixture.workers.dev', worker_name='monitor',
                account_id='a' * 32, database_name='fixture', database_id='b' * 36,
                assets_directory=str(assets), free_plan_proof=str(filename),
                deployment_state=str(root / 'deployment.json'), wrangler='/fixture/wrangler')


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
        self.addCleanup(self.api.folder.cleanup)

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
        self.assertEqual(len(self.api.readbacks), 4, 'qualification and stable both reverify retained bytes')
        self.assertLess(self.api.events.index('deploy'), self.api.events.index('INSERT:releases'))
        self.assertLess(self.api.events.index('readback'), self.api.events.index('INSERT:channels'))
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

    def test_free_proof_blocks_every_mutation_and_no_boolean_bypass(self):
        config = self.api.config
        original = delivery.private_json(config['free_plan_proof'])
        invalid = [{}, dict(original, observed_plan='Workers Paid'), dict(original, account_id='c' * 32),
                   dict(original, observed_at=1, expires_at=100), dict(original, observed_at=int(time.time()) + 30),
                   dict(original, expires_at=original['observed_at'] + 3601), dict(original, source='assume-free'),
                   dict(original, assume_free=True)]
        api = delivery.Cloudflare.__new__(delivery.Cloudflare)
        api.config = config
        api._opener = MagicMock()
        for proof in invalid:
            Path(config['free_plan_proof']).write_text(json.dumps(proof))
            for operation in (lambda: api.api('/d1/database', {'name': 'new'}),
                              lambda: api.query('CREATE TABLE forbidden(x)'), lambda: api.create_database('new'),
                              lambda: api.create_subdomain('new'), lambda: api.deploy(),
                              lambda: api.wrangler('deploy', '--config', '/unused'),
                              lambda: delivery.publish(api, release(), receipt(release())),
                              lambda: delivery.create_grant(api, config, 'fixture', self.api.root / 'unused', int(time.time()) + 30)):
                with self.assertRaises(delivery.DeliveryError): operation()
            api._opener.open.assert_not_called()
        Path(config['free_plan_proof']).write_text(json.dumps(original))
        self.assertEqual(delivery.require_free(config)['source'], 'owner-dashboard-observation')
        with self.assertRaises(delivery.DeliveryError):
            api.wrangler('r2', 'object', 'put', 'forbidden')
        with self.assertRaises(delivery.DeliveryError):
            api.api('/subscriptions', {'plan': 'paid'})
        with self.assertRaises(delivery.DeliveryError):
            delivery.NoRedirect().redirect_request(None, None, None, None, None, None)

    def test_bootstrap_only_creates_new_free_resources_with_capacity(self):
        api = delivery.Cloudflare.__new__(delivery.Cloudflare);api.config=self.api.config
        with patch.object(api,'api',side_effect=[[],{'uuid':'synthetic-only'}]) as calls:
            self.assertEqual(api.create_database('new-fixture'),{'uuid':'synthetic-only'})
            self.assertEqual(calls.call_args.args,('/d1/database',{'name':'new-fixture'},'POST'))
        for databases in ([{'name':'new-fixture'}], [{'name':'x'}] * 10, None):
            with patch.object(api,'api',return_value=databases) as calls, self.assertRaises(delivery.DeliveryError):api.create_database('new-fixture')
            self.assertEqual(calls.call_count,1)
        with patch.object(api,'api',side_effect=[None,{'subdomain':'new-fixture'}]) as calls:
            self.assertEqual(api.create_subdomain('new-fixture')['subdomain'],'new-fixture')
            self.assertEqual(calls.call_args.args,('/workers/subdomain',{'subdomain':'new-fixture'},'PUT'))
        with patch.object(api,'api',return_value={'subdomain':'existing'}) as calls, self.assertRaises(delivery.DeliveryError):api.create_subdomain('new-fixture')
        self.assertEqual(calls.call_count,1)
        for unknown in ({},{'subdomain':''},[],False):
            with patch.object(api,'api',return_value=unknown) as calls,self.assertRaises(delivery.DeliveryError):api.create_subdomain('new-fixture')
            self.assertEqual(calls.call_count,1)

    def test_initial_missing_resource_requires_exact_provider_error(self):
        api=delivery.Cloudflare.__new__(delivery.Cloudflare);api.config=self.api.config
        api._authorization='Bearer synthetic-only';api._opener=MagicMock()
        def refused(status=404,codes=(10007,),success=False,body=None):
            value={'success':success,'errors':[{'code':code} for code in codes],'result':None}
            return urllib.error.HTTPError('https://api.cloudflare.com/client/v4',status,'synthetic',{},io.BytesIO(body or json.dumps(value).encode()))
        for path in ('/workers/subdomain','/workers/scripts/monitor/deployments'):
            with patch.object(api._opener,'open',side_effect=refused()):self.assertIsNone(api.api(path,allow_not_found=True))
            response=MagicMock();response.__enter__.return_value.read.return_value=b'{"success":true,"result":null}'
            with patch.object(api._opener,'open',return_value=response),self.assertRaises(delivery.DeliveryError):api.api(path,allow_not_found=True)
            for error in (refused(403),refused(codes=(10000,)),refused(codes=(10007,10000)),refused(success=True),refused(body=b'not-json')):
                with patch.object(api._opener,'open',side_effect=error),self.assertRaises(delivery.DeliveryError):api.api(path,allow_not_found=True)
            with patch.object(api._opener,'open',side_effect=refused()),self.assertRaises(delivery.DeliveryError):api.api(path)
        with patch.object(api._opener,'open',side_effect=refused()),self.assertRaises(delivery.DeliveryError):api.api('/d1/database',allow_not_found=True)
        response=MagicMock();response.__enter__.return_value.read.return_value=b'{"success":true,"result":null}'
        with patch.object(api._opener,'open',return_value=response) as calls,self.assertRaises(delivery.DeliveryError):api.create_subdomain('new-fixture')
        self.assertEqual(calls.call_count,1)

    def test_deployment_requires_unconditional_private_worker_first_and_owned_origin(self):
        config = self.api.config
        api = delivery.Cloudflare.__new__(delivery.Cloudflare);api.config = config
        with patch.object(api, 'api', return_value={'subdomain': 'owned-fixture'}):
            result = delivery.deployment_config(config, api)
        self.assertTrue(result['workers_dev']);self.assertFalse(result['preview_urls'])
        self.assertEqual(result['routes'], [])
        self.assertEqual(result['d1_databases'][0]['binding'], 'DB')
        self.assertEqual(result['assets']['binding'], 'ASSETS')
        self.assertIs(result['assets']['run_worker_first'], True)
        self.assertNotIn('r2_buckets', result)
        for mutation in ({'run_worker_first': False}, {'run_worker_first': ['/v1/*', '!/_private/*']},
                         {'not_found_handling': 'single-page-application'}, {'html_handling': 'auto-trailing-slash'},
                         {'redirects': '/public'}):
            bad = dict(result, assets=dict(result['assets'], **mutation))
            with self.assertRaises(delivery.DeliveryError):delivery.validate_deployment_config(bad)
        for field, value in (('routes', [{'pattern': '*', 'fail_open': True}]), ('preview_urls', True), ('workers_dev', False)):
            with self.assertRaises(delivery.DeliveryError):delivery.validate_deployment_config(dict(result, **{field: value}))
        for ownership in ({}, None, {'subdomain': 'foreign'}, {'subdomain': 'owned-fixture/unsafe'}):
            with patch.object(api, 'api', return_value=ownership), self.assertRaises(delivery.DeliveryError):
                delivery.deployment_config(config, api)
        with self.assertRaises(delivery.DeliveryError):delivery.deployment_config(config)
        for host in ('other.owned-fixture.workers.dev', 'alias.monitor.owned-fixture.workers.dev', 'download.example.invalid'):
            with patch.object(api, 'api', return_value={'subdomain': 'owned-fixture'}), self.assertRaises(delivery.DeliveryError):
                delivery.deployment_config(dict(config, origin='https://' + host), api)

    def test_active_version_including_zero_percent_and_provider_source_readback(self):
        config = self.api.config
        api = delivery.Cloudflare.__new__(delivery.Cloudflare);api.config = config
        version = '12345678-1234-1234-1234-123456789abc'
        with patch.object(api, 'api', return_value={'subdomain': 'owned-fixture'}):
            configured = delivery.deployment_config(config, api)
        state = dict(schema='machine-monitor/private-deployment/v1',account_id=config['account_id'],worker_name=config['worker_name'],
                     version_id=version,etag='reviewed-etag',source_sha256=delivery.source_digest(),config=configured,assets={})
        delivery.private_write(config['deployment_state'],state)
        responses = {'/workers/subdomain': {'subdomain': 'owned-fixture'},
                     '/workers/scripts/monitor/deployments': {'deployments': [{'versions': [{'version_id': version, 'percentage': 100}]}]},
                     '/workers/scripts/monitor/versions/' + version: {'resources': {'script': {'etag': 'reviewed-etag'}}},
                     '/workers/scripts/monitor/subdomain': {'enabled': True, 'previews_enabled': False}, '/workers/domains': []}
        with patch.object(api, 'zone_routes', return_value=[]), patch.object(api,'api',side_effect=lambda path: responses[path]):delivery.audit_deployment(api)
        negatives = [('/workers/scripts/monitor/deployments', {'deployments': [{'versions': [{'version_id': version,'percentage':100},{'version_id':'unsafe','percentage':0}]}]}),
                     ('/workers/scripts/monitor/deployments', {'deployments': []}),
                     ('/workers/scripts/monitor/versions/' + version, {'resources': {'script': {'etag': 'changed'}}}),
                     ('/workers/scripts/monitor/subdomain', {'enabled': True,'previews_enabled': True}),
                     ('/workers/domains', [{'service':'monitor','hostname':'unsafe.invalid'}])]
        for path, bad in negatives:
            changed = dict(responses, **{path: bad})
            with patch.object(api, 'zone_routes', return_value=[]), patch.object(api,'api',side_effect=lambda key: changed[key]), self.assertRaises(delivery.DeliveryError):
                delivery.audit_deployment(api)
        for domains, routes in (([{'unknown_shape':'monitor'}],[]),([], [{'unknown_shape':'monitor','fail_open':True}]),
                                 ([None],[]),([{'service':False}],[]),([], [{'script':[]}]),([], [{'script':''}])):
            changed = dict(responses, **{'/workers/domains':domains})
            with patch.object(api, 'zone_routes', return_value=routes), patch.object(api,'api',side_effect=lambda key: changed[key]), self.assertRaises(delivery.DeliveryError):
                delivery.audit_deployment(api)
        changed = dict(responses, **{'/workers/domains':[{'service':'other-worker'}]})
        with patch.object(api, 'zone_routes', return_value=[{'script':None},{'script':'other-worker'}]), patch.object(api,'api',side_effect=lambda key: changed[key]):
            delivery.audit_deployment(api)

    def test_existing_worker_with_lost_receipt_cannot_be_replaced(self):
        api = delivery.Cloudflare.__new__(delivery.Cloudflare);api.config=self.api.config
        def response(path, **kwargs):
            return {'subdomain':'owned-fixture'} if path == '/workers/subdomain' else {'deployments':[]}
        with patch.object(api,'api',side_effect=response), patch.object(api,'query') as query, patch.object(api,'wrangler') as wrangler:
            with self.assertRaises(delivery.DeliveryError):api.deploy()
            query.assert_not_called();wrangler.assert_not_called()

    def test_zone_routes_are_exhaustive_read_only_and_fail_closed(self):
        api = delivery.Cloudflare.__new__(delivery.Cloudflare);api.config=self.api.config
        zone = 'f' * 32
        with patch.object(api,'_zone_read',side_effect=[[{'id':zone}],[{'script':'monitor','fail_open':True}]]) as reads:
            self.assertEqual(api.zone_routes()[0]['script'],'monitor')
            self.assertEqual(reads.call_count,2)
        with patch.object(api,'_zone_read',return_value=None), self.assertRaises(delivery.DeliveryError):api.zone_routes()
        for path in ('/zones/foreign/workers/routes', '/zones?account.id=foreign', '/subscriptions'):
            with self.assertRaises(delivery.DeliveryError):api._zone_read(path)

    def test_private_assets_bounded_immutable_retained_and_no_routing_files(self):
        root = Path(self.api.config['assets_directory'])
        source = self.api.root / 'large.zip'
        data = b'x' * delivery.PART_SIZE + b'y' * 17
        source.write_bytes(data)
        desc = {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
        parts = delivery.stage_artifact(self.api.config, source, 'fixture-1', 'archive', desc)
        self.assertEqual([p['size'] for p in parts], [delivery.PART_SIZE, 17])
        self.assertEqual(len(delivery.asset_inventory(self.api.config)),2)
        api = delivery.Cloudflare.__new__(delivery.Cloudflare);api.config = self.api.config
        rows = [{'parts_json':json.dumps(parts)}]
        with patch.object(api,'query',return_value=rows):
            api.preflight_retention(delivery.asset_inventory(self.api.config))
            (root / parts[0]['path'].lstrip('/')).unlink()
            with self.assertRaises(delivery.DeliveryError):api.preflight_retention(delivery.asset_inventory(self.api.config))
        for name in ('_headers','_redirects','index.html','secret.json'):
            path = root / name;path.write_text('forbidden');path.chmod(0o600)
            with self.assertRaises(delivery.DeliveryError):delivery.asset_inventory(self.api.config)
            path.unlink()
        link = root / 'link';link.symlink_to(source)
        with self.assertRaises(delivery.DeliveryError):delivery.asset_inventory(self.api.config)
        link.unlink()

    def test_readback_failure_never_advances_channel_and_stable_cannot_replace_bytes(self):
        value = release()
        artifact = self.api.root / 'artifact.zip';artifact.write_bytes(b'test')
        with patch.object(self.api,'readback',side_effect=delivery.DeliveryError('Synthetic readback failure')):
            with self.assertRaises(delivery.DeliveryError):delivery.publish(self.api,value,receipt(value),artifact,artifact)
        self.assertEqual(self.api.query('SELECT * FROM channels'), [])
        self.assertEqual(len(self.api.query('SELECT * FROM releases')),1)
        delivery.publish(self.api,value,receipt(value),artifact,artifact)
        stable = dict(value, channel='stable',qualified=True);proof=receipt(stable);proof['checks']['private_upgrade']=True
        with self.assertRaises(delivery.DeliveryError):delivery.publish(self.api,stable,proof,artifact,artifact)

    def test_pinned_wrangler_auth_is_captured_without_argv_secrets(self):
        secret = 'fixture-owner-token'
        seen = []
        def fake(args, **kwargs):
            seen.append((args, kwargs))
            if args[-1] == '--version':
                return subprocess.CompletedProcess(args, 0, b'4.158.0\n', b'')
            return subprocess.CompletedProcess(args, 0, json.dumps({'type': 'oauth', 'token': secret}).encode(), b'')
        with patch.object(delivery, 'pinned_node', return_value='/fixture/node'), patch.object(delivery.subprocess, 'run', side_effect=fake):
            api = delivery.Cloudflare({'wrangler': '/fixture/wrangler.js'})
        self.assertEqual(api._authorization, 'Bearer ' + secret)
        for args, kwargs in seen:
            self.assertEqual(args[:2], ['/fixture/node', '/fixture/wrangler.js'])
            self.assertNotIn(secret, repr(args))
            self.assertEqual(kwargs['env']['WRANGLER_SEND_METRICS'], 'false')
            self.assertEqual(kwargs['env']['WRANGLER_WRITE_LOGS'], 'false')
            self.assertEqual(kwargs['env']['WRANGLER_LOG'], 'log')
            self.assertEqual(kwargs['env']['WRANGLER_LOG_SANITIZE'], 'true')
            self.assertEqual(kwargs['env']['WRANGLER_SEND_ERROR_REPORTS'], 'false')
            self.assertEqual(kwargs['env']['CLOUDFLARE_API_BASE_URL'], 'https://api.cloudflare.com/client/v4')
            self.assertNotIn('WRANGLER_OUTPUT_FILE_PATH', kwargs['env'])
            self.assertNotIn('WRANGLER_OUTPUT_FILE_DIRECTORY', kwargs['env'])
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        with patch.object(delivery.Cloudflare, 'wrangler', return_value='4.0.0'), self.assertRaises(delivery.DeliveryError):
            delivery.Cloudflare({'wrangler': '/fixture/wrangler.js'})

    def test_wrangler_runs_the_verified_node_despite_conflicting_path(self):
        root = Path(self.temp.name).resolve() if hasattr(self,'temp') else self.api.root
        launcher = root/'wrangler.js'
        launcher.write_text("process.stdout.write(process.argv.includes('--version') ? '4.158.0' : JSON.stringify({type:'oauth',token:'synthetic-token'}))")
        fake = root/'node'; fake.write_text('#!/bin/sh\nexit 99\n'); fake.chmod(0o700)
        binary = str(Path(node()).resolve())
        with patch.dict(os.environ, {'PATH':str(root), 'MONITOR_NODE':binary}):
            api = delivery.Cloudflare({'wrangler':str(launcher)})
        self.assertEqual(api.node,binary)
        self.assertEqual(api._authorization,'Bearer synthetic-token')


if __name__ == '__main__':
    unittest.main()
