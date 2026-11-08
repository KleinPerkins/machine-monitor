"""Refuse unpinned or corrupted verification runtimes before executing them."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
import ssl
import urllib.error
from unittest.mock import call, patch

from scripts import sparkle, toolchain, workflow_lint


class DownloadRetryTests(unittest.TestCase):
    url = 'https://example.invalid/pinned-archive'

    def test_gateway_failures_retry_original_request_and_close_responses(self):
        bodies = [io.BytesIO(b'gateway'), io.BytesIO(b'gateway'), io.BytesIO(b'archive')]
        failures = [urllib.error.HTTPError(self.url, code, 'gateway', {}, body)
                    for code, body in zip((503, 504), bodies)]
        with patch.object(toolchain.urllib.request, 'urlopen', side_effect=[*failures, bodies[2]]) as open_url, \
             patch.object(toolchain.time, 'sleep') as sleep:
            self.assertEqual(toolchain.download_bytes(self.url, 100, 30), b'archive')
        self.assertEqual(open_url.call_args_list, [call(self.url, timeout=30)] * 3)
        self.assertEqual(sleep.call_args_list, [call(1), call(3)])
        self.assertTrue(all(body.closed for body in bodies))

    def test_transient_failures_stop_after_three_attempts(self):
        failure = urllib.error.HTTPError(self.url, 504, 'gateway', {}, io.BytesIO())
        with patch.object(toolchain.urllib.request, 'urlopen', side_effect=failure) as open_url, \
             patch.object(toolchain.time, 'sleep') as sleep:
            with self.assertRaises(urllib.error.HTTPError) as raised:
                toolchain.download_bytes(self.url, 100, 30)
        self.assertIs(raised.exception, failure)
        self.assertEqual(open_url.call_count, 3)
        self.assertEqual(sleep.call_args_list, [call(1), call(3)])

    def test_permanent_http_and_tls_failures_do_not_retry(self):
        failures = [urllib.error.HTTPError(self.url, code, 'permanent', {}, io.BytesIO())
                    for code in (401, 403, 404, 429)]
        failures.append(urllib.error.URLError(ssl.SSLCertVerificationError('untrusted')))
        for failure in failures:
            with self.subTest(failure=type(failure).__name__, code=getattr(failure, 'code', None)), \
                 patch.object(toolchain.urllib.request, 'urlopen', side_effect=failure) as open_url, \
                 patch.object(toolchain.time, 'sleep') as sleep:
                with self.assertRaises(type(failure)) as raised:
                    toolchain.download_bytes(self.url, 100, 30)
                self.assertIs(raised.exception, failure)
                open_url.assert_called_once_with(self.url, timeout=30)
                sleep.assert_not_called()

    def test_read_timeout_discards_partial_body_and_closes_it(self):
        class InterruptedBody(io.BytesIO):
            def read(self, maximum):
                super().read(3)
                raise TimeoutError('interrupted body')
        partial = InterruptedBody(b'partial')
        complete = io.BytesIO(b'complete')
        with patch.object(toolchain.urllib.request, 'urlopen', side_effect=[partial, complete]) as open_url, \
             patch.object(toolchain.time, 'sleep') as sleep:
            self.assertEqual(toolchain.download_bytes(self.url, 100, 30), b'complete')
        self.assertTrue(partial.closed and complete.closed)
        self.assertEqual(open_url.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_connection_timeout_retries_but_successful_content_stays_bounded(self):
        failure = urllib.error.URLError(TimeoutError('connect timeout'))
        with patch.object(toolchain.urllib.request, 'urlopen', side_effect=[failure, io.BytesIO(b'oversized')]) as open_url, \
             patch.object(toolchain.time, 'sleep') as sleep:
            self.assertEqual(toolchain.download_bytes(self.url, 3, 30), b'over')
        self.assertEqual(open_url.call_count, 2)
        sleep.assert_called_once_with(1)


class DownloadConsumerTests(unittest.TestCase):
    @staticmethod
    def archive(files, mode):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode=mode) as archive:
            for name, payload in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        return output.getvalue()

    def test_actionlint_recovers_gateway_error_and_cleans_verified_binary(self):
        payload = self.archive({'actionlint': b'synthetic-validator'}, 'w:gz')
        failure = urllib.error.HTTPError('https://example.invalid', 504, 'gateway', {}, io.BytesIO())
        executed = []
        def inspect_run(args, **kwargs):
            binary = Path(args[0])
            self.assertEqual(binary.read_bytes(), b'synthetic-validator')
            self.assertEqual(binary.stat().st_mode & 0o777, 0o700)
            executed.append(binary)
            return subprocess.CompletedProcess(args, 0)
        with tempfile.TemporaryDirectory(prefix='monitor-actionlint-fixture-') as temporary:
            root = Path(temporary)
            (root / '.github/workflows').mkdir(parents=True)
            (root / '.github/workflows/ci.yml').write_text('name: fixture\n')
            with patch.object(workflow_lint.platform, 'system', return_value='Darwin'), \
                 patch.object(workflow_lint.platform, 'machine', return_value='arm64'), \
                 patch.dict(workflow_lint.ASSETS, {('Darwin', 'arm64'): ('darwin_arm64', hashlib.sha256(payload).hexdigest())}), \
                 patch.object(toolchain.urllib.request, 'urlopen', side_effect=[failure, io.BytesIO(payload)]) as open_url, \
                 patch('time.sleep') as sleep, \
                 patch.object(workflow_lint.subprocess, 'run', side_effect=inspect_run) as run:
                workflow_lint.lint(root)
                self.assertEqual(open_url.call_count, 2)
                sleep.assert_called_once_with(1)
                run.assert_called_once()
        self.assertEqual(len(executed), 1)
        self.assertFalse(executed[0].exists())

    def test_sparkle_recovers_gateway_error_and_records_verified_bytes(self):
        payload = self.archive({'Sparkle.framework/Versions/A/Sparkle': b'synthetic-framework',
                                'bin/sign_update': b'synthetic-sign-tool', 'LICENSE': b'fixture license'}, 'w:xz')
        digest = hashlib.sha256(payload).hexdigest()
        failure = urllib.error.HTTPError(sparkle.URL, 504, 'gateway', {}, io.BytesIO())
        with tempfile.TemporaryDirectory(prefix='monitor-sparkle-fixture-') as temporary, \
             patch.object(sparkle, 'SHA256', digest), \
             patch.object(toolchain.urllib.request, 'urlopen', side_effect=[failure, io.BytesIO(payload)]) as open_url, \
             patch('time.sleep') as sleep:
            result = sparkle.distribution(Path(temporary))
            self.assertEqual((result / 'Sparkle.framework/Versions/A/Sparkle').read_bytes(), b'synthetic-framework')
            receipt = json.loads((result / 'verified.json').read_text())
            self.assertEqual(receipt['archive_sha256'], digest)
            self.assertIn('bin/sign_update', receipt['files'])
            self.assertEqual(open_url.call_count, 2)
            sleep.assert_called_once_with(1)
        self.assertFalse(result.exists())


class PinnedNodeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='monitor-toolchain-fixture-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.environment = patch.dict(os.environ)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        os.environ.pop('MONITOR_NODE', None)

    def test_explicit_runtime_wrong_version_never_falls_back_to_download(self):
        os.environ['MONITOR_NODE'] = str(self.root / 'node')
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'v1.0.0\n', '')), \
             patch.object(toolchain.urllib.request, 'urlopen', side_effect=AssertionError('Unexpected download')):
            with self.assertRaisesRegex(ValueError, '26.4.0'):
                toolchain.node(self.root / 'cache')

    def test_download_checksum_failure_never_extracts_or_runs_bytes(self):
        with patch.object(toolchain.shutil, 'which', return_value=None), \
             patch.object(toolchain.platform, 'system', return_value='Darwin'), \
             patch.object(toolchain.platform, 'machine', return_value='arm64'), \
             patch.object(toolchain.urllib.request, 'urlopen', return_value=io.BytesIO(b'corrupt archive')), \
             patch.object(toolchain.tarfile, 'open', side_effect=AssertionError('Unverified archive extracted')), \
             patch.object(toolchain, '_version', side_effect=AssertionError('Unverified binary executed')):
            with self.assertRaisesRegex(ValueError, 'checksum'):
                toolchain.node(self.root / 'cache')

    def test_changed_cached_binary_is_not_executed(self):
        cache = self.root / 'cache'
        target = cache / ('node-v' + toolchain.NODE_VERSION)
        (target / 'bin').mkdir(parents=True)
        (target / 'bin/node').write_bytes(b'changed')
        (target / 'verified.json').write_text(json.dumps({
            'archive_sha256': toolchain.NODE_SHA256,
            'binary_sha256': hashlib.sha256(b'original').hexdigest(),
        }))
        with patch.object(toolchain.shutil, 'which', return_value=None), \
             patch.object(toolchain.urllib.request, 'urlopen', side_effect=AssertionError('Unexpected repair')), \
             patch.object(toolchain, '_version', side_effect=AssertionError('Changed binary executed')):
            with self.assertRaisesRegex(ValueError, 'changed'):
                toolchain.node(cache)

    def test_archive_traversal_is_rejected_before_extraction(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w:xz') as output:
            member = tarfile.TarInfo('../escape')
            member.size = 1
            output.addfile(member, io.BytesIO(b'x'))
        payload = archive.getvalue()
        with patch.object(toolchain.shutil, 'which', return_value=None), \
             patch.object(toolchain.platform, 'system', return_value='Darwin'), \
             patch.object(toolchain.platform, 'machine', return_value='arm64'), \
             patch.object(toolchain, 'NODE_SHA256', hashlib.sha256(payload).hexdigest()), \
             patch.object(toolchain.urllib.request, 'urlopen', return_value=io.BytesIO(payload)), \
             patch.object(toolchain, '_version', side_effect=AssertionError('Unsafe binary executed')):
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                toolchain.node(self.root / 'cache')
        self.assertFalse((self.root / 'escape').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
