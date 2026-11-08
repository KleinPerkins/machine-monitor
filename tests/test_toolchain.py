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
from unittest.mock import patch

from scripts import toolchain


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
