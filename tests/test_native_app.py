"""Native window acceptance against a separately packaged synthetic-only service."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class NativeWindowTests(unittest.TestCase):
    def test_automatic_scan_repeat_reload_minimize_and_cleanup(self):
        app = Path(os.environ['MONITOR_TEST_APP'])
        self.assertTrue(app.name.endswith('.app'))
        with tempfile.TemporaryDirectory(prefix='monitor-window-evidence-') as temporary:
            path = Path(temporary) / 'native-app-validation.json'
            subprocess.run([str(app / 'Contents/MacOS/Machine Monitor'), '--verify', str(path)], check=True, timeout=75)
            result = json.loads(path.read_text())
            self.assertTrue(result['passed'])
            self.assertTrue(result['nativeWebView'])
            self.assertTrue(result['minimizeStopsScan'])
            self.assertTrue(result['restoreStaysDormant'])
            self.assertTrue(result['reloadStaysDormant'])
            self.assertGreaterEqual(result['completedScan']['count'], 25)
            self.assertFalse(result['completedScan']['startDisabled'])
            self.assertFalse(result['completedScan']['active'])
            from test_desktop_service import is_listening
            from urllib.parse import urlsplit
            self.assertFalse(is_listening(urlsplit(result['url']).port))
