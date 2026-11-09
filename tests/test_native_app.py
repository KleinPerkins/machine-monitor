"""Native window acceptance against a separately packaged synthetic-only service."""
import json
import fcntl
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class NativeWindowTests(unittest.TestCase):
    def test_frozen_prepare_inherits_exact_operation_ownership_before_trust_validation(self):
        from tests.update_fixtures import app, manifest
        service = os.environ['MONITOR_TEST_SERVICE']
        with tempfile.TemporaryDirectory(prefix='monitor-frozen-ownership-') as temporary:
            root = Path(temporary).resolve()
            home = root/'home'; home.mkdir(mode=0o700)
            target = app(root/'Monitor.app')
            candidate = app(root/'Candidate.app',2)
            state = home/'Library/Application Support/Machine Monitor/Updates'/hashlib.sha256(str(target).encode()).hexdigest()
            state.mkdir(parents=True,mode=0o700)
            # Every private component is owned by this isolated fixture HOME.
            for directory in (home/'Library',home/'Library/Application Support',home/'Library/Application Support/Machine Monitor',state.parent,state):
                directory.chmod(0o700)
            lock=state/'operation.lock'
            fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                launch=fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,4)
                try:
                    request={'action':'prepare','target_path':str(target),'candidate_path':str(candidate),
                             'manifest':manifest(),'expanded_size':1,'operation_lock_fd':3}
                    result=subprocess.run(['/bin/sh','-c','exec 3>&2 2>/dev/null; exec "$1" --update-recovery','monitor-update-helper',service],
                        input=json.dumps(request).encode(),stdout=subprocess.PIPE,stderr=launch,env=dict(os.environ,HOME=str(home)),timeout=20)
                finally:os.close(launch)
                response=json.loads(result.stdout)
                self.assertEqual(result.returncode,1)
                self.assertFalse(response['ok'])
                # Reaching Apple validation proves the actual frozen helper consumed
                # fd 3; synthetic unsigned code must still fail real trust checks.
                self.assertEqual(response['error'],'Apple code or platform validation failed')
                contender=os.open(lock,os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(contender)
                self.assertEqual(lock.read_bytes(),b'')
                self.assertFalse((state/'journal.json').exists())
            finally:os.close(fd)

    def test_automatic_scan_repeat_reload_minimize_and_cleanup(self):
        app = Path(os.environ['MONITOR_TEST_APP'])
        self.assertTrue(app.name.endswith('.app'))
        with tempfile.TemporaryDirectory(prefix='monitor-window-evidence-') as temporary:
            path = Path(temporary) / 'native-app-validation.json'
            subprocess.run([str(app / 'Contents/MacOS/Machine Monitor'), '--verify', str(path)], check=True, timeout=75)
            result = json.loads(path.read_text())
            self.assertTrue(result['passed'], json.dumps(result, sort_keys=True))
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
