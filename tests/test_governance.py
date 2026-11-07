"""Public-source hygiene, complete shard coverage and fail-closed aggregation."""
import copy
import importlib
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts.shard_contract import IDS, MANIFEST, aggregate, contract

ROOT = Path(__file__).resolve().parents[1]


class ShardContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='monitor-contract-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / '.github').mkdir()
        self.value = json.loads((ROOT / MANIFEST).read_text())
        for shard in self.value['shards']:
            for name in shard['tests']:
                path = self.root / name
                path.parent.mkdir(exist_ok=True)
                path.touch()
        self.write()

    def write(self):
        (self.root / MANIFEST).write_text(json.dumps(self.value))

    def reject(self):
        self.write()
        with self.assertRaises(ValueError):
            contract(self.root)

    def reports(self, value):
        return [dict(schema='dev-test-shard-result/v1', shard=identity, revision='a' * 40,
                     contract_sha256=value['contract_sha256'], status='passed', tests=1) for identity in IDS]

    def test_repository_contract_has_complete_nonempty_membership(self):
        current = contract(ROOT)
        self.assertEqual(len(current['shards']), 6)
        self.assertEqual({item['id'] for item in current['shards']}, set(IDS))

    def test_new_unassigned_test_is_discovered(self):
        (self.root / 'tests/test_added.py').touch()
        self.reject()

    def test_nested_unassigned_test_is_discovered(self):
        nested = self.root / 'tests/nested/test_added.py'
        nested.parent.mkdir()
        nested.touch()
        self.reject()

    def test_duplicate_assignment_is_rejected(self):
        self.value['shards'][1]['tests'].append(self.value['shards'][0]['tests'][0])
        self.reject()

    def test_unknown_empty_or_missing_command_is_rejected(self):
        original = copy.deepcopy(self.value)
        for key, replacement in (('id', 'unknown'), ('tests', []), ('command', [])):
            self.value = copy.deepcopy(original)
            self.value['shards'][0][key] = replacement
            self.reject()

    def test_missing_manifest_does_not_pass(self):
        (self.root / MANIFEST).unlink()
        with self.assertRaises(FileNotFoundError):
            contract(self.root)

    def test_all_current_reports_succeed(self):
        value = contract(self.root)
        self.assertEqual(aggregate(value, self.reports(value), 'a' * 40)['status'], 'passed')

    def test_failed_cancelled_skipped_and_empty_results_reject(self):
        value = contract(self.root)
        for status in ('failed', 'cancelled', 'skipped', 'pending'):
            reports = self.reports(value)
            reports[0]['status'] = status
            with self.assertRaises(ValueError):
                aggregate(value, reports, 'a' * 40)
        for count in (0, -1, True, '1'):
            reports = self.reports(value)
            reports[0]['tests'] = count
            with self.assertRaises(ValueError):
                aggregate(value, reports, 'a' * 40)

    def test_missing_duplicate_unknown_and_stale_reports_reject(self):
        value = contract(self.root)
        reports = self.reports(value)
        cases = [reports[:-1], reports + [reports[0]], [reports[0]] * 6]
        for key, replacement in (('shard', 'unknown'), ('revision', 'b' * 40), ('contract_sha256', '0' * 64)):
            altered = copy.deepcopy(reports)
            altered[0][key] = replacement
            cases.append(altered)
        for case in cases:
            with self.assertRaises(ValueError):
                aggregate(value, case, 'a' * 40)


class RepositoryPolicy(unittest.TestCase):
    def test_workflow_has_complete_unfiltered_bounded_matrix(self):
        source = (ROOT / '.github/workflows/ci.yml').read_text()
        for identity in IDS:
            self.assertIn(identity, source)
        for literal in ('pull_request:', 'workflow_dispatch:', 'branches: [main]',
                        'max-parallel: 4', 'fail-fast: false', 'runs-on: macos-26',
                        'retention-days: 14', 'persist-credentials: false', 'contents: read',
                        'ci-required:', 'if: always()', 'needs: [verify]', '--job-result',
                        'if-no-files-found: error'):
            self.assertIn(literal, source)
        self.assertNotRegex(source, r'(?m)^\s*paths(-ignore)?:')
        self.assertNotIn('secrets.', source)
        self.assertNotIn('continue-on-error', source)
        for action in re.findall(r'uses:\s*(\S+)', source):
            self.assertRegex(action, r'^[\w./-]+@[0-9a-f]{40}$')

    def test_dependencies_are_exactly_pinned(self):
        for name in ('requirements.txt', 'requirements-dev.txt', 'requirements-build.txt'):
            for line in (ROOT / name).read_text().splitlines():
                if line and not line.startswith(('#', '-r ')):
                    self.assertRegex(line, r'^[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+$')

    def test_production_builder_cannot_select_fixture_entrypoint(self):
        source = (ROOT / 'build_mac_app.py').read_text()
        self.assertIn("run(*args, ROOT / 'monitor.py')", source)
        self.assertNotIn('fixture_service', source)
        self.assertNotIn('SyntheticCollector', (ROOT / 'monitor.py').read_text())

    def test_application_sources_have_no_personal_absolute_paths(self):
        names = ('monitor.py', 'temperatures.py', 'app.js', 'style.css', 'index.html', 'README.md',
                 'build_mac_app.py', 'start.sh', 'mac/MachineMonitor.swift', 'mac/MakeIcon.swift')
        for name in names:
            content = (ROOT / name).read_text()
            self.assertNotIn('/' + 'Users/', content, name)
            self.assertNotIn('.' + 'codex/', content, name)
        self.assertIn('Proprietary Source-Visible License', (ROOT / 'LICENSE').read_text())
        self.assertIn('THIRD-PARTY-NOTICES.md', (ROOT / 'LICENSE').read_text())

    def test_browser_tests_import_without_starting_resources(self):
        with patch('subprocess.Popen', side_effect=AssertionError('Import launched a process')), \
             patch('threading.Thread.start', side_effect=AssertionError('Import started a thread')):
            for path in ROOT.glob('test_*.py'):
                importlib.import_module(path.stem)


class VerificationLifecycle(unittest.TestCase):
    def test_interrupted_rerun_invalidates_previous_pass_before_dispatch(self):
        import subprocess
        from scripts.verify import run_shard
        value = contract(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            report = output / 'result-core.json'
            report.write_text(json.dumps({'status': 'passed', 'tests': 99}))
            def interrupted(*args, **kwargs):
                self.assertEqual(json.loads(report.read_text())['status'], 'running')
                invocation = json.loads((output / 'invocation-core.json').read_text())
                self.assertEqual(invocation['run_id'], 'fresh-invocation')
                raise subprocess.TimeoutExpired('synthetic-worker', .1)
            with patch('scripts.verify.run_owned', side_effect=interrupted):
                with self.assertRaises(subprocess.TimeoutExpired):
                    run_shard('core', output, value, 'a' * 40, 'fresh-invocation')
            self.assertEqual(json.loads(report.read_text())['status'], 'failed')
            self.assertEqual(json.loads(report.read_text())['tests'], 0)

    def test_same_revision_reports_from_other_invocation_are_rejected(self):
        from scripts.verify import evidence
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            path = output / 'invocation-core.json'
            path.write_text(json.dumps(dict(schema='machine-monitor/shard-invocation/v1', shard='core',
                run_id='old-run', revision='a' * 40, contract_sha256='b' * 64)))
            with self.assertRaises(ValueError):
                evidence(output, 'core', 'new-run', 'a' * 40, 'b' * 64)
            evidence(output, 'core', 'old-run', 'a' * 40, 'b' * 64)

    def test_timeout_stops_the_owned_child_group(self):
        import os
        import subprocess
        import sys
        import time
        import psutil
        from scripts.processes import run_owned
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / 'owned-child.pid'
            program = "import pathlib,subprocess,sys,time; p=subprocess.Popen(['/bin/sleep','30']); pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(30)"
            with self.assertRaises(subprocess.TimeoutExpired):
                run_owned([sys.executable, '-c', program, str(marker)], timeout=.5)
            self.assertTrue(marker.exists())
            pid = int(marker.read_text())
            deadline = time.monotonic() + 2
            def executing():
                try:
                    return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
                except psutil.NoSuchProcess:
                    return False
            while executing() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertFalse(executing(), 'Owned test child survived its supervisor timeout')

    def test_sigterm_of_supervisor_cleans_its_detached_worker(self):
        import os
        import signal
        import subprocess
        import sys
        import time
        import psutil
        from scripts.processes import send_group
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / 'worker.pid'
            worker = "import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)"
            supervisor = "import sys; from scripts.processes import run_owned; run_owned([sys.executable,'-c',sys.argv[1],sys.argv[2]],timeout=30)"
            process = subprocess.Popen([sys.executable, '-c', supervisor, worker, str(marker)],
                                       cwd=ROOT, start_new_session=True)
            pid = None
            try:
                deadline = time.monotonic() + 3
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(marker.exists())
                pid = int(marker.read_text())
                process.terminate()
                self.assertEqual(process.wait(timeout=9), 143)
                try:
                    self.assertEqual(psutil.Process(pid).status(), psutil.STATUS_ZOMBIE)
                except psutil.NoSuchProcess:
                    pass
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=9)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                if pid is None and marker.exists():
                    pid = int(marker.read_text())
                if pid is not None:
                    send_group(pid, signal.SIGKILL)


    def test_cancellation_during_cleanup_is_not_discarded(self):
        import subprocess
        import sys
        program = """import os,signal,sys,threading
from scripts.processes import run_owned
threading.Timer(.6,lambda:os.kill(os.getpid(),signal.SIGTERM)).start()
run_owned([sys.executable,'-c',"import subprocess,time; subprocess.Popen(['/bin/sleep','30']); time.sleep(.15)"],timeout=5)
"""
        result = subprocess.run([sys.executable, '-c', program], cwd=ROOT, timeout=9)
        self.assertEqual(result.returncode, 143)
