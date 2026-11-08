"""HTTP/session and lifecycle contracts using only synthetic telemetry."""
import http.client
import json
import threading
import time
import unittest
import uuid
from unittest.mock import patch

import monitor
from tests.fixtures import SyntheticCollector


class FixtureServiceTests(unittest.TestCase):
    def setUp(self):
        self.guard = patch.object(monitor.Collector, '__init__', side_effect=AssertionError('Live collection forbidden'))
        self.guard.start()
        self.addCleanup(self.guard.stop)
        self.server = monitor.LoopbackHTTPServer(('127.0.0.1', 0), monitor.Handler)
        self.server.token = 'synthetic-session-token'
        self.server.engine = monitor.Engine(factory=SyntheticCollector)
        self.server.desktop = True
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .02})
        self.thread.start()
        self.addCleanup(self.close)
        self.base = f'http://127.0.0.1:{self.server.server_port}'

    def close(self):
        self.server.engine.stop()
        worker = self.server.engine.worker
        if worker is not None:
            worker.join(2)
            self.assertFalse(worker.is_alive())
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.assertFalse(self.thread.is_alive())

    def request(self, path, body=None, headers=None, authorized=True):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        defaults = {}
        if authorized:
            defaults = {'Cookie': 'monitor=' + self.server.token,
                        'Origin': self.base, 'X-Monitor': '1'}
        defaults.update(headers or {})
        try:
            data = json.dumps(body).encode() if body is not None else None
            connection.request('POST' if body is not None else 'GET', path, data, defaults)
            response = connection.getresponse()
            content = response.read()
            return response.status, dict(response.getheaders()), content
        finally:
            connection.close()

    def api(self, path, body=None):
        status, _, data = self.request('/api/' + path, body)
        self.assertEqual(status, 200, data)
        return json.loads(data)

    def test_loopback_binding_never_calls_reverse_dns(self):
        with patch('socket.getfqdn', side_effect=AssertionError('Reverse DNS forbidden')):
            server = monitor.LoopbackHTTPServer(('127.0.0.1', 0), monitor.Handler)
        self.addCleanup(server.server_close)
        self.assertEqual(server.server_name, '127.0.0.1')
        self.assertGreater(server.server_port, 0)

    def test_telemetry_requires_exact_session_cookie(self):
        self.assertEqual(self.request('/api/state', authorized=False)[0], 403)
        self.assertEqual(self.request('/api/state', headers={'Cookie': 'monitor=wrong'})[0], 403)
        self.assertEqual(self.request('/api/state', headers={'Cookie': 'prefixmonitor=' + self.server.token})[0], 403)
        self.assertFalse(self.api('state')['active'])
        self.assertEqual(self.api('state')['collections'], 0)

    def test_mutations_require_origin_and_custom_header(self):
        for headers in ({'Origin': 'https://example.invalid'}, {'X-Monitor': ''}):
            self.assertEqual(self.request('/api/start', {'duration': 30}, headers)[0], 403)
        self.assertFalse(self.server.engine.active)

    def test_host_and_asset_allowlist(self):
        self.assertEqual(self.request('/', headers={'Host': 'example.invalid'})[0], 403)
        self.assertEqual(self.request('/monitor.py')[0], 404)
        self.assertEqual(self.request('/../monitor.py')[0], 404)
        status, headers, body = self.request('/', authorized=False)
        self.assertEqual(status, 200)
        self.assertIn(b'Machine Monitor', body)
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', headers['Set-Cookie'])
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])

    def test_snapshot_completes_and_allows_new_scan(self):
        first = self.api('start', {'duration': 1.5})['scan']
        time.sleep(1.6)
        state = self.api('state')
        self.assertFalse(state['active'])
        self.assertEqual(state['reason'], 'Scan complete')
        self.assertGreater(state['count'], 0)
        self.assertTrue(all(frame['fixture'] for frame in state['frames']))
        second = self.api('start', {'duration': 30})['scan']
        self.assertNotEqual(first, second)
        self.api('stop', {'scan': second})

    def test_old_scan_cannot_stop_or_renew_new_scan(self):
        old = self.api('start', {'duration': 30})['scan']
        self.api('stop', {'scan': old})
        self.server.engine.worker.join(2)
        current = self.api('start', {'duration': 30})['scan']
        lease = self.server.engine.lease
        self.api('tick', {'scan': old})
        self.assertEqual(self.server.engine.lease, lease)
        self.assertTrue(self.api('stop', {'scan': old})['active'])
        self.api('stop', {'scan': current})

    def test_visibility_lease_expires_without_polling(self):
        self.api('start', {'duration': 30})
        self.server.engine.worker.join(4)
        self.assertFalse(self.server.engine.worker.is_alive())
        self.assertFalse(self.api('state')['active'])
        self.assertEqual(self.api('state')['reason'], 'Visibility lease expired')

    def test_deadline_is_immutable_and_late_renewal_cannot_revive(self):
        now = [100.0]
        self.server.engine.clock = lambda: now[0]
        scan = self.api('start', {'duration': 30})['scan']
        deadline = self.server.engine.deadline
        for value in range(101, 131):
            now[0] = value
            state = self.api('tick', {'scan': scan})
            self.assertEqual(self.server.engine.deadline, deadline)
        self.assertFalse(state['active'])
        self.assertFalse(self.api('tick', {'scan': scan})['active'])

    def test_invalid_duration_and_thresholds_do_not_start_collection(self):
        for body in ({'duration': 0}, {'duration': 300},
                     {'duration': 30, 'config': {'cpu_warn': 101}},
                     {'duration': 30, 'config': {'unknown': 1}}):
            self.assertEqual(self.request('/api/start', body)[0], 400)
        self.assertEqual(self.server.engine.collections, 0)
        self.assertFalse(self.server.engine.active)

    def test_install_admission_is_desktop_and_session_protected(self):
        transaction = str(uuid.uuid4())
        self.assertEqual(self.request('/api/install-admit', {'transaction': transaction}, authorized=False)[0], 403)
        self.server.desktop = False
        self.assertEqual(self.request('/api/install-admit', {'transaction': transaction})[0], 404)
        self.assertFalse(self.api('state')['installing'])
        self.server.desktop = True
        for value in (None, 1, '', 'not-a-uuid'):
            self.assertEqual(self.request('/api/install-admit', {'transaction': value})[0], 400)

    def test_install_lease_is_idempotent_private_and_does_not_expire(self):
        transaction = str(uuid.uuid4())
        admitted = self.api('install-admit', {'transaction': transaction})
        self.assertTrue(admitted['installing'])
        token = admitted['install_lease']
        self.assertEqual(self.api('install-admit', {'transaction': transaction})['install_lease'], token)
        self.assertEqual(self.request('/api/install-admit', {'transaction': str(uuid.uuid4())})[0], 409)
        self.assertNotIn('install_lease', self.api('state'))
        self.assertNotIn(token, json.dumps(self.api('state')))
        self.server.engine.clock = lambda: 10**12
        self.assertTrue(self.api('state')['installing'])
        self.api('stop', {})
        self.assertTrue(self.api('state')['installing'])
        for wrong in (None, '', 'wrong-lease'):
            self.assertEqual(self.request('/api/install-release', {'install_lease': wrong})[0], 409)
        self.api('install-release', {'install_lease': token})
        self.assertFalse(self.api('state')['installing'])
        newer = self.api('install-admit', {'transaction': str(uuid.uuid4())})
        self.assertNotEqual(newer['install_lease'], token)
        self.assertEqual(self.request('/api/install-release', {'install_lease': token})[0], 409)
        self.assertTrue(self.api('state')['installing'])

    def test_active_scan_and_stopping_collector_prevent_install_admission(self):
        self.api('start', {'duration': 30})
        self.assertEqual(self.request('/api/install-admit', {'transaction': str(uuid.uuid4())})[0], 409)
        self.api('stop', {})
        self.server.engine.worker.join(2)
        self.assertFalse(self.server.engine.worker.is_alive())
        with patch.object(self.server.engine.worker, 'is_alive', return_value=True):
            self.assertEqual(self.request('/api/install-admit', {'transaction': str(uuid.uuid4())})[0], 409)
        admitted = self.api('install-admit', {'transaction': str(uuid.uuid4())})
        for duration in (1.5, 30, 60):
            self.assertEqual(self.request('/api/start', {'duration': duration})[0], 423)
        self.assertFalse(self.api('state')['active'])
        self.api('install-release', {'install_lease': admitted['install_lease']})
        self.assertTrue(self.api('start', {'duration': 30})['active'])

    def test_scan_start_and_install_admission_have_one_atomic_winner(self):
        for _ in range(30):
            engine = monitor.Engine(factory=SyntheticCollector)
            gate = threading.Barrier(3)
            results = []
            def start():
                gate.wait()
                try:
                    engine.start(30)
                    results.append('scan')
                except ValueError:
                    pass
            def install():
                gate.wait()
                try:
                    engine.admit_install(str(uuid.uuid4()))
                    results.append('install')
                except ValueError:
                    pass
            threads = [threading.Thread(target=start), threading.Thread(target=install)]
            try:
                for thread in threads:
                    thread.start()
                gate.wait(timeout=2)
                for thread in threads:
                    thread.join(2)
                    self.assertFalse(thread.is_alive())
                self.assertEqual(len(results), 1, results)
                self.assertFalse(engine.active and engine.install_token is not None)
            finally:
                engine.stop()
                if engine.worker is not None:
                    engine.worker.join(2)
                    self.assertFalse(engine.worker.is_alive())


if __name__ == '__main__':
    unittest.main(verbosity=2)
