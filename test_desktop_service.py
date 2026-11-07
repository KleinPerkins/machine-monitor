"""Acceptance checks for the shipped service and native-parent lifetime contract."""
import http.cookiejar
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import tempfile
import unittest
import urllib.request
import psutil

ROOT = Path(__file__).resolve().parent
SERVICE = Path(os.environ['MONITOR_TEST_SERVICE']) if os.environ.get('MONITOR_TEST_SERVICE') else None

def ready(proc):
    if not select.select([proc.stdout], [], [], 12)[0]:
        raise AssertionError('Service did not report ready')
    line = proc.stdout.readline().decode()
    if not line.startswith('MACHINE_MONITOR_READY '):
        raise AssertionError(f'Invalid ready line: {line}')
    return json.loads(line.split(' ', 1)[1])

def client(port):
    base = f'http://127.0.0.1:{port}'
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    with opener.open(base + '/', timeout=3) as response:
        assert b'Machine Monitor' in response.read()
    def request(path, body=None):
        req = urllib.request.Request(base + '/api/' + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Content-Type':'application/json', 'Origin':base, 'X-Monitor':'1'})
        with opener.open(req, timeout=3) as response: return json.load(response)
    return request

def is_listening(port):
    import socket
    with socket.socket() as sock:
        sock.settimeout(.2)
        return sock.connect_ex(('127.0.0.1',port)) == 0

class DesktopServiceTests(unittest.TestCase):
    def launch(self):
        self.assertIsNotNone(SERVICE, 'Use the native-app shard with its isolated fixture bundle')
        proc = subprocess.Popen([str(SERVICE), '--port', '0', '--desktop', '--parent-pid', str(os.getpid())],
            cwd='/private/tmp', env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=4)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
            proc.stdout.close(); proc.stderr.close()
        self.addCleanup(cleanup)
        info = ready(proc)
        self.assertEqual(info['pid'], proc.pid)
        return proc, info, client(info['port'])

    def test_self_contained_dormant_snapshot_and_sigterm(self):
        proc, info, api = self.launch()
        self.assertEqual(api('state')['collections'],0)
        scan = api('start',{'duration':1.5})['scan']
        time.sleep(1)
        api('tick',{'scan':scan})
        time.sleep(.7)
        state = api('state')
        self.assertFalse(state['active'])
        self.assertGreaterEqual(state['count'],1)
        frame = state['frames'][-1]
        self.assertTrue(frame['fixture'], 'Native CI must use synthetic telemetry')
        self.assertGreater(len(frame['temperatures']['cpu_sensors']),0)
        self.assertIsNotNone(frame['memory']['total'])
        proc.terminate(); self.assertEqual(proc.wait(timeout=4),0)
        self.assertFalse(is_listening(info['port']))

    def test_forced_parent_exit_stops_active_service(self):
        wrapper = '''import json,os,subprocess,sys,time
p=subprocess.Popen([sys.argv[1],'--port','0','--desktop','--parent-pid',str(os.getpid())],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'},cwd='/private/tmp')
print(p.stdout.readline().decode().strip(),flush=True)
sys.stdin.read()
'''
        parent = subprocess.Popen([sys.executable,'-c',wrapper,str(SERVICE)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        info = None
        try:
            info = ready(parent)
            api = client(info['port'])
            api('start',{'duration':30})
            parent.kill(); parent.wait(timeout=3)
            deadline=time.monotonic()+4
            while is_listening(info['port']) and time.monotonic()<deadline: time.sleep(.05)
            self.assertFalse(is_listening(info['port']),'Service outlived its forcibly killed parent')
        finally:
            if parent.poll() is None: parent.kill(); parent.wait()
            for stream in (parent.stdin,parent.stdout,parent.stderr): stream.close()
            if info and is_listening(info['port']): os.kill(info['pid'],15)

    def test_rejects_unrelated_lifetime_owner(self):
        result = subprocess.run([str(SERVICE),'--port','0','--desktop','--parent-pid','1'],
            env={'PATH':'/usr/bin:/bin'},capture_output=True,timeout=10)
        self.assertEqual(result.returncode,2)
        self.assertIn(b'launching parent',result.stderr)

    def test_shutdown_joins_collector_child_cleanup(self):
        # Deliberately slower cleanup than serve_forever's poll boundary makes
        # this fail without the shutdown join, rather than relying on timing luck.
        wrapper='''import pathlib,subprocess,sys,time
sys.path.insert(0,sys.argv.pop(1))
marker=pathlib.Path(sys.argv.pop(1))
import monitor
class CleanupCollector:
 def sample(self):
  with subprocess.Popen(['/bin/sleep','30']) as child:
   marker.write_text(str(child.pid))
   self.cancel.wait(10)
   time.sleep(.65)
   child.terminate();child.wait()
   raise InterruptedError('Stopped')
Engine=monitor.Engine
monitor.Engine=lambda:Engine(factory=CleanupCollector)
monitor.main()
'''
        with tempfile.TemporaryDirectory(prefix='monitor-cleanup-fixture-') as temp:
            marker=Path(temp)/'child.pid'
            proc=subprocess.Popen([sys.executable,'-c',wrapper,str(ROOT),str(marker),
                '--port','0','--desktop','--parent-pid',str(os.getpid())],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            child=None
            try:
                info=ready(proc);api=client(info['port']);api('start',{'duration':30})
                deadline=time.monotonic()+2
                while not marker.exists() and time.monotonic()<deadline: time.sleep(.01)
                self.assertTrue(marker.exists())
                child=psutil.Process(int(marker.read_text()))
                proc.terminate();self.assertEqual(proc.wait(timeout=4),0)
                self.assertFalse(child.is_running(),'Collector subprocess survived interpreter teardown')
            finally:
                if proc.poll() is None: proc.kill();proc.wait()
                if child is not None and child.is_running(): child.kill()
                proc.stdout.close();proc.stderr.close()

if __name__ == '__main__': unittest.main(verbosity=2)
