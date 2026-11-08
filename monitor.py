#!/usr/bin/env python3
"""Local, bounded, on-demand macOS monitoring. No privileged helpers."""
from __future__ import annotations
import argparse
import ctypes
import json
import math
import os
from pathlib import Path
import plistlib
import secrets
import select
import signal
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer
from urllib.parse import urlsplit
import psutil
from temperatures import SMCTemperatures, summarize as unavailable_temperatures

ROOT = Path(__file__).resolve().parent
GIB = 1024 ** 3
DEFAULTS = dict(disk_warn_pct=10, disk_critical_pct=5, disk_warn_gib=20,
                disk_critical_gib=10, cpu_warn=90, persistence_s=5, recovery_s=3)

def run(args, cancel=None):
    if cancel and cancel.is_set(): raise InterruptedError('Scan stopped')
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
        deadline=time.monotonic()+.6
        while True:
            if (cancel and cancel.is_set()) or time.monotonic()>deadline:
                proc.kill(); proc.communicate()
                if cancel and cancel.is_set(): raise InterruptedError('Scan stopped')
                raise subprocess.TimeoutExpired(args,.6)
            try:
                out,_=proc.communicate(timeout=.02)
                if proc.returncode: raise subprocess.CalledProcessError(proc.returncode,args)
                return out
            except subprocess.TimeoutExpired: pass

def sysint(name):
    libc = ctypes.CDLL(None, use_errno=True)
    value = ctypes.c_int(); size = ctypes.c_size_t(ctypes.sizeof(value))
    if libc.sysctlbyname(name.encode(), ctypes.byref(value), ctypes.byref(size), None, 0):
        raise OSError(ctypes.get_errno(), name)
    return value.value

class Native:
    def __init__(self):
        self.info = None
        try:
            ctypes.CDLL('/System/Library/Frameworks/Foundation.framework/Foundation')
            self.objc = ctypes.CDLL('/usr/lib/libobjc.A.dylib')
            self.objc.objc_getClass.restype = ctypes.c_void_p
            self.objc.sel_registerName.restype = ctypes.c_void_p
            ptr = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(('objc_msgSend', self.objc))
            self.value = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p)(('objc_msgSend', self.objc))
            self.info = ptr(self.objc.objc_getClass(b'NSProcessInfo'), self.objc.sel_registerName(b'processInfo'))
        except (OSError, AttributeError):
            pass

    def get(self, selector):
        return self.value(self.info, self.objc.sel_registerName(selector.encode())) if self.info else None

def cpu_delta(previous, current):
    if previous is None:
        return None
    delta = {k: max(0, current[k] - previous[k]) for k in current}
    total = sum(delta.values())
    if total <= 0:
        return None
    return {k: v / total * 100 for k, v in delta.items()}

def rate(now, before, seconds):
    return max(0, now - before) / seconds if before is not None and seconds > 0 else None

def rollup_processes(processes, baselines=None, observed_at=0):
    """Partition observed processes into disjoint parent trees, stopping at PID 0/1.

    Unreadable/missing parents stay separate; names never establish ownership.
    Start times guard against a reused parent PID. Malformed cycles are bounded.
    """
    by_id={p['id']:p for p in processes}
    by_pid={p['pid']:p for p in processes}
    parents={}; missing=set()
    for p in processes:
        parent=by_pid.get(p.get('ppid'))
        valid=(p.get('ppid') not in (None,0,1) and parent is not None and
               parent['id']!=p['id'] and parent.get('started',0)<=p.get('started',0))
        parents[p['id']]=parent['id'] if valid else None
        if not valid and p.get('ppid') not in (None,0,1): missing.add(p['id'])
    roots={}; cycles=set()
    for ident in by_id:
        path=[]; seen={}; current=ident
        while current is not None and current not in roots and current not in seen:
            seen[current]=len(path); path.append(current); current=parents[current]
        if current in roots: root=roots[current]
        elif current in seen:
            cycle=path[seen[current]:]; root=min(cycle,key=lambda k:(by_id[k]['pid'],k)); cycles.add(root)
        else: root=path[-1]
        for item in path: roots[item]=root
    trees={}
    for ident,root in roots.items(): trees.setdefault(root,[]).append(by_id[ident])
    result=[]
    for root,members in trees.items():
        parent=by_id[root]; rss=sum(p['rss'] for p in members)
        known=[p['cpu'] for p in members if p['cpu'] is not None]
        member_ids=frozenset(p['id'] for p in members)
        previous=baselines.get(root) if baselines is not None else None
        if baselines is not None and previous is None:
            baselines[root]=(rss,observed_at,member_ids)
        hierarchy=[]
        for p in members:
            depth=0; cursor=p['id']; visited=set()
            while cursor!=root and parents.get(cursor) is not None and cursor not in visited:
                visited.add(cursor); cursor=parents[cursor]; depth+=1
            hierarchy.append(dict(id=p['id'],depth=depth))
        result.append(dict(id='group:'+root,pid=parent['pid'],name=parent['name'],rss=rss,
            cpu=sum(known) if known else None,cpu_partial=bool(known) and len(known)<len(members),
            memory_pct=sum(p['memory_pct'] for p in members),threads=sum(p['threads'] for p in members),
            growth=rss-previous[0] if previous else None,observed_s=observed_at-previous[1] if previous else 0,
            membership_changed=bool(previous and member_ids!=previous[2]),count=len(members),
            parent_missing=root in missing or root in cycles,members=sorted(hierarchy,key=lambda m:(m['depth'],by_id[m['id']]['pid']))))
    return result

class Collector:
    def __init__(self):
        self.native = Native()
        self.previous = None
        self.baselines = {}
        self.group_baselines = {}
        self.slow = {}
        self.slow_time = 0
        self.started = time.monotonic()
        self.self_proc = psutil.Process()
        self.cancel = None
        self.temperature_reader = None

    def sample(self):
        began = time.monotonic()
        cpu_time = psutil.cpu_times()._asdict()
        cores = [c._asdict() for c in psutil.cpu_times(percpu=True)]
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        io = psutil.disk_io_counters()
        net = psutil.net_io_counters()
        errors = []
        dt = began - self.previous['mono'] if self.previous else 0
        cpu = cpu_delta(self.previous['cpu'] if self.previous else None, cpu_time)
        pressure = None
        try:
            pressure = {1:'Normal', 2:'Warning', 4:'Critical'}.get(sysint('kern.memorystatus_vm_pressure_level'), 'Unknown')
        except OSError:
            errors.append('Native memory pressure unavailable')
        vm = {}
        try:
            import re
            raw = run(['/usr/bin/vm_stat'],self.cancel).decode()
            page_size = int(re.search(r'page size of (\d+)', raw)[1])
            for line in raw.splitlines()[1:]:
                if ':' in line:
                    k,v = line.split(':',1)
                    vm[k.strip('" ')] = int(v.strip().rstrip('.')) * page_size
        except (subprocess.SubprocessError, ValueError, TypeError):
            errors.append('Compression/swap activity unavailable')
        processes = {}
        denied = 0
        psutil.process_iter.cache_clear()  # Re-read start time; never conflate reused PIDs.
        for proc in psutil.process_iter():
            if self.cancel and self.cancel.is_set(): raise InterruptedError('Scan stopped')
            try:
                with proc.oneshot():
                    started = proc.create_time()
                    ident = f'{proc.pid}:{started}'
                    ppid = proc.ppid()
                    name = proc.name()
                    rss = proc.memory_info().rss
                    ct = proc.cpu_times(); ticks = ct.user + ct.system
                    old = self.previous['processes'].get(ident) if self.previous else None
                    self.baselines.setdefault(ident, (rss, began))
                    baseline, start = self.baselines[ident]
                    processes[ident] = dict(id=ident,pid=proc.pid,ppid=ppid,started=started,name=name[:150],rss=rss,
                        memory_pct=100*rss/mem.total,cpu=rate(ticks,old['ticks'] if old else None,dt)*100 if old else None,
                        ticks=ticks,growth=rss-baseline if old else None,observed_s=round(began-start,2),threads=proc.num_threads())
            except (psutil.Error, OSError):
                denied += 1
        # Slow sensors only within active scans, never an idle timer.
        if began - self.slow_time >= 5:
            self.slow_time = began
            self.slow = dict(at=time.time(),gpu=None,gpu_memory=None,battery=None,power=None)
            try:
                regs = plistlib.loads(run(['/usr/sbin/ioreg','-r','-c','IOAccelerator','-a','-d','1'],self.cancel))
                stats = next((r.get('PerformanceStatistics') for r in regs if r.get('PerformanceStatistics')), {})
                self.slow.update(gpu=stats.get('Device Utilization %'),gpu_memory=stats.get('In use system memory'))
            except (subprocess.SubprocessError, ValueError, StopIteration):
                pass
            try:
                battery = psutil.sensors_battery()
                if battery:
                    self.slow.update(battery=battery.percent,power='AC power' if battery.power_plugged else 'Battery')
            except (psutil.Error, OSError):
                pass
        disks = []
        # A single data volume represents the shared startup APFS pool; do not sum peers.
        for label,path in [('Startup data','/System/Volumes/Data')]:
            try:
                d = psutil.disk_usage(path)
                disks.append(dict(name=label,path=path,total=d.total,used=d.used,free=d.free,used_pct=d.percent))
            except OSError:
                errors.append('Startup disk unavailable')
        prev = self.previous
        disk_rates = {key:rate(getattr(io,attr),getattr(prev['io'],attr) if prev and prev['io'] else None,dt) if io else None
                      for key,attr in [('read','read_bytes'),('write','write_bytes')]}
        network = {key:rate(getattr(net,attr),getattr(prev['net'],attr) if prev else None,dt)
                   for key,attr in [('receive','bytes_recv'),('send','bytes_sent')]}
        swap_rates = {key:rate(vm.get(attr,0),prev['vm'].get(attr) if prev else None,dt) if attr in vm else None
                      for key,attr in [('in','Swapins'),('out','Swapouts')]}
        # Keep interval history for all readable processes, bounded by the 61-frame scan.
        compact = [{k:v for k,v in p.items() if k!='ticks'} for p in processes.values()]
        groups = rollup_processes(compact,self.group_baselines,began)
        thermal = self.native.get('thermalState')
        try:
            if self.temperature_reader is None:self.temperature_reader=SMCTemperatures()
            temperatures=self.temperature_reader.read(self.cancel)
        except (OSError,AttributeError):
            temperatures=unavailable_temperatures({},error='Temperature interface unavailable')
        frame = dict(at=time.time(),elapsed=began-self.started,interval=dt or None,
            cpu=100-cpu.get('idle',0) if cpu else None,cpu_parts=cpu,
            cores=[100-cpu_delta(a,b).get('idle',0) if cpu_delta(a,b) else None for a,b in zip(prev['cores'],cores)] if prev else [],
            memory=dict(total=mem.total,available=mem.available,used=mem.total-mem.available,percent=mem.percent,
                        wired=getattr(mem,'wired',None),compressed=vm.get('Pages occupied by compressor'),pressure=pressure),
            swap=dict(total=swap.total,used=swap.used,unused=max(0,swap.total-swap.used),**swap_rates),
            disks=disks,disk_io=disk_rates,network=network,load=list(os.getloadavg()),logical=psutil.cpu_count(),
            thermal=thermal,temperatures=temperatures,low_power=self.native.get('isLowPowerModeEnabled'),slow=dict(self.slow),
            process_count=len(processes),threads=sum(p['threads'] for p in processes.values()),denied=denied,
            processes=compact,process_groups=groups,uptime=time.time()-psutil.boot_time(),errors=errors,
            monitor=dict(rss=self.self_proc.memory_info().rss,cpu_one_core=self.self_proc.cpu_percent(None) if prev else None,collection_ms=(time.monotonic()-began)*1000))
        if not prev: self.self_proc.cpu_percent(None)
        self.previous = dict(mono=began,cpu=cpu_time,cores=cores,processes=processes,io=io,net=net,vm=vm)
        return frame

def evaluate(frames, cfg):
    if not frames:
        return dict(health=None,headroom=None,coverage='Unmeasured',alerts=[],factors={})
    f=frames[-1]; factors={}; alerts=[]
    def alert(severity,title,evidence,action):
        alerts.append(dict(severity=severity,title=title,evidence=evidence,action=action))
    disk=f['disks'][0] if f['disks'] else None
    if disk:
        pct=100*disk['free']/disk['total']; gib=disk['free']/GIB
        severity='critical' if pct<cfg['disk_critical_pct'] or gib<cfg['disk_critical_gib'] else 'warning' if pct<cfg['disk_warn_pct'] or gib<cfg['disk_warn_gib'] else None
        factors['disk']=20 if severity=='critical' else 60 if severity else 100
        if severity: alert(severity,'Startup disk space is low',f'{gib:.1f} GiB / {pct:.1f}% available at last observation.','Review large files and remove only items you no longer need; preserve a backup.')
    pressure=f['memory']['pressure']
    if pressure in ('Normal','Warning','Critical'):
        factors['memory']={'Normal':100,'Warning':60,'Critical':20}[pressure]
        if pressure!='Normal':
            alert('critical' if pressure=='Critical' else 'warning','Native memory pressure is '+pressure.lower(),f"macOS state at last observation; swap-out {f['swap']['out'] / 1048576:.2f} MiB/s." if f['swap']['out'] is not None else 'Native macOS state; swap activity unavailable.','Review memory-heavy processes and reduce concurrent workloads if tasks feel slow.')
    thermal=f['thermal']
    if thermal in (0,1,2,3):
        factors['thermal']=[100,85,50,10][thermal]
        if thermal>=1: alert('critical' if thermal==3 else 'warning','Thermal state: '+['Nominal','Fair','Serious','Critical'][thermal],'Native NSProcessInfo thermal state at last observation. Temperature sensor readings are reported separately.','Reduce heavy workloads; ensure airflow and allow the device to cool.')
    # CPU saturation is a workload observation, not a health penalty.
    sustained=False; high_since=None; recovered_since=None; previous_time=None
    for item in frames:
        t=item['elapsed']; cpu=item['cpu']
        if previous_time is not None and t-previous_time>2.5:
            sustained=False; high_since=None; recovered_since=None
        previous_time=t
        if cpu is None: continue
        if cpu>=cfg['cpu_warn']:
            recovered_since=None
            if high_since is None: high_since=t
            if t-high_since>=cfg['persistence_s']: sustained=True
        else:
            high_since=None
            if recovered_since is None: recovered_since=t
            if t-recovered_since>=cfg['recovery_s']: sustained=False
    if sustained: alert('warning','CPU headroom is limited',f"CPU reached ≥ {cfg['cpu_warn']}% for {cfg['persistence_s']}s; clears after {cfg['recovery_s']}s below that threshold.",'Defer additional compute-heavy work or review the busiest processes.')
    cpu_headroom=None if f['cpu'] is None else max(0,100-f['cpu'])
    mem_headroom=min(100,100*f['memory']['available']/f['memory']['total']/0.35)
    headroom=round(min(cpu_headroom,mem_headroom,factors['memory'],factors['thermal'])) if cpu_headroom is not None and 'memory' in factors and 'thermal' in factors else None
    growth=[p for p in f['processes'] if p['observed_s']>=15 and (p['growth'] or 0)>256*1048576]
    for p in sorted(growth,key=lambda x:x['growth'],reverse=True)[:2]:
        alert('info','Short-window memory growth: '+p['name'],f"RSS grew {p['growth']/1048576:.0f} MiB over {p['observed_s']:.0f}s (PID {p['pid']}). A leak is not established.",'Repeat an explicit scan under a comparable workload; use a longer dedicated profiler to investigate unexplained growth.')
    return dict(health=round(min(factors.values())) if len(factors)==3 else None,headroom=headroom,
                coverage=f'{len(factors)}/3 health domains · temperature / GPU not scored',alerts=alerts,factors=factors)

class InstallationBusyError(ValueError):
    """Collection cannot begin after an update has acquired admission."""


class InstallAdmissionError(ValueError):
    """An active collector or another installer owns the admission boundary."""


class Engine:
    def __init__(self, factory=Collector, clock=time.monotonic):
        self.lock=threading.RLock(); self.wake=threading.Event(); self.factory=factory; self.clock=clock
        self.active=False; self.scan=None; self.frames=[]; self.config=dict(DEFAULTS); self.reason='Not started'
        self.deadline=0; self.lease=0; self.cancel=threading.Event(); self.collections=0
        self.worker=None
        self.install_token=None; self.install_transaction=None

    def start(self,duration,config=None):
        with self.lock:
            if self.install_token is not None: raise InstallationBusyError('Update installation is in progress')
            if self.active: raise ValueError('A scan is already active')
            if self.worker and self.worker.is_alive(): raise ValueError('Previous collector is stopping')
            if duration not in (1.5,30,60): raise ValueError('Choose snapshot, 30 or 60 seconds')
            if config:
                for key,value in config.items():
                    if key not in DEFAULTS or not isinstance(value,(int,float)) or not math.isfinite(value) or value<=0: raise ValueError('Invalid threshold')
                combined={**self.config,**config}
                if combined['disk_critical_pct']>=combined['disk_warn_pct'] or combined['disk_critical_gib']>=combined['disk_warn_gib'] or combined['disk_warn_pct']>100 or combined['cpu_warn']>100 or combined['persistence_s']>30 or combined['recovery_s']>15: raise ValueError('Invalid threshold order or range')
                self.config=combined
            self.active=True; self.scan=secrets.token_hex(12); self.frames=[]; self.reason='Scanning'
            self.deadline=self.clock()+duration; self.lease=self.clock()+3; self.cancel=threading.Event()
            self.worker=threading.Thread(target=self._loop,args=(self.scan,self.cancel),daemon=True,name='bounded-scan')
            self.worker.start()
            return self.scan

    def admit_install(self, transaction):
        """Atomically exclude all scan starts, including already queued requests.

        The transaction makes a lost admission response safe to retry. Admission
        never expires on a timer: only a verified abort or service shutdown can
        hand collection back to the caller.
        """
        if not isinstance(transaction, str): raise ValueError('Transaction UUID required')
        transaction=uuid.UUID(transaction).hex
        with self.lock:
            if self.install_token is not None:
                if self.install_transaction==transaction: return self.install_token
                raise InstallAdmissionError('Another update installation is in progress')
            if self.active or (self.worker is not None and self.worker.is_alive()):
                raise InstallAdmissionError('Wait for the current collector to finish')
            self.install_token=secrets.token_urlsafe(32); self.install_transaction=transaction
            self.reason='Update installation admitted'
            return self.install_token

    def release_install(self, token):
        """Called by the native owner only after it proves no installer is pending."""
        with self.lock:
            if not isinstance(token,str) or self.install_token is None or not secrets.compare_digest(self.install_token,token):
                raise InstallAdmissionError('Installation lease does not match')
            self.install_token=None; self.install_transaction=None; self.reason='Update installation cancelled'

    def valid(self,scan):
        return self.active and scan==self.scan and self.clock()<min(self.deadline,self.lease)

    def renew(self,scan):
        with self.lock:
            if self.valid(scan): self.lease=min(self.deadline,self.clock()+3)

    def stop(self,reason='Stopped by user',scan=None):
        with self.lock:
            if scan is not None and scan!=self.scan: return
            self.active=False; self.reason=reason; self.cancel.set()

    def _loop(self,scan,cancel):
        collector=self.factory(); collector.cancel=cancel; next_at=self.clock()
        while not cancel.is_set():
            with self.lock:
                if not self.valid(scan):
                    if self.scan==scan: self.stop('Scan complete' if self.clock()>=self.deadline else 'Visibility lease expired',scan)
                    break
                until=min(next_at,self.deadline,self.lease)-self.clock()
            if until>0:
                cancel.wait(until); continue
            try:
                frame=collector.sample()
            except Exception as exc:
                if cancel.is_set(): break
                self.stop('Collector failed: '+type(exc).__name__,scan); break
            with self.lock:
                if self.scan!=scan: break
                self.collections+=1
                if self.active: self.frames.append(frame); self.frames=self.frames[-61:]
            next_at=max(next_at+1,self.clock()+.01)

    def state(self,after=-1):
        with self.lock:
            if self.active and not self.valid(self.scan): self.stop('Scan complete' if self.clock()>=self.deadline else 'Visibility lease expired')
            return dict(active=self.active,scan=self.scan,reason=self.reason,remaining=max(0,self.deadline-self.clock()) if self.active else 0,
                frames=self.frames[max(0,after+1):],count=len(self.frames),summary=evaluate(self.frames,self.config),config=dict(self.config),
                collections=self.collections,lease_seconds=3,service_pid=os.getpid(),
                installing=self.install_token is not None,installation_transaction=self.install_transaction)

class Handler(BaseHTTPRequestHandler):
    server_version='MachineMonitor/1'
    def log_message(self,*args): pass
    def reply(self,status,body,kind='application/json',cookie=False):
        data=json.dumps(body,allow_nan=False).encode() if kind=='application/json' else body
        self.send_response(status); self.send_header('Content-Type',kind); self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        if cookie: self.send_header('Set-Cookie',f'monitor={self.server.token}; HttpOnly; SameSite=Strict; Path=/')
        self.end_headers()
        try: self.wfile.write(data)
        except (BrokenPipeError,ConnectionResetError): pass
    def authorized(self,write=False):
        host=f'127.0.0.1:{self.server.server_port}'
        if self.headers.get('Host')!=host: return False
        if f'monitor={self.server.token}' not in self.headers.get('Cookie','').split('; '): return False
        return not write or (self.headers.get('Origin')=='http://'+host and self.headers.get('X-Monitor')=='1')
    def do_GET(self):
        host=f'127.0.0.1:{self.server.server_port}'
        if self.headers.get('Host')!=host: return self.reply(403,{'error':'Invalid host'})
        path=urlsplit(self.path).path
        assets={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8')}
        if path in assets:
            file,kind=assets[path]; return self.reply(200,(ROOT/file).read_bytes(),kind,cookie=path=='/')
        if path=='/api/state':
            if not self.authorized(): return self.reply(403,{'error':'Open the dashboard first'})
            return self.reply(200,self.server.engine.state())
        if path=='/favicon.ico': return self.reply(204,b'','image/x-icon')
        return self.reply(404,{'error':'Not found'})
    def do_POST(self):
        if not self.authorized(True): return self.reply(403,{'error':'Same-origin session required'})
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<=length<=4096: raise ValueError('Request too large')
            body=json.loads(self.rfile.read(length)); path=urlsplit(self.path).path
            if not isinstance(body,dict): raise ValueError('Object required')
            if path=='/api/start': self.server.engine.start(body.get('duration'),body.get('config'))
            elif path=='/api/tick': self.server.engine.renew(body.get('scan'))
            elif path=='/api/stop': self.server.engine.stop(scan=body.get('scan'))
            elif path=='/api/install-admit':
                if not getattr(self.server,'desktop',False): return self.reply(404,{'error':'Not found'})
                token=self.server.engine.admit_install(body.get('transaction'))
                return self.reply(200,{**self.server.engine.state(), 'install_lease':token})
            elif path=='/api/install-release':
                if not getattr(self.server,'desktop',False): return self.reply(404,{'error':'Not found'})
                self.server.engine.release_install(body.get('install_lease'))
            elif path=='/api/shutdown':
                self.server.engine.stop('Service stopped'); threading.Thread(target=self.server.shutdown,daemon=True).start()
            else: return self.reply(404,{'error':'Not found'})
            return self.reply(200,self.server.engine.state(body.get('after',-1)))
        except InstallationBusyError: return self.reply(423,{'error':'Update installation is in progress. Start a scan after the app restarts.'})
        except InstallAdmissionError: return self.reply(409,{
            **self.server.engine.state(), 'error':'Collection or another installation owns admission'})
        except (ValueError,TypeError): return self.reply(400,{'error':'Invalid request or a scan is already active'})

class LoopbackHTTPServer(ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer normally performs reverse DNS here. This local-only
        # service needs the literal bound address and must start without DNS.
        TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--port',type=int,default=8766)
    parser.add_argument('--desktop',action='store_true')
    parser.add_argument('--parent-pid',type=int)
    parser.add_argument('--install-transaction',help='Keep a validated update adoption dormant until native acceptance')
    modes=parser.add_mutually_exclusive_group()
    modes.add_argument('--update-preflight',action='store_true')
    modes.add_argument('--update-recovery',action='store_true')
    args=parser.parse_args()
    if args.update_preflight or args.update_recovery:
        if args.desktop or args.parent_pid is not None or args.install_transaction is not None or args.port!=8766:
            parser.error('Update helper modes cannot start a collector service')
        if args.update_preflight:
            from update_preflight import main as update_main
        else:
            from update_recovery import main as update_main
        return update_main()
    if args.install_transaction is not None and (not args.desktop or args.parent_pid is None):
        parser.error('An update adoption requires the native lifetime owner')
    if args.parent_pid is not None and args.parent_pid!=os.getppid():
        parser.error('The lifetime owner must be the launching parent process')
    parent_watch=None
    if args.parent_pid is not None:
        parent_watch=select.kqueue()
        parent_watch.control([select.kevent(args.parent_pid,filter=select.KQ_FILTER_PROC,
            flags=select.KQ_EV_ADD|select.KQ_EV_ONESHOT,fflags=select.KQ_NOTE_EXIT)],0,0)
    server=LoopbackHTTPServer(('127.0.0.1',args.port),Handler)
    server.token=secrets.token_urlsafe(32); server.engine=Engine(); server.desktop=args.desktop
    startup_lease=None
    if args.install_transaction is not None:
        try: startup_lease=server.engine.admit_install(args.install_transaction)
        except ValueError: server.server_close(); parser.error('Invalid update transaction')
    def shutdown(*_):
        server.engine.stop('App closed')
        threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,shutdown)
    if parent_watch is not None:
        def watch_parent():
            try:
                if parent_watch.control(None,1): shutdown()
            except (OSError,ValueError): pass
        threading.Thread(target=watch_parent,daemon=True,name='app-lifetime').start()
    if args.desktop:
        readiness=dict(port=server.server_port,pid=os.getpid())
        if startup_lease is not None: readiness['install_lease']=startup_lease
        print('MACHINE_MONITOR_READY '+json.dumps(readiness),flush=True)
    else:
        print(f'Machine Monitor: http://127.0.0.1:{server.server_port} — dormant until a scan is requested',flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally:
        server.engine.stop('Service stopped')
        # Let the cancellable subprocess context finish killing/reaping its child
        # before interpreter teardown can abandon the daemon collector.
        worker=server.engine.worker
        if worker is not None: worker.join(timeout=1)
        server.server_close()
        if parent_watch is not None: parent_watch.close()

if __name__=='__main__': raise SystemExit(main())
