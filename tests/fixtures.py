"""Deterministic telemetry. Contains no host observations or captured process data."""
import math
import time
from monitor import GIB, rollup_processes
from temperatures import CPU_KEYS, GPU_KEYS, summarize

class SyntheticCollector:
    def __init__(self):
        self.started=time.monotonic()
        self.previous=None
        self.index=0
        self.baselines={}

    def sample(self):
        now=time.monotonic()
        elapsed=now-self.started
        interval=None if self.previous is None else now-self.previous
        frame=synthetic_frame(self.index,elapsed,interval,self.baselines)
        self.previous=now;self.index+=1
        return frame

def synthetic_frame(index=0,elapsed=None,interval=1,baselines=None):
    elapsed=index if elapsed is None else elapsed
    processes=[]
    for group in range(10):
        root=1000+group*10
        for member in range(3):
            pid=root+member
            rss=(240-group*12+member*4)*1048576+index*131072
            processes.append(dict(id=f'{pid}:100',pid=pid,ppid=1 if member==0 else root,
                started=100,name=f'Fixture app {group}' if member==0 else f'Fixture worker {group}.{member}',
                cpu=None if interval is None else 2+group/3+member+math.sin(index)/4,
                rss=rss,memory_pct=100*rss/(16*GIB),threads=4+member,
                growth=None if index==0 else index*131072,observed_s=elapsed))
    cpu=None if interval is None else 25+4*math.sin(index/3)
    at=time.time()
    readings={key:54+offset*.25+math.sin(index/4) for offset,key in enumerate(CPU_KEYS)}
    readings.update({key:49+offset*.5+math.sin(index/4) for offset,key in enumerate(GPU_KEYS)})
    temperatures=summarize(readings,at=at)
    temperatures['source']='Synthetic test fixture'
    memory_used=(9+math.sin(index/6)/5)*GIB
    return dict(at=at,elapsed=elapsed,interval=interval,cpu=cpu,
        cpu_parts=None if cpu is None else dict(user=cpu*.7,system=cpu*.3,idle=100-cpu),
        cores=[] if cpu is None else [cpu+offset for offset in range(12)],logical=12,
        memory=dict(total=16*GIB,available=16*GIB-memory_used,used=memory_used,
                    percent=100*memory_used/(16*GIB),wired=2*GIB,compressed=GIB,pressure='Normal'),
        swap=dict(total=2*GIB,used=.5*GIB,unused=1.5*GIB,**{'in':0,'out':0}),
        disks=[dict(name='Fixture volume',path='/fixture-volume',total=500*GIB,used=200*GIB,free=300*GIB,used_pct=40)],
        disk_io=dict(read=1048576,write=524288),network=dict(receive=2097152,send=1048576),
        load=[.4,.5,.6],thermal=0,temperatures=temperatures,low_power=False,
        slow=dict(at=at,gpu=15,gpu_memory=128*1048576,battery=80,power='Fixture AC'),
        process_count=len(processes),threads=sum(p['threads'] for p in processes),denied=0,
        processes=processes,process_groups=rollup_processes(processes,baselines,elapsed),
        uptime=3600,errors=[],monitor=dict(rss=24*1048576,cpu_one_core=1,collection_ms=3),
        fixture=True)
