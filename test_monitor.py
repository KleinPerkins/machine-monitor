import copy
import time
import unittest
from monitor import Engine, DEFAULTS, evaluate, cpu_delta, rate, GIB, rollup_processes

def frame(t=0,cpu=20):
    return dict(elapsed=t,cpu=cpu,disks=[dict(free=100*GIB,total=500*GIB)],
                memory=dict(pressure='Normal',available=8*GIB,total=16*GIB),
                thermal=0,swap={'out':0},processes=[])

class FakeCollector:
    def sample(self): return frame()

def process(pid,ppid,started=None,cpu=10,rss=100,name='App'):
    started=pid if started is None else started
    return dict(id=f'{pid}:{started}',pid=pid,ppid=ppid,started=started,name=name,
                cpu=cpu,rss=rss,memory_pct=rss/10,threads=2)

class ProcessRollup(unittest.TestCase):
    def test_nested_totals_partition_observed_processes(self):
        ps=[process(10,1),process(11,10),process(12,11),process(20,1)]
        groups=rollup_processes(ps);self.assertEqual(len(groups),2)
        group=next(g for g in groups if g['pid']==10)
        self.assertEqual((group['cpu'],group['rss'],group['memory_pct'],group['threads'],group['count']),(30,300,30,6,3))
        self.assertEqual([m['depth'] for m in group['members']],[0,1,2])
        self.assertEqual(sum(g['rss'] for g in groups),sum(p['rss'] for p in ps))
        self.assertEqual(len({m['id'] for g in groups for m in g['members']}),len(ps))
    def test_launchd_does_not_merge_apps_or_names(self):
        ps=[process(1,0,started=0),process(10,1,name='App'),process(20,1,name='App')]
        groups=rollup_processes(ps);self.assertEqual(len(groups),3)
        self.assertEqual(len({g['id'] for g in groups}),3)
    def test_missing_parent_stays_separate(self):
        groups=rollup_processes([process(10,99),process(11,10),process(20,99)])
        self.assertEqual(len(groups),2);self.assertTrue(all(g['parent_missing'] for g in groups))
    def test_reused_parent_pid_cannot_claim_older_child(self):
        groups=rollup_processes([process(10,1,started=100),process(11,10,started=50)])
        self.assertEqual(len(groups),2)
        self.assertTrue(next(g for g in groups if g['pid']==11)['parent_missing'])
    def test_partial_cpu_and_first_baseline_are_explicit(self):
        ps=[process(10,1,cpu=None),process(11,10,cpu=20)]
        group=rollup_processes(ps)[0];self.assertEqual(group['cpu'],20);self.assertTrue(group['cpu_partial'])
        self.assertIsNone(rollup_processes([process(10,1,cpu=None)])[0]['cpu'])
    def test_growth_uses_group_baseline_with_membership_changes(self):
        base={};first=rollup_processes([process(10,1)],base,100)[0]
        self.assertIsNone(first['growth'])
        second=rollup_processes([process(10,1),process(11,10,rss=200)],base,102)[0]
        self.assertEqual(second['growth'],200);self.assertTrue(second['membership_changed'])
        third=rollup_processes([process(10,1,rss=50)],base,103)[0]
        self.assertEqual(third['growth'],-50)
        restarted=rollup_processes([process(10,1,started=1000)],base,104)[0]
        self.assertIsNone(restarted['growth']);self.assertNotEqual(restarted['id'],first['id'])
    def test_cycle_is_bounded_and_conserves_metrics(self):
        ps=[process(10,11,started=0),process(11,10,started=0),process(12,11,started=0)]
        groups=rollup_processes(ps);self.assertEqual(len(groups),1)
        self.assertEqual(groups[0]['rss'],300);self.assertTrue(groups[0]['parent_missing'])
    def test_empty_snapshot(self):
        self.assertEqual(rollup_processes([]),[])

class Rules(unittest.TestCase):
    def test_cpu_and_counter_resets(self):
        self.assertIsNone(cpu_delta(None,dict(user=0,idle=0)))
        self.assertEqual(cpu_delta(dict(user=1,idle=1),dict(user=2,idle=4)),dict(user=25,idle=75))
        self.assertEqual(rate(2,5,1),0)
        self.assertIsNone(rate(1,None,1))
    def test_missing_domain_not_healthy(self):
        f=frame();f['thermal']=None
        self.assertIsNone(evaluate([f],DEFAULTS)['health'])
        self.assertIsNone(evaluate([f],DEFAULTS)['headroom'])
        f['memory']['pressure']=None
        self.assertIsNone(evaluate([f],DEFAULTS)['headroom'])
    def test_critical_dominates(self):
        f=frame();f['thermal']=3
        s=evaluate([f],DEFAULTS)
        self.assertEqual(s['health'],10)
        self.assertEqual(s['alerts'][0]['severity'],'critical')
    def test_absolute_disk_threshold(self):
        f=frame();f['disks']=[dict(total=20*GIB,free=8*GIB)]
        self.assertEqual(evaluate([f],DEFAULTS)['health'],20)
    def test_cpu_persistence_and_recovery(self):
        fs=[frame(t,99) for t in range(6)]
        self.assertFalse(evaluate(fs[:5],DEFAULTS)['alerts'])
        self.assertTrue(evaluate(fs,DEFAULTS)['alerts'])
        fs += [frame(t,10) for t in range(6,10)]
        self.assertTrue(evaluate(fs[:-1],DEFAULTS)['alerts'])
        self.assertFalse(evaluate(fs,DEFAULTS)['alerts'])
        self.assertEqual(evaluate([frame(0,99)],DEFAULTS)['health'],100)
    def test_growth_is_not_diagnosis(self):
        f=frame();f['processes']=[dict(name='test',pid=1,observed_s=20,growth=300*1048576)]
        a=evaluate([f],DEFAULTS)['alerts'][0]
        self.assertEqual(a['severity'],'info')
        self.assertIn('not established',a['evidence'])
    def test_gap_resets_cpu_persistence(self):
        self.assertFalse(evaluate([frame(t,99) for t in [0,1,2,3,9]],DEFAULTS)['alerts'])

class Lifecycle(unittest.TestCase):
    def test_idle_no_collection(self):
        e=Engine(FakeCollector);time.sleep(.05)
        self.assertEqual(e.collections,0)
        self.assertFalse(e.active)
    def test_stop_does_not_resume(self):
        e=Engine(FakeCollector);scan=e.start(30);time.sleep(.04)
        with self.assertRaises(ValueError):e.start(30)
        e.stop(scan=scan);e.worker.join(1)
        self.assertFalse(e.worker.is_alive());n=e.collections
        e.renew(scan);time.sleep(.05)
        self.assertFalse(e.active);self.assertEqual(e.collections,n)
    def test_deadline_cannot_extend(self):
        now=[100];e=Engine(FakeCollector,lambda:now[0]);scan=e.start(30)
        deadline=e.deadline
        for t in range(101,131):now[0]=t;e.renew(scan)
        self.assertEqual(e.deadline,deadline);self.assertFalse(e.valid(scan))
        e.stop();e.worker.join(1)
    def test_expired_lease_cannot_revive(self):
        now=[0];e=Engine(FakeCollector,lambda:now[0]);scan=e.start(30);now[0]=4;e.renew(scan)
        self.assertFalse(e.valid(scan));e.state();e.worker.join(1)
        self.assertFalse(e.active)
    def test_wrong_generation_cannot_stop_new_scan(self):
        e=Engine(FakeCollector);old=e.start(30);e.stop();e.worker.join(1)
        new=e.start(30);e.stop(scan=old)
        self.assertTrue(e.active);self.assertTrue(e.valid(new));e.stop();e.worker.join(1)
    def test_invalid_thresholds(self):
        e=Engine(FakeCollector)
        for cfg in [dict(cpu_warn=101),dict(disk_critical_pct=20),dict(cpu_warn=float('nan'))]:
            with self.assertRaises(ValueError):e.start(30,cfg)
        self.assertFalse(e.active)

if __name__=='__main__':unittest.main()
