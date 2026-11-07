"""Test-only entrypoint. The production freezer never imports this module."""
from pathlib import Path
import faulthandler
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import monitor
from tests.fixtures import SyntheticCollector, synthetic_frame

def main():
    faulthandler.dump_traceback_later(6)
    def refuse_live_collector(*args, **kwargs):
        raise AssertionError("Fixture service must never construct a live collector")
    monitor.Collector.__init__=refuse_live_collector
    original=monitor.Engine
    seed='--seed-history' in sys.argv
    def fixture_engine():
        engine=original(factory=SyntheticCollector)
        if seed:
            baselines={}
            engine.frames=[synthetic_frame(i,baselines=baselines,interval=None if i==0 else 1) for i in range(30)]
            engine.scan='synthetic-fixture-history'
            engine.reason='Synthetic test fixture'
        faulthandler.cancel_dump_traceback_later()
        return engine
    monitor.Engine=fixture_engine
    if '--seed-history' in sys.argv:sys.argv.remove('--seed-history')
    monitor.main()

if __name__=='__main__':main()
