"""Isolated fixture service ownership for browser regressions."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from test_desktop_service import ready

def run(script,output):
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=True)
    proc=subprocess.Popen([sys.executable,str(ROOT/'tests/fixture_service.py'),'--port','0','--desktop',
        '--parent-pid',str(os.getpid()),'--seed-history'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        info=ready(proc)
        environment=dict(os.environ,MONITOR_TEST_URL=f"http://127.0.0.1:{info['port']}",MONITOR_TEST_OUTPUT=str(output))
        subprocess.run([sys.executable,str(ROOT/script)],cwd=ROOT,env=environment,check=True,timeout=150)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:proc.wait(timeout=4)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
        proc.stdout.close();proc.stderr.close()

if __name__=='__main__':
    run(sys.argv[1],sys.argv[2])
