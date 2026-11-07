"""Isolated UI fixtures; never sent to the live telemetry engine."""
import os
import copy
import json
from pathlib import Path
from playwright.sync_api import sync_playwright
from monitor import evaluate, GIB

ROOT=Path(__file__).resolve().parent
URL=os.environ.get('MONITOR_TEST_URL')
OUTPUT=Path(os.environ.get('MONITOR_TEST_OUTPUT',ROOT/'outputs'))

def main():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    if not URL: raise RuntimeError('Run this regression through tests/browser_support.py')
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True)
        context=browser.new_context(viewport={'width':820,'height':1000},color_scheme='dark')
        context.request.get(URL+'/')
        base=context.request.get(URL+'/api/state').json()
        assert base['frames']
        outcomes={}
        for scenario in ['normal','warning','critical','missing','growth']:
            s=copy.deepcopy(base);f=copy.deepcopy(s['frames'][-1]);f['memory']['pressure']='Normal';f['thermal']=0;f['cpu']=20
            f['disks'][0].update(free=100*GIB,total=500*GIB)
            f['elapsed']=20
            if scenario=='warning':f['memory']['pressure']='Warning';f['thermal']=1
            if scenario=='critical':f['memory']['pressure']='Critical';f['thermal']=3;f['disks'][0]['free']=3*GIB
            if scenario=='missing':f['memory']['pressure']=None;f['thermal']=None;f['slow']['gpu']=None;f['slow']['gpu_memory']=None;f['cpu']=None;f['cpu_parts']=None;f['cores']=[]
            if scenario=='growth':f['processes'][0].update(growth=300*1048576,observed_s=20)
            s.update(active=False,frames=[f],count=1,reason='Isolated test fixture',summary=evaluate([f],s['config']))
            page=context.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
            page.route('**/api/state',lambda route,request,payload=s:route.fulfill(status=200,content_type='application/json',body=json.dumps(payload)))
            page.goto(URL+'/');page.wait_for_load_state('networkidle')
            if scenario=='normal':assert page.locator('#health').inner_text()=='100'
            if scenario=='warning':assert page.locator('#health').inner_text()=='60';assert page.locator('#alerts .warning').count()>=1
            if scenario=='critical':assert page.locator('#health').inner_text()=='10';assert page.locator('#alerts .critical').count()==3
            if scenario=='missing':assert page.locator('#health').inner_text()=='—';assert page.locator('#headroom').inner_text()=='—';assert page.locator('#thermalValue').inner_text()=='Unavailable'
            if scenario=='growth':assert 'leak is not established' in page.locator('#alerts').inner_text()
            page.locator('#method summary').click()
            page.set_viewport_size({'width':320,'height':1000})
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
            assert not errors,errors
            outcomes[scenario]='passed; rendered with no script error and 320px settings reflow'
            page.close()
        browser.close()
    (OUTPUT/'scenario-validation.json').write_text(json.dumps(outcomes,indent=2))
    print(json.dumps(outcomes,indent=2))

if __name__=='__main__':main()
