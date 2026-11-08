"""Real 30-second completion plus isolated lost/late response regressions."""
import os
import copy
import json
import uuid
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parent
def state(page):return page.evaluate("fetch('/api/state').then(r=>r.json())")
def ready(page):
    page.wait_for_function("() => ['start','snapshot','duration'].every(id => !document.getElementById(id).disabled) && document.getElementById('stop').hidden", timeout=3000)
    assert page.locator('#start').is_enabled()
    assert page.locator('#snapshot').is_enabled()
    assert page.locator('#duration').is_enabled()
    assert not page.locator('#stop').is_visible()

results={}
URL=os.environ.get('MONITOR_TEST_URL')
OUTPUT=Path(os.environ.get('MONITOR_TEST_OUTPUT',ROOT/'outputs'))

def main():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    if not URL: raise RuntimeError('Run this regression through tests/browser_support.py')
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True)
        context=browser.new_context();page=context.new_page();errors=[]
        page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(URL);page.wait_for_load_state('networkidle');ready(page)
        began=page.evaluate('performance.now()')
        page.get_by_role('button',name='Start 30-second scan').click()
        page.wait_for_timeout(900)
        first=state(page)['scan'];assert page.locator('#start').is_disabled()
        page.wait_for_function("() => !document.querySelector('#start').disabled",timeout=33000)
        elapsed=(page.evaluate('performance.now()')-began)/1000
        ready(page);finished=state(page)
        assert not finished['active'] and finished['scan']==first and finished['count']>=29
        assert 29.5<elapsed<32,elapsed
        page.get_by_role('button',name='Start 30-second scan').click();page.wait_for_timeout(1200)
        second=state(page);assert second['active'] and second['scan']!=first
        assert page.locator('#start').is_disabled()
        page.get_by_role('button',name='Stop scan',exact=True).click();ready(page)
        results['live']={'reset_after_seconds':elapsed,'observations':finished['count'],'second_scan':'started without reload','stop':'all controls reset'}
        # The native installation handshake must also disable every scan entry.
        admitted=page.evaluate("async transaction => {const s=await api('install-admit',{transaction});accept(s,true);return s.install_lease;}",str(uuid.uuid4()))
        before=state(page)
        assert before['installing'] and not before['active']
        assert page.locator('#start').is_disabled() and page.locator('#snapshot').is_disabled()
        assert page.locator('#duration').is_disabled()
        assert page.locator('#state').inner_text()=='Installing update'
        page.evaluate('void start(30)');page.wait_for_timeout(150)
        after=state(page)
        assert after['collections']==before['collections'] and not after['active']
        page.evaluate("async token => {const s=await api('install-release',{install_lease:token});accept(s,true);}",admitted)
        ready(page)
        results['install_admission']='scan controls and programmatic start blocked until verified abort release'
        seed=state(page);seed['active']=False
        # Completion must unlock controls even when the final state request fails.
        isolated=context.new_page();starts=[];reads=[0]
        def final_state(route):
            reads[0]+=1
            if reads[0]==1:route.fulfill(content_type='application/json',body=json.dumps(seed))
            else:route.abort()
        def start_short(route):
            payload=copy.deepcopy(seed);payload.update(active=True,remaining=.2,scan=f'isolated-{len(starts)}',frames=[],count=0)
            starts.append(payload['scan']);route.fulfill(content_type='application/json',body=json.dumps(payload))
        isolated.route('**/api/state',final_state);isolated.route('**/api/start',start_short)
        isolated.goto(URL);isolated.wait_for_load_state('networkidle')
        for _ in range(2):
            isolated.locator('#start').click();isolated.wait_for_timeout(450);ready(isolated)
        assert len(set(starts))==2
        isolated.close();results['missing_final_response']='deadline resets controls and allows repeated starts'
        # A delayed response belonging to the old scan cannot overwrite a new scan.
        isolated=context.new_page();pending=[];starts=[]
        isolated.route('**/api/state',lambda r:r.fulfill(content_type='application/json',body=json.dumps(seed)))
        def start_delayed(route):
            payload=copy.deepcopy(seed);payload.update(active=True,remaining=.8 if not starts else 5,scan=f'delayed-{len(starts)}',frames=[],count=0)
            starts.append(payload);route.fulfill(content_type='application/json',body=json.dumps(payload))
        isolated.route('**/api/start',start_delayed)
        isolated.route('**/api/tick',lambda r:pending.append(r))
        isolated.goto(URL);isolated.wait_for_load_state('networkidle');isolated.locator('#start').click()
        isolated.wait_for_timeout(1000);ready(isolated);assert pending
        isolated.locator('#start').click();isolated.wait_for_timeout(100)
        pending[0].fulfill(content_type='application/json',body=json.dumps(starts[0]));isolated.wait_for_timeout(150)
        assert isolated.evaluate('scan')=='delayed-1'
        assert isolated.locator('#start').is_disabled()
        isolated.close();results['late_response']='old scan response cannot overwrite the new scan'
        assert not errors,errors
        browser.close()
    (OUTPUT/'scan-reset-validation.json').write_text(json.dumps(results,indent=2))
    print(json.dumps(results,indent=2))

if __name__=='__main__':main()
