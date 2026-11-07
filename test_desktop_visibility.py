"""Regression: hide during an unacknowledged start, in both request orderings."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from playwright.sync_api import sync_playwright
from test_desktop_service import ready, client

ROOT=Path(__file__).resolve().parent
URL=os.environ.get('MONITOR_TEST_URL')
OUTPUT=Path(os.environ.get('MONITOR_TEST_OUTPUT',ROOT/'outputs'))

def main():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    proc=subprocess.Popen([sys.executable,str(ROOT/'tests/fixture_service.py'),'--port','0','--desktop','--parent-pid',str(os.getpid())],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    results={}
    try:
        info=ready(proc);url=f"http://127.0.0.1:{info['port']}";api=client(info['port'])
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True)
            for ordering in ('response-delayed','request-delayed'):
                context=browser.new_context();page=context.new_page();errors=[]
                page.on('pageerror',lambda e:errors.append(str(e)))
                page.add_init_script("Object.defineProperty(document,'hidden',{configurable:true,get:()=>window.testHidden??false})")
                page.goto(url);page.wait_for_load_state('networkidle')
                def intercept(route):
                    response=route.fetch() if ordering=='response-delayed' else None
                    page.evaluate("window.testHidden=true;document.dispatchEvent(new Event('visibilitychange'))")
                    # Make stop-before-start deterministic in the request-delayed case.
                    deadline=time.monotonic()+1
                    while api('state')['active'] and time.monotonic()<deadline: time.sleep(.02)
                    assert not api('state')['active']
                    page.evaluate("window.testHidden=false;document.dispatchEvent(new Event('visibilitychange'))")
                    if response is not None: route.fulfill(response=response)
                    else: route.continue_()
                page.route('**/api/start',intercept)
                page.evaluate('void start(30)')
                page.wait_for_timeout(800)
                assert not api('state')['active'],ordering
                assert page.locator('#start').is_enabled(),ordering
                page.wait_for_timeout(700)
                assert not api('state')['active'],ordering
                assert not errors,errors
                results[ordering]='hidden start cancelled; fast restore stays dormant'
                context.close()
            browser.close()
        (OUTPUT/'desktop-visibility-validation.json').write_text(json.dumps(results,indent=2))
        print(json.dumps(results,indent=2))
    finally:
        proc.terminate()
        try: proc.wait(timeout=4)
        except subprocess.TimeoutExpired: proc.kill();proc.wait()
        proc.stdout.close();proc.stderr.close()

if __name__=='__main__':main()
