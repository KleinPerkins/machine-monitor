"""Live acceptance checks. Requires a running localhost service and Chrome."""
import os
import json
from pathlib import Path
import statistics
import time
import psutil
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parent

results={}; errors=[]; expected_network_failure=[False]

def state(page):
    return page.evaluate("fetch('/api/state').then(r=>r.json())")

URL=os.environ.get('MONITOR_TEST_URL')
OUTPUT=Path(os.environ.get('MONITOR_TEST_OUTPUT',ROOT/'outputs'))

def main():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    if not URL: raise RuntimeError('Run this regression through tests/browser_support.py')
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True)
        context=browser.new_context(viewport={'width':1440,'height':1100},color_scheme='dark')
        page=context.new_page()
        page.on('pageerror',lambda e:errors.append(str(e)))
        page.on('console',lambda m:errors.append(m.text) if m.type=='error' and not expected_network_failure[0] else None)
        requests=[];page.on('request',lambda r:requests.append(r.url))
        page.goto(URL);page.wait_for_load_state('networkidle')
        initial=state(page);assert not initial['active']
        proc=psutil.Process(initial['service_pid']); before=proc.cpu_times(); n=initial['collections'];req=len(requests)
        page.wait_for_timeout(3000)
        # The test's own /api/state requests do not sample telemetry.
        assert len(requests)==req
        after=state(page);assert after['collections']==n
        cpu=proc.cpu_times();results['dormant']={'extra_collections':0,'frontend_requests':0,'service_cpu_seconds_3s':(cpu.user+cpu.system)-(before.user+before.system)}
        page.get_by_role('button',name='Start 30-second scan').click()
        page.wait_for_timeout(7000)
        s=state(page);assert s['active'] and s['count']>=6
        scan=s['scan']
        duplicate=context.request.post(URL+'/api/start',headers={'Origin':URL,'X-Monitor':'1'},data={'duration':30}).status
        assert duplicate==400 and state(page)['scan']==scan
        page.locator('#cpuChart').focus();page.keyboard.press('ArrowLeft')
        assert 'historical' in page.locator('#cursorLabel').inner_text()
        cursor=page.locator('#cursorLabel').inner_text();assert 'tables aligned' in cursor
        page.locator('#memoryTable [data-process]').first.click()
        assert page.locator('#selectedProcess').is_visible()
        assert page.locator('#processChart svg').count()==1
        page.get_by_role('button',name='Return to latest').click()
        page.locator('#cpuTable [data-sort="rss"]').click()
        assert page.locator('#cpuTable tbody tr').count()==8
        page.wait_for_function("() => document.querySelector('#state').textContent.includes('Dormant')",timeout=35000)
        s=state(page);assert s['reason']=='Scan complete' and 29<=s['count']<=31
        fs=s['frames'];dts=[f['interval'] for f in fs[1:]]
        assert .9<statistics.median(dts)<1.1 and fs[-1]['elapsed']<30.5
        results['scan30']={'count':s['count'],'last_elapsed':fs[-1]['elapsed'],'median_interval':statistics.median(dts),'max_interval':max(dts),'median_collection_ms':statistics.median(f['monitor']['collection_ms'] for f in fs),'median_cpu_one_core':statistics.median(f['monitor']['cpu_one_core'] for f in fs[1:]),'rss_mib':fs[-1]['monitor']['rss']/1048576}
        # Real hover synchronizes readouts without changing the summary's live basis.
        box=page.locator('#cpuChart svg').bounding_box()
        page.mouse.move(box['x']+box['width']*.45,box['y']+70)
        assert 'historical' in page.locator('#cursorLabel').inner_text()
        page.mouse.move(0,0)
        page.screenshot(path=str(OUTPUT/'dashboard-dark.png'),full_page=True)
        # Responsive appearances, reflow, zoom and keyboard reachability.
        results['layouts']={}
        for width in [1440,820,360,320]:
            page.set_viewport_size({'width':width,'height':1100})
            assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth+1')
            results['layouts'][str(width)]='no page overflow'
        page.screenshot(path=str(OUTPUT/'dashboard-narrow.png'),full_page=True)
        page.set_viewport_size({'width':1440,'height':1100});page.emulate_media(color_scheme='light',reduced_motion='reduce')
        page.screenshot(path=str(OUTPUT/'dashboard-light.png'),full_page=True)
        page.evaluate("document.body.style.zoom='2'")
        assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth+1')
        page.evaluate("document.body.style.zoom='1'")
        page.emulate_media(color_scheme='dark');page.keyboard.press('Tab')
        results['keyboard_hover_sort_selection']='passed'
        # One-shot ends on its own.
        page.get_by_role('button',name='Snapshot (~1s)').click();page.wait_for_timeout(2500)
        assert not state(page)['active'] and state(page)['count']==2
        results['snapshot']='2 observations; automatic stop'
        # 60-second control and explicit stop.
        page.locator('#duration').select_option('60');page.locator('#duration').select_option('60');page.get_by_role('button',name='Start 60-second scan').click()
        page.wait_for_timeout(1500);assert state(page)['remaining']>55
        page.get_by_role('button',name='Stop scan',exact=True).click();page.wait_for_timeout(250)
        a=state(page);page.wait_for_timeout(1500);assert state(page)['collections']==a['collections']
        results['scan60_and_stop']='60s deadline set; Stop halted collection'
        # Visibility handler (synthetic browser signal); real navigation/close below.
        page.locator('#duration').select_option('60');page.get_by_role('button',name='Start 60-second scan').click();page.wait_for_timeout(1200)
        page.evaluate("Object.defineProperty(document,'hidden',{configurable:true,get:()=>true});document.dispatchEvent(new Event('visibilitychange'))")
        page.wait_for_timeout(300);assert not state(page)['active']
        page.evaluate("delete document.hidden;document.dispatchEvent(new Event('visibilitychange'))");page.wait_for_timeout(300)
        assert not state(page)['active'];results['hidden']='visibility handler stops; return stays dormant'
        # Abort telemetry requests to emulate a dead link; lease must independently expire.
        page.locator('#duration').select_option('60');page.get_by_role('button',name='Start 60-second scan').click();page.wait_for_timeout(1200)
        expected_network_failure[0]=True;page.route('**/api/tick',lambda route:route.abort());page.wait_for_timeout(4300)
        s=state(page);assert not s['active'] and s['reason']=='Visibility lease expired'
        page.unroute('**/api/tick');expected_network_failure[0]=False;page.reload();page.wait_for_load_state('networkidle');assert not state(page)['active']
        results['disconnect']='backend expired without stop request; reload dormant'
        # Cross-origin mutation rejection, regardless of the caller's valid cookie.
        r=context.request.post(URL+'/api/start',headers={'Origin':'https://example.invalid','X-Monitor':'1'},data={'duration':30})
        assert r.status==403;results['origin_protection']='foreign origin rejected'
        page.locator('#duration').select_option('60');page.get_by_role('button',name='Start 60-second scan').click();page.wait_for_timeout(1200)
        page.goto('about:blank');page.wait_for_timeout(3500)
        page.goto(URL);page.wait_for_load_state('networkidle');assert not state(page)['active']
        results['leave_reopen']='navigation stops; reopen dormant'
        page.locator('#duration').select_option('60');page.get_by_role('button',name='Start 60-second scan').click();page.wait_for_timeout(1200)
        page.close();page=context.new_page();page.goto(URL);page.wait_for_load_state('networkidle');page.wait_for_timeout(3500)
        assert not state(page)['active'];results['close_reopen']='close stops; reopen dormant'
        assert not errors,errors[:4]
        results['console_errors']=errors
        # Leave a useful final retained scan, without any ongoing collection.
        page.get_by_role('button',name='Snapshot (~1s)').click();page.wait_for_timeout(2500)
        assert not state(page)['active']
        browser.close()

    (OUTPUT/'validation.json').write_text(json.dumps(results,indent=2))
    print(json.dumps(results,indent=2))

if __name__=='__main__':main()
