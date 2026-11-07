"""Regression: moving through retained observations cannot move the page."""
import os
import json
from datetime import datetime
import http.cookiejar
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parent
URL=os.environ.get('MONITOR_TEST_URL')
OUTPUT=Path(os.environ.get('MONITOR_TEST_OUTPUT',ROOT/'outputs'))

def main():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    if not URL: raise RuntimeError('Run this regression through tests/browser_support.py')
    opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    opener.open(URL+'/').read()
    state=json.load(opener.open(URL+'/api/state'))
    assert state['frames'],'Take a scan before running the hover regression test.'
    state['active']=False
    # Mix short/long clock labels so counter wrapping is independent of host time/locale.
    clocks=[datetime.fromisoformat(value).timestamp() for value in
            ('2026-01-01T12:59:59+00:00','2026-01-01T03:45:09+00:00')]
    for index,frame in enumerate(state['frames']):
        frame['at']=clocks[index%2]
    geometry="""() => {
     const ids=['cursorLabel','cpuChart','memoryChart','cpuTable','memoryTable','swapChart','diskChart','gpuChart','networkChart'];
     const r={scrollY,scrollX,height:document.documentElement.scrollHeight,width:document.documentElement.scrollWidth};
     for(const id of ids){const b=document.getElementById(id).getBoundingClientRect();r[id]=[b.x,b.y+scrollY,b.width,b.height];}
     return r;
    }"""
    results=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True)
        context=browser.new_context(locale='en-US',timezone_id='UTC');page=context.new_page();errors=[]
        page.on('pageerror',lambda e:errors.append(str(e)))
        page.route('**/api/state',lambda route:route.fulfill(status=200,content_type='application/json',body=json.dumps(state)))
        for width in [1440,820,736,560,440,420,400,390,360,320]:
            page.set_viewport_size({'width':width,'height':1000})
            page.goto(URL+'/');page.wait_for_load_state('networkidle')
            for chart_id in ['cpuChart','memoryChart','swapChart','diskChart','gpuChart','networkChart']:
                chart=page.locator('#'+chart_id);chart.scroll_into_view_if_needed()
                # Move off the plots before taking the reference layout.
                page.mouse.move(0,0);page.wait_for_timeout(30)
                box=chart.locator('svg').bounding_box();baseline=page.evaluate(geometry)
                max_delta=0;worst=None
                for fraction in [.98,0,.25,.5,.75,.98]:
                    page.mouse.move(box['x']+box['width']*(55/600+fraction*530/600),box['y']+box['height']*.4)
                    page.wait_for_timeout(30)
                    current=page.evaluate(geometry)
                    for key,value in baseline.items():
                        pairs=zip(value,current[key]) if isinstance(value,list) else [(value,current[key])]
                        for before,after in pairs:
                            delta=abs(before-after)
                            if delta>max_delta:max_delta=delta;worst=(fraction,key,before,after,current)
                page.mouse.move(0,0);current=page.evaluate(geometry)
                max_delta=max(max_delta,abs(current['scrollY']-baseline['scrollY']),abs(current['height']-baseline['height']))
                assert max_delta<=.5,(width,chart_id,max_delta,baseline,worst,current)
                results.append(dict(width=width,chart=chart_id,max_shift_px=max_delta))
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
        # Expanded descendants and their changing membership stay within a stable viewport.
        page.set_viewport_size({'width':820,'height':1000});page.goto(URL+'/');page.wait_for_load_state('networkidle')
        page.locator('#memoryTable [data-expand]').first.click()
        page.locator('#memoryTable').evaluate('(e)=>e.scrollTop=150')
        page.locator('#memoryTable .group-row [data-process]').first.click()
        page.locator('#processCpuChart').scroll_into_view_if_needed()
        page.locator('#memoryTable').evaluate('(e)=>e.scrollTop=150')
        page.mouse.move(0,0);base=page.evaluate(geometry);box=page.locator('#processCpuChart svg').bounding_box()
        for fraction in [0,.25,.5,.75,.98]:
            page.mouse.move(box['x']+box['width']*(55/600+fraction*530/600),box['y']+30)
            current=page.evaluate(geometry)
            assert abs(current['height']-base['height'])<=.5
            assert abs(current['scrollY']-base['scrollY'])<=.5
            assert page.locator('#memoryTable').evaluate('(e)=>e.scrollTop')==150
        assert not errors,errors
        page.mouse.move(0,0);page.screenshot(path=str(OUTPUT/'dashboard-hover-fixed.png'),full_page=True)
        browser.close()
    report={'chart_width_combinations':len(results),'maximum_shift_px':max(r['max_shift_px'] for r in results),'expanded_group':'stable page and table scroll','errors':errors,'checks':results}
    (OUTPUT/'hover-validation.json').write_text(json.dumps(report,indent=2))
    print(json.dumps({k:v for k,v in report.items() if k!='checks'},indent=2))

if __name__=='__main__':main()
