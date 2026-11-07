"""Verify live temperatures, disclosure, hover and honest missing-sensor views."""
import os
import copy
import json
import math
from pathlib import Path
import psutil
from playwright.sync_api import sync_playwright
from temperatures import summarize

ROOT=Path(__file__).resolve().parent;
def get_state(page):return page.evaluate("fetch('/api/state').then(r=>r.json())")
URL=os.environ.get('MONITOR_TEST_URL')
OUTPUT=Path(os.environ.get('MONITOR_TEST_OUTPUT',ROOT/'outputs'))

def main():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    if not URL: raise RuntimeError('Run this regression through tests/browser_support.py')
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True)
        context=browser.new_context(viewport={'width':1200,'height':1000},color_scheme='dark')
        page=context.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(URL);page.wait_for_load_state('networkidle')
        page.locator('#start').click();page.wait_for_timeout(5200);page.get_by_role('button',name='Stop scan',exact=True).click()
        s=get_state(page);assert not s['active'] and s['count']>=5
        for f in s['frames']:
            t=f['temperatures']
            for component,count in [('cpu',12),('gpu',2)]:
                readings=[x['celsius'] for x in t[component+'_sensors']]
                assert len(readings)==count and all(0<v<=150 for v in readings)
                assert math.isclose(t[component+'_c'],sum(readings)/len(readings))
                assert t[component+'_max_c']==max(readings)
        assert '°C' in page.locator('#cpuTemperature').inner_text()
        assert '°C' in page.locator('#gpuTemperature').inner_text()
        page.locator('#temperatureSensorDetails summary').click()
        assert page.locator('#temperatureSensorTable tbody tr').count()==14
        page.locator('#temperatureChart').scroll_into_view_if_needed();page.mouse.move(0,0)
        before=page.evaluate('({y:scrollY,h:document.documentElement.scrollHeight})')
        chart=page.locator('#temperatureChart svg').bounding_box()
        for fraction in [0,.25,.5,.75,.98]:
            page.mouse.move(chart['x']+chart['width']*(55/600+fraction*530/600),chart['y']+60)
            assert 'CPU average:' in page.locator('#temperatureChart .chart-readout').inner_text()
            after=page.evaluate('({y:scrollY,h:document.documentElement.scrollHeight})')
            assert before==after,(before,after)
        page.mouse.move(0,0)
        page.screenshot(path=str(OUTPUT/'dashboard-temperatures.png'),full_page=True)
        for width in [1440,820,736,360,320]:
            page.set_viewport_size({'width':width,'height':1000})
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
        # Simulate a missing reading without altering the collector or its live state.
        fixture=copy.deepcopy(s)
        for f in fixture['frames']:f['temperatures']=summarize({},at=f['at'],error='Sensor read unavailable')
        missing=context.new_page();missing.route('**/api/state',lambda r:r.fulfill(content_type='application/json',body=json.dumps(fixture)))
        missing.goto(URL);missing.wait_for_load_state('networkidle')
        assert missing.locator('#cpuTemperature').inner_text()=='Unavailable'
        assert missing.locator('#gpuTemperature').inner_text()=='Unavailable'
        assert 'unavailable' in missing.locator('#temperatureChart .chart-readout').inner_text()
        missing.set_viewport_size({'width':320,'height':1000})
        assert missing.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
        missing.close();page.close()
        proc=psutil.Process(s['service_pid']);assert proc.num_threads()==2
        assert not errors,errors
        result={'samples':s['count'],'last_temperatures':s['frames'][-1]['temperatures'],
            'hover':'no page movement across temperature observations','missing_readings':'unavailable; no fabricated zero',
            'layouts':'1440/820/736/360/320px; no overflow','dormant_service_threads':proc.num_threads(),'errors':errors}
        browser.close()
    (OUTPUT/'temperature-validation.json').write_text(json.dumps(result,indent=2))
    print(json.dumps({k:v for k,v in result.items() if k!='last_temperatures'},indent=2))
    print('CPU average/max:',result['last_temperatures']['cpu_c'],result['last_temperatures']['cpu_max_c'])
    print('GPU average/max:',result['last_temperatures']['gpu_c'],result['last_temperatures']['gpu_max_c'])

if __name__=='__main__':main()
