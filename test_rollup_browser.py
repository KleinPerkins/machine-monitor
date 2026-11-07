"""Live parent rollup accounting and interactive drilldown acceptance checks."""
import os
import json
import math
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parent
URL=os.environ.get('MONITOR_TEST_URL')
OUTPUT=Path(os.environ.get('MONITOR_TEST_OUTPUT',ROOT/'outputs'))

def main():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    if not URL: raise RuntimeError('Run this regression through tests/browser_support.py')
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True)
        context=browser.new_context(viewport={'width':1440,'height':1100},color_scheme='dark')
        page=context.new_page();errors=[]
        page.on('pageerror',lambda e:errors.append(str(e)))
        page.on('console',lambda m:errors.append(m.text) if m.type=='error' else None)
        page.goto(URL+'/');page.wait_for_load_state('networkidle')
        assert not page.evaluate("fetch('/api/state').then(r=>r.json())")['active']
        page.get_by_role('button',name='Start 30-second scan').click();page.wait_for_timeout(4200)
        page.get_by_role('button',name='Stop scan',exact=True).click();page.wait_for_timeout(250)
        state=page.evaluate("fetch('/api/state').then(r=>r.json())")
        assert not state['active'] and len(state['frames'])>=4
        for f in state['frames']:
            by_id={p['id']:p for p in f['processes']};seen=[]
            for g in f['process_groups']:
                members=[by_id[m['id']] for m in g['members']];seen.extend(p['id'] for p in members)
                assert g['rss']==sum(p['rss'] for p in members)
                assert g['threads']==sum(p['threads'] for p in members)
                assert math.isclose(g['memory_pct'],sum(p['memory_pct'] for p in members))
                known=[p['cpu'] for p in members if p['cpu'] is not None]
                assert g['cpu']==(sum(known) if known else None)
            assert len(seen)==len(set(seen))==len(by_id)
            assert sum(g['rss'] for g in f['process_groups'])==sum(p['rss'] for p in f['processes'])
        f=state['frames'][-1]
        assert any(g['count']>1 for g in f['process_groups'])
        memory=page.locator('#memoryTable');expand=memory.locator('[data-expand]').first
        ident=expand.get_attribute('data-expand');group=next(g for g in f['process_groups'] if g['id']==ident)
        expand.click();assert memory.locator('.member-row').count()==group['count']
        assert memory.locator('[data-expand]').first.get_attribute('aria-expanded')=='true'
        ids=memory.locator('.member-row').evaluate_all('(rows)=>rows.map(r=>r.dataset.rowId)')
        assert set(ids)=={m['id'] for m in group['members']}
        memory.locator(f'.group-row [data-process="{ident}"]').click()
        assert 'process group' in page.locator('#processTitle').inner_text()
        assert page.locator('#processChart svg').count()==1
        assert page.locator('#processCpuChart svg').count()==1
        assert 'processes' in page.locator('#processInfo').inner_text()
        memory.locator('.member-row [data-process]').first.click()
        assert 'process group' not in page.locator('#processTitle').inner_text()
        assert 'Individual process' in page.locator('#processInfo').inner_text()
        memory.locator('[data-expand]').first.click();assert memory.locator('.member-row').count()==0
        page.locator('#cpuChart').focus();page.keyboard.press('ArrowLeft')
        assert 'historical observation' in page.locator('#cursorLabel').inner_text()
        historical=state['frames'][-2]
        expected=max(historical['process_groups'],key=lambda g:g['rss'])
        assert memory.locator('.group-row').first.get_attribute('data-row-id')==expected['id']
        page.get_by_role('button',name='Return to latest').click()
        memory.locator('[data-sort="cpu"]').click()
        expected=max(f['process_groups'],key=lambda g:g['cpu'] or 0)
        assert memory.locator('.group-row').first.get_attribute('data-row-id')==expected['id']
        page.screenshot(path=str(OUTPUT/'dashboard-rollup.png'),full_page=True)
        for width in [820,360,320]:
            page.set_viewport_size({'width':width,'height':1100})
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
        assert not errors,errors
        result={'frames_checked':len(state['frames']),'observed_processes':len(f['processes']),'parent_groups':len(f['process_groups']),
            'expanded_group':group['name'],'expanded_members':group['count'],'group_cpu':group['cpu'],'group_rss_bytes':group['rss'],
            'accounting':'all processes counted once; CPU/RSS/RAM-percent/threads match member sums',
            'interactions':'expand/collapse, group and member charts, historical cursor and group sorting passed',
            'layouts':'1440/820/360/320px; no page overflow','console_errors':errors,'active_after_test':state['active']}
        browser.close()
    (OUTPUT/'rollup-validation.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
