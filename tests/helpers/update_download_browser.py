"""Actual HTTPS Worker + isolated Chromium lifecycle/layout fixtures. No live auth."""
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests.test_update_channel import node


@contextmanager
def browser_fixture():
    with tempfile.TemporaryDirectory(prefix='monitor-download-fixture-') as temporary:
        folder = Path(temporary).resolve()
        key, cert = folder / 'fixture.key', folder / 'fixture.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-keyout', str(key), '-out', str(cert), '-subj', '/CN=127.0.0.1'],
            check=True, capture_output=True, timeout=15)
        process = subprocess.Popen([node(), str(ROOT / 'tests/helpers/update_download_server.mjs'), str(key), str(cert)],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            if not select.select([process.stdout], [], [], 15)[0]:
                raise AssertionError('Synthetic HTTPS Worker did not become ready.')
            info = json.loads(process.stdout.readline())
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True, viewport={'width': 1280, 'height': 1000},
                    accept_downloads=False, reduced_motion='reduce')
                try:
                    page = context.new_page()
                    errors = []
                    page.on('pageerror', lambda error: errors.append(str(error)))
                    page.goto(info['origin'])
                    page.wait_for_function("typeof document.querySelector('#download').onclick === 'object'")
                    yield page, context, info
                    assert errors == [], errors
                finally:
                    context.close()
                    browser.close()
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()


def choose(page, access):
    page.locator('#access').set_input_files({'name': 'fixture.machine-monitor-access', 'mimeType': 'application/json',
                                          'buffer': json.dumps(access).encode()})
    expect(page.locator('#status')).to_contain_text('Access file selected')
    assert page.locator('#access').input_value() == ''


def mode(context, info, value):
    response = context.request.post(info['origin'] + '/fixture-state', data={'mode': value})
    assert response.ok


def screenshot(page, name):
    output = os.environ.get('MONITOR_TEST_OUTPUT')
    if output:
        root = Path(output)
        root.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(root / name), full_page=True)


def layout():
    with browser_fixture() as (page, context, info):
        expect(page.get_by_role('heading', name='A clear view of your Mac.')).to_be_visible()
        expect(page.locator('#download')).to_be_disabled()
        assert page.locator('#status').get_attribute('aria-live') == 'polite'
        for scheme in ('light', 'dark'):
            page.emulate_media(color_scheme=scheme, reduced_motion='reduce')
            for width in (360, 768, 1280):
                page.set_viewport_size({'width': width, 'height': 1000})
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), (scheme, width)
                assert page.locator('#access').bounding_box()['width'] <= width
                before = page.locator('#download').bounding_box()
                page.locator('#download').hover(force=True)
                assert page.locator('#download').bounding_box() == before
                screenshot(page, f'download-{scheme}-{width}.png')
        page.set_viewport_size({'width': 360, 'height': 1000})
        page.locator('#access').focus()
        assert page.locator('#access').evaluate("e=>getComputedStyle(e).outlineStyle") != 'none'
        page.keyboard.press('Tab')
        expect(page.locator('#reset')).to_be_focused()
        # Invalid and revoked states remain readable at phone width.
        page.locator('#access').set_input_files({'name': 'bad.machine-monitor-access', 'mimeType': 'application/json', 'buffer': b'{}'})
        expect(page.locator('#status')).to_contain_text('Invalid access file')
        screenshot(page, 'download-invalid-360.png')
        choose(page, info['access'])
        mode(context, info, 'revoked')
        page.locator('#download').click()
        expect(page.locator('#status')).to_contain_text('Access expired or revoked')
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        screenshot(page, 'download-revoked-360.png')


def lifecycle():
    with browser_fixture() as (page, context, info):
        # Observe lifecycle only; no token is returned by a production endpoint.
        page.evaluate("""() => {window.fixtureURLs={created:0,revoked:0};const c=URL.createObjectURL.bind(URL),r=URL.revokeObjectURL.bind(URL);URL.createObjectURL=b=>{window.fixtureURLs.created++;return c(b)};URL.revokeObjectURL=u=>{window.fixtureURLs.revoked++;r(u)}}""")
        requests = []
        page.on('request', lambda r: requests.append(r.url))
        choose(page, info['access'])
        page.locator('#download').click()
        expect(page.locator('#status')).to_contain_text('Download verified')
        expect(page.locator('#save')).to_be_visible()
        assert page.locator('#save').get_attribute('href').startswith('blob:')
        assert all(info['access']['token'] not in url for url in requests)
        assert page.evaluate('localStorage.length + sessionStorage.length') == 0
        assert context.cookies() == []
        page.locator('#reset').click()
        expect(page.locator('#download')).to_be_disabled()
        expect(page.locator('#save')).to_be_hidden()
        assert page.locator('#save').get_attribute('href') is None
        assert page.evaluate('window.fixtureURLs') == {'created': 1, 'revoked': 1}
        # Reset while streaming cancels the request and ignores its completion.
        mode(context, info, 'slow')
        choose(page, info['access'])
        page.locator('#download').click()
        expect(page.locator('#progress')).to_be_visible()
        assert float(page.locator('#progress').get_attribute('value')) > 0
        page.locator('#reset').click()
        expect(page.locator('#status')).to_contain_text('Choose your access file')
        page.wait_for_timeout(1700)
        expect(page.locator('#save')).to_be_hidden()
        assert context.request.get(info['origin'] + '/fixture-state').json()['aborted'] >= 1
        # Retry exposes meaningful failures and does not persist access.
        for failure, message in (('revoked', 'Access expired or revoked'), ('tamper', 'verification failed'),
                                 ('short', 'temporarily unavailable'), ('offline', 'interrupted or unavailable'),
                                 ('redirect', 'interrupted or unavailable')):
            mode(context, info, failure)
            choose(page, info['access'])
            page.locator('#download').click()
            expect(page.locator('#status')).to_contain_text(message)
            expect(page.locator('#save')).to_be_hidden()
            expect(page.locator('#download')).to_be_enabled()
        # A successful retry works with the selected in-memory file.
        mode(context, info, 'normal')
        page.locator('#download').click()
        expect(page.locator('#status')).to_contain_text('Download verified')
        # Pagehide aborts owned requests and releases object URLs/credential refs.
        page.evaluate("window.dispatchEvent(new Event('pagehide'))")
        expect(page.locator('#download')).to_be_disabled()
        expect(page.locator('#save')).to_be_hidden()
        assert page.evaluate('window.fixtureURLs.created === window.fixtureURLs.revoked')
        page.reload()
        expect(page.locator('#download')).to_be_disabled()
        assert page.evaluate('localStorage.length + sessionStorage.length') == 0

if __name__ == '__main__':
    {'layout': layout, 'lifecycle': lifecycle}[sys.argv[1]]()
