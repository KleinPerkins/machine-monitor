"""Build a separate native test bundle whose service can only emit synthetic data.

Production build_mac_app.py always freezes monitor.py. This harness freezes a
separate test entrypoint, then packages it in a temporary source copy. It never
modifies an installed app or the production build output.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile

from scripts.processes import run_build

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('monitor.py', 'temperatures.py', 'index.html', 'app.js', 'style.css',
           'build_mac_app.py', 'THIRD-PARTY-NOTICES.md', 'LICENSE', 'PRIVATE-BINARY-LICENSE',
           'update_contract.py', 'update_preflight.py', 'update_recovery.py',
           'mac/MachineMonitor.swift', 'mac/MakeIcon.swift', 'mac/RecoveryMain.swift', 'mac/RecoveryModel.swift',
           'mac/UpdateCore.swift', 'mac/UpdateTransport.swift', 'mac/UpdateBridge.swift', 'mac/UpdateState.swift',
           'mac/UpdateHelper.swift', 'mac/UpdateSparkle.swift', 'mac/UpdateCoordinator.swift', 'mac/UpdateSettings.swift', 'mac/UpdateJSON.swift',
           'scripts/__init__.py', 'scripts/processes.py', 'scripts/sparkle.py',
           'tests/__init__.py', 'tests/fixtures.py', 'tests/fixture_service.py')


def build(destination):
    destination = Path(destination).resolve()
    if destination.exists():
        raise FileExistsError('Fixture output must be a fresh path')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='monitor-fixture-build-', dir=destination.parent) as temporary:
        root = Path(temporary)
        for name in SOURCES:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, path)
        spec = importlib.util.spec_from_file_location('fixture_app_builder', root / 'build_mac_app.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # Qualify the unchanged production entrypoint too; never launch it in CI.
        module.build()
        run_build(['codesign', '--verify', '--deep', '--strict', str(root / 'dist/Machine Monitor.app')])
        shutil.rmtree(root / 'dist')
        shutil.rmtree(root / 'build/frozen')
        args = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir', '--noupx',
                '--name', 'monitor-service', '--paths', str(root),
                '--distpath', str(root / 'build/frozen'), '--workpath', str(root / 'build/freezer'),
                '--specpath', str(root / 'build'), '--copy-metadata', 'psutil']
        for asset in ('index.html', 'app.js', 'style.css'):
            args += ['--add-data', f'{root / asset}:.']
        environment = dict(os.environ, PYINSTALLER_CONFIG_DIR=str(root / 'build/pyinstaller-cache'))
        run_build(args + [str(root / 'tests/fixture_service.py')], cwd=root, env=environment)
        module.build(reuse_helper=True)
        app = root / 'dist/Machine Monitor.app'
        plist = app / 'Contents/Info.plist'
        info = plistlib.loads(plist.read_bytes())
        info['CFBundleIdentifier'] = 'com.kleinperkins.machine-monitor.fixture-tests'
        info['CFBundleDisplayName'] = 'Machine Monitor Fixture Tests'
        plist.write_bytes(plistlib.dumps(info))
        run_build(['codesign', '--force', '--deep', '--sign', '-', str(app)])
        run_build(['codesign', '--verify', '--deep', '--strict', str(app)])
        shutil.copytree(app, destination, symlinks=True)
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('destination')
    print(build(parser.parse_args().destination))
