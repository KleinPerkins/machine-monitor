#!/usr/bin/env python3
"""Build a self-contained, locally signed arm64 macOS app. No installation side effects."""
import argparse
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import sysconfig
from scripts.processes import run_build

ROOT = Path(__file__).resolve().parent

def run(*args):
    environment = dict(os.environ, PYINSTALLER_CONFIG_DIR=str(ROOT / 'build' / 'pyinstaller-cache'))
    run_build([str(arg) for arg in args], cwd=ROOT, env=environment)

def build(reuse_helper=False):
    build_dir = ROOT / 'build'
    build_dir.mkdir(exist_ok=True)
    frozen = build_dir / 'frozen' / 'monitor-service'
    if not reuse_helper:
        args = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir', '--noupx',
                '--name', 'monitor-service', '--distpath', build_dir / 'frozen',
                '--workpath', build_dir / 'freezer', '--specpath', build_dir,
                '--copy-metadata', 'psutil']
        for asset in ('index.html', 'app.js', 'style.css'):
            args += ['--add-data', f'{ROOT / asset}:.']
        run(*args, ROOT / 'monitor.py')
    if not (frozen / 'monitor-service').exists():
        raise RuntimeError('Frozen service is missing; run without --reuse-helper')
    app = ROOT / 'dist' / 'Machine Monitor.app'
    # Only replace our generated build output, never an installed app.
    if app.exists(): shutil.rmtree(app)
    contents = app / 'Contents'
    resources = contents / 'Resources'
    executable = contents / 'MacOS' / 'Machine Monitor'
    executable.parent.mkdir(parents=True)
    resources.mkdir()
    shutil.copytree(frozen, resources / 'service', symlinks=True)
    cache = build_dir / 'swift-cache'
    run('xcrun', 'swiftc', ROOT / 'mac' / 'MachineMonitor.swift', '-O', '-target', 'arm64-apple-macosx26.0',
        '-framework', 'AppKit', '-framework', 'WebKit', '-module-cache-path', cache, '-o', executable)
    icon_builder = build_dir / 'make-icon'
    run('xcrun', 'swiftc', ROOT / 'mac' / 'MakeIcon.swift', '-framework', 'AppKit',
        '-module-cache-path', cache, '-o', icon_builder)
    iconset = build_dir / 'Monitor.iconset'
    run(icon_builder, iconset)
    run('iconutil', '-c', 'icns', iconset, '-o', resources / 'Monitor.icns')
    info = dict(CFBundleDevelopmentRegion='en', CFBundleExecutable='Machine Monitor',
        CFBundleIdentifier='com.kleinperkins.machine-monitor', CFBundleName='Machine Monitor',
        CFBundleDisplayName='Machine Monitor', CFBundlePackageType='APPL', CFBundleVersion='1',
        CFBundleShortVersionString='1.0', CFBundleIconFile='Monitor',
        LSMinimumSystemVersion='26.0', LSApplicationCategoryType='public.app-category.utilities',
        NSHighResolutionCapable=True, NSPrincipalClass='NSApplication',
        NSAppTransportSecurity=dict(NSAllowsLocalNetworking=True),
        NSHumanReadableCopyright='Copyright 2026 KleinPerkins. All rights reserved. Third-party notices included.')
    (contents / 'Info.plist').write_bytes(plistlib.dumps(info))
    licenses = resources / 'Licenses'
    licenses.mkdir()
    shutil.copy2(ROOT / 'THIRD-PARTY-NOTICES.md', licenses)
    shutil.copy2(ROOT / 'LICENSE', licenses)
    for package in ('psutil', 'pyinstaller'):
        distribution = metadata.distribution(package)
        for file in distribution.files or []:
            if file.name in ('LICENSE', 'COPYING.txt'):
                shutil.copy2(distribution.locate_file(file), licenses / f'{package}-{file.name}')
    # Homebrew ships CPython's complete license alongside its Frameworks directory.
    prefix = Path(sysconfig.get_config_var('prefix')).resolve()
    candidates = [Path(sysconfig.get_path('stdlib')) / 'LICENSE.txt', prefix / 'LICENSE.txt',
                  *[p / 'LICENSE' for p in prefix.parents]]
    python_license = next((p for p in candidates if p.is_file()), None)
    if python_license is None: raise RuntimeError('Could not locate CPython license')
    shutil.copy2(python_license, licenses / 'Python-LICENSE.txt')
    (resources / 'build-info.json').write_text(json.dumps(dict(
        python=sys.version.split()[0], psutil=metadata.version('psutil'),
        pyinstaller=metadata.version('pyinstaller'), architecture='arm64', minimum_macos='26.0'), indent=2))
    run('codesign', '--force', '--deep', '--sign', '-', app)
    run('codesign', '--verify', '--deep', '--strict', app)
    print(f'Built {app}', flush=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--reuse-helper', action='store_true', help='Rebuild native shell using a previously frozen service')
    build(parser.parse_args().reuse_helper)
