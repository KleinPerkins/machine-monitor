#!/usr/bin/env python3
"""Build a self-contained, locally signed arm64 macOS app. No installation side effects."""
import argparse
import base64
import importlib.metadata as metadata
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import sysconfig
from urllib.parse import urlsplit
from scripts.processes import run_build
from scripts.sparkle import distribution as sparkle_distribution
from update_contract import version_tuple

ROOT = Path(__file__).resolve().parent

def run(*args):
    environment = dict(os.environ, PYINSTALLER_CONFIG_DIR=str(ROOT / 'build' / 'pyinstaller-cache'))
    run_build([str(arg) for arg in args], cwd=ROOT, env=environment)

def update_settings(path):
    if path is None:
        return {}
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        raise ValueError('Update configuration must be a bounded regular JSON file')
    from update_contract import read_request
    value = read_request(io.BytesIO(path.read_bytes()))
    if set(value) != {'origin', 'channel', 'public_ed25519_key'}:
        raise ValueError('Update configuration contains unsupported fields')
    url = urlsplit(value['origin'])
    if (url.scheme != 'https' or not url.hostname or url.netloc != url.hostname or
            url.path or url.query or url.fragment or url.username or url.password):
        raise ValueError('Update origin must be canonical HTTPS on the default port')
    if value['channel'] not in ('stable', 'qualification'):
        raise ValueError('Unsupported update channel')
    key = base64.b64decode(value['public_ed25519_key'], validate=True)
    if len(key) != 32 or base64.b64encode(key).decode() != value['public_ed25519_key']:
        raise ValueError('Expected a canonical 32-byte public update key')
    return dict(MachineMonitorUpdateOrigin=value['origin'], MachineMonitorUpdateChannel=value['channel'],
                SUPublicEDKey=value['public_ed25519_key'])


def source_revision():
    result = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], capture_output=True, text=True)
    value = result.stdout.strip()
    return value if result.returncode == 0 and len(value) == 40 else 'unversioned'


def arm64_framework(directory):
    """Thin only our generated copy; never mutate the verified dependency cache."""
    magic = {bytes.fromhex(s) for s in ('feedface', 'feedfacf', 'cefaedfe', 'cffaedfe', 'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca')}
    for path in sorted(directory.rglob('*')):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as source:
            if source.read(4) not in magic:
                continue
        architectures = subprocess.check_output(['xcrun', 'lipo', '-archs', str(path)], text=True).split()
        if 'arm64' not in architectures:
            raise RuntimeError('Sparkle contains a binary without arm64 support')
        if architectures != ['arm64']:
            temporary = path.with_name(path.name + '.arm64-stage')
            if temporary.exists():
                raise FileExistsError('Unexpected framework staging output')
            mode = path.stat().st_mode & 0o777
            run('xcrun', 'lipo', path, '-thin', 'arm64', '-output', temporary)
            temporary.chmod(mode)
            temporary.replace(path)


def build(reuse_helper=False, *, version='1.1.0', build_number=2, update_config=None):
    version_tuple(version)
    if type(build_number) is not int or not 1 <= build_number < 2**31:
        raise ValueError('Build number must be a positive integer')
    settings = update_settings(update_config)
    revision = source_revision()
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
    sparkle = sparkle_distribution()
    frameworks = contents / 'Frameworks'
    frameworks.mkdir()
    shutil.copytree(sparkle / 'Sparkle.framework', frameworks / 'Sparkle.framework', symlinks=True)
    arm64_framework(frameworks / 'Sparkle.framework')
    cache = build_dir / 'swift-cache'
    native_sources = sorted((ROOT / 'mac').glob('Update*.swift'))
    if not native_sources:
        raise RuntimeError('Native updater sources are missing')
    run('xcrun', 'swiftc', '-swift-version', '5', '-parse-as-library', ROOT / 'mac' / 'MachineMonitor.swift',
        *native_sources, '-O', '-target', 'arm64-apple-macosx26.0', '-F', frameworks,
        '-framework', 'AppKit', '-framework', 'WebKit', '-framework', 'Security', '-framework', 'Sparkle',
        '-Xlinker', '-rpath', '-Xlinker', '@executable_path/../Frameworks',
        '-module-cache-path', cache, '-o', executable)
    icon_builder = build_dir / 'make-icon'
    run('xcrun', 'swiftc', ROOT / 'mac' / 'MakeIcon.swift', '-framework', 'AppKit',
        '-module-cache-path', cache, '-o', icon_builder)
    iconset = build_dir / 'Monitor.iconset'
    run(icon_builder, iconset)
    run('iconutil', '-c', 'icns', iconset, '-o', resources / 'Monitor.icns')
    info = dict(CFBundleDevelopmentRegion='en', CFBundleExecutable='Machine Monitor',
        CFBundleIdentifier='com.kleinperkins.machine-monitor', CFBundleName='Machine Monitor',
        CFBundleDisplayName='Machine Monitor', CFBundlePackageType='APPL', CFBundleVersion=str(build_number),
        CFBundleShortVersionString=version, CFBundleIconFile='Monitor',
        LSMinimumSystemVersion='26.0', LSApplicationCategoryType='public.app-category.utilities',
        NSHighResolutionCapable=True, NSPrincipalClass='NSApplication',
        NSAppTransportSecurity=dict(NSAllowsLocalNetworking=True), MachineMonitorDataSchemaVersion=1,
        MachineMonitorSourceRevision=revision, SUEnableAutomaticChecks=False, SUAllowsAutomaticUpdates=True,
        SUAutomaticallyUpdate=True, SUVerifyUpdateBeforeExtraction=True,
        CFBundleDocumentTypes=[dict(CFBundleTypeName='Machine Monitor Update Access', CFBundleTypeRole='Viewer',
            LSHandlerRank='Owner', LSItemContentTypes=['com.kleinperkins.machine-monitor.update-access'])],
        UTExportedTypeDeclarations=[dict(UTTypeIdentifier='com.kleinperkins.machine-monitor.update-access',
            UTTypeDescription='Machine Monitor Update Access', UTTypeConformsTo=['public.json'],
            UTTypeTagSpecification={'public.filename-extension':['machine-monitor-access']})],
        NSHumanReadableCopyright='Copyright 2026 KleinPerkins. All rights reserved. Third-party notices included.')
    info.update(settings)
    (contents / 'Info.plist').write_bytes(plistlib.dumps(info))
    licenses = resources / 'Licenses'
    licenses.mkdir()
    shutil.copy2(ROOT / 'THIRD-PARTY-NOTICES.md', licenses)
    shutil.copy2(ROOT / 'LICENSE', licenses)
    shutil.copy2(ROOT / 'PRIVATE-BINARY-LICENSE', licenses)
    shutil.copy2(sparkle / 'LICENSE', licenses / 'Sparkle-LICENSE')
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
        pyinstaller=metadata.version('pyinstaller'), sparkle='2.10.1', architecture='arm64', minimum_macos='26.0',
        version=version, build=build_number, source_revision=revision, updates_configured=bool(settings)), indent=2))
    run('codesign', '--force', '--deep', '--sign', '-', app)
    run('codesign', '--verify', '--deep', '--strict', app)
    recovery = ROOT / 'dist' / 'Machine Monitor Recovery.app'
    if recovery.exists(): shutil.rmtree(recovery)
    recovery_contents = recovery / 'Contents'
    recovery_resources = recovery_contents / 'Resources'
    recovery_executable = recovery_contents / 'MacOS/Machine Monitor Recovery'
    recovery_executable.parent.mkdir(parents=True)
    recovery_resources.mkdir()
    shutil.copytree(frozen, recovery_resources / 'service', symlinks=True)
    shutil.copytree(licenses, recovery_resources / 'Licenses')
    shutil.copy2(resources / 'Monitor.icns', recovery_resources / 'Monitor.icns')
    run('xcrun', 'swiftc', '-swift-version', '5', '-parse-as-library', ROOT / 'mac/RecoveryModel.swift',
        ROOT / 'mac/RecoveryMain.swift', '-O', '-target', 'arm64-apple-macosx26.0',
        '-framework', 'AppKit', '-framework', 'Security', '-module-cache-path', cache, '-o', recovery_executable)
    recovery_info = dict(CFBundleDevelopmentRegion='en', CFBundleExecutable='Machine Monitor Recovery',
        CFBundleIdentifier='com.kleinperkins.machine-monitor.recovery', CFBundleName='Machine Monitor Recovery',
        CFBundleDisplayName='Machine Monitor Recovery', CFBundlePackageType='APPL',
        CFBundleVersion=str(build_number), CFBundleShortVersionString=version, CFBundleIconFile='Monitor',
        LSMinimumSystemVersion='26.0', NSHighResolutionCapable=True, NSPrincipalClass='NSApplication',
        MachineMonitorDataSchemaVersion=1, MachineMonitorSourceRevision=revision,
        NSHumanReadableCopyright=info['NSHumanReadableCopyright'])
    (recovery_contents / 'Info.plist').write_bytes(plistlib.dumps(recovery_info))
    run('codesign', '--force', '--deep', '--sign', '-', recovery)
    run('codesign', '--verify', '--deep', '--strict', recovery)
    print(f'Built {app}', flush=True)
    print(f'Built {recovery}', flush=True)
    return app, recovery

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--reuse-helper', action='store_true', help='Rebuild native shell using a previously frozen service')
    parser.add_argument('--version', default='1.1.0')
    parser.add_argument('--build-number', type=int, default=2)
    parser.add_argument('--update-config', type=Path, help='Public origin/channel/key inputs; never a credential file')
    options = parser.parse_args()
    build(options.reuse_helper, version=options.version, build_number=options.build_number, update_config=options.update_config)
