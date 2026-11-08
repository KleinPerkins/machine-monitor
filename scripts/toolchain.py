"""Pinned, credential-free verification runtimes; no global installation."""
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
NODE_VERSION = '26.4.0'
NODE_ARCHIVE = f'node-v{NODE_VERSION}-darwin-arm64.tar.xz'
NODE_SHA256 = 'bef4c7e75087c029835f519a7ba640eba52fa617fadb3a9049828ff3b45b57dd'
MAX_ARCHIVE = 100 * 1024**2
MAX_EXPANDED = 512 * 1024**2


def download_bytes(url, maximum, timeout):
    """Retry transient transport failures three times, retaining no partial body.

    Callers still verify the size and pinned digest before extracting any bytes.
    Permanent HTTP errors, TLS validation and content failures do not retry.
    """
    for attempt, delay in enumerate((0, 1, 3)):
        if delay:
            time.sleep(delay)
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                return response.read(maximum + 1)
        except urllib.error.HTTPError as error:
            error.close()
            if error.code not in (500, 502, 503, 504) or attempt == 2:
                raise
        except urllib.error.URLError as error:
            if not isinstance(error.reason, (TimeoutError, ConnectionResetError, ConnectionAbortedError)) or attempt == 2:
                raise
        except (TimeoutError, ConnectionResetError, ConnectionAbortedError):
            if attempt == 2:
                raise


def _version(binary):
    result = subprocess.run([str(binary), '--version'], capture_output=True, text=True, timeout=10, check=True)
    if result.stdout.strip() != 'v' + NODE_VERSION:
        raise ValueError('Verification requires Node ' + NODE_VERSION)
    return Path(binary).resolve(strict=True)


def node(cache=None):
    """Use an exact installed runtime or verify/cache the official distribution."""
    configured = os.environ.get('MONITOR_NODE')
    if configured:
        return _version(configured)
    installed = shutil.which('node')
    if installed:
        try:
            return _version(installed)
        except (ValueError, subprocess.SubprocessError):
            pass
    if (platform.system(), platform.machine()) != ('Darwin', 'arm64'):
        raise RuntimeError('Pinned verification runtime requires macOS Apple Silicon')
    cache = Path(cache or ROOT / 'build/toolchains')
    cache.mkdir(parents=True, exist_ok=True)
    if cache.is_symlink():
        raise ValueError('Toolchain cache must be a regular directory')
    target = cache / f'node-v{NODE_VERSION}'
    with (cache / '.node.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if target.exists():
            receipt = json.loads((target / 'verified.json').read_text())
            binary = target / 'bin/node'
            if target.is_symlink() or binary.is_symlink() or receipt != {
                'archive_sha256': NODE_SHA256,
                'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            }:
                raise ValueError('Cached verification runtime changed')
            return _version(binary)
        payload = download_bytes(f'https://nodejs.org/dist/v{NODE_VERSION}/{NODE_ARCHIVE}', MAX_ARCHIVE, 30)
        if len(payload) > MAX_ARCHIVE or hashlib.sha256(payload).hexdigest() != NODE_SHA256:
            raise ValueError('Verification runtime archive checksum mismatch')
        with tempfile.TemporaryDirectory(prefix='node-stage-', dir=cache) as temporary:
            staging = Path(temporary)
            with tarfile.open(fileobj=io.BytesIO(payload), mode='r:xz') as archive:
                members = archive.getmembers()
                prefix = NODE_ARCHIVE.removesuffix('.tar.xz')
                if len(members) > 10000 or sum(member.size for member in members) > MAX_EXPANDED:
                    raise ValueError('Verification runtime archive exceeds limits')
                for member in members:
                    parts = Path(member.name).parts
                    if not parts or parts[0] != prefix or '..' in parts or Path(member.name).is_absolute():
                        raise ValueError('Unsafe verification runtime archive path')
                archive.extractall(staging, filter='data')
            unpacked = staging / prefix
            binary = _version(unpacked / 'bin/node')
            receipt = {'archive_sha256': NODE_SHA256, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
            (unpacked / 'verified.json').write_text(json.dumps(receipt, sort_keys=True) + '\n')
            unpacked.rename(target)
        return _version(target / 'bin/node')
