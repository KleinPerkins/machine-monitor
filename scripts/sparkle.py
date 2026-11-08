"""Fetch the exact official Sparkle distribution without global installation."""
import fcntl
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
VERSION = '2.10.1'
SHA256 = '1a856d2a9edb8e628de88121d7be04cf0e2167f8641650b78fca00b14244cf27'
URL = f'https://github.com/sparkle-project/Sparkle/releases/download/{VERSION}/Sparkle-{VERSION}.tar.xz'


def _manifest(directory):
    # Bind the complete framework and signing tools, including link destinations.
    result = {}
    for root in ('Sparkle.framework', 'bin', 'LICENSE'):
        start = directory / root
        if not start.exists():
            raise ValueError('Incomplete Sparkle distribution')
        paths = [start, *start.rglob('*')] if start.is_dir() else [start]
        for path in paths:
            name = path.relative_to(directory).as_posix()
            if path.is_symlink():
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(directory.resolve()):
                    raise ValueError('Escaping Sparkle link')
                result[name] = {'link': str(path.readlink())}
            elif path.is_file():
                result[name] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'mode': path.stat().st_mode & 0o777}
    return result


def distribution(cache=None):
    cache = Path(cache or ROOT / 'build/toolchains')
    cache.mkdir(parents=True, exist_ok=True)
    if cache.is_symlink():
        raise ValueError('Sparkle cache must be a regular directory')
    target = cache / ('Sparkle-' + VERSION)
    with (cache / '.sparkle.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if target.exists():
            receipt = json.loads((target / 'verified.json').read_text())
            if target.is_symlink() or receipt != {'archive_sha256': SHA256, 'files': _manifest(target)}:
                raise ValueError('Cached Sparkle distribution changed')
            return target
        with urllib.request.urlopen(URL, timeout=40) as response:
            payload = response.read(40 * 1024**2 + 1)
        if len(payload) > 40 * 1024**2 or hashlib.sha256(payload).hexdigest() != SHA256:
            raise ValueError('Sparkle archive checksum mismatch')
        with tempfile.TemporaryDirectory(prefix='sparkle-stage-', dir=cache) as temporary:
            staging = Path(temporary)
            with tarfile.open(fileobj=io.BytesIO(payload), mode='r:xz') as archive:
                members = archive.getmembers()
                if len(members) > 20000 or sum(member.size for member in members) > 512 * 1024**2:
                    raise ValueError('Sparkle archive exceeds limits')
                for member in members:
                    if Path(member.name).is_absolute() or '..' in Path(member.name).parts:
                        raise ValueError('Unsafe Sparkle archive path')
                archive.extractall(staging, filter='data')
            receipt = {'archive_sha256': SHA256, 'files': _manifest(staging)}
            (staging / 'verified.json').write_text(json.dumps(receipt, sort_keys=True) + '\n')
            # Rename the owned staging directory; never remove an unknown cache.
            staging.rename(target)
        return target
