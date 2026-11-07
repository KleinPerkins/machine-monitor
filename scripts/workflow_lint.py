"""Run a version- and SHA-256-pinned official actionlint binary."""
import hashlib
import io
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
import urllib.request

VERSION = '1.7.12'
ASSETS = {
    ('Darwin', 'arm64'): ('darwin_arm64', 'aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f'),
}


def lint(root):
    target, digest = ASSETS[(platform.system(), platform.machine())]
    url = f'https://github.com/rhysd/actionlint/releases/download/v{VERSION}/actionlint_{VERSION}_{target}.tar.gz'
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(20 * 1024 * 1024 + 1)
    if len(data) > 20 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError('Workflow validator checksum mismatch')
    with tempfile.TemporaryDirectory(prefix='monitor-actionlint-') as temporary:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            member = archive.getmember('actionlint')
            if not member.isfile() or member.size > 40 * 1024 * 1024:
                raise RuntimeError('Invalid workflow-validator archive')
            binary = Path(temporary) / 'actionlint'
            with archive.extractfile(member) as source:
                binary.write_bytes(source.read())
        binary.chmod(0o700)
        workflows = sorted((Path(root) / '.github/workflows').glob('*.yml'))
        if not workflows:
            raise RuntimeError('No workflows to validate')
        subprocess.run([str(binary), '-shellcheck=', *map(str, workflows)], check=True, cwd=root, timeout=30)
