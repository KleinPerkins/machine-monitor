"""Bounded archive inspection and Apple code identity verification; no collector imports.

Native verifies publisher Ed25519 before invoking this module. CLI does not accept
an injectable verifier. Tests may inject identity verification into Python functions.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import time
import unicodedata
import zipfile

from update_contract import APP_ID, TEAM_ID, UpdateError, read_request, validate_manifest, integer, version_tuple

MAX_ENTRIES = 20000
MAX_EXPANDED = 2 * 1024**3
MAX_RATIO = 200
MAX_SECONDS = 120
DISK_RESERVE = 64 * 1024**2


def run_checked(args):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
    except (OSError,subprocess.SubprocessError):
        raise UpdateError('Apple code or platform validation failed') from None
    if len(result.stdout) > 65536 or len(result.stderr) > 65536:
        raise UpdateError('Code validation output limit exceeded')
    return result.stdout.decode('utf-8',errors='strict').strip()


def verify_identity(app, expected=None):
    """Require actual Apple Developer ID trust, sealed metadata and arm64 executable."""
    app = Path(app)
    if sys.platform != 'darwin':
        raise UpdateError('Apple trust validation requires macOS')
    requirement = ('anchor apple generic and certificate leaf[subject.OU] = "' + TEAM_ID + '" '
                   'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
                   'and identifier "' + APP_ID + '"')
    run_checked(['/usr/bin/codesign','--verify','--deep','--strict','-R','='+requirement,str(app)])
    run_checked(['/usr/sbin/spctl','--assess','--type','execute',str(app)])
    try:
        with (app/'Contents/Info.plist').open('rb') as stream:
            encoded=stream.read(65537)
        if len(encoded)>65536: raise ValueError()
        info = plistlib.loads(encoded)
        executable = info['CFBundleExecutable']
        if (not isinstance(executable,str) or executable != executable.strip() or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._ -]{0,127}',executable)):
            raise ValueError()
        identity = {'bundle_id':info['CFBundleIdentifier'],'team_id':TEAM_ID,
                    'version':info['CFBundleShortVersionString'],'build':int(info['CFBundleVersion']),
                    'data_schema_version':info.get('MachineMonitorDataSchemaVersion')}
        # Sealed legacy baseline used schema 1 before the field was introduced.
        if identity['data_schema_version'] is None and identity['version']=='1.0' and str(info['CFBundleVersion'])=='1':
            identity['data_schema_version']=1
        if identity['bundle_id'] != APP_ID or type(identity['data_schema_version']) is not int or identity['data_schema_version'] != 1:
            raise ValueError()
        integer(identity['build'],'build')
        version_tuple(identity['version'])
        minimum = version_tuple(info['LSMinimumSystemVersion'])
        if minimum != version_tuple('26.0'):
            raise ValueError()
        arches = run_checked(['/usr/bin/lipo','-archs',str(app/'Contents/MacOS'/executable)]).split()
        if arches != ['arm64']:
            raise ValueError()
        if expected and any(identity[key] != expected[key] for key in ('bundle_id','team_id','version','build','data_schema_version')):
            raise ValueError()
    except (KeyError,ValueError,TypeError,OSError,plistlib.InvalidFileException):
        raise UpdateError('Application identity or platform is incompatible') from None
    return identity


def checked_name(name):
    if not isinstance(name,str) or not name or '\\' in name or ':' in name or '\x00' in name or any(ord(c)<32 or ord(c)==127 for c in name):
        raise UpdateError('Unsafe archive name')
    parts = name.rstrip('/').split('/')
    if any(p in ('','.','..') for p in parts) or name.startswith('/'):
        raise UpdateError('Unsafe archive path')
    if len(name.encode('utf-8')) > 1024 or len(parts) > 64:
        raise UpdateError('Archive path limit exceeded')
    return '/'.join(parts)


def tree_digest(root):
    """Hash names, types, modes and bytes, preserving links without following them."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise UpdateError('Application must be a real directory')
    h = hashlib.sha256()
    size = 0
    count = 0
    deadline=time.monotonic()+MAX_SECONDS
    for directory, dirs, files in os.walk(root,followlinks=False):
        dirs.sort()
        for name in sorted(dirs+files):
            count += 1
            if time.monotonic()>deadline: raise UpdateError('Application verification time limit exceeded')
            if count > MAX_ENTRIES:
                raise UpdateError('Application entry limit exceeded')
            path = Path(directory)/name
            s = path.lstat()
            relative = path.relative_to(root).as_posix()
            h.update(relative.encode()+b'\0'+str(stat.S_IMODE(s.st_mode)).encode()+b'\0')
            if stat.S_ISLNK(s.st_mode):
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(root.resolve()):
                    raise UpdateError('Application symlink escapes bundle')
                link=os.readlink(path).encode()
                size+=len(link)
                if size>MAX_EXPANDED: raise UpdateError('Application size limit exceeded')
                h.update(b'L'+link+b'\0')
            elif stat.S_ISDIR(s.st_mode):
                h.update(b'D')
            elif stat.S_ISREG(s.st_mode) and s.st_nlink == 1:
                h.update(b'F'+str(s.st_size).encode()+b'\0')
                with path.open('rb') as f:
                    for chunk in iter(lambda:f.read(1024*1024),b''):
                        size += len(chunk)
                        if time.monotonic()>deadline: raise UpdateError('Application verification time limit exceeded')
                        if size > MAX_EXPANDED:
                            raise UpdateError('Application size limit exceeded')
                        h.update(chunk)
            else:
                raise UpdateError('Application contains a special file')
    return h.hexdigest(),size


def _local_header(f, item):
    f.seek(item.header_offset)
    raw = f.read(30)
    if len(raw)!=30:
        raise UpdateError('Truncated ZIP header')
    signature,version,flags,method,mtime,mdate,crc,compressed,expanded,nlen,xlen = struct.unpack('<IHHHHHIIIHH',raw)
    if signature != 0x04034B50 or flags != item.flag_bits or method != item.compress_type:
        raise UpdateError('Local and central ZIP headers disagree')
    name = f.read(nlen)
    try:
        decoded = name.decode('utf-8' if flags & 0x800 else 'ascii')
    except UnicodeError:
        raise UpdateError('Ambiguous ZIP filename encoding') from None
    if decoded != item.orig_filename or decoded != item.filename:
        raise UpdateError('Local and central ZIP names disagree')
    # Restrict unsupported features, encrypted data, alternate Unicode names and ZIP64.
    if version > 20 or flags & ~(0x800 | 8 | 2 | 4):
        raise UpdateError('Unsupported ZIP flags')
    if not flags & 8 and (crc,compressed,expanded)!=(item.CRC,item.compress_size,item.file_size):
        raise UpdateError('Local and central ZIP sizes disagree')
    for extra in (f.read(xlen),item.extra):
        offset=0
        while offset<len(extra):
            if offset+4>len(extra):
                raise UpdateError('Malformed ZIP extra data')
            tag,length=struct.unpack_from('<HH',extra,offset)
            offset+=4
            if offset+length>len(extra) or tag in (0x7075,0x0001):
                raise UpdateError('Unsupported ZIP name or size metadata')
            offset+=length
    start=item.header_offset+30+nlen+xlen
    end=start+item.compress_size
    if flags & 8:
        f.seek(end); descriptor=f.read(16)
        signed=descriptor[:4]==b'PK\x07\x08'
        values=descriptor[4:16] if signed else descriptor[:12]
        if len(values)!=12 or struct.unpack('<III',values)!=(item.CRC,item.compress_size,item.file_size):
            raise UpdateError('ZIP data descriptor disagrees with directory')
        end+=16 if signed else 12
    return start,end


def extract_archive(archive,destination,manifest,*,verifier=verify_identity,limits=None):
    manifest = validate_manifest(manifest)
    limits = limits or {}
    max_size=limits.get('expanded',MAX_EXPANDED)
    max_ratio=limits.get('ratio',MAX_RATIO)
    deadline=time.monotonic()+limits.get('seconds',MAX_SECONDS)
    destination=Path(destination)
    parent=destination.parent
    if parent.resolve()!=parent.absolute() or destination.exists() or destination.is_symlink():
        raise UpdateError('Extraction requires a new canonical directory')
    if not parent.is_dir() or parent.stat().st_uid!=os.getuid() or parent.stat().st_mode & 0o022:
        raise UpdateError('Extraction parent must be owner controlled')
    fd=os.open(archive,os.O_RDONLY|os.O_NOFOLLOW)
    created=False
    try:
        with os.fdopen(fd,'rb') as raw:
            s=os.fstat(raw.fileno())
            if not stat.S_ISREG(s.st_mode) or s.st_size!=manifest['archive']['size']:
                raise UpdateError('Archive length mismatch')
            digest=hashlib.sha256()
            for chunk in iter(lambda:raw.read(1024*1024),b''):
                digest.update(chunk)
                if time.monotonic()>deadline:
                    raise UpdateError('Archive time limit exceeded')
            if digest.hexdigest()!=manifest['archive']['sha256']:
                raise UpdateError('Archive digest mismatch')
            # Bound central-directory allocation before ZipFile constructs entries.
            raw.seek(max(0,s.st_size-65557)); tail=raw.read(65557)
            offset=tail.rfind(b'PK\x05\x06')
            if offset<0 or offset+22>len(tail): raise UpdateError('Missing ZIP directory')
            _,disk,cd_disk,disk_count,count,cd_size,cd_offset,comment=struct.unpack_from('<IHHHHIIH',tail,offset)
            if disk or cd_disk or disk_count!=count or count>limits.get('entries',MAX_ENTRIES) or cd_size>16*1024**2 or cd_offset+cd_size!=s.st_size-len(tail)+offset or offset+22+comment!=len(tail):
                raise UpdateError('ZIP directory bounds exceeded')
            raw.seek(0)
            with zipfile.ZipFile(raw) as z:
                entries=z.infolist()
                if not entries or len(entries)>limits.get('entries',MAX_ENTRIES):
                    raise UpdateError('Archive entry limit exceeded')
                seen={}; explicit=set(); kinds={}; spans=[]; total=0; roots=set()
                for item in entries:
                    if time.monotonic()>deadline: raise UpdateError('Archive time limit exceeded')
                    name=checked_name(item.filename)
                    key=unicodedata.normalize('NFC',name).casefold()
                    if key in explicit:
                        raise UpdateError('Duplicate or colliding ZIP entries')
                    explicit.add(key)
                    # Compare every path component, including implicit directories.
                    for i in range(1,len(name.split('/'))+1):
                        prefix='/'.join(name.split('/')[:i]); folded=unicodedata.normalize('NFC',prefix).casefold()
                        if folded in seen and seen[folded]!=prefix:
                            raise UpdateError('Case or Unicode directory collision')
                        seen[folded]=prefix
                    roots.add(name.split('/')[0])
                    mode=item.external_attr>>16
                    kind=stat.S_IFMT(mode)
                    if mode & 0o7000 or kind not in (0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK):
                        raise UpdateError('Special ZIP entry')
                    kinds[name]='link' if kind==stat.S_IFLNK else 'dir' if item.is_dir() else 'file'
                    if kind==stat.S_IFDIR and not item.is_dir() or item.is_dir() and (item.file_size or kind not in (0,stat.S_IFDIR)):
                        raise UpdateError('Malformed ZIP directory')
                    if item.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):
                        raise UpdateError('Unsupported ZIP compression')
                    start,end=_local_header(raw,item); spans.append((item.header_offset,end))
                    if end>z.start_dir or start>end:
                        raise UpdateError('ZIP data overlaps directory')
                    total+=item.file_size
                    if total>max_size or item.file_size>max(1,item.compress_size)*max_ratio:
                        raise UpdateError('Archive expansion limit exceeded')
                spans.sort()
                if any(b[0]<a[1] for a,b in zip(spans,spans[1:])):
                    raise UpdateError('Overlapping ZIP entries')
                if len(roots)!=1 or not next(iter(roots)).endswith('.app'):
                    raise UpdateError('Expected one application payload')
                for name in kinds:
                    if any(kinds.get('/'.join(name.split('/')[:i])) in ('link','file') for i in range(1,len(name.split('/')))):
                        raise UpdateError('ZIP writes through a non-directory parent')
                if shutil.disk_usage(parent).free < total+DISK_RESERVE:
                    raise UpdateError('Insufficient extraction space')
                destination.mkdir(mode=0o700); created=True
                actual=0; links=[]
                for item in entries:
                    name=checked_name(item.filename); path=destination/name
                    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                    if kinds[name]=='dir':
                        path.mkdir(exist_ok=True,mode=0o700); continue
                    count=0; link_data=bytearray()
                    out=None
                    try:
                        if kinds[name]!='link':
                            out=path.open('xb')
                        with z.open(item) as source:
                            while True:
                                chunk=source.read(65536)
                                if not chunk: break
                                count+=len(chunk); actual+=len(chunk)
                                if actual>max_size or count>max(1,item.compress_size)*max_ratio or time.monotonic()>deadline:
                                    raise UpdateError('Streamed archive limit exceeded')
                                if out: out.write(chunk)
                                else:
                                    link_data.extend(chunk)
                                    if len(link_data)>1024: raise UpdateError('Symlink too long')
                        if count!=item.file_size: raise UpdateError('Expanded size mismatch')
                    finally:
                        if out: out.close()
                    if kinds[name]=='link':
                        try: target=bytes(link_data).decode('utf-8')
                        except UnicodeError: raise UpdateError('Malformed symlink') from None
                        if not target or target.startswith('/') or '\\' in target or ':' in target or '\x00' in target:
                            raise UpdateError('Unsafe symlink')
                        links.append((path,target))
                    else:
                        os.chmod(path,0o755 if item.external_attr>>16 & 0o111 else 0o644)
                # Create links only after all regular writes. Resolve entire chains afterwards.
                for path,target in links: path.symlink_to(target)
                app=destination/next(iter(roots))
                for path,_ in links:
                    try: resolved=path.resolve(strict=True)
                    except (OSError,RuntimeError): raise UpdateError('Broken or cyclic symlink') from None
                    if not resolved.is_relative_to(app): raise UpdateError('Symlink escapes application')
                identity=verifier(app,manifest)
                digest,_=tree_digest(app)
                return {'ok':True,'app_path':str(app),'identity':identity,'sha256':digest,'expanded_size':actual}
    except Exception:
        if created: shutil.rmtree(destination)
        raise


def main(stdin=None,stdout=None):
    stdin=stdin or sys.stdin; stdout=stdout or sys.stdout
    try:
        request=read_request(stdin)
        if set(request)!={'archive','destination','manifest'}: raise UpdateError('Invalid preflight request')
        result=extract_archive(request['archive'],request['destination'],request['manifest'])
    except (UpdateError,OSError,ValueError,UnicodeError,zipfile.BadZipFile,RuntimeError) as error:
        result={'ok':False,'error':str(error) if isinstance(error,UpdateError) else 'Archive validation failed'}
    stdout.write(json.dumps(result)+'\n')
    return 0 if result['ok'] else 1


if __name__=='__main__':
    raise SystemExit(main())
