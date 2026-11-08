"""Closed public update metadata. Importing this module performs no I/O."""
import base64
import json
import re

APP_ID = 'com.kleinperkins.machine-monitor'
TEAM_ID = 'J2V7GRV5CM'
MAX_JSON = 65536
MAX_ARCHIVE = 512 * 1024 * 1024


class UpdateError(ValueError):
    """A safe, credential-free diagnostic suitable for the native UI."""


def integer(value, name, minimum=1, maximum=2**53-1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise UpdateError('Invalid ' + name)
    return value


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r'(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){0,3}', value):
        raise UpdateError('Invalid version')
    return tuple(map(int, value.split('.'))) + (0,) * (4-len(value.split('.')))


def validate_manifest(value, current_build=None):
    fields = {'schema','app_id','bundle_id','team_id','channel','version','build','minimum_macos','architecture','data_schema_version','source_revision','qualification_id','qualified','archive','first_install'}
    if not isinstance(value, dict) or set(value) != fields:
        raise UpdateError('Invalid release fields')
    for key, expected in [('schema','machine-monitor/release/v1'), ('app_id',APP_ID), ('bundle_id',APP_ID), ('team_id',TEAM_ID), ('minimum_macos','26.0'), ('architecture','arm64'), ('data_schema_version',1)]:
        if value[key] != expected or key == 'data_schema_version' and type(value[key]) is not int:
            raise UpdateError('Unsupported release ' + key)
    version_tuple(value['version'])
    integer(value['build'], 'build')
    if current_build is not None and value['build'] <= integer(current_build, 'current build'):
        raise UpdateError('Release build must increase')
    if value['channel'] not in ('stable','qualification') or type(value['qualified']) is not bool:
        raise UpdateError('Invalid release channel')
    if value['channel'] == 'stable' and not value['qualified']:
        raise UpdateError('Stable release is not qualified')
    if not isinstance(value['qualification_id'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',value['qualification_id']):
        raise UpdateError('Invalid qualification identifier')
    if not isinstance(value['source_revision'],str) or not re.fullmatch('[0-9a-f]{40}',value['source_revision']):
        raise UpdateError('Invalid source revision')
    for descriptor,suffix in (('archive','archive'),('first_install','package')):
        archive = value[descriptor]
        if not isinstance(archive,dict) or set(archive) != {'path','size','sha256','ed25519_signature'}:
            raise UpdateError('Invalid archive fields')
        if not isinstance(archive['path'],str) or not re.fullmatch(r'/v1/apps/com\.kleinperkins\.machine-monitor/releases/[A-Za-z0-9_-]{1,128}/'+suffix,archive['path']):
            raise UpdateError('Invalid archive path')
        integer(archive['size'],'archive size',maximum=MAX_ARCHIVE)
        if not isinstance(archive['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',archive['sha256']):
            raise UpdateError('Invalid archive digest')
        try:
            decoded=base64.b64decode(archive['ed25519_signature'],validate=True)
            if len(decoded) != 64 or base64.b64encode(decoded).decode('ascii') != archive['ed25519_signature']:
                raise ValueError()
        except (ValueError,TypeError):
            raise UpdateError('Invalid archive signature') from None
    if value['archive']['path'].rsplit('/',1)[0] != value['first_install']['path'].rsplit('/',1)[0]:
        raise UpdateError('Release descriptor identities disagree')
    return value


def read_request(stream):
    raw = stream.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise UpdateError('Request is too large')
    def pairs(items):
        out = {}
        for key,value in items:
            if key in out:
                raise UpdateError('Duplicate JSON key')
            out[key] = value
        return out
    try:
        result = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError,UnicodeError,RecursionError):
        raise UpdateError('Invalid JSON request') from None
    if not isinstance(result,dict):
        raise UpdateError('Expected JSON object')
    return result
