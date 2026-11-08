"""Synthetic update inputs. Never used by production CLI or bundles."""
import base64
import hashlib
import json
from pathlib import Path
import stat
import zipfile
from update_contract import APP_ID, TEAM_ID, UpdateError


def manifest(build=2):
    descriptor={'path':f'/v1/apps/{APP_ID}/releases/fixture/archive','size':1,'sha256':'0'*64,'ed25519_signature':base64.b64encode(bytes(64)).decode()}
    return {'schema':'machine-monitor/release/v1','app_id':APP_ID,'bundle_id':APP_ID,'team_id':TEAM_ID,'channel':'stable',
            'version':f'1.{build}','build':build,'minimum_macos':'26.0','architecture':'arm64','data_schema_version':1,
            'source_revision':'a'*40,'qualification_id':'fixture','qualified':True,'archive':descriptor,
            'first_install':descriptor|{'path':descriptor['path'].removesuffix('archive')+'package'}}


def identity(build=1):
    return {'bundle_id':APP_ID,'team_id':TEAM_ID,'version':f'1.{build}','build':build,'data_schema_version':1}


def app(path,build=1):
    path.mkdir(mode=0o755)
    (path/'Contents').mkdir()
    (path/'Contents/fixture.json').write_text(json.dumps(identity(build),sort_keys=True))
    (path/'Contents/executable').write_bytes(b'Synthetic inert application '+str(build).encode())
    return path


def verifier(path,expected=None):
    value=json.loads((Path(path)/'Contents/fixture.json').read_text())
    if value['bundle_id']!=APP_ID or value['team_id']!=TEAM_ID or value['data_schema_version']!=1:
        raise UpdateError('Fixture identity is invalid')
    if expected and any(value[k]!=expected[k] for k in ('bundle_id','team_id','version','build','data_schema_version')):
        raise UpdateError('Fixture identity mismatch')
    return value


def archive(path, entries=None):
    if entries is None:
        entries=[('Monitor.app/Contents/fixture.json',json.dumps(identity(2)).encode(),stat.S_IFREG|0o644),
                 ('Monitor.app/Contents/executable',b'fixture',stat.S_IFREG|0o755)]
    with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for name,data,mode in entries:
            item=zipfile.ZipInfo(name); item.create_system=3; item.external_attr=mode<<16
            z.writestr(item,data,compress_type=zipfile.ZIP_DEFLATED)
    result=manifest()
    result['archive']['size']=path.stat().st_size
    result['archive']['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
    return result
