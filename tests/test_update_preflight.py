import copy
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import stat
import struct
import sys
import subprocess
import tempfile
import unittest
import zipfile
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from update_contract import UpdateError,validate_manifest,version_tuple,read_request
import update_preflight as preflight
from update_fixtures import archive,manifest,verifier,identity


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve(); self.zip=self.root/'fixture.zip'; self.out=self.root/'expanded'

    def extract(self,entries=None,**kwargs):
        value=archive(self.zip,entries)
        return preflight.extract_archive(self.zip,self.out,value,verifier=verifier,**kwargs)

    def test_valid_archive_and_no_collector_import(self):
        result=self.extract()
        self.assertTrue(result['ok']); self.assertEqual(result['identity']['build'],2)
        subprocess.run([sys.executable,'-c',"import sys; import update_preflight; import update_recovery; assert 'monitor' not in sys.modules"],cwd=Path(__file__).resolve().parents[1],check=True,timeout=10)

    def test_invalid_paths(self):
        for name in ('../Monitor.app/a','/Monitor.app/a','C:/Monitor.app/a','Monitor.app/../a','Monitor.app//a','Monitor.app/./a','Monitor.app\\a','Other/a'):
            with self.subTest(name=name):
                with self.assertRaises(UpdateError): self.extract([(name,b'x',stat.S_IFREG|0o644)])
                self.assertFalse(self.out.exists())

    def test_null_filename(self):
        with self.assertRaises(UpdateError): preflight.checked_name('Monitor.app/a\x00x')

    def test_duplicate_case_unicode_and_implicit_directory_collisions(self):
        for names in [('a','a'),('a','A'),('é','e\u0301'),('Dir/a','dir/b')]:
            with self.subTest(names=names):
                with self.assertRaises(UpdateError): self.extract([('Monitor.app/'+name,b'x',stat.S_IFREG|0o644) for name in names])

    def test_special_files_and_parent_writes(self):
        for kind in (stat.S_IFIFO,stat.S_IFCHR,stat.S_IFSOCK,stat.S_IFBLK):
            with self.assertRaises(UpdateError): self.extract([('Monitor.app/a',b'x',kind|0o600)])
        with self.assertRaises(UpdateError): self.extract([('Monitor.app/a',b'b',stat.S_IFLNK|0o777),('Monitor.app/a/file',b'x',stat.S_IFREG|0o644)])

    def test_links_escapes_cycles_broken_and_framework_valid(self):
        for target in ('../../escape','/tmp/escape','C:/escape','a','missing'):
            with self.assertRaises(UpdateError): self.extract([('Monitor.app/a',target.encode(),stat.S_IFLNK|0o777)])
        entries=[('Monitor.app/Contents/fixture.json',json.dumps(identity(2)).encode(),stat.S_IFREG|0o644),
                 ('Monitor.app/Contents/Frameworks/F.framework/Versions/A/F',b'fixture',stat.S_IFREG|0o755),
                 ('Monitor.app/Contents/Frameworks/F.framework/Versions/Current',b'A',stat.S_IFLNK|0o777),
                 ('Monitor.app/Contents/Frameworks/F.framework/F',b'Versions/Current/F',stat.S_IFLNK|0o777)]
        result=self.extract(entries)
        self.assertTrue(result['ok'])
        self.assertEqual(result['expanded_size'],preflight.tree_digest(result['app_path'])[1])

    def test_limits_entry_size_ratio_time_space(self):
        for limits in ({'entries':1},{'expanded':1},{'ratio':0},{'seconds':-1}):
            with self.assertRaises(UpdateError): self.extract(limits=limits)
        with patch.object(preflight.shutil,'disk_usage',return_value=type('Disk',(),{'free':0})()):
            with self.assertRaises(UpdateError): self.extract()

    def test_local_central_mismatch(self):
        value=archive(self.zip)
        data=bytearray(self.zip.read_bytes()); data[30]=ord('X'); self.zip.write_bytes(data)
        value['archive']['sha256']=hashlib.sha256(data).hexdigest()
        with self.assertRaisesRegex(UpdateError,'names disagree'): preflight.extract_archive(self.zip,self.out,value,verifier=verifier)

    def test_local_size_flags_encoding_and_overlapping_entries(self):
        for offset,change in ((18,b'\x00\x00\x00\x00'),(6,b'\x01\x00'),(30,b'\xff')):
            value=archive(self.zip); data=bytearray(self.zip.read_bytes()); data[offset:offset+len(change)]=change; self.zip.write_bytes(data)
            value['archive']['sha256']=hashlib.sha256(data).hexdigest()
            with self.assertRaises(UpdateError): preflight.extract_archive(self.zip,self.out,value,verifier=verifier)

    def test_hash_length_identity_and_destination_fail_closed(self):
        value=archive(self.zip); value['archive']['sha256']='0'*64
        with self.assertRaises(UpdateError): preflight.extract_archive(self.zip,self.out,value,verifier=verifier)
        value=archive(self.zip); value['archive']['size']+=1
        with self.assertRaises(UpdateError): preflight.extract_archive(self.zip,self.out,value,verifier=verifier)
        value=archive(self.zip)
        def deny(*args): raise UpdateError('Untrusted signature')
        with self.assertRaises(UpdateError): preflight.extract_archive(self.zip,self.out,value,verifier=deny)
        self.assertFalse(self.out.exists())
        self.out.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(UpdateError): preflight.extract_archive(self.zip,self.out,value,verifier=verifier)

    def test_apple_verifier_checks_trust_and_legacy_metadata(self):
        app=self.root/'app'; (app/'Contents').mkdir(parents=True)
        info={'CFBundleIdentifier':'com.kleinperkins.machine-monitor','CFBundleExecutable':'Monitor','CFBundleVersion':'1',
              'CFBundleShortVersionString':'1.0','LSMinimumSystemVersion':'26.0'}
        path=app/'Contents/Info.plist'; path.write_bytes(plistlib.dumps(info))
        def command(args): return 'arm64' if 'lipo' in args[0] else ''
        with patch.object(preflight.sys,'platform','darwin'),patch.object(preflight,'run_checked',side_effect=command) as calls:
            self.assertEqual(preflight.verify_identity(app)['data_schema_version'],1)
            self.assertIn('anchor apple generic',calls.call_args_list[0].args[0][-2])
            self.assertTrue(calls.call_args_list[0].args[0][-2].startswith('=anchor apple generic'))
            self.assertIn('spctl',calls.call_args_list[1].args[0][0])
            info['CFBundleVersion']='2'; path.write_bytes(plistlib.dumps(info))
            with self.assertRaises(UpdateError): preflight.verify_identity(app)
            info['MachineMonitorDataSchemaVersion']=1; path.write_bytes(plistlib.dumps(info))
            self.assertEqual(preflight.verify_identity(app)['build'],2)
        with patch.object(preflight.sys,'platform','darwin'),patch.object(preflight,'run_checked',side_effect=UpdateError('trust denied')):
            with self.assertRaises(UpdateError): preflight.verify_identity(app)
        with patch.object(preflight.sys,'platform','darwin'),patch.object(preflight,'run_checked',return_value='x86_64'):
            with self.assertRaises(UpdateError): preflight.verify_identity(app)

    def test_streamed_actual_bytes_override_forged_metadata(self):
        value=archive(self.zip)
        original=zipfile.ZipFile.open
        def malicious(z,item,*args,**kwargs):
            return io.BytesIO(b'x'*1000)
        with patch.object(zipfile.ZipFile,'open',malicious):
            with self.assertRaises(UpdateError):
                preflight.extract_archive(self.zip,self.out,value,verifier=verifier,limits={'expanded':500})
        self.assertFalse(self.out.exists())

    def test_oversized_directory_rejected_before_zipfile_allocation(self):
        value=archive(self.zip); data=bytearray(self.zip.read_bytes())
        end=data.rfind(b'PK\x05\x06'); struct.pack_into('<HH',data,end+8,50000,50000)
        self.zip.write_bytes(data); value['archive']['sha256']=hashlib.sha256(data).hexdigest()
        with patch.object(preflight.zipfile,'ZipFile',side_effect=AssertionError('must not allocate')):
            with self.assertRaisesRegex(UpdateError,'directory bounds'):
                preflight.extract_archive(self.zip,self.out,value,verifier=verifier)

    def test_wrong_platform_metadata_and_nonlegacy_absent_schema(self):
        app=self.root/'app'; (app/'Contents').mkdir(parents=True)
        info={'CFBundleIdentifier':'com.kleinperkins.machine-monitor','CFBundleExecutable':'Monitor','CFBundleVersion':'2',
              'CFBundleShortVersionString':'1.2','LSMinimumSystemVersion':'26.0','MachineMonitorDataSchemaVersion':1}
        path=app/'Contents/Info.plist'
        for key,value in [('CFBundleIdentifier','wrong'),('LSMinimumSystemVersion','27.0'),('MachineMonitorDataSchemaVersion',2),('CFBundleExecutable','../escape')]:
            bad=info|{key:value}; path.write_bytes(plistlib.dumps(bad))
            with patch.object(preflight.sys,'platform','darwin'),patch.object(preflight,'run_checked',return_value='arm64'):
                with self.assertRaises(UpdateError): preflight.verify_identity(app)

    def test_safe_executable_basename_preserves_spaces(self):
        app=self.root/'app'; (app/'Contents').mkdir(parents=True)
        info={'CFBundleIdentifier':'com.kleinperkins.machine-monitor','CFBundleExecutable':'Machine Monitor','CFBundleVersion':'2',
              'CFBundleShortVersionString':'1.2','LSMinimumSystemVersion':'26.0','MachineMonitorDataSchemaVersion':1}
        path=app/'Contents/Info.plist'; path.write_bytes(plistlib.dumps(info))
        with patch.object(preflight.sys,'platform','darwin'),patch.object(preflight,'run_checked',return_value='arm64') as calls:
            self.assertEqual(preflight.verify_identity(app)['build'],2)
            self.assertEqual(calls.call_args.args[0][-1],str(app/'Contents/MacOS/Machine Monitor'))
            for name in ('',' ',' Machine Monitor','Machine Monitor ','.','..','../escape','a/b','a\\b','a\n','a\x00','a'*129):
                with self.subTest(name=name):
                    path.write_bytes(plistlib.dumps(info|{'CFBundleExecutable':name},fmt=plistlib.FMT_BINARY))
                    with self.assertRaises(UpdateError): preflight.verify_identity(app)

    def test_manifest_and_json(self):
        self.assertEqual(version_tuple('1.10'),(1,10,0,0))
        for key,value in [('build',True),('build',1),('architecture','x86_64'),('team_id','OTHER'),('qualified',False),('data_schema_version',True)]:
            m=manifest(); m[key]=value
            with self.assertRaises(UpdateError): validate_manifest(m,current_build=1)
        for payload in ('{"a":1,"a":2}', '[]', 'x'*65537):
            with self.assertRaises(UpdateError): read_request(io.StringIO(payload))
        output=io.StringIO(); self.assertEqual(preflight.main(io.StringIO('{"fixture_bypass":true}'),output),1)
        self.assertFalse(json.loads(output.getvalue())['ok'])

    def test_real_codesign_inline_expression_requires_literal_prefix(self):
        binary=self.root/'signed-fixture'
        subprocess.run(['xcrun','clang','-arch','arm64','-x','c','-','-o',str(binary)],
                       input=b'int main(void) { return 0; }\n',check=True,capture_output=True,timeout=60)
        identifier='com.kleinperkins.machine-monitor.requirement-fixture'
        subprocess.run(['/usr/bin/codesign','--force','--sign','-','--identifier',identifier,str(binary)],
                       check=True,capture_output=True,timeout=20)
        expression='identifier "'+identifier+'"'
        def verify(requirement):
            return subprocess.run(['/usr/bin/codesign','--verify','--strict','-R',requirement,str(binary)],
                                  capture_output=True,timeout=20)
        self.assertNotEqual(verify(expression).returncode,0)
        accepted=verify('='+expression)
        self.assertEqual(accepted.returncode,0,accepted.stderr.decode(errors='replace'))
        self.assertNotEqual(verify('=identifier "different.fixture"').returncode,0)


if __name__=='__main__': unittest.main()
