import io
import json
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from scripts.processes import run_build
from update_contract import UpdateError
import update_recovery as recovery
from update_fixtures import app,identity,manifest,verifier


class Crash(BaseException): pass


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve(); self.target=app(self.root/'Monitor.app')
        self.base=self.root/'state'; self.boot='boot-one'
        self.store=self.new()

    def new(self,**kwargs):
        return recovery.RecoveryStore(self.target,base=self.base,verifier=verifier,boot=lambda:self.boot,**kwargs)

    def prepare_store(self,store,release=None):
        release=release or manifest()
        candidate=store.target.parent/'Candidate.app'
        if candidate.exists(): shutil.rmtree(candidate)
        app(candidate,release['build'])
        return store.prepare(release,candidate_path=candidate,expanded_size=recovery.tree_digest(candidate)[1])

    def prepare(self): return self.prepare_store(self.store)

    def replace(self,build):
        shutil.rmtree(self.target); app(self.target,build)

    def phase(self,value):
        journal=recovery.load_json(self.store.state/'journal.json'); journal['phase']=value
        recovery.durable_json(self.store.state/'journal.json',journal)
        return journal

    def accepted(self):
        journal=self.phase('accepted')
        recovery.durable_json(self.store.state/'acceptance.json',{'transaction_id':journal['transaction_id'],'target_path':str(self.target),'build':journal['expected']['build']})

    def test_damaged_target_is_quarantined_under_existing_authority(self):
        prepared=self.prepare(); self.replace(2)
        (self.target/'Contents/executable').write_bytes(b'corrupt signed resource')
        original_verifier=self.store.verifier
        def trusted(path,expected=None):
            if (Path(path)/'Contents/executable').read_bytes()==b'corrupt signed resource':
                raise UpdateError('Signature mismatch')
            return original_verifier(path,expected)
        self.store.verifier=trusted
        self.assertEqual(self.store.restore(prepared['transaction_id'])['restored']['build'],1)
        record=recovery.load_json(self.store.state/'recovery.json')
        self.assertTrue(record['old']['damaged'])
        self.assertEqual((Path(record['saved_path'])/'Contents/executable').read_bytes(),b'corrupt signed resource')
        other=app(self.root/'Unrelated.app',2)
        unknown=recovery.RecoveryStore(other,base=self.base,verifier=trusted,boot=lambda:self.boot)
        with self.assertRaises(UpdateError): unknown.restore(prepared['transaction_id'])

    def test_preparation_crashes_reconcile_and_allow_retry(self):
        points=('prepare-intent','prepare-directory','prepare-owner','prepare-original-copy','prepare-original-published',
                'prepare-original-receipt','prepare-backup-copy','prepare-backup-published','prepare-backup-receipt',
                'prepare-before-journal','prepare-after-journal')
        for point in points:
            with self.subTest(point=point), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary).resolve(); target=app(root/'Monitor.app')
                store=recovery.RecoveryStore(target,base=root/'state',verifier=verifier,boot=lambda:'boot')
                def fault(actual):
                    if actual==point: raise Crash()
                store.fault=fault
                with self.assertRaises(Crash): self.prepare_store(store)
                intent=recovery.load_json(store.state/'preparation.json')
                self.assertIsNotNone(intent)
                store.fault=lambda point:None
                status=store.status()
                self.assertFalse((store.state/'preparation.json').exists())
                self.assertEqual(list(store.state.glob('.prepare-*')),[])
                self.assertEqual(verifier(target)['build'],1)
                if point=='prepare-after-journal':
                    self.assertTrue(status['available'])
                    store.discard(status['transaction_id'])
                else:
                    self.assertFalse(status['available'])
                    self.assertEqual(list(store.backups.glob('*.app')),[])
                self.assertTrue(self.prepare_store(store)['ok'])
                self.assertEqual(verifier(store.state/'original.app')['build'],1)

    def test_partial_copy_is_removed_from_proved_staging_only(self):
        original_copy=recovery.shutil.copytree
        def interrupted(source,destination,**kwargs):
            destination.mkdir(); (destination/'partial').write_bytes(b'incomplete')
            raise Crash()
        with patch.object(recovery.shutil,'copytree',side_effect=interrupted):
            with self.assertRaises(Crash): self.prepare()
        foreign=self.store.state/'unrelated.app'; foreign.mkdir(); (foreign/'keep').write_text('foreign')
        self.assertFalse(self.store.status()['available'])
        self.assertEqual(list(self.store.state.glob('.prepare-*')),[])
        self.assertEqual((foreign/'keep').read_text(),'foreign')
        self.assertTrue(self.prepare()['ok'])

    def test_foreign_staging_paths_and_extra_contents_are_preserved(self):
        transaction='e'*32
        foreign=self.store.state/('.prepare-'+transaction); foreign.mkdir(); (foreign/'keep').write_text('foreign')
        candidate=app(self.root/'Candidate.app',2)
        with self.assertRaisesRegex(UpdateError,'foreign bytes preserved'):
            self.store.prepare(manifest(),transaction_id=transaction,candidate_path=candidate,expanded_size=recovery.tree_digest(candidate)[1])
        self.assertEqual((foreign/'keep').read_text(),'foreign')
        self.assertFalse((self.store.state/'preparation.json').exists())
        def fault(point):
            if point=='prepare-owner': raise Crash()
        self.store.fault=fault
        with self.assertRaises(Crash): self.prepare()
        intent=recovery.load_json(self.store.state/'preparation.json'); stage=Path(intent['stage_path'])
        (stage/'foreign.txt').write_text('foreign')
        with self.assertRaisesRegex(UpdateError,'Foreign preparation contents'): self.store.status()
        self.assertEqual((stage/'foreign.txt').read_text(),'foreign')

    def test_actual_small_candidate_budget_and_size_binding(self):
        # 128MiB free accommodates a tiny release and the 64MiB reserve; the
        # previous archive-size worst-case multiplication would reject this.
        release=manifest(); release['archive']['size']=1024*1024
        with patch.object(recovery.shutil,'disk_usage',return_value=type('Disk',(),{'free':128*1024**2})()):
            prepared=self.prepare_store(self.store,release)
        self.assertTrue(prepared['ok']); self.store.discard(prepared['transaction_id'])
        candidate=self.root/'Candidate.app'
        with self.assertRaisesRegex(UpdateError,'expanded size changed'):
            self.store.prepare(release,candidate_path=candidate,expanded_size=recovery.tree_digest(candidate)[1]+1)
        self.assertFalse((self.store.state/'preparation.json').exists())

    def test_native_recovery_presentation(self):
        repo=Path(__file__).resolve().parents[1]
        binary=self.root/'recovery-model'
        run_build(['xcrun','swiftc','-parse-as-library',str(repo/'mac/RecoveryModel.swift'),str(repo/'tests/recovery_model_harness.swift'),'-o',str(binary)],timeout=120)
        result=subprocess.run([str(binary)],check=True,capture_output=True,text=True,timeout=10)
        self.assertIn('8 assertions passed',result.stdout)

    def test_prepare_keeps_original_and_restore_is_explicit(self):
        prepared=self.prepare(); original=recovery.load_json(self.store.state/'original.json')
        self.replace(2); self.accepted()
        for name in ('relaunch.json','relaunch-consumed.json'):
            recovery.durable_json(self.store.state/name,{'stale':True})
        result=self.store.restore(prepared['transaction_id'])
        self.assertEqual(result['restored']['build'],1)
        self.assertFalse((self.store.state/'relaunch.json').exists())
        self.assertFalse((self.store.state/'relaunch-consumed.json').exists())
        self.assertEqual(verifier(self.target)['build'],1)
        self.assertEqual(recovery.load_json(self.store.state/'original.json'),original)
        self.assertFalse(recovery.load_json(self.store.state/'recovery-receipt.json')['monitoring_started'])
        self.assertEqual(self.store.restore(prepared['transaction_id'])['phase'],'accepted')

    def test_pending_requires_changed_boot_and_lock(self):
        prepared=self.prepare(); self.phase('installer-pending'); self.replace(2)
        self.assertFalse(self.store.status()['can_restore'])
        with self.assertRaisesRegex(UpdateError,'Restart your Mac'): self.store.restore(prepared['transaction_id'])
        self.boot='boot-two'
        with self.store.lock():
            with self.assertRaisesRegex(UpdateError,'Quit Machine Monitor'): self.new().restore(prepared['transaction_id'])
        self.assertEqual(self.store.restore(prepared['transaction_id'])['phase'],'accepted')

    def test_accepted_requires_matching_receipt(self):
        prepared=self.prepare(); self.phase('accepted')
        with self.assertRaises(UpdateError): self.store.restore(prepared['transaction_id'])
        self.accepted(); self.assertTrue(self.store.status()['can_restore'])

    def test_discard_only_pre_admission(self):
        prepared=self.prepare()
        with self.assertRaises(UpdateError): self.store.discard('wrong')
        self.assertEqual(self.store.discard(prepared['transaction_id'])['phase'],'cancelled')
        self.phase('installer-pending')
        with self.assertRaises(UpdateError): self.store.discard(prepared['transaction_id'])

    def test_two_backup_rotation_never_prunes_original(self):
        first=self.prepare(); original=recovery.load_json(self.store.state/'original.json')
        for build in (2,3,4):
            self.accepted(); self.replace(build)
            self.prepare_store(self.store,manifest(build+1))
        self.assertEqual(len(list(self.store.backups.glob('*.app'))),2)
        self.assertEqual(recovery.load_json(self.store.state/'original.json'),original)
        self.assertEqual(verifier(self.store.state/'original.app')['build'],1)

    def test_crash_reconciliation_at_every_boundary(self):
        for point in ('restore-staging','restore-stage-directory','restore-stage-owned','restore-stage-copy','prepared','before-target-rename','after-target-rename','target-saved','before-backup-rename','after-backup-rename','backup-published','before-receipt','after-receipt','accepted'):
            with self.subTest(point=point):
                with tempfile.TemporaryDirectory() as temp:
                    root=Path(temp).resolve(); target=app(root/'Monitor.app')
                    store=recovery.RecoveryStore(target,base=root/'state',verifier=verifier,boot=lambda:'boot')
                    prepared=self.prepare_store(store); shutil.rmtree(target); app(target,2)
                    def fault(actual):
                        if actual==point: raise Crash()
                    store.fault=fault
                    with self.assertRaises(Crash): store.restore(prepared['transaction_id'])
                    store.fault=lambda point:None
                    self.assertEqual(store.restore(prepared['transaction_id'])['phase'],'accepted')
                    self.assertEqual(verifier(target)['build'],1)
                    self.assertTrue(Path(prepared['backup']['path']).exists())

    def test_partial_restore_copy_reconciles_without_manual_cleanup(self):
        prepared=self.prepare(); self.replace(2)
        def interrupted(source,destination,**kwargs):
            (destination/'partial').write_bytes(b'incomplete')
            raise Crash()
        with patch.object(recovery.shutil,'copytree',side_effect=interrupted):
            with self.assertRaises(Crash): self.store.restore(prepared['transaction_id'])
        record=recovery.load_json(self.store.state/'recovery.json')
        self.assertEqual(record['phase'],'staging')
        self.assertEqual(verifier(self.target)['build'],2)
        self.assertEqual(self.store.restore(prepared['transaction_id'])['restored']['build'],1)

    def test_repeated_restore_staging_crashes_remain_resumable(self):
        prepared=self.prepare(); self.replace(2)
        def fault(point):
            if point=='restore-stage-directory': raise Crash()
        self.store.fault=fault
        for _ in range(2):
            with self.assertRaises(Crash): self.store.restore(prepared['transaction_id'])
        self.store.fault=lambda point:None
        self.assertEqual(self.store.restore(prepared['transaction_id'])['restored']['build'],1)

    def test_failed_second_rename_rolls_back_without_losing_backup(self):
        prepared=self.prepare(); self.replace(2)
        original=recovery.os.rename
        def rename(src,dst):
            if '.machine-monitor-restore-' in str(src): raise OSError('fixture failure')
            return original(src,dst)
        with patch.object(recovery.os,'rename',side_effect=rename):
            with self.assertRaisesRegex(UpdateError,'preserved'): self.store.restore(prepared['transaction_id'])
        self.assertEqual(verifier(self.target)['build'],2)
        self.assertTrue(Path(prepared['backup']['path']).exists())
        self.assertEqual(recovery.load_json(self.store.state/'recovery.json')['phase'],'rolled-back')

    def test_tampered_backup_journal_path_and_permissions(self):
        prepared=self.prepare()
        backup=Path(prepared['backup']['path']); (backup/'Contents/executable').write_bytes(b'tampered')
        with self.assertRaises(UpdateError): self.store.restore(prepared['transaction_id'])
        journal=recovery.load_json(self.store.state/'journal.json'); journal['target_path']=str(self.root/'other.app')
        recovery.durable_json(self.store.state/'journal.json',journal)
        with self.assertRaises(UpdateError): self.store.status()
        (self.store.state/'journal.json').chmod(0o644)
        with self.assertRaises(UpdateError): self.store.status()

    def test_symlink_target_state_lock_and_nonwritable_target(self):
        alias=self.root/'Alias.app'; alias.symlink_to(self.target,target_is_directory=True)
        with self.assertRaises(UpdateError): recovery.RecoveryStore(alias,base=self.base,verifier=verifier)
        self.target.chmod(0o555)
        with self.assertRaises(UpdateError): self.prepare()
        self.target.chmod(0o755)
        lock=self.store.state/'operation.lock'; lock.unlink(); lock.symlink_to(self.root/'foreign')
        with self.assertRaises(OSError): self.prepare()

    def test_crashed_restore_refuses_path_substitution(self):
        prepared=self.prepare(); self.replace(2)
        def fault(point):
            if point=='after-target-rename': raise Crash()
        self.store.fault=fault
        with self.assertRaises(Crash): self.store.restore(prepared['transaction_id'])
        self.target.symlink_to(self.root/'unrelated.app')
        self.store.fault=lambda point:None
        with self.assertRaises(UpdateError): self.store.restore(prepared['transaction_id'])
        self.assertTrue(Path(prepared['backup']['path']).exists())

    def test_owner_boot_and_combined_volume_space_checks(self):
        with patch.object(recovery.os,'getuid',return_value=123456):
            with self.assertRaises(UpdateError): self.prepare()
        with patch.object(recovery.shutil,'disk_usage',return_value=type('Disk',(),{'free':recovery.DISK_RESERVE+1500})()):
            with self.assertRaises(UpdateError): self.store._space(1000,(self.store.state,1),(self.target.parent,1))
        self.store.boot=lambda: (_ for _ in ()).throw(UpdateError('boot unavailable'))
        with self.assertRaises(UpdateError): self.prepare()
        self.assertFalse((self.store.state/'original.app').exists())

    def test_malformed_manifest_authority_and_receipt_fail_closed(self):
        prepared=self.prepare(); journal=self.phase('accepted')
        recovery.durable_json(self.store.state/'acceptance.json',{'transaction_id':'wrong','target_path':str(self.target),'build':2})
        with self.assertRaises(UpdateError): self.store.restore(prepared['transaction_id'])
        journal['old']['sha256']='0'*64
        recovery.durable_json(self.store.state/'journal.json',journal)
        with self.assertRaises(UpdateError): self.store.status()
        journal['backup']='not a manifest'
        recovery.durable_json(self.store.state/'journal.json',journal)
        with self.assertRaises(UpdateError): self.store.status()

    def test_space_wrong_transaction_and_no_cli_test_bypass(self):
        with patch.object(recovery.shutil,'disk_usage',return_value=type('Disk',(),{'free':0})()):
            with self.assertRaisesRegex(UpdateError,'space'): self.prepare()
        self.assertFalse((self.store.state/'original.app').exists())
        prepared=self.prepare()
        with self.assertRaises(UpdateError): self.store.restore('0'*32)
        output=io.StringIO()
        self.assertEqual(recovery.main(io.StringIO('{"action":"restore","fixture_verifier":true}'),output),1)
        self.assertFalse(json.loads(output.getvalue())['ok'])


if __name__=='__main__': unittest.main()
