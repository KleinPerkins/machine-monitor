"""Explicit, locked, crash-consistent restoration. This module never starts an app.

Normal updates are Sparkle's responsibility. This is the independent Recovery
app's narrow operation, with in-process dependency injection for synthetic tests.
No environment or CLI option disables code trust, ownership, or boot checks.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import uuid

from update_contract import UpdateError, integer, read_request, validate_manifest
from update_preflight import verify_identity, tree_digest, DISK_RESERVE, MAX_RATIO, MAX_EXPANDED

JOURNAL_SCHEMA='machine-monitor/update-journal/v1'
RECOVERY_SCHEMA='machine-monitor/recovery-journal/v1'


def boot_identity():
    if sys.platform!='darwin': raise UpdateError('Boot identity requires macOS')
    try:
        value=subprocess.check_output(['/usr/sbin/sysctl','-n','kern.bootsessionuuid'],timeout=5).decode().strip().lower()
        return str(uuid.UUID(value))
    except (OSError,ValueError,subprocess.SubprocessError):
        raise UpdateError('Cannot establish OS boot identity') from None


def canonical_target(value, *, missing=False):
    if not isinstance(value,(str,Path)): raise UpdateError('Invalid application path')
    path=Path(value)
    if not path.is_absolute() or path.suffix!='.app' or path.resolve()!=path:
        raise UpdateError('Application path must be canonical and contain no symlinks')
    if not path.parent.is_dir() or not os.access(path.parent,os.W_OK|os.X_OK):
        raise UpdateError('Application location is not writable')
    if path.exists():
        s=path.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode & 0o022 or not s.st_mode & 0o200:
            raise UpdateError('Application must be an owner-writable directory')
    elif not missing:
        raise UpdateError('Application is missing')
    return path


def private_dir(path):
    path=Path(path)
    # Inspect each preexisting component before mkdir. Canonical ancestors cannot
    # be replaced by a symlink into an unrelated location.
    if path.absolute()!=path.resolve(): raise UpdateError('State path contains a symlink')
    path.mkdir(mode=0o700,parents=True,exist_ok=True)
    s=path.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o700:
        raise UpdateError('Update state must be owner-only')
    return path


def sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def durable_json(path,value):
    path=Path(path)
    temporary=path.parent/('.'+path.name+'.'+uuid.uuid4().hex)
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as output:
            json.dump(value,output,sort_keys=True,separators=(',',':'))
            output.flush(); os.fsync(output.fileno())
        os.replace(temporary,path); sync_dir(path.parent)
    finally:
        if temporary.exists(): temporary.unlink()


def load_json(path):
    if not path.exists() and not path.is_symlink(): return None
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        s=os.fstat(stream.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:
            raise UpdateError('Journal ownership or permissions are invalid')
        return read_request(stream)


def sync_tree(root):
    for directory,dirs,files in os.walk(root,followlinks=False):
        for name in files:
            path=Path(directory)/name
            if path.is_symlink(): continue
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            try: os.fsync(fd)
            finally: os.close(fd)
        sync_dir(directory)


class RecoveryStore:
    def __init__(self,target,*,base=None,verifier=verify_identity,boot=boot_identity,fault=None):
        self.target=canonical_target(target,missing=True)
        self.verifier=verifier; self.boot=boot; self.fault=fault or (lambda point:None)
        base=Path(base) if base is not None else Path.home()/'Library/Application Support/Machine Monitor/Updates'
        self.base=private_dir(base)
        self.state=private_dir(self.base/hashlib.sha256(str(self.target).encode()).hexdigest())
        self.backups=private_dir(self.state/'backups')

    @contextmanager
    def lock(self):
        fd=os.open(self.state/'operation.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            s=os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:
                raise UpdateError('Invalid update operation lock')
            try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError: raise UpdateError('Quit Machine Monitor before opening Recovery') from None
            yield
        finally: os.close(fd)

    def inspect(self,path,expected=None):
        path=Path(path)
        if not path.is_dir() or path.is_symlink() or path.stat().st_uid!=os.getuid():
            raise UpdateError('Application ownership changed')
        before,size=tree_digest(path)
        identity=self.verifier(path,expected)
        after,_=tree_digest(path)
        if before!=after: raise UpdateError('Application changed during verification')
        return {'path':str(path),'sha256':after,'identity':identity,'size':size}

    def verify_record(self,record,path):
        if not isinstance(record,dict) or record.get('path')!=str(path): raise UpdateError('Backup path is invalid')
        actual=self.inspect(path,record.get('identity'))
        if actual!=record: raise UpdateError('Verified application changed')
        return actual

    def _journal(self):
        value=load_json(self.state/'journal.json')
        if value is None: return None
        if value.get('schema')!=JOURNAL_SCHEMA or value.get('target_path')!=str(self.target):
            raise UpdateError('Transaction target mismatch')
        self._transaction(value.get('transaction_id'))
        validate_manifest(value.get('expected'))
        if value.get('phase') not in ('prepared','installer-pending','replacement-observed','accepted','recovery-required','cancelled','restored'):
            raise UpdateError('Unknown transaction phase')
        backup=value.get('backup',{})
        if not isinstance(backup,dict) or set(backup)!={'path','sha256','identity','size'} or not isinstance(backup.get('path'),str) or not isinstance(backup.get('sha256'),str) or not re.fullmatch('[0-9a-f]{64}',backup['sha256']):
            raise UpdateError('Invalid transaction backup manifest')
        integer(backup['size'],'backup size',minimum=0,maximum=MAX_EXPANDED)
        name=Path(backup['path']).name
        if not re.fullmatch(r'[0-9a-f]{32}\.app',name) or backup.get('path')!=str(self.backups/name):
            raise UpdateError('Invalid transaction backup')
        if not isinstance(value.get('boot_id'),str) or not value['boot_id']:
            raise UpdateError('Missing transaction boot identity')
        old=value.get('old')
        identity=backup.get('identity')
        if not isinstance(old,dict) or not isinstance(identity,dict) or any(old.get(k)!=identity.get(k) for k in ('bundle_id','team_id','version','build','data_schema_version')) or old.get('sha256')!=backup.get('sha256'):
            raise UpdateError('Previous application authority is invalid')
        validate_manifest(value['expected'],old.get('build'))
        return value

    @staticmethod
    def _transaction(value):
        if not isinstance(value,str) or not re.fullmatch(r'[0-9a-f]{32}',value): raise UpdateError('Invalid transaction identifier')
        return value

    def _copy(self,source,destination,expected):
        if destination.exists() or destination.is_symlink(): raise UpdateError('Recovery staging path already exists')
        shutil.copytree(source,destination,symlinks=True)
        sync_tree(destination); sync_dir(destination.parent)
        result=self.inspect(destination,expected['identity'])
        if result['sha256']!=expected['sha256']:
            raise UpdateError('Backup copy verification failed')
        return result

    def _space(self,required,*paths):
        # Group by volume so same-volume allocations are added, not independently
        # compared against a free-space value that each copy could consume.
        volumes={}
        for path,count in paths:
            volume=path.stat().st_dev
            old=volumes.get(volume,(path,0))
            volumes[volume]=(path,old[1]+count)
        for path,count in volumes.values():
            if shutil.disk_usage(path).free < required*count+DISK_RESERVE:
                raise UpdateError('Insufficient update or recovery space')

    def prepare(self,manifest,credential_generation=0,transaction_id=None):
        with self.lock():
            manifest=validate_manifest(manifest)
            boot_id=self.boot()
            old_journal=self._journal()
            previous_restore=self._recovery()
            if previous_restore and previous_restore['phase'] not in ('accepted','rolled-back'):
                raise UpdateError('Interrupted restoration needs Recovery first')
            if old_journal and old_journal['phase'] not in ('accepted','cancelled','restored'):
                raise UpdateError('Previous update needs reconciliation')
            canonical_target(self.target)
            old=self.inspect(self.target)
            validate_manifest(manifest,old['identity']['build'])
            if old['identity']['data_schema_version']!=manifest['data_schema_version']:
                raise UpdateError('Data schema is incompatible')
            integer(credential_generation,'credential generation',minimum=0)
            original=load_json(self.state/'original.json')
            copies=1 if original else 2
            # Budget backup + extraction/target staging + Sparkle's own copies.
            self._space(max(old['size'],min(MAX_EXPANDED,manifest['archive']['size']*MAX_RATIO)),(self.state,copies),(self.target.parent,4))
            if original:
                self.verify_record(original,self.state/'original.app')
            else:
                if (self.state/'original.app').exists():
                    original=self.inspect(self.state/'original.app',old['identity'])
                    if original['sha256']!=old['sha256']: raise UpdateError('Unrecorded original backup needs manual reconciliation')
                else:
                    original=self._copy(self.target,self.state/'original.app',old)
                durable_json(self.state/'original.json',original)
            transaction=self._transaction(transaction_id) if transaction_id is not None else uuid.uuid4().hex
            backup=self._copy(self.target,self.backups/(transaction+'.app'),old)
            durable_json(self.backups/(transaction+'.json'),backup)
            journal={'schema':JOURNAL_SCHEMA,'transaction_id':transaction,'target_path':str(self.target),
                     'boot_id':boot_id,'phase':'prepared','old':old['identity']|{'sha256':old['sha256']},
                     'expected':manifest,'backup':backup,'credential_generation':credential_generation}
            durable_json(self.state/'journal.json',journal)
            self._rotate(transaction)
            return {'ok':True,'state_dir':str(self.state),'transaction_id':transaction,'journal':journal,'backup':backup}

    def _rotate(self,current):
        records=[]
        for path in self.backups.glob('*.json'):
            if not re.fullmatch(r'[0-9a-f]{32}\.json',path.name): raise UpdateError('Unexpected backup entry')
            record=load_json(path)
            self.verify_record(record,self.backups/(path.stem+'.app'))
            records.append((path.stat().st_mtime_ns,path))
        records.sort(reverse=True)
        retained={current}
        for _,path in records:
            if len(retained)<2: retained.add(path.stem)
        for _,path in records:
            if path.stem not in retained:
                shutil.rmtree(self.backups/(path.stem+'.app')); path.unlink()
        sync_dir(self.backups)

    def _quiescent(self,journal):
        if journal['phase'] in ('prepared','cancelled','restored'): return
        if journal['phase']=='accepted':
            receipt=load_json(self.state/'acceptance.json')
            if receipt and all(receipt.get(k)==journal.get(k) for k in ('transaction_id','target_path')) and receipt.get('build')==journal['expected']['build']:
                return
        if self.boot()!=journal['boot_id']: return
        raise UpdateError('Restart your Mac, then open Recovery before Machine Monitor')

    def status(self):
        with self.lock():
            journal=self._journal()
            if not journal: return {'ok':True,'available':False,'message':'No verified previous version is available'}
            self.verify_record(journal['backup'],Path(journal['backup']['path']))
            try: self._quiescent(journal); permitted=True; reason='Restore the verified previous version'
            except UpdateError as e: permitted=False; reason=str(e)
            return {'ok':True,'available':True,'can_restore':permitted,'transaction_id':journal['transaction_id'],
                    'previous_version':journal['backup']['identity']['version'],'previous_build':journal['backup']['identity']['build'],
                    'phase':journal['phase'],'message':reason,'target_path':str(self.target)}

    def discard(self,transaction):
        with self.lock():
            journal=self._journal()
            if not journal or journal['transaction_id']!=transaction or journal['phase']!='prepared':
                raise UpdateError('Only an unadmitted update can be discarded')
            journal['phase']='cancelled'; durable_json(self.state/'journal.json',journal)
            return {'ok':True,'phase':'cancelled'}

    def _recovery_paths(self,transaction):
        self._transaction(transaction)
        return (self.target.parent/('.machine-monitor-restore-'+transaction+'.app'),
                self.target.parent/('.machine-monitor-saved-'+transaction+'.app'))

    def _recovery(self):
        value=load_json(self.state/'recovery.json')
        if value is None: return None
        if value.get('schema')!=RECOVERY_SCHEMA or value.get('target_path')!=str(self.target): raise UpdateError('Invalid restoration journal')
        stage,saved=self._recovery_paths(value.get('transaction_id'))
        if value.get('stage_path')!=str(stage) or value.get('saved_path')!=str(saved): raise UpdateError('Invalid restoration paths')
        if value.get('phase') not in ('prepared','target-saved','backup-published','accepted','rolled-back'): raise UpdateError('Invalid restoration phase')
        return value

    def _matches(self,path,record):
        if not path.exists() and not path.is_symlink(): raise UpdateError('Required restoration application is missing')
        if record.get('damaged') is True:
            if path.is_symlink() or not path.is_dir() or path.stat().st_uid!=os.getuid(): raise UpdateError('Saved target ownership changed')
            digest,size=tree_digest(path)
            actual={'sha256':digest}
            if size!=record['size']: raise UpdateError('Saved target size changed')
        else:
            actual=self.inspect(path,record['identity'])
        if actual['sha256']!=record['sha256']: raise UpdateError('Restoration application bytes changed')
        return True

    def restore(self,transaction):
        with self.lock():
            journal=self._journal()
            if not journal or journal['transaction_id']!=transaction: raise UpdateError('Update selection changed')
            self._quiescent(journal)
            backup=self.verify_record(journal['backup'],Path(journal['backup']['path']))
            restore=self._recovery()
            if restore and restore['phase'] not in ('accepted','rolled-back'):
                if restore['transaction_id']!=transaction: raise UpdateError('Another restoration needs reconciliation')
                return self._resume(restore,journal)
            if restore and restore['transaction_id']==transaction and restore['phase']=='accepted':
                return self._resume(restore,journal)
            canonical_target(self.target)
            try:
                current=self.inspect(self.target)
            except UpdateError:
                # Only the durable transaction's exact target may be quarantined.
                # Its damaged bytes are never executed or treated as trusted code.
                # Backup authority was independently checked above.
                digest,size=tree_digest(self.target)
                current={'path':str(self.target),'sha256':digest,'size':size,'identity':None,'damaged':True}
            if not current.get('damaged'):
                if current['identity']['build'] not in (journal['old']['build'],journal['expected']['build']):
                    raise UpdateError('Installed build does not match this transaction')
                if current['identity']['data_schema_version']!=backup['identity']['data_schema_version']:
                    raise UpdateError('Restoration data schema is incompatible')
            stage,saved=self._recovery_paths(transaction)
            if saved.exists() or saved.is_symlink(): raise UpdateError('Saved recovery target already exists')
            self._space(backup['size'],(self.target.parent,1))
            if stage.exists():
                staged=self.inspect(stage,backup['identity'])
                if staged['sha256']!=backup['sha256']: raise UpdateError('Incomplete recovery staging needs manual reconciliation')
            else:
                staged=self._copy(Path(backup['path']),stage,backup)
            restore={'schema':RECOVERY_SCHEMA,'transaction_id':transaction,'target_path':str(self.target),
                     'stage_path':str(stage),'saved_path':str(saved),'phase':'prepared','backup':backup,'old':current,
                     'staged':staged,'boot_id':self.boot()}
            durable_json(self.state/'recovery.json',restore)
            self.fault('prepared')
            return self._resume(restore,journal)

    def _phase(self,restore,phase):
        restore['phase']=phase; durable_json(self.state/'recovery.json',restore); self.fault(phase)

    def _resume(self,restore,journal):
        canonical_target(self.target,missing=True)
        stage,saved=self._recovery_paths(restore['transaction_id'])
        if stage.is_symlink() or saved.is_symlink(): raise UpdateError('Restoration path was replaced by a symlink')
        backup=restore['backup']; old=restore['old']
        if restore['phase']=='prepared':
            # Crash after first rename but before phase persistence: verify saved
            # bytes and absence of target, never infer authority from existence.
            if saved.exists():
                self._matches(saved,old)
                if self.target.exists(): raise UpdateError('Ambiguous first restoration rename')
            else:
                canonical_target(self.target)
                self._matches(self.target,old); self._matches(stage,backup)
                self.fault('before-target-rename')
                os.rename(self.target,saved); sync_dir(self.target.parent)
                self.fault('after-target-rename')
            self._phase(restore,'target-saved')
        if restore['phase']=='target-saved':
            self._matches(saved,old)
            if self.target.exists():
                self._matches(self.target,backup)
                if stage.exists(): raise UpdateError('Ambiguous second restoration rename')
            else:
                self._matches(stage,backup)
                self.fault('before-backup-rename')
                try: os.rename(stage,self.target)
                except OSError:
                    if not self.target.exists():
                        os.rename(saved,self.target); sync_dir(self.target.parent)
                        self._phase(restore,'rolled-back')
                    raise UpdateError('Restore failed; the prior target and verified backup were preserved') from None
                sync_dir(self.target.parent); self.fault('after-backup-rename')
            self._phase(restore,'backup-published')
        if restore['phase'] in ('backup-published','accepted'):
            self._matches(self.target,backup); self._matches(saved,old)
            self.fault('before-receipt')
            receipt={'schema':'machine-monitor/recovery-receipt/v1','transaction_id':journal['transaction_id'],
                     'target_path':str(self.target),'build':backup['identity']['build'],'sha256':backup['sha256'],
                     'boot_id':self.boot(),'monitoring_started':False}
            durable_json(self.state/'recovery-receipt.json',receipt); self.fault('after-receipt')
            self._phase(restore,'accepted')
            # The restored app is a future explicit launch, never an updater relaunch.
            for name in ('relaunch.json','relaunch-consumed.json'):
                marker=self.state/name
                if marker.exists() or marker.is_symlink():
                    fd=os.open(marker,os.O_RDONLY|os.O_NOFOLLOW)
                    try:
                        info=os.fstat(fd)
                        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:
                            raise UpdateError('Invalid relaunch marker ownership')
                    finally: os.close(fd)
                    marker.unlink(); sync_dir(self.state)
            journal['phase']='restored'; journal['restored']=backup['identity']
            durable_json(self.state/'journal.json',journal)
            return {'ok':True,'phase':'accepted','target_path':str(self.target),'restored':backup['identity'],
                    'message':'Previous version restored. Open Machine Monitor when you are ready.'}
        raise UpdateError('Restoration was rolled back; verified backup retained')


def main(stdin=None,stdout=None):
    stdin=stdin or sys.stdin; stdout=stdout or sys.stdout
    try:
        request=read_request(stdin)
        allowed={'action','target_path','manifest','transaction_id','credential_generation'}
        if set(request)-allowed or request.get('action') not in ('status','prepare','restore','discard'):
            raise UpdateError('Invalid recovery request')
        store=RecoveryStore(request.get('target_path'))
        action=request['action']
        if action=='prepare': result=store.prepare(request.get('manifest'),request.get('credential_generation',0),request.get('transaction_id'))
        elif action=='restore': result=store.restore(request.get('transaction_id'))
        elif action=='discard': result=store.discard(request.get('transaction_id'))
        else: result=store.status()
    except (UpdateError,OSError,ValueError,KeyError,TypeError,RuntimeError) as error:
        result={'ok':False,'error':str(error) if isinstance(error,UpdateError) else 'Recovery validation failed; retained applications were not discarded'}
    stdout.write(json.dumps(result)+'\n')
    return 0 if result['ok'] else 1


if __name__=='__main__':
    raise SystemExit(main())
