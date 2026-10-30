#!/usr/bin/env python3
"""Managed Guard installation: files, verification and release receipt in one transaction."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import uuid
import tempfile

from guard_engine_upgrade import Upgrade, POLICY, ENGINE, SERVICE, TIMER, read_regular, atomic_write, digest


def create_resource(path,data,mode,created):
    fd,temporary=tempfile.mkstemp(prefix='.guard-install-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchown(stream.fileno(),0,0);os.fchmod(stream.fileno(),mode)
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.link(temporary,path,follow_symlinks=False)
        created.append((path,data))
    finally:
        Path(temporary).unlink(missing_ok=True)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


class Install:
    def __init__(self, guard):
        self.guard=guard
        self.root=guard.root
        self.paths=[self.root/ENGINE.lstrip('/'),self.root/'etc/systemd/system'/SERVICE,self.root/'etc/systemd/system'/TIMER]

    def bundle(self, directory):
        names=['xtls-auto-abuse-guard.py','xtls-auto-abuse-guard.service','xtls-auto-abuse-guard.timer']
        raw=[read_regular(directory/name)[0] for name in names]
        expected=[self.guard.policy['target_sha256'],self.guard.policy['units'][SERVICE],self.guard.policy['units'][TIMER]]
        if [digest(data) for data in raw]!=expected: raise ValueError('installation bundle fingerprint mismatch')
        compile(raw[0],str(directory/names[0]),'exec')
        if self.guard.registration.release['resources'][ENGINE]['sha256']!=expected[0]:
            raise ValueError('registry target and install policy disagree')
        return raw

    def check(self,directory):
        raw=self.bundle(directory)
        exists=[path.exists() or path.is_symlink() for path in self.paths]
        receipt=self.guard.registration.snapshot()
        if all(exists):
            report=self.guard.check(directory/'xtls-auto-abuse-guard.py')[0]
            if report['status']!='noop': raise ValueError('use engine update for an older installation')
            return dict(report,status='noop' if receipt is not None else 'ready_register_existing'),raw
        if any(exists) or receipt is not None: raise ValueError('partial installation requires manual review')
        # Do not replace cached/transient/foreign units with absent disk files.
        for name in (SERVICE,TIMER):
            out=self.guard.command('show','--no-pager',name,'--property=LoadState')
            if out.strip()!='LoadState=not-found': raise ValueError('existing unit requires review: '+name)
        from vps_inventory import os_identity
        props=os_identity(self.root)['properties']
        if (props.get('ID'),props.get('VERSION_ID')) not in (('debian','13'),('ubuntu','24.04')):
            raise ValueError('unsupported or unknown OS')
        return {'status':'ready_fresh_install','changes_applied':False,'component':'auto-abuse-guard'},raw

    def apply(self,directory):
        if os.geteuid()!=0: raise ValueError('root required')
        guard=self.guard
        with guard.locked():
            # Both installer and engine updater block unresolved transactions.
            guard.unresolved()
            report,raw=self.check(directory)
            before=guard.registration.snapshot()
            if report['status']=='noop': return report
            if report['status']=='ready_register_existing':
                proposed=guard.registration.prepare('managed_install')
                try:
                    guard.registration.replace(before,proposed)
                    guard.registration.snapshot()
                except Exception:
                    guard.registration.restore(before,proposed)
                    raise
                return dict(report,status='registered_existing',changes_applied=True)
            guard.backups.mkdir(mode=0o700,parents=True,exist_ok=True)
            directory_backup=guard.backups/(dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-install-'+uuid.uuid4().hex)
            directory_backup.mkdir(mode=0o700)
            def save(status):
                atomic_write(directory_backup/'transaction.json',json.dumps({'operation':'install','status':status,'previous_files_absent':True,
                    'registry_before_present':False,'target_revision':guard.policy['target_revision'],
                    'target_sha256':guard.policy['target_sha256'],'unit_sha256':guard.policy['units']}).encode()+b'\n',0o600)
            save('pending')
            attempted=[];controls=False;proposed=None
            try:
                for name,data in zip(('candidate-engine','candidate-service','candidate-timer'),raw):
                    atomic_write(directory_backup/name,data,0o600)
                for index,(path,data) in enumerate(zip(self.paths,raw)):
                    for parent in (path.parent,*path.parent.parents):
                        if parent.is_symlink(): raise ValueError('installation path symlink requires review')
                    path.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
                    if path.exists() or path.is_symlink(): raise ValueError('resource appeared during installation')
                    create_resource(path,data,0o755 if index==0 else 0o644,attempted)
                controls=True
                guard.command('daemon-reload')
                guard.command('enable','--now',TIMER)
                guard.verify_scan()
                guard.check(self.paths[0])
                proposed=guard.registration.prepare('managed_install')
                guard.registration.replace(before,proposed)
                guard.registration.snapshot()
                guard.verify_timer({'timer_active':True,'timer_enabled':'enabled'})
                save('committed')
                return dict(report,status='installed',changes_applied=True,backup=str(directory_backup))
            except Exception as failure:
                try:
                    if controls:
                        guard.command('disable','--now',TIMER)
                        guard.command('stop',SERVICE)
                    guard.registration.restore(before,proposed)
                    for path,data in reversed(attempted):
                        if not path.exists() and not path.is_symlink(): continue
                        if read_regular(path)[0]!=data: raise ValueError('external resource change; refusing cleanup')
                        path.unlink()
                    if controls: guard.command('daemon-reload')
                    save('rolled_back')
                except Exception as recovery:
                    save('recovery_required')
                    raise RuntimeError('install rollback incomplete; backup: '+str(directory_backup)+'; '+str(recovery)) from failure
                raise RuntimeError('installation failed; created resources and receipt removed; '+str(failure)) from failure


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['check','install'])
    parser.add_argument('--bundle',required=True,type=Path)
    parser.add_argument('--confirm')
    args=parser.parse_args()
    try:
        if args.action=='install' and args.confirm!='INSTALL-GUARD-OBSERVE': raise ValueError('explicit INSTALL-GUARD-OBSERVE required')
        operation=Install(Upgrade(json.loads(POLICY.read_text())))
        result=operation.check(args.bundle)[0] if args.action=='check' else operation.apply(args.bundle)
        print(json.dumps(result,indent=2))
    except (OSError,ValueError,RuntimeError,SyntaxError) as error:
        parser.exit(1,'Managed install refused: '+str(error)+'\n')


if __name__=='__main__':main()
