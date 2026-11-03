"""Managed install uses real files and fake systemd; failures restore absence."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'lib'))
from guard_engine_upgrade import Upgrade, ENGINE, SERVICE, TIMER, digest
from guard_managed_install import Install
from module_registry import Registration


class ManagedInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        for path in ('run','etc/systemd/system','usr/local/sbin','var/lib'):(self.root/path).mkdir(parents=True,exist_ok=True)
        (self.root/'etc/os-release').write_text('ID=debian\nVERSION_ID=13\n')
        self.bundle=self.root/'bundle';self.bundle.mkdir()
        data=[b'print("guard")\n',b'service\n',b'timer\n']
        self.policy={'target_revision':'a'*40,'target_sha256':digest(data[0]),'accepted_current_sha256':[digest(data[0])],
                     'units':{SERVICE:digest(data[1]),TIMER:digest(data[2])}}
        resources={path:{'sha256':digest(raw),'allowed_modes':[0o755] if i==0 else [0o600,0o644]}
                   for i,(path,raw) in enumerate(zip((ENGINE,'/etc/systemd/system/'+SERVICE,'/etc/systemd/system/'+TIMER),data))}
        self.catalog={'schema_version':1,'components':{'auto-abuse-guard':{
            'version':'1.0.0-rc.1','source_revision':'a'*40,'resources':resources}}}
        for name,raw in zip(('xtls-auto-abuse-guard.py','xtls-auto-abuse-guard.service','xtls-auto-abuse-guard.timer'),data):
            (self.bundle/name).write_bytes(raw)
        self.calls=[];self.enabled=False;self.active=False;self.fail_scan=False
        self.registration=Registration(self.root,self.catalog)
        self.guard=Upgrade(self.policy,self.root,self.runner,self.registration)
        self.install=Install(self.guard)

    def runner(self,argv,timeout):
        self.calls.append(argv);action=argv[1]
        if action=='show':
            name=argv[3];present=(self.root/'etc/systemd/system'/name).exists()
            if argv[-1]=='--property=LoadState':return {'status':'ok','output':'LoadState='+('loaded' if present else 'not-found')}
            if argv[-1]=='--property=Result,ExecMainStatus':return {'status':'ok','output':'Result=success\nExecMainStatus=0'}
            values={'LoadState':'loaded','ActiveState':'active' if name==TIMER and self.active else 'inactive',
                    'SubState':'waiting' if name==TIMER and self.active else 'dead','UnitFileState':('enabled' if self.enabled else 'disabled') if name==TIMER else 'static',
                    'FragmentPath':'/etc/systemd/system/'+name,'DropInPaths':'','NeedDaemonReload':'no'}
            return {'status':'ok','output':'\n'.join(k+'='+v for k,v in values.items())}
        if action=='enable':self.enabled=True;self.active=True
        elif action=='disable':self.enabled=False;self.active=False
        elif action=='stop' and argv[-1]==TIMER:self.active=False
        elif action=='start' and argv[-1]==TIMER:self.active=True
        elif action=='start' and argv[-1]==SERVICE and self.fail_scan:return {'status':'error'}
        elif action not in ('start','stop','reset-failed','daemon-reload'):raise AssertionError(argv)
        return {'status':'ok','output':''}

    def test_check_clean_install_has_no_writes_or_control_actions(self):
        before=set(self.root.rglob('*'))
        result=self.install.check(self.bundle)[0]
        self.assertEqual(result['status'],'ready_fresh_install')
        self.assertEqual(before,set(self.root.rglob('*')))
        self.assertTrue(all(c[1]=='show' for c in self.calls))

    def test_fresh_install_registers_only_after_success_and_repeat_is_noop(self):
        result=self.install.apply(self.bundle)
        self.assertEqual(result['status'],'installed')
        self.assertTrue(self.enabled and self.active)
        receipt=self.registration.snapshot();self.assertEqual(json.loads(receipt)['provenance'],'managed_install')
        self.calls.clear()
        self.assertEqual(self.install.apply(self.bundle)['status'],'noop')
        self.assertEqual(self.registration.snapshot(),receipt)
        self.assertTrue(all(c[1]=='show' for c in self.calls))

    def test_scan_failure_restores_absent_files_and_receipt(self):
        self.fail_scan=True
        with self.assertRaisesRegex(RuntimeError,'created resources and receipt removed'):self.install.apply(self.bundle)
        self.assertTrue(all(not p.exists() for p in self.install.paths))
        self.assertIsNone(self.registration.current());self.assertFalse(self.enabled or self.active)
        record=next(self.guard.backups.glob('*/transaction.json'))
        self.assertEqual(json.loads(record.read_text())['status'],'rolled_back')

    def test_registry_write_failure_after_creation_also_rolls_back_files(self):
        original=self.registration.replace
        def fail(expected,new):
            original(expected,new)
            if new is not None:raise OSError('receipt fsync failed')
        with patch.object(self.registration,'replace',side_effect=fail):
            with self.assertRaisesRegex(RuntimeError,'created resources and receipt removed'):self.install.apply(self.bundle)
        self.assertTrue(all(not p.exists() for p in self.install.paths));self.assertIsNone(self.registration.current())

    def test_existing_unregistered_install_only_records_and_preserves_disabled_timer(self):
        for path in self.install.paths:
            # Use fixed name mapping, independent of directory iteration order.
            name='xtls-auto-abuse-guard.py' if path.name=='xtls-auto-abuse-guard' else path.name
            path.write_bytes((self.bundle/name).read_bytes());path.chmod(0o755 if name.endswith('.py') else 0o644)
        self.calls.clear()
        result=self.install.apply(self.bundle)
        self.assertEqual(result['status'],'registered_existing')
        self.assertFalse(self.enabled or self.active)
        self.assertTrue(all(c[1]=='show' for c in self.calls))

    def test_unknown_partial_or_corrupt_registration_blocks_install(self):
        self.install.paths[0].write_text('custom')
        with self.assertRaises(ValueError):self.install.apply(self.bundle)
        self.assertTrue(all(c[1]=='show' for c in self.calls))
        self.assertEqual(self.install.paths[0].read_text(),'custom')

    def test_bundle_hash_error_is_refused_before_mutations(self):
        (self.bundle/'xtls-auto-abuse-guard.py').write_text('different')
        with self.assertRaises(ValueError):self.install.apply(self.bundle)
        self.assertEqual(self.calls,[])

    def test_real_unit_artifacts_match_existing_installer_policy(self):
        policy=json.loads((ROOT/'lib/guard_engine_policy.json').read_text())
        for name,expected in policy['units'].items():self.assertEqual(digest((ROOT/'modules'/name).read_bytes()),expected)


if __name__=='__main__':unittest.main()
