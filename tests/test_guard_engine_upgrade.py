"""Run real file transactions in a private root; all systemd actions are fake."""
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'lib'))
spec = importlib.util.spec_from_file_location('engine_upgrade', ROOT/'lib/guard_engine_upgrade.py')
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.old=b'print("old observer")\n'
        self.new=b'print("new observer")\n'
        self.engine=self.root/upgrade.ENGINE.lstrip('/')
        self.engine.parent.mkdir(parents=True)
        self.engine.write_bytes(self.old);self.engine.chmod(0o755)
        self.candidate=self.root/'candidate';self.candidate.write_bytes(self.new)
        (self.root/'run').mkdir()
        unitdir=self.root/'etc/systemd/system';unitdir.mkdir(parents=True)
        (self.root/'etc/os-release').write_text('ID=debian\nVERSION_ID=13\n')
        self.policy={'target_revision':'a'*40,'target_sha256':upgrade.digest(self.new),
                     'accepted_current_sha256':[upgrade.digest(self.old),upgrade.digest(self.new)],'units':{}}
        for name in (upgrade.SERVICE,upgrade.TIMER):
            data=('unit '+name+'\n').encode()
            (unitdir/name).write_bytes(data)
            self.policy['units'][name]=upgrade.digest(data)
        self.states={name:{'LoadState':'loaded','ActiveState':'active' if name==upgrade.TIMER else 'inactive',
                          'SubState':'waiting' if name==upgrade.TIMER else 'dead','UnitFileState':'enabled',
                          'FragmentPath':'/etc/systemd/system/'+name,'DropInPaths':'','NeedDaemonReload':'no'}
                     for name in (upgrade.SERVICE,upgrade.TIMER)}
        self.calls=[];self.fail_scan=False;self.fail_old=False;self.fail_stop=False
        self.guard=upgrade.Upgrade(self.policy,self.root,self.runner)
        self.history=self.root/'history.json';self.history.write_text('history untouched')

    def runner(self, argv, timeout):
        self.assertEqual(argv[0],'systemctl')
        self.assertIn(argv[1],('show','start','stop'))
        self.assertTrue(any(name in argv for name in (upgrade.SERVICE,upgrade.TIMER)))
        self.calls.append(argv)
        action=argv[1]
        name=next(name for name in (upgrade.SERVICE,upgrade.TIMER) if name in argv)
        if action=='show':
            fields={'Result':'success','ExecMainStatus':'0'} if '--property=Result,ExecMainStatus' in argv else self.states[name]
            return {'status':'ok','output':'\n'.join(k+'='+v for k,v in fields.items())}
        if action=='stop' and self.fail_stop:
            self.fail_stop=False
            return {'status':'error'}
        if action=='start' and name==upgrade.SERVICE:
            if (self.fail_scan and self.engine.read_bytes()==self.new) or self.fail_old:
                return {'status':'error'}
        self.states[name]['ActiveState']='active' if action=='start' and name==upgrade.TIMER else 'inactive'
        return {'status':'ok','output':''}

    def records(self):
        return [json.loads(p.read_text()) for p in self.guard.backups.glob('*/transaction.json')]

    def test_check_is_read_only(self):
        paths=set(self.root.rglob('*'))
        result=self.guard.check(self.candidate)[0]
        self.assertEqual(result['status'],'ready_for_explicit_apply')
        self.assertFalse(result['changes_applied'])
        self.assertEqual(paths,set(self.root.rglob('*')))
        self.assertTrue(all(call[1]=='show' for call in self.calls))

    def test_apply_backup_verified_scan_and_only_own_services(self):
        result=self.guard.apply(self.candidate)
        self.assertEqual(result['status'],'updated')
        self.assertEqual(self.engine.read_bytes(),self.new)
        self.assertEqual(self.engine.stat().st_mode & 0o777,0o755)
        directory=Path(result['backup'])
        self.assertEqual((directory/'engine').read_bytes(),self.old)
        self.assertEqual(self.records()[0]['status'],'committed')
        self.assertEqual(self.history.read_text(),'history untouched')
        self.assertIn(['systemctl','start',upgrade.SERVICE],self.calls)
        for name in self.policy['units']:
            self.assertEqual(upgrade.digest((self.root/'etc/systemd/system'/name).read_bytes()),self.policy['units'][name])

    def test_current_target_is_noop_without_backup_or_service_actions(self):
        self.engine.write_bytes(self.new)
        result=self.guard.apply(self.candidate)
        self.assertEqual(result['status'],'noop')
        self.assertFalse(self.guard.backups.exists())
        self.assertTrue(all(call[1]=='show' for call in self.calls))

    def test_disabled_inactive_timer_stays_disabled_and_no_scan_started(self):
        state=self.states[upgrade.TIMER];state['ActiveState']='inactive';state['UnitFileState']='disabled'
        self.guard.apply(self.candidate)
        self.assertEqual(state['ActiveState'],'inactive')
        self.assertEqual(state['UnitFileState'],'disabled')
        self.assertFalse(any(call[1]=='start' for call in self.calls))

    def test_candidate_failure_rolls_back_and_restores_timer(self):
        self.fail_scan=True
        with self.assertRaisesRegex(RuntimeError,'old engine and timer restored'):
            self.guard.apply(self.candidate)
        self.assertEqual(self.engine.read_bytes(),self.old)
        self.assertEqual(self.records()[0]['status'],'rolled_back')
        self.assertEqual(self.states[upgrade.TIMER]['ActiveState'],'active')
        self.assertEqual(self.history.read_text(),'history untouched')

    def test_failed_rollback_is_explicit_and_blocks_followup(self):
        self.fail_scan=True;self.fail_old=True
        with self.assertRaisesRegex(RuntimeError,'rollback incomplete'):
            self.guard.apply(self.candidate)
        self.assertEqual(self.engine.read_bytes(),self.old)
        self.assertEqual(self.records()[0]['status'],'recovery_required')
        with self.assertRaisesRegex(ValueError,'unfinished transaction'):
            self.guard.apply(self.candidate)

    def test_stop_failure_restores_original_state_without_replacing(self):
        self.fail_stop=True
        with self.assertRaisesRegex(RuntimeError,'old engine and timer restored'):
            self.guard.apply(self.candidate)
        self.assertEqual(self.engine.read_bytes(),self.old)
        self.assertEqual(self.states[upgrade.TIMER]['ActiveState'],'active')

    def test_unknown_files_or_overrides_refuse_before_service_changes(self):
        self.engine.write_bytes(b'custom')
        with self.assertRaises(ValueError):self.guard.apply(self.candidate)
        self.assertFalse(any(c[1]!='show' for c in self.calls))
        self.engine.write_bytes(self.old)
        self.states[upgrade.SERVICE]['DropInPaths']='/etc/custom.conf'
        with self.assertRaises(ValueError):self.guard.apply(self.candidate)
        self.assertFalse(any(c[1]!='show' for c in self.calls))
        self.assertFalse(self.guard.backups.exists())

    def test_changed_unit_and_pending_reload_are_unknown(self):
        for field,value in [('NeedDaemonReload','yes'),('FragmentPath','/other/unit'),('LoadState','masked')]:
            old=self.states[upgrade.SERVICE][field];self.states[upgrade.SERVICE][field]=value
            with self.assertRaises(ValueError):self.guard.check(self.candidate)
            self.states[upgrade.SERVICE][field]=old
        path=self.root/'etc/systemd/system'/upgrade.SERVICE;path.write_text('custom')
        with self.assertRaises(ValueError):self.guard.check(self.candidate)

    def test_candidate_hash_and_symlinks_are_refused(self):
        self.candidate.write_bytes(b'wrong')
        with self.assertRaises(ValueError):self.guard.check(self.candidate)
        self.candidate.unlink();self.candidate.symlink_to(self.engine)
        with self.assertRaises(ValueError):self.guard.check(self.candidate)

    def test_shared_installer_lock_prevents_update(self):
        with self.guard.lock.open('w') as stream:
            fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.guard.apply(self.candidate)
        self.assertEqual(self.calls,[])

    def test_interrupted_transaction_requires_manual_recovery(self):
        directory=self.guard.backups/'unfinished';directory.mkdir(parents=True)
        self.guard.backups.chmod(0o700)
        (directory/'transaction.json').write_text('{"status":"pending"}')
        with self.assertRaisesRegex(ValueError,'unfinished transaction'):
            self.guard.apply(self.candidate)
        self.assertEqual(self.calls,[])

    def test_write_failure_before_or_after_replace_restores_original(self):
        original = upgrade.atomic_write
        for after_replace in (False, True):
            self.calls.clear()
            def failing(path, raw, mode):
                if path == self.engine and raw == self.new:
                    if after_replace: original(path, raw, mode)
                    raise OSError('simulated disk/directory sync failure')
                return original(path, raw, mode)
            with patch.object(upgrade, 'atomic_write', side_effect=failing):
                with self.assertRaisesRegex(RuntimeError, 'old engine and timer restored'):
                    self.guard.apply(self.candidate)
            self.assertEqual(self.engine.read_bytes(), self.old)
            self.assertEqual(self.states[upgrade.TIMER]['ActiveState'], 'active')
            self.assertTrue(all(r['status']=='rolled_back' for r in self.records()))

    def test_backup_failure_happens_before_service_changes(self):
        with patch.object(upgrade, 'atomic_write', side_effect=OSError('disk full')):
            with self.assertRaises(OSError): self.guard.apply(self.candidate)
        self.assertTrue(all(call[1]=='show' for call in self.calls))
        self.assertEqual(self.engine.read_bytes(), self.old)

    def test_unsafe_backup_root_refused_before_probes_or_actions(self):
        self.guard.backups.mkdir(parents=True, mode=0o777)
        self.guard.backups.chmod(0o777)
        with self.assertRaisesRegex(ValueError,'unsafe backup directory'):
            self.guard.apply(self.candidate)
        self.assertEqual(self.calls, [])

    def test_engine_symlink_and_hardlink_refused(self):
        self.engine.unlink();self.engine.symlink_to(self.candidate)
        with self.assertRaises(ValueError): self.guard.check(self.candidate)
        self.engine.unlink();self.engine.write_bytes(self.old)
        os.link(self.engine, self.root/'alias')
        with self.assertRaises(ValueError): self.guard.check(self.candidate)

    def test_nonzero_scan_result_rolls_back_even_when_systemctl_exits_zero(self):
        original=self.guard.runner
        def runner(argv, timeout):
            result=original(argv, timeout)
            if '--property=Result,ExecMainStatus' in argv and self.engine.read_bytes()==self.new:
                return {'status':'ok','output':'Result=exit-code\nExecMainStatus=1\n'}
            return result
        self.guard.runner=runner
        with self.assertRaisesRegex(RuntimeError,'old engine and timer restored'):
            self.guard.apply(self.candidate)
        self.assertEqual(self.engine.read_bytes(),self.old)

    def test_timer_restart_failure_rolls_back(self):
        original=self.guard.runner
        def runner(argv, timeout):
            if argv==['systemctl','start',upgrade.TIMER] and self.engine.read_bytes()==self.new:
                return {'status':'error'}
            return original(argv, timeout)
        self.guard.runner=runner
        with self.assertRaisesRegex(RuntimeError,'old engine and timer restored'):
            self.guard.apply(self.candidate)
        self.assertEqual(self.engine.read_bytes(),self.old)
        self.assertEqual(self.states[upgrade.TIMER]['ActiveState'],'active')

    def test_external_engine_change_is_never_blindly_overwritten(self):
        original=self.guard.runner
        def runner(argv, timeout):
            if argv==['systemctl','start',upgrade.SERVICE] and self.engine.read_bytes()==self.new:
                self.engine.write_bytes(b'admin changed this concurrently')
                return {'status':'error'}
            return original(argv, timeout)
        self.guard.runner=runner
        with self.assertRaisesRegex(RuntimeError,'rollback incomplete'):
            self.guard.apply(self.candidate)
        self.assertEqual(self.engine.read_bytes(),b'admin changed this concurrently')
        self.assertEqual(self.records()[0]['status'],'recovery_required')

    def test_unsupported_os_refused_without_service_actions(self):
        (self.root/'etc/os-release').write_text('ID=debian\nVERSION_ID=12\n')
        with self.assertRaisesRegex(ValueError,'unsupported or unknown OS'):
            self.guard.apply(self.candidate)
        self.assertEqual(self.calls, [])

    def test_policy_matches_release_engine_and_installer_units(self):
        policy=json.loads((ROOT/'lib/guard_engine_policy.json').read_text())
        source=(ROOT/'modules/xtls-auto-abuse-guard-install.sh').read_text()
        for name,var in [(upgrade.SERVICE,'SERVICE'),(upgrade.TIMER,'TIMER')]:
            unit=source.split('cat > "$'+var+'" <<\'UNIT\'\n',1)[1].split('\nUNIT',1)[0]+'\n'
            self.assertEqual(upgrade.digest(unit.encode()),policy['units'][name])
        self.assertEqual(upgrade.digest((ROOT/'modules/xtls-auto-abuse-guard.py').read_bytes()),policy['target_sha256'])


if __name__=='__main__':unittest.main()
