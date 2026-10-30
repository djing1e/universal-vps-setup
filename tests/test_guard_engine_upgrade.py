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
        (self.root/'var/lib').mkdir(parents=True)
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
        resources={upgrade.ENGINE:{'sha256':self.policy['target_sha256'],'allowed_modes':[0o755]}}
        for name,digest in self.policy['units'].items():
            resources['/etc/systemd/system/'+name]={'sha256':digest,'allowed_modes':[0o600,0o644]}
        self.catalog={'schema_version':1,'components':{'auto-abuse-guard':{
            'version':'1.0.0-rc.1','source_revision':'a'*40,'resources':resources}}}
        self.registration=upgrade.Registration(self.root,self.catalog)
        self.guard=upgrade.Upgrade(self.policy,self.root,self.runner,self.registration)
        self.history=self.root/'history.json';self.history.write_text('history untouched')

    def runner(self, argv, timeout):
        self.assertEqual(argv[0],'systemctl')
        self.assertIn(argv[1],('show','start','stop','reset-failed'))
        self.assertTrue(any(name in argv for name in (upgrade.SERVICE,upgrade.TIMER)))
        self.calls.append(argv)
        action=argv[1]
        name=next(name for name in (upgrade.SERVICE,upgrade.TIMER) if name in argv)
        if action=='show':
            fields={'Result':'success','ExecMainStatus':'0'} if '--property=Result,ExecMainStatus' in argv else self.states[name]
            return {'status':'ok','output':'\n'.join(k+'='+v for k,v in fields.items())}
        if action=='reset-failed':
            return {'status':'ok','output':''}
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

    def test_exhausted_start_budget_is_reset_for_candidate_and_rollback(self):
        original=self.guard.runner
        budget={'starts':5}
        def runner(argv, timeout):
            if argv==['systemctl','reset-failed',upgrade.SERVICE]:
                budget['starts']=0
            if argv==['systemctl','start',upgrade.SERVICE]:
                budget['starts']+=1
                if budget['starts']>1: return {'status':'error'}
            return original(argv, timeout)
        self.guard.runner=runner
        self.fail_scan=True
        with self.assertRaisesRegex(RuntimeError,'old engine and timer restored'):
            self.guard.apply(self.candidate)
        resets=[c for c in self.calls if c[1]=='reset-failed']
        self.assertEqual(resets,[['systemctl','reset-failed',upgrade.SERVICE]]*2)
        self.assertEqual(self.engine.read_bytes(),self.old)
        self.assertEqual(self.records()[0]['status'],'rolled_back')
        self.assertEqual(self.states[upgrade.TIMER]['ActiveState'],'active')

    def test_preexisting_failed_service_is_still_refused_without_reset(self):
        self.states[upgrade.SERVICE]['ActiveState']='failed'
        with self.assertRaises(ValueError):self.guard.apply(self.candidate)
        self.assertTrue(all(c[1]=='show' for c in self.calls))
        self.assertFalse(self.guard.backups.exists())

    def reset_result_runner(self, result):
        original=self.guard.runner
        def runner(argv, timeout):
            if argv==['systemctl','reset-failed',upgrade.SERVICE]:
                self.calls.append(argv)
                return result
            return original(argv, timeout)
        self.guard.runner=runner

    def test_unloaded_inactive_service_is_validated_then_started(self):
        self.reset_result_runner({'status':'error','output':
            'Failed to reset failed state of unit '+upgrade.SERVICE+': Unit '+upgrade.SERVICE+' not loaded.'})
        self.guard.verify_scan()
        self.assertEqual([call[1] for call in self.calls],['reset-failed','show','start','show'])
        self.assertIn(upgrade.SERVICE, self.calls[1])

    def test_reset_failure_other_than_exact_unloaded_unit_is_not_ignored(self):
        for status, output in [('error','Access denied'),('timeout',''),('limited',''),
                               ('error','Unit unrelated.service not loaded.')]:
            self.calls.clear()
            self.guard.runner=self.runner
            self.reset_result_runner({'status':status,'output':output})
            with self.assertRaises(RuntimeError): self.guard.verify_scan()
            self.assertFalse(any(call[1]=='start' for call in self.calls))

    def test_unloaded_diagnostic_does_not_bypass_unknown_or_active_unit(self):
        self.reset_result_runner({'status':'error','output':'Unit '+upgrade.SERVICE+' not loaded.'})
        self.states[upgrade.SERVICE]['ActiveState']='active'
        with self.assertRaises(RuntimeError): self.guard.verify_scan()
        self.states[upgrade.SERVICE]['ActiveState']='inactive'
        self.states[upgrade.SERVICE]['DropInPaths']='/etc/local.conf'
        with self.assertRaises(ValueError): self.guard.verify_scan()
        self.assertFalse(any(call[1]=='start' for call in self.calls))

    def test_real_unloaded_diagnostic_allows_rollback_and_timer_restore(self):
        self.reset_result_runner({'status':'error','output':'Unit '+upgrade.SERVICE+' not loaded.'})
        self.fail_scan=True
        with self.assertRaisesRegex(RuntimeError,'old engine and timer restored'):
            self.guard.apply(self.candidate)
        self.assertEqual(self.engine.read_bytes(),self.old)
        self.assertEqual(self.records()[0]['status'],'rolled_back')
        self.assertEqual(self.states[upgrade.TIMER]['ActiveState'],'active')

    def test_update_commits_matching_registry_record(self):
        self.guard.apply(self.candidate)
        record=json.loads(self.registration.snapshot())
        self.assertEqual(record['provenance'],'managed_update')
        self.assertEqual(record['resources'][upgrade.ENGINE]['sha256'],upgrade.digest(self.new))

    def test_failed_registry_write_after_replace_restores_engine_and_absent_record(self):
        original=self.registration.replace
        def failing(expected,new):
            original(expected,new)
            if new is not None:raise OSError('registry sync failure')
        with patch.object(self.registration,'replace',side_effect=failing):
            with self.assertRaisesRegex(RuntimeError,'old engine and timer restored'):
                self.guard.apply(self.candidate)
        self.assertEqual(self.engine.read_bytes(),self.old)
        self.assertIsNone(self.registration.current())
        self.assertEqual(self.records()[0]['status'],'rolled_back')

    def test_noop_preserves_existing_receipt_byte_for_byte(self):
        self.engine.write_bytes(self.new)
        receipt=self.registration.prepare('managed_install')
        self.registration.replace(None,receipt)
        self.assertEqual(self.guard.apply(self.candidate)['status'],'noop')
        self.assertEqual(self.registration.snapshot(),receipt)
        self.assertTrue(all(c[1]=='show' for c in self.calls))

    def test_registered_drift_blocks_before_service_changes(self):
        self.engine.write_bytes(self.new)
        self.registration.replace(None,self.registration.prepare('managed_install'))
        self.engine.write_bytes(self.old)
        with self.assertRaisesRegex(ValueError,'registered_resources_require_review'):
            self.guard.apply(self.candidate)
        self.assertEqual(self.calls,[])

    def test_policy_matches_release_engine_and_installer_units(self):
        policy=json.loads((ROOT/'lib/guard_engine_policy.json').read_text())
        source=(ROOT/'modules/xtls-auto-abuse-guard-install.sh').read_text()
        for name,var in [(upgrade.SERVICE,'SERVICE'),(upgrade.TIMER,'TIMER')]:
            unit=source.split('cat > "$'+var+'" <<\'UNIT\'\n',1)[1].split('\nUNIT',1)[0]+'\n'
            self.assertEqual(upgrade.digest(unit.encode()),policy['units'][name])
        self.assertEqual(upgrade.digest((ROOT/'modules/xtls-auto-abuse-guard.py').read_bytes()),policy['target_sha256'])


if __name__=='__main__':unittest.main()
