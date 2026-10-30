"""Exercise the actual Bash menu wrapper with pinned fixture downloads/fake updater."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/'vps-setup.sh').read_text()


class GuardMenuTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.bin=self.root/'bin';self.bin.mkdir()
        self.calls=self.root/'calls'
        self.env=dict(os.environ,PATH=str(self.bin)+':'+os.environ['PATH'],
                      FIXTURE_ROOT=str(ROOT),CALLS=str(self.calls))
        self.source='guard_engine_menu_action() ('+SOURCE.split('guard_engine_menu_action() (',1)[1].split('setup_auto_abuse_guard() {',1)[0]
        self.source=self.source.replace('/tmp/xtls-guard-upgrade.',str(self.root/'bundle.'))
        self.tool('curl', '''from pathlib import Path
if os.environ.get('FAIL_DOWNLOAD'): sys.exit(22)
url=sys.argv[-3];name=url.split('/')[-1]
source=('modules/' if name in ('xtls-auto-abuse-guard.py','xtls-auto-abuse-guard.service','xtls-auto-abuse-guard.timer') else 'lib/')+name
raw=(Path(os.environ['FIXTURE_ROOT'])/source).read_bytes()
Path(sys.argv[-1]).write_bytes(b'corrupt' if os.environ.get('CORRUPT') else raw)
''')
        self.tool('python3', '''if len(sys.argv)>2 and sys.argv[1].endswith(('guard_engine_upgrade.py','guard_managed_install.py')):
    action=sys.argv[2]
    with open(os.environ['CALLS'],'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')
    if action=='check':
        if os.environ.get('FAIL_CHECK'): sys.exit(1)
        print(json.dumps({'status':os.environ.get('CHECK_STATUS','ready_for_explicit_apply'),'changes_applied':False}))
    elif os.environ.get('FAIL_APPLY'): sys.exit(1)
    else: print('{"status":"updated"}')
    sys.exit(0)
os.execv(sys.executable,[sys.executable]+sys.argv[1:])
''')

    def tool(self,name,body):
        path=self.bin/name
        path.write_text('#!'+sys.executable+'\nimport os,sys,json\n'+body)
        path.chmod(0o755)

    def run_action(self,action='check',answer='',**env):
        result=subprocess.run(['bash','-c','set -euo pipefail\n'+self.source+'\nguard_engine_menu_action '+action],
                              input=answer,text=True,capture_output=True,env=self.env|env)
        self.assertFalse(list(self.root.glob('bundle.*')),'temporary bundle leaked')
        return result

    def actions(self):
        return [json.loads(row) for row in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def test_check_only_runs_preflight(self):
        result=self.run_action()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual([row[1] for row in self.actions()],['check'])
        self.assertIn('Доступно обновление',result.stdout)

    def test_current_version_skips_confirmation_and_apply(self):
        result=self.run_action('apply',CHECK_STATUS='noop')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual([row[1] for row in self.actions()],['check'])
        self.assertIn('уже актуален',result.stdout)
        self.assertNotIn('Для обновления введите',result.stdout)

    def test_download_failures_or_hash_mismatch_never_execute_updater(self):
        for flag in ('FAIL_DOWNLOAD','CORRUPT'):
            self.calls.unlink(missing_ok=True)
            result=self.run_action('apply','UPDATE-GUARD-ENGINE\n',**{flag:'1'})
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.actions(),[])

    def test_preflight_failure_never_applies(self):
        result=self.run_action('apply','UPDATE-GUARD-ENGINE\n',FAIL_CHECK='1')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual([row[1] for row in self.actions()],['check'])

    def test_unexpected_check_status_is_refused(self):
        result=self.run_action('apply','UPDATE-GUARD-ENGINE\n',CHECK_STATUS='blocked')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual([row[1] for row in self.actions()],['check'])

    def test_cancel_or_eof_has_no_apply(self):
        for answer in ('cancel\n',''):
            self.calls.unlink(missing_ok=True)
            result=self.run_action('apply',answer)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual([row[1] for row in self.actions()],['check'])

    def test_confirmed_apply_uses_verified_candidate_and_explicit_phrase(self):
        result=self.run_action('apply','UPDATE-GUARD-ENGINE\n')
        self.assertEqual(result.returncode,0,result.stderr)
        check,apply=self.actions()
        self.assertEqual([check[1],apply[1]],['check','apply'])
        self.assertEqual(check[check.index('--candidate')+1],apply[apply.index('--candidate')+1])
        self.assertEqual(apply[-2:],['--confirm','UPDATE-GUARD-ENGINE'])

    def test_apply_failure_propagates_without_success(self):
        result=self.run_action('apply','UPDATE-GUARD-ENGINE\n',FAIL_APPLY='1')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual([row[1] for row in self.actions()],['check','apply'])
        self.assertNotIn('"status":"updated"',result.stdout)

    def test_invalid_action_is_refused_before_download(self):
        result=self.run_action('remove')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.actions(),[])

    def test_managed_install_requires_distinct_confirmation(self):
        result=self.run_action('install','INSTALL-GUARD-OBSERVE\n',CHECK_STATUS='ready_fresh_install')
        self.assertEqual(result.returncode,0,result.stderr)
        check,install=self.actions()
        self.assertTrue(check[0].endswith('guard_managed_install.py'))
        self.assertEqual(install[1],'install')
        self.assertEqual(install[-2:],['--confirm','INSTALL-GUARD-OBSERVE'])
        self.assertIn('--bundle',install)

    def test_install_does_not_accept_update_confirmation(self):
        result=self.run_action('install','UPDATE-GUARD-ENGINE\n',CHECK_STATUS='ready_register_existing')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual([r[1] for r in self.actions()],['check'])

    def test_menu_routes_managed_install_and_updates_without_legacy_install(self):
        menu='setup_auto_abuse_guard() {'+SOURCE.split('setup_auto_abuse_guard() {',1)[1].split('setup_smtp25_guard() {',1)[0]
        # Isolate the existing installer download used when opening the menu.
        menu=menu.replace('/tmp/xtls-auto-guard.',str(self.root/'installer.'))
        self.tool('curl', 'from pathlib import Path\nPath(sys.argv[-1]).write_text("#!/bin/bash\\nexit 99\\n")\n')
        override='\nguard_engine_menu_action() { echo "$1" >> "$CALLS"; }\n'
        result=subprocess.run(['bash','-c','set -euo pipefail\n'+menu+override+'\nsetup_auto_abuse_guard'],
                              input='1\n5\n6\n0\n',text=True,capture_output=True,env=self.env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.calls.read_text().splitlines(),['install','check','apply'])
        self.assertFalse(list(self.root.glob('installer.*')))


if __name__=='__main__':unittest.main()
