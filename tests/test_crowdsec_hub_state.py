"""Emulate 1.4 JSON inspection, including failed human metrics and tainted packages."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/'vps-setup.sh').read_text()
HELPERS='crowdsec_hub_item_state() ('+SOURCE.split('crowdsec_hub_item_state() (',1)[1].split('crowdsec_install() {',1)[0]


class HubStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.bin=self.root/'bin';self.bin.mkdir()
        self.calls=self.root/'calls'
        self.env=dict(os.environ,PATH=str(self.bin)+':'+os.environ['PATH'],FIXTURE=str(self.root))
        path=self.bin/'cscli'
        path.write_text('#!'+sys.executable+'\n'+'''import os,sys,json
from pathlib import Path
root=Path(os.environ['FIXTURE'])
with (root/'calls').open('a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')
args=sys.argv[1:]
if args[:2]==['hub','update']: sys.exit(0)
kind,action,name=args[:3]
if action=='inspect':
    if '-o' not in args or args[-1]!='json':
        print('metrics connection refused',file=sys.stderr);sys.exit(1)
    if os.environ.get('INSPECT_ERROR'):
        print('config failed',file=sys.stderr);sys.exit(1)
    if os.environ.get('MISSING_INDEX') and not (root/'installed').exists():
        print('unable to retrieve item.',file=sys.stderr);sys.exit(1)
    if os.environ.get('INVALID_JSON'): print('invalid');sys.exit(0)
    obj={'type':kind,'name':name,'tainted':os.environ.get('TAINTED')=='1'}
    if not os.environ.get('OMIT_INSTALLED'):
        obj['installed']=(root/'installed').exists() or os.environ.get('INSTALLED','1')=='1'
    if os.environ.get('WRONG_NAME'): obj['name']='other/item'
    if os.environ.get('STRING_STATE'): obj['installed']='true'
    print(json.dumps(obj));sys.exit(0)
if action=='install':
    if os.environ.get('STALE') and not (root/'retried').exists():
        (root/'retried').touch();print('invalid download hash',file=sys.stderr);sys.exit(1)
    if os.environ.get('FAIL_INSTALL'):
        print("tainted, won't enable unless --force",file=sys.stderr);sys.exit(1)
    if not os.environ.get('FAKE_SUCCESS'): (root/'installed').touch()
    sys.exit(0)
sys.exit(1)
''');path.chmod(0o755)

    def run_helper(self, entry='crowdsec_ensure_collection crowdsecurity/linux required',**env):
        return subprocess.run(['bash','-c',HELPERS+'\n'+entry],text=True,capture_output=True,env=self.env|env,timeout=5)

    def logged(self):
        return [json.loads(x) for x in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def test_installed_tainted_skips_install_and_human_metrics(self):
        result=self.run_helper(TAINTED='1')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.logged(),[['collections','inspect','crowdsecurity/linux','-o','json']])
        self.assertIn('уже установлена',result.stdout)

    def test_available_but_not_installed_does_not_skip_install(self):
        result=self.run_helper(INSTALLED='0')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual([x[1] for x in self.logged()],['inspect','install','inspect'])

    def test_omitted_legacy_false_is_not_installed(self):
        result=self.run_helper('crowdsec_hub_item_state collections crowdsecurity/linux',OMIT_INSTALLED='1')
        self.assertEqual(result.returncode,1,result.stderr)

    def test_unknown_states_never_trigger_install(self):
        for flag in ('INSPECT_ERROR','INVALID_JSON','WRONG_NAME','STRING_STATE'):
            self.calls.unlink(missing_ok=True)
            result=self.run_helper(**{flag:'1'})
            self.assertNotEqual(result.returncode,0)
            self.assertTrue(all(x[1]=='inspect' for x in self.logged()))

    def test_optional_unknown_is_preserved_with_warning(self):
        result=self.run_helper('crowdsec_ensure_collection crowdsecurity/linux optional',INVALID_JSON='1')
        self.assertEqual(result.returncode,0)
        self.assertIn('неизвестно',result.stdout)
        self.assertEqual(len(self.logged()),1)

    def test_tainted_but_disabled_requires_review_without_install(self):
        result=self.run_helper(TAINTED='1',INSTALLED='0')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(len(self.logged()),1)

    def test_install_success_is_verified(self):
        result=self.run_helper(INSTALLED='0',FAKE_SUCCESS='1')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('не подтверждена',result.stdout)

    def test_missing_index_entry_still_tries_normal_install(self):
        result=self.run_helper(MISSING_INDEX='1')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(['collections','install','crowdsecurity/linux'],self.logged())

    def test_stale_hash_refreshes_once_and_verifies(self):
        result=self.run_helper(INSTALLED='0',STALE='1')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.logged().count(['hub','update']),1)
        self.assertEqual(self.logged().count(['collections','install','crowdsecurity/linux']),2)

    def test_install_failure_never_uses_force(self):
        result=self.run_helper(INSTALLED='0',FAIL_INSTALL='1')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(any('--force' in x for x in self.logged()))

    def test_parser_check_also_uses_installed_json_state(self):
        result=self.run_helper('crowdsec_hub_item_state parsers crowdsecurity/sshd-logs',TAINTED='1')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.logged(),[['parsers','inspect','crowdsecurity/sshd-logs','-o','json']])
