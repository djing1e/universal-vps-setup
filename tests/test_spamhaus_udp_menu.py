"""Run isolated menu functions with fake service/activation commands."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class UDPMenuTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.config=self.root/'config';self.config.mkdir()
        self.target=self.root/'module'
        self.target.write_bytes((ROOT/'modules/xtls-spamhaus-udp.py').read_bytes())
        self.target.chmod(0o755)
        self.calls=self.root/'calls'
        self.bin=self.root/'bin';self.bin.mkdir()
        self.tool('systemd-run', "if os.environ.get('FAIL_TIMER'): sys.exit(1)")
        self.tool('systemctl', "if sys.argv[1]=='is-active': sys.exit(0 if os.environ.get('TIMER_ACTIVE') else 3)\nif sys.argv[1]=='show': print('loaded')")
        self.tool('fakepython', "print('UDP status/action:',sys.argv[-1])")
        self.tool('nft', "print('chain output { policy accept; }')")
        self.tool('systemd-analyze', 'pass')
        self.tool('curl', '''from pathlib import Path
if os.environ.get('FAIL_DOWNLOAD'): sys.exit(22)
name='xtls-spamhaus-udp.py' if sys.argv[-3].endswith('.py') else 'xtls-spamhaus-udp-restore.service'
raw=(Path(os.environ['MENU_SOURCE_ROOT'])/'modules'/name).read_bytes()
Path(sys.argv[-1]).write_bytes(b'corrupt' if os.environ.get('CORRUPT_DOWNLOAD') else raw)''')
        text=(ROOT/'vps-setup.sh').read_text()
        self.source=text.split('spamhaus_udp_require_installed() {',1)[1].split('setup_spamhaus_out_observe() {',1)[0]
        self.source='spamhaus_udp_require_installed() {'+self.source
        replacements={'/usr/local/sbin/xtls-spamhaus-udp':str(self.target),
                      '/etc/xtls-spamhaus-udp':str(self.config),
                      '/run/xtls-spamhaus-udp.lock':str(self.root/'lock'),
                      '/etc/systemd/system/xtls-spamhaus-udp-restore.service':str(self.root/'restore.service'),
                      '/usr/bin/python3':str(self.bin/'fakepython')}
        for old,new in replacements.items(): self.source=self.source.replace(old,new)
        self.env=dict(os.environ,PATH=str(self.bin)+':'+os.environ['PATH'],MENU_CALLS=str(self.calls),MENU_SOURCE_ROOT=str(ROOT))

    def tool(self,name,body):
        p=self.bin/name
        p.write_text('#!/usr/bin/env python3\nimport os,sys,json\n'
                     'with open(os.environ["MENU_CALLS"],"a") as f: f.write(json.dumps([os.path.basename(sys.argv[0])]+sys.argv[1:])+"\\n")\n'+body+'\n')
        p.chmod(0o755)

    def run_menu(self,choices='',function='setup_spamhaus_udp_drop',**env):
        return subprocess.run(['bash','-c','set -euo pipefail\n'+self.source+'\n'+function],
                              input=choices,text=True,capture_output=True,env=self.env|env)

    def logged(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def test_open_and_exit_has_no_external_actions(self):
        r=self.run_menu('0\n')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(self.logged(),[])
        self.assertEqual(list(self.config.iterdir()),[])

    def test_status_does_not_activate_or_change_services(self):
        r=self.run_menu('2\n0\n')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual([row[-1] for row in self.logged()],['status'])

    def test_unknown_installed_content_is_not_executed(self):
        self.target.write_text('custom module')
        r=self.run_menu('2\n0\n')
        self.assertIn('Неизвестная версия',r.stdout)
        self.assertEqual(self.logged(),[])

    def test_cancel_enable_does_not_schedule_or_enable(self):
        (self.config/'exemptions.txt').write_text('# reviewed\n')
        r=self.run_menu('4\ncancel\n0\n')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(self.logged(),[])

    def test_enable_schedules_safety_before_module_action(self):
        (self.config/'exemptions.txt').write_text('# reviewed\n')
        r=self.run_menu('4\nENABLE-SPAMHAUS-UDP-DROP\n0\n')
        self.assertEqual(r.returncode,0,r.stderr)
        calls=self.logged()
        self.assertEqual(calls[0][0],'systemd-run')
        self.assertIn('--on-active=5m',calls[0])
        self.assertIn('--timer-property=RemainAfterElapse=no',calls[0])
        self.assertEqual(calls[1][-1],'enable-block')

    def test_failed_safety_timer_prevents_enable(self):
        (self.config/'exemptions.txt').write_text('# reviewed\n')
        r=self.run_menu('4\nENABLE-SPAMHAUS-UDP-DROP\n0\n',FAIL_TIMER='1')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(len(self.logged()),1)
        self.assertEqual(self.logged()[0][0],'systemd-run')

    def test_disable_is_explicit_and_routes_only_to_own_module(self):
        r=self.run_menu('5\n0\n')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(self.logged(),[['fakepython',str(self.target),'disable-block']])

    def test_keep_after_auto_disable_does_not_reenable_or_stop_anything(self):
        (self.config/'mode').write_text('observe\n')
        r=self.run_menu('6\n0\n')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(self.logged(),[])

    def test_keep_confirmed_stops_only_safety_timer(self):
        (self.config/'mode').write_text('block\n')
        r=self.run_menu('6\nKEEP-UDP-DROP\n0\n',TIMER_ACTIVE='1')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(self.logged()[1],['systemctl','stop','xtls-sh-udp-safety.timer'])
        self.assertEqual(self.logged()[2][-1],'status')

    def test_exemptions_require_observe_and_validate_before_writing(self):
        p=self.config/'exemptions.txt';p.write_text('192.0.2.1/32\n')
        (self.config/'mode').write_text('block\n')
        self.run_menu('3\n0\n')
        self.assertEqual(p.read_text(),'192.0.2.1/32\n')
        (self.config/'mode').write_text('observe\n')
        self.run_menu('3\n0.0.0.0/0\n0\n')
        self.assertEqual(p.read_text(),'192.0.2.1/32\n')
        r=self.run_menu('3\n192.0.2.10,2001:db8::1\n0\n')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(p.read_text(),'192.0.2.10/32\n2001:db8::1/128\n')
        self.assertTrue(list(self.config.glob('exemptions.txt.bak-*')))

    def test_summary_uses_chain_not_full_table_dump(self):
        r=self.run_menu(function='spamhaus_output_summary')
        self.assertEqual(r.returncode,0,r.stderr)
        nft_calls=[row for row in self.logged() if row[0]=='nft']
        self.assertEqual(nft_calls,[['nft','-a','list','chain','inet','xtls_spamhaus_out','output']])

    def test_install_download_failure_or_bad_hash_does_not_enable_service(self):
        for variable in ('FAIL_DOWNLOAD','CORRUPT_DOWNLOAD'):
            with self.subTest(variable=variable):
                self.calls.unlink(missing_ok=True)
                original=self.target.read_bytes()
                r=self.run_menu(function='spamhaus_udp_install',**{variable:'1'})
                self.assertNotEqual(r.returncode,0)
                self.assertEqual(self.target.read_bytes(),original)
                self.assertFalse((self.root/'restore.service').exists())
                self.assertFalse(any(row[:2]==['systemctl','enable'] for row in self.logged()))

    def test_install_matching_files_preserves_mode_and_exemptions(self):
        (self.config/'mode').write_text('observe\n')
        (self.config/'exemptions.txt').write_text('192.0.2.10\n')
        for _ in range(2):
            r=self.run_menu(function='spamhaus_udp_install')
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual((self.config/'mode').read_text(),'observe\n')
            self.assertEqual((self.config/'exemptions.txt').read_text(),'192.0.2.10\n')
        self.assertFalse(any(row[-1]=='enable-block' for row in self.logged()))

    def test_install_refuses_unknown_unit_without_overwriting(self):
        unit=self.root/'restore.service';unit.write_text('local unit')
        r=self.run_menu(function='spamhaus_udp_install')
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(unit.read_text(),'local unit')


if __name__=='__main__': unittest.main()
