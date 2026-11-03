"""Run the real bundled observer installer in a temporary filesystem with fake services/feeds."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/'vps-setup.sh').read_text()
OBSERVER=SOURCE.split("cat <<'XTLS_SPAMHAUS_OUTPUT_MODULE_END'\n",1)[1].split('\nXTLS_SPAMHAUS_OUTPUT_MODULE_END',1)[0]+'\n'
HELPERS=SOURCE.split('spamhaus_output_ready() {',1)[1].split('spamhaus_udp_install() (',1)[0]
HELPERS='spamhaus_output_ready() {'+HELPERS


class BootstrapTests(unittest.TestCase):
    real_nft=False

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.bin=self.root/'bin';self.bin.mkdir()
        self.sbin=self.root/'sbin';self.sbin.mkdir()
        self.units=self.root/'units';self.units.mkdir()
        self.config=self.root/'config';self.calls=self.root/'calls'
        self.env=dict(os.environ,PATH=str(self.bin)+':'+os.environ['PATH'],FIXTURE=str(self.root))
        self.module=OBSERVER;self.source=HELPERS
        for old,new in [('/usr/local/sbin',str(self.sbin)),('/etc/systemd/system',str(self.units)),
                        ('/etc/xtls-spamhaus-output',str(self.config)),
                        ('/run/xtls-spamhaus-output.lock',str(self.root/'observer.lock'))]:
            self.module=self.module.replace(old,new);self.source=self.source.replace(old,new)
        self.script=self.root/'observer.sh';self.script.write_text(self.module)
        self.source='xtls_spamhaus_out_write_module() { cat "'+str(self.script)+'"; }\n'+self.source
        self.tool('curl', '''if os.environ.get('FAIL_FEED'): sys.exit(22)
url=next(x for x in sys.argv if x.startswith('https:'))
v=4 if 'v4' in url else 6
rows=[{'cidr':f'11.{i}.0.0/16' if v==4 else f'2606:{i:x}::/32'} for i in range(100 if v==4 else 10)]
Path(sys.argv[sys.argv.index('-o')+1]).write_text(''.join(json.dumps(x)+'\\n' for x in rows))''')
        self.tool('systemctl', "if 'show' in sys.argv: print('loaded')")
        if not self.real_nft:
            self.tool('nft', '''args=sys.argv[1:]
if 'list' in args and 'table' in args and not (root/'table').exists(): sys.exit(1)
if args[:2]==['add','table']: (root/'table').touch()
if '-f' in args and '-c' not in args:
    data=Path(args[args.index('-f')+1]).read_text()
    if 'add element' in data: (root/'populated').touch()
if '-j' in args:
    rows=[]
    if 'table' in args:
        rows=[{'chain':{'name':'output','hook':'output','type':'filter'}}]
        for v,kind in [(4,'ipv4_addr'),(6,'ipv6_addr')]:
            rows.append({'set':{'name':f'v{v}','type':kind,'elem':['11.0.0.0/16'] if (root/'populated').exists() else []}})
    print(json.dumps({'nftables':rows}))''')

    def tool(self,name,body):
        path=self.bin/name
        path.write_text('#!'+sys.executable+'\nimport os,sys,json\nfrom pathlib import Path\nroot=Path(os.environ["FIXTURE"])\n'
                        'with (root/"calls").open("a") as f: f.write(json.dumps([Path(sys.argv[0]).name]+sys.argv[1:])+"\\n")\n'+body+'\n')
        path.chmod(0o755)

    def run_install(self, **env):
        return subprocess.run(['bash','-c',self.source+'\nspamhaus_udp_prepare_source'],
                              text=True,capture_output=True,env=self.env|env,timeout=15)

    def logged(self):
        return [json.loads(x) for x in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def test_clean_install_populates_both_sets_and_enables_only_observer(self):
        r=self.run_install();self.assertEqual(r.returncode,0,r.stderr+r.stdout)
        self.assertEqual((self.sbin/'xtls-spamhaus-output').read_bytes(),self.script.read_bytes())
        self.assertEqual(len((self.config/'cidr4').read_text().splitlines()),100)
        self.assertEqual(len((self.config/'cidr6').read_text().splitlines()),10)
        self.assertEqual(len(list(self.units.iterdir())),3)
        controls=[x for x in self.logged() if x[:2]==['systemctl','enable']]
        self.assertEqual(controls,[['systemctl','enable','xtls-spamhaus-output-restore.service'],
                                  ['systemctl','enable','--now','xtls-spamhaus-output-update.timer']])
        self.assertNotIn('enable-block',json.dumps(self.logged()))
        self.calls.unlink()
        r=self.run_install();self.assertEqual(r.returncode,0,r.stderr)
        self.assertFalse(any(x[0] in ('curl','systemctl') and 'show' not in x for x in self.logged()))

    def test_feed_failure_does_not_enable_any_observer_service(self):
        r=self.run_install(FAIL_FEED='1');self.assertNotEqual(r.returncode,0)
        self.assertFalse(any(x[:2]==['systemctl','enable'] for x in self.logged()))
        self.assertIn('UDP-расширение не запускается',r.stdout)

    def test_unknown_module_is_preserved_before_download_or_service_control(self):
        target=self.sbin/'xtls-spamhaus-output';target.write_text('local custom script')
        r=self.run_install();self.assertNotEqual(r.returncode,0)
        self.assertEqual(target.read_text(),'local custom script')
        self.assertFalse(any(x[0] in ('curl','systemctl') for x in self.logged()))

    def test_custom_unit_and_dropin_are_not_overwritten(self):
        for kind in ('unit','dropin'):
            path=self.units/'xtls-spamhaus-output-restore.service'
            if kind=='dropin':
                path=Path(str(path)+'.d');path.mkdir();path=path/'custom.conf'
            path.write_text('local override')
            r=self.run_install();self.assertNotEqual(r.returncode,0)
            self.assertEqual(path.read_text(),'local override')
            self.assertFalse(any(x[0] in ('curl','systemctl') for x in self.logged()))
            path.unlink()

    def test_symlink_module_or_config_is_refused(self):
        outside=self.root/'outside';outside.write_text('preserve')
        for path in (self.sbin/'xtls-spamhaus-output',self.config):
            path.symlink_to(outside)
            r=self.run_install();self.assertNotEqual(r.returncode,0)
            self.assertEqual(outside.read_text(),'preserve')
            path.unlink()

    def test_foreign_table_with_no_known_module_is_not_adopted(self):
        (self.root/'table').touch()
        r=self.run_install();self.assertNotEqual(r.returncode,0)
        self.assertFalse(any(x[0] in ('curl','systemctl') for x in self.logged()))
