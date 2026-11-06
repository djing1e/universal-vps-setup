"""Dependency errors stop before feed/firewall changes, even inside the batch runner."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'vps-setup.sh').read_text()


def function(start, end):
    return SOURCE[SOURCE.index(start):SOURCE.index(end, SOURCE.index(start))]


class DependencyFailureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.calls = self.root / 'calls'
        self.env = dict(os.environ, CALLS=str(self.calls))

    def run_function(self, entry, source, missing='ipset', apt_code=100):
        # Override discovery only for the missing dependency. No real APT commands
        # or module runtime functions may run in these tests.
        prelude = r'''
log_section() { :; }
rn_error() { echo "$*"; }
asb_detect_crowdsec() { echo none; }
asb_print_env() { :; }
tib_detect_crowdsec() { echo none; }
tib_print_env() { :; }
command() { if [[ "$1" == -v && "$2" == "$MISSING" ]]; then return 1; fi; builtin command "$@"; }
apt-get() { printf '%s\n' "$*" >> "$CALLS"; return "$APT_CODE"; }
ensure_loopback_accept() { echo UNEXPECTED-FIREWALL; return 91; }
vps_fetch_github() { echo UNEXPECTED-FEED; return 91; }
tib_build_lists() { echo UNEXPECTED-FEED; return 91; }
ipset() { echo UNEXPECTED-IPSET; return 91; }
systemctl() { echo UNEXPECTED-SERVICE; return 91; }
'''
        # Invoke in a conditional, as onebtn_step does: set -e must not be the
        # mechanism that stops dependent commands.
        body = prelude + source + '\nrc=0; ' + entry + ' || rc=$?; exit "$rc"'
        return subprocess.run(['bash', '-c', body], text=True, capture_output=True, timeout=5,
                              env=self.env | {'MISSING':missing, 'APT_CODE':str(apt_code)})

    def test_as_and_threat_do_not_fetch_or_mutate_after_failed_dependency(self):
        sources = [('asb_install_iptables', function('asb_install_iptables() {','asb_create_update_script_iptables() {')),
                   ('tib_install', function('tib_install() {','tib_create_update_script() {'))]
        for entry, source in sources:
            r = self.run_function(entry, source)
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertNotIn('UNEXPECTED-', r.stdout)
            args = self.calls.read_text().splitlines()[-1]
            self.assertIn('-o DPkg::Lock::Timeout=600 install', args)
            self.assertIn('--no-remove ipset', args)
            self.assertNotIn('Правила добавлены', r.stdout)

    def test_apt_success_without_dependency_also_stops(self):
        for entry, source in [('asb_install_iptables', function('asb_install_iptables() {','asb_create_update_script_iptables() {')),
                              ('tib_install', function('tib_install() {','tib_create_update_script() {'))]:
            r = self.run_function(entry, source, apt_code=0)
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn('UNEXPECTED-', r.stdout)
            self.assertIn('отсутствует после установки', r.stdout)

    def test_fail2ban_install_error_stops_before_prompt_and_configuration(self):
        r = self.run_function('do_fail2ban', function('do_fail2ban() {','do_docker_mirrors() {'))
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn('SSH порт', r.stdout)
        self.assertNotIn('UNEXPECTED-', r.stdout)

    def test_crowdsec_and_base_package_transactions_have_bounded_wait(self):
        for start, end in [('crowdsec_install_impl() {','crowdsec_uninstall() {'),
                           ('do_update_packages() {','vps_ssh_public_key() {'),
                           ('do_ufw_setup() {','do_sysctl_setup() {')]:
            for line in function(start,end).splitlines():
                if re.search(r'\b(?:apt-get|apt)\b.*\b(?:install|upgrade)\b',line):
                    self.assertIn('DPkg::Lock::Timeout=600', line)


class ThreatSetFailureTests(unittest.TestCase):
    def test_failed_create_add_or_swap_preserves_previous_set_and_returns_failure(self):
        loader = function('tib_load_set() {','tib_install() {')
        for fail in ('create-target','create-stage','add','swap'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); (root/'bin').mkdir(); (root/'networks').write_text('8.8.8.0/24\n1.1.1.0/24\n')
                (root/'state').write_text(json.dumps({'target':['9.9.9.0/24'], 'stage':[]}))
                tool = root/'bin/ipset'
                tool.write_text('#!'+sys.executable+'''\nimport json,os,sys
from pathlib import Path
p=Path(os.environ['FIXTURE']); state=json.loads((p/'state').read_text()); a=sys.argv[1:]
which='stage' if a[1].endswith('-tmp') else 'target'
failure=os.environ['FAIL']
if a[0]=='create' and failure=='create-'+which: sys.exit(1)
if a[0] in ('add','swap') and failure==a[0]: sys.exit(1)
if a[0]=='create' and which=='stage': state['stage']=[]
if a[0]=='add': state['stage'].append(a[2])
if a[0]=='swap': state['target'],state['stage']=state['stage'],state['target']
(p/'state').write_text(json.dumps(state))
'''); tool.chmod(0o755)
                result = subprocess.run(['bash','-c','rn_error() { echo "$*"; }\n'+loader+'\nrc=0; tib_load_set target inet "$FIXTURE/networks" || rc=$?; exit "$rc"'],
                                        text=True,capture_output=True,timeout=5,
                                        env=dict(os.environ, FIXTURE=str(root), FAIL=fail, PATH=str(root/'bin')+':'+os.environ['PATH']))
                self.assertNotEqual(result.returncode,0,fail+result.stderr)
                self.assertEqual(json.loads((root/'state').read_text())['target'], ['9.9.9.0/24'])


class RealAptLockTests(unittest.TestCase):
    @unittest.skipUnless(os.geteuid()==0 and shutil.which('apt-get'), 'root and APT required')
    def test_real_apt_waits_for_isolated_frontend_lock_then_times_out(self):
        # Redirect dpkg status/locks and archives into a disposable tree. No host
        # lock or package DB is touched; --download-only --no-download cannot
        # install or fetch anything even if APT ignores the isolated lock.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'status').touch(); (root/'archives').mkdir()
            holder = subprocess.Popen([sys.executable,'-c',
                'import fcntl,sys; f=open(sys.argv[1],"w"); fcntl.lockf(f,fcntl.LOCK_EX); print("locked",flush=True); sys.stdin.read()', str(root/'lock-frontend')],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
            try:
                self.assertEqual(holder.stdout.readline().strip(),'locked')
                started=time.monotonic()
                result=subprocess.run(['apt-get','-o','DPkg::Lock::Timeout=1',
                    '-o','Dir::State::status='+str(root/'status'), '-o','Dir::Cache::archives='+str(root/'archives'),
                    '-o','Dir::Log='+str(root/'logs'), '--download-only','--no-download','install','nonexistent-vps-setup-test-package'],
                    text=True,capture_output=True,timeout=8,env=dict(os.environ,LC_ALL='C'))
                self.assertEqual(result.returncode,100,result.stdout+result.stderr)
                self.assertIn('lock-frontend',result.stderr)
                self.assertIn('Unable to acquire the dpkg frontend lock',result.stderr)
                self.assertGreaterEqual(time.monotonic()-started,.8)
            finally:
                holder.communicate('',timeout=3)
