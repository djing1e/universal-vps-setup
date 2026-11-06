"""DoH configuration is readable to its service user under restrictive umasks."""
import grp
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE=(Path(__file__).resolve().parents[1]/'vps-setup.sh').read_text()
PREPARE='_nextdns_doh_prepare() {'+SOURCE.split('_nextdns_doh_prepare() {',1)[1].split('\n_nextdns_verify() {',1)[0]
CAN_SWITCH=bool(shutil.which('runuser')) and subprocess.run(['runuser','-u','nobody','--','true'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0


class DoHPermissionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.root.chmod(0o755)
        for name in ('bin','units'): (self.root/name).mkdir(mode=0o755)
        self.config=self.root/'config'; self.calls=self.root/'calls'
        (self.root/'os-release').write_text('ID=debian\nVERSION_ID=13\n')
        self.checker=self.root/'checker'
        self.checker.write_text('#!'+sys.executable+'''\nimport os,sys,tomllib
from pathlib import Path
obj=tomllib.loads(Path(sys.argv[3]).read_text())
assert obj['max_clients']==1000
assert len(obj['static'])==2
print('CHECK_UID='+str(os.geteuid()))
''');self.checker.chmod(0o755)
        tool=self.root/'bin/dig';tool.write_text('#!/bin/sh\necho 1.1.1.1\n');tool.chmod(0o755)
        self.prepare=PREPARE
        for old,new in (('/etc/os-release',str(self.root/'os-release')),('/etc/nextdns-doh',str(self.config)),
                        ('/etc/systemd/system',str(self.root/'units')),('/usr/sbin/dnscrypt-proxy',str(self.checker))):
            self.prepare=self.prepare.replace(old,new)
        self.env=dict(os.environ,FIXTURE=str(self.root),CALLS=str(self.calls),PATH=str(self.root/'bin')+':'+os.environ['PATH'])
        self.prelude='''
apt-get() { :; }
_nextdns_doh_probe() { return 0; }
_nextdns_doh_stamp() { echo sdns://fixture; }
sleep() { :; }
systemctl() { echo "$*" >> "$CALLS"; return 0; }
'''

    def run_prepare(self, mask='077', real=False, fail=False):
        source=self.prepare
        prelude=self.prelude
        if real:
            source=source.replace('doh_user=_dnscrypt-proxy','doh_user=nobody')
        else:
            group=grp.getgrgid(os.getgid()).gr_name
            prelude+='id() { if [[ "$1" == -gn ]]; then echo '+group+'; else command id "$@"; fi; }\n'
            # The constrained executor cannot switch UIDs. Assert the group
            # access bits before emulating runuser; CI also exercises real UID.
            prelude+='''runuser() { python3 - "$@" <<'CHECK'
import os,stat,sys
from pathlib import Path
assert sys.argv[1:4]==['-u','_dnscrypt-proxy','--']
p=Path(sys.argv[-1]); info=p.stat()
assert stat.S_IMODE(info.st_mode)==0o640
assert stat.S_IMODE(p.parent.stat().st_mode)==0o750
assert info.st_uid==0
if os.environ.get('FAIL_CHECK'): sys.exit(1)
print('CHECKED_AS_SERVICE')
CHECK
}
'''
        return subprocess.run(['bash','-c','umask '+mask+'\n'+prelude+source+'\n_nextdns_doh_prepare e57d7c'],
                              text=True,capture_output=True,timeout=10,env=self.env|({'FAIL_CHECK':'1'} if fail else {}))

    def assert_permissions(self, group):
        conf=self.config/'dnscrypt-proxy.toml'
        self.assertEqual(conf.stat().st_mode&0o777,0o640)
        self.assertEqual(conf.stat().st_uid,0)
        self.assertEqual(conf.stat().st_gid,grp.getgrnam(group).gr_gid)
        self.assertEqual(self.config.stat().st_mode&0o777,0o750)
        unit=(self.root/'units/nextdns-doh.service')
        self.assertEqual(unit.stat().st_mode&0o777,0o644)
        self.assertIn('Group='+group,unit.read_text())
        self.assertFalse(list(self.config.glob('.dnscrypt-proxy.*')))

    def test_restrictive_mask_and_existing_root_only_file_are_repaired(self):
        for mask in ('077','022'):
            if not self.config.exists(): self.config.mkdir(mode=0o700)
            conf=self.config/'dnscrypt-proxy.toml';conf.write_text('old config');conf.chmod(0o600)
            result=self.run_prepare(mask)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('CHECKED_AS_SERVICE',result.stdout)
            self.assert_permissions(grp.getgrgid(os.getgid()).gr_name)

    def test_failed_service_user_check_preserves_old_config_and_no_service_changes(self):
        self.config.mkdir(); conf=self.config/'dnscrypt-proxy.toml';conf.write_text('old config')
        result=self.run_prepare(fail=True)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(conf.read_text(),'old config')
        self.assertFalse(self.calls.exists())
        self.assertFalse(list(self.config.glob('.dnscrypt-proxy.*')))

    def test_symlink_config_is_not_overwritten(self):
        self.config.mkdir(); other=self.root/'other';other.write_text('local config')
        (self.config/'dnscrypt-proxy.toml').symlink_to(other)
        result=self.run_prepare()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(other.read_text(),'local config')
        self.assertFalse(self.calls.exists())

    @unittest.skipUnless(CAN_SWITCH,'executor cannot switch service UID; covered on CI')
    def test_real_service_uid_reads_config_but_cannot_write_it(self):
        for mask in ('077','022'):
            result=self.run_prepare(mask,real=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('CHECK_UID='+str(pwd.getpwnam('nobody').pw_uid),result.stdout)
            self.assert_permissions(grp.getgrgid(pwd.getpwnam('nobody').pw_gid).gr_name)
            conf=self.config/'dnscrypt-proxy.toml'
            probe=subprocess.run(['runuser','-u','nobody','--','test','-w',str(conf)])
            self.assertNotEqual(probe.returncode,0)
