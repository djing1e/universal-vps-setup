"""Deleted conffiles are repaired; failed purge never permits directory deletion."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
SOURCE=(Path(__file__).resolve().parents[1]/'vps-setup.sh').read_text()
HELPERS=SOURCE[SOURCE.index('crowdsec_restore_missing_config() {'):SOURCE.index('\ncrowdsec_install() {')]

class CrowdsecRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.config=self.root/'etc/crowdsec';self.config.mkdir(parents=True)
        self.calls=self.root/'calls'
        self.source=HELPERS.replace('/etc/crowdsec',str(self.config)).replace('/root/crowdsec-config-recovery.',str(self.root/'recovery.'))
        self.env=dict(os.environ,CALLS=str(self.calls),CONFIG=str(self.config))
        self.base='''
dpkg-query() {
  if [[ "$*" == *'${Version}'* ]]; then echo 1.4.6-test; return; fi
  case "${@: -1}" in
    crowdsec|crowdsec-firewall-bouncer)
      if [[ -f "$CALLS.purged" ]]; then echo 'unknown ok not-installed';
      else echo 'install ok installed'; fi ;;
    *) return 1 ;;
  esac
}
apt-get() {
  echo "$*" >> "$CALLS"
  [[ "${FAIL_APT:-0}" != 1 ]] || return 100
  if [[ "$*" == *purge* ]]; then touch "$CALLS.purged";
  elif [[ "${NO_RESTORE:-0}" != 1 ]]; then
    mkdir -p "$CONFIG/bouncers"
    echo restored > "$CONFIG/config.yaml"
    echo restored > "$CONFIG/bouncers/crowdsec-firewall-bouncer.yaml"
  fi
}
'''
    def run_shell(self,entry,extra='',env=None):
        return subprocess.run(['bash','-c',self.base+self.source+'\n'+extra+'\n'+entry],capture_output=True,text=True,timeout=10,env=self.env|(env or {}))
    def test_existing_config_does_not_reinstall_or_write(self):
        cfg=self.config/'config.yaml';cfg.write_text('custom')
        r=self.run_shell('crowdsec_restore_missing_config crowdsec "$CONFIG/config.yaml"')
        self.assertEqual(r.returncode,0,r.stderr);self.assertFalse(self.calls.exists());self.assertEqual(cfg.read_text(),'custom')
    def test_deleted_config_reinstall_pins_version_and_keeps_other_files(self):
        sentinel=self.config/'acquis.yaml';sentinel.write_text('custom acquisition')
        r=self.run_shell('crowdsec_restore_missing_config crowdsec "$CONFIG/config.yaml"')
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        args=self.calls.read_text();self.assertIn('--force-confmiss',args);self.assertIn('--force-confold',args)
        self.assertIn('--reinstall',args);self.assertIn('--no-remove crowdsec=1.4.6-test',args)
        self.assertEqual(sentinel.read_text(),'custom acquisition')
        backups=list(self.root.glob('recovery.*'));self.assertEqual(len(backups),1)
        self.assertEqual(backups[0].stat().st_mode&0o777,0o700)
        self.assertEqual((backups[0]/'crowdsec/acquis.yaml').read_text(),'custom acquisition')
    def test_missing_bouncer_repaired_before_secret_check(self):
        r=self.run_shell('crowdsec_restore_missing_config crowdsec-firewall-bouncer "$CONFIG/bouncers/crowdsec-firewall-bouncer.yaml"')
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertIn('crowdsec-firewall-bouncer=1.4.6-test',self.calls.read_text())
    def test_symlink_refused_without_apt(self):
        (self.config/'config.yaml').symlink_to(self.root/'absent')
        r=self.run_shell('crowdsec_restore_missing_config crowdsec "$CONFIG/config.yaml"')
        self.assertNotEqual(r.returncode,0);self.assertFalse(self.calls.exists())
    def test_failed_reinstall_and_absent_file_never_report_success(self):
        for env in ({'FAIL_APT':'1'},{'NO_RESTORE':'1'}):
            r=self.run_shell('crowdsec_restore_missing_config crowdsec "$CONFIG/config.yaml"',env=env)
            self.assertNotEqual(r.returncode,0)
    def test_purge_includes_distribution_bouncer_and_omits_unknown_variants(self):
        r=self.run_shell('crowdsec_purge_packages')
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        args=self.calls.read_text();self.assertIn('purge -y crowdsec crowdsec-firewall-bouncer\n',args)
        self.assertNotIn('bouncer-iptables',args);self.assertNotIn('bouncer-nftables',args)
    def test_purge_failure_blocks_following_directory_delete(self):
        r=self.run_shell('if crowdsec_purge_packages; then echo BAD_DELETE; fi',env={'FAIL_APT':'1'})
        self.assertNotIn('BAD_DELETE',r.stdout)
        self.assertIn('сохраняются',r.stdout)
    def test_success_exit_with_remaining_installed_package_still_refuses_cleanup(self):
        r=self.run_shell('crowdsec_purge_packages',extra='apt-get() { return 0; }')
        self.assertNotEqual(r.returncode,0)
        self.assertIn('остался в dpkg',r.stdout)
    def test_cleanup_and_uninstall_call_shared_checked_purge(self):
        self.assertNotIn('apt-get purge -y crowdsec',SOURCE)
        self.assertIn('crowdsec_purge_packages || return 1\n    rm -rf /etc/crowdsec /var/lib/crowdsec',SOURCE)
        self.assertIn('crowdsec_restore_missing_config "$cs_bouncer_pkg" "$bouncer_config" || return 1',SOURCE)

if __name__=='__main__':unittest.main()
