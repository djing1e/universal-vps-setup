"""Debian container regression: deleted conffiles and actual distro bouncer purge."""
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
s=(ROOT/'vps-setup.sh').read_text()
helpers=s[s.index('crowdsec_restore_missing_config() {'):s.index('\ncrowdsec_install() {')]

def run_helper(call):
    subprocess.run(['bash','-c',helpers+'\n'+call],check=True)

main=Path('/etc/crowdsec/config.yaml')
bouncer=Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml')
assert main.is_file() and bouncer.is_file()
# Reproduce the old transaction failure without deleting anything.
r=subprocess.run(['apt-get','-s','purge','crowdsec','vps-test-nonexistent-bouncer'],capture_output=True)
assert r.returncode!=0
assert subprocess.check_output(['dpkg-query','-W','-f=${Status}','crowdsec'],text=True)=='install ok installed'
acquis=Path('/etc/crowdsec/acquis.yaml');original=acquis.read_bytes()+b'\n# retained local acquisition\n'
acquis.write_bytes(original)
main.unlink()
run_helper('crowdsec_restore_missing_config crowdsec /etc/crowdsec/config.yaml')
assert main.is_file() and acquis.read_bytes()==original
bouncer.unlink()
run_helper('crowdsec_restore_missing_config crowdsec-firewall-bouncer /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml')
assert bouncer.is_file() and acquis.read_bytes()==original
print('PASS real dpkg missing CrowdSec/Bouncer conffiles restored; local acquisition preserved')
run_helper('crowdsec_purge_packages')
for name in ('crowdsec','crowdsec-firewall-bouncer'):
    r=subprocess.run(['dpkg-query','-W','-f=${Status}',name],capture_output=True,text=True)
    assert r.returncode or r.stdout.endswith(' not-installed'),(name,r.stdout)
print('PASS real purge includes Debian firewall bouncer and excludes unknown package variants')
