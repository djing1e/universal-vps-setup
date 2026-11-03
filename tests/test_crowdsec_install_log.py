"""The install wrapper must retain stderr and the actual step return code."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/'vps-setup.sh').read_text()
WRAPPER='crowdsec_install() {'+SOURCE.split('crowdsec_install() {',1)[1].split('crowdsec_install_impl() {',1)[0]


class CrowdSecInstallLogTests(unittest.TestCase):
    def test_success_and_failure_retain_output_status_and_private_log(self):
        for code in (0,1,73):
            with tempfile.TemporaryDirectory() as directory:
                source=WRAPPER.replace('/var/log/vps-setup-crowdsec.',directory+'/detail.')
                script='log() { :; }\ncrowdsec_install_impl() { echo stage; echo apt-failure >&2; return '+str(code)+'; }\n'
                r=subprocess.run(['bash','-c',script+source+'\ncrowdsec_install'],text=True,capture_output=True)
                self.assertEqual(r.returncode,code,r.stderr)
                logs=list(Path(directory).glob('detail.*.log'));self.assertEqual(len(logs),1)
                self.assertEqual(logs[0].stat().st_mode & 0o777,0o600)
                self.assertIn('stage\napt-failure',logs[0].read_text())
                self.assertIn(str(logs[0]),r.stdout)
