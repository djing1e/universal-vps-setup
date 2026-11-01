"""CI VM only: verify distro Hub detection with metrics unavailable and files unchanged."""
import hashlib
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'vps-setup.sh').read_text()
helpers='crowdsec_hub_item_state() ('+source.split('crowdsec_hub_item_state() (',1)[1].split('crowdsec_install() {',1)[0]


def fingerprint():
    rows={}
    for path in sorted(Path('/etc/crowdsec').rglob('*')):
        if path.is_file():
            rows[str(path)]=(os.readlink(path) if path.is_symlink() else None,
                             hashlib.sha256(path.read_bytes()).hexdigest())
    return rows


before=fingerprint()
assert before, 'CrowdSec package config missing'
subprocess.run(['bash','-c',helpers+'''
crowdsec_ensure_collection crowdsecurity/linux required || exit 1
crowdsec_ensure_collection crowdsecurity/sshd required || exit 1
crowdsec_hub_item_state parsers crowdsecurity/sshd-logs || exit 1
'''],check=True)
assert before==fingerprint(), 'Hub detection changed packaged files'
print('PASS Ubuntu packaged collections and SSH parser detected with stopped agent; all files unchanged')
