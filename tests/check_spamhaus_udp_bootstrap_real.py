"""Exercise shared-source bootstrap with real nft, only in a disposable named netns."""
import importlib.util
import json
from pathlib import Path
import subprocess

from test_spamhaus_udp_bootstrap import BootstrapTests, ROOT

if not subprocess.check_output(['ip','netns','identify'],text=True).strip():
    raise SystemExit('Run only in a disposable named network namespace')
subprocess.run(['nft','delete','table','inet','xtls_spamhaus_out'],check=False,capture_output=True)
fixture=BootstrapTests('test_clean_install_populates_both_sets_and_enables_only_observer')
fixture.real_nft=True
fixture.setUp()
try:
    # Real observer shell and real set updates, fake external feed and service commands.
    fixture.test_clean_install_populates_both_sets_and_enables_only_observer()
    table=json.loads(subprocess.check_output(['nft','-j','list','table','inet','xtls_spamhaus_out'],text=True))
    rules=[r['rule'] for r in table['nftables'] if 'rule' in r]
    assert len(rules)==2, rules
    assert all(not any('drop' in e for e in r['expr']) for r in rules), rules
    spec=importlib.util.spec_from_file_location('bootstrap_udp',ROOT/'modules/xtls-spamhaus-udp.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    guard=module.Guard(root=fixture.root/'udp',lock=fixture.root/'udp.lock')
    guard.restore()  # Fresh Observe restore succeeds with the newly prepared table.
    assert guard.mode()=='observe'
    print('PASS fresh Spamhaus bootstrap + populated IPv4/IPv6 sets + UDP Observe restore; no DROP')
finally:
    fixture.doCleanups()
    subprocess.run(['nft','delete','table','inet','xtls_spamhaus_out'],check=False,capture_output=True)
