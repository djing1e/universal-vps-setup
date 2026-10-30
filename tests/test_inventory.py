"""Inventory unknown-state and read-only command contract."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('inventory', ROOT/'lib/vps_inventory.py')
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_content_match_never_grants_update(self):
        module = self.root/'module'
        module.write_text('known')
        digest = hashlib.sha256(module.read_bytes()).hexdigest()
        manifest = {'files': [{'path':'/module', 'sha256':[digest]}]}
        def unavailable(argv):
            return {'status':'unavailable'}
        report = inventory.collect(self.root, unavailable, manifest)
        self.assertEqual(report['modules']['/module']['status'], 'known_content')
        self.assertEqual(report['modules']['/module']['ownership'], 'not_established')
        self.assertEqual(report['update_gate'], 'manual_review_required')
        self.assertFalse(report['changes_applied'])
        self.assertEqual(report['services']['docker.service']['status'], 'unknown')

    def test_custom_unreadable_and_missing_remain_distinct(self):
        p = self.root/'file'; p.write_text('custom')
        self.assertEqual(inventory.file_fingerprint(p, [])['status'], 'custom_or_unknown')
        self.assertEqual(inventory.file_fingerprint(self.root/'missing', [])['status'], 'absent')
        self.assertEqual(inventory.file_fingerprint(self.root, [])['status'], 'unknown')
        self.assertEqual(inventory.file_fingerprint(p, [], 2)['reason'], 'file_too_large')

    def test_symlinks_including_broken_are_not_owned(self):
        p = self.root/'link'; p.symlink_to(self.root/'missing')
        self.assertEqual(inventory.file_fingerprint(p, [])['status'], 'unknown')

    def test_failed_or_incomplete_unit_probe_is_unknown(self):
        for result in [{'status':'error','output':'LoadState=not-found'},
                       {'status':'limited','output':'LoadState=loaded'},
                       {'status':'ok','output':''},
                       {'status':'ok','output':'LoadState=masked'}]:
            self.assertEqual(inventory.unit_state('test', lambda argv: result)['status'], 'unknown')
        self.assertEqual(inventory.unit_state('test', lambda argv: {
            'status':'ok','output':'LoadState=not-found\n'})['status'], 'absent')

    def test_inactive_docker_is_not_queried(self):
        calls=[]
        def runner(argv):
            calls.append(argv)
            return {'status':'ok','output':'LoadState=loaded\nActiveState=inactive\n'}
        report=inventory.collect(self.root, runner, {'files':[]})
        self.assertEqual(report['probes']['containers']['status'], 'unknown')
        self.assertFalse(any('ps' in argv for argv in calls))

    def test_only_read_commands_and_local_docker_endpoint(self):
        calls=[]
        def runner(argv):
            calls.append(argv)
            return {'status':'ok','output':'LoadState=loaded\nActiveState=active\n'}
        inventory.collect(self.root, runner, {'files':[]})
        for argv in calls:
            if argv[0]=='systemctl':
                self.assertEqual(argv[1], 'show')
                self.assertNotIn('ExecStart', ' '.join(argv))
            else:
                self.assertIn(argv, inventory.PROBES.values())
        docker=inventory.PROBES['containers']
        self.assertIn('unix:///var/run/docker.sock', docker)
        self.assertNotIn('{{json .}}', docker)
        self.assertNotIn('inspect', docker)

    def test_probe_caps_output_and_timeout(self):
        result=inventory.probe([sys.executable,'-c','print("x"*1000000)'], limit=1024)
        self.assertEqual(result['status'], 'limited')
        self.assertEqual(len(result['output']), 1024)
        result=inventory.probe([sys.executable,'-c','import time; time.sleep(30)'], timeout=.1)
        self.assertEqual(result['status'], 'timeout')
        result=inventory.probe(['/nonexistent/inventory-test-tool'])
        self.assertEqual(result['status'], 'unavailable')

    def test_update_is_not_an_available_action(self):
        result=subprocess.run([sys.executable,str(ROOT/'lib/vps_inventory.py'),'update'],
                              capture_output=True,text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')

    def test_manifest_matches_release_sources(self):
        manifest=json.loads((ROOT/'lib/inventory_manifest.json').read_text())
        mapping={'xtls-c2-feed':'xtls-c2-feed.sh',
                 'xtls-spamhaus-output':'xtls-spamhaus-output.sh',
                 'xtls-auto-abuse-guard':'xtls-auto-abuse-guard.py'}
        for item in manifest['files']:
            source=ROOT/'modules'/mapping[Path(item['path']).name]
            self.assertIn(hashlib.sha256(source.read_bytes()).hexdigest(),item['sha256'])


if __name__=='__main__':
    unittest.main()
