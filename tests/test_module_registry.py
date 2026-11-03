"""Registration writes metadata only; audit never infers authority from hashes."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'lib'))
import module_registry as registry
import vps_inventory as inventory


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        (self.root/'run').mkdir();(self.root/'var/lib').mkdir(parents=True)
        self.catalog={'schema_version':1,'components':{registry.COMPONENT:{
            'version':'1.0.0-rc.1','source_revision':'a'*40,'resources':{}}}}
        self.release=self.catalog['components'][registry.COMPONENT]
        self.original={}
        for path in registry.RESOURCES:
            file=self.root/path.lstrip('/');file.parent.mkdir(parents=True,exist_ok=True)
            raw=('known '+path+'\n').encode();file.write_bytes(raw)
            mode=0o755 if path.startswith('/usr/local/') else 0o644
            file.chmod(mode);self.original[path]=(raw,mode)
            self.release['resources'][path]={'sha256':hashlib.sha256(raw).hexdigest(),'allowed_modes':[mode]}
        self.calls=[];self.overrides={}
        self.receipt=self.root/registry.RECEIPT.lstrip('/')

    def runner(self,argv):
        self.calls.append(argv)
        self.assertEqual(argv[:2],['systemctl','show'])
        name=argv[3]
        values={'LoadState':'loaded','ActiveState':'active' if name.endswith('.timer') else 'inactive',
                'SubState':'waiting' if name.endswith('.timer') else 'dead',
                'UnitFileState':'enabled' if name.endswith('.timer') else 'static',
                'FragmentPath':'/etc/systemd/system/'+name,'DropInPaths':'','NeedDaemonReload':'no'}
        values.update(self.overrides)
        return {'status':'ok','output':'\n'.join(key+'='+value for key,value in values.items())}

    def inspect(self):return registry.inspect(self.root,self.catalog)
    def adopt(self):return registry.adopt(self.root,self.catalog,self.runner)

    def test_inspect_recognizes_without_claiming_management_or_writing(self):
        paths=set(self.root.rglob('*'))
        result=self.inspect()
        self.assertEqual(result['status'],'recognized_unregistered')
        self.assertEqual(result['detected_version'],'1.0.0-rc.1')
        self.assertEqual(result['ownership'],'not_established')
        self.assertFalse(result['automatic_update']);self.assertFalse(result['changes_applied'])
        self.assertEqual(paths,set(self.root.rglob('*')))
        self.assertEqual(self.calls,[])

    def test_adoption_is_metadata_only_private_and_idempotent(self):
        result=self.adopt()
        self.assertEqual(result['status'],'registered_matches')
        self.assertTrue(result['changes_applied']);self.assertFalse(result['automatic_update'])
        before=self.receipt.read_bytes()
        self.assertEqual(self.receipt.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.receipt.parent.stat().st_mode & 0o777,0o700)
        self.assertFalse(self.adopt()['changes_applied'])
        self.assertEqual(self.receipt.read_bytes(),before)
        for name,(raw,mode) in self.original.items():
            path=self.root/name.lstrip('/')
            self.assertEqual(path.read_bytes(),raw);self.assertEqual(path.stat().st_mode & 0o777,mode)

    def test_custom_or_absent_resource_refuses_adoption(self):
        path=self.root/registry.RESOURCES[0].lstrip('/')
        path.write_text('custom')
        self.assertEqual(self.inspect()['status'],'unknown')
        with self.assertRaises(ValueError):self.adopt()
        path.unlink()
        with self.assertRaises(ValueError):self.adopt()
        self.assertFalse(self.receipt.exists());self.assertEqual(self.calls,[])

    def test_modified_registered_resource_is_drift_without_receipt_rewrite(self):
        self.adopt();before=self.receipt.read_bytes()
        (self.root/registry.RESOURCES[0].lstrip('/')).write_text('changed')
        self.assertEqual(self.inspect()['status'],'registered_drift')
        with self.assertRaises(ValueError):self.adopt()
        self.assertEqual(self.receipt.read_bytes(),before)

    def test_permission_drift_is_not_treated_as_current(self):
        self.adopt()
        path=self.root/registry.RESOURCES[0].lstrip('/')
        path.chmod(0o700)
        self.assertEqual(self.inspect()['status'],'registered_drift')
        with self.assertRaises(ValueError):self.adopt()

    def test_unknown_dropins_masked_reload_or_failed_state_refused(self):
        for key,value in [('DropInPaths','/etc/local.conf'),('NeedDaemonReload','yes'),
                          ('LoadState','masked'),('ActiveState','failed'),('FragmentPath','/other/unit'),('UnitFileState','static')]:
            self.overrides={key:value}
            with self.assertRaises(ValueError):self.adopt()
            self.assertFalse(self.receipt.exists())

    def test_disabled_timer_is_registered_without_enable_or_start(self):
        self.overrides={'ActiveState':'inactive','UnitFileState':'disabled'}
        self.assertEqual(self.adopt()['status'],'registered_matches')
        self.assertTrue(all(call[:2]==['systemctl','show'] for call in self.calls))

    def test_probe_failure_does_not_create_registration(self):
        with self.assertRaises(ValueError):registry.adopt(self.root,self.catalog,lambda argv:{'status':'error'})
        self.assertFalse(self.receipt.exists())

    def test_corrupt_receipt_is_preserved_and_blocks_adoption(self):
        self.adopt();self.receipt.write_text('{broken')
        self.assertEqual(self.inspect()['status'],'unknown')
        with self.assertRaises(ValueError):self.adopt()
        self.assertEqual(self.receipt.read_text(),'{broken')

    def test_receipt_does_not_supply_arbitrary_paths_or_versions(self):
        self.adopt();original=json.loads(self.receipt.read_text())
        for key,value in [('version','unknown'),('source_revision','b'*40),('resources',{'/etc/shadow':{}})]:
            receipt=copy.deepcopy(original);receipt[key]=value
            self.receipt.write_text(json.dumps(receipt))
            self.assertEqual(self.inspect()['status'],'unknown')
            with self.assertRaises(ValueError):self.adopt()

    def test_duplicate_json_and_unsafe_registry_permissions_refused(self):
        self.adopt();self.receipt.write_text('{"schema_version":1,"schema_version":1}')
        self.assertEqual(self.inspect()['status'],'unknown')
        self.receipt.parent.chmod(0o777)
        self.assertEqual(self.inspect()['status'],'unknown')

    def test_symlink_and_hardlink_resources_are_unknown(self):
        path=self.root/registry.RESOURCES[0].lstrip('/')
        path.rename(self.root/'saved');path.symlink_to(self.root/'saved')
        with self.assertRaises(ValueError):self.adopt()
        path.unlink();os.link(self.root/'saved',path)
        with self.assertRaises(ValueError):self.adopt()
        self.assertFalse(self.receipt.exists())

    def test_receipt_symlink_and_unsafe_permissions_are_unknown(self):
        self.adopt();self.receipt.chmod(0o644)
        self.assertEqual(self.inspect()['status'],'unknown')
        self.receipt.unlink();self.receipt.symlink_to(self.root/'missing')
        self.assertEqual(self.inspect()['status'],'unknown')
        with self.assertRaises(ValueError):self.adopt()

    def test_lock_prevents_registration(self):
        with (self.root/'run/xtls-auto-abuse-guard-install.lock').open('w') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.adopt()
        self.assertFalse(self.receipt.exists())

    def test_nonroot_adopt_is_refused(self):
        with patch.object(registry.os,'geteuid',return_value=1000):
            with self.assertRaises(ValueError):self.adopt()
        self.assertFalse(self.receipt.exists())

    def test_cli_requires_explicit_adoption_phrase(self):
        result=subprocess.run([sys.executable,str(ROOT/'lib/module_registry.py'),'adopt'],text=True,capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(registry.CONFIRM,result.stderr)

    def test_inventory_reads_registration_without_writes_or_update_permission(self):
        self.adopt();before=self.receipt.read_bytes()
        with patch.object(registry,'load_catalog',return_value=self.catalog):
            report=inventory.collect(self.root,lambda argv:{'status':'unavailable'},{'files':[]})
        self.assertEqual(report['component_registry'][registry.COMPONENT]['status'],'registered_matches')
        self.assertFalse(report['changes_applied'])
        self.assertEqual(report['update_gate'],'manual_review_required')
        self.assertEqual(self.receipt.read_bytes(),before)

    def test_lifecycle_restores_previous_receipt_bytes(self):
        self.adopt();before=self.receipt.read_bytes()
        managed=registry.Registration(self.root,self.catalog)
        proposed=managed.prepare('managed_update')
        managed.replace(before,proposed)
        self.assertEqual(self.inspect()['status'],'registered_matches')
        managed.restore(before,proposed)
        self.assertEqual(self.receipt.read_bytes(),before)

    def test_lifecycle_never_overwrites_external_receipt_change(self):
        self.adopt();before=self.receipt.read_bytes()
        managed=registry.Registration(self.root,self.catalog)
        proposed=managed.prepare('managed_update')
        self.receipt.write_text('external change')
        with self.assertRaises(ValueError):managed.replace(before,proposed)
        with self.assertRaises(ValueError):managed.restore(before,proposed)
        self.assertEqual(self.receipt.read_text(),'external change')

    def test_catalog_matches_current_release_sources(self):
        policy=json.loads((ROOT/'lib/guard_engine_policy.json').read_text())
        release=registry.validate_catalog(registry.load_catalog())
        engine=release['resources'][registry.RESOURCES[0]]
        self.assertEqual(engine['sha256'],policy['target_sha256'])
        for name,digest in policy['units'].items():
            self.assertEqual(release['resources']['/etc/systemd/system/'+name]['sha256'],digest)


if __name__=='__main__':unittest.main()
