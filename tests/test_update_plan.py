"""Conservative advisory planning; no host operations permitted."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('update_plan', ROOT/'lib/vps_update_plan.py')
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)


class UpdatePlanTests(unittest.TestCase):
    def setUp(self):
        self.catalog = json.loads((ROOT/'lib/update_catalog.json').read_text())
        self.report = {'schema_version':1,'mode':'audit','changes_applied':False,
                       'update_gate':'manual_review_required',
                       'os':{'status':'observed','properties':{'ID':'debian','VERSION_ID':'13'}},
                       'modules':{},'services':{},'saved_modes':{},'probes':{'nft_tables':{'status':'ok'}}}
        for item in self.catalog['components'].values():
            if 'saved_mode' in item:
                mode = item['saved_mode']
                self.report['saved_modes'][mode['path']] = {'status':'observed','scope':'saved_only','value':mode['allowed'][0]}
            self.report['modules'][item['path']] = {'status':'known_content','sha256':item['target_sha256']}
            for unit in item['units']:
                self.report['services'][unit] = {'status':'observed','properties':{
                    'LoadState':'loaded','ActiveState':'active','SubState':'running','UnitFileState':'enabled',
                    'FragmentPath':'/etc/systemd/system/'+unit,'DropInPaths':''}}

    def plan(self, selection=None):
        return planner.build_plan(self.report, selection or list(self.catalog['components']), self.catalog)

    def test_current_modules_are_noop_without_apply(self):
        result = self.plan()
        self.assertEqual(result['summary'],{'noop':4,'review_required':0,'blocked':0})
        self.assertFalse(result['changes_applied'])
        self.assertFalse(result['apply_available'])
        self.assertTrue(all(not row['automatic_apply'] for row in result['steps']))

    def test_known_old_content_is_only_review_candidate(self):
        for item in self.catalog['components'].values():
            if not item['known_previous_sha256']: continue
            self.report['modules'][item['path']] = {'status':'custom_or_unknown','sha256':item['known_previous_sha256'][0]}
        result = self.plan()
        self.assertEqual(result['summary']['review_required'],4)
        for row in result['steps']:
            if row['status'] == 'noop': continue
            self.assertIn('ownership_not_established',row['reasons'])
            self.assertIn('backup_and_rollback_not_implemented',row['reasons'])
        self.assertFalse(result['apply_available'])

    def test_forged_known_content_does_not_bypass_catalog(self):
        item=self.catalog['components']['tcp-c2']
        self.report['modules'][item['path']]['sha256']='f'*64
        row=self.plan(['tcp-c2'])['steps'][0]
        self.assertEqual(row['status'],'blocked')
        self.assertIn('unrecognized_content',row['reasons'])

    def test_unknown_even_with_known_hash_is_blocked(self):
        item=self.catalog['components']['tcp-c2']
        self.report['modules'][item['path']]['status']='unknown'
        self.assertIn('module_unknown',self.plan(['tcp-c2'])['steps'][0]['reasons'])

    def test_absent_module_requires_separate_install(self):
        item=self.catalog['components']['tcp-c2']
        self.report['modules'][item['path']]={'status':'absent'}
        self.assertIn('module_absent_install_is_separate',self.plan(['tcp-c2'])['steps'][0]['reasons'])

    def test_dropins_missing_and_failed_services_block(self):
        unit=self.catalog['components']['tcp-c2']['units'][0]
        original=copy.deepcopy(self.report['services'][unit])
        for field,value in [('DropInPaths','/etc/systemd/system/test.d/local.conf'),
                            ('LoadState','masked'),('ActiveState','failed'),('UnitFileState','masked'),
                            ('FragmentPath','')]:
            with self.subTest(field=field):
                self.report['services'][unit]=copy.deepcopy(original)
                self.report['services'][unit]['properties'][field]=value
                self.assertEqual(self.plan(['tcp-c2'])['steps'][0]['status'],'blocked')
        del self.report['services'][unit]
        self.assertEqual(self.plan(['tcp-c2'])['steps'][0]['status'],'blocked')

    def test_missing_dropin_field_is_unknown(self):
        unit=self.catalog['components']['tcp-c2']['units'][0]
        del self.report['services'][unit]['properties']['DropInPaths']
        self.assertEqual(self.plan(['tcp-c2'])['steps'][0]['status'],'blocked')

    def test_failed_probe_blocks_selected_firewall_modules(self):
        self.report['probes']['nft_tables']={'status':'error'}
        result=self.plan()
        self.assertEqual(result['summary']['blocked'],3)
        self.assertEqual(result['summary']['noop'],1)

    def test_stopped_disabled_service_is_not_enabled_by_plan(self):
        for unit in self.report['services'].values():
            unit['properties']['ActiveState']='inactive'
            unit['properties']['UnitFileState']='disabled'
        result=self.plan()
        self.assertEqual(result['summary']['noop'],4)
        self.assertNotIn('systemctl enable',planner.render_text(result))
        self.assertTrue(all(not row['automatic_apply'] for row in result['steps']))
        self.assertTrue(all(unit['properties']['ActiveState']=='inactive' and
                            unit['properties']['UnitFileState']=='disabled'
                            for unit in self.report['services'].values()))

    def test_unrelated_missing_services_do_not_expand_selection(self):
        self.report['services']['docker.service']={'status':'unknown'}
        self.report['services']['caddy.service']={'status':'absent'}
        result=self.plan(['tcp-c2'])
        self.assertEqual([r['component'] for r in result['steps']],['tcp-c2'])
        self.assertEqual(result['steps'][0]['status'],'noop')

    def test_unsupported_or_unknown_os_blocks(self):
        for props in ({},{'ID':'debian','VERSION_ID':'12'},{'ID':'other','VERSION_ID':'13'}):
            self.report['os']['properties']=props
            self.assertEqual(self.plan()['summary']['blocked'],4)
        self.report['os']['properties']={'ID':'ubuntu','VERSION_ID':'24.04'}
        self.assertEqual(self.plan()['summary']['noop'],4)

    def test_invalid_schema_and_selection_refused(self):
        for value in (None,True,2):
            self.report['schema_version']=value
            with self.assertRaises(ValueError): self.plan()
        self.report['schema_version']=1
        for selection in ([],['bad'],['tcp-c2','tcp-c2']):
            with self.assertRaises(ValueError):
                planner.build_plan(self.report,selection,self.catalog)
        self.report['changes_applied']=True
        with self.assertRaises(ValueError): self.plan()

    def test_read_json_limits_and_duplicate_keys(self):
        for data in (b'{"mode":"audit","mode":"apply"}',b'x'*(planner.MAX_INPUT+1),b'bad'):
            with self.assertRaises(ValueError): planner.read_json(io.BytesIO(data))

    def test_plan_is_deterministic_and_has_no_subprocess_or_writes(self):
        before=copy.deepcopy(self.report)
        with patch('subprocess.Popen',side_effect=AssertionError('no processes')), \
             patch('builtins.open',side_effect=AssertionError('no files')):
            first=self.plan(['tcp-c2','spamhaus-output'])
            second=self.plan(['spamhaus-output','tcp-c2'])
        self.assertEqual(first,second)
        self.assertEqual(before,self.report)

    def test_cli_reads_stdin_and_emits_only_plan(self):
        result=subprocess.run([sys.executable,str(ROOT/'lib/vps_update_plan.py'),
                               '--inventory','-','--select','tcp-c2','--format','json'],
                              input=json.dumps(self.report),text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['summary']['noop'],1)
        self.assertEqual(result.stderr,'')

    def test_block_mode_is_preserved_without_apply(self):
        for component in ('tcp-c2', 'spamhaus-udp'):
            path = self.catalog['components'][component]['saved_mode']['path']
            self.report['saved_modes'][path]['value'] = 'block'
            row = self.plan([component])['steps'][0]
            self.assertEqual(row['status'], 'noop')
            self.assertEqual(row['preserve_saved_mode']['value'], 'block')
            self.assertFalse(row['automatic_apply'])

    def test_unknown_missing_or_forged_mode_blocks_only_selected_component(self):
        path = self.catalog['components']['spamhaus-udp']['saved_mode']['path']
        for observation in (None, {'status':'unknown'},
                            {'status':'observed','value':'invalid','scope':'saved_only'},
                            {'status':'observed','value':'block','scope':'live'}):
            self.report['saved_modes'][path] = observation
            self.assertEqual(self.plan(['spamhaus-udp'])['steps'][0]['status'], 'blocked')
            self.assertEqual(self.plan(['auto-abuse-guard'])['steps'][0]['status'], 'noop')
        del self.report['saved_modes']
        self.assertEqual(self.plan(['tcp-c2'])['steps'][0]['status'], 'blocked')

    def test_udp_requires_observer_units_without_selecting_observer_update(self):
        del self.report['services']['xtls-spamhaus-output-restore.service']
        plan = self.plan(['spamhaus-udp'])
        self.assertEqual(len(plan['steps']), 1)
        self.assertEqual(plan['steps'][0]['status'], 'blocked')

    def test_missing_substate_blocks_even_with_active_state(self):
        unit = self.catalog['components']['tcp-c2']['units'][0]
        del self.report['services'][unit]['properties']['SubState']
        self.assertEqual(self.plan(['tcp-c2'])['steps'][0]['status'], 'blocked')

    def test_catalog_targets_match_release_files(self):
        for item in self.catalog['components'].values():
            self.assertEqual(hashlib.sha256((ROOT/item['source']).read_bytes()).hexdigest(),item['target_sha256'])


if __name__=='__main__':
    unittest.main()
