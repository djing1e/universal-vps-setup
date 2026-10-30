"""Safety boundaries for the separately invoked real-systemd VM fixture."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('systemd_fixture',ROOT/'tests/run_guard_upgrade_systemd.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)


class SystemdFixtureTests(unittest.TestCase):
    def test_production_host_and_missing_confirmation_refused(self):
        with patch.object(fixture.upgrade,'probe',side_effect=AssertionError('no probes')):
            for host,phrase in [('vm2-xvpn',fixture.PHRASE),('vm1-xtlspro','wrong')]:
                with self.assertRaises(ValueError):fixture.require_test_host(host,phrase)

    def test_fixture_policy_is_in_memory_and_does_not_mutate_release_policy(self):
        policy={'target_sha256':'release','accepted_current_sha256':['release'],
                'units':{'service':'unit-hash'}}
        before=copy.deepcopy(policy)
        result=fixture.fixture_policy(policy,b'old',b'new')
        self.assertEqual(policy,before)
        self.assertEqual(result['target_sha256'],fixture.upgrade.digest(b'new'))
        self.assertEqual(result['units'],policy['units'])
        self.assertNotEqual(result['accepted_current_sha256'],policy['accepted_current_sha256'])

    def test_nonroot_refused_before_reading_systemd(self):
        with patch.object(fixture.os,'geteuid',return_value=1000), \
             patch.object(fixture.Path,'read_text',side_effect=AssertionError('no reads')):
            with self.assertRaisesRegex(ValueError,'root required'):
                fixture.require_test_host('vm1-xtlspro',fixture.PHRASE)


if __name__=='__main__':unittest.main()
