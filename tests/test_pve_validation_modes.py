"""Mode isolation, including real Perl execution with synthetic PVE packages."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'lib'))
import proxmox_host as host
from test_pve_compiled import fixture, ADMINS


class ValidationModeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.candidate = self.root/'host.fw'; self.candidate.write_text(host.firewall_content(ADMINS))
        self.cluster = self.root/'test-cluster.fw'
        self.cluster.write_text('[OPTIONS]\nenable: 1\npolicy_in: DROP\npolicy_out: ACCEPT\n')

    def test_production_never_passes_test_datacenter(self):
        with patch.object(host, 'run', return_value=json.dumps(fixture())) as run:
            result = host.validate_candidate(self.candidate)
        self.assertEqual(run.call_args.args[0][-2:], [str(self.candidate), ''])
        self.assertEqual(result['datacenter_source'], 'live')
        self.assertEqual(result['validation_mode'], 'production')
        self.assertFalse(result['apply_authorized'])
        with self.assertRaises(ValueError):
            host.compile_candidate(self.candidate, mode='production', datacenter=self.cluster)

    def test_offline_provenance_is_test_only_and_files_unchanged(self):
        before = (self.cluster.read_bytes(), self.candidate.read_bytes())
        with patch.object(host, 'run', return_value=json.dumps(fixture())) as run:
            result = host.validate_offline(self.candidate, self.cluster)
        self.assertEqual(run.call_args.args[0][-2:], [str(self.candidate), str(self.cluster)])
        self.assertEqual(result['datacenter_source'], 'explicit_test_file')
        self.assertEqual(result['test_datacenter_sha256'], host.fingerprint(before[0]))
        self.assertFalse(result['production_safety_evidence'])
        self.assertFalse(result['activation_allowed'])
        self.assertFalse(result['apply_authorized'])
        self.assertEqual(result['compiled_snapshot']['provenance']['validation_mode'], 'offline')
        self.assertEqual(before, (self.cluster.read_bytes(), self.candidate.read_bytes()))
        with self.assertRaisesRegex(ValueError, 'validation results cannot authorize Apply'):
            host.apply(result, SimpleNamespace())

    def test_offline_requires_explicit_enabled_external_test_file(self):
        for path in (None, self.root/'missing', Path('/etc/pve/firewall/cluster.fw')):
            with self.assertRaises(ValueError): host.validate_offline(self.candidate, path)
        self.cluster.write_text('[OPTIONS]\nenable: 0\n')
        with patch.object(host, 'run') as run:
            with self.assertRaises(ValueError): host.validate_offline(self.candidate, self.cluster)
            run.assert_not_called()

    def test_reanalysis_of_offline_artifact_never_becomes_production_evidence(self):
        with patch.object(host, 'run', return_value=json.dumps(fixture())):
            result = host.validate_offline(self.candidate, self.cluster)
        artifact = self.root/'report.json'; artifact.write_text(json.dumps(result))
        check = subprocess.run([sys.executable, str(Path(host.__file__)), 'analyze-compiled',
                                str(self.candidate), str(artifact)], capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)
        report = json.loads(check.stdout)
        self.assertEqual(report['validation_mode'], 'offline_artifact_analysis')
        self.assertEqual(report['source_provenance']['validation_mode'], 'offline')
        self.assertFalse(report['production_safety_evidence'])
        self.assertFalse(report['apply_authorized'])

    def test_missing_host_chain_is_failure_in_both_modes(self):
        snapshot = fixture(); snapshot['ipv4'] = {}
        with patch.object(host, 'run', return_value=json.dumps(snapshot)):
            with self.assertRaisesRegex(ValueError, 'Host chain missing'): host.validate_candidate(self.candidate)
            with self.assertRaisesRegex(ValueError, 'Host chain missing'): host.validate_offline(self.candidate, self.cluster)

    def test_changed_test_configuration_is_rejected(self):
        def run(argv, **kwargs):
            self.cluster.write_text('[OPTIONS]\nenable: 0\n')
            return json.dumps(fixture())
        with patch.object(host, 'run', side_effect=run):
            with self.assertRaisesRegex(ValueError, 'changed during compilation'):
                host.validate_offline(self.candidate, self.cluster)

    def test_cli_cannot_inject_test_datacenter_into_production_or_apply(self):
        script = str(Path(host.__file__))
        for args in (['validate-candidate', str(self.candidate)], ['apply', str(self.candidate), '--confirm', host.CONFIRM]):
            result = subprocess.run([sys.executable, script, *args, '--datacenter', str(self.cluster)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('unrecognized arguments', result.stderr)

    def setup_perl_stub(self):
        directory = self.root/'perl/PVE'; directory.mkdir(parents=True)
        (directory/'Cluster.pm').write_text('package PVE::Cluster; sub cfs_update {} 1;\n')
        (directory/'Firewall.pm').write_text(r'''package PVE::Firewall;
use JSON::PP;
sub load_clusterfw_conf {
    my ($path)=@_; $path=$ENV{PVE_TEST_LIVE} unless defined($path);
    open(my $log, '>>', $ENV{PVE_TEST_CALLS}) or die $!;
    print $log "cluster:$path\n"; close($log);
    open(my $f,'<',$path) or die $!; local $/; my $raw=<$f>;
    return {options=>{enable=>($raw =~ /^enable:\s*1\s*$/m ? 1 : 0)}};
}
sub load_hostfw_conf { return {}; }
sub compile {
    open(my $log, '>>', $ENV{PVE_TEST_CALLS}) or die $!; print $log "compile\n"; close($log);
    open(my $f, '<', $ENV{PVE_TEST_SNAPSHOT}) or die $!; local $/;
    my $s=JSON::PP->new->decode(<$f>);
    return ({filter=>$s->{ipv4}},$s->{ipsets},{filter=>$s->{ipv6}},{});
}
1;
''')
        self.live = self.root/'live-cluster.fw'; self.live.write_text('[OPTIONS]\nenable: 0\n')
        snapshot = self.root/'snapshot.json'; snapshot.write_text(json.dumps(fixture()))
        self.calls = self.root/'calls'
        self.env = dict(os.environ, PERL5LIB=str(directory.parent), PVE_TEST_LIVE=str(self.live),
                        PVE_TEST_SNAPSHOT=str(snapshot), PVE_TEST_CALLS=str(self.calls))

    def real_perl(self, argv, **kwargs):
        result = subprocess.run(argv, capture_output=True, text=True, env=self.env, timeout=5)
        if result.returncode:
            raise RuntimeError(result.stdout+result.stderr)
        return result.stdout+result.stderr

    def test_real_perl_disabled_live_fails_but_enabled_test_compiles(self):
        self.setup_perl_stub()
        before = self.live.read_bytes()
        with patch.object(host, 'run', side_effect=self.real_perl):
            with self.assertRaisesRegex(RuntimeError, 'Datacenter firewall disabled'):
                host.validate_candidate(self.candidate)
            self.assertNotIn('compile\n', self.calls.read_text())
            result = host.validate_offline(self.candidate, self.cluster)
        self.assertTrue(result['semantic_rules_verified'])
        self.assertFalse(result['production_safety_evidence'])
        self.assertEqual(self.live.read_bytes(), before)
        self.assertEqual(self.calls.read_text().splitlines(), [f'cluster:{self.live}', f'cluster:{self.cluster}', 'compile'])

    def test_real_perl_enabled_live_uses_only_live_configuration(self):
        self.setup_perl_stub(); self.live.write_text('[OPTIONS]\nenable: 1\n')
        with patch.object(host, 'run', side_effect=self.real_perl):
            result = host.validate_candidate(self.candidate)
        self.assertEqual(result['validation_mode'], 'production')
        self.assertEqual(self.calls.read_text().splitlines(), [f'cluster:{self.live}', 'compile'])
