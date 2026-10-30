"""Offline Proxmox safety contracts. Never invoke a real firewall or SSH daemon."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'lib'))
import proxmox_host as host
import vps_inventory as inventory
import vps_update_plan as updates
from test_pve_compiled import fixture as compiled_fixture

ADMINS = ['8.8.8.8/32', '2606:4700:4700::1111/128']


def compiler_result(argv):
    if argv[0] != 'perl':
        return ''
    from pve_compiled import expected_rules
    snapshot = compiled_fixture()
    for family in (4, 6):
        snapshot['ipv'+str(family)]['PVEFW-HOST-IN'] = [
            f'-A PVEFW-HOST-IN -s {source} -p tcp --dport {port} -j RETURN'
            for f, source, _, port in expected_rules(Path(argv[-1]).read_text()) if f == family]
    return json.dumps(snapshot)


class ProxmoxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.calls = []
        for name, value in {
            'etc/os-release': 'ID=debian\nVERSION_ID="13"\n',
            'etc/pve/firewall/cluster.fw': '[OPTIONS]\nenable: 1\npolicy_in: DROP\npolicy_out: ACCEPT\n',
            'etc/network/interfaces': 'vmbr0 enp5s0\nvmbr1 10.77.77.1/24\n',
            'etc/pve/qemu-server/101.conf': 'net0: virtio=00:50:56:01:29:1A,bridge=vmbr0\n',
            'etc/pve/qemu-server/102.conf': 'net0: virtio=00:50:56:01:24:12,bridge=vmbr0\n',
        }.items():
            path = self.root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(value)
        for d in ('etc/pve/nodes/testnode', 'etc/ssh/sshd_config.d', 'etc/fail2ban/jail.d'):
            (self.root/d).mkdir(parents=True, exist_ok=True)
        # Transaction tests isolate the mechanism from the intentionally closed
        # production gate for unverified compiled management exceptions.
        self.real_access_review = host.management_access_review
        access = patch.object(host, 'management_access_review', return_value={'status': 'fixture_only', 'activation_allowed': True})
        access.start(); self.addCleanup(access.stop)
        self.args = SimpleNamespace(confirm=host.CONFIRM, console_confirmed=True,
                                    rollback_confirmed=True, key_login_confirmed=True, rollback_seconds=180)
        self.outputs = {
            'dpkg-query': 'install ok installed', 'pveversion': 'pve-manager/9.2.24/abc',
            'qm': 'VMID NAME STATUS\n101 vm1-xtlspro running\n102 vm2-xvpn running\n',
            'pct': 'VMID STATUS NAME\n', 'pve-firewall': 'Status: enabled/running',
            'sshd': 'port 22\npubkeyauthentication yes\npasswordauthentication yes\n',
            'systemctl': 'inactive', 'ip': '[]', 'ss': 'LISTEN 0 4096 [::]:8006', 'pvecm': 'standalone',
        }

    def runner(self, argv):
        self.calls.append(argv)
        if argv[:2] == ['qm', 'agent']:
            return {'status': 'ok', 'output': ''}
        return {'status': 'ok', 'output': self.outputs.get(argv[0], '')}

    def audit(self):
        return host.audit(self.root, self.runner, 'testnode')

    def plan(self, op='firewall', **kwargs):
        return host.make_plan(self.audit(), op, ADMINS, **kwargs)

    def apply(self, plan):
        with patch.object(host.os, 'geteuid', return_value=0):
            return host.apply(plan, self.args, self.root, self.runner)

    def snapshot(self):
        return {str(p.relative_to(self.root)): p.read_bytes() for base in ('etc/network', 'etc/pve/qemu-server')
                for p in (self.root/base).rglob('*') if p.is_file()}

    def test_detection_requires_both_signals(self):
        self.assertEqual(self.audit()['profile'], 'proxmox')
        self.outputs['pveversion'] = 'broken'
        self.assertEqual(self.audit()['profile'], 'proxmox_uncertain')
        self.outputs['dpkg-query'] = 'deinstall ok config-files'
        self.assertEqual(self.audit()['profile'], 'proxmox_uncertain')

    def test_vps_and_unknown_detection(self):
        empty = self.root/'empty'; empty.mkdir()
        def absent(argv):
            return {'status': 'error' if argv[0] == 'dpkg-query' else 'unavailable', 'returncode': 1}
        self.assertEqual(host.detect(empty, absent)['profile'], 'vps')
        self.assertEqual(host.detect(empty, lambda argv: {'status': 'timeout'})['profile'], 'unknown')

    def test_audit_is_bounded_readonly_and_filters_ssh(self):
        before = self.snapshot()
        self.outputs['sshd'] += 'authorizedkeyscommand /private/secret\n'
        report = self.audit()
        self.assertFalse(report['changes_applied'])
        self.assertNotIn('secret', json.dumps(report))
        self.assertEqual(set(report['guest_agent']), {'101', '102'})
        self.assertEqual(self.snapshot(), before)
        forbidden = {'install', 'restart', 'reload', 'set', 'exec', 'guest-exec', 'add', 'delete'}
        self.assertFalse(any(forbidden.intersection(argv) for argv in self.calls))

    def test_host_options_never_include_datacenter_policies(self):
        candidate = host.firewall_content(ADMINS)
        options = candidate.split('[OPTIONS]\n')[1].split('[RULES]')[0].strip()
        self.assertEqual(options, 'enable: 1')
        self.assertNotIn('policy_in', candidate)
        self.assertNotIn('policy_out', candidate)

    def test_audit_reports_datacenter_policy_sources(self):
        report = self.audit()
        self.assertEqual(report['datacenter']['policies']['policy_in']['declared'], 'DROP')
        path = self.root/'etc/pve/firewall/cluster.fw'
        path.write_text('[OPTIONS]\nenable: 1\n')
        p = self.plan()
        self.assertTrue(any('policy_in' in reason for reason in p['blockers']))
        self.assertIn('assumed', self.audit()['datacenter']['policies']['policy_in']['source'])
        path.write_text('[OPTIONS]\nenable: 1\npolicy_in: ACCEPT\npolicy_out: DROP\n')
        self.assertTrue(any('Host cannot override' in reason for reason in self.plan()['blockers']))

    def test_builtin_and_datacenter_bypasses_cannot_be_certified_by_host_file(self):
        with patch.object(host, 'management_access_review', self.real_access_review):
            p = self.plan()
            self.assertFalse(p['management_access']['activation_allowed'])
            self.assertTrue(p['blockers'])
            with self.assertRaises(ValueError): self.apply(p)
            path = self.root/'etc/pve/firewall/cluster.fw'
            path.write_text(path.read_text()+'[RULES]\nIN ACCEPT -p tcp -dport 8006\n[IPSET management]\n8.8.4.4\n')
            p = self.plan()
            self.assertTrue(p['management_access']['datacenter_rules_present'])
            self.assertTrue(p['management_access']['management_ipset_present'])
            self.assertTrue(p['blockers'])

    def test_invalid_host_options_and_zero_exit_diagnostics_reject_preflight(self):
        path = self.root/'candidate.fw'
        path.write_text(host.firewall_content(ADMINS).replace('enable: 1', 'enable: 1\npolicy_in: DROP'))
        with patch.object(host, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'unsupported Host options'): host.validate_candidate(path)
            run.assert_not_called()
        path.write_text(host.firewall_content(ADMINS))
        for output in ('warning: unknown option', 'errors in config', 'parser warning on stderr'):
            with patch.object(host, 'run', return_value=output):
                with self.assertRaisesRegex(ValueError, 'diagnostics'): host.validate_candidate(path)
        with patch.object(host, 'run', side_effect=compiler_result):
            host.validate_candidate(path)

    def test_preflight_diagnostics_never_arm_timer_or_write_host(self):
        commands = []
        def run(argv):
            commands.append(argv)
            return 'config parser: unknown option' if argv[0] == 'perl' else ''
        with patch.object(host, 'run', side_effect=run):
            with self.assertRaisesRegex(ValueError, 'diagnostics'):
                self.apply(self.plan())
        self.assertFalse((self.root/'etc/pve/nodes/testnode/host.fw').exists())
        self.assertFalse(any(argv[0] == 'systemd-run' for argv in commands))

    def test_duplicate_datacenter_options_are_not_accepted(self):
        path = self.root/'etc/pve/firewall/cluster.fw'
        path.write_text(path.read_text()+'policy_in: ACCEPT\n')
        self.assertTrue(self.plan()['datacenter']['parse_errors'])
        self.assertTrue(self.plan()['blockers'])

    def test_native_plan_host_only_dual_stack(self):
        p = self.plan(spice=True)
        self.assertEqual(p['blockers'], [])
        self.assertEqual(p['destination'], '/etc/pve/nodes/testnode/host.fw')
        self.assertIn('-source 2606:4700:4700::1111/128', p['content'])
        for port in (22, 8006, 3128):
            self.assertEqual(p['content'].count(f'-dport {port}\n'), 2)
        for word in ('FORWARD', 'vmbr', 'net0', 'iptables', 'nft'):
            self.assertNotIn(word, p['content'])
        self.assertEqual(p, self.plan(spice=True))

    def test_invalid_and_dynamic_allowlists_fail_closed(self):
        for admins in ([], ['0.0.0.0/0'], ['8.8.8.8; reboot'], ['8.8.8.8/32'],
                       ['127.0.0.1/32', ADMINS[1]], ['8.8.8.1/24', ADMINS[1]]):
            with self.assertRaises(ValueError):
                host.make_plan(self.audit(), 'firewall', admins)
        self.assertTrue(self.plan(dynamic_admin=True)['blockers'])

    def test_foreign_cluster_and_host_rules_preserved(self):
        path = self.root/'etc/pve/nodes/testnode/host.fw'; path.write_text('[RULES]\nIN ACCEPT\n')
        self.assertTrue(self.plan()['blockers'])
        (self.root/'etc/pve/firewall/cluster.fw').unlink()
        self.assertTrue(self.plan()['blockers'])
        self.assertEqual(path.read_text(), '[RULES]\nIN ACCEPT\n')

    def test_confirmation_and_plan_tampering_precede_writes(self):
        p = self.plan()
        self.args.console_confirmed = False
        with self.assertRaises(ValueError): self.apply(p)
        self.args.console_confirmed = True
        p['content'] += '\nIN ACCEPT\n'
        with self.assertRaises(ValueError): self.apply(p)
        self.assertFalse((self.root/'var').exists())

    def test_unsupported_version_and_os_block_apply(self):
        p = self.plan()
        self.outputs['pveversion'] = 'pve-manager/10.0/abc'
        with self.assertRaises(ValueError): self.apply(p)
        self.outputs['pveversion'] = 'pve-manager/9.2.24/abc'
        (self.root/'etc/os-release').write_text('ID=ubuntu\nVERSION_ID=24.04\n')
        with self.assertRaises(ValueError): self.apply(p)

    def test_timer_before_activation_and_rollback_preserves_guests(self):
        before = self.snapshot(); commands = []
        def run(argv):
            commands.append(argv)
            return compiler_result(argv)
        with patch.object(host, 'run', side_effect=run):
            result = self.apply(self.plan())
            path = self.root/'etc/pve/nodes/testnode/host.fw'
            self.assertTrue(path.exists())
            self.assertEqual(commands[0][0], 'perl')  # Candidate parse/compile before active write.
            self.assertEqual(commands[1][0], 'systemd-run')
            self.assertLess(next(i for i,a in enumerate(commands) if a[0]=='systemd-run'),
                            next(i for i,a in enumerate(commands) if 'restart' in a))
            host.rollback(Path(result['transaction']))
            self.assertFalse(path.exists())
            host.rollback(Path(result['transaction']))
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(any(a[0] in ('nft', 'iptables', 'ip', 'qm', 'pct') for a in commands))

    def test_timer_failure_never_writes_host_config(self):
        def run(argv):
            if argv[0] == 'systemd-run': raise RuntimeError('timer failure')
            return compiler_result(argv)
        with patch.object(host, 'run', side_effect=run):
            with self.assertRaises(RuntimeError): self.apply(self.plan())
        self.assertFalse((self.root/'etc/pve/nodes/testnode/host.fw').exists())
        self.assertTrue(list((self.root/'var/lib/proxmox-host').glob('*/rolled-back')))

    def test_failed_compile_rolls_back_before_commit(self):
        def run(argv):
            if argv == ['pve-firewall', 'compile']:
                # Fail only the initial post-write check; permit rollback check.
                if not getattr(run, 'failed', False):
                    run.failed = True; raise RuntimeError('compile failure')
            return compiler_result(argv)
        with patch.object(host, 'run', side_effect=run):
            with self.assertRaises(RuntimeError): self.apply(self.plan())
        self.assertFalse((self.root/'etc/pve/nodes/testnode/host.fw').exists())

    def test_commit_requires_independent_verification_and_deadline(self):
        with patch.object(host, 'run', side_effect=compiler_result):
            result = self.apply(self.plan())
            txn = Path(result['transaction'])
            with self.assertRaises(ValueError): host.commit(txn, 'yes')
            host.commit(txn, 'VERIFIED SSH UI IPV4 IPV6 AND GUESTS')
            host.rollback(txn)
            self.assertTrue((self.root/'etc/pve/nodes/testnode/host.fw').exists())
        state = json.loads((txn/'state.json').read_text()); state['deadline'] = 0
        (txn/'state.json').write_text(json.dumps(state))
        with self.assertRaises(ValueError): host.commit(txn, 'VERIFIED SSH UI IPV4 IPV6 AND GUESTS')

    def test_ssh_failure_restores_backup_without_changing_bridges(self):
        before = self.snapshot(); commands=[]
        def run(argv):
            commands.append(argv)
            if argv == ['sshd', '-T']:
                return 'pubkeyauthentication yes\npasswordauthentication yes\n'
            return compiler_result(argv)
        with patch.object(host, 'run', side_effect=run):
            with self.assertRaises(ValueError): self.apply(self.plan('ssh'))
        self.assertFalse((self.root/'etc/ssh/sshd_config.d/00-proxmox-host.conf').exists())
        self.assertIn(['sshd', '-t'], commands)
        self.assertEqual(self.snapshot(), before)

    def test_idempotent_apply_and_stale_plan(self):
        p = self.plan(); path = self.root/'etc/pve/nodes/testnode/host.fw'
        with patch.object(host, 'run', side_effect=compiler_result):
            result = self.apply(p)
            host.commit(Path(result['transaction']), 'VERIFIED SSH UI IPV4 IPV6 AND GUESTS')
            with self.assertRaises(ValueError): self.apply(p)
            self.assertEqual(self.apply(self.plan())['status'], 'unchanged')
        self.assertEqual(path.read_text(), p['content'])

    def test_only_allowlisted_operations(self):
        for op in ('ufw', 'docker', 'xanmod', 'nextdns', 'C2', 'network'):
            with self.assertRaises(ValueError): host.make_plan(self.audit(), op)
        self.assertIn('banaction = dummy', self.plan('fail2ban')['content'])
        with patch.object(host, 'run', side_effect=compiler_result):
            self.assertEqual(self.apply(self.plan('sysctl-advice'))['status'], 'advisory_only')

    def test_inventory_and_legacy_planner_mark_proxmox(self):
        report = inventory.collect(self.root, self.runner, {'files': []})
        self.assertEqual(report['host_profile'], 'proxmox')
        self.assertEqual(report['proxmox']['mode'], 'audit')
        catalog = json.loads((ROOT/'lib/update_catalog.json').read_text())
        result = updates.build_plan(report, list(catalog['components']), catalog)
        self.assertTrue(all('proxmox_host_vps_modules_blocked' in row['reasons'] for row in result['steps']))

    def test_bash_default_and_internal_execution_gates(self):
        binpath = self.root/'bin'; binpath.mkdir()
        for name, body in {
            'dpkg-query': "printf 'install ok installed'",
            'python3': "printf 'AUDIT %s\\n' \"$*\"",
        }.items():
            path = binpath/name; path.write_text('#!/bin/sh\n'+body+'\n'); path.chmod(0o755)
        env = dict(os.environ, PATH=str(binpath)+':'+os.environ['PATH'], VPS_PROFILE='vps')
        result = subprocess.run(['bash', str(ROOT/'vps-setup.sh')], input='00\nW\n',
                                text=True, capture_output=True, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Proxmox Host', result.stderr)
        self.assertIn('proxmox_host.py audit', result.stdout)
        (binpath/'dpkg-query').write_text('#!/bin/sh\nexit 2\n')
        uncertain = subprocess.run(['bash', str(ROOT/'vps-setup.sh')], input='00\n', text=True, capture_output=True, env=env)
        self.assertIn('proxmox_host.py audit', uncertain.stdout)
        (binpath/'dpkg-query').write_text('#!/bin/sh\nprintf \"install ok installed\"\n')
        source = (ROOT/'vps-setup.sh').read_text()
        for name, opener in [('setup_base', '{'), ('setup_one_button', '{'),
                             ('do_ufw_setup', '{'), ('cleanup_legacy', '{'),
                             ('kt_apply_sysctl', '{'), ('ad_install', '{'), ('tib_install', '{'),
                             ('crowdsec_install', '{'),
                             ('spamhaus_udp_install', '('), ('rn_install_docker', '{'),
                             ('_nextdns_apply', '{'), ('ensure_loopback_accept', '{')]:
            prefix = source.split(name+'() '+opener, 1)[1].split('\n    fi', 1)[0]+'\n    fi\n'
            code = name+'() { '+prefix+'\necho MUTATED; }; '+name
            result = subprocess.run(['bash', '-c', code], env=env, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0, name)
            self.assertNotIn('MUTATED', result.stdout)

    def test_independent_process_can_rollback_during_restart(self):
        def run(argv):
            if argv == ['systemctl', 'restart', 'pve-firewall.service']:
                txn = next((self.root/'var/lib/proxmox-host').iterdir())
                # A real second process takes the real flock and restores files.
                code = "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); import proxmox_host as h; h.run=lambda argv: ''; h.rollback(Path(sys.argv[2]))"
                subprocess.run([sys.executable, '-c', code, str(ROOT/'lib'), str(txn)],
                               check=True, timeout=5, capture_output=True)
            return compiler_result(argv)
        with patch.object(host, 'run', side_effect=run):
            with self.assertRaisesRegex(ValueError, 'rolled back'):
                self.apply(self.plan())
        self.assertFalse((self.root/'etc/pve/nodes/testnode/host.fw').exists())

    def test_expiry_during_service_checks_rejects_apply(self):
        def run(argv):
            if argv == ['systemctl', 'restart', 'pve-firewall.service']:
                txn = next((self.root/'var/lib/proxmox-host').iterdir())
                state = json.loads((txn/'state.json').read_text())
                # Use a future clock for the final deadline check, not timer mocks.
                clock.return_value = state['deadline'] + 1
            return compiler_result(argv)
        with patch.object(host.time, 'time', return_value=time.time()) as clock, patch.object(host, 'run', side_effect=run):
            with self.assertRaisesRegex(ValueError, 'expired'):
                self.apply(self.plan())
        self.assertFalse((self.root/'etc/pve/nodes/testnode/host.fw').exists())

    def test_commit_cannot_attest_before_apply_completed(self):
        with patch.object(host, 'run', side_effect=compiler_result):
            result = self.apply(self.plan())
        txn = Path(result['transaction']); (txn/'applied').unlink()
        with self.assertRaisesRegex(ValueError, 'not completed'):
            host.commit(txn, 'VERIFIED SSH UI IPV4 IPV6 AND GUESTS')

    def test_ssh_effective_uses_exact_lines_and_accepts_openssh_alias(self):
        good = 'passwordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin without-password'
        host.validate_ssh_effective(good)
        with self.assertRaises(ValueError):
            host.validate_ssh_effective(good.replace('passwordauthentication no', 'passwordauthentication no-invalid'))

    def test_fail2ban_other_jails_and_firewall_actions_rejected(self):
        for dump in ("['add', 'recidive', 'systemd']", "['set', 'sshd', 'addaction', 'nftables-multiport']"):
            with patch.object(host, 'run', return_value=dump):
                with self.assertRaises(ValueError): host.check_fail2ban_dump()
        with patch.object(host, 'run', return_value="['add', 'sshd', 'systemd']\n['set', 'sshd', 'addaction', 'dummy']"):
            host.check_fail2ban_dump()

    def test_restore_existing_backup_and_file_mode(self):
        path = self.root/'etc/pve/nodes/testnode/host.fw'
        original = host.firewall_content(ADMINS)
        path.write_text(original)
        with patch.object(host, 'run', side_effect=compiler_result):
            result = self.apply(self.plan(spice=True))
            self.assertIn('3128', path.read_text())
            host.rollback(Path(result['transaction']))
        self.assertEqual(path.read_text(), original)

    def test_alternative_backend_and_nonstandard_ssh_port_block(self):
        self.outputs['systemctl'] = 'active'
        self.assertTrue(self.plan()['blockers'])
        self.outputs['systemctl'] = 'inactive'
        self.outputs['sshd'] = 'port 2222\n'
        self.assertTrue(self.plan()['blockers'])

    def test_crowdsec_bouncers_unknown_or_present_prevent_start(self):
        for packages, bouncers in [('crowdsec\ncrowdsec-firewall-bouncer', '[]'),
                                  ('crowdsec', '[{"name":"existing"}]'),
                                  ('crowdsec', 'null')]:
            p = self.plan('crowdsec-observe')
            def runner(argv):
                if argv == ['dpkg-query', '-W', '-f=${binary:Package}\n']:
                    return {'status':'ok', 'output':packages}
                if argv[0] == 'cscli':
                    return {'status':'ok', 'output':bouncers}
                return self.runner(argv)
            with patch.object(host.os, 'geteuid', return_value=0), patch.object(host, 'run') as run:
                with self.assertRaises(ValueError): host.apply(p, self.args, self.root, runner)
                run.assert_not_called()

    def test_imported_python_mutator_gate(self):
        spec = importlib.util.spec_from_file_location('proxmox_udp_fixture', ROOT/'modules/xtls-spamhaus-udp.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with patch.object(module.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='install ok installed')):
            with self.assertRaises(SystemExit):
                module.Guard(root=self.root/'should-not-exist').save_mode('block')
        self.assertFalse((self.root/'should-not-exist').exists())

    def test_standalone_node_modules_block_proxmox(self):
        binpath = self.root/'bin'; binpath.mkdir()
        path = binpath/'dpkg-query'; path.write_text('#!/bin/sh\nprintf "install ok installed"\n'); path.chmod(0o755)
        env = dict(os.environ, PATH=str(binpath)+':'+os.environ['PATH'])
        for path in (ROOT/'modules').glob('*'):
            if path.suffix not in ('.sh', '.py'): continue
            result = subprocess.run(['bash' if path.suffix == '.sh' else sys.executable, str(path), 'install'],
                                    env=env, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0, path.name)
            self.assertIn('BLOCKED', result.stderr, path.name)


if __name__ == '__main__':
    unittest.main()
