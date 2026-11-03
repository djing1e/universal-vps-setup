"""Run the real batch runner with inert backends; no host configuration changes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'vps-setup.sh').read_text()
BATCH = SOURCE[SOURCE.index('ONEBTN_RESULTS=()\nonebtn_step()'):SOURCE.index('\n# =====================================================\n# ПОЛНАЯ ВЫЧИСТКА')]
STEPS = ('do_update_packages', 'do_ssh_setup', 'do_ufw_setup',
         'kt_apply_sysctl', 'do_autoupgrade', 'do_fail2ban', 'crowdsec_install')
FORBIDDEN = ('do_sysctl_setup', 'kt_install_xanmod', 'setup_nextdns',
             'ad_install', 'tib_install', 'asb_install_iptables',
             'setup_antiabuse_center', 'setup_remnanode', 'do_docker_mirrors',
             'ensure_loopback_accept', 'reboot')


class UniversalInstallTests(unittest.TestCase):
    def run_batch(self, answers='yes\n', fail=None, code=1, bbr='bbr', qdisc='fq'):
        with tempfile.TemporaryDirectory() as directory:
            calls = Path(directory) / 'calls'
            stubs = ['print_header() { :; }', 'log() { :; }',
                     'rn_warn() { echo "$*"; }', 'rn_error() { echo "$*"; }',
                     'rn_success() { echo "$*"; }', 'rn_info() { echo "$*"; }',
                     'DEFAULT_SSH_PORT=62152', 'LOG_FILE=/tmp/inert-install.log']
            for name in STEPS + FORBIDDEN:
                rc = code if name == fail else (91 if name in FORBIDDEN else 0)
                stubs.append(f'{name}() {{ echo {name} >> "$CALLS"; return {rc}; }}')
            stubs.append('sysctl() { case "$2" in net.ipv4.tcp_congestion_control) echo "$BBR";; net.core.default_qdisc) echo "$QDISC";; *) return 1;; esac; }')
            result = subprocess.run(['bash', '-c', '\n'.join(stubs) + '\n' + BATCH + '\nsetup_one_button'],
                                    input=answers, text=True, capture_output=True, timeout=5,
                                    env=dict(os.environ, CALLS=str(calls), BBR=bbr, QDISC=qdisc))
            return result, calls.read_text().splitlines() if calls.exists() else []

    def test_success_runs_only_the_seven_selected_steps_in_order(self):
        result, calls = self.run_batch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, list(STEPS))
        self.assertIn('7 OK, 0 FAIL, 0 SKIP', result.stdout)
        self.assertIn('Не входят: DNS, XanMod, Anti-DDoS, Anti-Abuse и AS-списки', result.stdout)

    def test_decline_invalid_and_eof_do_nothing(self):
        for answer in ('', '0\n', 'y\n', 'YES\n'):
            result, calls = self.run_batch(answer)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls, [])

    def test_critical_failure_stops_remaining_steps_and_prints_report(self):
        for index, step in enumerate(STEPS[:3]):
            for rc in (1, 2):
                result, calls = self.run_batch(fail=step, code=rc)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(calls, list(STEPS[:index + 1]))
                self.assertIn('ОТЧЁТ: универсальная установка', result.stdout)
                self.assertIn('Установка остановлена', result.stdout)

    def test_noncritical_failure_runs_remaining_steps_but_returns_failure(self):
        for step in STEPS[3:]:
            result, calls = self.run_batch(fail=step)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(calls, list(STEPS))
            self.assertIn('6 OK, 1 FAIL, 0 SKIP', result.stdout)

    def test_optional_crowdsec_skip_is_visible(self):
        result, calls = self.run_batch(fail='crowdsec_install', code=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, list(STEPS))
        self.assertIn('6 OK, 0 FAIL, 1 SKIP', result.stdout)
        self.assertIn('с пропущенными шагами', result.stdout)

    def test_unavailable_bbr_or_fq_does_not_install_another_kernel(self):
        for bbr, qdisc in (('cubic', 'fq'), ('bbr', 'fq_codel')):
            result, calls = self.run_batch(bbr=bbr, qdisc=qdisc)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(calls, list(STEPS))
            self.assertIn('BBR / fq не подтверждены', result.stdout)
