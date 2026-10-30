"""Exercise interactive actions without production services or network access."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'vps-setup.sh').read_text()


def function_between(name, following):
    return name + '() {' + SOURCE.split(name + '() {', 1)[1].split(following + '() {', 1)[0]


class NavigationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.calls = self.root / 'calls'
        self.env = dict(os.environ, PATH=str(self.bin)+':'+os.environ['PATH'],
                        NAV_CALLS=str(self.calls), TMPDIR=str(self.root))

    def tool(self, name, body):
        p = self.bin / name
        p.write_text('#!/bin/bash\nprintf "%s\\n" "'+name+' $*" >> "$NAV_CALLS"\n'+body+'\n')
        p.chmod(0o755)

    def run_menu(self, source, name, choices):
        return subprocess.run(['bash', '-c', 'set -euo pipefail\n'+source+'\n'+name],
                              input=choices, text=True, capture_output=True, env=self.env)

    def feed_source(self):
        source = function_between('setup_spamhaus_out_observe', 'setup_auto_abuse_guard')
        source = source.replace('/tmp/xtls-spamhaus-out.', str(self.root / 'feed.'))
        source += '''
xtls_spamhaus_out_write_module() {
    cat <<'MODULE'
#!/bin/bash
printf 'observer %s\\n' "$1" >> "$NAV_CALLS"
if [[ "$1" == diagnostics-enable ]]; then exit 1; fi
MODULE
}
spamhaus_output_summary() { echo summary >> "$NAV_CALLS"; }
'''
        return source

    def test_feed_actions_stay_in_submenu_until_back(self):
        r = self.run_menu(self.feed_source(), 'setup_spamhaus_out_observe', '3\n6\n0\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls.read_text().splitlines(), ['summary', 'observer diagnostics-show'])
        self.assertFalse(list(self.root.glob('feed.*')))

    def test_feed_failure_allows_status_and_exit(self):
        r = self.run_menu(self.feed_source(), 'setup_spamhaus_out_observe', '4\n3\n0\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('ошибкой', r.stdout)
        self.assertEqual(self.calls.read_text().splitlines(), ['observer diagnostics-enable', 'summary'])
        self.assertFalse(list(self.root.glob('feed.*')))

    def test_feed_eof_cleans_temporary_module(self):
        r = self.run_menu(self.feed_source(), 'setup_spamhaus_out_observe', '')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(list(self.root.glob('feed.*')))

    def test_overall_status_reads_portscan_chain_without_dynamic_set_dump(self):
        self.tool('ipset', 'exit 1')
        self.tool('iptables', 'exit 1')
        self.tool('ip6tables', 'exit 1')
        self.tool('systemctl', 'exit 0')
        self.tool('nft', 'echo chain-summary')
        portscan = self.root / 'xtls-portscan-observe'
        portscan.write_text('#!/bin/bash\nexit 99\n')
        portscan.chmod(0o755)
        source = 'antiabuse_center_status() {' + SOURCE.split('antiabuse_center_status() {', 1)[1].split(
            '# =====================================', 1)[0]
        source = source.replace('/usr/local/sbin/', str(self.root)+'/')
        source += '\nspamhaus_output_summary() { :; }\n'
        r = self.run_menu(source, 'antiabuse_center_status', '')
        self.assertEqual(r.returncode, 0, r.stderr)
        nft_calls = [line for line in self.calls.read_text().splitlines() if line.startswith('nft ')]
        self.assertEqual(nft_calls, ['nft -a list chain inet xtls_portscan_observe out'])
        self.assertIn('chain-summary', r.stdout)

    def guard_source(self):
        self.tool('curl', 'printf "#!/bin/bash\\n" > "${@: -1}"')
        self.tool('systemctl', '[[ -z "${FAIL_START:-}" || "$1" != start ]]')
        self.tool('journalctl', 'echo guard-log')
        source = function_between('setup_auto_abuse_guard', 'setup_smtp25_guard')
        executable = self.root / 'engine'
        executable.write_text('#!/bin/bash\nexit 99\n')
        executable.chmod(0o755)
        return source.replace('/usr/local/sbin/xtls-auto-abuse-guard', str(executable)).replace(
            '/tmp/xtls-auto-guard.', str(self.root / 'guard.'))

    def test_manual_guard_uses_service_for_both_checks_and_limits(self):
        r = self.run_menu(self.guard_source(), 'setup_auto_abuse_guard', '3\n0\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.calls.read_text().splitlines()
        self.assertIn('systemctl start xtls-auto-abuse-guard.service', calls)
        self.assertTrue(any(c.startswith('journalctl ') for c in calls))
        self.assertFalse(list(self.root.glob('guard.*')))

    def test_failed_guard_stays_in_menu(self):
        source = self.guard_source()
        self.env['FAIL_START'] = '1'
        r = self.run_menu(source, 'setup_auto_abuse_guard', '3\n0\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('Проверка не завершена', r.stdout)
        self.assertNotIn('Проверка завершена.', r.stdout)
        self.assertFalse(list(self.root.glob('guard.*')))


if __name__ == '__main__':
    unittest.main()
