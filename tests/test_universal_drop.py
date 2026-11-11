"""Exercise universal DROP orchestration with the real C2 installer and isolated tools."""
import json
import subprocess
from pathlib import Path
import unittest

import test_c2_feed as c2_fixture
import test_spamhaus_udp_menu as udp_fixture

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'vps-setup.sh').read_text()
TCP = 'universal_tcp_drop() (' + SOURCE.split('universal_tcp_drop() (', 1)[1].split('\nuniversal_udp_drop() {', 1)[0]
UDP = 'universal_udp_drop() {' + SOURCE.split('universal_udp_drop() {', 1)[1].split('\nONEBTN_RESULTS=()', 1)[0]


class UniversalC2Tests(unittest.TestCase):
    def setUp(self):
        self.f = c2_fixture.C2Tests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        for name in ('mode', 'validated.csv'):
            (self.f.cache / name).unlink()
        self.f.save_state(dict(table=False, chain=False, set=False, rules=[], next=2, elements=[]))
        self.helper = TCP.replace('/root/xtls-c2-upgrade.',str(self.f.root/'backup.'))
        for prefix in ['/etc/', '/run/', '/usr/local/']:
            self.helper = self.helper.replace(prefix, f'{self.f.root}{prefix}')
        self.helper = 'xtls_c2_write_embedded_module() { cat "' + str(self.f.script) + '"; }\n' + self.helper
        systemctl = self.f.bin / 'systemctl'
        text = systemctl.read_text().replace("assert a ==", "if a[:1] == ['is-active']: sys.exit(3)\nassert a ==", 1)
        systemctl.write_text(text)
        nft = self.f.bin / 'nft'
        data = nft.read_text()
        marker = "elif a in (['list', 'chain', 'ip', 'xtls_c2_feed', 'output'],"
        data = data.replace("        print(f'  {expr} comment \"{comment}\" {handle}')", "        quote='' if (p/'unquoted').exists() else chr(34)\n        print(f'  {expr} comment {quote}{comment}{quote} {handle}')")
        nft.write_text(data)

    def run_install(self):
        return subprocess.run(['bash', '-c', self.helper + '\nuniversal_tcp_drop'],
                              text=True, capture_output=True, timeout=20, env=self.f.env)

    def test_fresh_install_downloads_validates_and_persists_drop_without_duplicates(self):
        for _ in range(2):
            r = self.run_install()
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual((self.f.cache / 'mode').read_text(), 'block\n')
            self.assertEqual([r[1] for r in self.f.state()['rules']], ['xtls-c2-block'])
            self.assertIn('1.1.1.1 . 8443', self.f.state()['elements'][0])
        self.assertTrue((self.f.root / 'etc/systemd/system/xtls-c2-feed-update.timer').exists())

    def test_known_previous_release_is_backed_up_and_upgraded(self):
        import hashlib
        old=(ROOT/'tests/fixtures/xtls-c2-feed-pre-normalize.sh').read_bytes()
        self.assertEqual(hashlib.sha256(old).hexdigest(),'1c1aa5912fa87a867da6a606c0584b31a250c6362fb1c27105e49291e0076939')
        target=self.f.root/'usr/local/sbin/xtls-c2-feed'
        target.write_bytes(old);target.chmod(0o755)
        result=self.run_install()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        backup=list(self.f.root.glob('backup.*/xtls-c2-feed'))
        self.assertEqual(len(backup),1)
        self.assertEqual(backup[0].read_bytes(),old)
        self.assertEqual([r[1] for r in self.f.state()['rules']],['xtls-c2-block'])

    def test_human_comment_quoting_does_not_turn_successful_drop_into_failure(self):
        (self.f.root / 'unquoted').touch()
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Live mode: block', result.stdout)
        self.assertEqual([r[1] for r in self.f.state()['rules']], ['xtls-c2-block'])

    def test_unreadable_invalid_json_and_marker_without_drop_do_not_report_success(self):
        for marker in ('json-error', 'json-broken', 'marker-only'):
            path = self.f.root / marker
            path.touch()
            result = self.run_install()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Проверка TCP C2', result.stdout + result.stderr)
            self.assertNotIn('Verified C2 DROP rules: 1', result.stdout)
            path.unlink()

    def test_failed_feed_never_enables_drop_or_claims_success(self):
        for raw in (None, '8.8.8.8,not-a-port\n'):
            if raw is None:
                (self.f.root / 'fail-download').touch()
            else:
                (self.f.root / 'fail-download').unlink()
                (self.f.root / 'source.csv').write_text(raw)
            r = self.run_install()
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(self.f.state()['rules'], [])
            self.assertNotIn('Blocking enabled and persisted', r.stdout)

    def test_unknown_executable_unit_override_and_foreign_table_stop_before_drop(self):
        target = self.f.root / 'usr/local/sbin/xtls-c2-feed'
        target.write_text('local changes')
        r = self.run_install()
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(target.read_text(), 'local changes')
        target.unlink()
        override = self.f.root / 'etc/systemd/system/xtls-c2-feed-restore.service.d'
        override.mkdir(); (override / 'local.conf').write_text('[Service]\n')
        self.assertNotEqual(self.run_install().returncode, 0)
        (override / 'local.conf').unlink(); override.rmdir()
        state = self.f.state(); state['table'] = True; self.f.save_state(state)
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertFalse(target.exists())
        self.assertEqual(self.f.state()['rules'], [])


class UniversalUDPTests(unittest.TestCase):
    def setUp(self):
        self.f = udp_fixture.UDPMenuTests(); self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.helper = UDP
        self.helper = self.helper.replace('/usr/local/sbin/xtls-spamhaus-udp', str(self.f.target))
        self.helper = self.helper.replace('/etc/xtls-spamhaus-udp', str(self.f.config))
        self.helper = self.helper.replace('/usr/bin/python3', str(self.f.bin / 'fakepython'))
        self.f.source += self.helper
        self.f.tool('fakepython', '''from pathlib import Path
root=Path(os.environ['BASE_READY_FILE']).parent
if sys.argv[-1]=='enable-block':
    if os.environ.get('FAIL_ENABLE'): sys.exit(1)
    (root/'config/mode').write_text('block\\n')
print('UDP status/action:',sys.argv[-1])''')

    def test_fresh_install_prepares_source_saves_exemptions_then_enables_permanent_drop(self):
        r = self.f.run_menu('85.93.10.24,2001:4860::/32\n', function='universal_udp_drop', BASE_READY='0')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((self.f.config / 'mode').read_text(), 'block\n')
        self.assertIn('85.93.10.24/32', (self.f.config / 'exemptions.txt').read_text())
        calls = self.f.logged()
        base = next(i for i,c in enumerate(calls) if c[0]=='base-install')
        enable = next(i for i,c in enumerate(calls) if c[-1]=='enable-block')
        self.assertLess(base, enable)
        self.assertFalse(any(c[0]=='systemd-run' for c in calls))

    def test_failed_source_cancel_or_invalid_exemptions_never_enables_drop(self):
        for answers, flags in (('', {'BASE_READY':'0','FAIL_BASE':'1'}), ('', {}), ('\n', {}), ('0.0.0.0/0\n', {})):
            self.f.calls.unlink(missing_ok=True)
            r = self.f.run_menu(answers, function='universal_udp_drop', **flags)
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertFalse(any(c[-1]=='enable-block' for c in self.f.logged()))

    def test_repeat_preserves_existing_exemptions_and_failed_enable_is_reported(self):
        path = self.f.config / 'exemptions.txt'; path.write_text('# reviewed\n1.1.1.1/32\n')
        for flags, code in (({}, 0), ({'FAIL_ENABLE':'1'}, 1)):
            r = self.f.run_menu(function='universal_udp_drop', **flags)
            self.assertEqual(r.returncode, code, r.stdout + r.stderr)
            self.assertEqual(path.read_text(), '# reviewed\n1.1.1.1/32\n')
