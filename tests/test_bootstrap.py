"""Bootstrap verifies and installs a fixture payload without touching the host."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('sbin', 'localbin', 'bin', 'root'):
            (self.root / name).mkdir()
        self.calls = self.root / 'calls'
        self.payload = self.root / 'payload'
        self.payload.write_text('#!/bin/bash\necho "LAUNCHED:$*"\nread -r answer\necho "ANSWER:$answer"\n')
        self.digest = hashlib.sha256(self.payload.read_bytes()).hexdigest()
        self.source = (ROOT / 'install.sh').read_text()
        # Match either a published pin or placeholders during source preparation.
        import re
        self.source = re.sub(r'^SCRIPT_SHA256=.*$', 'SCRIPT_SHA256=' + self.digest, self.source, flags=re.M)
        for old, new in (('/usr/local/sbin', str(self.root / 'sbin')),
                         ('/usr/local/bin', str(self.root / 'localbin')),
                         ('/root/vps-setup-backup.', str(self.root / 'root/backup.'))):
            self.source = self.source.replace(old, new)
        self.target = self.root / 'sbin/vps-setup'
        self.launcher = self.root / 'localbin/vps-setup'
        self.env = dict(os.environ, PATH=str(self.root / 'bin') + ':' + os.environ['PATH'],
                        FIXTURE=str(self.root), PAYLOAD=str(self.payload))
        self.tool('curl', '''[[ -z "${FAIL_DOWNLOAD:-}" ]] || exit 22
if [[ -n "${CORRUPT_DOWNLOAD:-}" ]]; then echo corrupt > "${@: -1}"; else cp "$PAYLOAD" "${@: -1}"; fi''')
        self.tool('apt-get', '[[ -z "${FAIL_APT:-}" ]] || exit 100')

    def tool(self, name, body):
        p = self.root / 'bin' / name
        p.write_text('#!/bin/bash\necho "'+name+':$*" >> "$FIXTURE/calls"\n' + body + '\n')
        p.chmod(0o755)

    def run_install(self, action='--install', missing_curl=False, **env):
        prefix = ''
        if missing_curl:
            prefix = 'command() { if [[ "$1" == -v && "$2" == curl ]]; then return 1; fi; builtin command "$@"; }\n'
        return subprocess.run(['bash', '-c', prefix + self.source, 'test', action], input='interactive-key\n',
                              text=True, capture_output=True, env=self.env | env, timeout=10)

    def test_published_pin_matches_payload(self):
        import re
        source = (ROOT / 'install.sh').read_text()
        revision = re.search(r'^SOURCE_REVISION=([0-9a-f]{40})$', source, re.M)
        digest = re.search(r'^SCRIPT_SHA256=([0-9a-f]{64})$', source, re.M)
        self.assertIsNotNone(revision)
        self.assertIsNotNone(digest)
        self.assertEqual(digest[1], hashlib.sha256((ROOT / 'vps-setup.sh').read_bytes()).hexdigest())

    def test_missing_curl_installs_prerequisites_then_verified_payload_with_terminal_input(self):
        r = self.run_install(missing_curl=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.target.read_bytes(), self.payload.read_bytes())
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.launcher.resolve(), self.target)
        self.assertIn('LAUNCHED:--install', r.stdout)
        self.assertIn('ANSWER:interactive-key', r.stdout)
        calls = self.calls.read_text().splitlines()
        self.assertEqual(calls[:2], ['apt-get:update', 'apt-get:install -y --no-remove curl ca-certificates'])

    def test_download_checksum_syntax_or_apt_failure_does_not_replace_old_manager(self):
        self.target.write_text('old version\n')
        for flags in ({'FAIL_DOWNLOAD':'1'}, {'CORRUPT_DOWNLOAD':'1'}, {'FAIL_APT':'1'}):
            r = self.run_install(missing_curl=True, **flags)
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(self.target.read_text(), 'old version\n')
            self.assertFalse(self.launcher.exists())
        self.payload.write_text('if\n')
        self.source = self.source.replace(self.digest, hashlib.sha256(self.payload.read_bytes()).hexdigest())
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertEqual(self.target.read_text(), 'old version\n')

    def test_update_backs_up_old_file_and_menu_does_not_start_installation(self):
        self.target.write_text('old manager\n')
        self.launcher.symlink_to(self.target)
        r = self.run_install('--menu')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('LAUNCHED:\n', r.stdout)
        backups = list((self.root / 'root').glob('backup.*/vps-setup'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), 'old manager\n')

    def test_unknown_launcher_symlink_target_and_bad_arguments_stop(self):
        self.launcher.write_text('local tool')
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertFalse(self.target.exists())
        self.launcher.unlink()
        other = self.root / 'other'; other.write_text('untouched')
        self.target.symlink_to(other)
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertEqual(other.read_text(), 'untouched')
        self.assertEqual(self.run_install('--unknown').returncode, 2)
