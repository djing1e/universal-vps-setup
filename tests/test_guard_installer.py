"""Run the actual installer with private paths and fake systemd/download tools."""
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ('[Service]\nExecStart=\n'
          'ExecStart=/usr/bin/python3 /usr/local/sbin/xtls-auto-abuse-guard scan\n'
          'ExecStart=/usr/bin/python3 /usr/local/sbin/xtls-auto-abuse-guard behavior-record\n')


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for d in ('bin', 'sbin', 'units', 'backups', 'tmp'):
            (self.root / d).mkdir()
        self.dropins = self.root / 'units/xtls-auto-abuse-guard.service.d'
        self.dropins.mkdir()
        source = (ROOT / 'modules/xtls-auto-abuse-guard-install.sh').read_text()
        for old, new in [('/usr/local/sbin/', str(self.root / 'sbin') + '/'),
                         ('/etc/systemd/system/', str(self.root / 'units') + '/'),
                         ('/root/xtls-guard-backup.', str(self.root / 'backups/backup.')),
                         ('/run/xtls-auto-abuse-guard-install.lock', str(self.root / 'lock'))]:
            source = source.replace(old, new)
        self.script = self.root / 'installer.sh'
        self.script.write_text(source)
        self.tool('curl', '''#!/usr/bin/env python3
import os,sys,pathlib
if os.environ.get('FAIL_DOWNLOAD'): sys.exit(22)
pathlib.Path(sys.argv[-1]).write_text('# incident_id behavior-record\\n')
''')
        self.tool('systemd-analyze', '#!/bin/sh\n[ -z "$FAIL_VERIFY" ]\n')
        self.tool('systemctl', '''#!/usr/bin/env python3
import os,sys,pathlib
r=pathlib.Path(os.environ['TEST_ROOT']); a=sys.argv[1:]; c=a[0]
with (r/'calls').open('a') as f: f.write(' '.join(a)+'\\n')
if c in ('is-enabled','is-active'):
    sys.exit(0 if (r/('enabled' if c=='is-enabled' else 'active')).exists() else 1)
if c in ('enable','disable'):
    p=r/'enabled'
    if c=='enable': p.touch()
    else: p.unlink(missing_ok=True)
if c in ('start','stop') and a[-1].endswith('.timer') or c=='enable' and '--now' in a:
    p=r/'active'
    if c!='stop': p.touch()
    else: p.unlink(missing_ok=True)
if c=='start' and a[-1].endswith('.service') and os.environ.get('FAIL_START'): sys.exit(1)
''')
        self.env = dict(os.environ, TEST_ROOT=str(self.root), TMPDIR=str(self.root/'tmp'),
                        PATH=str(self.root/'bin')+':'+os.environ['PATH'])

    def tool(self, name, content):
        p = self.root / 'bin' / name
        p.write_text(content)
        p.chmod(0o755)

    def run_install(self, **env):
        return subprocess.run(['bash', str(self.script), 'install'], env=self.env | env,
                              text=True, capture_output=True)

    def seed(self):
        for p in [self.root/'sbin/xtls-auto-abuse-guard',
                  self.root/'units/xtls-auto-abuse-guard.service',
                  self.root/'units/xtls-auto-abuse-guard.timer']:
            p.write_text('old '+p.name)
        (self.root/'enabled').touch()
        (self.root/'active').touch()

    def test_fresh_and_reinstall(self):
        for _ in range(2):
            r = self.run_install()
            self.assertEqual(r.returncode, 0, r.stderr)
            service = (self.root/'units/xtls-auto-abuse-guard.service').read_text()
            self.assertEqual(service.count('ExecStart='), 2)
            self.assertTrue((self.root/'active').exists())
            self.assertFalse(list((self.root/'tmp').glob('tmp.*')))

    def test_exact_legacy_migrated_foreign_preserved(self):
        # The test installer rewrites paths, so its expected legacy uses test paths.
        legacy = LEGACY.replace('/usr/local/sbin/', str(self.root/'sbin')+'/')
        (self.dropins/'20-behavior.conf').write_text(legacy)
        custom = self.dropins/'90-local.conf'
        custom.write_text('[Service]\nMemoryMax=96M\n')
        r = self.run_install()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.dropins/'20-behavior.conf').exists())
        self.assertEqual(custom.read_text(), '[Service]\nMemoryMax=96M\n')
        self.assertTrue(list((self.root/'backups').glob('*/dropins/20-behavior.conf')))

    def test_unknown_override_refuses_without_changes(self):
        self.seed()
        (self.dropins/'20-behavior.conf').write_text('[Service]\nExecStart=/custom\n')
        r = self.run_install()
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.root/'calls').exists())
        self.assertEqual((self.root/'sbin/xtls-auto-abuse-guard').read_text(), 'old xtls-auto-abuse-guard')

    def test_symlink_override_refuses(self):
        (self.dropins/'90-local.conf').symlink_to('/nonexistent')
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertFalse((self.root/'calls').exists())

    def test_failed_download_does_not_mutate(self):
        self.seed()
        self.assertNotEqual(self.run_install(FAIL_DOWNLOAD='1').returncode, 0)
        self.assertFalse((self.root/'calls').exists())
        self.assertFalse(list((self.root/'tmp').glob('tmp.*')))

    def test_failed_verify_rolls_back_legacy_and_timer(self):
        self.seed()
        legacy = LEGACY.replace('/usr/local/sbin/', str(self.root/'sbin')+'/')
        (self.dropins/'20-behavior.conf').write_text(legacy)
        foreign = self.dropins/'90-local.conf'
        foreign.write_text('[Service]\nNice=12\n')
        r = self.run_install(FAIL_VERIFY='1')
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual((self.dropins/'20-behavior.conf').read_text(), legacy)
        self.assertEqual(foreign.read_text(), '[Service]\nNice=12\n')
        self.assertEqual((self.root/'sbin/xtls-auto-abuse-guard').read_text(), 'old xtls-auto-abuse-guard')
        self.assertTrue((self.root/'enabled').exists())
        self.assertTrue((self.root/'active').exists())

    def test_failed_first_scan_rolls_back_fresh_install(self):
        r = self.run_install(FAIL_START='1')
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.root/'sbin/xtls-auto-abuse-guard').exists())
        self.assertFalse((self.root/'enabled').exists())
        self.assertFalse((self.root/'active').exists())

    @unittest.skipUnless(shutil.which('systemd-analyze'), 'systemd-analyze unavailable')
    def test_real_systemd_unit_validation(self):
        (self.root/'bin/systemd-analyze').unlink()
        r = self.run_install()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_concurrent_install_refuses(self):
        import fcntl
        with (self.root/'lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            r = self.run_install()
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.root/'calls').exists())


if __name__ == '__main__':
    unittest.main()
