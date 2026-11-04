"""Real ssh-keygen validation against disposable authorized_keys, never host SSH."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'vps-setup.sh').read_text()
HELPER = 'vps_ssh_public_key() {' + SOURCE.split('vps_ssh_public_key() {', 1)[1].split('\ndo_ssh_setup() {', 1)[0]


class PublicKeyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.authorized = self.root / '.ssh' / 'authorized_keys'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.root / 'key')], check=True)
        self.key = (self.root / 'key.pub').read_text().strip()

    def enter(self, answers):
        return subprocess.run(['bash', '-c', HELPER + '\nvps_ssh_public_key "$1"', 'test', str(self.authorized)],
                              input=answers, text=True, capture_output=True, timeout=5)

    def test_new_valid_key_has_private_permissions_and_is_idempotent(self):
        self.assertEqual(self.enter(self.key + '\n').returncode, 0)
        original = self.authorized.read_bytes()
        self.assertEqual(self.authorized.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.authorized.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.enter(self.key + '\n').returncode, 0)
        self.assertEqual(self.authorized.read_bytes(), original)

    def test_empty_cancel_invalid_and_private_key_do_not_create_access(self):
        for answer in ('', '\n', '0\n', 'ssh-ed25519 invalid\n', '-----BEGIN OPENSSH PRIVATE KEY-----\n'):
            with self.subTest(answer=answer):
                self.assertNotEqual(self.enter(answer).returncode, 0)
                self.assertFalse(self.authorized.exists())

    def test_blank_requires_existing_valid_key_and_preserves_options(self):
        self.authorized.parent.mkdir()
        data = 'from="192.0.2.1" ' + self.key + '\n'
        self.authorized.write_text(data)
        self.assertEqual(self.enter('\n').returncode, 0)
        self.assertEqual(self.authorized.read_text(), data)
        self.authorized.write_text('broken key\n')
        self.assertNotEqual(self.enter('\n').returncode, 0)
        self.assertEqual(self.authorized.read_text(), 'broken key\n')

    def test_invalid_then_valid_and_missing_newline_preserve_old_keys(self):
        self.authorized.parent.mkdir()
        old = '# existing notes, missing newline'
        self.authorized.write_text(old)
        self.assertEqual(self.enter('ssh-rsa broken\n' + self.key + '\n').returncode, 0)
        self.assertEqual(self.authorized.read_text(), old + '\n' + self.key + '\n')

    def test_runtime_input_is_literal_and_no_personal_key_is_bundled(self):
        key = self.key.split()[0:2]
        attack = self.root / 'unexpected'
        literal = ' '.join(key) + ' $(touch ' + str(attack) + ')'
        self.assertEqual(self.enter(literal + '\n').returncode, 0)
        self.assertFalse(attack.exists())
        self.assertIn(literal, self.authorized.read_text())
        self.assertNotIn('SSH_KEY=', SOURCE)
        self.assertNotIn('rsa-key-20250213', SOURCE)

    def test_cancel_or_eof_prevents_ssh_config_changes_and_service_calls(self):
        # Real setup function, isolated paths and service/validator commands.
        config = self.root / 'sshd_config'
        config.write_text('Port 22\nPasswordAuthentication yes\n')
        body = 'do_ssh_setup() {' + SOURCE.split('do_ssh_setup() {', 1)[1].split('\ndo_ufw_setup() {', 1)[0]
        body = body.replace('/root/.ssh', str(self.authorized.parent)).replace('/etc/ssh/sshd_config', str(config))
        calls = self.root / 'service_calls'
        inert = f'log_section() {{ :; }}\nlog() {{ :; }}\nsystemctl() {{ touch "{calls}"; return 90; }}\n'
        for answer in ('', '\n0\n', '\nssh-ed25519 invalid\n'):
            result = subprocess.run(['bash', '-c', inert + HELPER + body + '\nDEFAULT_SSH_PORT=62152\ndo_ssh_setup'],
                                    input=answer, text=True, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(config.read_text(), 'Port 22\nPasswordAuthentication yes\n')
            self.assertFalse(calls.exists())
