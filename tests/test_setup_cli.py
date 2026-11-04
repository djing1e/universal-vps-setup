"""Direct installation routes through the same batch and propagates its result."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'vps-setup.sh').read_text()
FOOTER = SOURCE.split('# Инициализация лога выполняется только при запуске программы.', 1)[1]


class CLITests(unittest.TestCase):
    def run_cli(self, args=(), code=0):
        with tempfile.TemporaryDirectory() as directory:
            prefix = 'log() { :; }\nvps_main_menu() { echo MENU; }\n'
            prefix += f'setup_one_button() {{ echo INSTALL; return {code}; }}\n'
            prefix += f'LOG_FILE="{directory}/logs/setup.log"\n'
            return subprocess.run(['bash', '-c', prefix + FOOTER, 'vps-setup', *args],
                                  text=True, capture_output=True, timeout=5)

    def test_install_skips_menu_and_preserves_failure_status(self):
        for code in (0, 1):
            result = self.run_cli(['--install'], code)
            self.assertEqual(result.returncode, code, result.stderr)
            self.assertIn('INSTALL', result.stdout)
            self.assertNotIn('MENU', result.stdout)

    def test_default_opens_menu_only(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('MENU', result.stdout)
        self.assertNotIn('INSTALL', result.stdout)

    def test_help_and_invalid_arguments_do_not_run_any_setup(self):
        for args, code in ((['--help'], 0), (['--unknown'], 2), (['--install', 'extra'], 2)):
            result = self.run_cli(args)
            self.assertEqual(result.returncode, code, result.stderr)
            self.assertNotIn('MENU', result.stdout)
            self.assertNotIn('INSTALL', result.stdout)
