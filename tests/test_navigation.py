"""Exercise menu input against inert component stubs; never run host installers."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'vps-setup.sh').read_text()
NAV = SOURCE.split('# НАВИГАЦИЯ VPS MANAGER\n', 1)[1]
NAV = NAV.split('# Инициализация лога выполняется только при запуске программы.', 1)[0]
# Include no top-level script code, downloads, or privileged operations.
CALLBACKS = set(re.findall(r'\|(?:action|page)\|([^|\n]+)\|', NAV))
CALLBACKS.update(re.findall(r'callback=([a-z0-9_]+)', NAV))
CALLBACKS.update(('prepare_ru_node', 'prepare_ru_docker'))
EXTERNAL = sorted(name for name in CALLBACKS if not name.startswith('vps_'))


class NavigationTests(unittest.TestCase):
    def run_menu(self, entry='vps_main_menu', answers='', fail=None):
        with tempfile.TemporaryDirectory() as directory:
            calls = Path(directory) / 'calls'
            stubs = ['print_header() { :; }']
            for name in EXTERNAL:
                code = 17 if name == fail else 0
                stubs.append(f'{name}() {{ printf "%s\\n" "{name}:$*" >> "$CALLS"; return {code}; }}')
            result = subprocess.run(
                ['bash', '-c', '\n'.join(stubs) + '\n' + NAV + '\n' + entry],
                input=answers, text=True, capture_output=True, timeout=5,
                env=dict(os.environ, CALLS=str(calls)),
            )
            events = calls.read_text().splitlines() if calls.exists() else []
            return result, events

    def test_open_every_top_level_section_and_back_without_actions(self):
        for key in ('1', '2', '3', '4', '5', '6', '9'):
            with self.subTest(key=key):
                result, calls = self.run_menu(answers=f'{key}\n0\n0\n')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [])
                self.assertGreaterEqual(result.stdout.count('VPS / Главное меню'), 2)

    def test_eof_at_every_menu_is_clean_and_has_no_action(self):
        entries = re.findall(r'^(vps_\w+_menu)\(\)', NAV, re.M)
        for entry in entries:
            result, calls = self.run_menu(entry)
            self.assertEqual(result.returncode, 0, entry + result.stderr)
            self.assertEqual(calls, [], entry)

    def test_install_preview_cancel_invalid_or_eof_never_calls_backend(self):
        components = re.findall(r'^        ([a-z]+)\) title=', NAV, re.M)
        self.assertGreater(len(components), 10)
        for component in components:
            for answer in ('', '0\n', 'yes\n'):
                result, calls = self.run_menu('vps_install_entry ' + component, answer)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [], component)

    def test_explicit_selection_runs_only_selected_installer(self):
        # Main -> installation -> NextDNS -> preview continue -> pause -> back -> exit.
        result, calls = self.run_menu(answers='1\n2\n1\n\n0\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ['setup_nextdns:'])
        self.assertIn('Применение изменит системный DNS', result.stdout)

    def test_base_ssh_does_not_install_full_stack(self):
        result, calls = self.run_menu(answers='1\n1\n2\n1\n\n0\n0\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ['do_ssh_setup:'])

    def test_diagnostics_routes_only_selected_reader(self):
        expected = ('show_system_status', 'antiabuse_center_status', 'show_security_log', 'show_script_log')
        for key, callback in enumerate(expected, 1):
            result, calls = self.run_menu('vps_diagnostics_menu', f'{key}\n\n0\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls, [callback + ':'])

    def test_guard_check_and_apply_are_distinct_actions(self):
        for key, action in ((1, 'check'), (2, 'apply')):
            result, calls = self.run_menu('vps_updates_menu', f'{key}\n\n0\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls, ['guard_engine_menu_action:' + action])

    def test_old_shortcuts_and_shell_input_cannot_dispatch(self):
        for answer in ('00', 'W', '16', '18', '$(do_ufw_setup)', 'do_ufw_setup', '1;do_ufw_setup'):
            result, calls = self.run_menu(answers=answer + '\n\n0\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls, [])
            self.assertIn('Такого пункта нет', result.stdout)

    def test_failed_action_stays_in_section_and_reports_failure(self):
        result, calls = self.run_menu('vps_updates_menu', '1\n\n0\n', fail='guard_engine_menu_action')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ['guard_engine_menu_action:check'])
        self.assertIn('кодом 17', result.stdout)
        self.assertEqual(result.stdout.count('VPS / Обновления'), 2)

    def test_all_menu_callbacks_exist(self):
        for name in CALLBACKS:
            self.assertTrue(re.search(rf'(?m)^{re.escape(name)}\(\)', SOURCE), name)

    def test_ru_preparation_requires_its_own_confirmation(self):
        for answer in ('', 'yes\n', '0\n'):
            result, calls = self.run_menu('vps_prepare_ru_entry', answer)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls, [])
        result, calls = self.run_menu('vps_prepare_ru_entry', 'PREPARE-RU\n')
        self.assertEqual(calls, ['prepare_ru_node:', 'prepare_ru_docker:'])
