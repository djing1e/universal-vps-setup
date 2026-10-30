"""Offline CLI regression tests. All system paths and commands are sandboxed."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
MODULE = (REPO / "modules/xtls-c2-feed.sh").read_text()
MARKER = "XTLS_C2_EMBEDDED_MODULE_END_2026"
EMBEDDED = (REPO / "vps-setup.sh").read_text().split(
    f"    cat <<'{MARKER}'\n", 1
)[1].split(f"{MARKER}\n", 1)[0]

# Stateful nft double: exercise real Bash/sed with nft's human-readable handles.
# Unknown commands fail, so broad flushes or service restarts cannot pass silently.
NFT = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
p = pathlib.Path(os.environ['C2_TEST_DIR'])
a = sys.argv[1:]
with (p / 'nft-calls').open('a') as f:
    f.write(json.dumps(a) + '\n')
s = json.loads((p / 'nft-state').read_text())
def save():
    (p / 'nft-state').write_text(json.dumps(s))
if (p / 'fail-list').exists() and 'list' in a:
    sys.exit(1)
if a == ['list', 'tables']:
    if s['table']: print('table ip xtls_c2_feed')
elif a in (['list', 'chain', 'ip', 'xtls_c2_feed', 'output'],
           ['-a', 'list', 'chain', 'ip', 'xtls_c2_feed', 'output']):
    if not s['chain']: sys.exit(1)
    print('table ip xtls_c2_feed {\n chain output { # handle 2')
    print('  type filter hook output priority -20; policy accept;')
    for h, comment in s['rules']:
        handle = f'# handle {h}' if not (p / 'bad-handle').exists() else ''
        expr = 'ip daddr . tcp dport @c2_pairs counter packets 0 bytes 0 drop' if comment == 'xtls-c2-block' else 'counter packets 1 bytes 60'
        print(f'  {expr} comment "{comment}" {handle}')
    print(' }\n}')
elif a == ['list', 'table', 'ip', 'xtls_c2_feed']:
    sys.exit(0 if s['table'] else 1)
elif a == ['list', 'set', 'ip', 'xtls_c2_feed', 'c2_pairs']:
    sys.exit(0 if s['set'] else 1)
elif a == ['add', 'table', 'ip', 'xtls_c2_feed']:
    s['table'] = True; save()
elif len(a) == 1 and a[0] == 'add set ip xtls_c2_feed c2_pairs { type ipv4_addr . inet_service; }':
    s['set'] = True; save()
elif len(a) == 1 and a[0] == 'add chain ip xtls_c2_feed output { type filter hook output priority -20; policy accept; }':
    s['chain'] = True; save()
elif a[:6] == ['delete', 'rule', 'ip', 'xtls_c2_feed', 'output', 'handle']:
    if (p / 'fail-delete').exists(): sys.exit(1)
    h = int(a[6])
    assert any(r[0] == h for r in s['rules'])
    s['rules'] = [r for r in s['rules'] if r[0] != h]; save()
elif a == ['add', 'rule', 'ip', 'xtls_c2_feed', 'output', 'ip', 'daddr', '.', 'tcp', 'dport', '@c2_pairs', 'counter', 'drop', 'comment', '"xtls-c2-block"']:
    s['next'] += 1
    s['rules'].append([s['next'], 'xtls-c2-block']); save()
elif len(a) in (2, 3) and a[:-1] in (['-f'], ['-c', '-f']):
    lines = pathlib.Path(a[-1]).read_text().splitlines()
    assert lines[0] == 'flush set ip xtls_c2_feed c2_pairs'
    assert all(line.startswith('add element ip xtls_c2_feed c2_pairs { ') for line in lines[1:])
    if a[0] != '-c': s['elements'] = lines[1:]; save()
else:
    raise AssertionError(f'Unexpected nft command: {a}')
'''

CURL = r'''#!/usr/bin/env python3
import os, pathlib, shutil, sys
p = pathlib.Path(os.environ['C2_TEST_DIR'])
if (p / 'fail-download').exists(): sys.exit(22)
shutil.copyfile(p / 'source.csv', sys.argv[sys.argv.index('-o') + 1])
'''

SYSTEMCTL = r'''#!/usr/bin/env python3
import os, pathlib, sys
p = pathlib.Path(os.environ['C2_TEST_DIR'])
a = sys.argv[1:]
assert a == ['daemon-reload'] or a == ['enable', 'xtls-c2-feed-restore.service', 'xtls-c2-feed-update.timer'] or a in (
    ['start', 'xtls-c2-feed-restore.service'], ['start', 'xtls-c2-feed-update.timer'],
    ['is-enabled', 'xtls-c2-feed-restore.service'], ['is-enabled', 'xtls-c2-feed-update.timer'])
with (p / 'systemctl-calls').open('a') as f: f.write(' '.join(a) + '\n')
if a[0] == 'is-enabled': print('enabled')
'''


class C2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.cache = self.root / 'etc/xtls-c2-feed'
        self.cache.mkdir(parents=True)
        (self.root / 'etc/systemd/system').mkdir(parents=True)
        (self.root / 'run').mkdir()
        (self.root / 'usr/local/sbin').mkdir(parents=True)
        self.env = dict(os.environ, C2_TEST_DIR=str(self.root),
                        PATH=f'{self.bin}:{os.environ["PATH"]}')
        for name, source in [('nft', NFT), ('curl', CURL), ('systemctl', SYSTEMCTL),
                             ('id', '#!/bin/sh\necho 0\n')]:
            p = self.bin / name
            p.write_text(source)
            p.chmod(0o755)
        self.script = self.root / 'module.sh'
        # No production test hooks or real /etc, /run, systemd, network access.
        source = MODULE
        for prefix in ['/etc/', '/run/', '/usr/local/']:
            source = source.replace(prefix, f'{self.root}{prefix}')
        self.script.write_text(source)
        (self.cache / 'mode').write_text('observe\n')
        (self.cache / 'validated.csv').write_text('8.8.8.8,443\n')
        (self.root / 'source.csv').write_text('1.1.1.1,8443\n')
        self.save_state(dict(table=True, chain=True, set=True, rules=[], next=2,
                             elements=['cached elements']))

    def save_state(self, state):
        (self.root / 'nft-state').write_text(json.dumps(state))

    def state(self):
        return json.loads((self.root / 'nft-state').read_text())

    def stale(self):
        state = self.state()
        state['rules'] = [[3, 'xtls-c2-block'], [4, 'unrelated'], [5, 'xtls-c2-block']]
        state['next'] = 5
        self.save_state(state)

    def run_cli(self, command, ok=True, answer='', script=None):
        result = subprocess.run(['bash', str(script or self.script), command],
                                env=self.env, input=answer, text=True,
                                capture_output=True, timeout=15)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn('disabled and persisted', result.stdout)
        return result

    def assert_observe(self):
        self.assertEqual((self.cache / 'mode').read_text(), 'observe\n')
        self.assertFalse(any(r[1] == 'xtls-c2-block' for r in self.state()['rules']))
        result = self.run_cli('status')
        self.assertIn('Saved mode: observe', result.stdout)
        self.assertIn('Live mode: observe', result.stdout)

    def test_embedded_module_matches(self):
        self.assertEqual(MODULE, EMBEDDED)

    def test_observe_block_observe_and_idempotence(self):
        self.run_cli('enable-block', answer='ENABLE-C2-BLOCK\n')
        self.run_cli('enable-block', answer='ENABLE-C2-BLOCK\n')
        self.assertEqual(len(self.state()['rules']), 1)
        result = self.run_cli('status')
        self.assertIn('Saved mode: block', result.stdout)
        self.assertIn('Live mode: block', result.stdout)
        before = self.state()
        cache = (self.cache / 'validated.csv').read_bytes()
        self.run_cli('disable-block')
        self.run_cli('disable-block')
        self.assert_observe()
        for key in ['table', 'chain', 'set', 'elements']:
            self.assertEqual(self.state()[key], before[key])
        self.assertEqual((self.cache / 'validated.csv').read_bytes(), cache)
        calls = (self.root / 'systemctl-calls').read_text().splitlines()
        self.assertTrue(all(call.startswith('is-enabled ') for call in calls))

    def test_delete_all_tagged_handles_preserve_unrelated(self):
        self.stale()
        self.run_cli('disable-block')
        self.assert_observe()
        self.assertEqual(self.state()['rules'], [[4, 'unrelated']])

    def test_disable_before_install(self):
        self.save_state(dict(table=False, chain=False, set=False, rules=[], next=0))
        self.run_cli('disable-block')
        self.assert_observe()
        self.assertFalse(self.state()['table'])

    def test_delete_failure_never_claims_success(self):
        self.stale()
        (self.root / 'fail-delete').touch()
        self.run_cli('disable-block', ok=False)
        self.assertEqual((self.cache / 'mode').read_text(), 'observe\n')
        (self.root / 'fail-delete').unlink()
        self.run_cli('disable-block')
        self.assert_observe()

    def test_inspection_failure_never_claims_success(self):
        self.stale()
        (self.root / 'fail-list').touch()
        self.run_cli('disable-block', ok=False)

    def test_missing_chain_in_existing_table_is_error(self):
        state = self.state()
        state['chain'] = False
        self.save_state(state)
        self.run_cli('disable-block', ok=False)

    def test_unparsed_handle_never_claims_success(self):
        self.stale()
        (self.root / 'bad-handle').touch()
        self.run_cli('disable-block', ok=False)

    def test_update_heals_observe_mismatch(self):
        self.stale()
        self.run_cli('update')
        self.assert_observe()
        self.assertEqual((self.cache / 'validated.csv').read_text(), '1.1.1.1,8443\n')
        self.assertIn('1.1.1.1 . 8443', self.state()['elements'][0])

    def test_failed_download_heals_observe_preserves_feed(self):
        self.stale()
        before = self.state()['elements']
        cache = (self.cache / 'validated.csv').read_bytes()
        (self.root / 'fail-download').touch()
        self.run_cli('update', ok=False)
        self.assert_observe()
        self.assertEqual(self.state()['elements'], before)
        self.assertEqual((self.cache / 'validated.csv').read_bytes(), cache)

    def test_invalid_feed_preserves_cache_and_set(self):
        before = self.state()['elements']
        cache = (self.cache / 'validated.csv').read_bytes()
        (self.root / 'source.csv').write_text('bad-ip,443\n')
        self.run_cli('update', ok=False)
        self.assert_observe()
        self.assertEqual(self.state()['elements'], before)
        self.assertEqual((self.cache / 'validated.csv').read_bytes(), cache)

    def test_update_block_preserved_without_duplicate(self):
        self.run_cli('enable-block', answer='ENABLE-C2-BLOCK\n')
        self.run_cli('update')
        self.assertEqual(len(self.state()['rules']), 1)
        self.assertEqual((self.cache / 'mode').read_text(), 'block\n')
        self.assertIn('Live mode: block', self.run_cli('status').stdout)

    def test_restore_heals_observe_even_without_cache(self):
        self.stale()
        (self.cache / 'validated.csv').unlink()
        self.run_cli('restore', ok=False)
        self.assert_observe()

    def test_restore_heals_observe_with_cache(self):
        self.stale()
        self.run_cli('restore')
        self.assert_observe()
        self.assertIn('8.8.8.8 . 443', self.state()['elements'][0])

    def test_install_units_and_simulated_boot_both_modes(self):
        self.run_cli('install')
        units = self.root / 'etc/systemd/system'
        snapshots = {p.name: p.read_bytes() for p in units.iterdir()}
        restore = (units / 'xtls-c2-feed-restore.service').read_text()
        executable, action = re.search(r'^ExecStart=(.*)$', restore, re.M).group(1).split()
        self.assertEqual(action, 'restore')
        timer = (units / 'xtls-c2-feed-update.timer').read_text()
        self.assertIn('OnUnitActiveSec=6h', timer)
        self.assertIn('Persistent=true', timer)
        calls = (self.root / 'systemctl-calls').read_text()
        for mode in ['observe', 'block', 'observe']:
            if mode == 'block':
                self.run_cli('enable-block', answer='ENABLE-C2-BLOCK\n')
            else:
                self.run_cli('disable-block')
            # Simulate kernel nft state loss at boot; execute generated ExecStart.
            self.save_state(dict(table=False, chain=False, set=False, rules=[], next=2))
            self.run_cli(action, script=executable)
            self.assertEqual((self.cache / 'mode').read_text().strip(), mode)
            self.assertEqual(bool(self.state()['rules']), mode == 'block')
            self.run_cli('restore', script=executable)
            self.assertEqual(len(self.state()['rules']), int(mode == 'block'))
        self.assertEqual({p.name: p.read_bytes() for p in units.iterdir()}, snapshots)
        self.assertEqual((self.root / 'systemctl-calls').read_text(), calls)


if __name__ == '__main__':
    unittest.main()
