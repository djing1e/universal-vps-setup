"""Exercise diagnostic migration with fake nft; real nft is covered separately."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'bin').mkdir()
        source = (ROOT/'modules/xtls-spamhaus-output.sh').read_text()
        source = source.replace('ROOT=/etc/xtls-spamhaus-output', 'ROOT='+str(self.root/'state'))
        source = source.replace('LOCK=/run/xtls-spamhaus-output.lock', 'LOCK='+str(self.root/'lock'))
        self.script = self.root/'module.sh'
        self.script.write_text(source)
        self.rules = self.root/'rules.json'
        self.initial = [
            {'handle': 4, 'comment': 'xtls-sh-out-v4', 'counter': 123},
            {'handle': 5, 'comment': 'xtls-sh-out-v6', 'counter': 456},
            {'handle': 6, 'comment': 'xtls-sh-diag-v4'},
            {'handle': 7, 'comment': 'xtls-sh-diag-v6'},
            {'handle': 8, 'comment': 'xtls-sh-diag-v4'},
            {'handle': 9, 'comment': 'local-xtls-sh-diag-v4-other'},
        ]
        self.rules.write_text(json.dumps(self.initial))
        nft = self.root/'bin/nft'
        nft.write_text('''#!/usr/bin/env python3
import json,os,pathlib,re,sys
a=sys.argv[1:]; p=pathlib.Path(os.environ['RULES']); rules=json.loads(p.read_text())
if '-j' in a:
    if os.environ.get('FAIL_READ'): sys.exit(1)
    print(json.dumps({'nftables':[{'rule':r} for r in rules]})); sys.exit(0)
if '-f' not in a:
    print('xtls-sh-out-v4 xtls-sh-out-v6'); sys.exit(0)
batch=pathlib.Path(a[-1]).read_text()
if '-c' in a:
    if os.environ.get('FAIL_CHECK'): sys.exit(1)
    if 'xtls-sh-diag-' in batch: assert batch.count('ct direction original')==2
    assert ' drop' not in batch and 'flush' not in batch
    sys.exit(0)
if os.environ.get('FAIL_APPLY'): sys.exit(1)
for line in batch.splitlines():
    if line.startswith('delete'):
        handle=int(line.split()[-1]); rules=[r for r in rules if r['handle']!=handle]
    else:
        marker=re.search(r'comment "([^"]+)"',line).group(1)
        rules.append({'handle':max(r['handle'] for r in rules)+1,'comment':marker,'rule':line})
p.write_text(json.dumps(rules))
''')
        nft.chmod(0o755)
        self.env = dict(os.environ, RULES=str(self.rules), PATH=str(self.root/'bin')+':'+os.environ['PATH'])

    def run_enable(self, **env):
        return subprocess.run(['bash', str(self.script), 'diagnostics-enable'],
                              env=self.env | env, capture_output=True, text=True)

    def test_legacy_duplicate_migration_and_repeat(self):
        for _ in range(2):
            r = self.run_enable()
            self.assertEqual(r.returncode, 0, r.stderr)
            rows = json.loads(self.rules.read_text())
            self.assertEqual(rows[:3], [self.initial[0], self.initial[1], self.initial[5]])
            for v in (4,6):
                own = [row for row in rows if row['comment']==f'xtls-sh-diag-v{v}']
                self.assertEqual(len(own), 1)
                self.assertIn('ct direction original', own[0]['rule'])
            self.assertEqual((self.root/'state/diagnostics-mode').read_text(), 'enabled\n')

    def test_failures_preserve_live_rules_and_saved_mode(self):
        for failure in ('FAIL_READ', 'FAIL_CHECK', 'FAIL_APPLY'):
            with self.subTest(failure=failure):
                r = self.run_enable(**{failure:'1'})
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(json.loads(self.rules.read_text()), self.initial)
                self.assertFalse((self.root/'state/diagnostics-mode').exists())

    def run_prepare(self, **env):
        source = self.script.read_text().split('case "${1:-}" in', 1)[0]
        return subprocess.run(['bash', '-c', source+'\nprepare'],
                              env=self.env | env, capture_output=True, text=True)

    def test_prepare_removes_counter_duplicates_keeps_oldest_and_foreign_rules(self):
        extra = [
            {'handle': 20, 'comment': 'xtls-sh-out-v4', 'counter': 99},
            {'handle': 21, 'comment': 'xtls-sh-out-v6', 'counter': 88},
            {'handle': 22, 'comment': 'xtls-sh-udp-drop-v4'},
            {'handle': 23, 'comment': 'local-xtls-sh-out-v4'},
        ]
        self.rules.write_text(json.dumps(self.initial+extra))
        expected = self.initial+extra[2:]
        for _ in range(2):
            r = self.run_prepare()
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(self.rules.read_text()), expected)

    def test_prepare_adds_only_missing_family_counter(self):
        rows = [r for r in self.initial if r['comment']!='xtls-sh-out-v6']
        self.rules.write_text(json.dumps(rows))
        r = self.run_prepare()
        self.assertEqual(r.returncode, 0, r.stderr)
        result = json.loads(self.rules.read_text())
        self.assertEqual(result[:-1], rows)
        self.assertEqual(result[-1]['comment'], 'xtls-sh-out-v6')

    def test_prepare_failure_preserves_existing_counters_and_drop(self):
        initial = self.initial + [{'handle': 20, 'comment': 'xtls-sh-out-v4'},
                                  {'handle': 21, 'comment': 'xtls-sh-udp-drop-v4'}]
        for failure in ('FAIL_READ', 'FAIL_CHECK', 'FAIL_APPLY'):
            self.rules.write_text(json.dumps(initial))
            r = self.run_prepare(**{failure:'1'})
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(json.loads(self.rules.read_text()), initial)

    def test_embedded_copy_matches_module(self):
        text = (ROOT/'vps-setup.sh').read_text()
        embedded = text.split("    cat <<'XTLS_SPAMHAUS_OUTPUT_MODULE_END'\n",1)[1].split('\nXTLS_SPAMHAUS_OUTPUT_MODULE_END',1)[0]
        self.assertEqual(embedded.strip(), (ROOT/'modules/xtls-spamhaus-output.sh').read_text().strip())


if __name__ == '__main__':
    unittest.main()
