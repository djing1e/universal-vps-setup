"""Offline kernel/access-log correlation; no packets or live journal required."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('correlation_guard', ROOT / 'modules/xtls-auto-abuse-guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.addCleanup(patch.stopall)
        patch.object(guard, 'STATE', root / 'state').start()
        patch.object(guard, 'ACCESS', root / 'access.log').start()
        self.stamp = 1793337211

    def access(self, user='test-a', host='8.8.8.8', proto='tcp', port=443, offset=0):
        stamp = guard.dt.datetime.fromtimestamp(self.stamp + offset, guard.dt.timezone.utc)
        host = '['+host+']' if ':' in host else host
        with guard.ACCESS.open('a') as f:
            f.write(stamp.strftime('%Y/%m/%d %H:%M:%S') +
                    f'.123456 from 192.0.2.1:12345 accepted {proto}:{host}:{port} [in >> out] email: {user}\n')

    def run_scan(self, host='8.8.8.8', proto='tcp', port='443', offset=0):
        event = ('cursor-test', self.stamp+offset, host, proto, port, '192.0.2.2', '55555')
        with patch.object(guard, 'get_events', return_value=[event]), contextlib.redirect_stdout(io.StringIO()):
            guard.scan()
        p = guard.STATE / 'detections.jsonl'
        return [json.loads(line) for line in p.read_text().splitlines()]

    def test_single_user(self):
        self.access()
        rows = self.run_scan()
        self.assertEqual(rows[0]['status'], 'matched')
        self.assertEqual(rows[0]['matched_users'], ['test-a'])
        self.assertEqual(rows[0]['action'], 'observe')

    def test_two_users_are_ambiguous(self):
        self.access()
        self.access(user='test-b')
        row = self.run_scan()[0]
        self.assertEqual(row['status'], 'ambiguous')
        self.assertEqual(row['matched_users'], ['test-a', 'test-b'])

    def test_protocol_port_and_time_must_match(self):
        self.access(proto='udp')
        self.access(port=80)
        self.access(offset=4)
        self.assertEqual(self.run_scan()[0]['status'], 'unmatched')

    def test_repeated_flow_is_not_recorded_twice(self):
        self.access()
        self.run_scan()
        self.assertEqual(len(self.run_scan(offset=1)), 1)
        self.assertEqual((guard.STATE/'cursor').read_text().strip(), 'cursor-test')

    def test_equivalent_ipv6_spellings_match(self):
        self.access(host='2001:4860:4860::8888')
        row = self.run_scan(host='2001:4860:4860:0:0:0:0:8888')[0]
        self.assertEqual(row['status'], 'matched')

    def test_domain_is_not_guessed_as_resolved_ip(self):
        self.access(host='example.org')
        self.assertEqual(self.run_scan()[0]['status'], 'unmatched')

    def test_stale_cursor_records_discontinuity(self):
        guard.STATE.mkdir()
        (guard.STATE/'cursor').write_text('old-cursor')
        with patch.object(guard, 'get_events', side_effect=LookupError('stale')), contextlib.redirect_stdout(io.StringIO()):
            guard.scan()
        self.assertEqual((guard.STATE/'cursor').read_text(), '')
        row = json.loads((guard.STATE/'health.jsonl').read_text())
        self.assertEqual(row['event'], 'journal_cursor_lost')
        self.assertFalse((guard.STATE/'detections.jsonl').exists())


if __name__ == '__main__':
    unittest.main()
