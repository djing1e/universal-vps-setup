#!/usr/bin/env python3
"""Offline smoke tests for Auto Abuse Guard observe release."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "modules" / "xtls-auto-abuse-guard.py"
spec = importlib.util.spec_from_file_location("xtls_guard", MODULE)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def event(start, end, user="TEST-18113", reason="ssh_90s_burst"):
    return [{"user": user, "reasons": [reason],
             "evidence": {reason: {"start_epoch": start, "end_epoch": end}},
             "windows_seconds": {}, "action": "observe"}]


class ObserveHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.prev_state = guard.STATE
        self.addCleanup(setattr, guard, "STATE", self.prev_state)
        guard.STATE = Path(self.tmp.name)
        self.start = 1793271610

    def history(self):
        return json.loads((guard.STATE / "behavior-incidents.json").read_text())

    def test_repeat_is_not_new_incident(self):
        start = self.start
        for t in (start+90, start+150, start+210):
            guard.record_behavior_incidents(event(start, start+81), t)
        rows = self.history()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["observations"], 1)
        self.assertTrue(rows[0]["incident_id"])

    def test_independent_event_after_hour(self):
        start = self.start
        guard.record_behavior_incidents(event(start, start+81), start+90)
        guard.record_behavior_incidents(event(start+3600, start+3681), start+3700)
        self.assertEqual(len(self.history()), 2)

    def test_legacy_not_overwritten(self):
        start = self.start
        legacy = [{"user": "TEST-18113", "reason": "ssh_90s_burst",
                   "first_seen_epoch": start+100, "last_seen_epoch": start+200,
                   "observations": 3, "status": "SUSPICIOUS", "action": "observe"}]
        (guard.STATE / "behavior-incidents.json").write_text(json.dumps(legacy))
        guard.record_behavior_incidents(event(start, start+81), start+300)
        self.assertEqual(self.history(), legacy)

    def test_corrupt_store_preserved(self):
        p = guard.STATE / "behavior-incidents.json"
        p.write_text("{corrupted")
        guard.record_behavior_incidents(event(self.start, self.start+81), self.start+90)
        self.assertEqual(p.read_text(), "{corrupted")


if __name__ == "__main__":
    unittest.main()
