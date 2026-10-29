#!/usr/bin/env python3
"""Auto Abuse Guard: bounded, local, fail-open observation (no bans)."""
import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

STATE = Path("/var/lib/xtls-auto-abuse-guard")
ACCESS = Path("/var/log/remnanode/access.log")
MAX_EVENTS = 100
MAX_ACCESS_BYTES = 2 * 1024 * 1024
WINDOW_SEC = 3
EVENT_RE = re.compile(r"\bSRC=(\S+).*?\bDST=(\S+).*?\bPROTO=(TCP|UDP)\b.*?\bSPT=(\d+)\b.*?\bDPT=(\d+)\b")
ACCESS_RE = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)\.\d+ .*? accepted (tcp|udp):(\S+) \[([^]]+)\] email: (\S+)")

def read_recent_access():
    if not ACCESS.is_file():
        return []
    with ACCESS.open("rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - MAX_ACCESS_BYTES))
        if size > MAX_ACCESS_BYTES:
            f.readline()
        raw = f.read(MAX_ACCESS_BYTES)
    records = []
    for line in raw.decode("utf-8", "replace").splitlines():
        m = ACCESS_RE.search(line)
        if not m:
            continue
        dest = m.group(3).rsplit(":", 1)
        if len(dest) != 2:
            continue
        try:
            stamp = dt.datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S").replace(tzinfo=dt.timezone.utc).timestamp()
        except ValueError:
            continue
        records.append((stamp, m.group(2), dest[0].strip("[]"), dest[1], m.group(5), m.group(4)))
    return records

def get_events(cursor):
    cmd = ["journalctl", "-k", "--no-pager", "-o", "json", "--grep", "XTLS-SH[46] ", "-n", "+" + str(MAX_EVENTS)]
    if cursor:
        cmd += ["--after-cursor", cursor]
    else:
        cmd += ["--since", "3 minutes ago"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=8, check=False)
    # journalctl --grep returns status 1 when no records match; this is normal.
    if result.returncode == 1 and not result.stdout.strip() and result.stderr.strip() in ("", "-- No entries --"):
        return []
    if result.returncode != 0:
        msg = result.stderr.strip()[:200]
        if cursor and ("Failed to seek to journal cursor" in msg or "Invalid cursor" in msg):
            raise LookupError("stale journal cursor: " + msg)
        raise RuntimeError(msg or f"journalctl exit={result.returncode}")
    events = []
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
            message = item.get("MESSAGE", "")
            if not ("XTLS-SH4 " in message or "XTLS-SH6 " in message):
                continue
            m = EVENT_RE.search(message)
            if not m:
                continue
            stamp = int(item["__REALTIME_TIMESTAMP"]) / 1_000_000
            events.append((item.get("__CURSOR"), stamp, m.group(2), m.group(3).lower(), m.group(5), m.group(1), m.group(4)))
        except (ValueError, KeyError, TypeError):
            continue
    return events

def scan():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE / "lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("Already running; skip")
            return
        statefile = STATE / "cursor"
        cursor = statefile.read_text().strip() if statefile.exists() else ""
        try:
            events = get_events(cursor)
        except LookupError as exc:
            # Explicit discontinuity: no user action or fabricated attribution.
            warning = {"time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                       "event": "journal_cursor_lost", "action": "observe",
                       "detail": str(exc)[:160]}
            with (STATE / "health.jsonl").open("a") as f:
                f.write(json.dumps(warning) + "\n")
            temporary = STATE / "cursor.tmp"
            temporary.write_text("")
            temporary.replace(statefile)
            print("WARNING: journal cursor lost; discontinuity recorded; next scan starts recent window")
            return
        if not events:
            print("No new Spamhaus OUTPUT events")
            return
        if len(events) >= MAX_EVENTS:
            print("INFO: journal batch full; next scan resumes from saved cursor (no newest-only skipping)")
        records = read_recent_access()
        out = []
        seen_flows = set()
        for ecursor, stamp, dst, proto, port, src, sport in events:
            flow = (src, sport, dst, port, proto, int(stamp // 60))
            if flow in seen_flows:
                continue
            seen_flows.add(flow)
            matches = {(user, route) for t, p, addr, dport, user, route in records
                       if abs(t - stamp) <= WINDOW_SEC and p == proto and addr == dst and dport == port}
            record = {"time_utc": dt.datetime.fromtimestamp(stamp, dt.timezone.utc).isoformat(),
                      "destination": dst, "port": int(port), "protocol": proto,
                      "matched_users": sorted(u for u, _ in matches),
                      "status": "matched" if len(matches) == 1 else ("ambiguous" if matches else "unmatched"),
                      "action": "observe"}
            out.append(record)
        # State is written atomically; no remote calls or firewall actions.
        with (STATE / "detections.jsonl").open("a") as f:
            for row in out:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        # Keep detection log below 1 MiB without loading full history.
        history = STATE / "detections.jsonl"
        if history.stat().st_size > 1024 * 1024:
            with history.open("rb") as f:
                f.seek(-512 * 1024, os.SEEK_END)
                f.readline()
                rest = f.read()
            temporary = STATE / "detections.tmp"
            temporary.write_bytes(rest)
            temporary.replace(history)
        lastcursor = next((e[0] for e in reversed(events) if e[0]), None)
        if lastcursor:
            temporary = STATE / "cursor.tmp"
            temporary.write_text(lastcursor + "\n")
            temporary.replace(statefile)
        print(f"Observed {len(events)} logged packets; {len(out)} distinct flows (within minute buckets); unique user matches: {sum(x['status']=='matched' for x in out)}; bans: 0")

def report():
    file = STATE / "detections.jsonl"
    if not file.exists():
        print("No recorded events")
        return
    with file.open("rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - 100 * 1024))
        if size > 100 * 1024:
            f.readline()
        for line in f.read().decode("utf-8", "replace").splitlines()[-25:]:
            print(line)

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["scan", "report"])
    args = p.parse_args()
    if args.action == "scan":
        scan()
    else:
        report()
