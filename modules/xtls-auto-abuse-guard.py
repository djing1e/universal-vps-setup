#!/usr/bin/env python3
"""Auto Abuse Guard: bounded, local, fail-open observation (no bans)."""
import argparse
import datetime as dt
import fcntl
import hashlib
import ipaddress
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
FLOW_TTL_SEC = 600
MAX_FLOW_KEYS = 4096
EVENT_RE = re.compile(r"\bSRC=(\S+).*?\bDST=(\S+).*?\bPROTO=(TCP|UDP)\b.*?\bSPT=(\d+)\b.*?\bDPT=(\d+)\b")
ACCESS_RE = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)\.\d+ .*? accepted (tcp|udp):(\S+) \[([^]]+)\] email: (\S+)")

def canonical_address(value):
    """Normalize numeric addresses locally; never resolve access-log domains."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value

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
        records = [(t, p, canonical_address(addr), port, user, route)
                   for t, p, addr, port, user, route in read_recent_access()]
        out = []
        flows_path = STATE / "flows.json"
        try:
            previous = json.loads(flows_path.read_text()) if flows_path.exists() else {}
            if not isinstance(previous, dict):
                raise ValueError("invalid flow state")
            previous = {str(k): float(v) for k, v in previous.items()}
        except (OSError, ValueError, TypeError):
            previous = {}
            print("WARNING: dedup state unreadable; continuity not guaranteed")
        newest = max(e[1] for e in events)
        previous = {k: v for k, v in previous.items()
                    if newest - FLOW_TTL_SEC <= v <= newest + 60}
        for ecursor, stamp, dst, proto, port, src, sport in events:
            dst = canonical_address(dst)
            src = canonical_address(src)
            # The source port belongs to the server's outbound socket, not VPN client.
            flow = hashlib.sha256(
                json.dumps([src, sport, dst, port, proto], separators=(",", ":")).encode()
            ).hexdigest()[:24]
            if flow in previous and abs(stamp - previous[flow]) <= FLOW_TTL_SEC:
                previous[flow] = max(previous[flow], stamp)
                continue
            previous[flow] = stamp
            matches = {(user, route) for t, p, addr, dport, user, route in records
                       if abs(t - stamp) <= WINDOW_SEC and p == proto and addr == dst and dport == port}
            users = sorted({user for user, route in matches})
            record = {"time_utc": dt.datetime.fromtimestamp(stamp, dt.timezone.utc).isoformat(),
                      "destination": dst, "port": int(port), "protocol": proto,
                      "matched_users": users,
                      "status": "matched" if len(users) == 1 else ("ambiguous" if users else "unmatched"),
                      "action": "observe"}
            out.append(record)
        if len(previous) > MAX_FLOW_KEYS:
            previous = dict(sorted(previous.items(), key=lambda kv: kv[1], reverse=True)[:MAX_FLOW_KEYS])
            print("WARNING: dedup capacity reached; oldest keys evicted")
        temporary_flows = STATE / "flows.tmp"
        temporary_flows.write_text(json.dumps(previous, separators=(",", ":")))
        temporary_flows.replace(flows_path)
        # Observe only; no remote calls or firewall actions.
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
        print(f"Observed {len(events)} logged packets; {len(out)} distinct flows (10-minute dedup window); unique user matches: {sum(x['status']=='matched' for x in out)}; bans: 0")


def record_behavior_incidents(results, now):
    """Persist bounded, deduplicated signals; never modify subscribers or firewall."""
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    file = STATE / "behavior-incidents.json"
    lockfile = STATE / "behavior.lock"
    with lockfile.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            data = json.loads(file.read_text()) if file.exists() else []
            if not isinstance(data, list):
                raise ValueError("invalid incident store")
            if any(not isinstance(item, dict) for item in data):
                raise ValueError("invalid incident item")
        except (OSError, ValueError, TypeError) as exc:
            # Preserve corrupted state for investigation; fail open, never ban.
            print("WARNING: incident state unreadable; not overwriting: " + str(exc)[:100], file=sys.stderr)
            return
        retention = 7 * 86400
        data = [item for item in data if isinstance(item.get("last_seen_epoch"), (float, int))
                and 0 <= now - item["last_seen_epoch"] <= retention]
        for result in results:
            user = result["user"]
            for reason in result["reasons"]:
                evidence = result.get("evidence", {}).get(reason)
                if not evidence:
                    # Do not synthesize incident timestamps from scan time.
                    continue
                start = evidence["start_epoch"]
                end = evidence["end_epoch"]
                if not (isinstance(start, (int, float)) and
                        isinstance(end, (int, float)) and start <= end <= now + 60):
                    continue
                # Stable for unchanged evidence. Do not use timer/scan timestamp.
                key = json.dumps([user, reason, start, end], separators=(",", ":"))
                incident_id = hashlib.sha256(key.encode()).hexdigest()[:24]
                if any(item.get("incident_id") == incident_id for item in data):
                    continue
                # Backward compatibility: preserve legacy records untouched,
                # avoid adding duplicate evidence for the same old episode.
                # Old timestamps were scan times, so allow a 30m correlation.
                legacy = any(
                    item.get("incident_id") is None
                    and item.get("user") == user and item.get("reason") == reason
                    and isinstance(item.get("first_seen_epoch"), (int, float))
                    and isinstance(item.get("last_seen_epoch"), (int, float))
                    and item["first_seen_epoch"] <= end + 1800
                    and item["last_seen_epoch"] >= start - 1800
                    for item in data)
                if legacy:
                    continue
                # If the same episode grows slightly, coalesce overlapping
                # evidence without refreshing observations.
                same_episode = next((item for item in data
                    if item.get("incident_id") is not None
                    and item.get("user") == user and item.get("reason") == reason
                    and isinstance(item.get("evidence_start_epoch"), (int, float))
                    and isinstance(item.get("evidence_end_epoch"), (int, float))
                    and start <= item["evidence_end_epoch"] + 90
                    and end >= item["evidence_start_epoch"] - 90), None)
                if same_episode:
                    continue
                data.append({"incident_id": incident_id, "user": user,
                             "reason": reason, "evidence_start_epoch": start,
                             "evidence_end_epoch": end, "first_seen_epoch": end,
                             "last_seen_epoch": end, "observations": 1,
                             "status": "SUSPICIOUS", "action": "observe"})
        # Bounded history, fixed size; most recently updated incidents first.
        data = sorted(data, key=lambda item: item["last_seen_epoch"])[-1000:]
        import tempfile
        fd, tmp = tempfile.mkstemp(prefix=".behavior-", dir=str(STATE))
        try:
            with os.fdopen(fd, "w") as out:
                os.fchmod(out.fileno(), 0o600)
                json.dump(data, out, separators=(",", ":"))
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, file)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


def behavior_history():
    file = STATE / "behavior-incidents.json"
    if not file.exists():
        print("[]")
        return
    with file.open() as f:
        data = json.load(f)
    print(json.dumps(data[-100:], ensure_ascii=False))


def behavior(record=False):
    """Bounded subscription-level heuristics from Xray access logs; observation only."""
    from collections import defaultdict
    import ipaddress

    now = dt.datetime.now(dt.timezone.utc).timestamp()
    windows = (300, 1800)
    activity = defaultdict(lambda: {w: [] for w in windows})
    invalid = 0
    domains = 0
    nonglobal = 0
    all_records = read_recent_access()
    earliest = min((r[0] for r in all_records), default=None)
    latest = max((r[0] for r in all_records), default=None)
    domain_activity = defaultdict(lambda: {w: [] for w in windows})
    ssh_timeline = defaultdict(list)
    nonweb_timeline = defaultdict(list)
    for stamp, proto, dest, port, user, route in all_records:
        age = now - stamp
        if age < -60 or age > max(windows):
            continue
        host = dest.strip("[]")
        try:
            parsed_port = int(port)
        except ValueError:
            invalid += 1
            continue
        if not 1 <= parsed_port <= 65535:
            invalid += 1
            continue
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            # Xray can record a domain instead of a resolved IP.
            # Do not count hostnames as unique scan targets.
            if re.fullmatch(r"(?=.{1,253}$)[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*\.?", host):
                domains += 1
                for window in windows:
                    if age <= window:
                        domain_activity[user][window].append((proto, host.lower(), parsed_port))
            else:
                invalid += 1
            continue
        if not ip.is_global:
            nonglobal += 1
            continue
        if proto == "tcp" and parsed_port == 22:
            ssh_timeline[user].append((stamp, host))
        if parsed_port not in (80, 443, 853):
            nonweb_timeline[user].append((stamp, proto, host, parsed_port))
        for window in windows:
            if age <= window:
                activity[user][window].append((proto, host, parsed_port))

    results = []
    for user in sorted(set(activity) | set(domain_activity)):
        per_window = activity[user]
        measures = {}
        suspicious = False
        reasons = []
        evidence = {}
        for window in windows:
            events = per_window[window]
            domain_events = domain_activity[user][window]
            destinations = {(proto, host, port) for proto, host, port in events}
            nonweb = [(proto, host, port) for proto, host, port in events
                      if port not in (80, 443, 853)]
            nonweb_ips = {host for _, host, _ in nonweb}
            nonweb_ports = {port for _, _, port in nonweb}
            ssh_ips = {host for proto, host, port in nonweb if proto == "tcp" and port == 22}
            measures[str(window)] = {
                "connections": len(events),
                "domain_connections": len(domain_events),
                "domain_unique_destinations": len(set(domain_events)),
                "unique_destinations": len(destinations),
                "nonweb_connections": len(nonweb),
                "nonweb_ips": len(nonweb_ips),
                "nonweb_ports": len(nonweb_ports),
                "ssh_ips": len(ssh_ips),
            }
            # Conservative indicators; these are signals for human review, never proof.
            if window == 300 and len(nonweb) >= 50 and len(nonweb_ips) >= 20 and len(nonweb_ports) >= 8:
                suspicious = True
                reasons.append("five_minute_nonweb_fanout")
                sample = [v for v in nonweb_timeline[user] if now - v[0] <= window]
                evidence["five_minute_nonweb_fanout"] = {"start_epoch": min(v[0] for v in sample), "end_epoch": max(v[0] for v in sample)}
            if window == 1800 and len(ssh_ips) >= 15 and len(nonweb) >= 30:
                suspicious = True
                reasons.append("ssh_multi_destination")
                sample = [v for v in ssh_timeline[user] if now - v[0] <= window]
                evidence["ssh_multi_destination"] = {"start_epoch": min(v[0] for v in sample), "end_epoch": max(v[0] for v in sample)}
            if window == 1800 and len(nonweb_ips) >= 75 and len(nonweb_ports) >= 12:
                suspicious = True
                reasons.append("thirty_minute_nonweb_fanout")
                sample = [v for v in nonweb_timeline[user] if now - v[0] <= window]
                evidence["thirty_minute_nonweb_fanout"] = {"start_epoch": min(v[0] for v in sample), "end_epoch": max(v[0] for v in sample)}
        # Sliding 90-second window anchored to event times, not the scan time.
        ssh_events = sorted(ssh_timeline[user])
        left = 0
        counts = {}
        peak = {"unique_ips": 0, "events": 0, "start_utc": None, "end_utc": None}
        for right, (stamp, host) in enumerate(ssh_events):
            counts[host] = counts.get(host, 0) + 1
            while stamp - ssh_events[left][0] > 90:
                old_host = ssh_events[left][1]
                counts[old_host] -= 1
                if not counts[old_host]:
                    del counts[old_host]
                left += 1
            if len(counts) > peak["unique_ips"]:
                peak = {
                    "unique_ips": len(counts),
                    "events": right - left + 1,
                    "start_utc": dt.datetime.fromtimestamp(ssh_events[left][0], dt.timezone.utc).isoformat(),
                    "end_utc": dt.datetime.fromtimestamp(stamp, dt.timezone.utc).isoformat(),
                }
        measures["ssh_90s_peak"] = peak
        if peak["unique_ips"] >= 12:
            suspicious = True
            reasons.append("ssh_90s_burst")
            evidence["ssh_90s_burst"] = {"start_epoch": dt.datetime.fromisoformat(peak["start_utc"]).timestamp(), "end_epoch": dt.datetime.fromisoformat(peak["end_utc"]).timestamp()}
        if suspicious:
            results.append({
                "user": user,
                "status": "SUSPICIOUS",
                "reasons": reasons,
                "evidence": evidence,
                "windows_seconds": measures,
                "action": "observe",
            })
    if record:
        record_behavior_incidents(results, now)
    print(json.dumps({
        "time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": str(ACCESS),
        "max_access_bytes": MAX_ACCESS_BYTES,
        "window_seconds": list(windows),
        "subscriptions_seen": len(set(activity) | set(domain_activity)),
        "access_log_first_utc": dt.datetime.fromtimestamp(earliest, dt.timezone.utc).isoformat() if earliest is not None else None,
        "access_log_last_utc": dt.datetime.fromtimestamp(latest, dt.timezone.utc).isoformat() if latest is not None else None,
        "access_log_span_seconds": round(latest - earliest) if earliest is not None and latest is not None else 0,
        "oldest_record_age_seconds": round(now - earliest) if earliest is not None else None,
        "full_30min_coverage": earliest is not None and earliest <= now - 1800 and latest >= now - 60,
        "domain_destinations_excluded_from_ip_heuristics": domains,
        "non_global_ip_destinations_excluded": nonglobal,
        "suspected": results,
        "skipped_invalid_destinations": invalid,
        "attribution": "access_log_email",
        "action": "observe",
        "note": "No bans. Only bounded log tail is analyzed; incomplete evidence is possible.",
    }, ensure_ascii=False, separators=(",", ":")))

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
    p.add_argument("action", choices=["scan", "report", "behavior", "behavior-record", "behavior-history"])
    args = p.parse_args()
    if args.action == "scan":
        scan()
    elif args.action == "behavior":
        behavior()
    elif args.action == "behavior-record":
        behavior(record=True)
    elif args.action == "behavior-history":
        behavior_history()
    else:
        report()
