#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT=/etc/xtls-spamhaus-output
TABLE=xtls_spamhaus_out
LOCK=/run/xtls-spamhaus-output.lock
URL4=https://www.spamhaus.org/drop/drop_v4.json
URL6=https://www.spamhaus.org/drop/drop_v6.json

prepare() {
  nft list table inet "$TABLE" >/dev/null 2>&1 || nft add table inet "$TABLE"
  nft list set inet "$TABLE" v4 >/dev/null 2>&1 || nft 'add set inet xtls_spamhaus_out v4 { type ipv4_addr; flags interval; auto-merge; }'
  nft list set inet "$TABLE" v6 >/dev/null 2>&1 || nft 'add set inet xtls_spamhaus_out v6 { type ipv6_addr; flags interval; auto-merge; }'
  nft list chain inet "$TABLE" output >/dev/null 2>&1 || nft 'add chain inet xtls_spamhaus_out output { type filter hook output priority -18; policy accept; }'
  nft list chain inet "$TABLE" output | grep -q 'xtls-sh-out-v4' || nft add rule inet "$TABLE" output ip daddr @v4 counter comment '"xtls-sh-out-v4"'
  nft list chain inet "$TABLE" output | grep -q 'xtls-sh-out-v6' || nft add rule inet "$TABLE" output ip6 daddr @v6 counter comment '"xtls-sh-out-v6"'
}
update() (
  install -d -m 700 "$ROOT"
  exec 9>"$LOCK"
  flock -x 9
  local d
  d=$(mktemp -d /tmp/xtls-spamhaus-out.XXXXXXXX)
  trap 'rm -rf "$d"' EXIT
  curl -fsSL --retry 2 --connect-timeout 10 --max-time 90 "$URL4" -o "$d/v4"
  curl -fsSL --retry 2 --connect-timeout 10 --max-time 90 "$URL6" -o "$d/v6"
  python3 - "$d" <<'PY'
import ipaddress,json,pathlib,sys
p=pathlib.Path(sys.argv[1])
for ver,minimum in [(4,100),(6,10)]:
    raw=(p/f'v{ver}').read_text().splitlines()
    nets=set()
    for line in raw:
        if not line.strip(): continue
        item=json.loads(line)
        if not isinstance(item,dict): raise ValueError("Unexpected Spamhaus entry")
        cidr=item.get("cidr")
        if cidr is None: continue
        n=ipaddress.ip_network(cidr,strict=False)
        if n.version!=ver: raise ValueError("IP family mismatch")
        if n.is_global: nets.add(str(n))
    if len(nets)<minimum or len(nets)>100000:
        raise ValueError(f"Suspicious Spamhaus IPv{ver} count: {len(nets)}")
    (p/f'cidr{ver}').write_text('\n'.join(sorted(nets))+'\n')
    print(f"Validated Spamhaus IPv{ver}: {len(nets)}")
with (p/'batch').open('w') as out:
    for ver in (4,6):
        out.write(f'flush set inet xtls_spamhaus_out v{ver}\n')
        nets=(p/f'cidr{ver}').read_text().splitlines()
        for i in range(0,len(nets),100):
            out.write(f'add element inet xtls_spamhaus_out v{ver} {{ '+', '.join(nets[i:i+100])+' }\n')
PY
  prepare
  nft -c -f "$d/batch"
  nft -f "$d/batch"
  install -m 600 "$d/cidr4" "$ROOT/cidr4"
  install -m 600 "$d/cidr6" "$ROOT/cidr6"
  printf '%s\n' "$(date -u '+%FT%TZ')" > "$ROOT/last-success"
  echo "Spamhaus OUTPUT observation updated (no DROP)"
)
install_module() {
  command -v nft >/dev/null || { echo 'nft is required' >&2; return 1; }
  command -v python3 >/dev/null || { echo 'python3 is required' >&2; return 1; }
  command -v curl >/dev/null || { echo 'curl is required' >&2; return 1; }
  install -d -m 700 "$ROOT" /usr/local/sbin
  install -m 700 "$0" /usr/local/sbin/xtls-spamhaus-output
  cat >/etc/systemd/system/xtls-spamhaus-output-restore.service <<'UNIT'
[Unit]
Description=Restore Spamhaus OUTPUT observation sets
After=network-pre.target
Before=network.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xtls-spamhaus-output restore
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
  cat >/etc/systemd/system/xtls-spamhaus-output-update.service <<'UNIT'
[Unit]
Description=Refresh Spamhaus OUTPUT observation sets
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xtls-spamhaus-output update
UNIT
  cat >/etc/systemd/system/xtls-spamhaus-output-update.timer <<'UNIT'
[Unit]
Description=Refresh Spamhaus OUTPUT observation every 12 hours
[Timer]
OnCalendar=*-*-* 00,12:55:00
Persistent=true
RandomizedDelaySec=10m
Unit=xtls-spamhaus-output-update.service
[Install]
WantedBy=timers.target
UNIT
  # Validate and populate the observer before enabling boot/timer units.
  # Failed downloads must not leave an enabled but empty installation.
  update
  systemctl daemon-reload
  systemctl enable xtls-spamhaus-output-restore.service
  systemctl enable --now xtls-spamhaus-output-update.timer
}
restore() (
  prepare
  local d
  d=$(mktemp -d /tmp/xtls-spamhaus-restore.XXXXXXXX)
  trap 'rm -rf "$d"' EXIT
  local ver
  for ver in 4 6; do
    if [[ ! -s "$ROOT/cidr$ver" ]]; then
      echo "No cached Spamhaus OUTPUT IPv$ver; empty set retained"
      continue
    fi
    { printf 'flush set inet %s v%s\n' "$TABLE" "$ver"
      python3 - "$ROOT/cidr$ver" "$ver" <<'PY'
import ipaddress,sys
v=int(sys.argv[2]);nets=[]
for line in open(sys.argv[1]):
    line=line.strip()
    if not line:continue
    net=ipaddress.ip_network(line,strict=False)
    if net.version!=v or not net.is_global: raise ValueError("invalid cached range")
    nets.append(str(net))
for i in range(0,len(nets),100):
    print(f'add element inet xtls_spamhaus_out v{v} {{ '+', '.join(nets[i:i+100])+' }')
PY
    } > "$d/v$ver.batch"
  done
  if ! compgen -G "$d/*.batch" >/dev/null; then return 0; fi
  cat "$d"/*.batch > "$d/all.batch"
  nft -c -f "$d/all.batch"
  nft -f "$d/all.batch"
  # Explicit restore verification; a successful nft exit alone is not enough.
  local ver expected actual
  for ver in 4 6; do
    [[ -s "$ROOT/cidr$ver" ]] || continue
    expected=$(wc -l < "$ROOT/cidr$ver")
    actual=$(nft -j list set inet "$TABLE" "v$ver" | python3 -c '
import json,sys
obj=json.load(sys.stdin)
print(sum(len(e["set"].get("elem",[])) for e in obj["nftables"] if "set" in e))
')
    echo "Restore IPv$ver: cached=$expected nft_elements=$actual"
    [[ "$actual" =~ ^[0-9]+$ && "$actual" -gt 0 ]] || {
      echo "ERROR: IPv$ver nft set is empty after restore" >&2
      return 1
    }
  done
  if [[ "$(cat "$ROOT/diagnostics-mode" 2>/dev/null || true)" == enabled ]]; then
    diagnostics_enable
  fi
)
diagnostics_enable() {
  prepare
  # Rate limits are per-rule (not per destination). Log only outbound matches;
  # no drop, no NFLOG daemon, no payload capture.
  if ! nft list chain inet "$TABLE" output | grep -q 'xtls-sh-diag-v4'; then
    nft add rule inet "$TABLE" output ip daddr @v4 limit rate 2/minute burst 5 packets log prefix '"XTLS-SH4 "' level notice comment '"xtls-sh-diag-v4"'
  fi
  if ! nft list chain inet "$TABLE" output | grep -q 'xtls-sh-diag-v6'; then
    nft add rule inet "$TABLE" output ip6 daddr @v6 limit rate 2/minute burst 5 packets log prefix '"XTLS-SH6 "' level notice comment '"xtls-sh-diag-v6"'
  fi
  install -d -m 700 "$ROOT"
  echo enabled > "$ROOT/diagnostics-mode"
  echo "Spamhaus matched-packet logging enabled (2/minute per family, burst 5; no DROP)"
}
diagnostics_disable() {
  local handle
  for marker in xtls-sh-diag-v4 xtls-sh-diag-v6; do
    while :; do
      handle=$(nft -a list chain inet "$TABLE" output 2>/dev/null |
        awk -v marker="$marker" 'index($0,marker){for(i=1;i<=NF;i++)if($i=="handle"){print $(i+1);exit}}')
      [[ -n "$handle" ]] || break
      nft delete rule inet "$TABLE" output handle "$handle"
    done
  done
  install -d -m 700 "$ROOT"
  echo disabled > "$ROOT/diagnostics-mode"
  echo "Spamhaus matched-packet logging disabled"
}
diagnostics_report() {
  # Explicitly on-demand. No background worker, network request, or persistent index.
  # journalctl bounds both time and rows; tail seeks backwards instead of reading all access.log.
  python3 - "$ROOT" <<'PY'
import collections, datetime as dt, ipaddress, os, re, subprocess, sys
from pathlib import Path
ROOT=Path(sys.argv[1])
ACCESS=Path('/var/log/remnanode/access.log')
LIMIT_EVENTS=60
LIMIT_JOURNAL=3000
LIMIT_ACCESS=20000
WINDOW=3.0
def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=8, check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ''
def parse_time(t):
    try:
        return dt.datetime.fromisoformat(t.replace('Z','+00:00')).timestamp()
    except ValueError:
        return None
# Read at most 3000 recent kernel messages and only retain 60 Spamhaus log records.
journal=run(['journalctl','-k','--since','2 hours ago','-n',str(LIMIT_JOURNAL),'--no-pager','-o','short-iso'])
events=[]
for line in journal.splitlines():
    if 'XTLS-SH4 ' not in line and 'XTLS-SH6 ' not in line:
        continue
    ts=parse_time(line.split(' ',1)[0])
    dst=re.search(r'\bDST=([^ ]+)',line)
    proto=re.search(r'\bPROTO=(TCP|UDP)\b',line)
    port=re.search(r'\bDPT=(\d+)\b',line)
    if ts is None or not dst or not proto or not port: continue
    events.append((ts,dst.group(1),proto.group(1).lower(),port.group(1)))
events=events[-LIMIT_EVENTS:]
if not events:
    print('No Spamhaus kernel matches in bounded recent journal sample.')
    print('Limits: 2h / last 3000 kernel records; no network requests.')
    raise SystemExit(0)
ranges={4:[],6:[]}
for ver in (4,6):
    file=ROOT/f'cidr{ver}'
    if file.exists():
        for line in file.read_text().splitlines():
            try: ranges[ver].append(ipaddress.ip_network(line.strip()))
            except ValueError: pass
# Avoid 60*1800 comparisons by mapping unique destinations once.
range_cache={}
def cidr_for(ip):
    if ip not in range_cache:
        try:
            addr=ipaddress.ip_address(ip)
            range_cache[ip]=next((str(n) for n in ranges[addr.version] if addr in n), '?')
        except ValueError:
            range_cache[ip]='?'
    return range_cache[ip]
records=[]
if ACCESS.is_file():
    content=run(['tail','-n',str(LIMIT_ACCESS),str(ACCESS)])
    pattern=re.compile(r'^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)\.\d+ .*? accepted (tcp|udp):([^ ]+) \[([^]]+)\] email: (\S+)')
    for line in content.splitlines():
        m=pattern.search(line)
        if not m: continue
        moment=dt.datetime.strptime(m.group(1),'%Y/%m/%d %H:%M:%S').replace(tzinfo=dt.timezone.utc).timestamp()
        target=m.group(3).rsplit(':',1)
        if len(target)!=2: continue
        records.append((moment,target[0].strip('[]'),m.group(2),target[1],m.group(4),m.group(5)))
print(f'Spamhaus OUTPUT correlations: {len(events)} sampled packets (not unique connections)')
print(f'Limits: last {LIMIT_JOURNAL} kernel entries, last {LIMIT_ACCESS} access.log lines, ±{WINDOW:g}s UTC')
if not ACCESS.is_file(): print('WARN: Remnanode access.log is missing')
unique={}
for t,ip,proto,port in events:
    key=(ip,proto,port)
    if key not in unique: unique[key]=[t,0]
    unique[key][1]+=1
for (ip,proto,port),(t,count) in list(unique.items())[-25:]:
    moment=dt.datetime.fromtimestamp(t,dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    candidates={(r[4],r[5]) for r in records if abs(r[0]-t)<=WINDOW and r[1]==ip and r[2]==proto and r[3]==port}
    print(f'\n{moment}  {proto.upper()} {ip}:{port}  packets_sampled={count}  range={cidr_for(ip)}')
    if len(candidates)==1:
        user,route=next(iter(candidates))
        print(f'  Remnanode candidate: email={user} route={route} (time/destination match; not proof)')
    elif candidates:
        print('  Ambiguous Remnanode candidates: '+', '.join(f'{u} [{r}]' for u,r in sorted(candidates)[:8]))
    else: print('  Remnanode: no match in bounded access.log sample')
print('No blocking performed. No process/user attribution without an unambiguous corroborating record.')
PY
}
diagnostics_show() {
  echo "Recent Spamhaus OUTPUT log events (kernel journal):"
  journalctl -k --since "2 hours ago" --no-pager -o short-iso 2>/dev/null |
    grep -E 'XTLS-SH[46] ' | tail -n 60 || true
  echo "Note: capped logging samples packets, not complete connection counts."
}
status() {
  nft list table inet "$TABLE" 2>/dev/null || echo "Not installed"
  echo "Last successful update: $(cat "$ROOT/last-success" 2>/dev/null || echo none)"
}
case "${1:-}" in
  install) install_module ;;
  update) update ;;
  restore) restore ;;
  status) status ;;
  diagnostics-enable) diagnostics_enable ;;
  diagnostics-disable) diagnostics_disable ;;
  diagnostics-show) diagnostics_show ;;
  diagnostics-report) diagnostics_report ;;
  *) echo "Usage: xtls-spamhaus-output {install|update|restore|status|diagnostics-enable|diagnostics-disable|diagnostics-show|diagnostics-report}" >&2;exit 2 ;;
esac
