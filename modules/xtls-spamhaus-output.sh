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
update() {
  install -d -m 700 "$ROOT"
  exec 9>"$LOCK"
  flock -x 9
  local d
  d=$(mktemp -d /tmp/xtls-spamhaus-out.XXXXXXXX)
  trap 'rm -rf "$d"' RETURN
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
}
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
  systemctl daemon-reload
  systemctl enable xtls-spamhaus-output-restore.service xtls-spamhaus-output-update.timer
  update
}
restore() {
  prepare
  local d
  d=$(mktemp -d /tmp/xtls-spamhaus-restore.XXXXXXXX)
  trap 'rm -rf "$d"' RETURN
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
  *) echo "Usage: xtls-spamhaus-output {install|update|restore|status}" >&2;exit 2 ;;
esac
