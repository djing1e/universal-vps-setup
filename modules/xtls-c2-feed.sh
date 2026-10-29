#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
TABLE=xtls_c2_feed
ROOT=/etc/xtls-c2-feed
URL=https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPPortC2s.csv
BACKUP=https://cdn.jsdelivr.net/gh/drb-ra/C2IntelFeeds@master/feeds/IPPortC2s.csv
mode() { if nft list chain ip "$TABLE" output 2>/dev/null | grep -q xtls-c2-block; then echo block; else echo observe; fi; }
prepare() {
 nft list table ip "$TABLE" >/dev/null 2>&1 && return 0
 nft -f - <<'NFT'
add table ip xtls_c2_feed
add set ip xtls_c2_feed c2_pairs { type ipv4_addr . inet_service; }
add chain ip xtls_c2_feed output { type filter hook output priority -20; policy accept; }
NFT
}
update() {
 exec 9>/run/xtls-c2-feed.lock
 flock -x 9
 install -d -m 700 "$ROOT"
 tmp=$(mktemp -d)
 trap 'rm -rf "$tmp"' RETURN
 if ! curl -fsSL --retry 2 --connect-timeout 10 --max-time 60 "$URL" -o "$tmp/source"; then
   curl -fsSL --retry 2 --connect-timeout 10 --max-time 60 "$BACKUP" -o "$tmp/source"
 fi
 python3 - "$tmp/source" "$tmp/validated" "$tmp/batch" <<'PY'
import csv,ipaddress,pathlib,sys
source,validated,batch=map(pathlib.Path,sys.argv[1:])
pairs=set()
with source.open(newline='') as f:
    for row in csv.reader(f):
        if not row or row[0].strip().startswith('#'): continue
        if len(row)<2: raise ValueError('Malformed CSV')
        ip=ipaddress.ip_address(row[0].strip())
        if ip.version!=4 or not ip.is_global: continue
        port=int(row[1].strip())
        if not 1<=port<=65535: raise ValueError('Invalid port')
        pairs.add((str(ip),port))
if not 1<=len(pairs)<=50000: raise ValueError(f'Unexpected feed size: {len(pairs)}')
pairs=sorted(pairs,key=lambda p:(int(ipaddress.ip_address(p[0])),p[1]))
validated.write_text(''.join(f'{ip},{port}\n' for ip,port in pairs))
with batch.open('w') as f:
    f.write('flush set ip xtls_c2_feed c2_pairs\n')
    for i in range(0,len(pairs),500):
        f.write('add element ip xtls_c2_feed c2_pairs { '+', '.join(f'{ip} . {port}' for ip,port in pairs[i:i+500])+' }\n')
print('Validated pairs:',len(pairs))
PY
 prepare
 nft -c -f "$tmp/batch"
 nft -f "$tmp/batch"
 install -m 600 "$tmp/validated" "$ROOT/validated.csv"
 echo "Updated. Mode: $(mode)"
}
install_module() {
 install -m 755 "$0" /usr/local/sbin/xtls-c2-feed
 cat >/etc/systemd/system/xtls-c2-feed-update.service <<'UNIT'
[Unit]
Description=Update xtlsproVPN C2 IP and port feed
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xtls-c2-feed update
UNIT
 cat >/etc/systemd/system/xtls-c2-feed-update.timer <<'UNIT'
[Unit]
Description=Update C2 feed every six hours
[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
Persistent=true
Unit=xtls-c2-feed-update.service
[Install]
WantedBy=timers.target
UNIT
 systemctl daemon-reload
 update
 systemctl enable --now xtls-c2-feed-update.timer
 echo 'Installed in observation mode (no drop rule).'
}
block() {
 prepare
 [ "$(mode)" = block ] && { echo 'Already blocking'; return; }
 echo 'WARNING: feed is UNVERIFIED and can cause false-positive VPN disruptions.'
 read -r -p 'Type ENABLE-C2-BLOCK to activate outgoing TCP DROP: ' answer
 [ "$answer" = ENABLE-C2-BLOCK ] || { echo 'Cancelled'; return; }
 nft add rule ip "$TABLE" output ip daddr . tcp dport @c2_pairs counter drop comment '"xtls-c2-block"'
}
unblock() {
 handle=$(nft -a list chain ip "$TABLE" output 2>/dev/null | sed -n '/xtls-c2-block/s/.*# handle \([0-9][0-9]*\).*/\1/p' | head -1)
 [ -z "$handle" ] || nft delete rule ip "$TABLE" output handle "$handle"
 echo 'Block rule removed'
}
[ "$(id -u)" -eq 0 ] || { echo 'Run as root'; exit 1; }
case "${1:-}" in
 install) install_module ;;
 update) update ;;
 enable-block) block ;;
 disable-block) unblock ;;
 status) echo "Mode: $(mode)"; [ ! -f "$ROOT/validated.csv" ] || wc -l "$ROOT/validated.csv"; systemctl is-enabled xtls-c2-feed-update.timer 2>/dev/null || true ;;
 *) echo 'Usage: xtls-c2-feed {install|update|enable-block|disable-block|status}' ; exit 2 ;;
esac
