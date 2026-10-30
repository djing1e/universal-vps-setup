#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
TABLE=xtls_c2_feed
ROOT=/etc/xtls-c2-feed
URL=https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPPortC2s.csv
BACKUP=https://cdn.jsdelivr.net/gh/drb-ra/C2IntelFeeds@master/feeds/IPPortC2s.csv
STATE="$ROOT/mode"
CSV="$ROOT/validated.csv"
lock() { exec 9>/run/xtls-c2-feed.lock; flock -x 9; }
saved_mode() { local m=observe; if [[ -f "$STATE" ]]; then IFS= read -r m < "$STATE" || true; fi; case "$m" in observe|block) echo "$m";; *) echo "Invalid mode" >&2; return 1;; esac; }
write_mode() { install -d -m 700 "$ROOT"; local f; f=$(mktemp "$ROOT/.mode.XXXXXX"); printf "%s\n" "$1" > "$f"; chmod 600 "$f"; mv -f "$f" "$STATE"; }
mode() { if nft list chain ip "$TABLE" output 2>/dev/null | grep -q xtls-c2-block; then echo block; else echo observe; fi; }
prepare() {
 nft list table ip "$TABLE" >/dev/null 2>&1 || nft add table ip "$TABLE"
 nft list set ip "$TABLE" c2_pairs >/dev/null 2>&1 || nft 'add set ip xtls_c2_feed c2_pairs { type ipv4_addr . inet_service; }'
 nft list chain ip "$TABLE" output >/dev/null 2>&1 || nft 'add chain ip xtls_c2_feed output { type filter hook output priority -20; policy accept; }'
}
validate_and_apply() {
 local tmp="$1" source="$2"
 python3 - "$source" "$tmp/validated" "$tmp/batch" <<'PY'
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
 local rc=$?
 if (( rc != 0 )); then
   echo "ERROR: C2 feed validation failed (exit $rc); existing nft set unchanged" >&2
   return "$rc"
 fi
 [[ -s "$tmp/batch" && -s "$tmp/validated" ]] || { echo 'ERROR: missing validated feed or nft batch' >&2; return 1; }
 prepare || return 1
 nft -c -f "$tmp/batch" || return 1
 nft -f "$tmp/batch" || return 1
}
remove_rules() {
 local h rules handles tables
 if ! rules=$(nft -a list chain ip "$TABLE" output 2>/dev/null); then
   # A never-installed module has nothing to remove. Inspection errors on an
   # existing table must not be reported as a successful switch to observe.
   tables=$(nft list tables) || return 1
   if printf '%s\n' "$tables" | grep -Fxq "table ip $TABLE"; then
     echo 'ERROR: cannot inspect C2 output chain' >&2
     return 1
   fi
   return 0
 fi
 handles=$(printf '%s\n' "$rules" | sed -n '/comment "xtls-c2-block"/s/.*# handle \([0-9][0-9]*\).*/\1/p')
 for h in $handles; do
   nft delete rule ip "$TABLE" output handle "$h" || return 1
 done
 rules=$(nft -a list chain ip "$TABLE" output) || return 1
 if [[ "$rules" == *'comment "xtls-c2-block"'* ]]; then
   echo 'ERROR: C2 DROP rule remains; observe mode not applied' >&2
   return 1
 fi
}

restore_locked() {
 local tmp m
 m=$(saved_mode) || return 1
 # Enforce observe even when the cached feed is missing or invalid.
 if [[ "$m" == observe ]]; then remove_rules || return 1; fi
 [[ -s "$CSV" ]] || { echo 'No local C2 cache' >&2; return 1; }
 tmp=$(mktemp -d)
 validate_and_apply "$tmp" "$CSV" || { rm -rf "$tmp"; return 1; }
 rm -rf "$tmp"
 if [[ "$m" == block ]]; then
   if [[ "$(mode)" != block ]]; then
     nft add rule ip "$TABLE" output ip daddr . tcp dport @c2_pairs counter drop comment '"xtls-c2-block"'
   fi
 fi
 echo "Restored. Mode: $m"
}
restore() ( lock; restore_locked; )
update() (
 lock
 install -d -m 700 "$ROOT"
 local tmp m
 m=$(saved_mode) || return 1
 # A refresh must also heal an old Saved=observe / Live=block mismatch.
 if [[ "$m" == observe ]]; then remove_rules || return 1; fi
 tmp=$(mktemp -d)
 if ! curl -fsSL --retry 2 --connect-timeout 10 --max-time 60 "$URL" -o "$tmp/source"; then
   if ! curl -fsSL --retry 2 --connect-timeout 10 --max-time 60 "$BACKUP" -o "$tmp/source"; then
     rm -rf "$tmp"
     echo 'Feed unavailable: existing nft set and CSV preserved' >&2
     return 1
   fi
 fi
 validate_and_apply "$tmp" "$tmp/source" || { rm -rf "$tmp"; return 1; }
 install -m 600 "$tmp/validated" "$ROOT/.validated.new"
 mv -f "$ROOT/.validated.new" "$CSV"
 rm -rf "$tmp"
 if [[ "$m" == block && "$(mode)" != block ]]; then
   nft add rule ip "$TABLE" output ip daddr . tcp dport @c2_pairs counter drop comment '"xtls-c2-block"'
 fi
 echo "Updated. Mode: $(mode)"
)
install_module() {
 install -d -m 700 "$ROOT"
 install -m 755 "$0" /usr/local/sbin/xtls-c2-feed
 if [[ ! -f "$STATE" ]]; then write_mode observe; fi
 cat >/etc/systemd/system/xtls-c2-feed-restore.service <<'UNIT'
[Unit]
Description=Restore xtlsproVPN C2 cache at boot
After=local-fs.target
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xtls-c2-feed restore
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
 cat >/etc/systemd/system/xtls-c2-feed-update.service <<'UNIT'
[Unit]
Description=Update xtlsproVPN C2 IP and port feed
Wants=network-online.target
After=network-online.target xtls-c2-feed-restore.service
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
 if [[ -s "$CSV" ]]; then restore; else update; fi
 systemctl enable xtls-c2-feed-restore.service xtls-c2-feed-update.timer
 systemctl start xtls-c2-feed-restore.service
 systemctl start xtls-c2-feed-update.timer
 echo "Installed. Mode: $(saved_mode)"
}
block() {
 echo 'WARNING: unverified C2 data can cause false-positive VPN disruptions.'
 local answer tmp
 read -e -r -p 'Type ENABLE-C2-BLOCK to activate outgoing TCP DROP: ' answer
 [[ "$answer" == ENABLE-C2-BLOCK ]] || { echo 'Cancelled'; return; }
 lock
 [[ -s "$CSV" ]] || { echo 'No cached feed; update first' >&2; return 1; }
 tmp=$(mktemp -d)
 validate_and_apply "$tmp" "$CSV" || { rm -rf "$tmp"; return 1; }
 rm -rf "$tmp"
 if [[ "$(mode)" != block ]]; then
   nft add rule ip "$TABLE" output ip daddr . tcp dport @c2_pairs counter drop comment '"xtls-c2-block"'
 fi
 write_mode block
 echo 'Blocking enabled and persisted'
}
unblock() {
 lock
 # Persist the safe boot intent first, but only report success after removal.
 write_mode observe || return 1
 remove_rules || return 1
 echo 'Blocking disabled and persisted'
}

[ "$(id -u)" -eq 0 ] || { echo 'Run as root'; exit 1; }
case "${1:-}" in
 install) install_module ;;
 update) update ;;
 restore) restore ;;
 enable-block) block ;;
 disable-block) unblock ;;
 status) echo "Saved mode: $(saved_mode)"; echo "Live mode: $(mode)"; [ ! -f "$CSV" ] || wc -l "$CSV"; systemctl is-enabled xtls-c2-feed-restore.service 2>/dev/null || true; systemctl is-enabled xtls-c2-feed-update.timer 2>/dev/null || true ;;
 *) echo 'Usage: xtls-c2-feed {install|update|restore|enable-block|disable-block|status}' ; exit 2 ;;
esac
