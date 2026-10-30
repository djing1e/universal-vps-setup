#!/usr/bin/env bash
    # Proxmox execution gate: no mutable profile override.
    if [[ -e /etc/pve || -e /usr/bin/pveversion || $(uname -r) == *-pve ]] ||
       [[ $(timeout 3 dpkg-query -W -f='${Status}' pve-manager 2>/dev/null) == 'install ok installed' ]]; then
        echo 'BLOCKED: Proxmox Host permits Audit and reviewed allowlisted plans only.' >&2
        exit 1
    fi
set -Eeuo pipefail
# Port Scan Guard: aggregate outbound TCP SYN telemetry only.
# Never DROP/REJECT; no subscriber attribution.
TABLE=xtls_portscan_observe
STATE_DIR=/etc/xtls-portscan-observe
STATE_FILE=$STATE_DIR/enabled
SERVICE=/etc/systemd/system/xtls-portscan-observe-restore.service
require_root() { (( EUID == 0 )) || { echo "root required" >&2; exit 1; }; }
make_batch() {
  local mode=$1
  if nft list table inet "$TABLE" >/dev/null 2>&1; then
    printf 'delete table inet %s\n' "$TABLE"
  fi
  if [[ "$mode" == enabled ]]; then
    cat <<'NFT'
add table inet xtls_portscan_observe
add set inet xtls_portscan_observe recent_v4 { type ipv4_addr . inet_service; flags dynamic,timeout; timeout 60s; size 16384; }
add chain inet xtls_portscan_observe out { type filter hook output priority -16; policy accept; }
add rule inet xtls_portscan_observe out meta nfproto ipv4 meta l4proto tcp ct state new tcp flags & (syn | ack) == syn tcp dport != { 80, 443, 25, 465, 587, 853 } update @recent_v4 { ip daddr . tcp dport timeout 60s } counter comment "xtls-portscan-syn-observe"
NFT
  fi
}
apply_mode() {
  require_root
  command -v nft >/dev/null || { echo "nft missing" >&2; return 1; }
  local mode=$1 tmp
  [[ "$mode" == enabled || "$mode" == disabled ]] || return 2
  tmp=$(mktemp /tmp/xtls-portscan.XXXXXX)
  make_batch "$mode" > "$tmp"
  if ! nft -c -f "$tmp"; then rm -f "$tmp"; return 1; fi
  if ! nft -f "$tmp"; then rm -f "$tmp"; return 1; fi
  rm -f "$tmp"
  echo "Port Scan Observe: $mode (no DROP, REJECT or packet logging)"
}
set_mode() {
  local mode=$1
  apply_mode "$mode"
  install -d -m 700 "$STATE_DIR"
  printf '%s\n' "$mode" > "$STATE_FILE.tmp"
  chmod 600 "$STATE_FILE.tmp"
  mv "$STATE_FILE.tmp" "$STATE_FILE"
}
restore() {
  local mode
  mode=$(cat "$STATE_FILE" 2>/dev/null || echo disabled)
  apply_mode "$mode"
}
status() {
  echo "Mode: $(cat "$STATE_FILE" 2>/dev/null || echo absent)"
  if nft list table inet "$TABLE" >/dev/null 2>&1; then
    nft -a list table inet "$TABLE"
  else
    echo "nft table: absent"
  fi
}
install_service() {
  require_root
  local self
  self=$(readlink -f "$0")
  if [[ "$self" != /usr/local/sbin/xtls-portscan-observe ]]; then
    install -o root -g root -m 0755 "$self" /usr/local/sbin/xtls-portscan-observe
  fi
  cat > "$SERVICE" <<'UNIT'
[Unit]
Description=Restore xtls Port Scan Observe nft telemetry
After=network-pre.target
Before=network.target
ConditionPathExists=/usr/local/sbin/xtls-portscan-observe

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xtls-portscan-observe restore
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable xtls-portscan-observe-restore.service
  if [[ -e "$STATE_FILE" ]]; then restore; else set_mode enabled; fi
  echo "Installed. Observe only; no blocking."
}
case "${1:-}" in
  install) install_service ;;
  enable) set_mode enabled ;;
  disable) set_mode disabled ;;
  restore) restore ;;
  status) status ;;
  *) echo "Usage: $0 {install|enable|disable|restore|status}" >&2; exit 2 ;;
esac
