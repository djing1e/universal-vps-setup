#!/usr/bin/env bash
set -Eeuo pipefail
# Optional outbound SMTP/25 abuse guard. Observe by default. Never touches other tables.
TABLE=xtls_smtp25_guard
STATE_DIR=/etc/xtls-smtp25-guard
STATE_FILE=$STATE_DIR/mode
SERVICE=/etc/systemd/system/xtls-smtp25-guard-restore.service

need_root() { (( EUID == 0 )) || { echo "root required" >&2; exit 1; }; }
need_tools() { command -v nft >/dev/null || { echo "nft missing" >&2; exit 1; }; }
status() {
  echo "Configured mode: $(cat "$STATE_FILE" 2>/dev/null || echo absent)"
  if nft list table inet "$TABLE" >/dev/null 2>&1; then nft -a list table inet "$TABLE"; else echo "nft table: absent"; fi
}
restore() {
  need_root; need_tools
  local mode
  mode=$(cat "$STATE_FILE" 2>/dev/null || echo disabled)
  case "$mode" in observe|block|disabled) ;; *) echo "Invalid saved mode: $mode" >&2; exit 1 ;; esac
  # Do not alter unrelated tables, and do not silently replace unknown table state.
  if nft list table inet "$TABLE" >/dev/null 2>&1; then
    nft delete table inet "$TABLE"
  fi
  if [[ "$mode" == disabled ]]; then return; fi
  local tmp
  tmp=$(mktemp /tmp/xtls-smtp25.XXXXXX)
  trap 'rm -f "$tmp"' RETURN
  {
    echo "add table inet $TABLE"
    echo "add chain inet $TABLE out { type filter hook output priority -17; policy accept; }"
    if [[ "$mode" == observe ]]; then
      echo 'add rule inet xtls_smtp25_guard out meta l4proto tcp tcp dport 25 ct state new counter limit rate 2/minute burst 4 packets log prefix "XTLS-SMTP25 " level notice'
    else
      echo 'add rule inet xtls_smtp25_guard out meta l4proto tcp tcp dport 25 counter reject with tcp reset'
    fi
  } > "$tmp"
  nft -c -f "$tmp"
  nft -f "$tmp"
  echo "SMTP/25 guard mode: $mode (only OUTPUT TCP/25; 465/587 untouched)"
}
set_mode() {
  need_root; need_tools
  local mode=$1
  mkdir -p -m 700 "$STATE_DIR"
  printf '%s\n' "$mode" > "$STATE_FILE.new"
  chmod 600 "$STATE_FILE.new"
  mv "$STATE_FILE.new" "$STATE_FILE"
  restore
}
install_service() {
  need_root
  local self
  self=$(readlink -f "$0")
  [[ "$self" == "/usr/local/sbin/xtls-smtp25-guard" ]] || {
    install -o root -g root -m 0755 "$self" /usr/local/sbin/xtls-smtp25-guard
  }
  cat > "$SERVICE" <<'UNIT'
[Unit]
Description=Restore optional xtls SMTP/25 outbound protection
After=network-pre.target
Before=network.target
ConditionPathExists=/usr/local/sbin/xtls-smtp25-guard

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xtls-smtp25-guard restore
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable xtls-smtp25-guard-restore.service
  if [[ ! -e "$STATE_FILE" ]]; then set_mode observe; else restore; fi
  echo "Installed; existing mode kept or OBSERVE selected. No blocking enabled by installer."
}
case "${1:-}" in
  install) install_service ;;
  observe) set_mode observe ;;
  block) set_mode block ;;
  disable) set_mode disabled ;;
  restore) restore ;;
  status) need_tools; status ;;
  *) echo "Usage: $0 {install|observe|block|disable|restore|status}"; exit 2 ;;
esac
