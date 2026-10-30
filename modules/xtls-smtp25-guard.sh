#!/usr/bin/env bash
    # Proxmox execution gate: no mutable profile override.
    if [[ -e /etc/pve || -e /usr/bin/pveversion || $(uname -r) == *-pve ]] ||
       [[ $(timeout 3 dpkg-query -W -f='${Status}' pve-manager 2>/dev/null) == 'install ok installed' ]]; then
        echo 'BLOCKED: Proxmox Host permits Audit and reviewed allowlisted plans only.' >&2
        exit 1
    fi
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
apply_mode() {
  need_root; need_tools
  local mode=${1:?mode required} tmp
  case "$mode" in observe|block|disabled) ;; *) echo "Invalid mode: $mode" >&2; return 1 ;; esac
  tmp=$(mktemp /tmp/xtls-smtp25.XXXXXX)
  # Build one transactional nft batch: if parsing or execution fails,
  # existing rules stay intact. Do not modify unrelated tables.
  {
    if nft list table inet "$TABLE" >/dev/null 2>&1; then
      echo "delete table inet $TABLE"
    fi
    if [[ "$mode" != disabled ]]; then
      echo "add table inet $TABLE"
      echo "add chain inet $TABLE out { type filter hook output priority -17; policy accept; }"
      if [[ "$mode" == observe ]]; then
        echo 'add rule inet xtls_smtp25_guard out meta l4proto tcp tcp dport 25 ct state new counter limit rate 2/minute burst 4 packets log prefix "XTLS-SMTP25 " level notice'
      else
        echo 'add rule inet xtls_smtp25_guard out meta l4proto tcp tcp dport 25 counter reject with tcp reset'
      fi
    fi
  } > "$tmp"
  if ! nft -c -f "$tmp"; then rm -f "$tmp"; return 1; fi
  if ! nft -f "$tmp"; then rm -f "$tmp"; return 1; fi
  rm -f "$tmp"
  echo "SMTP/25 guard mode: $mode (only OUTPUT TCP/25; 465/587 untouched)"
}
restore() {
  local mode
  mode=$(cat "$STATE_FILE" 2>/dev/null || echo disabled)
  apply_mode "$mode"
}
set_mode() {
  need_root; need_tools
  local mode=$1
  case "$mode" in observe|block|disabled) ;; *) return 1 ;; esac
  # Persist new mode only after successful nft transaction.
  apply_mode "$mode"
  mkdir -p -m 700 "$STATE_DIR"
  printf '%s\n' "$mode" > "$STATE_FILE.new"
  chmod 600 "$STATE_FILE.new"
  mv "$STATE_FILE.new" "$STATE_FILE"
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
