#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_URL="https://raw.githubusercontent.com/djing1e/universal-vps-setup/b3eb5fc22fc705e255d10d378b19067737c4624b/modules/xtls-auto-abuse-guard.py"
TARGET=/usr/local/sbin/xtls-auto-abuse-guard
SERVICE=/etc/systemd/system/xtls-auto-abuse-guard.service
TIMER=/etc/systemd/system/xtls-auto-abuse-guard.timer
require_root() { if (( EUID != 0 )); then echo "Run as root" >&2; exit 1; fi; }
install_guard() {
  require_root
  command -v python3 >/dev/null
  command -v journalctl >/dev/null
  command -v curl >/dev/null
  local tmp
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' RETURN
  curl -fsSL --connect-timeout 10 --max-time 40 "$SCRIPT_URL" -o "$tmp"
  python3 -m py_compile "$tmp"
  grep -q 'behavior-record' "$tmp" || { echo "Behavior support missing" >&2; return 1; }
  install -o root -g root -m 0755 "$tmp" "$TARGET"
  cat > "$SERVICE" <<'UNIT'
[Unit]
Description=Xtls Auto Abuse Guard (observe-only, no banning)
After=systemd-journald.service
ConditionPathExists=/usr/local/sbin/xtls-auto-abuse-guard

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /usr/local/sbin/xtls-auto-abuse-guard scan
ExecStart=/usr/bin/python3 /usr/local/sbin/xtls-auto-abuse-guard behavior-record
StateDirectory=xtls-auto-abuse-guard
StateDirectoryMode=0700
UMask=0077
Nice=10
IOSchedulingClass=idle
CPUQuota=15%
MemoryMax=128M
TasksMax=16
TimeoutStartSec=25
NoNewPrivileges=yes
PrivateTmp=yes
PrivateNetwork=yes
ProtectSystem=strict
ProtectHome=yes
ProtectControlGroups=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=/var/lib/xtls-auto-abuse-guard
UNIT
  cat > "$TIMER" <<'UNIT'
[Unit]
Description=Run xtls Auto Abuse Guard observe scan every minute

[Timer]
OnBootSec=2min
OnUnitInactiveSec=1min
AccuracySec=15s
RandomizedDelaySec=5s
Persistent=false
Unit=xtls-auto-abuse-guard.service

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now xtls-auto-abuse-guard.timer
  echo "Installed: observe-only timer. No firewall or user bans."
}
status_guard() {
  systemctl status --no-pager --lines=8 xtls-auto-abuse-guard.timer || true
  systemctl status --no-pager --lines=8 xtls-auto-abuse-guard.service || true
  if [[ -x "$TARGET" ]]; then "$TARGET" report; fi
}
remove_guard() {
  require_root
  systemctl disable --now xtls-auto-abuse-guard.timer 2>/dev/null || true
  rm -f "$TIMER" "$SERVICE" "$TARGET"
  systemctl daemon-reload
  echo "Removed service and timer; observation data preserved."
}
case "${1:-}" in
  install) install_guard ;;
  status) status_guard ;;
  remove) remove_guard ;;
  *) echo "Usage: $0 {install|status|remove}"; exit 2 ;;
esac
