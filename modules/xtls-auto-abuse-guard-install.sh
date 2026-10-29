#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_URL="https://raw.githubusercontent.com/djing1e/universal-vps-setup/5f7e6ed977d48054ca01f38a152900f48896aa54/modules/xtls-auto-abuse-guard.py"
TARGET=/usr/local/sbin/xtls-auto-abuse-guard
SERVICE=/etc/systemd/system/xtls-auto-abuse-guard.service
TIMER=/etc/systemd/system/xtls-auto-abuse-guard.timer
DROPIN_DIR=/etc/systemd/system/xtls-auto-abuse-guard.service.d
LEGACY_DROPIN=$DROPIN_DIR/20-behavior.conf
legacy_dropin_matches() {
  [[ -f "$LEGACY_DROPIN" ]] || return 1
  [[ "$(cat "$LEGACY_DROPIN")" == "$(printf "%s\n" "[Service]" "ExecStart=" "ExecStart=/usr/bin/python3 /usr/local/sbin/xtls-auto-abuse-guard scan" "ExecStart=/usr/bin/python3 /usr/local/sbin/xtls-auto-abuse-guard behavior-record")" ]]
}
check_dropins() {
  local f
  [[ -d "$DROPIN_DIR" ]] || return 0
  while IFS= read -r -d "" f; do
    if grep -Eq "^[[:space:]]*ExecStart[[:space:]]*=" "$f"; then
      if [[ "$f" == "$LEGACY_DROPIN" ]] && legacy_dropin_matches; then continue; fi
      echo "Unknown ExecStart override: $f; refusing update" >&2
      return 1
    fi
  done < <(find "$DROPIN_DIR" -maxdepth 1 -type f -name "*.conf" -print0)
}
require_root() { if (( EUID != 0 )); then echo "Run as root" >&2; exit 1; fi; }
install_guard() (
  require_root
  command -v python3 >/dev/null
  command -v journalctl >/dev/null
  command -v curl >/dev/null
  local tmp
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  curl -fsSL --connect-timeout 10 --max-time 40 "$SCRIPT_URL" -o "$tmp"
  python3 -m py_compile "$tmp"
  grep -q 'incident_id' "$tmp" || { echo "Incident ID support missing" >&2; return 1; }
  grep -q 'behavior-record' "$tmp" || { echo "Behavior support missing" >&2; return 1; }
  check_dropins
  local backup_dir
  backup_dir=$(mktemp -d /root/xtls-guard-backup.XXXXXXXX)
  [[ ! -f "$TARGET" ]] || cp -a "$TARGET" "$backup_dir/xtls-auto-abuse-guard"
  [[ ! -f "$SERVICE" ]] || cp -a "$SERVICE" "$backup_dir/xtls-auto-abuse-guard.service"
  [[ ! -f "$TIMER" ]] || cp -a "$TIMER" "$backup_dir/xtls-auto-abuse-guard.timer"
  [[ ! -d "$DROPIN_DIR" ]] || cp -a "$DROPIN_DIR" "$backup_dir/dropins"
  echo "Previous version backed up to: $backup_dir"
  local was_enabled=no was_active=no committed=no
  systemctl is-enabled --quiet xtls-auto-abuse-guard.timer && was_enabled=yes || true
  systemctl is-active --quiet xtls-auto-abuse-guard.timer && was_active=yes || true
  rollback() {
    local rc=$?
    if [[ "$committed" != yes && $rc -ne 0 ]]; then
      echo "Update failed (exit=$rc); restoring unit files and executable" >&2
      if [[ -e "$backup_dir/xtls-auto-abuse-guard" ]]; then
        cp -a "$backup_dir/xtls-auto-abuse-guard" "$TARGET"
      else rm -f "$TARGET"; fi
      if [[ -e "$backup_dir/xtls-auto-abuse-guard.service" ]]; then
        cp -a "$backup_dir/xtls-auto-abuse-guard.service" "$SERVICE"
      else rm -f "$SERVICE"; fi
      if [[ -e "$backup_dir/xtls-auto-abuse-guard.timer" ]]; then
        cp -a "$backup_dir/xtls-auto-abuse-guard.timer" "$TIMER"
      else rm -f "$TIMER"; fi
      rm -rf "$DROPIN_DIR"
      if [[ -d "$backup_dir/dropins" ]]; then cp -a "$backup_dir/dropins" "$DROPIN_DIR"; fi
      systemctl daemon-reload || true
      if [[ "$was_enabled" == yes ]]; then systemctl enable xtls-auto-abuse-guard.timer || true
      else systemctl disable xtls-auto-abuse-guard.timer || true; fi
      if [[ "$was_active" == yes ]]; then systemctl start xtls-auto-abuse-guard.timer || true
      else systemctl stop xtls-auto-abuse-guard.timer || true; fi
      echo "Rollback attempted; backup: $backup_dir" >&2
    fi
  }
  trap rollback EXIT
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
  if legacy_dropin_matches; then rm -f "$LEGACY_DROPIN"; fi
  systemctl daemon-reload
  systemd-analyze verify "$SERVICE"
  systemctl enable --now xtls-auto-abuse-guard.timer
  systemctl start xtls-auto-abuse-guard.service
  systemctl is-active --quiet xtls-auto-abuse-guard.timer
  committed=yes
  echo "Installed: observe-only timer. No firewall or user bans."
)
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
  preflight) require_root; check_dropins; echo "Drop-in preflight OK" ;;
  install) install_guard ;;
  status) status_guard ;;
  remove) remove_guard ;;
  *) echo "Usage: $0 {preflight|install|status|remove}"; exit 2 ;;
esac
