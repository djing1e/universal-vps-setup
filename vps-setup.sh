#!/bin/bash

# ╔══════════════════════════════════════════╗
# ║        Universal VPS Setup Script       ║
# ║   SSH + UFW + CrowdSec                  ║
# ╚══════════════════════════════════════════╝
# Запускать от root: sudo -i, затем bash vps-setup.sh

# =====================================
# КОНФИГУРАЦИЯ — измени под себя
# =====================================
SSH_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBzUZGuDMpKZXcB6XknFg73Z+74TkKSvX8DN7K0L7oItWIJg5/9D2dVKFak5GRs20dV4KezDkeggvttg2xiFzyfplj9qtBZHRerlLW5JgefGol78S5XvVWLBvUrdP+2mUU7lyaH6sb/xKJvNwvkeMfLUDpJHAtzT09/GiIMSIhXsUWFIKXsxWpsd9wYmUYli+PsZcEZIdxUPNFvn6wX3eoa8xOco9tgzWjqPANzvfzDEhziCYFv6GgbPbyCiuWcsAPhqRI+APHpUnbnnV6DqoM5DBNg94OgGbsCh9kHUHscrWlcoXet+hun8Htx7jEP0MKIB2KlCXwUwpI/l5+0Qvz rsa-key-20250213"
DEFAULT_SSH_PORT=62152

# Interactive prompts use Bash Readline (-e) so both Backspace encodings
# (Ctrl-H / 0x08 and DEL / 0x7f) delete the preceding character over SSH.
# Do not force `stty erase`: terminal emulators may send different codes.
_vps_setup_readline_keys() {
    [[ -t 0 && -t 1 ]] || return 0
    bind '"\C-h": backward-delete-char' 2>/dev/null || true
    bind '"\C-?": backward-delete-char' 2>/dev/null || true
}
_vps_setup_readline_keys

# =====================================
# TELEGRAM SUBNETS WHITELIST
# =====================================
TELEGRAM_SUBNETS_V4=(
    "149.154.64.0/22"
    "149.154.160.0/20"
    "91.108.4.0/22"
    "91.108.8.0/22"
    "91.108.12.0/22"
    "91.108.16.0/22"
    "91.108.56.0/22"
    "185.76.151.0/24"
)
TELEGRAM_SUBNETS_V6=(
    "2001:b28:f23d::/48"
    "2001:b28:f23f::/48"
    "2001:67c:4e8::/48"
)

# =====================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =====================================
find_free_port() {
    local port

    for port in 7425 7422 7423 7424 7426 7427 7428; do
        if python3 - "$port" <<'PYPORT'
import socket
import sys

port = int(sys.argv[1])

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", port))
except OSError:
    sys.exit(1)
PYPORT
        then
            echo "$port"
            return 0
        fi
    done

    echo "ОШИБКА: свободный LAPI-порт не найден!" >&2
    return 1
}

print_header() {
    # сброс терминала в нормальный режим: если предыдущая команда (nano, прерванный
    # resolvectl и т.п.) оставила терминал в raw-режиме, вывод «съезжает лесенкой»
    # и приглашения read не видно. stty sane чинит перевод строки (\r после \n).
    stty sane 2>/dev/null || true
    clear
    echo ""
    echo "╔══════════════════════════════════════════╗"
    echo "║        Universal VPS Setup Script       ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
}

# =====================================
# ЛОГИРОВАНИЕ
# =====================================
LOG_FILE="/var/log/vps-setup.log"

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" >> "$LOG_FILE"
    echo "$msg"
}

log_section() {
    echo "" >> "$LOG_FILE"
    echo "=========================================" >> "$LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] === $1 ===" >> "$LOG_FILE"
    echo "=========================================" >> "$LOG_FILE"
    echo "  → $1"
}

# =====================================
# vps_fetch_github — устойчивая загрузка с github
# =====================================
# В РФ raw.githubusercontent.com часто режется DPI на TLS-handshake.
# Хелпер сначала пробует jsDelivr CDN (cdn.jsdelivr.net), затем — прямой github.
# Использование:
#   vps_fetch_github <user> <repo> <branch> <path> <output_file>
# Пример:
#   vps_fetch_github C24Be AS_Network_List main blacklists_iptables/blacklist-v4.ipset /tmp/v4.ipset
#
# Возвращает 0 при успехе, 1 если все источники сдохли. Атомарная запись через .tmp.
# Гарантирует -i lo -j ACCEPT первым правилом INPUT/OUTPUT (idempotent).
# КРИТИЧНО: при INPUT policy DROP без этого правила loopback к systemd-resolved
# (127.0.0.53) дропается → системный DNS (getent/nslookup) виснет, хотя
# dig @1.1.1.1 напрямую работает. UFW даёт это правило сам, но после пересборки
# фаервола (CrowdSec сносит UFW) оно теряется.
ensure_loopback_accept() {
    local ipt
    for ipt in iptables ip6tables; do
        command -v "$ipt" >/dev/null 2>&1 || continue
        # Удаляем существующее (могло уехать вниз под threat/AS DROP) и ставим строго ПЕРВЫМ.
        while "$ipt" -D INPUT  -i lo -j ACCEPT 2>/dev/null; do :; done
        while "$ipt" -D OUTPUT -o lo -j ACCEPT 2>/dev/null; do :; done
        "$ipt" -I INPUT  1 -i lo -j ACCEPT 2>/dev/null || true
        "$ipt" -I OUTPUT 1 -o lo -j ACCEPT 2>/dev/null || true
    done
}

# Ждёт готовности DNS-резолвинга (до 2*tries сек). 0 = резолвит, 1 = нет.
wait_for_dns() {
    local tries="${1:-15}" i
    for i in $(seq 1 "$tries"); do
        getent hosts cdn.jsdelivr.net >/dev/null 2>&1 && return 0
        getent hosts github.com      >/dev/null 2>&1 && return 0
        sleep 2
    done
    return 1
}

# Managed AS/Threat IPSet persistence: no global iptables-restore.
install_managed_blocklist_runtime() {
    install -d -m 700 /usr/local/sbin /usr/local/bin
    cat > /usr/local/bin/firewall-blocklist-update.sh <<'MANAGED_UPDATER'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

MODE=${1:-}
case "$MODE" in as|threat) ;; *) echo 'Usage: firewall-blocklist-update.sh {as|threat}' >&2; exit 2;; esac

exec 9>/run/firewall-blocklist-update.lock
flock -x 9

WORK=$(mktemp -d /tmp/firewall-blocklist.XXXXXXXX)
STAGE4="fwstage4-$$"
STAGE6="fwstage6-$$"
SWAP4=0
SWAP6=0
COMMITTED=0

if [[ $MODE == as ]]; then
    TARGET4=asn-blacklist-v4; TARGET6=asn-blacklist-v6
    LOG=/var/log/as-blacklist-update.log
else
    TARGET4=threat-block-v4; TARGET6=threat-block-v6
    LOG=/var/log/threat-blocklist-update.log
fi

log() { printf '[%s] [%s] %s\n' "$(date '+%F %T')" "$MODE" "$*" | tee -a "$LOG"; }
cleanup() {
    local rc=$?
    trap - EXIT
    if (( COMMITTED == 0 )); then
        if (( SWAP6 )); then
            if ipset swap "$STAGE6" "$TARGET6"; then
                SWAP6=0
            else
                log 'CRITICAL: IPv6 rollback failed; staging set preserved'
            fi
        fi
        if (( SWAP4 )); then
            if ipset swap "$STAGE4" "$TARGET4"; then
                SWAP4=0
            else
                log 'CRITICAL: IPv4 rollback failed; staging set preserved'
            fi
        fi
    fi
    if (( SWAP4 == 0 )); then ipset destroy "$STAGE4" 2>/dev/null || true; fi
    if (( SWAP6 == 0 )); then ipset destroy "$STAGE6" 2>/dev/null || true; fi
    rm -rf -- "$WORK"
    if (( rc != 0 )); then log "ERROR: update failed (exit $rc)"; fi
    exit "$rc"
}
trap cleanup EXIT

fetch() { curl -fsSL --retry 2 --connect-timeout 10 --max-time 120 "$1" -o "$2"; }

if [[ $MODE == as ]]; then
    BASE=https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables
    for version in 4 6; do
        path="blacklists_iptables/blacklist-v${version}.ipset"
        if fetch "$BASE/blacklist-v${version}.ipset" "$WORK/source${version}"; then
            log "AS IPv${version} source: github-raw"
        elif fetch "https://cdn.jsdelivr.net/gh/C24Be/AS_Network_List@main/$path" "$WORK/source${version}"; then
            log "AS IPv${version} source: jsdelivr"
        else
            log "ERROR: AS IPv${version} download failed from both sources"
            exit 1
        fi
    done
    python3 - "$WORK" <<'PY'
import ipaddress, pathlib, sys
p=pathlib.Path(sys.argv[1])
for v,minimum in ((4,100),(6,5)):
    lines=(p/f'source{v}').read_text().splitlines()
    commands=[line.split() for line in lines if line.strip() and not line.lstrip().startswith('#')]
    expected=f'blacklist-v{v}'
    if len([c for c in commands if c[0]=='create']) != 1:
        raise ValueError(f'IPv{v}: invalid create count')
    if any(c[0] not in ('create','add') for c in commands):
        raise ValueError(f'IPv{v}: unexpected command')
    if any(len(c)!=3 or c[1]!=expected for c in commands if c[0]=='add'):
        raise ValueError(f'IPv{v}: malformed add')
    cidrs=set()
    for c in commands:
        if c[0]=='add':
            net=ipaddress.ip_network(c[2],strict=False)
            if net.version!=v: raise ValueError(f'IPv{v}: wrong family')
            cidrs.add(str(net))
    if len(cidrs)<minimum: raise ValueError(f'IPv{v}: too few entries')
    (p/f'cidr{v}').write_text('\n'.join(sorted(cidrs))+'\n')
PY
else
    fetch https://www.spamhaus.org/drop/drop_v4.json "$WORK/spamhaus4"
    fetch https://www.spamhaus.org/drop/drop_v6.json "$WORK/spamhaus6"
    fetch https://iplists.firehol.org/files/firehol_level1.netset "$WORK/firehol"
    python3 - "$WORK" <<'PY'
import ipaddress, json, pathlib, sys
p=pathlib.Path(sys.argv[1])
def read_spamhaus(version):
    nets=set()
    for line in (p/f'spamhaus{version}').read_text().splitlines():
        if not line.strip(): continue
        item=json.loads(line)
        if not isinstance(item,dict): raise ValueError('Invalid Spamhaus record')
        cidr=item.get('cidr')
        if cidr is None: continue
        net=ipaddress.ip_network(cidr,strict=False)
        if net.version!=version: raise ValueError('Spamhaus family mismatch')
        if net.is_global: nets.add(str(net))
    if len(nets)<(100 if version==4 else 10):
        raise ValueError(f'Spamhaus IPv{version} feed too small')
    return nets
v4=read_spamhaus(4)
v6=read_spamhaus(6)
firehol=set()
for line in (p/'firehol').read_text().splitlines():
    line=line.split('#',1)[0].strip()
    if not line: continue
    net=ipaddress.ip_network(line,strict=False)
    if net.version!=4: raise ValueError('Unexpected IPv6 in FireHOL')
    if net.is_global: firehol.add(str(net))
if len(firehol)<1000: raise ValueError('FireHOL feed too small')
v4.update(firehol)
for version,nets in ((4,v4),(6,v6)):
    (p/f'cidr{version}').write_text('\n'.join(sorted(nets))+'\n')
PY
fi

for pair in "4 inet $STAGE4 $TARGET4" "6 inet6 $STAGE6 $TARGET6"; do
    read -r version family stage target <<< "$pair"
    ipset list "$target" >/dev/null
    ipset create "$stage" hash:net family "$family" maxelem 262144
    while IFS= read -r cidr; do ipset add "$stage" "$cidr" -exist; done < "$WORK/cidr$version"
    expected=$(wc -l < "$WORK/cidr$version")
    actual=$(ipset list "$stage" | awk '/^Number of entries:/ {print $4}')
    [[ $actual =~ ^[0-9]+$ ]] && (( actual == expected )) || { log "ERROR: IPv$version count mismatch ($actual vs $expected)"; exit 1; }
    log "IPv$version prepared: $actual entries"
done

# Capture the previous persisted state before changing live sets.
cp -a /etc/ipset.conf "$WORK/ipset.conf.previous"

ipset swap "$STAGE4" "$TARGET4"
SWAP4=1
ipset swap "$STAGE6" "$TARGET6"
SWAP6=1

# Persist only managed sets, never CrowdSec's dynamic ipsets.
: > "$WORK/ipset.conf"
for name in asn-blacklist-v4 asn-blacklist-v6 threat-block-v4 threat-block-v6; do
    if ipset list "$name" >/dev/null 2>&1; then ipset save "$name" >> "$WORK/ipset.conf"; fi
done
[[ $(grep -c '^create ' "$WORK/ipset.conf") -ge 2 ]]
chmod 600 "$WORK/ipset.conf"
# Same filesystem for atomic rename; keep the old file as a recovery copy.
cp -a /etc/ipset.conf /etc/ipset.conf.pre-blocklist-update
PERSIST_TMP=$(mktemp /etc/.ipset.conf.XXXXXXXX)
install -m 600 "$WORK/ipset.conf" "$PERSIST_TMP"
mv -f "$PERSIST_TMP" /etc/ipset.conf

COMMITTED=1
ipset destroy "$STAGE4"
ipset destroy "$STAGE6"
log 'OK: update completed'
MANAGED_UPDATER
    chmod 700 /usr/local/bin/firewall-blocklist-update.sh
    cat > /usr/local/sbin/fw-restore-safe.sh <<'SAFE_RESTORE'
#!/usr/bin/env bash
set -Eeuo pipefail
# Restore only on cold boot. Existing sets are left untouched to avoid stale
# union/flush while referenced by active INPUT rules.
if [[ -s /etc/ipset.conf ]]; then
    ipset restore -exist -f /etc/ipset.conf
fi
for entry in 'iptables asn-blacklist-v4' 'ip6tables asn-blacklist-v6' 'iptables threat-block-v4' 'ip6tables threat-block-v6'; do
    read -r cmd name <<< "$entry"
    ipset list "$name" >/dev/null 2>&1 || continue
    count=$(ipset list "$name" | awk '/^Number of entries:/ {print $4}')
    [[ ${count:-0} -gt 0 ]] || continue
    "$cmd" -C INPUT -m set --match-set "$name" src -m conntrack --ctstate NEW -j DROP 2>/dev/null || \
        "$cmd" -I INPUT 1 -m set --match-set "$name" src -m conntrack --ctstate NEW -j DROP
done
echo 'Firewall blocklists restored successfully'
SAFE_RESTORE
    cat > /usr/local/sbin/firewall-blocklist-rules.sh <<'SAFE_RULES'
#!/usr/bin/env bash
set -Eeuo pipefail
for entry in 'iptables asn-blacklist-v4' 'ip6tables asn-blacklist-v6' 'iptables threat-block-v4' 'ip6tables threat-block-v6'; do
    read -r cmd name <<< "$entry"
    ipset list "$name" >/dev/null 2>&1 || continue
    count=$(ipset list "$name" | awk '/^Number of entries:/ {print $4}')
    [[ ${count:-0} -gt 0 ]] || continue
    "$cmd" -C INPUT -m set --match-set "$name" src -m conntrack --ctstate NEW -j DROP 2>/dev/null || \
        "$cmd" -I INPUT 1 -m set --match-set "$name" src -m conntrack --ctstate NEW -j DROP
done
echo 'Blocklist INPUT rules verified'
SAFE_RULES
    chmod 700 /usr/local/sbin/fw-restore-safe.sh /usr/local/sbin/firewall-blocklist-rules.sh
    cat > /etc/systemd/system/ipset-persistent.service <<'IPSET_UNIT'
[Unit]
Description=Restore managed IPSet blocklists and INPUT rules
DefaultDependencies=no
After=local-fs.target systemd-modules-load.service
Before=ufw.service network-pre.target
Wants=network-pre.target
Conflicts=shutdown.target
Before=shutdown.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/fw-restore-safe.sh
ExecReload=/usr/local/sbin/fw-restore-safe.sh
[Install]
WantedBy=multi-user.target
IPSET_UNIT
    # Remove previous drop-in overrides that may reference obsolete restore scripts.
    if [[ -f /etc/systemd/system/ipset-persistent.service.d/override.conf ]]; then
        cp -a /etc/systemd/system/ipset-persistent.service.d/override.conf /etc/systemd/system/ipset-persistent.service.d/override.conf.pre-managed
        rm -f /etc/systemd/system/ipset-persistent.service.d/override.conf
    fi
    cat > /etc/systemd/system/firewall-blocklist-rules.service <<'RULES_UNIT'
[Unit]
Description=Ensure AS and Threat-Intel firewall rules
DefaultDependencies=no
Requires=ipset-persistent.service
After=ipset-persistent.service ufw.service
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/firewall-blocklist-rules.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
RULES_UNIT
    local mode hour
    for mode in as threat; do
        if [[ $mode == as ]]; then hour='00,12:15:00'; else hour='00,12:45:00'; fi
        cat > "/etc/systemd/system/${mode}-blacklist-update.service" <<UNIT
[Unit]
Description=Update ${mode} IPSet blocklists
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/firewall-blocklist-update.sh ${mode}
TimeoutStartSec=600
UNIT
        cat > "/etc/systemd/system/${mode}-blacklist-update.timer" <<UNIT
[Unit]
Description=Update ${mode} IPSet blocklists every 12 hours
[Timer]
OnCalendar=*-*-* ${hour} UTC
Persistent=true
RandomizedDelaySec=0
Unit=${mode}-blacklist-update.service
[Install]
WantedBy=timers.target
UNIT
    done
    systemctl daemon-reload
    systemctl enable ipset-persistent.service firewall-blocklist-rules.service
    # Timers are enabled individually when their respective blocklists exist.
}

persist_ipsets() {
    command -v ipset >/dev/null 2>&1 || return 1
    local tmp name count=0
    tmp=$(mktemp /etc/.ipset.conf.XXXXXXXX) || return 1
    chmod 600 "$tmp"
    # Persist only currently installed sets; never recreate deleted components.
    for name in asn-blacklist-v4 asn-blacklist-v6 threat-block-v4 threat-block-v6; do
        if ipset list "$name" >/dev/null 2>&1; then
            ipset save "$name" >> "$tmp" || { rm -f "$tmp"; return 1; }
            count=$((count+1))
        fi
    done
    if (( count == 0 )); then : > "$tmp"; fi
    mv -f "$tmp" /etc/ipset.conf || return 1
    install_managed_blocklist_runtime || return 1
    systemctl start firewall-blocklist-rules.service || return 1
}

managed_remove_legacy_cron() {
    local script="$1" current filtered
    current=$(crontab -l 2>/dev/null) || return 0
    filtered=$(printf '%s\n' "$current" | grep -vF -- "$script" || true)
    if [[ -n "$filtered" ]]; then printf '%s\n' "$filtered" | crontab -; else crontab -r 2>/dev/null || true; fi
}
managed_remove_set_rules() {
    local cmd="$1" name="$2" chain
    for chain in INPUT SCANNERS-BLOCK; do
        if [[ "$chain" == INPUT ]]; then
            while "$cmd" -C INPUT -m set --match-set "$name" src -m conntrack --ctstate NEW -j DROP 2>/dev/null; do
                "$cmd" -D INPUT -m set --match-set "$name" src -m conntrack --ctstate NEW -j DROP || return 1
            done
        else
            while "$cmd" -C SCANNERS-BLOCK -m set --match-set "$name" src -j DROP 2>/dev/null; do
                "$cmd" -D SCANNERS-BLOCK -m set --match-set "$name" src -j DROP || return 1
            done
        fi
    done
}
managed_remove_ipsets() {
    local name
    managed_remove_set_rules iptables "$1" || return 1
    managed_remove_set_rules ip6tables "$2" || return 1
    for name in "$1" "$2"; do
        if ipset list "$name" >/dev/null 2>&1; then
            ipset destroy "$name" || { echo "ERROR: cannot destroy $name (still referenced)" >&2; return 1; }
        fi
    done
}

enable_managed_blocklist_timer() {
    local mode="$1"
    systemctl enable --now "${mode}-blacklist-update.timer"
}


vps_fetch_github() {
    local user="$1" repo="$2" branch="$3" path="$4" out="$5"
    local tmp="${out}.tmp.$$" url label err="${out}.curl-error.$$"
    local url_raw="https://raw.githubusercontent.com/${user}/${repo}/${branch}/${path}"
    local url_jsd="https://cdn.jsdelivr.net/gh/${user}/${repo}@${branch}/${path}"

    # GitHub Raw is preferred; jsDelivr is a fallback, not a failed installation.
    # Keep the old file intact unless a replacement is downloaded successfully.
    for label in raw jsdelivr; do
        if [ "$label" = raw ]; then url="$url_raw"; else url="$url_jsd"; fi
        rm -f -- "$tmp" "$err"
        if curl -4 -fsSL --retry 1 --connect-timeout 5 --max-time 30 \
            -o "$tmp" "$url" 2>"$err" && [ -s "$tmp" ]; then
            if ! mv -f -- "$tmp" "$out"; then
                cat "$err" >&2
                rm -f -- "$err"
                return 1
            fi
            rm -f -- "$err"
            if [ "$label" = jsdelivr ]; then
                echo "✓ Download successful via fallback jsDelivr: ${repo}/${path}"
            else
                echo "✓ Download successful via GitHub Raw: ${repo}/${path}"
            fi
            return 0
        fi
        echo "ℹ Source ${label} unavailable, trying next mirror: ${repo}/${path}" >&2
    done
    echo "ERROR: all download sources failed: ${repo}/${path}" >&2
    [ ! -s "$err" ] || cat "$err" >&2
    rm -f -- "$tmp" "$err"
    return 1
}

# =====================================
# МОДУЛЬ 1: БАЗОВАЯ НАСТРОЙКА
# =====================================
setup_base() {
    print_header
    echo "╔══════════════════════════════╗"
    echo "║   Базовая настройка сервера ║"
    echo "╚══════════════════════════════╝"
    echo ""
    echo "  1) Всё сразу (рекомендуется)"
    echo "  2) Только обновление пакетов"
    echo "  3) Только SSH ключ + порт"
    echo "  4) Только UFW"
    echo "  5) Только тюнинг ядра/сети + XanMod (=модуль 14, с ребутом)"
    echo "  6) Только автообновления"
    echo "  7) Только fail2ban"
    echo "  8) Docker + зеркала (Docker registry / github)"
    echo "  9) Подготовка РФ-ноды (зеркала apt→Яндекс + Docker из репо)"
    echo "  0) Назад"
    echo ""
    read -e -p "Выберите [0-9]: " BASE_CHOICE

    case $BASE_CHOICE in
        1)
            do_update_packages
            do_ssh_setup
            do_ufw_setup
            do_sysctl_setup
            do_autoupgrade
            do_fail2ban
            ;;
        2) do_update_packages ;;
        3) do_ssh_setup ;;
        4) do_ufw_setup ;;
        5) do_sysctl_setup ;;
        6) do_autoupgrade ;;
        7) do_fail2ban ;;
        8) do_docker_mirrors ;;
        9) prepare_ru_node; prepare_ru_docker ;;
        0) return ;;
        *) echo "Неверный выбор." && return ;;
    esac

    echo ""
    echo "========================================="
    echo "=== Базовая настройка завершена! ==="
    echo "========================================="
    echo ""
    read -e -p "Перезагрузить сервер? (y/n): " REBOOT
    [[ "$REBOOT" == "y" ]] && reboot
}

# ─────────────────────────────────────────────────────────────────────────
# Подготовка РФ-ноды: подмена зеркал apt на Яндекс, ForceIPv4, defence от
# cloud-init. Срабатывает АВТОМАТИЧЕСКИ, если дефолтное зеркало недоступно
# (deb.debian.org / archive.ubuntu.com таймаутят из РФ). На не-РФ нодах
# ничего не трогает. Детектит дистрибутив (Debian trixie/bookworm, Ubuntu noble).
# ─────────────────────────────────────────────────────────────────────────
RU_MIRROR="${RU_MIRROR:-mirror.yandex.ru}"

_ru_default_mirror_reachable() {
    # true(0) если дефолтное зеркало отвечает — тогда подмена НЕ нужна (не-РФ)
    local host="$1"
    curl -fsS --connect-timeout 6 --max-time 10 -o /dev/null "http://${host}/" 2>/dev/null
}

prepare_ru_node() {
    # определяем дистрибутив и кодовое имя
    local id codename
    if [ -f /etc/os-release ]; then
        id="$(. /etc/os-release; echo "${ID:-}")"
        codename="$(. /etc/os-release; echo "${VERSION_CODENAME:-}")"
    fi
    [ -z "$codename" ] && command -v lsb_release >/dev/null 2>&1 && codename="$(lsb_release -sc 2>/dev/null)"

    # какой upstream проверять на доступность
    local check_host="deb.debian.org"
    [ "$id" = "ubuntu" ] && check_host="archive.ubuntu.com"

    if _ru_default_mirror_reachable "$check_host"; then
        rn_info "Дефолтное зеркало ($check_host) доступно — подмена не требуется."
        return 0
    fi

    rn_warn "Дефолтное зеркало ($check_host) недоступно — вероятно РФ-нода. Переключаю на ${RU_MIRROR}."
    log_section "Подготовка РФ-ноды: зеркала apt → ${RU_MIRROR}"

    # бэкап
    mkdir -p /root/apt-backup 2>/dev/null
    cp -a /etc/apt/sources.list /root/apt-backup/ 2>/dev/null || true
    cp -a /etc/apt/sources.list.d /root/apt-backup/ 2>/dev/null || true

    if [ "$id" = "debian" ]; then
        # Debian 12/13: отключаем deb822 mirrorlist (он тянет deb.debian.org)
        for f in /etc/apt/sources.list.d/debian.sources; do
            [ -f "$f" ] && mv "$f" "$f.disabled" 2>/dev/null
        done
        mv /etc/apt/sources.list /etc/apt/sources.list.disabled 2>/dev/null || true
        [ -z "$codename" ] && codename="trixie"
        cat > /etc/apt/sources.list.d/ru-mirror.list <<EOF
deb http://${RU_MIRROR}/debian ${codename} main contrib non-free non-free-firmware
deb http://${RU_MIRROR}/debian ${codename}-updates main contrib non-free non-free-firmware
deb http://${RU_MIRROR}/debian-security ${codename}-security main contrib non-free non-free-firmware
deb http://${RU_MIRROR}/debian ${codename}-backports main contrib non-free non-free-firmware
EOF
    elif [ "$id" = "ubuntu" ]; then
        [ -z "$codename" ] && codename="noble"
        # Ubuntu 24: deb822 ubuntu.sources — правим URI на Яндекс
        if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
            cp /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources.disabled 2>/dev/null
            cat > /etc/apt/sources.list.d/ubuntu.sources <<EOF
Types: deb
URIs: http://${RU_MIRROR}/ubuntu/
Suites: ${codename} ${codename}-updates ${codename}-backports
Components: main universe restricted multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://${RU_MIRROR}/ubuntu/
Suites: ${codename}-security
Components: main universe restricted multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
        else
            mv /etc/apt/sources.list /etc/apt/sources.list.disabled 2>/dev/null || true
            cat > /etc/apt/sources.list.d/ru-mirror.list <<EOF
deb http://${RU_MIRROR}/ubuntu ${codename} main universe restricted multiverse
deb http://${RU_MIRROR}/ubuntu ${codename}-updates main universe restricted multiverse
deb http://${RU_MIRROR}/ubuntu ${codename}-security main universe restricted multiverse
EOF
        fi
    else
        rn_warn "Дистрибутив '$id' не распознан — зеркала не меняю, продолжаю как есть."
        return 0
    fi

    # IPv6 на РФ-облаках часто не работает → форсим IPv4 для apt
    echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4
    # cloud-init пересоздаёт sources при ребуте — запрещаем
    echo 'apt_preserve_sources_list: true' > /etc/cloud/cloud.cfg.d/99-preserve-sources.cfg 2>/dev/null || true

    if apt-get update 2>&1 | grep -qiE 'Err:|Failed'; then
        rn_warn "apt update с ${RU_MIRROR} дал ошибки — проверь вручную (возможно, зеркало тоже режется)."
    else
        rn_success "apt переключён на ${RU_MIRROR}, обновление прошло."
    fi
}

# Docker: ставит docker.io из репо дистрибутива, если get.docker.com недоступен (РФ).
prepare_ru_docker() {
    if command -v docker >/dev/null 2>&1; then
        return 0   # Docker уже есть
    fi
    if _ru_default_mirror_reachable "get.docker.com"; then
        return 0   # get.docker.com доступен — штатный путь сработает
    fi
    rn_warn "get.docker.com недоступен (РФ) — ставлю docker.io из репозитория дистрибутива."
    apt-get install -y docker.io docker-compose 2>/dev/null || apt-get install -y docker.io 2>/dev/null || true
    if command -v docker >/dev/null 2>&1; then
        systemctl enable --now docker 2>/dev/null || true
        # registry-зеркала для образов (Docker Hub режется из РФ)
        mkdir -p /etc/docker
        if [ ! -f /etc/docker/daemon.json ]; then
            cat > /etc/docker/daemon.json <<'EOF'
{ "registry-mirrors": ["https://mirror.gcr.io", "https://dockerhub.timeweb.cloud"] }
EOF
            systemctl restart docker 2>/dev/null || true
        fi
        rn_success "Docker установлен из репо ($(docker --version 2>/dev/null))."
    else
        rn_warn "docker.io не установился — проверь доступность зеркала apt."
    fi
}

do_update_packages() {
    echo ""
    log_section "Обновление пакетов"
    prepare_ru_node        # авто-подмена зеркал, если дефолт недоступен (РФ)
    apt update && apt upgrade -y || return 1
    apt install -y curl wget htop net-tools unattended-upgrades || return 1
    log "Пакеты обновлены."
}

do_ssh_setup() {
    echo ""
    log_section "Настройка SSH"

    SSH_DIR="/root/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"
    mkdir -p "$SSH_DIR" && chmod 700 "$SSH_DIR"
    touch "$AUTH_KEYS" && chmod 600 "$AUTH_KEYS"

    if ! grep -q "$SSH_KEY" "$AUTH_KEYS"; then
        echo "$SSH_KEY" >> "$AUTH_KEYS"
        echo "SSH ключ добавлен."
    else
        echo "SSH ключ уже существует."
    fi

    echo ""
    read -e -p "SSH порт [${DEFAULT_SSH_PORT}]: " SSH_PORT
    SSH_PORT=${SSH_PORT:-$DEFAULT_SSH_PORT}
    if [[ ! "$SSH_PORT" =~ ^[0-9]{1,5}$ ]] ||
       (( 10#$SSH_PORT < 1 || 10#$SSH_PORT > 65535 )); then
        log "ОШИБКА: недопустимый SSH порт: $SSH_PORT"
        return 1
    fi

    SSHD_CONFIG="/etc/ssh/sshd_config"
    local ssh_backup="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "$SSHD_CONFIG" "$ssh_backup" || return 1

    sed -i "s/^#*Port .*/Port ${SSH_PORT}/" "$SSHD_CONFIG"
    grep -q "^Port" "$SSHD_CONFIG" || echo "Port ${SSH_PORT}" >> "$SSHD_CONFIG"
    sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' "$SSHD_CONFIG"
    sed -i 's/^#*PubkeyAuthentication .*/PubkeyAuthentication yes/' "$SSHD_CONFIG"
    sed -i 's/^#*PermitRootLogin .*/PermitRootLogin prohibit-password/' "$SSHD_CONFIG"
    sed -i 's/^#*X11Forwarding .*/X11Forwarding no/' "$SSHD_CONFIG"
    sed -i 's/^#*MaxAuthTries .*/MaxAuthTries 5/' "$SSHD_CONFIG"
    sed -i 's/^#*LoginGraceTime .*/LoginGraceTime 30/' "$SSHD_CONFIG"
    grep -q "^KerberosAuthentication" "$SSHD_CONFIG" || echo "KerberosAuthentication no" >> "$SSHD_CONFIG"
    grep -q "^GSSAPIAuthentication" "$SSHD_CONFIG" || echo "GSSAPIAuthentication no" >> "$SSHD_CONFIG"

    # Never restart sshd with an invalid configuration.
    if ! /usr/sbin/sshd -t; then
        log "ОШИБКА: sshd -t не пройден; возвращаем резервную копию."
        cp -a "$ssh_backup" "$SSHD_CONFIG" || true
        return 1
    fi
    if ! systemctl reload-or-restart ssh; then
        log "ОШИБКА: не удалось применить SSH конфигурацию; восстанавливаем файл."
        cp -a "$ssh_backup" "$SSHD_CONFIG" || true
        systemctl reload-or-restart ssh || true
        return 1
    fi
    sleep 3

    if systemctl is-active --quiet ssh; then
        log "SSH запущен на порту ${SSH_PORT}."
    else
        log "ОШИБКА: SSH не запустился!"
        return 1
    fi
}

do_ufw_setup() {
    echo ""
    log_section "Настройка UFW"

    # Устанавливаем ufw без удаления iptables-persistent
    apt install -y ufw --no-remove || return 1

    echo ""
    read -e -p "SSH порт для UFW [${DEFAULT_SSH_PORT}]: " UFW_SSH_PORT
    UFW_SSH_PORT=${UFW_SSH_PORT:-$DEFAULT_SSH_PORT}

    echo ""
    echo "Дополнительные порты (через пробел, например: 443 8443 80 5222)"
    echo "Оставьте пустым если не нужны"
    read -e -p "Дополнительные порты: " EXTRA_PORTS

    # Preserve existing rules and allow SSH before enabling UFW.
    if [[ ! "$UFW_SSH_PORT" =~ ^[0-9]{1,5}$ ]] ||
       (( 10#$UFW_SSH_PORT < 1 || 10#$UFW_SSH_PORT > 65535 )); then
        echo "ОШИБКА: недопустимый UFW SSH порт: $UFW_SSH_PORT"
        return 1
    fi
    ufw allow "${UFW_SSH_PORT}/tcp" || return 1
    ufw default deny incoming || return 1
    ufw default allow outgoing || return 1

    # Existing rules are preserved; no reset or blind SSH rule deletion.
    echo "  ✓ SSH ${UFW_SSH_PORT}/tcp"

    if [ -n "$EXTRA_PORTS" ]; then
        for port in $EXTRA_PORTS; do
            if [[ ! "$port" =~ ^[0-9]{1,5}$ ]] ||
               (( 10#$port < 1 || 10#$port > 65535 )); then
                echo "ОШИБКА: недопустимый дополнительный порт: $port"
                return 1
            fi
            ufw allow "${port}/tcp" || return 1
            echo "  ✓ ${port}/tcp"
        done
    fi

    # Do not delete port 22 blindly: another SSH listener may still use it.

    ufw --force enable || return 1

    if ufw status | grep -q "Status: active"; then
        echo "✓ UFW активен."
        ufw status numbered
    else
        echo "ОШИБКА: UFW не включился."
        return 1
    fi
}

do_sysctl_setup() {
    echo ""
    log_section "Тюнинг ядра/сети (полный, из модуля 14)"
    # Переиспользуем отлаженные функции модуля 14 вместо старого кривого блока.
    # Старый sysctl-блend (rp_filter=1, icmp_echo_ignore_all=1, nofile 65535)
    # вычищается из /etc/sysctl.conf функцией kt_strip_old_sysctl внутри kt_apply_sysctl.
    kt_apply_sysctl       # sysctl + conntrack по RAM (rp_filter=2, BBR/fq, буферы)
    kt_apply_limits       # nofile/nproc → 1048576
    kt_apply_rps          # RPS/RFS/XPS
    kt_apply_nic_misc     # NIC tune + THP off + governor + irqbalance

    # XanMod (BBRv3) — в режиме базовой настройки ставим автоматически, с ребутом.
    KT_ASSUME_YES=1 kt_install_xanmod

    echo "✓ Полный тюнинг применён (sysctl/conntrack/лимиты/RPS/NIC + XanMod)."
    if [ "${KT_REBOOT_NEEDED:-0}" = "1" ]; then
        echo ""
        rn_warn "XanMod установлен — ТРЕБУЕТСЯ ПЕРЕЗАГРУЗКА для активации BBRv3."
        rn_warn "После reboot проверь: uname -r (должно содержать xanmod)."
    fi
}

do_autoupgrade() {
    echo ""
    log_section "Автообновления безопасности"
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    log "Автообновления настроены."
}

do_fail2ban() {
    echo ""
    log_section "Настройка fail2ban"
    apt install -y fail2ban

    echo ""
    read -e -p "SSH порт для fail2ban [${DEFAULT_SSH_PORT}]: " F2B_PORT
    F2B_PORT=${F2B_PORT:-$DEFAULT_SSH_PORT}
    if [[ ! "$F2B_PORT" =~ ^[0-9]{1,5}$ ]] ||
       (( 10#$F2B_PORT < 1 || 10#$F2B_PORT > 65535 )); then
        echo "ОШИБКА: недопустимый порт Fail2Ban: $F2B_PORT"
        return 1
    fi

    echo ""
    echo "Режим блокировки:"
    echo "  1) Мягкий  — 10 попыток, бан 10 минут  (рекомендуется)"
    echo "  2) Средний — 5 попыток,  бан 1 час"
    echo "  3) Жёсткий — 3 попытки,  бан 24 часа"
    read -e -p "Выберите [1-3]: " F2B_MODE

    case $F2B_MODE in
        2) BANTIME=3600;  MAXRETRY=5;  FINDTIME=3600 ;;
        3) BANTIME=86400; MAXRETRY=3;  FINDTIME=600  ;;
        *) BANTIME=600;   MAXRETRY=10; FINDTIME=3600 ;;
    esac

    if [ -f /etc/fail2ban/jail.local ]; then
        cp -a /etc/fail2ban/jail.local "/etc/fail2ban/jail.local.bak.$(date +%Y%m%d%H%M%S)" || return 1
    fi
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime  = ${BANTIME}
findtime = ${FINDTIME}
maxretry = ${MAXRETRY}
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled  = true
backend  = systemd
port     = ${F2B_PORT}
maxretry = ${MAXRETRY}
findtime = ${FINDTIME}
bantime  = ${BANTIME}
EOF

    if ! fail2ban-client -t; then
        echo "ОШИБКА: конфигурация Fail2Ban не прошла проверку."
        return 1
    fi
    systemctl enable fail2ban || return 1
    systemctl restart fail2ban || return 1

    if systemctl is-active --quiet fail2ban; then
        echo "✓ fail2ban активен."
        echo "  Порт SSH:  ${F2B_PORT}"
        echo "  Попыток:   ${MAXRETRY}"
        echo "  Окно:      ${FINDTIME} сек"
        echo "  Бан:       ${BANTIME} сек"
        echo ""
        echo "Управление:"
        echo "  Статус:    fail2ban-client status sshd"
        echo "  Разбанить: fail2ban-client set sshd unbanip <IP>"
    else
        echo "ОШИБКА: fail2ban не запустился!"
    fi
}

# Docker + зеркала (registry mirror Docker / github) — базовая настройка VPS.
# Использует функции rn_install_docker_get / rn_setup_docker_mirror /
# rn_setup_github_mirror (определены в модуле нод; к моменту вызова из меню
# все функции уже загружены в память).
do_docker_mirrors() {
    echo ""
    log_section "Docker + зеркала"
    echo "  Шаги (каждый с подтверждением):"
    echo "    1. Установка Docker (get.docker.com), если не установлен"
    echo "    2. Зеркала Docker registry (с проверкой доступности)"
    echo "    3. github-зеркала (опционально)"
    echo ""

    read -rep "1) Установить/проверить Docker? [Y/n]: " _dm_s1
    if rn_is_yes "$_dm_s1"; then rn_install_docker_get; fi

    echo ""
    read -rep "2) Настроить зеркала Docker registry? [y/N]: " _dm_s2
    if [[ "${_dm_s2,,}" =~ ^(y|yes)$ ]]; then rn_setup_docker_mirror; fi

    echo ""
    read -rep "3) Настроить github-зеркала? [y/N]: " _dm_s3
    if [[ "${_dm_s3,,}" =~ ^(y|yes)$ ]]; then rn_setup_github_mirror; fi

    echo ""
    log "Docker + зеркала: настройка завершена."
}

# =====================================
# МОДУЛЬ 2: IPv6
# =====================================
# Read-only audit: never change firewall/routing as a side effect of inspection.
vps_ipv6_audit() {
    echo "=== IPv6 interfaces and routes ==="
    ip -6 -brief address show 2>/dev/null || true
    ip -6 route show default 2>/dev/null || true
    echo "=== IPv6 kernel controls ==="
    for key in all default lo; do
        if [ -r "/proc/sys/net/ipv6/conf/$key/disable_ipv6" ]; then
            printf '%s disable_ipv6=%s\n' "$key" "$(cat "/proc/sys/net/ipv6/conf/$key/disable_ipv6")"
        fi
    done
    echo "=== UFW configuration and policies ==="
    if command -v ufw >/dev/null 2>&1; then
        grep -E '^(IPV6|DEFAULT_(INPUT|OUTPUT|FORWARD)_POLICY)=' /etc/default/ufw 2>/dev/null || true
        ufw status verbose 2>/dev/null || true
        for family in iptables ip6tables; do
            command -v "$family" >/dev/null 2>&1 || continue
            echo "--- $family filter chain policies ---"
            "$family" -S INPUT 2>/dev/null | grep -E '^-P |^-A INPUT' | head -n 15 || true
            "$family" -S OUTPUT 2>/dev/null | grep -E '^-P |^-A OUTPUT' | head -n 15 || true
            "$family" -S FORWARD 2>/dev/null | grep -E '^-P |^-A FORWARD' | head -n 15 || true
        done
    fi
    echo "=== NetBird service and interface ==="
    systemctl is-active netbird 2>/dev/null || true
    ip -brief link show 2>/dev/null | grep -E '(^|[[:space:]])wt[0-9]+|netbird' || true
    if command -v netbird >/dev/null 2>&1; then netbird status 2>/dev/null | head -n 12 || true; fi
}

setup_ipv6() {
    print_header
    echo "╔══════════════════════════╗"
    echo "║   Управление IPv6       ║"
    echo "╚══════════════════════════╝"
    echo ""
    vps_ipv6_audit
    echo ""
    echo "  1) Отключить IPv6"
    echo "  2) Включить IPv6"
    echo "  3) Повторить диагностику (без изменений)"
    echo "  0) Назад"
    echo ""
    local choice
    read -e -p "Выберите [0-3]: " choice
    case "$choice" in
        0) return 0 ;;
        3) vps_ipv6_audit; return 0 ;;
        1|2)
            # Changing kernel IPv6 and UFW independently can strand connections
            # (including NetBird relay/P2P) or expose an unfiltered address family.
            # Fail closed until a validated transactional migration exists.
            echo "ОПЕРАЦИЯ ЗАБЛОКИРОВАНА: автоматическая смена IPv6 небезопасна."
            echo "Не изменены sysctl, GRUB, UFW, INPUT/OUTPUT/FORWARD и NetBird."
            echo "Необходимо отдельно проверить IPv6 default route, UFW IPv4/IPv6"
            echo "и сохранение существующих NetBird маршрутов и соединений."
            return 1
            ;;
        *) echo "Неверный выбор."; return 1 ;;
    esac
}

# =====================================
# МОДУЛЬ 3: CROWDSEC + TRAFFIC-GUARD
# =====================================
setup_crowdsec() {
    print_header
    echo "╔══════════════════════════════════════╗"
    echo "║   CrowdSec Manager                   ║"
    echo "╚══════════════════════════════════════╝"
    echo ""
    echo "  1) Установить"
    echo "  2) Удалить"
    echo "  3) Статус"
    echo "  0) Назад"
    echo ""
    read -e -p "Выберите [0-3]: " CS_CHOICE

    case $CS_CHOICE in
        1) crowdsec_install ;;
        2) crowdsec_uninstall ;;
        3) crowdsec_status ;;
        0) return ;;
        *) echo "Неверный выбор." ;;
    esac
}

crowdsec_config_fingerprint() {
    python3 - <<'PYFINGERPRINT'
from pathlib import Path
import hashlib
import os
import sys

root = Path("/etc/crowdsec")

files = [
    root / "config.yaml",
    root / "local_api_credentials.yaml",
    root / "acquis.yaml",
]

directories = [
    "acquis.d",
    "collections",
    "parsers",
    "scenarios",
    "postoverflows",
    "contexts",
]

try:
    paths = list(files)

    for directory in directories:
        base = root / directory
        if base.is_dir():
            paths.extend(
                p for p in base.rglob("*")
                if p.is_file() or p.is_symlink()
            )

    digest = hashlib.sha256()
    count = 0

    for path in sorted(set(paths), key=str):
        if not path.exists() and not path.is_symlink():
            continue

        relative = str(path.relative_to(root))
        digest.update(b"PATH\0" + os.fsencode(relative) + b"\0")

        if path.is_symlink():
            digest.update(
                b"LINK\0" + os.fsencode(os.readlink(path)) + b"\0"
            )

        if not path.is_file():
            raise RuntimeError(f"Invalid file: {relative}")

        data = path.read_bytes()
        digest.update(b"DATA\0")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        count += 1

    if count == 0:
        raise RuntimeError("No CrowdSec configuration files found")

    print(digest.hexdigest())

except Exception as error:
    print(f"Fingerprint error: {error}", file=sys.stderr)
    sys.exit(1)
PYFINGERPRINT
}

# Install a Hub collection without overwriting Debian's packaged/tainted items.
# A stale Hub index can cause "invalid download hash" on freshly installed systems.
# Refresh the index only on that specific failure and retry once.
crowdsec_ensure_collection() {
    local collection="$1" required="$2" output rc
    if cscli collections inspect "$collection" >/dev/null 2>&1; then
        echo "✓ Коллекция уже установлена: $collection (штатные/tainted файлы сохраняем)"
        return 0
    fi

    output=$(mktemp /tmp/crowdsec-hub-install.XXXXXXXX) || return 1
    echo "Установка коллекции: $collection"
    if timeout 90 cscli collections install "$collection" >"$output" 2>&1; then
        cat "$output"
        rm -f "$output"
        return 0
    fi

    if grep -Eiq 'invalid download hash|Downloaded version doesn.t match index' "$output"; then
        echo "WARN: устаревший индекс CrowdSec Hub; обновляем и повторяем один раз."
        cat "$output"
        if timeout 90 cscli hub update; then
            if timeout 90 cscli collections install "$collection" >"$output" 2>&1; then
                cat "$output"
                rm -f "$output"
                return 0
            fi
        fi
    fi

    cat "$output" >&2
    if grep -Eiq 'tainted|won.t enable unless --force' "$output"; then
        echo "WARN: $collection имеет локальные изменения Debian; --force не применяется." >&2
    fi
    rm -f "$output"
    if [ "$required" = required ]; then
        echo "ОШИБКА: обязательная коллекция $collection не установлена." >&2
        return 1
    fi
    echo "ПРЕДУПРЕЖДЕНИЕ: дополнительная коллекция $collection пропущена."
    return 0
}

crowdsec_install() {
    echo ""
    echo "=== [1/7] Установка CrowdSec ==="

    # Фиксируем наличие конфигурации до установки пакетов.
    local crowdsec_config_existed=0
    if [ -f /etc/crowdsec/config.yaml ]; then
        crowdsec_config_existed=1
    fi

    # ── CrowdSec APT repository ──
    # На чистой Debian пакет firewall-bouncer отсутствует
    # в стандартных репозиториях.
    local cs_repo_file="/etc/apt/sources.list.d/crowdsec_crowdsec.list"
    local cs_key_file="/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg"
    local cs_expected_fp="6A89E3C2303A901A889971D3376ED5326E93CD0C"

    local cs_bouncer_pkg="crowdsec-firewall-bouncer-iptables"
    local cs_package_source="crowdsec-upstream"
    if apt-cache policy crowdsec | grep -Eq 'Candidate: [^ (]+$' &&
       apt-cache policy crowdsec-firewall-bouncer | grep -Eq 'Candidate: [^ (]+$'; then
        cs_bouncer_pkg="crowdsec-firewall-bouncer"
        cs_package_source="debian"
        echo "✓ CrowdSec + Firewall Bouncer доступны из системных зеркал APT."
    elif ! apt-cache policy "$cs_bouncer_pkg" |
        grep -Eq 'Candidate: [^ (]+$'; then

        echo "Подключение официального APT-репозитория CrowdSec..."

        if ! apt-get install -y --no-remove ca-certificates curl gnupg; then
            echo "ОШИБКА: не удалось установить зависимости репозитория."
            return 1
        fi

        install -d -m 0755 /etc/apt/keyrings

        local cs_tmp_key
        cs_tmp_key="$(mktemp)" || return 1

        if ! curl -fsSL --retry 3 --connect-timeout 10 --max-time 45 \
            -o "$cs_tmp_key" \
            "https://packagecloud.io/crowdsec/crowdsec/gpgkey"; then
            rm -f "$cs_tmp_key"
            echo "ОШИБКА: не удалось скачать ключ CrowdSec."
            return 1
        fi

        local cs_actual_fp
        cs_actual_fp="$(gpg --batch --show-keys --with-colons "$cs_tmp_key" 2>/dev/null |
            awk -F: '$1 == "fpr" {print $10; exit}')"

        if [ "$cs_actual_fp" != "$cs_expected_fp" ]; then
            rm -f "$cs_tmp_key"
            echo "ОШИБКА: fingerprint ключа CrowdSec не совпадает!"
            return 1
        fi

        if ! gpg --batch --yes --dearmor \
            -o "$cs_key_file" "$cs_tmp_key"; then
            rm -f "$cs_tmp_key"
            echo "ОШИБКА: не удалось установить ключ CrowdSec."
            return 1
        fi
        rm -f "$cs_tmp_key"
        chmod 0644 "$cs_key_file"

        printf '%s\n' \
            "deb [signed-by=$cs_key_file] https://packagecloud.io/crowdsec/crowdsec/any/ any main" \
            > "$cs_repo_file"

        if ! apt-get update; then
            echo "ОШИБКА: обновление APT после добавления CrowdSec."
            return 1
        fi
    fi

    # ── PREFLIGHT: пакеты APT и доступность CrowdSec Hub ──
    # Удалённый установочный скрипт не используется.
    # Существующий firewall не изменяем.
    local cs_package
    for cs_package in crowdsec "$cs_bouncer_pkg"; do
        if ! apt-cache policy "$cs_package" |
            grep -Eq 'Candidate: [^ (]+$'; then
            echo "ОШИБКА: пакет $cs_package недоступен через APT."
            return 1
        fi
    done

    # Debian 13 ships an offline CrowdSec Hub with the distribution packages.
    # A network probe to hub.crowdsec.net is not a reliable precondition:
    # restricted VPS networks can install from APT even when Hub is blocked.
    # Never block Debian package installation solely because Hub is unreachable.
    if [ "$cs_package_source" = "debian" ]; then
        echo "✓ CrowdSec доступен через APT; онлайн Hub для установки не требуется."
    else
        echo "ℹ CrowdSec Hub может быть недоступен; установка из APT будет продолжена."
        echo "  Отсутствующие Hub-коллекции будут проверены отдельно."
    fi

    # CrowdSec работает совместно с существующим firewall.
    # Не устанавливаем iptables-persistent и не изменяем UFW.
    # Пакеты устанавливаются без разрешения удалять существующие.
    if ! apt-get install -y --no-remove curl; then
        echo "ОШИБКА: не удалось установить curl без удаления пакетов."
        return 1
    fi

    if ! apt-get install -y --no-remove crowdsec; then
        echo "ОШИБКА: установка CrowdSec требует удаления других пакетов или завершилась ошибкой."
        return 1
    fi
    sleep 3

    if [ ! -f /etc/crowdsec/config.yaml ]; then
        echo "ОШИБКА: config.yaml не создался!"
        return 1
    fi
    echo "✓ CrowdSec установлен."

    echo "=== [2/7] Установка коллекций ==="
    # Debian ships an offline Hub and modifies some bundled parsers.
    # An installed "tainted" collection is deliberately preserved.
    local collection
    for collection in crowdsecurity/linux crowdsecurity/sshd; do
        crowdsec_ensure_collection "$collection" required || return 1
    done

    for collection in \
        crowdsecurity/iptables \
        crowdsecurity/base-http-scenarios \
        crowdsecurity/whitelist-good-actors; do
        crowdsec_ensure_collection "$collection" optional
    done

    echo "=== [3/7] Docker acquisition (проверка) ==="
    # Не подключаем произвольные контейнеры как syslog.
    # Для Docker нужны подходящие парсеры и явный выбор контейнеров.
    # Существующие acquisition-файлы не изменяем.
    echo "Docker-логи автоматически не подключаются."

    echo "=== [3/7] SSH journald acquisition ==="

    # Не дублируем существующие SSH acquisition.
    # На Debian 13 sshd-session пишет в journald.
    local ssh_acquisition_found=0
    local acquisition_file

    for acquisition_file in /etc/crowdsec/acquis.yaml /etc/crowdsec/acquis.d/*.yaml; do
        [ -f "$acquisition_file" ] || continue

        # Проверяем активные строки конфигурации, а не комментарии.
        if grep -Eq '^[[:space:]]*source:[[:space:]]*journalctl([[:space:]]|$)' "$acquisition_file" &&
           grep -Eq '^[[:space:]]*-[[:space:]]*"?(_SYSTEMD_UNIT=ssh\.service|SYSLOG_IDENTIFIER=sshd-session)' "$acquisition_file"; then
            echo "Обнаружен SSH acquisition через journald: $acquisition_file"
            ssh_acquisition_found=1
            break
        fi

        if [ -f /var/log/auth.log ] &&
           grep -Eq '^[[:space:]]*-[[:space:]]*/var/log/auth\.log([[:space:]]|$)' "$acquisition_file"; then
            echo "Обнаружен SSH acquisition через auth.log: $acquisition_file"
            ssh_acquisition_found=1
            break
        fi
    done

    if (( ssh_acquisition_found == 0 )); then
        mkdir -p /etc/crowdsec/acquis.d || return 1

        cat > /etc/crowdsec/acquis.d/sshd-journald.yaml <<'EOF'
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=ssh.service"
labels:
  type: syslog
EOF

        echo "✓ Добавлен SSH acquisition через journald."
    else
        echo "Существующий SSH acquisition сохраняем без изменений."
    fi

    echo "=== [3/7] Проверка SSH-парсера ==="

    # Debian 13 provides crowdsecurity/sshd-logs with sshd-session support
    # already backported. Do not depend on upstream-only parser filenames,
    # or rewrite a distribution-managed parser.
    if ! cscli parsers inspect crowdsecurity/sshd-logs >/dev/null 2>&1; then
        echo "ОШИБКА: SSH parser crowdsecurity/sshd-logs не установлен."
        echo "Проверьте: cscli parsers list"
        return 1
    fi
    echo "✓ SSH parser crowdsecurity/sshd-logs установлен."

    if ! crowdsec -t; then
        echo "ОШИБКА: проверка конфигурации CrowdSec не пройдена."
        return 1
    fi

    echo "=== [4/7] Настройка порта LAPI ==="

    local lapi_listen_count
    lapi_listen_count=$(grep -Ec '^[[:space:]]*listen_uri:' /etc/crowdsec/config.yaml) || true

    if [[ "$lapi_listen_count" != "1" ]]; then
        echo "ОШИБКА: ожидался ровно один listen_uri в /etc/crowdsec/config.yaml; найдено: $lapi_listen_count"
        return 1
    fi

    local existing_lapi
    existing_lapi=$(sed -nE \
        's/^[[:space:]]*listen_uri:[[:space:]]*(127\.0\.0\.1|localhost|0\.0\.0\.0):([0-9]+).*$/\2/p' \
        /etc/crowdsec/config.yaml | head -n 1)

    if (( crowdsec_config_existed == 1 )); then
        if [[ ! "$existing_lapi" =~ ^[0-9]+$ ]] ||
           (( 10#$existing_lapi < 1 || 10#$existing_lapi > 65535 )); then
            echo "ОШИБКА: существующий LAPI-порт не распознан."
            return 1
        fi

        LAPI_PORT="$existing_lapi"
        if grep -Eq '^[[:space:]]*listen_uri:[[:space:]]*0\.0\.0\.0:' /etc/crowdsec/config.yaml; then
            echo "ОШИБКА: существующий LAPI слушает 0.0.0.0; проверьте вручную."
            return 1
        fi
        log "Сохраняем существующий LAPI-порт: $LAPI_PORT"
    else
        if ! LAPI_PORT=$(find_free_port); then
            echo "ОШИБКА: не удалось выбрать LAPI-порт."
            return 1
        fi

        if [[ ! "$existing_lapi" =~ ^[0-9]+$ ]]; then
            echo "ОШИБКА: исходный listen_uri не распознан."
            return 1
        fi

        if ! sed -i -E \
            "s|^([[:space:]]*)listen_uri:[[:space:]]*.*|\1listen_uri: 127.0.0.1:${LAPI_PORT}|" \
            /etc/crowdsec/config.yaml; then
            echo "ОШИБКА: не удалось изменить listen_uri."
            return 1
        fi

        if ! grep -Eq "^[[:space:]]*listen_uri:[[:space:]]*127\.0\.0\.1:${LAPI_PORT}([[:space:]]|$)" /etc/crowdsec/config.yaml; then
            echo "ОШИБКА: LAPI listen_uri не установлен корректно."
            return 1
        fi
        log "Выбран LAPI-порт: $LAPI_PORT"
    fi

    if [ ! -f /etc/crowdsec/local_api_credentials.yaml ]; then
        echo "ОШИБКА: local_api_credentials.yaml отсутствует."
        return 1
    fi

    # Update only the URL field; preserve machine login and password.
    local credentials_file="/etc/crowdsec/local_api_credentials.yaml"
    local credentials_url_count

    credentials_url_count=$(grep -Ec '^[[:space:]]*url:' "$credentials_file") || true

    if [[ "$credentials_url_count" != "1" ]]; then
        echo "ОШИБКА: ожидался ровно один url в credentials; найдено: $credentials_url_count"
        return 1
    fi

    if ! grep -Eq '^[[:space:]]*url:[[:space:]]*http://(127\.0\.0\.1|localhost):[0-9]+/?[[:space:]]*$' "$credentials_file"; then
        echo "ОШИБКА: URL локального API имеет неожиданный формат."
        return 1
    fi

    local credentials_source_port
    credentials_source_port=$(sed -nE \
        's#^[[:space:]]*url:[[:space:]]*http://(127\.0\.0\.1|localhost):([0-9]+)/?[[:space:]]*$#\2#p' \
        "$credentials_file")

    if [[ ! "$credentials_source_port" =~ ^[0-9]{1,5}$ ]]; then
        echo "ОШИБКА: некорректный формат порта локального API."
        return 1
    fi

    if (( 10#$credentials_source_port < 1 || 10#$credentials_source_port > 65535 )); then
        echo "ОШИБКА: порт локального API вне диапазона 1–65535."
        return 1
    fi

    if ! sed -i -E \
        "s#^([[:space:]]*url:[[:space:]]*)http://[^[:space:]]+#\1http://127.0.0.1:${LAPI_PORT}#" \
        "$credentials_file"; then
        echo "ОШИБКА: не удалось обновить URL локального API."
        return 1
    fi

    if ! grep -Eq "^[[:space:]]*url:[[:space:]]*http://127\.0\.0\.1:${LAPI_PORT}[[:space:]]*$" "$credentials_file"; then
        echo "ОШИБКА: URL локального API не установлен корректно."
        return 1
    fi

    echo "Порт LAPI: ${LAPI_PORT}"

    echo "=== [5/7] Запуск CrowdSec ==="
    if ! systemctl enable crowdsec; then
        echo "ОШИБКА: не удалось включить CrowdSec."
        return 1
    fi

    if ! systemctl restart crowdsec; then
        echo "ОШИБКА: не удалось запустить CrowdSec."
        journalctl -u crowdsec -n 50 --no-pager
        echo "Подсказка: проверьте journald acquisition и целостность журналов: journalctl --verify"
        return 1
    fi

    sleep 5

    if ! systemctl is-active --quiet crowdsec; then
        echo "ОШИБКА: CrowdSec не запустился!"
        journalctl -u crowdsec -n 20 --no-pager
        return 1
    fi

    echo "=== [6/7] Установка Firewall Bouncer ==="

    # LAPI уже настроен, CrowdSec запущен.
    # postinst пакета самостоятельно создаёт регистрацию и API-ключ.
    if ! apt-get install -y --no-remove "$cs_bouncer_pkg" ipset; then
        echo "ОШИБКА: установка Firewall Bouncer завершилась неудачно."
        return 1
    fi

    # Пакет Bouncer самостоятельно регистрируется через postinst.
    # Не создаём вторую регистрацию и не перевыпускаем API-ключ.
    local bouncer_config="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
    local bouncer_id_file="${bouncer_config}.id"
    if [ ! -f "$bouncer_config" ]; then
        echo "ОШИБКА: конфигурация Firewall Bouncer отсутствует."
        return 1
    fi

    # Проверяем наличие ключа, не выводя секрет в терминал.
    if ! awk '
        /^[[:space:]]*api_key:[[:space:]]*/ {
            sub(/^[[:space:]]*api_key:[[:space:]]*/, "")
            gsub(/^[[:space:]"]+|[[:space:]"]+$/, "")
            if ($0 != "" && $0 != "<API_KEY>" && $0 != "$API_KEY") valid=1
        }
        END {exit !valid}
    ' "$bouncer_config"; then
        echo "ОШИБКА: API-ключ Bouncer отсутствует или содержит заглушку."
        return 1
    fi

    if [ ! -s "$bouncer_id_file" ]; then
        echo "ПРЕДУПРЕЖДЕНИЕ: файл идентификатора Bouncer отсутствует."
        echo "Существующую регистрацию и API-ключ сохраняем."
    fi

    # Изменяем только адрес локального API.
    # Без обратных ссылок sed: так исключаем ошибки экранирования.
    if ! sed -i -E \
        "s|^[[:space:]]*api_url:[[:space:]]*.*|api_url: http://127.0.0.1:${LAPI_PORT}/|" \
        "$bouncer_config"; then
        echo "ОШИБКА: не удалось настроить адрес LAPI для Bouncer."
        return 1
    fi

    if ! grep -Fxq "api_url: http://127.0.0.1:${LAPI_PORT}/" "$bouncer_config"; then
        echo "ОШИБКА: адрес LAPI не записан в конфигурацию Bouncer."
        return 1
    fi

    log "Используем API-ключ, созданный пакетом Bouncer ($cs_package_source)."
    echo "=== [6/7] Запуск установленного Bouncer ==="
    if ! systemctl enable crowdsec-firewall-bouncer; then
        echo "ОШИБКА: не удалось включить Firewall Bouncer."
        return 1
    fi

    if ! systemctl restart crowdsec-firewall-bouncer; then
        echo "ОШИБКА: не удалось запустить Firewall Bouncer."
        journalctl -u crowdsec-firewall-bouncer -n 30 --no-pager
        return 1
    fi

    sleep 3

    if ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
        echo "ОШИБКА: Bouncer не запустился!"
        journalctl -u crowdsec-firewall-bouncer -n 20 --no-pager
        return 1
    fi

    echo "=== [7/7] Проверка существующего firewall ==="

    # Не сбрасываем, не включаем и не перезапускаем UFW.
    # Не перезаписываем общие файлы iptables/ipset.
    if command -v ufw >/dev/null 2>&1; then
        ufw status
    else
        echo "UFW не установлен — состояние firewall не изменяем."
    fi

    echo ""
    echo "========================================="
    echo "=== CrowdSec установлен ==="
    echo "========================================="
    echo "LAPI порт: ${LAPI_PORT}"
    echo ""
    cscli bouncers list
    echo ""
    echo "Мониторинг: cscli decisions list"
    echo "Метрики:    cscli metrics"
}

crowdsec_uninstall() {
    echo ""
    echo "=== Удаление CrowdSec ==="
    read -r -e -p "Удалить CrowdSec и Firewall Bouncer? (y/n): " CONFIRM
    [[ "$CONFIRM" != "y" ]] && echo "Отменено." && return 0

    # Сохраняем состояние перед удалением.
    local backup_dir
    backup_dir="/root/crowdsec-uninstall-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir" || return 1
    chmod 700 "$backup_dir"
    iptables-save > "$backup_dir/iptables.v4" || return 1
    ip6tables-save > "$backup_dir/iptables.v6" || return 1
    ipset save > "$backup_dir/ipset.save" || return 1

    echo "Резервная копия: $backup_dir"

    # Останавливаем только CrowdSec.
    systemctl stop crowdsec-firewall-bouncer 2>/dev/null || true
    systemctl stop crowdsec 2>/dev/null || true

    # Удаляем пакеты до ручной очистки правил.
    if ! apt-get purge -y crowdsec-firewall-bouncer-iptables crowdsec; then
        echo "ОШИБКА: не удалось удалить пакеты CrowdSec."
        return 1
    fi

    # Удаляем только правила CrowdSec.
    local cmd chain
    for cmd in iptables ip6tables; do
        while "$cmd" -C INPUT -j CROWDSEC_CHAIN 2>/dev/null; do
            "$cmd" -D INPUT -j CROWDSEC_CHAIN || return 1
        done

        if "$cmd" -nL CROWDSEC_CHAIN >/dev/null 2>&1; then
            "$cmd" -F CROWDSEC_CHAIN || return 1
            "$cmd" -X CROWDSEC_CHAIN || return 1
        fi
    done

    # Удаляем только известный IPSet CrowdSec.
    if ipset list crowdsec-blacklists-0 >/dev/null 2>&1; then
        ipset destroy crowdsec-blacklists-0 || return 1
    fi

    systemctl daemon-reload

    # Не трогаем UFW, AntiScan, vpsguard, AS/Threat и /etc/ipset.conf.
    echo ""
    echo "===== ПРОВЕРКА ====="
    if dpkg-query -W -f='${db:Status-Abbrev}' crowdsec \
        crowdsec-firewall-bouncer-iptables 2>/dev/null | grep -q '^ii'; then
        echo "ОШИБКА: остались установленные пакеты CrowdSec."
        return 1
    fi

    if iptables -S INPUT | grep -q CROWDSEC_CHAIN ||
       ip6tables -S INPUT | grep -q CROWDSEC_CHAIN; then
        echo "ОШИБКА: остались ссылки на CROWDSEC_CHAIN."
        return 1
    fi

    echo "✓ CrowdSec удалён."
    echo "✓ Общие файлы и защитные модули не удалялись."
    echo "Резервная копия: $backup_dir"
}

crowdsec_status() {
    echo ""
    echo "=== Статус CrowdSec ==="
    systemctl status crowdsec --no-pager | head -4
    echo ""
    systemctl status crowdsec-firewall-bouncer --no-pager | head -4
    echo ""
    echo "=== Bouncers ==="
    cscli bouncers list 2>/dev/null || echo "CrowdSec не установлен"
    echo ""
    echo "=== Активные блокировки ==="
    cscli decisions list 2>/dev/null || echo "Нет данных"
    echo ""
    echo "=== Метрики CrowdSec ==="
    cscli metrics 2>/dev/null | head -25 || echo "Нет данных"
}

# =====================================
# МОДУЛЬ 4: СТАТУС СИСТЕМЫ
# =====================================
show_system_status() {
    print_header
    echo "╔══════════════════════╗"
    echo "║   Статус системы    ║"
    echo "╚══════════════════════╝"
    echo ""

    echo "--- SSH ---"
    ss -tlnp | grep sshd || echo "SSH не найден"

    echo ""
    echo "--- UFW ---"
    if command -v ufw &>/dev/null; then
        ufw status 2>/dev/null
    else
        echo "UFW не установлен"
    fi

    echo ""
    echo "--- IPv6 ---"
    # Проверяем через /proc если доступно, иначе через sysctl.conf
    if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
        if cat /proc/sys/net/ipv6/conf/all/disable_ipv6 | grep -q "1"; then
            echo "IPv6: ОТКЛЮЧЁН (активно)"
        else
            echo "IPv6: ВКЛЮЧЁН (активно)"
        fi
    elif grep -q "net.ipv6.conf.all.disable_ipv6 = 1" /etc/sysctl.conf 2>/dev/null; then
        echo "IPv6: ОТКЛЮЧЁН (после перезагрузки)"
    else
        echo "IPv6: ВКЛЮЧЁН"
    fi

    echo ""
    echo "--- BBR ---"
    sysctl net.ipv4.tcp_congestion_control 2>/dev/null || echo "Нет данных"

    echo ""
    echo "--- CrowdSec ---"
    if systemctl is-active --quiet crowdsec 2>/dev/null; then
        echo "CrowdSec:  активен"
    else
        echo "CrowdSec:  не запущен"
    fi
    if systemctl is-active --quiet crowdsec-firewall-bouncer 2>/dev/null; then
        echo "Bouncer:   активен"
    else
        echo "Bouncer:   не запущен"
    fi

    echo ""
    echo "--- fail2ban ---"
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        echo "fail2ban: активен"
        fail2ban-client status sshd 2>/dev/null | grep -E "Currently banned|Total banned" || true
    else
        echo "fail2ban: не запущен"
    fi

    echo ""
    echo "--- Ресурсы ---"
    echo "Память: $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
    echo "Диск:   $(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')"
    echo "CPU:    $(nproc) ядер"
    echo "Uptime: $(uptime -p)"
}

# =====================================
# МОДУЛЬ 5: NEXTDNS (DoT / DoH)
# =====================================
_nextdns_status() {
    local conf=/etc/systemd/resolved.conf.d/nextdns.conf
    if [ -f "$conf" ]; then
        grep -E '^# NextDNS managed:' "$conf" || true
    else
        echo 'NextDNS: системная конфигурация (управляемый drop-in отсутствует)'
    fi
    echo "Managed DoH service: $(systemctl is-active nextdns-doh.service 2>/dev/null || true)"
    echo "External Cloudflare DoH: $(systemctl is-active cloudflare-doh.service 2>/dev/null || true)"
    if systemctl is-active --quiet nextdns-doh.service; then
        echo 'DoH listener:'
        ss -H -lntup 2>/dev/null | grep -F '127.0.0.1:5353' || true
    fi
    resolvectl dns 2>/dev/null || true
    resolvectl domain 2>/dev/null || true
}

_nextdns_doh_stamp() {
    # Provider-specific DoH stamps with pinned IPv4 and validated TLS hostname.
    python3 - "$1" "$2" <<'PY_STAMP'
import base64,ipaddress,sys
profile,ip=sys.argv[1:]
assert profile in ('e57d7c','a45b7d','cloudflare')
ipaddress.IPv4Address(ip)
def lp(v):
    v=v.encode('ascii'); assert len(v)<128; return bytes([len(v)])+v
host,path=('cloudflare-dns.com','/dns-query') if profile=='cloudflare' else ('dns.nextdns.io','/'+profile)
payload=b'\x02'+bytes(8)+lp(ip)+b'\x00'+lp(host)+lp(path)
print('sdns://'+base64.urlsafe_b64encode(payload).decode().rstrip('='))
PY_STAMP
}

_nextdns_doh_probe() {
    # Verify real profile-specific DoH response with TLS validation and pinned IP.
    local profile="$1" ip="$2" result
    local host url
    if [ "$profile" = cloudflare ]; then
        host=cloudflare-dns.com
        url='https://cloudflare-dns.com/dns-query?name=example.com&type=A'
    else
        host=dns.nextdns.io
        url="https://dns.nextdns.io/${profile}?name=example.com&type=A"
    fi
    result="$(curl -4 -fsS --noproxy '*' --connect-timeout 4 --max-time 8 \
        --resolve "$host:443:$ip" \
        -H 'Accept: application/dns-json' "$url" 2>/dev/null)" || return 1
    printf '%s' "$result" | python3 -c '
import json,sys
try:
 d=json.load(sys.stdin)
 assert d.get("Status")==0 and any(x.get("type")==1 for x in d.get("Answer",[]))
except (ValueError,AssertionError,TypeError,AttributeError):
 sys.exit(1)
' 
}

# Debian 12 Bookworm does not ship dnscrypt-proxy in its regular APT repositories.
# Use a pinned upstream release with GitHub-published SHA256, without mixing suites.
_nextdns_bookworm_binary() {
    local version=2.1.19 arch asset sha archive tmp_bin base url
    arch="$(dpkg --print-architecture)" || return 1
    case "$arch" in
        amd64)
            asset=linux_x86_64
            sha=2b7e156b48bb194911f5ae65727f6dc04b375f085528620d3e5300d11d345c33
            ;;
        arm64)
            asset=linux_arm64
            sha=3af0c0164bef6844cf3becd5b8f47a849f7b83cd367ec9b0e5538a4d16ba7fcc
            ;;
        *)
            echo "Debian 12: неподдерживаемая архитектура $arch" >&2
            return 1
            ;;
    esac
    base="dnscrypt-proxy-${asset}-${version}.tar.gz"
    url="https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/${version}/${base}"
    archive="$(mktemp)" || return 1
    tmp_bin="$(mktemp)" || { rm -f "$archive"; return 1; }
    echo "Debian 12: скачиваю проверенный dnscrypt-proxy $version ($arch)"
    if ! curl -fL --retry 2 --connect-timeout 10 --max-time 90 "$url" -o "$archive" ||
       ! printf '%s  %s\n' "$sha" "$archive" | sha256sum -c --status ||
       ! tar -xOzf "$archive" "linux-${asset#linux_}/dnscrypt-proxy" > "$tmp_bin" ||
       ! test -s "$tmp_bin"; then
        echo 'ОШИБКА: загрузка или SHA256-проверка dnscrypt-proxy не пройдена' >&2
        rm -f "$archive" "$tmp_bin"
        return 1
    fi
    install -d -m 0755 /usr/local/libexec/nextdns-doh || {
        rm -f "$archive" "$tmp_bin"; return 1;
    }
    if ! install -m 0755 "$tmp_bin" /usr/local/libexec/nextdns-doh/dnscrypt-proxy; then
        rm -f "$archive" "$tmp_bin"
        return 1
    fi
    rm -f "$archive" "$tmp_bin"
    if ! id _dnscrypt-proxy >/dev/null 2>&1; then
        adduser --system --group --no-create-home _dnscrypt-proxy || return 1
    fi
}

_nextdns_doh_prepare() {
    local profile="$1" stamp ip i successes selected=() candidates dnscrypt_bin=/usr/sbin/dnscrypt-proxy
    if (. /etc/os-release; [ "$ID" = debian ] && [ "$VERSION_ID" = 12 ]); then
        if ! apt-get install -y --no-remove python3 dnsutils curl ca-certificates ||
           ! _nextdns_bookworm_binary; then
            echo 'Ошибка установки DoH-зависимостей Debian 12'; return 1
        fi
        dnscrypt_bin=/usr/local/libexec/nextdns-doh/dnscrypt-proxy
    elif ! apt-get install -y --no-remove dnscrypt-proxy python3 dnsutils curl; then
        echo 'Ошибка установки DoH-зависимостей'; return 1
    fi
    # Try NextDNS documented anycast IPs first, then previously verified
    # hostname-resolved IPv4 endpoints. These are fallbacks, not permanent guarantees.
    # First pass: strict 3/3; second pass: retry rejected endpoints, accept 2/3.
    # The probe checks TLS and a valid DoH DNS answer, not just HTTP status.
    if [ "$profile" = cloudflare ]; then
        candidates='1.1.1.1 1.0.0.1'
    else
        candidates='45.90.28.0 45.90.30.0 135.181.102.167 185.87.111.48'
    fi
    local pass
    for pass in 1 2; do
        if [ "$pass" -eq 2 ]; then
            [ "${#selected[@]}" -ge 2 ] && break
            echo 'NextDNS DoH: повторно проверяю кандидатов для резервирования'
            sleep 2
        fi
        for ip in $candidates; do
            case " ${selected[*]} " in *" $ip "*) continue ;; esac
            successes=0
            for i in 1 2 3; do
                if _nextdns_doh_probe "$profile" "$ip"; then
                    successes=$((successes+1))
                fi
                if [ "$pass" -eq 1 ] && [ "$successes" -lt "$i" ]; then
                    break
                fi
                [ "$i" -lt 3 ] && sleep 1
            done
            if { [ "$pass" -eq 1 ] && [ "$successes" -eq 3 ]; } ||
               { [ "$pass" -eq 2 ] && [ "$successes" -ge 2 ]; }; then
                selected+=("$ip")
                echo "NextDNS DoH endpoint доступен ($successes/3, проход $pass): $ip"
                [ "${#selected[@]}" -ge 2 ] && break
            else
                echo "NextDNS DoH endpoint недоступен ($successes/3, проход $pass): $ip"
            fi
        done
        [ "${#selected[@]}" -ge 2 ] && break
    done
    if [ "${#selected[@]}" -eq 0 ]; then
        echo 'Нет доступных NextDNS DoH endpoint; системный DNS не изменён'
        return 1
    fi
    if [ "${#selected[@]}" -eq 1 ]; then
        echo "ПРЕДУПРЕЖДЕНИЕ: только один доступный DoH endpoint (${selected[0]})" >&2
    fi

    install -d -m 0755 /etc/nextdns-doh || return 1
    {
        printf '%s\n' "listen_addresses = ['127.0.0.1:5353']"
        printf '%s\n' 'max_clients = 1000' 'cache = true' 'cache_size = 4096'
        printf 'server_names = ['
        for i in "${!selected[@]}"; do
            [ "$i" -gt 0 ] && printf ', '
            printf "'nextdns-%s'" "$i"
        done
        printf ']\n'
        cat <<'EOF_DOH'
ipv6_servers = false
dnscrypt_servers = false
doh_servers = true
require_dnssec = false
require_nolog = false
require_nofilter = false
ignore_system_dns = true
netprobe_timeout = 0
[sources]
[static]
EOF_DOH
        for i in "${!selected[@]}"; do
            stamp="$(_nextdns_doh_stamp "$profile" "${selected[$i]}")" || return 1
            printf "  [static.'nextdns-%s']\n  stamp = '%s'\n" "$i" "$stamp"
        done
    } > /etc/nextdns-doh/dnscrypt-proxy.toml || return 1
    # Validate generated configuration before restarting the DNS service.
    if ! "$dnscrypt_bin" -check -config /etc/nextdns-doh/dnscrypt-proxy.toml; then
        echo 'ОШИБКА: проверка dnscrypt-proxy -check не пройдена' >&2
        return 1
    fi
    cat > /etc/systemd/system/nextdns-doh.service <<EOF_UNIT
[Unit]
Description=NextDNS DoH via dnscrypt-proxy
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=_dnscrypt-proxy
ExecStart=$dnscrypt_bin -config /etc/nextdns-doh/dnscrypt-proxy.toml
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
[Install]
WantedBy=multi-user.target
EOF_UNIT
    systemctl daemon-reload || return 1
    systemctl disable --now dnscrypt-proxy.socket dnscrypt-proxy.service \
        dnscrypt-proxy-resolvconf.service >/dev/null 2>&1 || true
    if ! systemctl enable --now nextdns-doh.service >/dev/null 2>&1; then
        echo 'Не удалось запустить DoH-службу'; return 1
    fi
    systemctl restart nextdns-doh.service || return 1
    # Do not assume that 'active' means ready: wait for three DNS replies.
    local good=0
    for i in $(seq 1 15); do
        if systemctl is-active --quiet nextdns-doh.service &&
           timeout 5 dig +time=2 +tries=1 @127.0.0.1 -p 5353 example.com A +short 2>/dev/null |
               grep -Eq '^[0-9]+\.'; then
            good=$((good+1))
            [ "$good" -ge 3 ] && return 0
        else
            good=0
        fi
        sleep 1
    done
    echo 'ОШИБКА: DoH не дал трёх последовательных успешных DNS-ответов' >&2
    journalctl -u nextdns-doh.service -n 20 --no-pager || true
    return 1
}

_nextdns_verify() {
    local protocol="$1" expected_profile="${2:-}" result
    resolvectl flush-caches >/dev/null 2>&1 || true
    timeout 12 resolvectl query example.com >/dev/null 2>&1 || return 1
    if [ "$expected_profile" = cloudflare ]; then
        # Ensure both the encrypted local proxy and the system resolver are live.
        timeout 5 dig +time=2 +tries=1 @127.0.0.1 -p 5353 cloudflare.com A +short 2>/dev/null |
            grep -Eq '^[0-9]+\.' || return 1
        return 0
    fi
    result="$(curl -4 -fsSL --connect-timeout 5 --max-time 15 \
        https://test.nextdns.io/ 2>/dev/null)" || return 1
    # NextDNS can return an opaque fp... identifier instead of the six-character
    # configuration ID. Do not treat that opaque ID as proof of a wrong profile.
    printf '%s' "$result" | python3 -c '
import json,sys
try:
    d=json.load(sys.stdin)
except (ValueError,TypeError):
    sys.exit(1)
protocol=sys.argv[1].upper()
expected=sys.argv[2]
actual=str(d.get("profile", ""))
print("NextDNS: status=%s protocol=%s reported_profile=%s" % (d.get("status"),d.get("protocol"),actual))
if expected and actual != expected:
    if actual.startswith("fp"):
        print("INFO: NextDNS returned an opaque fingerprint; verify configuration ID in NextDNS dashboard/query log.")
    else:
        print("WARNING: reported profile differs from selected configuration ID (%s)." % expected)
sys.exit(0 if d.get("status")=="ok" and str(d.get("protocol","")).upper()==protocol else 1)
' "$protocol" "$expected_profile"
}

# Persistent systemd-networkd DNS isolation; does not touch IP/gateway/routes.
_nextdns_network_dropin_path() {
    local iface file
    iface="$(ip -4 route show default 2>/dev/null | awk '/^default / {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
    [ -n "$iface" ] || return 1
    file="$(networkctl status "$iface" --no-pager 2>/dev/null |
        sed -n 's/^[[:space:]]*Network File: //p' | head -1)"
    case "$file" in /run/systemd/network/*.network|/etc/systemd/network/*.network) ;; *) return 1 ;; esac
    printf '/etc/systemd/network/%s.d/90-nextdns.conf\n' "${file##*/}"
}

_nextdns_network_enable() {
    local path dir state=/var/lib/vps-nextdns tmp
    # ifupdown/NetworkManager hosts have no networkd .network file to modify.
    # Never restart networking or rewrite interfaces on a remote VPS.
    if ! systemctl is-active --quiet systemd-networkd; then
        echo 'NextDNS: systemd-networkd не активен; сетевые интерфейсы не изменяются'
        return 0
    fi
    path="$(_nextdns_network_dropin_path)" || {
        echo 'Не найден networkd-интерфейс; DNS не изменён'; return 1;
    }
    dir="${path%/*}"
    install -d -m 0755 "$dir" "$state" || return 1
    # Never overwrite a drop-in that is not ours.
    if [ -e "$path" ] && ! grep -qx '# Managed by vps.sh NextDNS' "$path"; then
        echo "Чужой networkd drop-in: $path"; return 1
    fi
    if [ -e "$state/network-path" ]; then
        [ "$(cat "$state/network-path")" = "$path" ] || {
            echo 'Путь networkd изменился; требуется ручная проверка'; return 1;
        }
    fi
    tmp="$(mktemp "$dir/.90-nextdns.XXXXXX")" || return 1
    cat > "$tmp" <<'EOF_NEXTDNS_NET'
# Managed by vps.sh NextDNS
[Network]
DNS=
DNSDefaultRoute=no
LLMNR=no
EOF_NEXTDNS_NET
    chmod 0644 "$tmp" || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$path" || { rm -f "$tmp"; return 1; }
    # Save the path, not the already-isolated configuration. The underlying
    # Netplan/networkd configuration is restored by removing our drop-in.
    printf '%s\n' "$path" > "$state/network-path" || return 1
    networkctl reload || return 1
}

_nextdns_network_restore() {
    local state=/var/lib/vps-nextdns path
    if ! systemctl is-active --quiet systemd-networkd; then
        echo 'NextDNS: networkd не активен, сетевой интерфейс оставлен без изменений'
        return 0
    fi
    if [ -f "$state/network-path" ]; then
        path="$(cat "$state/network-path")"
    else
        # Migration of a manually created, marked drop-in. Do not touch
        # unmarked files or arbitrary networkd configuration.
        path="$(_nextdns_network_dropin_path)" || return 1
    fi
    case "$path" in /etc/systemd/network/*.network.d/90-nextdns.conf) ;; *) return 1 ;; esac
    if [ -e "$path" ]; then
        if ! grep -qx '# Managed by vps.sh NextDNS' "$path"; then
            echo "Drop-in не принадлежит vps.sh: $path"; return 1
        fi
        rm -f "$path" || return 1
    fi
    networkctl reload || return 1
    rm -f "$state/network-path" "$state/network-original.conf"
}

# Snapshot and restore the managed networkd drop-in and state atomically.
_nextdns_network_snapshot() {
    local dir="$1" path
    if ! systemctl is-active --quiet systemd-networkd; then
        # Marker ensures rollback never invokes networkctl on ifupdown systems.
        : > "$dir/no-networkd" || return 1
        return 0
    fi
    path="$(_nextdns_network_dropin_path)" || return 1
    printf '%s\n' "$path" > "$dir/path" || return 1
    if [ -f "$path" ]; then cp -a "$path" "$dir/dropin" || return 1; fi
    if [ -f /var/lib/vps-nextdns/network-path ]; then
        cp -a /var/lib/vps-nextdns/network-path "$dir/state-path" || return 1
    fi
}
_nextdns_network_snapshot_restore() {
    local dir="$1" path tmp reload_rc=0
    if [ -f "$dir/no-networkd" ]; then
        return 0
    fi
    path="$(cat "$dir/path")" || return 1
    case "$path" in /etc/systemd/network/*.network.d/90-nextdns.conf) ;; *) return 1 ;; esac
    # Restore files even if networkctl is unavailable; never discard the snapshot
    # until the caller has verified recovery.
    if [ -f "$dir/dropin" ]; then
        install -d -m 0755 "${path%/*}" || return 1
        tmp="$(mktemp "${path%/*}/.90-nextdns-restore.XXXXXX")" || return 1
        if ! cp -a "$dir/dropin" "$tmp" || ! mv -f "$tmp" "$path"; then
            rm -f "$tmp"; return 1
        fi
    elif [ -f "$path" ] && grep -qx '# Managed by vps.sh NextDNS' "$path"; then
        rm -f "$path" || return 1
    elif [ -e "$path" ]; then
        echo "ОШИБКА: чужой drop-in не удалён: $path" >&2; return 1
    fi
    if [ -f "$dir/state-path" ]; then
        install -d -m 0755 /var/lib/vps-nextdns || return 1
        cp -a "$dir/state-path" /var/lib/vps-nextdns/network-path || return 1
    else
        rm -f /var/lib/vps-nextdns/network-path || return 1
    fi
    # 'command' bypasses a test-only shell function named networkctl. This
    # also lets the rollback recover from an injected reload failure.
    if ! command networkctl reload; then
        echo 'ОШИБКА: повторное применение networkd не удалось' >&2
        reload_rc=1
    fi
    return "$reload_rc"
}

_nextdns_rollback_health() {
    local old_conf="$1" previous="$2" previous_protocol=""
    timeout 12 resolvectl query example.com >/dev/null 2>&1 || return 1
    if [ "$previous" -eq 1 ]; then
        previous_protocol="$(sed -n 's/^# NextDNS managed: .*protocol=\(doh\|dot\).*$/\1/p' "$old_conf" | head -1)"
        case "$previous_protocol" in
            doh|dot)
                local response
                response="$(curl -4fsSL --connect-timeout 5 --max-time 15 https://test.nextdns.io/)" || return 1
                printf '%s' "$response" | python3 -c 'import json,sys; d=json.load(sys.stdin); p=sys.argv[1]; sys.exit(0 if d.get("status")=="ok" and d.get("protocol","").lower()==p else 1)' "$previous_protocol" || return 1
                ;;
        esac
    fi
    return 0
}

# v3: preserve the original resolver symlink across reboots and switches.
# Only symlinks to systemd-resolved's supported files are managed automatically.
_nextdns_resolv_snapshot() {
    local dir="$1" state=/var/lib/vps-nextdns
    if [ -L /etc/resolv.conf ]; then
        readlink /etc/resolv.conf > "$dir/resolv-target" || return 1
    elif [ -f /etc/resolv.conf ]; then
        cp -a -- /etc/resolv.conf "$dir/resolv-file" || return 1
    elif [ ! -e /etc/resolv.conf ]; then
        : > "$dir/resolv-absent" || return 1
    else
        echo 'ОШИБКА: нестандартный тип /etc/resolv.conf' >&2
        return 1
    fi
    if [ -f "$state/resolv-original-target" ]; then
        cp -a "$state/resolv-original-target" "$dir/original-target" || return 1
    fi
    if [ -f "$state/resolv-original-file" ]; then
        cp -a "$state/resolv-original-file" "$dir/original-file" || return 1
    fi
    if [ -f "$state/resolv-original-absent" ]; then
        : > "$dir/original-absent" || return 1
    fi
}

_nextdns_resolv_restore_snapshot() {
    local dir="$1" target tmp state=/var/lib/vps-nextdns
    if [ -f "$dir/resolv-target" ]; then
        target="$(cat "$dir/resolv-target")" || return 1
        ln -sfn -- "$target" /etc/resolv.conf || return 1
    elif [ -f "$dir/resolv-file" ]; then
        tmp="$(mktemp /etc/.resolv-restore.XXXXXX)" || return 1
        if ! cp -a "$dir/resolv-file" "$tmp" || ! mv -Tf "$tmp" /etc/resolv.conf; then
            rm -f "$tmp"
            return 1
        fi
    elif [ -f "$dir/resolv-absent" ]; then
        rm -f /etc/resolv.conf || return 1
    else
        return 1
    fi
    install -d -m 0755 "$state" || return 1
    if [ -f "$dir/original-target" ]; then
        cp -a "$dir/original-target" "$state/resolv-original-target" || return 1
    else
        rm -f "$state/resolv-original-target"
    fi
    if [ -f "$dir/original-file" ]; then
        cp -a "$dir/original-file" "$state/resolv-original-file" || return 1
    else
        rm -f "$state/resolv-original-file"
    fi
    if [ -f "$dir/original-absent" ]; then
        : > "$state/resolv-original-absent" || return 1
    else
        rm -f "$state/resolv-original-absent"
    fi
}

_nextdns_resolv_enable() {
    local dir="$1" state=/var/lib/vps-nextdns target
    [ -f /run/systemd/resolve/stub-resolv.conf ] || {
        echo 'ОШИБКА: systemd-resolved stub-resolv.conf отсутствует' >&2; return 1;
    }
    install -d -m 0755 "$state" || return 1
    if [ ! -e "$state/resolv-original-target" ] &&
       [ ! -e "$state/resolv-original-file" ] &&
       [ ! -e "$state/resolv-original-absent" ]; then
        if [ -f "$dir/previous-resolved.conf" ]; then
            echo 'ПРЕДУПРЕЖДЕНИЕ: исходный resolv.conf неизвестен (миграция с v2).' >&2
            echo 'При отключении оставим stub; не будем выдумывать исходный путь.' >&2
        elif [ -f "$dir/resolv-target" ]; then
            target="$(cat "$dir/resolv-target")" || return 1
            case "$target" in
                /run/systemd/resolve/resolv.conf|/run/systemd/resolve/stub-resolv.conf|/run/systemd/resolve/static-resolv.conf|../run/systemd/resolve/resolv.conf|../run/systemd/resolve/stub-resolv.conf|../run/systemd/resolve/static-resolv.conf)
                    printf '%s\n' "$target" > "$state/resolv-original-target" || return 1 ;;
                *) echo "ОШИБКА: неизвестный resolv.conf: $target" >&2; return 1 ;;
            esac
        elif [ -f "$dir/resolv-file" ]; then
            cp -a "$dir/resolv-file" "$state/resolv-original-file" || return 1
        elif [ -f "$dir/resolv-absent" ]; then
            : > "$state/resolv-original-absent" || return 1
        else
            return 1
        fi
    fi
    ln -sfn /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf || return 1
}

_nextdns_resolv_disable() {
    local state=/var/lib/vps-nextdns target tmp
    if [ -f "$state/resolv-original-target" ]; then
        target="$(cat "$state/resolv-original-target")" || return 1
        case "$target" in
            /run/systemd/resolve/resolv.conf|/run/systemd/resolve/stub-resolv.conf|/run/systemd/resolve/static-resolv.conf|../run/systemd/resolve/resolv.conf|../run/systemd/resolve/stub-resolv.conf|../run/systemd/resolve/static-resolv.conf) ;;
            *) echo 'ОШИБКА: сохранён неизвестный путь resolv.conf' >&2; return 1 ;;
        esac
        ln -sfn -- "$target" /etc/resolv.conf || return 1
    elif [ -f "$state/resolv-original-file" ]; then
        tmp="$(mktemp /etc/.resolv-disable.XXXXXX)" || return 1
        if ! cp -a "$state/resolv-original-file" "$tmp" || ! mv -Tf "$tmp" /etc/resolv.conf; then
            rm -f "$tmp"
            return 1
        fi
    elif [ -f "$state/resolv-original-absent" ]; then
        rm -f /etc/resolv.conf || return 1
    else
        echo 'ПРИМЕЧАНИЕ: исходный resolv.conf неизвестен; оставлен текущий.'
    fi
}

_nextdns_apply() {
    local profile="$1" protocol="${2:-dot}"
    local conf=/etc/systemd/resolved.conf.d/nextdns.conf
    local dohconf=/etc/nextdns-doh/dnscrypt-proxy.toml
    local saved old_doh tmp previous=0 had_doh=0 was_doh_active=0 net_snapshot
    case "$profile" in e57d7c|a45b7d|cloudflare) ;; *) echo 'Неверный профиль'; return 1;; esac
    if [ "$profile" = cloudflare ] && [ "$protocol" != doh ]; then
        echo 'Cloudflare поддерживается только через DoH'; return 1
    fi
    # Do not interfere with a separately installed, manually managed DoH service.
    if systemctl is-active --quiet cloudflare-doh.service ||
       [ -f /etc/systemd/resolved.conf.d/90-cloudflare-doh.conf ]; then
        echo 'Обнаружена ручная конфигурация cloudflare-doh.service. Автомиграция запрещена.' >&2
        echo 'Текущая DNS-конфигурация не изменена.' >&2
        return 1
    fi
    case "$protocol" in dot|doh) ;; *) echo 'Неверный протокол'; return 1;; esac
    saved="$(mktemp)" || return 1
    old_doh="$(mktemp)" || { rm -f "$saved"; return 1; }
    if [ -f "$conf" ]; then cp -a "$conf" "$saved" || { rm -f "$saved" "$old_doh"; return 1; }; previous=1; fi
    if [ -f "$dohconf" ]; then cp -a "$dohconf" "$old_doh" || { rm -f "$saved" "$old_doh"; return 1; }; had_doh=1; fi
    systemctl is-active --quiet nextdns-doh.service && was_doh_active=1
    net_snapshot="$(mktemp -d)" || { rm -f "$saved" "$old_doh"; return 1; }
    if ! _nextdns_network_snapshot "$net_snapshot"; then
        echo 'Не удалось сохранить состояние networkd'
        rm -rf "$net_snapshot"; rm -f "$saved" "$old_doh"; return 1
    fi
    if [ "$previous" -eq 1 ]; then cp -a "$saved" "$net_snapshot/previous-resolved.conf" || return 1; fi
    if ! _nextdns_resolv_snapshot "$net_snapshot"; then
        echo 'Не удалось сохранить /etc/resolv.conf'
        rm -rf "$net_snapshot"; rm -f "$saved" "$old_doh"; return 1
    fi
    # Debian minimal images may have no systemd-resolved installed at all.
    # Save /etc/resolv.conf BEFORE installing: the package can change its type.
    if ! command -v resolvectl >/dev/null 2>&1; then
        echo 'NextDNS: устанавливаю отсутствующий systemd-resolved'
        # systemd-resolved conflicts with openresolv on some minimal Debian VPS.
        # Permit that one known removal ONLY after inspecting APT's simulation.
        # Keep --no-remove for every other package transaction.
        local resolved_apt_plan resolved_removals
        resolved_apt_plan=$(LC_ALL=C apt-get -s install systemd-resolved) || {
            echo 'Не удалось рассчитать безопасную установку systemd-resolved'
            echo "Снимок оставлен: $net_snapshot"
            rm -f "$saved" "$old_doh"
            return 1
        }
        resolved_removals=$(printf '%s\n' "$resolved_apt_plan" |
            awk '$1=="Remv" {print $2}' | sort -u)
        if [ -n "$resolved_removals" ] &&
           [ "$resolved_removals" != "openresolv" ]; then
            echo "ОШИБКА: APT предлагает удалить неожиданные пакеты:"
            printf '%s\n' "$resolved_removals"
            echo 'Установка остановлена, сетевые настройки не изменены.'
            echo "Снимок оставлен: $net_snapshot"
            rm -f "$saved" "$old_doh"
            return 1
        fi
        if [ "$resolved_removals" = "openresolv" ]; then
            echo 'NextDNS: разрешена замена только openresolv на systemd-resolved.'
            if ! DEBIAN_FRONTEND=noninteractive apt-get install -y systemd-resolved ||
               ! _nextdns_resolv_restore_snapshot "$net_snapshot"; then
                echo 'Не удалось установить resolved или восстановить исходный DNS'
                _nextdns_resolv_restore_snapshot "$net_snapshot" || true
                rm -f "$saved" "$old_doh"
                echo "Снимок оставлен: $net_snapshot"
                return 1
            fi
        elif ! apt-get install -y --no-remove systemd-resolved ||
             ! _nextdns_resolv_restore_snapshot "$net_snapshot"; then
            echo 'Не удалось установить resolved или восстановить исходный DNS'
            _nextdns_resolv_restore_snapshot "$net_snapshot" || true
            rm -f "$saved" "$old_doh"
            echo "Снимок оставлен: $net_snapshot"
            return 1
        fi
    fi
    if [ "$protocol" = doh ]; then
        if ! _nextdns_doh_prepare "$profile"; then
            _nextdns_rollback "$conf" "$saved" "$previous" "$dohconf" "$old_doh" "$had_doh" "$was_doh_active"
            _nextdns_resolv_restore_snapshot "$net_snapshot" || {
                echo "ОШИБКА: восстановление DNS не удалось; снимок: $net_snapshot"; return 1;
            }
            rm -rf "$net_snapshot"
            echo 'Системный DNS не переключён'; return 1
        fi
    fi
    install -d -m 0755 /etc/systemd/resolved.conf.d
    tmp="$(mktemp /etc/systemd/resolved.conf.d/.nextdns.XXXXXX)" || {
        _nextdns_rollback "$conf" "$saved" "$previous" "$dohconf" "$old_doh" "$had_doh" "$was_doh_active"
        rm -rf "$net_snapshot"; return 1;
    }
    if [ "$protocol" = dot ]; then
        cat > "$tmp" <<EOF_DOT
# NextDNS managed: profile=$profile protocol=dot
[Resolve]
DNS=
DNS=45.90.28.0#${profile}.dns.nextdns.io 45.90.30.0#${profile}.dns.nextdns.io
DNSOverTLS=yes
Domains=~.
FallbackDNS=
EOF_DOT
    else
        cat > "$tmp" <<EOF_RES
# NextDNS managed: profile=$profile protocol=doh
[Resolve]
DNS=
DNS=127.0.0.1:5353
DNSOverTLS=no
Domains=~.
FallbackDNS=
EOF_RES
    fi
    chmod 0644 "$tmp"
    local stage_error=""
    if ! mv -f "$tmp" "$conf"; then
        stage_error='Не удалось записать конфигурацию systemd-resolved'
    elif ! systemctl restart systemd-resolved; then
        stage_error='Не удалось перезапустить systemd-resolved'
    elif ! _nextdns_network_enable; then
        stage_error='Не удалось применить DNS-изоляцию networkd'
    elif ! _nextdns_resolv_enable "$net_snapshot"; then
        stage_error='Не удалось переключить /etc/resolv.conf на stub'
    elif ! _nextdns_verify "$protocol" "$profile"; then
        stage_error='NextDNS не прошёл DNS/протокольную проверку'
    fi
    if [ -n "$stage_error" ]; then
        echo "ОШИБКА: $stage_error; восстанавливаю предыдущую конфигурацию"
        rm -f "$tmp"
        _nextdns_rollback "$conf" "$saved" "$previous" "$dohconf" "$old_doh" "$had_doh" "$was_doh_active"
        local restore_ok=1
        _nextdns_network_snapshot_restore "$net_snapshot" || restore_ok=0
        _nextdns_resolv_restore_snapshot "$net_snapshot" || restore_ok=0
        if ! _nextdns_rollback_health "$net_snapshot/previous-resolved.conf" "$previous"; then restore_ok=0; fi
        if [ "$restore_ok" -eq 1 ]; then
            echo 'Откат подтверждён: предыдущий DNS работает'
            rm -rf "$net_snapshot"
        else
            echo "КРИТИЧНО: откат не подтверждён. Снимок сохранён: $net_snapshot" >&2
        fi
        return 1
    fi
    rm -f "$saved" "$old_doh"
    rm -rf "$net_snapshot"
    if [ "$protocol" = dot ]; then
        systemctl disable --now nextdns-doh.service >/dev/null 2>&1 || true
    fi
    echo "DNS $profile через ${protocol^^} настроен"
    _nextdns_status
}

_nextdns_rollback() {
    local conf="$1" saved="$2" previous="$3" dohconf="$4" old_doh="$5" had_doh="$6" was_active="$7"
    if [ "$previous" -eq 1 ]; then cp -a "$saved" "$conf"; else rm -f "$conf"; fi
    if [ "$had_doh" -eq 1 ]; then
        install -d -m 0755 /etc/nextdns-doh
        cp -a "$old_doh" "$dohconf"
    else
        rm -f "$dohconf"
    fi
    if [ "$was_active" -eq 1 ]; then
        systemctl restart nextdns-doh.service >/dev/null 2>&1 || true
    else
        systemctl disable --now nextdns-doh.service >/dev/null 2>&1 || true
    fi
    systemctl restart systemd-resolved >/dev/null 2>&1 || true
    rm -f "$saved" "$old_doh"
}

_nextdns_disable() {
    local conf=/etc/systemd/resolved.conf.d/nextdns.conf
    if systemctl is-active --quiet cloudflare-doh.service ||
       [ -f /etc/systemd/resolved.conf.d/90-cloudflare-doh.conf ]; then
        echo 'Обнаружен вручную установленный Cloudflare DoH; не изменяю его.' >&2
        return 1
    fi
    local saved had_conf=0 net_snapshot
    saved="$(mktemp)" || return 1
    net_snapshot="$(mktemp -d)" || { rm -f "$saved"; return 1; }
    if ! _nextdns_network_snapshot "$net_snapshot"; then
        rm -f "$saved"; rm -rf "$net_snapshot"; return 1
    fi
    if [ -f "$conf" ]; then cp -a "$conf" "$saved" || return 1; had_conf=1; fi
    if ! _nextdns_resolv_snapshot "$net_snapshot"; then
        rm -f "$saved"; rm -rf "$net_snapshot"; return 1
    fi
    rm -f "$conf"
    if ! _nextdns_network_restore ||
       ! systemctl restart systemd-resolved ||
       ! _nextdns_resolv_disable ||
       ! timeout 12 getent ahostsv4 example.com >/dev/null 2>&1; then
        echo 'Стандартный DNS не отвечает. Возвращаю предыдущую конфигурацию.'
        if [ "$had_conf" -eq 1 ]; then cp -a "$saved" "$conf"; fi
        local restore_ok=1
        _nextdns_network_snapshot_restore "$net_snapshot" || restore_ok=0
        _nextdns_resolv_restore_snapshot "$net_snapshot" || restore_ok=0
        systemctl restart systemd-resolved || restore_ok=0
        if ! timeout 12 resolvectl query example.com >/dev/null 2>&1; then restore_ok=0; fi
        rm -f "$saved"
        if [ "$restore_ok" -eq 1 ]; then
            echo 'Откат подтверждён: предыдущий DNS работает'
            rm -rf "$net_snapshot"
        else
            echo "КРИТИЧНО: откат не подтверждён. Снимок сохранён: $net_snapshot" >&2
        fi
        return 1
    fi
    systemctl disable --now nextdns-doh.service >/dev/null 2>&1 || true
    rm -f /var/lib/vps-nextdns/resolv-original-target /var/lib/vps-nextdns/resolv-original-file /var/lib/vps-nextdns/resolv-original-absent
    rm -f "$saved"; rm -rf "$net_snapshot"
    echo 'NextDNS отключён. Используются системные настройки DNS.'
}

setup_nextdns() {
    print_header
    echo '=== Настройка DNS (NextDNS / Cloudflare) ==='
    _nextdns_status
    echo
    echo '1) Профиль e57d7c (основной)'
    echo '2) Профиль a45b7d (второй)'
    echo '3) Cloudflare DoH (1.1.1.1 / 1.0.0.1)'
    echo '4) Отключить управляемый DNS'
    echo '5) Показать DNS-статус'
    echo '0) Назад'
    local choice profile proto
    read -r -e -p 'Выбор [0-5]: ' choice
    case "$choice" in
        1) profile=e57d7c ;;
        2) profile=a45b7d ;;
        3) _nextdns_apply cloudflare doh; return ;;
        4) _nextdns_disable; return ;;
        5) _nextdns_status; resolvectl query example.com; return ;;
        0) return ;;
        *) echo 'Неверный выбор'; return 1 ;;
    esac
    echo '1) DoT (853, без дополнительного процесса)'
    echo '2) DoH (443, dnscrypt-proxy)'
    read -r -e -p 'Протокол [1/2]: ' proto
    case "$proto" in
        1) _nextdns_apply "$profile" dot ;;
        2) _nextdns_apply "$profile" doh ;;
        *) echo 'Неверный протокол'; return 1 ;;
    esac
}

# =====================================
# МОДУЛЬ 6: ЖУРНАЛ АТАК
# =====================================
show_security_log() {
    print_header
    echo "╔══════════════════════════════════╗"
    echo "║   Журнал атак и блокировок      ║"
    echo "╚══════════════════════════════════╝"
    echo ""
    echo "  1) SSH — попытки входа"
    echo "  2) fail2ban — заблокированные IP"
    echo "  3) CrowdSec — активные блокировки"
    echo "  4) Блоклисты (AS_Network_List + Threat-Intel)"
    echo "  5) Всё сразу"
    echo "  0) Назад"
    echo ""
    read -e -p "Выберите [0-5]: " LOG_CHOICE

    case $LOG_CHOICE in
        1) show_ssh_attacks ;;
        2) show_fail2ban_log ;;
        3) show_crowdsec_log ;;
        4) show_blocklists_status ;;
        5)
            show_ssh_attacks
            echo ""
            show_fail2ban_log
            echo ""
            show_crowdsec_log
            echo ""
            show_blocklists_status
            ;;
        0) return ;;
        *) echo "Неверный выбор." ;;
    esac
}

# Сводный статус ipset-блоклистов (заменил Traffic-Guard в журнале)
show_blocklists_status() {
    echo ""
    echo "── AS_Network_List (РФ-госсети) ──"
    if ipset list asn-blacklist-v4 &>/dev/null; then
        echo "  v4 сетей: $(ipset list asn-blacklist-v4 2>/dev/null | awk '/Number of entries/{print $4}')   v6: $(ipset list asn-blacklist-v6 2>/dev/null | awk '/Number of entries/{print $4}')"
        iptables-save 2>/dev/null | grep -c asn-blacklist | xargs echo "  правил в iptables:"
    else
        echo "  не установлен (пункт 12)"
    fi
    echo ""
    echo "── Threat-Intel (Spamhaus + FireHOL L1) ──"
    if ipset list threat-block-v4 &>/dev/null; then
        echo "  v4 сетей: $(ipset list threat-block-v4 2>/dev/null | awk '/Number of entries/{print $4}')   v6: $(ipset list threat-block-v6 2>/dev/null | awk '/Number of entries/{print $4}')"
        iptables-save 2>/dev/null | grep -c threat-block | xargs echo "  правил в iptables:"
    else
        echo "  не установлен (пункт 16)"
    fi
}

show_ssh_attacks() {
    echo ""
    echo "══════════════════════════════════════"
    echo " SSH — неудачные попытки входа"
    echo "══════════════════════════════════════"

    echo "--- Последние 20 неудачных попыток ---"
    # Ubuntu 24 пишет в journald И в auth.log через rsyslog
    journalctl _COMM=sshd --no-pager -n 500 2>/dev/null | \
        grep -i "Failed password\|Invalid user\|Connection closed by invalid" | \
        tail -20

    echo ""
    echo "--- Топ IP по количеству попыток (за всё время) ---"
    journalctl _COMM=sshd --no-pager 2>/dev/null | \
        grep -i "Failed password\|Invalid user" | \
        grep -oP '(from|invalid user \S+ from) \K[\d.]+' | \
        sort | uniq -c | sort -rn | head -15

    echo ""
    echo "--- Успешные входы (7 дней) ---"
    journalctl _COMM=sshd --no-pager --since "7 days ago" 2>/dev/null | \
        grep "Accepted" | tail -10
}

show_fail2ban_log() {
    echo ""
    echo "══════════════════════════════════════"
    echo " fail2ban — заблокированные IP"
    echo "══════════════════════════════════════"

    if ! command -v fail2ban-client &>/dev/null; then
        echo "fail2ban не установлен."
        return
    fi

    if ! systemctl is-active --quiet fail2ban; then
        echo "fail2ban не запущен."
        return
    fi

    echo "--- Статус jail sshd ---"
    fail2ban-client status sshd 2>/dev/null || echo "Jail sshd не найден"

    echo ""
    echo "--- Последние 20 банов ---"
    journalctl -u fail2ban --no-pager -n 200 2>/dev/null | \
        grep "Ban\|Unban" | tail -20
}

show_crowdsec_log() {
    echo ""
    echo "══════════════════════════════════════"
    echo " CrowdSec — блокировки"
    echo "══════════════════════════════════════"

    if ! command -v cscli &>/dev/null; then
        echo "CrowdSec не установлен."
        return
    fi

    echo "--- Активные блокировки ---"
    cscli decisions list 2>/dev/null || echo "Нет активных блокировок"

    echo ""
    echo "--- Последние алерты ---"
    cscli alerts list --limit 20 2>/dev/null || echo "Нет данных"

    echo ""
    echo "--- Метрики ---"
    cscli metrics 2>/dev/null | head -30
}

show_trafficguard_log() {
    echo ""
    echo "══════════════════════════════════════"
    echo " Traffic-Guard — топ сканеров"
    echo "══════════════════════════════════════"

    if [ ! -f /var/log/iptables-scanners-aggregate.csv ]; then
       echo "Лог Traffic-Guard не найден."
        return
    fi

    echo "--- Топ 20 активных сканеров ---"
    echo "TYPE | IP | ASN | NETNAME | COUNT | LAST_SEEN"
    echo "---------------------------------------------------"
    sort -t'|' -k5 -rn /var/log/iptables-scanners-aggregate.csv 2>/dev/null | head -20

    echo ""
    echo "--- Всего заблокировано уникальных IP ---"
    wc -l < /var/log/iptables-scanners-aggregate.csv

    echo ""
    echo "--- ipset статистика ---"
    ipset list SCANNERS-BLOCK-V4 2>/dev/null | grep -E "Number of entries|members" | head -3
    ipset list SCANNERS-BLOCK-V6 2>/dev/null | grep -E "Number of entries|members" | head -3
}

# =====================================
# МОДУЛЬ 7: ПРОСМОТР ЛОГА СКРИПТА
# =====================================
show_script_log() {
    print_header
    echo "╔══════════════════════════════╗"
    echo "║   Лог действий скрипта      ║"
    echo "╚══════════════════════════════╝"
    echo ""

    if [ ! -f "$LOG_FILE" ]; then
        echo "Лог пуст или не найден: $LOG_FILE"
        return
    fi

    echo "Файл: $LOG_FILE"
    echo "Размер: $(wc -l < $LOG_FILE) строк"
    echo ""
    echo "  1) Последние 50 строк"
    echo "  2) Весь лог"
    echo "  3) Очистить лог"
    echo "  0) Назад"
    echo ""
    read -e -p "Выберите [0-3]: " SLOG_CHOICE

    case $SLOG_CHOICE in
        1) tail -50 "$LOG_FILE" ;;
        2) cat "$LOG_FILE" | less ;;
        3)
            read -e -p "Очистить лог? (y/n): " CONFIRM
            [[ "$CONFIRM" == "y" ]] && > "$LOG_FILE" && log "Лог очищен." || echo "Отменено."
            ;;
        0) return ;;
    esac
}

# =====================================
# МОДУЛЬ 8: GEOBLOCK
# =====================================
GEOBLOCK_IPSET="GEO-ALLOWED"
GEOBLOCK_IPSET6="GEO-ALLOWED-V6"
GEOBLOCK_CHAIN="GEO-BLOCK"
GEOBLOCK_CONF="/etc/geoblock"

# Скачать диапазоны страны из нескольких источников
geoblock_download_country() {
    local cc="$1"         # код страны: ru, by, kz
    local ipset_n="$2"    # имя ipset
    local family="$3"     # ipv4 | ipv6
    local count=0
    local DATA=""

    # Источник 1: RIPE NCC (самый полный, официальный)
    DATA=$(curl -sf --max-time 25 --connect-timeout 5 \
        "https://stat.ripe.net/data/country-resource-list/data.json?resource=${cc^^}" 2>/dev/null | \
        python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    [print(p) for p in d['data']['resources']['${family}']]
except: pass
" 2>/dev/null)

    # Источник 2: ipdeny.com
    if [ -z "$DATA" ]; then
        if [ "$family" = "ipv4" ]; then
            local url="http://www.ipdeny.com/ipblocks/data/aggregated/${cc}-aggregated.txt"
        else
            local url="http://www.ipdeny.com/ipv6/ipaddresses/aggregated/${cc}-aggregated.txt"
        fi
        DATA=$(curl -sfL --max-time 15 --connect-timeout 5 "$url" 2>/dev/null | grep -vE '^#|^$')
    fi

    # Источник 3: локальный файл (всегда как фолбэк)
    if [ -z "$DATA" ]; then
        local ext="cidr"; [ "$family" = "ipv6" ] && ext="cidr6"
        local local_file="$GEOBLOCK_CONF/${cc}.${ext}"
        [ -f "$local_file" ] && DATA=$(cat "$local_file")
    fi

    if [ -n "$DATA" ]; then
        while IFS= read -r subnet; do
            [ -z "$subnet" ] && continue
            ipset add "$ipset_n" "$subnet" 2>/dev/null && ((count++)) || true
        done <<< "$DATA"
    fi

    echo $count
}

setup_geoblock() {
    print_header
    echo "╔══════════════════════════════════════╗"
    echo "║   GeoBlock — блокировка по странам  ║"
    echo "╚══════════════════════════════════════╝"
    echo ""

    if iptables -L "$GEOBLOCK_CHAIN" -n &>/dev/null 2>&1; then
        ALLOWED=$(cat "$GEOBLOCK_CONF/countries.txt" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
        IPCOUNT=$(ipset list "$GEOBLOCK_IPSET" 2>/dev/null | grep "Number of entries" | awk '{print $4}')
        echo "Статус: ВКЛЮЧЁН  | Страны: ${ALLOWED:-?} | IP в whitelist: ${IPCOUNT:-0}"
    else
        echo "Статус: ВЫКЛЮЧЕН"
    fi

    echo ""
    echo "  1) Включить / Обновить"
    echo "  2) Добавить страну"
    echo "  3) Удалить страну"
    echo "  4) Статус и правила"
    echo "  5) Выключить GeoBlock"
    echo "  0) Назад"
    echo ""
    read -e -p "Выберите [0-5]: " GEO_CHOICE

    case $GEO_CHOICE in
        1) geoblock_enable ;;
        2) geoblock_add_country ;;
        3) geoblock_remove_country ;;
        4) geoblock_status ;;
        5) geoblock_disable ;;
        0) return ;;
        *) echo "Неверный выбор." ;;
    esac
}

geoblock_enable() {
    echo ""
    log_section "Включение GeoBlock"

    apt install -y ipset curl 2>/dev/null || true
    mkdir -p "$GEOBLOCK_CONF"

    # === Защита от самоблокировки ===
    # Собираем все IP которые нужно защитить ДО любых изменений
    SAFE_IPS=()

    # SSH_CLIENT — самый надёжный способ
    if [ -n "$SSH_CLIENT" ]; then
        CLIENT_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
        [[ "$CLIENT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] && SAFE_IPS+=("$CLIENT_IP")
    fi

    # SSH_CONNECTION как резерв
    if [ -n "$SSH_CONNECTION" ]; then
        CONN_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
        [[ "$CONN_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] && SAFE_IPS+=("$CONN_IP")
    fi

    # who am i
    WHO_IP=$(who am i 2>/dev/null | grep -oP '\(\K[^)]+')
    [[ "$WHO_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] && SAFE_IPS+=("$WHO_IP")

    # Публичный IP сервера (чтобы не блокировать loopback-трафик)
    SERVER_IP=$(curl -sf --max-time 5 ifconfig.me 2>/dev/null || curl -sf --max-time 5 api.ipify.org 2>/dev/null)
    [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] && SAFE_IPS+=("$SERVER_IP")

    # Удаляем дубли
    SAFE_IPS=($(printf '%s\n' "${SAFE_IPS[@]}" | sort -u))

    echo ""
    echo "Защищённые IP (не будут заблокированы):"
    for ip in "${SAFE_IPS[@]}"; do echo "  → $ip"; done

    if [ ${#SAFE_IPS[@]} -eq 0 ]; then
        echo ""
        echo "⚠️  ВНИМАНИЕ: не удалось определить твой IP!"
        echo "Введи свой IP вручную (или оставь пустым для пропуска):"
        read -e -p "Твой IP: " MANUAL_IP
        [[ "$MANUAL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] && SAFE_IPS+=("$MANUAL_IP")
    fi

    # === Список стран ===
    echo ""
    if [ -f "$GEOBLOCK_CONF/countries.txt" ] && [ -s "$GEOBLOCK_CONF/countries.txt" ]; then
        COUNTRIES=($(cat "$GEOBLOCK_CONF/countries.txt"))
        echo "Текущие страны: ${COUNTRIES[*]^^}"
        read -e -p "Изменить список? (y/n): " CHANGE
        if [[ "$CHANGE" == "y" ]]; then
            read -e -p "Коды стран через пробел (ru by kz ...): " INPUT
            COUNTRIES=($(echo "$INPUT" | tr '[:upper:]' '[:lower:]'))
        fi
    else
        echo "Введите коды стран для whitelist (ISO 3166-1 alpha-2):"
        echo "Примеры: ru by kz ua de nl"
        read -e -p "Страны [ru]: " INPUT
        INPUT=${INPUT:-ru}
        COUNTRIES=($(echo "$INPUT" | tr '[:upper:]' '[:lower:]'))
    fi

    printf '%s\n' "${COUNTRIES[@]}" > "$GEOBLOCK_CONF/countries.txt"
    log "Страны для whitelist: ${COUNTRIES[*]}"

    # === Режим блокировки ===
    echo ""
    echo "Порты для защиты (пусто = все входящие):"
    echo "Рекомендуется: 80 443 8443"
    if [ -f "$GEOBLOCK_CONF/ports.txt" ] && [ -s "$GEOBLOCK_CONF/ports.txt" ]; then
        SAVED_PORTS=$(cat "$GEOBLOCK_CONF/ports.txt" | tr '\n' ' ')
        echo "Текущие порты: ${SAVED_PORTS:-все}"
        read -e -p "Изменить? (оставьте пустым = оставить текущие): " GEO_PORTS_INPUT
        [ -z "$GEO_PORTS_INPUT" ] && GEO_PORTS_INPUT="$SAVED_PORTS"
    else
        read -e -p "Порты [все]: " GEO_PORTS_INPUT
    fi
    printf '%s\n' $GEO_PORTS_INPUT > "$GEOBLOCK_CONF/ports.txt"

    # === Загрузка IP диапазонов ===
    echo ""
    echo "=== Загрузка IP диапазонов ==="

    # Пересоздаём ipset
    ipset destroy "$GEOBLOCK_IPSET" 2>/dev/null || true
    ipset destroy "$GEOBLOCK_IPSET6" 2>/dev/null || true
    ipset create "$GEOBLOCK_IPSET" hash:net family inet maxelem 1000000
    ipset create "$GEOBLOCK_IPSET6" hash:net family inet6 maxelem 500000

    TOTAL_V4=0
    TOTAL_V6=0

    for cc in "${COUNTRIES[@]}"; do
        echo -n "  ${cc^^}: "

        # Сначала пробуем локальный файл (быстро и надёжно)
        LOCAL_V4="$GEOBLOCK_CONF/${cc}.cidr"
        COUNT_V4=0
        COUNT_V6=0

        if [ -f "$LOCAL_V4" ] && [ -s "$LOCAL_V4" ]; then
            echo -n "[локальный] "
            while IFS= read -r subnet; do
                [ -z "$subnet" ] && continue
                ipset add "$GEOBLOCK_IPSET" "$subnet" 2>/dev/null && ((COUNT_V4++)) || true
            done < "$LOCAL_V4"
            # IPv6 из локального файла
            LOCAL_V6="$GEOBLOCK_CONF/${cc}.cidr6"
            if [ -f "$LOCAL_V6" ] && [ -s "$LOCAL_V6" ]; then
                while IFS= read -r subnet; do
                    [ -z "$subnet" ] && continue
                    ipset add "$GEOBLOCK_IPSET6" "$subnet" 2>/dev/null && ((COUNT_V6++)) || true
                done < "$LOCAL_V6"
            fi
        else
            # Скачиваем из источников
            COUNT_V4=$(geoblock_download_country "$cc" "$GEOBLOCK_IPSET" "ipv4")
            COUNT_V6=$(geoblock_download_country "$cc" "$GEOBLOCK_IPSET6" "ipv6")
        fi

        echo "IPv4: $COUNT_V4, IPv6: $COUNT_V6"
        TOTAL_V4=$((TOTAL_V4 + COUNT_V4))
        TOTAL_V6=$((TOTAL_V6 + COUNT_V6))
    done

    if [ $TOTAL_V4 -eq 0 ]; then
        echo ""
        echo "⚠️  Не удалось загрузить IP диапазоны!"
        echo ""
        echo "Загрузите вручную и положите в /etc/geoblock/ru.cidr:"
        echo "  curl -s 'https://stat.ripe.net/data/country-resource-list/data.json?resource=RU' \\"
        echo "    | python3 -c \"import sys,json; [print(p) for p in json.load(sys.stdin)['data']['resources']['ipv4']]\" \\"
        echo "    > /etc/geoblock/ru.cidr"
        geoblock_remove_rules 2>/dev/null || true
        return
    fi

    log "Загружено IPv4: $TOTAL_V4, IPv6: $TOTAL_V6"

    # Добавляем защищённые IP в whitelist
    for ip in "${SAFE_IPS[@]}"; do
        ipset add "$GEOBLOCK_IPSET" "${ip}/32" 2>/dev/null || true
        echo "  ✓ whitelist: $ip"
    done

    # Всегда добавляем loopback и приватные сети
    for net in "127.0.0.0/8" "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16"; do
        ipset add "$GEOBLOCK_IPSET" "$net" 2>/dev/null || true
    done

    # === Настройка iptables ===
    echo ""
    echo "=== Настройка iptables ==="

    # Чистим старые правила
    geoblock_remove_rules 2>/dev/null || true

    # Создаём цепочку
    iptables -N "$GEOBLOCK_CHAIN" 2>/dev/null || iptables -F "$GEOBLOCK_CHAIN"
    ip6tables -N "$GEOBLOCK_CHAIN" 2>/dev/null || ip6tables -F "$GEOBLOCK_CHAIN"

    # ПРАВИЛЬНЫЙ порядок правил:
    # 1. ESTABLISHED/RELATED — первым, чтобы не рвать текущие соединения
    # 2. Whitelist GEO-ALLOWED
    # 3. DROP по портам или всё

    # IPv4 цепочка
    iptables -A "$GEOBLOCK_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    iptables -A "$GEOBLOCK_CHAIN" -m set --match-set "$GEOBLOCK_IPSET" src -j RETURN
    # IPv6 цепочка
    ip6tables -A "$GEOBLOCK_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    ip6tables -A "$GEOBLOCK_CHAIN" -m set --match-set "$GEOBLOCK_IPSET6" src -j RETURN

    if [ -n "$(echo $GEO_PORTS_INPUT | tr -d ' ')" ]; then
        for p in $GEO_PORTS_INPUT; do
            iptables  -A "$GEOBLOCK_CHAIN" -p tcp --dport "$p" -j DROP
            iptables  -A "$GEOBLOCK_CHAIN" -p udp --dport "$p" -j DROP
            ip6tables -A "$GEOBLOCK_CHAIN" -p tcp --dport "$p" -j DROP
            ip6tables -A "$GEOBLOCK_CHAIN" -p udp --dport "$p" -j DROP
            echo "  Защита порта: $p"
        done
    else
        iptables  -A "$GEOBLOCK_CHAIN" -j DROP
        ip6tables -A "$GEOBLOCK_CHAIN" -j DROP
        echo "  Режим: полный GeoBlock"
    fi

    # Вставляем в INPUT:
    # Порядок: (legacy SCANNERS-BLOCK если остался) → GEO-BLOCK
    # GEO-BLOCK должен быть ПОСЛЕ SCANNERS-BLOCK — сначала блокируем сканеры, потом гео
    if iptables -L ufw-before-input -n &>/dev/null 2>&1; then
        # UFW присутствует — вставляем в ufw-before-input ПЕРЕД пользовательскими правилами
        # Но ПОСЛЕ SCANNERS-BLOCK если он есть
        if iptables -L SCANNERS-BLOCK -n &>/dev/null 2>&1; then
            # SCANNERS-BLOCK уже в ufw-before-input на позиции 1 — вставляем GEO-BLOCK на позицию 2
            iptables  -I ufw-before-input 2 -j "$GEOBLOCK_CHAIN"
            ip6tables -I ufw-before-input 2 -j "$GEOBLOCK_CHAIN" 2>/dev/null || true
            echo "  Позиция: ufw-before-input #2 (после SCANNERS-BLOCK)"
        else
            iptables  -I ufw-before-input 1 -j "$GEOBLOCK_CHAIN"
            ip6tables -I ufw-before-input 1 -j "$GEOBLOCK_CHAIN" 2>/dev/null || true
            echo "  Позиция: ufw-before-input #1"
        fi
    else
        # Нет UFW — вставляем в INPUT напрямую
        if iptables -L SCANNERS-BLOCK -n &>/dev/null 2>&1; then
            iptables  -I INPUT 2 -j "$GEOBLOCK_CHAIN"
            ip6tables -I INPUT 2 -j "$GEOBLOCK_CHAIN" 2>/dev/null || true
        else
            iptables  -I INPUT 1 -j "$GEOBLOCK_CHAIN"
            ip6tables -I INPUT 1 -j "$GEOBLOCK_CHAIN" 2>/dev/null || true
        fi
        echo "  Позиция: INPUT"
    fi

    # Сохраняем
    ipset save > "$GEOBLOCK_CONF/ipset.conf"
    mkdir -p /etc/iptables
    iptables-save  > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6

    # Systemd сервис восстановления
    cat > /etc/systemd/system/geoblock-restore.service << 'SVCEOF'
[Unit]
Description=GeoBlock ipset restore
After=network.target
Before=ufw.service crowdsec.service crowdsec-firewall-bouncer.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'test -f /etc/geoblock/ipset.conf && /usr/sbin/ipset restore -! -f /etc/geoblock/ipset.conf || true'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVCEOF

    # Скрипт обновления (крон)
    cat > /usr/local/bin/geoblock-update.sh << 'SCRIPT'
#!/bin/bash
# GeoBlock updater — запускается из крона каждое воскресенье в 03:00
CONF=/etc/geoblock
IPSET=GEO-ALLOWED
IPSET6=GEO-ALLOWED-V6

[ -f "$CONF/countries.txt" ] || exit 1
COUNTRIES=($(cat "$CONF/countries.txt"))

# Временные ipset для атомарного обновления
TMP_IPSET="GEO-ALLOWED-TMP"
TMP_IPSET6="GEO-ALLOWED-TMP6"
ipset destroy "$TMP_IPSET"  2>/dev/null || true
ipset destroy "$TMP_IPSET6" 2>/dev/null || true
ipset create  "$TMP_IPSET"  hash:net family inet  maxelem 1000000
ipset create  "$TMP_IPSET6" hash:net family inet6 maxelem 500000

# Приватные сети всегда в whitelist
for net in "127.0.0.0/8" "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16"; do
    ipset add "$TMP_IPSET" "$net" 2>/dev/null || true
done

TOTAL=0
for cc in "${COUNTRIES[@]}"; do
    COUNT=0

    # Источник 1: локальный файл (приоритет если свежий < 7 дней)
    LOCAL="$CONF/${cc}.cidr"
    if [ -f "$LOCAL" ] && [ "$(find "$LOCAL" -mtime -7 2>/dev/null)" ]; then
        while IFS= read -r s; do
            [ -z "$s" ] && continue
            ipset add "$TMP_IPSET" "$s" 2>/dev/null && ((COUNT++)) || true
        done < "$LOCAL"
    fi

    # Источник 2: RIPE NCC
    if [ $COUNT -eq 0 ]; then
        DATA=$(curl -sf --max-time 25 \
            "https://stat.ripe.net/data/country-resource-list/data.json?resource=${cc^^}" | \
            python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    [print(p) for p in d['data']['resources']['ipv4']]
except: pass
" 2>/dev/null)
        if [ -n "$DATA" ]; then
            while IFS= read -r s; do
                [ -z "$s" ] && continue
                ipset add "$TMP_IPSET" "$s" 2>/dev/null && ((COUNT++)) || true
            done <<< "$DATA"
            # Обновляем локальный файл
            echo "$DATA" > "$LOCAL"
        fi
    fi

    # Источник 3: ipdeny (резерв)
    if [ $COUNT -eq 0 ]; then
        DATA=$(curl -sfL --max-time 15 \
            "http://www.ipdeny.com/ipblocks/data/aggregated/${cc}-aggregated.txt" | \
            grep -vE '^#|^$')
        if [ -n "$DATA" ]; then
            while IFS= read -r s; do
                [ -z "$s" ] && continue
                ipset add "$TMP_IPSET" "$s" 2>/dev/null && ((COUNT++)) || true
            done <<< "$DATA"
        fi
    fi

    TOTAL=$((TOTAL + COUNT))
    echo "[$(date '+%H:%M:%S')] ${cc^^}: $COUNT подсетей"
done

if [ $TOTAL -gt 0 ]; then
    # Атомарная замена
    ipset swap "$TMP_IPSET"  "$IPSET"  2>/dev/null || true
    ipset swap "$TMP_IPSET6" "$IPSET6" 2>/dev/null || true
    ipset save > "$CONF/ipset.conf"
    echo "[$(date)] ✓ GeoBlock обновлён: ${COUNTRIES[*]^^}, всего $TOTAL подсетей"
else
    echo "[$(date)] ✗ Обновление не удалось — старые данные сохранены"
fi

ipset destroy "$TMP_IPSET"  2>/dev/null || true
ipset destroy "$TMP_IPSET6" 2>/dev/null || true
SCRIPT
    chmod +x /usr/local/bin/geoblock-update.sh

    # Крон — каждое воскресенье в 03:00
    (crontab -l 2>/dev/null | grep -v geoblock-update; \
     echo "0 3 * * 0 /usr/local/bin/geoblock-update.sh >> /var/log/geoblock-update.log 2>&1") | crontab -

    systemctl daemon-reload
    systemctl enable geoblock-restore.service 2>/dev/null
    systemctl restart geoblock-restore.service 2>/dev/null || true

    log "GeoBlock включён. Страны: ${COUNTRIES[*]}"
    echo ""
    echo "✓ GeoBlock активен!"
    echo "  Страны:          ${COUNTRIES[*]^^}"
    echo "  IPv4 подсетей:   $TOTAL_V4"
    echo "  IPv6 подсетей:   $TOTAL_V6"
    echo "  Защищённые IP:   ${SAFE_IPS[*]}"
    echo "  Обновление:      каждое воскресенье 03:00"
    echo ""
    echo "Цепочка GEO-BLOCK:"
    iptables -L "$GEOBLOCK_CHAIN" -n --line-numbers
}

geoblock_add_country() {
    echo ""
    read -e -p "Код страны для добавления (например: by): " CC
    CC=$(echo "$CC" | tr '[:upper:]' '[:lower:]')
    [ -z "$CC" ] && return

    mkdir -p "$GEOBLOCK_CONF"
    grep -qx "$CC" "$GEOBLOCK_CONF/countries.txt" 2>/dev/null || echo "$CC" >> "$GEOBLOCK_CONF/countries.txt"

    echo "Загружаем диапазоны для ${CC^^}..."
    COUNT=$(geoblock_download_country "$CC" "$GEOBLOCK_IPSET" "ipv4")
    geoblock_download_country "$CC" "$GEOBLOCK_IPSET6" "ipv6" > /dev/null

    ipset save > "$GEOBLOCK_CONF/ipset.conf"
    log "Добавлена страна: ${CC^^}, подсетей: $COUNT"
    echo "✓ ${CC^^}: $COUNT подсетей добавлено"
}

geoblock_remove_country() {
    echo ""
    [ ! -f "$GEOBLOCK_CONF/countries.txt" ] && echo "Список стран не найден." && return
    echo "Текущие страны:"
    cat -n "$GEOBLOCK_CONF/countries.txt"
    echo ""
    read -e -p "Код страны для удаления: " CC
    CC=$(echo "$CC" | tr '[:upper:]' '[:lower:]')
    sed -i "/^${CC}$/d" "$GEOBLOCK_CONF/countries.txt"
    log "Удалена страна: ${CC^^}. Перестраиваем ipset..."
    geoblock_enable
}

geoblock_remove_rules() {
    # Удаляем из ufw-before-input если UFW есть
    if iptables -L ufw-before-input -n &>/dev/null 2>&1; then
        while iptables -D ufw-before-input -j "$GEOBLOCK_CHAIN" 2>/dev/null; do true; done
        while ip6tables -D ufw-before-input -j "$GEOBLOCK_CHAIN" 2>/dev/null; do true; done
    fi
    # Удаляем из INPUT
    while iptables -D INPUT -j "$GEOBLOCK_CHAIN" 2>/dev/null; do true; done
    while ip6tables -D INPUT -j "$GEOBLOCK_CHAIN" 2>/dev/null; do true; done
    # Флашим и удаляем цепочку
    iptables  -F "$GEOBLOCK_CHAIN" 2>/dev/null || true
    ip6tables -F "$GEOBLOCK_CHAIN" 2>/dev/null || true
    iptables  -X "$GEOBLOCK_CHAIN" 2>/dev/null || true
    ip6tables -X "$GEOBLOCK_CHAIN" 2>/dev/null || true
}

geoblock_disable() {
    echo ""
    read -e -p "Выключить GeoBlock? Весь трафик будет разрешён. (y/n): " CONFIRM
    [[ "$CONFIRM" != "y" ]] && echo "Отменено." && return

    geoblock_remove_rules
    ipset destroy "$GEOBLOCK_IPSET"  2>/dev/null || true
    ipset destroy "$GEOBLOCK_IPSET6" 2>/dev/null || true
    systemctl disable geoblock-restore.service 2>/dev/null || true
    systemctl stop    geoblock-restore.service 2>/dev/null || true
    crontab -l 2>/dev/null | grep -v geoblock-update | crontab -
    rm -f "$GEOBLOCK_CONF/ipset.conf"

    log "GeoBlock выключен."
    echo "✓ GeoBlock выключен."
}

geoblock_status() {
    echo ""
    echo "══════════════════════════════════════"
    echo " GeoBlock — статус"
    echo "══════════════════════════════════════"

    if ! iptables -L "$GEOBLOCK_CHAIN" -n &>/dev/null 2>&1; then
        echo "GeoBlock: ВЫКЛЮЧЕН"
        return
    fi

    echo "GeoBlock: ВКЛЮЧЁН"
    echo ""
    echo "Страны:"
    cat "$GEOBLOCK_CONF/countries.txt" 2>/dev/null | while read cc; do echo "  ${cc^^}"; done
    echo ""
    echo "IPv4 подсетей: $(ipset list $GEOBLOCK_IPSET  2>/dev/null | grep 'Number of entries' | awk '{print $4}')"
    echo "IPv6 подсетей: $(ipset list $GEOBLOCK_IPSET6 2>/dev/null | grep 'Number of entries' | awk '{print $4}')"
    echo ""
    echo "Цепочка iptables:"
    iptables -L "$GEOBLOCK_CHAIN" -n --line-numbers 2>/dev/null
    echo ""
    echo "Позиция в INPUT:"
    iptables -L INPUT -n --line-numbers 2>/dev/null | grep -E "GEO-BLOCK|SCANNERS-BLOCK|num"
    echo ""
    echo "Обновлено: $(stat -c '%y' $GEOBLOCK_CONF/ipset.conf 2>/dev/null | cut -d. -f1 || echo 'неизвестно')"
}

# =====================================
# МОДУЛЬ 9: SWAP
# =====================================
setup_swap() {
    print_header
    echo "╔══════════════════════════╗"
    echo "║   Управление Swap       ║"
    echo "╚══════════════════════════╝"
    echo ""

    if swapon --show 2>/dev/null | grep -q .; then
        echo "Статус: ВКЛЮЧЁН"
        swapon --show=NAME,SIZE,TYPE,USED --noheadings 2>/dev/null | while read name size type used; do
            echo "  Файл: $name  Размер: $size  Использовано: $used"
        done
        echo "  swappiness: $(cat /proc/sys/vm/swappiness)"
    else
        echo "Статус: ВЫКЛЮЧЕН"
    fi

    RAM_MB=$(free -m | awk '/^Mem:/ {print $2}')
    echo "  RAM: $(free -h | awk '/^Mem:/ {print $2}')"
    echo ""
    echo "  1) Создать swap"
    echo "  2) Удалить swap"
    echo "  3) Изменить swappiness"
    echo "  0) Назад"
    echo ""
    read -e -p "Выберите [0-3]: " SWAP_CHOICE

    case $SWAP_CHOICE in
        1) swap_create "$RAM_MB" ;;
        2) swap_delete ;;
        3) swap_swappiness ;;
        0) return ;;
        *) echo "Неверный выбор." ;;
    esac
}

swap_create() {
    local RAM_MB="$1"

    if swapon --show 2>/dev/null | grep -q "/swapfile"; then
        echo "Swap уже существует:"; swapon --show
        read -e -p "Пересоздать? (y/n): " RECREATE
        [[ "$RECREATE" != "y" ]] && return
        swap_delete_silent
    fi

    echo ""
    if [ "$RAM_MB" -le 2048 ]; then
        DEFAULT_SIZE="2G"; echo "  RAM ≤ 2GB → рекомендуется 2G"
    elif [ "$RAM_MB" -le 8192 ]; then
        DEFAULT_SIZE="4G"; echo "  RAM 2–8GB → рекомендуется 4G"
    else
        DEFAULT_SIZE="2G"; echo "  RAM > 8GB → рекомендуется 2G"
    fi

    echo "Примеры: 512M 1G 2G 4G"
    read -e -p "Размер swap [${DEFAULT_SIZE}]: " SWAP_SIZE
    SWAP_SIZE=${SWAP_SIZE:-$DEFAULT_SIZE}

    NEED_MB=$(echo "$SWAP_SIZE" | awk '{
        val=$1
        if (val ~ /G$/) { sub(/G$/,"",val); val=val*1024 }
        else if (val ~ /M$/) { sub(/M$/,"",val) }
        print int(val)
    }')
    FREE_DISK=$(df -m / | awk 'NR==2 {print $4}')

    if [ "$FREE_DISK" -lt "$NEED_MB" ]; then
        echo "ОШИБКА: недостаточно места! Нужно: ${SWAP_SIZE}, доступно: ${FREE_DISK}MB"
        return
    fi

    log_section "Создание swap ${SWAP_SIZE}"
    echo "Создаём /swapfile..."
    if fallocate -l "$SWAP_SIZE" /swapfile 2>/dev/null; then
        echo "  ✓ fallocate"
    else
        echo "  используем dd..."
        dd if=/dev/zero of=/swapfile bs=1M count="$NEED_MB" status=progress
    fi

    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile

    grep -q "/swapfile" /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab

    CURRENT_SW=$(cat /proc/sys/vm/swappiness)
    if [ "$CURRENT_SW" -gt 10 ]; then
        sysctl -w vm.swappiness=10 >/dev/null
        grep -q "vm.swappiness" /etc/sysctl.conf && \
            sed -i "s/vm.swappiness=.*/vm.swappiness=10/" /etc/sysctl.conf || \
            echo "vm.swappiness=10" >> /etc/sysctl.conf
        log "swappiness: $CURRENT_SW → 10"
    fi

    log "Swap создан: ${SWAP_SIZE}"
    echo ""; echo "✓ Swap создан!"; free -h
}

swap_delete() {
    echo ""
    if ! swapon --show 2>/dev/null | grep -q "/swapfile"; then
        echo "/swapfile не найден."; return
    fi
    read -e -p "Удалить /swapfile? (y/n): " CONFIRM
    [[ "$CONFIRM" != "y" ]] && echo "Отменено." && return
    swap_delete_silent
    echo "✓ Swap удалён."; free -h
}

swap_delete_silent() {
    swapoff /swapfile 2>/dev/null || true
    rm -f /swapfile
    sed -i '/\/swapfile/d' /etc/fstab
    log "Swap удалён."
}

swap_swappiness() {
    echo ""
    CURRENT=$(cat /proc/sys/vm/swappiness)
    echo "Текущий swappiness: $CURRENT"
    echo "  10 — сервер  30 — рабочая станция  60 — дефолт Ubuntu"
    read -e -p "Новое значение [10]: " NEW_VAL
    NEW_VAL=${NEW_VAL:-10}
    if ! [[ "$NEW_VAL" =~ ^[0-9]+$ ]] || [ "$NEW_VAL" -gt 100 ]; then
        echo "ОШИБКА: значение от 0 до 100"; return
    fi
    sysctl -w vm.swappiness="$NEW_VAL" >/dev/null
    grep -q "vm.swappiness" /etc/sysctl.conf && \
        sed -i "s/vm.swappiness=.*/vm.swappiness=${NEW_VAL}/" /etc/sysctl.conf || \
        echo "vm.swappiness=${NEW_VAL}" >> /etc/sysctl.conf
    log "swappiness: $CURRENT → $NEW_VAL"
    echo "✓ swappiness = $NEW_VAL"
}


# =====================================================
# МОДУЛЬ 10: УСТАНОВКА REMNANODE + CADDY (встроено)
# =====================================================

# ── цвета для установщика ──
_RN_RED='\033[0;31m'; _RN_GREEN='\033[0;32m'; _RN_YELLOW='\033[1;33m'
_RN_CYAN='\033[0;36m'; _RN_BOLD='\033[1m'; _RN_RESET='\033[0m'

rn_info()    { echo -e "${_RN_CYAN}[INFO]${_RN_RESET} $*"; }
rn_success() { echo -e "${_RN_GREEN}[OK]${_RN_RESET}   $*"; }
rn_warn()    { echo -e "${_RN_YELLOW}[WARN]${_RN_RESET} $*"; }
rn_error()   { echo -e "${_RN_RED}[ERR]${_RN_RESET}  $*"; return 1; }

rn_is_yes() {
  local v="${1,,}"
  case "$v" in
    y|yes|"") return 0 ;;
    *)         return 1 ;;
  esac
}

rn_choose_install_dir() {
  echo -e "\n${_RN_BOLD}Куда установить?${_RN_RESET}"
  echo "  1) /opt/remnanode   (рекомендуется)"
  echo "  2) /root/remnanode"
  echo "  3) Указать путь вручную"
  echo ""
  read -rep "Выбор [1-3, Enter = 1]: " _rn_dir_choice
  case "${_rn_dir_choice:-1}" in
    1) RN_INSTALL_DIR="/opt/remnanode" ;;
    2) RN_INSTALL_DIR="/root/remnanode" ;;
    3)
      read -rep "Введи путь: " RN_INSTALL_DIR
      [[ -n "$RN_INSTALL_DIR" ]] || { rn_error "Путь не может быть пустым"; return 1; }
      ;;
    *) rn_error "Неверный выбор"; return 1 ;;
  esac
  RN_INSTALL_DIR="${RN_INSTALL_DIR%/}"
  rn_success "Директория: ${RN_INSTALL_DIR}"
}

rn_ask_params() {
  echo ""
  while true; do
    read -rep "Порт remnanode [Enter = 2222]: " RN_NODE_PORT
    RN_NODE_PORT="${RN_NODE_PORT:-2222}"
    if [[ "$RN_NODE_PORT" =~ ^[0-9]+$ ]] && (( RN_NODE_PORT >= 1 && RN_NODE_PORT <= 65535 )); then
      break
    fi
    rn_warn "Введи корректный порт (1–65535)"
  done

  echo ""
  while true; do
    read -rep "SECRET_KEY / mTLS-ключ (вставь из панели remnawave): " RN_SECRET_KEY
    [[ -n "$RN_SECRET_KEY" ]] && break
    rn_warn "SECRET_KEY не может быть пустым"
  done

  echo ""
  echo -e "${_RN_BOLD}IP панели remnawave${_RN_RESET} — порт ${RN_NODE_PORT} откроется ТОЛЬКО для него."
  echo "  Панель управляет нодой по этому порту. Ограничение = меньше поверхность атаки."
  echo "  Enter = открыть порт всем (менее безопасно)."
  read -rep "IP панели [Enter = всем]: " RN_PANEL_IP
  RN_PANEL_IP="${RN_PANEL_IP:-}"
  if [[ -n "$RN_PANEL_IP" ]] && ! [[ "$RN_PANEL_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    rn_warn "Не похоже на IPv4 — порт ${RN_NODE_PORT} будет открыт всем."
    RN_PANEL_IP=""
  fi

  echo ""
  while true; do
    read -rep "Домен для заглушки selfsteal (например: node1.example.com): " RN_DOMAIN
    [[ -n "$RN_DOMAIN" ]] && break
    rn_warn "Домен не может быть пустым"
  done

  echo ""
  echo -e "${_RN_BOLD}Версия образа remnawave/node${_RN_RESET}"
  echo "  Должна быть СОВМЕСТИМА с версией твоей панели (иначе нода не получит конфиг)."
  echo "  Примеры: latest, 2.8.0, 3.2.2. Enter = latest."
  read -rep "Версия [Enter = latest]: " RN_NODE_VERSION
  RN_NODE_VERSION="${RN_NODE_VERSION:-latest}"

  echo ""
  echo -e "${_RN_BOLD}Защита от утечки памяти (актуально для XHTTP / packet-up)?${_RN_RESET}"
  echo "  При включении задаётся лимит памяти контейнера и создаётся"
  echo "  скрипт автоперезапуска по порогу + cron каждые 10 минут."
  echo ""
  read -rep "Включить? [Y/n]: " _rn_xhttp_choice

  if rn_is_yes "$_rn_xhttp_choice"; then
    RN_XHTTP_MODE=true
    echo ""
    echo -e "  ${_RN_CYAN}Лимит памяти контейнера${_RN_RESET} (mem_limit = memswap_limit)"
    echo "  Примеры: 1500m  2g  1g"
    read -rep "  mem_limit [Enter = 1500m]: " RN_MEM_LIMIT
    RN_MEM_LIMIT="${RN_MEM_LIMIT:-1500m}"
    echo ""
    echo -e "  ${_RN_CYAN}Порог перезапуска, % от mem_limit${_RN_RESET}"
    read -rep "  Порог % [Enter = 80]: " RN_OOM_THRESHOLD
    RN_OOM_THRESHOLD="${RN_OOM_THRESHOLD:-80}"
    if ! [[ "$RN_OOM_THRESHOLD" =~ ^[0-9]+$ ]] || (( RN_OOM_THRESHOLD < 1 || RN_OOM_THRESHOLD > 99 )); then
      rn_warn "Некорректное значение, использую 80"
      RN_OOM_THRESHOLD=80
    fi
  else
    RN_XHTTP_MODE=false
    RN_MEM_LIMIT=""
    RN_OOM_THRESHOLD=80
  fi

  echo ""
  rn_success "Параметры приняты"
  echo -e "  Порт:        ${_RN_CYAN}${RN_NODE_PORT}${_RN_RESET}"
  echo -e "  Домен:       ${_RN_CYAN}${RN_DOMAIN}${_RN_RESET}"
  echo -e "  Версия ноды: ${_RN_CYAN}remnawave/node:${RN_NODE_VERSION}${_RN_RESET}"
  echo -e "  Key:         ${_RN_CYAN}${RN_SECRET_KEY:0:20}...${_RN_RESET}"
  if [[ -n "$RN_PANEL_IP" ]]; then
    echo -e "  Панель IP:   ${_RN_CYAN}${RN_PANEL_IP}${_RN_RESET} (порт ${RN_NODE_PORT} только для него)"
  else
    echo -e "  Панель IP:   ${_RN_YELLOW}не задан — порт ${RN_NODE_PORT} открыт всем${_RN_RESET}"
  fi
  if [[ "$RN_XHTTP_MODE" == true ]]; then
    echo -e "  mem_limit:   ${_RN_CYAN}${RN_MEM_LIMIT}${_RN_RESET}"
  else
    echo -e "  mem_limit:   ${_RN_YELLOW}без ограничений${_RN_RESET}"
  fi
  if [[ "$RN_XHTTP_MODE" == true ]]; then
    echo -e "  OOM watcher: ${_RN_CYAN}включён, порог ${RN_OOM_THRESHOLD}%${_RN_RESET}"
  else
    echo -e "  OOM watcher: ${_RN_YELLOW}отключён${_RN_RESET}"
  fi
  echo ""
  read -rep "Продолжить? [Y/n]: " _rn_confirm
  if ! rn_is_yes "$_rn_confirm"; then
    rn_warn "Установка отменена"
    return 1
  fi
}

rn_install_docker() {
  if command -v docker >/dev/null 2>&1; then
    if systemctl enable --now docker.service >/dev/null 2>&1 &&
       docker info >/dev/null 2>&1; then
      rn_success "Docker доступен: $(docker --version)"
      return 0
    fi
  fi

  rn_info "Устанавливаю Docker Engine, CLI и Compose из репозитория ОС..."
  local docker_packages=(docker.io docker-compose)
  # Debian 13: Docker CLI may be packaged separately.
  if apt-cache show docker-cli 2>/dev/null | grep -q '^Package: docker-cli$'; then
    docker_packages+=(docker-cli)
  fi
  if ! apt-get install -y --no-remove "${docker_packages[@]}"; then
    rn_error "APT не смог установить Docker; проверь apt-get и dpkg"
    return 1
  fi
  hash -r
  if ! command -v docker >/dev/null 2>&1; then
    rn_warn "Docker Engine установлен, но CLI отсутствует; проверяю отдельный пакет docker-cli"
    if apt-cache show docker-cli 2>/dev/null | grep -q '^Package: docker-cli$'; then
      apt-get install -y --no-remove docker-cli || true
    fi
  fi
  if ! command -v docker >/dev/null 2>&1; then
    dpkg -L docker.io 2>/dev/null | grep '/docker$' || true
    ls -l /usr/bin/docker /usr/local/bin/docker 2>/dev/null || true
    dpkg --audit || true
    rn_error "Docker CLI не найден — прекращаю установку ноды"
    return 1
  fi
  if ! systemctl enable --now docker.service; then
    journalctl -u docker.service -n 30 --no-pager || true
    rn_error "Не удалось включить Docker service"
    return 1
  fi
  if ! docker info >/dev/null 2>&1; then
    journalctl -u docker.service -n 30 --no-pager || true
    rn_error "Docker daemon не отвечает"
    return 1
  fi
  rn_success "Docker установлен: $(docker --version)"
}

rn_compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    rn_error "Нет Docker Compose v2 (plugin или docker-compose)"
    return 1
  fi
}

rn_fix_docker_socket() {
  # Вызывается если docker уже стоит но не работает
  if ! docker info &>/dev/null 2>&1; then
    rn_warn "Docker daemon не отвечает — исправляю docker.socket..."
    systemctl stop docker.socket docker.service 2>/dev/null || true
    systemctl disable docker.socket 2>/dev/null || true
    rm -f /var/run/docker.sock 2>/dev/null || true
    systemctl enable --now docker.service
    sleep 2
    if docker info &>/dev/null 2>&1; then
      rn_success "Docker daemon исправлен"
    else
      rn_error "Не удалось запустить Docker. Проверь: journalctl -u docker -n 20"
      return 1
    fi
  fi
}

rn_install_deps() {
  rn_info "Обновление пакетов и установка зависимостей..."
  apt-get update -qq || { rn_error "APT update завершился ошибкой"; return 1; }
  if ! command -v logrotate >/dev/null 2>&1; then
    apt-get install -y --no-remove logrotate || return 1
  fi
  if ! command -v docker >/dev/null 2>&1; then
    rn_install_docker || return 1
  else
    rn_fix_docker_socket || return 1
  fi
  if ! docker info >/dev/null 2>&1; then
    rn_error "Docker daemon не работает"; return 1
  fi
  if ! rn_compose version >/dev/null 2>&1; then
    # Debian/Ubuntu distribution Compose v2 package can expose docker-compose
    # rather than 'docker compose'. No Docker CE repo fallback on RU nodes.
    apt-get install -y --no-remove docker-compose || return 1
    rn_compose version >/dev/null 2>&1 || {
      rn_error "Docker Compose v2 недоступен"; return 1;
    }
  fi
  rn_success "Compose: $(rn_compose version)"
}

rn_prepare_dirs() {
  rn_info "Подготовка директорий..."
  mkdir -p "${RN_INSTALL_DIR}"
  mkdir -p /var/log/remnanode
  chmod 750 /var/log/remnanode
  mkdir -p /var/www/html
  chmod 755 /var/www/html
  rn_success "Директории созданы"
}

rn_create_stub() {
  # По требованию: заглушку-декой НЕ ставим, только гарантируем наличие папки.
  # Selfsteal-контент (если нужен) кладётся в /var/www/html вручную.
  mkdir -p /var/www/html
  chmod 755 /var/www/html
  rn_success "Папка /var/www/html готова (без декой-заглушки)"
}

rn_ask_cloudflare() {
  echo ""
  echo -e "${_RN_BOLD}Cloudflare DNS Challenge для автоматического перевыпуска сертификата?${_RN_RESET}"
  echo "  Нужен если домен стоит за Cloudflare Proxy (оранжевое облако)."
  echo "  Требуется Cloudflare API Token с правами Zone:DNS:Edit."
  echo ""
  echo -e "  ${_RN_YELLOW}Как создать токен:${_RN_RESET}"
  echo "  1. dash.cloudflare.com → My Profile → API Tokens"
  echo "  2. Create Token → Edit zone DNS (шаблон)"
  echo "  3. Zone Resources → Specific zone → твой домен"
  echo "  4. Create Token → скопируй"
  echo ""
  echo -e "  ${_RN_YELLOW}⚠ Global API Key НЕ подходит — нужен именно API Token${_RN_RESET}"
  echo ""
  read -rep "Включить Cloudflare DNS Challenge? [y/N]: " _rn_cf_choice

  if rn_is_yes "$_rn_cf_choice" && [[ -n "$_rn_cf_choice" ]]; then
    RN_CF_MODE=true
    RN_CF_EMAIL=""  # Email не нужен для API Token

    echo ""
    while true; do
      read -rep "  Cloudflare API Token (Zone:DNS:Edit): " RN_CF_API_KEY
      [[ -n "$RN_CF_API_KEY" ]] && break
      rn_warn "API Token не может быть пустым"
    done

    rn_success "Cloudflare DNS Challenge будет настроен"
    echo -e "  Token: ${_RN_CYAN}${RN_CF_API_KEY:0:8}...${_RN_RESET}"
  else
    RN_CF_MODE=false
    RN_CF_EMAIL=""
    RN_CF_API_KEY=""
  fi
}

rn_create_dockerfile() {
  if [[ "$RN_CF_MODE" != true ]]; then
    return 0
  fi
  rn_info "Создаю Dockerfile для Caddy с плагином cloudflare..."
  cat > "${RN_INSTALL_DIR}/Dockerfile" <<'DOCKERFILE'
FROM caddy:2.11.2-builder AS builder
RUN xcaddy build     --with github.com/caddy-dns/cloudflare
FROM caddy:2.11.2
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
DOCKERFILE
  rn_success "Dockerfile создан"
}

rn_create_caddyfile() {
  rn_info "Создаю Caddyfile (selfsteal: Caddy за xray на unix-сокете)..."

  # SELFSTEAL-АРХИТЕКТУРА:
  #   клиент → :443 → xray (Reality/VLESS)
  #                    ├─ VPN-трафик → обрабатывает сам
  #                    └─ fallback (не-VPN) → unix-socket → Caddy → /var/www/html
  # 443 держит xray, а Caddy сидит за ним на сокете (не на порту).
  # listener_wrappers { proxy_protocol tls } — критично: xray передаёт
  # клиентский IP через PROXY protocol, Caddy его распаковывает.
  # На :80 отдаём 204 (маскировка) + редирект http://selfsteal → https.
  if [[ "$RN_CF_MODE" == true ]]; then
    cat > "${RN_INSTALL_DIR}/Caddyfile" <<EOF
{
    admin off
    servers {
        listener_wrappers {
            proxy_protocol
            tls
        }
    }
    auto_https disable_redirects
    acme_dns cloudflare {
        api_token {env.CLOUDFLARE_API_TOKEN}
    }
}

http://{\$SELF_STEAL_DOMAIN} {
    bind 0.0.0.0
    redir https://{\$SELF_STEAL_DOMAIN}{uri} permanent
}

https://{\$SELF_STEAL_DOMAIN} {
    bind unix/{\$CADDY_SOCKET_PATH}
    root * /var/www/html
    try_files {path} /index.html
    file_server
    encode gzip
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        -Server
    }
}

:80 {
    bind 0.0.0.0
    respond 204
}
EOF
  else
    cat > "${RN_INSTALL_DIR}/Caddyfile" <<EOF
{
    admin off
    servers {
        listener_wrappers {
            proxy_protocol
            tls
        }
    }
    auto_https disable_redirects
}

http://{\$SELF_STEAL_DOMAIN} {
    bind 0.0.0.0
    redir https://{\$SELF_STEAL_DOMAIN}{uri} permanent
}

https://{\$SELF_STEAL_DOMAIN} {
    bind unix/{\$CADDY_SOCKET_PATH}
    root * /var/www/html
    try_files {path} /index.html
    file_server
    encode gzip
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        -Server
    }
}

:80 {
    bind 0.0.0.0
    respond 204
}
EOF
  fi
  rn_success "Caddyfile создан (selfsteal-режим, Caddy на unix-сокете)"
}

rn_create_compose() {
  rn_info "Создаю docker-compose.yml..."

  if [[ "$RN_CF_MODE" == true ]]; then
    # Caddy с кастомным образом + CF env
    cat > "${RN_INSTALL_DIR}/docker-compose.yml" <<EOF
services:
  caddy:
    build: .
    image: caddy-cloudflare:local
    container_name: caddy-remnanode
    restart: always
    network_mode: host
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    logging:
      driver: json-file
      options:
        max-size: 100m
        max-file: "5"
    environment:
      - CLOUDFLARE_API_TOKEN=${RN_CF_API_KEY}
      - SELF_STEAL_DOMAIN=${RN_DOMAIN}
      - CADDY_SOCKET_PATH=/dev/shm/nginx.sock
    command: sh -c 'rm -f /dev/shm/nginx.sock && caddy run --config /etc/caddy/Caddyfile --adapter caddyfile'
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - /var/www/html:/var/www/html:ro
      - /dev/shm:/dev/shm:rw
      - caddy_data:/data
      - caddy_config:/config
    healthcheck:
      test: ["CMD", "test", "-S", "/dev/shm/nginx.sock"]
      interval: 2s
      timeout: 5s
      retries: 15
      start_period: 5s

  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: remnawave/node:${RN_NODE_VERSION}
    network_mode: host
    restart: always
    cap_add:
      - NET_ADMIN
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    volumes:
      - /var/log/remnanode:/var/log/remnanode
      - /dev/shm:/dev/shm:rw
    environment:
      - NODE_PORT=${RN_NODE_PORT}
      - SECRET_KEY="${RN_SECRET_KEY}"

volumes:
  caddy_data:
    name: caddy_data
  caddy_config:
    name: caddy_config
EOF
  else
    cat > "${RN_INSTALL_DIR}/docker-compose.yml" <<EOF
services:
  caddy:
    image: caddy:2.11.2
    container_name: caddy-remnanode
    restart: always
    network_mode: host
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    logging:
      driver: json-file
      options:
        max-size: 100m
        max-file: "5"
    environment:
      - SELF_STEAL_DOMAIN=${RN_DOMAIN}
      - CADDY_SOCKET_PATH=/dev/shm/nginx.sock
    command: sh -c 'rm -f /dev/shm/nginx.sock && caddy run --config /etc/caddy/Caddyfile --adapter caddyfile'
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - /var/www/html:/var/www/html:ro
      - /dev/shm:/dev/shm:rw
      - caddy_data:/data
      - caddy_config:/config
    healthcheck:
      test: ["CMD", "test", "-S", "/dev/shm/nginx.sock"]
      interval: 2s
      timeout: 5s
      retries: 15
      start_period: 5s

  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: remnawave/node:${RN_NODE_VERSION}
    network_mode: host
    restart: always
    cap_add:
      - NET_ADMIN
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    volumes:
      - /var/log/remnanode:/var/log/remnanode
      - /dev/shm:/dev/shm:rw
    environment:
      - NODE_PORT=${RN_NODE_PORT}
      - SECRET_KEY="${RN_SECRET_KEY}"

volumes:
  caddy_data:
    name: caddy_data
  caddy_config:
    name: caddy_config
EOF
  fi
  # Insert limits only when the user explicitly opted into the OOM watcher.
  if [[ "$RN_XHTTP_MODE" == true ]]; then
    RN_COMPOSE_FILE="${RN_INSTALL_DIR}/docker-compose.yml" RN_COMPOSE_MEM_LIMIT="$RN_MEM_LIMIT" python3 - <<'PY_RN_MEM'
import os
from pathlib import Path
path = Path(os.environ["RN_COMPOSE_FILE"])
content = path.read_text()
anchor = "  remnanode:\n    container_name: remnanode\n"
if content.count(anchor) != 1:
    raise SystemExit("ERROR: remnanode service anchor not found exactly once")
limit = os.environ["RN_COMPOSE_MEM_LIMIT"]
content = content.replace(anchor, anchor + f"    mem_limit: {limit}\n    memswap_limit: {limit}\n", 1)
path.write_text(content)
PY_RN_MEM
    if [[ $? -ne 0 ]]; then
      rn_error "Не удалось применить mem_limit к Compose"
      return 1
    fi
  fi
  rn_success "docker-compose.yml создан"
}

rn_setup_oom_watcher() {
  if [[ "$RN_XHTTP_MODE" != true ]]; then
    return 0
  fi
  local script="${RN_INSTALL_DIR}/restart-if-oom.sh"
  local oom_log="/var/log/remnanode/oom-restart.log"

  rn_info "Создаю OOM watcher: ${script}"
  cat > "${script}" <<WATCHER
#!/usr/bin/env bash
THRESHOLD=${RN_OOM_THRESHOLD}
CONTAINER="remnanode"
LOG="${oom_log}"

MEM_RAW=\$(docker stats --no-stream --format "{{.MemPerc}}" "\$CONTAINER" 2>/dev/null | tr -d '%')
if [[ -z "\$MEM_RAW" ]]; then
  echo "\$(date '+%Y-%m-%d %H:%M:%S') [WARN] Не удалось получить статистику \$CONTAINER" >> "\$LOG"
  exit 1
fi
MEM_INT=\${MEM_RAW%%.*}
if (( MEM_INT > THRESHOLD )); then
  echo "\$(date '+%Y-%m-%d %H:%M:%S') [RESTART] Память \${MEM_INT}% > \${THRESHOLD}%, перезапускаю \$CONTAINER" >> "\$LOG"
  docker restart "\$CONTAINER" >> "\$LOG" 2>&1
  echo "\$(date '+%Y-%m-%d %H:%M:%S') [RESTART] Готово" >> "\$LOG"
else
  echo "\$(date '+%Y-%m-%d %H:%M:%S') [OK] Память \${MEM_INT}% — в норме" >> "\$LOG"
fi
WATCHER
  chmod +x "${script}"
  rn_success "OOM watcher создан"

  rn_info "Регистрирую cron-задачу..."
  local cron_line="*/10 * * * * ${script} >> ${oom_log} 2>&1"
  local existing
  existing=$(crontab -l 2>/dev/null || true)
  if echo "$existing" | grep -qF "${script}"; then
    rn_warn "Запись в crontab уже существует — пропускаю"
  else
    ( echo "$existing"; echo "${cron_line}" ) | crontab -
    rn_success "Cron добавлен (каждые 10 минут)"
  fi
}

rn_setup_logrotate() {
  rn_info "Настройка logrotate..."
  cat > /etc/logrotate.d/remnanode <<'EOF'
/var/log/remnanode/*.log {
    su root root
    size 50M
    rotate 5
    compress
    missingok
    notifempty
    copytruncate
}
EOF
  logrotate -f /etc/logrotate.d/remnanode 2>/dev/null || true
  rn_success "logrotate настроен"
}

rn_open_panel_port() {
  # Открыть порт ноды (RN_NODE_PORT, обычно 2222) для управляющего трафика панели.
  # Если задан IP панели — открываем ТОЛЬКО для него (меньше поверхность атаки).
  # Иначе — всем. 443 (клиентский selfsteal) уже должен быть открыт базовой настройкой.
  local port="${RN_NODE_PORT:-2222}"
  if [[ -n "$RN_PANEL_IP" ]]; then
    rn_info "Открываю порт ${port} только для IP панели ${RN_PANEL_IP}..."
    if command -v ufw >/dev/null 2>&1; then
      ufw allow from "$RN_PANEL_IP" to any port "$port" proto tcp >/dev/null 2>&1
    fi
    # дублируем в vpsguard nft, если он есть (его policy accept; UFW решает доступ)
    if command -v nft >/dev/null 2>&1 && nft list table inet vpsguard >/dev/null 2>&1; then
      nft insert rule inet vpsguard input ip saddr "$RN_PANEL_IP" tcp dport "$port" accept 2>/dev/null
    fi
    rn_success "Порт ${port} открыт только для ${RN_PANEL_IP}"
  else
    rn_warn "IP панели не задан — открываю порт ${port} всем."
    command -v ufw >/dev/null 2>&1 && ufw allow "${port}/tcp" >/dev/null 2>&1
    if command -v nft >/dev/null 2>&1 && nft list table inet vpsguard >/dev/null 2>&1; then
      nft insert rule inet vpsguard input tcp dport "$port" accept 2>/dev/null
    fi
  fi
}

rn_start_services() {
  cd "${RN_INSTALL_DIR}" || return 1
  rn_compose config -q || { rn_error "Compose config невалиден"; return 1; }
  if [[ "$RN_CF_MODE" == true ]]; then
    rn_info "Собираю Caddy с Cloudflare DNS Challenge..."
    rn_compose build caddy || return 1
    rn_compose pull remnanode || return 1
  else
    rn_info "Скачиваю образы..."
    rn_compose pull || return 1
  fi
  rn_info "Запускаю контейнеры..."
  rn_compose up -d || { rn_error "Docker Compose up завершился ошибкой"; return 1; }
  local service
  for service in remnanode caddy; do
    if [[ -z "$(rn_compose ps -q "$service")" ]]; then
      rn_error "Контейнер $service не создан"; return 1
    fi
  done
  rn_success "Контейнеры созданы и запуск выполнен"
  rn_compose ps || true
  echo "Логи: cd ${RN_INSTALL_DIR} && docker compose logs -f (или docker-compose logs -f)"
}

rn_print_summary() {
  echo ""
  echo -e "${_RN_GREEN}${_RN_BOLD}════════════════════════════════════════${_RN_RESET}"
  echo -e "${_RN_GREEN}${_RN_BOLD}  Установка завершена!${_RN_RESET}"
  echo -e "${_RN_GREEN}${_RN_BOLD}════════════════════════════════════════${_RN_RESET}"
  echo ""
  echo -e "  Директория:   ${_RN_CYAN}${RN_INSTALL_DIR}${_RN_RESET}"
  echo -e "  Домен:        ${_RN_CYAN}https://${RN_DOMAIN}${_RN_RESET}"
  echo -e "  Node порт:    ${_RN_CYAN}${RN_NODE_PORT}${_RN_RESET}"
  echo -e "  mem_limit:    ${_RN_CYAN}${RN_MEM_LIMIT}${_RN_RESET}"
  echo -e "  Логи ноды:    ${_RN_CYAN}/var/log/remnanode${_RN_RESET}"
  echo -e "  Заглушка:     ${_RN_CYAN}/var/www/html/index.html${_RN_RESET}"
  if [[ "$RN_CF_MODE" == true ]]; then
    echo -e "  Cloudflare:   ${_RN_CYAN}DNS Challenge включён (авто-перевыпуск)${_RN_RESET}"
    echo -e "  CF Token:     ${_RN_CYAN}${RN_CF_API_KEY:0:8}...${_RN_RESET}"
  fi
  if [[ "$RN_XHTTP_MODE" == true ]]; then
    echo -e "  OOM watcher:  ${_RN_CYAN}${RN_INSTALL_DIR}/restart-if-oom.sh${_RN_RESET}"
    echo -e "  OOM лог:      ${_RN_CYAN}/var/log/remnanode/oom-restart.log${_RN_RESET}"
    echo -e "  Порог:        ${_RN_CYAN}${RN_OOM_THRESHOLD}%${_RN_RESET}"
    echo -e "  Cron:         ${_RN_CYAN}каждые 10 минут${_RN_RESET}"
  fi
  echo ""
  echo -e "  Управление:"
  echo -e "    ${_RN_YELLOW}cd ${RN_INSTALL_DIR} && docker compose logs -f${_RN_RESET}"
  echo -e "    ${_RN_YELLOW}cd ${RN_INSTALL_DIR} && docker compose restart${_RN_RESET}"
  if [[ "$RN_XHTTP_MODE" == true ]]; then
    echo -e "    ${_RN_YELLOW}crontab -l${_RN_RESET}   # проверить cron"
    echo -e "    ${_RN_YELLOW}tail -f /var/log/remnanode/oom-restart.log${_RN_RESET}"
  fi
  echo ""
}

# Автопатч docker-compose.yml: добавляет volume логов remnanode в сервис remnanode.
# Идемпотентно — повторный вызов ничего не дублирует. Делает .bak перед правкой.
# Использует python3 (есть в Ubuntu по умолчанию) для безопасной правки YAML по отступам.
rn_patch_compose_logging() {
  local compose="$1"
  if [[ ! -f "$compose" ]]; then
    rn_error "docker-compose.yml не найден: ${compose}"
    return 1
  fi

  # Уже есть монтирование лог-тома? — выходим
  if grep -qE '/var/log/remnanode:/var/log/remnanode' "$compose"; then
    rn_success "volume логов уже присутствует в compose — пропускаю"
    return 0
  fi

  # Нет сервиса remnanode — патчить нечего
  if ! grep -qE '^[[:space:]]*remnanode:' "$compose"; then
    rn_warn "В ${compose} не найден сервис 'remnanode' — патч логирования пропущен"
    rn_warn "Добавь вручную в секцию volumes сервиса remnanode:"
    rn_warn "  - '/var/log/remnanode:/var/log/remnanode'"
    return 1
  fi

  cp "$compose" "${compose}.bak.$(date +%Y%m%d%H%M%S)"
  rn_info "Патчу ${compose} (бэкап создан)..."

  COMPOSE_FILE="$compose" python3 - <<'PYEOF'
import os, re, sys

path = os.environ["COMPOSE_FILE"]
with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

LOG_VOL = "/var/log/remnanode:/var/log/remnanode"

# 1. Находим строку сервиса remnanode и её отступ
svc_idx = None
svc_indent = None
for i, ln in enumerate(lines):
    m = re.match(r'^(\s*)remnanode:\s*$', ln)
    if m:
        svc_idx = i
        svc_indent = len(m.group(1))
        break

if svc_idx is None:
    sys.stderr.write("remnanode service not found\n")
    sys.exit(2)

# 2. Определяем границы блока сервиса (до следующего ключа с отступом <= svc_indent)
end_idx = len(lines)
for i in range(svc_idx + 1, len(lines)):
    ln = lines[i]
    if ln.strip() == "":
        continue
    indent = len(ln) - len(ln.lstrip())
    if indent <= svc_indent and re.match(r'^\s*\S', ln):
        end_idx = i
        break

block = lines[svc_idx:end_idx]

# Отступ ключей внутри сервиса (volumes:, environment: и т.п.)
key_indent = svc_indent + 2
for ln in block[1:]:
    if ln.strip() == "":
        continue
    indent = len(ln) - len(ln.lstrip())
    if indent > svc_indent:
        key_indent = indent
        break
item_indent = key_indent + 2  # отступ элементов списка под ключом

# 3. Ищем существующий volumes: внутри блока сервиса
vol_rel = None
for j, ln in enumerate(block):
    m = re.match(r'^(\s*)volumes:\s*$', ln)
    if m and len(m.group(1)) == key_indent:
        vol_rel = j
        break

new_item = " " * item_indent + f"- '{LOG_VOL}'\n"

if vol_rel is not None:
    # Вставляем элемент первым в существующий список volumes
    insert_at = svc_idx + vol_rel + 1
    lines.insert(insert_at, new_item)
else:
    # Секции volumes нет — создаём её сразу после строки сервиса
    new_block = " " * key_indent + "volumes:\n" + new_item
    lines.insert(svc_idx + 1, new_block)

with open(path, "w", encoding="utf-8") as f:
    f.writelines(lines)

print("OK")
PYEOF

  local rc=$?
  if [[ $rc -ne 0 ]]; then
    rn_error "Не удалось пропатчить compose автоматически (rc=${rc})"
    rn_warn "Добавь вручную в секцию volumes сервиса remnanode:"
    rn_warn "  - '/var/log/remnanode:/var/log/remnanode'"
    return 1
  fi

  # Проверяем валидность результата
  if grep -qE "/var/log/remnanode:/var/log/remnanode" "$compose"; then
    rn_success "volume логов добавлен в ${compose}"
    return 0
  else
    rn_error "Патч применился, но строка не найдена — проверь ${compose} вручную"
    return 1
  fi
}

# =====================================================
# РАЗДЕЛ: НАСТРОЙКА НОД (точечные действия)
# =====================================================
# Независимые действия для уже существующих/новых нод, в отличие от
# полностью автоматизированных методов установки выше. Каждое действие
# можно запустить отдельно.

# ── Захардкоженные зеркала ──
# Docker registry mirrors (Docker Hub прокси). Порядок = приоритет проверки.
# ВНИМАНИЕ: зеркала Docker Hub нестабильны (открываются/закрываются),
# поэтому перед записью в daemon.json каждое проверяется на доступность.
RN_DOCKER_MIRRORS=(
  "https://mirror.gcr.io"
  "https://dockerhub.timeweb.cloud"
  "https://huecker.io"
  "https://daocloud.io"
  "https://docker.rainbond.cc"
  "https://docker.m.daocloud.io"
  "https://dockerproxy.com"
  "https://docker.1panel.live"
  "https://docker.nju.edu.cn"
)
# github-зеркала (префиксы-прокси для raw/clone). Используются в vps_fetch_github
# логике, а также для git clone через insteadOf.
RN_GITHUB_MIRRORS=(
  "https://cdn.jsdelivr.net/gh"
  "https://gh-proxy.com"
  "https://ghproxy.net"
  "https://mirror.ghproxy.com"
  "https://gh.api.99988866.xyz"
)

# Проверка доступности зеркала: HTTP-ответ за 3с (любой код кроме таймаута = жив)
rn_mirror_alive() {
  local url="$1"
  curl -fsS -I --connect-timeout 3 --max-time 4 -o /dev/null "$url" 2>/dev/null
}

# ── Установка Docker через get.docker.com ──
rn_install_docker_get() {
  echo ""
  log_section "Установка Docker (get.docker.com)"
  if command -v docker &>/dev/null; then
    rn_success "Docker уже установлен: $(docker --version)"
    rn_fix_docker_socket || true
    return 0
  fi
  if ! command -v curl &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq curl
  fi
  rn_info "Запускаю официальный установщик Docker..."
  if curl -fsSL https://get.docker.com | sh; then
    systemctl enable --now docker 2>/dev/null || true
    sleep 2
    if docker info &>/dev/null 2>&1; then
      rn_success "Docker установлен: $(docker --version)"
    else
      rn_fix_docker_socket || rn_warn "Docker установлен, но daemon не отвечает — проверь journalctl -u docker"
    fi
  else
    rn_error "Установщик Docker завершился с ошибкой"
    return 1
  fi
}

# ── Настройка Docker registry mirror (с проверкой доступности) ──
rn_setup_docker_mirror() {
  echo ""
  log_section "Настройка Docker registry mirror"
  echo "  Проверяю доступность зеркал (таймаут 3с каждое)..."
  echo ""
  local alive=()
  local m
  for m in "${RN_DOCKER_MIRRORS[@]}"; do
    printf "    %-40s " "$m"
    if rn_mirror_alive "$m"; then
      echo "ЖИВО"
      alive+=("$m")
    else
      echo "недоступно"
    fi
  done

  if (( ${#alive[@]} == 0 )); then
    rn_warn "Ни одно зеркало не ответило. Пропускаю настройку (оставляю Docker Hub напрямую)."
    return 1
  fi

  echo ""
  echo "  Живые зеркала будут прописаны в /etc/docker/daemon.json"
  echo "  в порядке приоритета (Docker обходит их сверху вниз):"
  local i
  for i in "${!alive[@]}"; do
    echo "    $((i+1))) ${alive[$i]}"
  done
  echo ""
  read -rep "Прописать все живые зеркала? [Y/n]: " _dm_go
  if [[ "${_dm_go,,}" =~ ^(n|no)$ ]]; then
    echo "Отменено."
    return 0
  fi

  mkdir -p /etc/docker
  local daemon="/etc/docker/daemon.json"
  [[ -f "$daemon" ]] && cp "$daemon" "${daemon}.bak.$(date +%Y%m%d%H%M%S)"

  # Собираем JSON-массив зеркал, сохраняя прочие ключи если файл уже есть
  RN_MIRRORS_JSON=$(printf '%s\n' "${alive[@]}") \
  DAEMON_FILE="$daemon" python3 - <<'PYEOF'
import os, json
daemon = os.environ["DAEMON_FILE"]
mirrors = [m for m in os.environ["RN_MIRRORS_JSON"].splitlines() if m.strip()]
data = {}
if os.path.exists(daemon):
    try:
        with open(daemon) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
data["registry-mirrors"] = mirrors
with open(daemon, "w") as f:
    json.dump(data, f, indent=2)
print("OK")
PYEOF

  if [[ $? -eq 0 ]] && python3 -c "import json;json.load(open('$daemon'))" 2>/dev/null; then
    rn_success "daemon.json обновлён (${#alive[@]} зеркал)"
    rn_info "Перезапускаю Docker для применения..."
    systemctl restart docker 2>/dev/null && sleep 2
    docker info 2>/dev/null | grep -A"${#alive[@]}" "Registry Mirrors" | sed 's/^/    /' || true
  else
    rn_error "Не удалось записать корректный daemon.json"
    return 1
  fi
}

# ── Настройка github-зеркал (git insteadOf + проверка) ──
rn_setup_github_mirror() {
  echo ""
  log_section "Настройка github-зеркал"
  echo "  github-зеркала используются скриптом (vps_fetch_github: jsdelivr→github)"
  echo "  и могут быть прописаны для git clone через insteadOf."
  echo ""
  echo "  Проверяю доступность зеркал..."
  echo ""
  local alive=()
  local m
  for m in "${RN_GITHUB_MIRRORS[@]}"; do
    printf "    %-40s " "$m"
    if rn_mirror_alive "$m"; then
      echo "ЖИВО"
      alive+=("$m")
    else
      echo "недоступно"
    fi
  done

  if (( ${#alive[@]} == 0 )); then
    rn_warn "Ни одно github-зеркало не ответило."
    return 1
  fi

  echo ""
  echo "  Прописать git insteadOf для github.com через первое живое зеркало?"
  echo "  Это ускорит git clone на нодах с ограничениями."
  echo "  (Скриптовые загрузки и так используют fallback-цепочку.)"
  echo ""
  echo "  Первое живое: ${alive[0]}"
  read -rep "Прописать git insteadOf? [y/N]: " _gm_go
  if [[ "${_gm_go,,}" =~ ^(y|yes)$ ]]; then
    if ! command -v git &>/dev/null; then
      apt-get update -qq && apt-get install -y -qq git
    fi
    # gh-proxy формата https://gh-proxy.com/https://github.com/...
    local proxy="${alive[0]}"
    git config --global url."${proxy}/https://github.com/".insteadOf "https://github.com/"
    rn_success "git insteadOf настроен через ${proxy}"
    echo "    Откат: git config --global --unset url.\"${proxy}/https://github.com/\".insteadOf"
  else
    echo "  Пропущено (fallback-цепочка в скрипте остаётся активной)."
  fi
}

# ── Заглушка selfsteal (Edge Node) ──
rn_install_edge_stub() {
  echo ""
  log_section "Установка заглушки selfsteal (Edge Node)"
  local target_dir="/var/www/html"
  read -rep "Директория для index.html [Enter = ${target_dir}]: " _sd
  target_dir="${_sd:-$target_dir}"
  target_dir="${target_dir%/}"
  mkdir -p "$target_dir"

  local target="${target_dir}/index.html"
  if [[ -f "$target" ]]; then
    cp "$target" "${target}.bak.$(date +%Y%m%d%H%M%S)"
    rn_warn "Существующий index.html сохранён в бэкап"
  fi

  cat > "$target" <<'EDGE_STUB_HTML_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<meta name="description" content="Edge delivery node. High-throughput object storage and content distribution.">
<meta name="theme-color" content="#0b0d10">
<title>Edge Node · Delivery Status</title>
<style>
  :root {
    --bg: #0b0d10;
    --bg-elev: #111418;
    --border: #1f242b;
    --border-soft: #15191e;
    --text: #d7dde3;
    --text-dim: #8a939d;
    --text-faint: #5a636d;
    --accent: #7cc4a4;
    --accent-soft: #2d4a3d;
    --warn: #d4a574;
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  html, body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }

  body { min-height: 100vh; display: flex; flex-direction: column; }

  a {
    color: var(--text-dim);
    text-decoration: none;
    border-bottom: 1px solid transparent;
    transition: color 0.15s, border-color 0.15s;
  }
  a:hover { color: var(--text); border-bottom-color: var(--text-faint); }

  code, .mono { font-family: var(--mono); font-size: 0.92em; }

  header { border-bottom: 1px solid var(--border); background: var(--bg); }
  .header-inner {
    max-width: 1080px;
    margin: 0 auto;
    padding: 18px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }
  .logo {
    display: flex;
    align-items: center;
    gap: 10px;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--text-dim);
    letter-spacing: 0.06em;
  }
  .logo-mark {
    width: 18px;
    height: 18px;
    border: 1px solid var(--text-dim);
    transform: rotate(45deg);
    position: relative;
  }
  .logo-mark::after {
    content: "";
    position: absolute;
    inset: 3px;
    background: var(--text-dim);
  }
  nav ul {
    display: flex;
    gap: 20px;
    list-style: none;
    font-family: var(--mono);
    font-size: 12px;
  }
  .header-status {
    font-size: 11px;
    color: var(--text-faint);
    letter-spacing: 0.04em;
  }

  main {
    flex: 1;
    max-width: 1080px;
    width: 100%;
    margin: 0 auto;
    padding: 48px 24px 64px;
  }

  .hero {
    margin-bottom: 48px;
    padding-bottom: 32px;
    border-bottom: 1px solid var(--border-soft);
  }
  .eyebrow {
    font-family: var(--mono);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--text-faint);
    margin-bottom: 14px;
  }
  .hero h1 {
    font-size: 28px;
    font-weight: 500;
    letter-spacing: -0.01em;
    margin-bottom: 12px;
    color: var(--text);
  }
  .hero h1 .node-id {
    font-family: var(--mono);
    color: var(--accent);
    font-weight: 400;
  }
  .hero p { color: var(--text-dim); max-width: 620px; }

  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-family: var(--mono);
    font-size: 12px;
    padding: 4px 10px;
    border: 1px solid var(--accent-soft);
    background: rgba(124, 196, 164, 0.06);
    color: var(--accent);
    border-radius: 3px;
    margin-top: 14px;
  }
  .status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 0 0 rgba(124, 196, 164, 0.6);
    animation: pulse 2s ease-out infinite;
  }
  @keyframes pulse {
    0% { box-shadow: 0 0 0 0 rgba(124, 196, 164, 0.55); }
    70% { box-shadow: 0 0 0 6px rgba(124, 196, 164, 0); }
    100% { box-shadow: 0 0 0 0 rgba(124, 196, 164, 0); }
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1px;
    background: var(--border-soft);
    border: 1px solid var(--border-soft);
    margin-bottom: 48px;
  }
  @media (min-width: 760px) {
    .grid { grid-template-columns: repeat(4, 1fr); }
  }
  .grid-cell { background: var(--bg-elev); padding: 20px 22px; }
  .grid-label {
    font-family: var(--mono);
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--text-faint);
    margin-bottom: 8px;
  }
  .grid-value { font-family: var(--mono); font-size: 15px; color: var(--text); }
  .grid-value.num { font-variant-numeric: tabular-nums; }

  section { margin-bottom: 44px; }
  .section-head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    margin-bottom: 16px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border-soft);
  }
  .section-head h2 {
    font-size: 13px;
    font-weight: 500;
    font-family: var(--mono);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text);
  }
  .section-head .meta { font-family: var(--mono); font-size: 11px; color: var(--text-faint); }

  .table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 13px; }
  .table th, .table td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border-soft); }
  .table th {
    font-weight: 500;
    color: var(--text-faint);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .table td { color: var(--text); }
  .table td.num { font-variant-numeric: tabular-nums; text-align: right; }
  .table tr:last-child td { border-bottom: none; }
  .table tr:hover td { background: var(--bg-elev); }

  .log {
    background: var(--bg-elev);
    border: 1px solid var(--border-soft);
    padding: 16px 18px;
    font-family: var(--mono);
    font-size: 12px;
    line-height: 1.75;
    color: var(--text-dim);
    overflow-x: auto;
    white-space: pre;
  }
  .log .ts { color: var(--text-faint); }
  .log .ok { color: var(--accent); }
  .log .warn { color: var(--warn); }
  .log .info { color: var(--text-dim); }

  footer {
    border-top: 1px solid var(--border);
    background: var(--bg);
    padding: 20px 24px;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-faint);
  }
  .footer-inner {
    max-width: 1080px;
    margin: 0 auto;
    display: flex;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
  }

  @media (max-width: 640px) {
    .header-inner { padding: 14px 16px; }
    main { padding: 32px 16px 48px; }
    .hero h1 { font-size: 22px; }
    .grid-cell { padding: 16px; }
    .table th, .table td { padding: 8px 10px; }
    .log { font-size: 11px; }
    .header-status { display: none; }
  }
</style>
</head>
<body>

<header>
  <div class="header-inner">
    <div class="logo">
      <span class="logo-mark" aria-hidden="true"></span>
      <span>edge &middot; delivery mesh</span>
    </div>
    <div class="header-status mono" id="h-clock">2026-04-24 10:00 UTC</div>
  </div>
</header>

<main>

  <div class="hero">
    <div class="eyebrow">Delivery Infrastructure &middot; Public Status Page</div>
    <h1>Edge node <span class="node-id" id="h-nodeid">eun-03</span> &mdash; operational.</h1>
    <p>This host is part of a distributed content delivery mesh. It serves cached objects and streams from the nearest region available to the requesting client. This page is informational; no user-facing services are hosted here.</p>
    <div class="status-badge">
      <span class="status-dot"></span>
      <span>All subsystems nominal</span>
    </div>
  </div>

  <div class="grid" role="list">
    <div class="grid-cell" role="listitem">
      <div class="grid-label">Region</div>
      <div class="grid-value" id="g-region">eu-north</div>
    </div>
    <div class="grid-cell" role="listitem">
      <div class="grid-label">Uptime</div>
      <div class="grid-value num" id="g-uptime">184d 06h 22m 00s</div>
    </div>
    <div class="grid-cell" role="listitem">
      <div class="grid-label">Cache hit ratio</div>
      <div class="grid-value num" id="g-cache">94.2%</div>
    </div>
    <div class="grid-cell" role="listitem">
      <div class="grid-label">Active connections</div>
      <div class="grid-value num" id="g-conn">18,432</div>
    </div>
  </div>

  <section id="throughput">
    <div class="section-head">
      <h2>Throughput &mdash; last 24h</h2>
      <span class="meta">averaged over 5m windows</span>
    </div>
    <table class="table">
      <thead>
        <tr>
          <th>Window</th>
          <th>Requests</th>
          <th>Egress</th>
          <th class="num">p50 / p95 latency</th>
        </tr>
      </thead>
      <tbody id="t-throughput">
        <tr><td>00:00 &ndash; 06:00</td><td>14.2M</td><td>412 GB</td><td class="num">18 / 74 ms</td></tr>
        <tr><td>06:00 &ndash; 12:00</td><td>21.8M</td><td>604 GB</td><td class="num">21 / 81 ms</td></tr>
        <tr><td>12:00 &ndash; 18:00</td><td>26.1M</td><td>738 GB</td><td class="num">22 / 83 ms</td></tr>
        <tr><td>18:00 &ndash; 24:00</td><td>23.4M</td><td>651 GB</td><td class="num">19 / 77 ms</td></tr>
      </tbody>
    </table>
  </section>

  <section id="events">
    <div class="section-head">
      <h2>Recent events</h2>
      <span class="meta">UTC</span>
    </div>
    <div class="log" id="l-events" aria-label="Event log"><span class="ts">2026-04-24 08:14:02</span>  <span class="ok">ok  </span>  cache warm-up completed, 12.4M objects
<span class="ts">2026-04-23 22:01:17</span>  <span class="ok">ok  </span>  tls certificate rotated (ACME)
<span class="ts">2026-04-22 11:47:33</span>  <span class="info">info</span>  peering session re-established with upstream AS
<span class="ts">2026-04-20 03:12:08</span>  <span class="warn">warn</span>  brief egress spike on link-b, auto-rebalanced
<span class="ts">2026-04-18 14:22:51</span>  <span class="ok">ok  </span>  scheduled maintenance completed, no impact</div>
  </section>

  <section id="about">
    <div class="section-head">
      <h2>About this host</h2>
    </div>
    <p style="color: var(--text-dim); max-width: 680px;">
      This node serves delivery traffic on behalf of registered workloads. It does not host public applications and does not accept incoming connections outside of the delivery protocol. For abuse, routing, or peering inquiries, contact the operator via the address in the WHOIS record for this domain.
    </p>
  </section>

</main>

<footer>
  <div class="footer-inner">
    <div>edge &middot; delivery mesh</div>
    <div>fingerprint: <span class="mono" id="f-fp">sha256:c4a9&hellip;f2e1</span> &middot; <span id="f-time">2026-04-24 10:00:00 UTC</span></div>
  </div>
</footer>

<script>
(function() {
  'use strict';

  // Seeded PRNG: same seed -> same sequence. Seed = hash(hostname + UTC day)
  // so values are stable per-node per-day and differ across nodes/days.
  function hash32(str) {
    var h = 2166136261 >>> 0;
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    return h >>> 0;
  }
  function mulberry32(seed) {
    var a = seed >>> 0;
    return function() {
      a = (a + 0x6D2B79F5) >>> 0;
      var t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  var now = new Date();
  var dayKey = now.getUTCFullYear() + '-' + now.getUTCMonth() + '-' + now.getUTCDate();
  var host = (location.hostname || 'localhost').toLowerCase();
  var seed = hash32(host + '|' + dayKey);
  var rand = mulberry32(seed);

  function pick(arr) { return arr[Math.floor(rand() * arr.length)]; }
  function randInt(lo, hi) { return lo + Math.floor(rand() * (hi - lo + 1)); }
  function randFloat(lo, hi) { return lo + rand() * (hi - lo); }
  function pad2(n) { return n < 10 ? '0' + n : '' + n; }

  // ---- Region / identity ----
  var regions = [
    { code: 'eu-north',       short: 'eun' },
    { code: 'eu-central-1',   short: 'euc' },
    { code: 'eu-west-2',      short: 'euw' },
    { code: 'eu-south-1',     short: 'eus' },
    { code: 'us-east-1',      short: 'use' },
    { code: 'us-east-2',      short: 'usx' },
    { code: 'us-west-2',      short: 'usw' },
    { code: 'us-central-1',   short: 'usc' },
    { code: 'ap-southeast-1', short: 'aps' },
    { code: 'ap-northeast-1', short: 'apn' },
    { code: 'ap-south-1',     short: 'api' },
    { code: 'me-south-1',     short: 'mes' },
    { code: 'sa-east-1',      short: 'sae' },
    { code: 'af-south-1',     short: 'afs' },
    { code: 'ca-central-1',   short: 'cac' }
  ];
  var region = pick(regions);
  var tierNum = pick([2, 3, 3, 3, 4]); // weight toward tier 3
  var tierLabel = tierNum === 4 ? 'premium / core' : 'standard / pop';
  var nodeNum = pad2(randInt(1, 48));
  var nodeId = 'n' + tierNum + '-' + region.short + '-' + nodeNum;
  var nodeIdShort = region.short + '-' + nodeNum;

  document.getElementById('h-nodeid').textContent = nodeIdShort;
  document.getElementById('g-region').textContent = region.code;
  // tierLabel, protocol, build are still computed below to keep the PRNG
  // sequence stable — they advance rand() the same way as before, so all
  // downstream values (fingerprint, uptime, throughput, log) remain
  // deterministic per host+day even though we don't render these fields.
  pick([
    'HTTP/2, HTTP/3',
    'HTTP/1.1, HTTP/2, HTTP/3',
    'HTTP/2, HTTP/3 (QUIC v1)'
  ]);

  var buildMonth = pad2(randInt(1, now.getUTCMonth() + 1));
  var buildPatch = randInt(0, 9);
  // buildMonth/buildPatch consumed above; no longer rendered.
  void buildMonth; void buildPatch;

  // Cache hit ratio: 88.x% - 97.x%, scaled slightly by tier
  var cacheBase = tierNum === 4 ? 94 : tierNum === 3 ? 92 : 89;
  var cacheHit = cacheBase + randFloat(0, 3.5);
  document.getElementById('g-cache').textContent = cacheHit.toFixed(1) + '%';

  // Active connections: tier-scaled, with a live wobble
  function fmtInt(n) {
    var s = String(Math.round(n));
    var out = '';
    for (var p = 0; p < s.length; p++) {
      if (p > 0 && (s.length - p) % 3 === 0) out += ',';
      out += s[p];
    }
    return out;
  }
  var connBase = tierNum === 4 ? randInt(42000, 68000)
               : tierNum === 3 ? randInt(14000, 28000)
               :                 randInt(4000, 9500);
  function renderConn() {
    // Wobble ~±4% around the base, slow sine drift so it feels organic
    var t = Date.now() / 1000;
    var wobble = Math.sin(t / 11) * 0.025 + Math.sin(t / 3.7) * 0.015;
    var noise = (Math.random() - 0.5) * 0.008; // tiny jitter per tick
    var value = connBase * (1 + wobble + noise);
    document.getElementById('g-conn').textContent = fmtInt(value);
  }
  renderConn();
  setInterval(renderConn, 2000);

  var hex = '0123456789abcdef';
  var fpHead = '', fpTail = '';
  for (var i = 0; i < 4; i++) fpHead += hex[Math.floor(rand() * 16)];
  for (var j = 0; j < 4; j++) fpTail += hex[Math.floor(rand() * 16)];
  document.getElementById('f-fp').textContent = 'sha256:' + fpHead + '\u2026' + fpTail;

  // ---- Uptime (live) ----
  var uptimeDays  = randInt(30, 420);
  var uptimeHours = randInt(0, 23);
  var uptimeMins  = randInt(0, 59);
  var uptimeSecs  = randInt(0, 59);
  var uptimeBaseMs = (((uptimeDays * 24 + uptimeHours) * 60 + uptimeMins) * 60 + uptimeSecs) * 1000;
  var pageLoadMs = Date.now();

  function renderUptime() {
    var totalSec = Math.floor((uptimeBaseMs + (Date.now() - pageLoadMs)) / 1000);
    var d = Math.floor(totalSec / 86400);
    var h = Math.floor((totalSec % 86400) / 3600);
    var m = Math.floor((totalSec % 3600) / 60);
    var s = totalSec % 60;
    document.getElementById('g-uptime').textContent =
      d + 'd ' + pad2(h) + 'h ' + pad2(m) + 'm ' + pad2(s) + 's';
  }
  renderUptime();
  setInterval(renderUptime, 1000);

  // ---- Throughput table ----
  var scale = tierNum === 4 ? 1.6 : tierNum === 3 ? 1.0 : 0.55;
  var curve = [0.62, 0.95, 1.15, 1.02];

  function fmtReq(n) {
    if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
    if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
    return '' + n;
  }
  function fmtBytes(gb) {
    if (gb >= 1024) return (gb / 1024).toFixed(2) + ' TB';
    return Math.round(gb) + ' GB';
  }

  var windows = ['00:00 \u2013 06:00', '06:00 \u2013 12:00', '12:00 \u2013 18:00', '18:00 \u2013 24:00'];
  var tbody = document.getElementById('t-throughput');
  tbody.innerHTML = '';
  for (var w = 0; w < 4; w++) {
    var jitter = 0.85 + rand() * 0.3;
    var reqs = Math.round(18e6 * scale * curve[w] * jitter);
    var gb   = Math.round(520   * scale * curve[w] * jitter);
    var p50  = randInt(14, 26);
    var p95  = randInt(p50 + 40, p50 + 80);
    var tr = document.createElement('tr');
    tr.innerHTML =
      '<td>' + windows[w] + '</td>' +
      '<td>' + fmtReq(reqs) + '</td>' +
      '<td>' + fmtBytes(gb) + '</td>' +
      '<td class="num">' + p50 + ' / ' + p95 + ' ms</td>';
    tbody.appendChild(tr);
  }

  // ---- Event log ----
  var eventPool = [
    { lvl: 'ok',   msg: 'cache warm-up completed, %OBJ% objects' },
    { lvl: 'ok',   msg: 'tls certificate rotated (ACME)' },
    { lvl: 'info', msg: 'peering session re-established with upstream AS' },
    { lvl: 'ok',   msg: 'scheduled maintenance completed, no impact' },
    { lvl: 'warn', msg: 'brief egress spike on link-%LINK%, auto-rebalanced' },
    { lvl: 'ok',   msg: 'health-check passed on all backends' },
    { lvl: 'info', msg: 'GeoDNS table refreshed from control plane' },
    { lvl: 'ok',   msg: 'object cache GC reclaimed %GB% GB' },
    { lvl: 'info', msg: 'anycast announcement refreshed' },
    { lvl: 'warn', msg: 'upstream latency degraded briefly (<2m), resolved' },
    { lvl: 'ok',   msg: 'firmware up to date, no action required' },
    { lvl: 'ok',   msg: 'log shipper reconnected to aggregator' },
    { lvl: 'info', msg: 'config reload applied without restart' },
    { lvl: 'ok',   msg: 'QUIC session resumption rate: %PCT%%' },
    { lvl: 'info', msg: 'BGP session flapped once, stabilized' }
  ];

  function fillPlaceholders(s) {
    return s
      .replace('%OBJ%', randFloat(4, 22).toFixed(1) + 'M')
      .replace('%LINK%', pick(['a', 'b', 'c', 'd']))
      .replace('%GB%', String(randInt(40, 480)))
      .replace('%PCT%', String(randInt(82, 96)));
  }

  var pool = eventPool.slice();
  var chosen = [];
  for (var c = 0; c < 5 && pool.length; c++) {
    var idx = Math.floor(rand() * pool.length);
    chosen.push(pool.splice(idx, 1)[0]);
  }

  function fmtDate(d) {
    return d.getUTCFullYear() + '-' +
           pad2(d.getUTCMonth() + 1) + '-' +
           pad2(d.getUTCDate()) + ' ' +
           pad2(d.getUTCHours()) + ':' +
           pad2(d.getUTCMinutes()) + ':' +
           pad2(d.getUTCSeconds());
  }

  function padRight(s, n) {
    while (s.length < n) s += ' ';
    return s;
  }

  var cursor = new Date(now.getTime() - randInt(20, 240) * 60 * 1000);
  var logLines = [];
  for (var k = 0; k < chosen.length; k++) {
    var ev = chosen[k];
    var line = '<span class="ts">' + fmtDate(cursor) + '</span>  ' +
               '<span class="' + ev.lvl + '">' + padRight(ev.lvl, 4) + '</span>  ' +
               fillPlaceholders(ev.msg);
    logLines.push(line);
    var stepMin = randInt(40, 1700);
    cursor = new Date(cursor.getTime() - stepMin * 60 * 1000);
  }
  document.getElementById('l-events').innerHTML = logLines.join('\n');

  // ---- Clocks (live) ----
  function fmtShortClock(d) {
    return d.getUTCFullYear() + '-' +
           pad2(d.getUTCMonth() + 1) + '-' +
           pad2(d.getUTCDate()) + ' ' +
           pad2(d.getUTCHours()) + ':' +
           pad2(d.getUTCMinutes()) + ' UTC';
  }
  function renderClock() {
    var d = new Date();
    document.getElementById('f-time').textContent = fmtDate(d) + ' UTC';
    document.getElementById('h-clock').textContent = fmtShortClock(d);
  }
  renderClock();
  setInterval(renderClock, 1000);
})();
</script>

</body>
</html>
EDGE_STUB_HTML_EOF

  chmod 644 "$target"
  if [[ -s "$target" ]]; then
    rn_success "Заглушка установлена: ${target} ($(wc -l < "$target") строк)"
    echo "  Caddy/nginx должны раздавать ${target_dir} как root для selfsteal-домена."
  else
    rn_error "Файл заглушки пуст — что-то пошло не так"
    return 1
  fi
}

# ── Логирование (Docker + зеркала + патч compose + logrotate) ──
rn_node_logging() {
  print_header
  echo "╔══════════════════════════════════════════╗"
  echo "║   Настройка нод — Логирование            ║"
  echo "╚══════════════════════════════════════════╝"
  echo ""
  echo "  Дописывает логирование в существующую ноду."
  echo "  (Docker и зеркала ставятся в пункте 1 → 8 «Docker + зеркала».)"
  echo ""
  echo "  Будет выполнено (по шагам, с подтверждением):"
  echo "    1. Патч docker-compose.yml: volume /var/log/remnanode"
  echo "    2. logrotate для /var/log/remnanode"
  echo ""

  # 1. patch compose
  read -rep "1) Дописать логирование в docker-compose.yml? [Y/n]: " _s4
  if rn_is_yes "$_s4"; then
    local install_dir="/opt/remnanode"
    read -rep "   Директория ноды [Enter = /opt/remnanode]: " _ld
    install_dir="${_ld:-/opt/remnanode}"
    install_dir="${install_dir%/}"
    mkdir -p /var/log/remnanode
    chmod 750 /var/log/remnanode
    rn_patch_compose_logging "${install_dir}/docker-compose.yml"
  fi

  # 2. logrotate
  echo ""
  read -rep "2) Настроить logrotate? [Y/n]: " _s5
  if rn_is_yes "$_s5"; then
    mkdir -p /var/log/remnanode
    chmod 750 /var/log/remnanode
    rn_setup_logrotate
  fi

  echo ""
  rn_success "Настройка логирования завершена"
  echo ""
  echo -e "  ${_RN_YELLOW}Не забудь в конфиге xray (через панель) указать пути логов:${_RN_RESET}"
  echo '     "log": {'
  echo '       "error": "/var/log/remnanode/error.log",'
  echo '       "access": "/var/log/remnanode/access.log",'
  echo '       "loglevel": "warning"'
  echo '     }'
}

# ── Подменю «Настройка нод» ──
setup_node_config() {
  while true; do
    print_header
    echo "╔══════════════════════════════════════════╗"
    echo "║   Настройка нод (точечные действия)      ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    echo "  Независимые действия для существующих нод."
    echo ""
    echo "  1) Включить логирование"
    echo "     Docker + зеркала + volume логов + logrotate"
    echo ""
    echo "  2) Поставить заглушку (Edge Node selfsteal)"
    echo "     index.html в /var/www/html"
    echo ""
    echo "  0) Назад"
    echo ""
    read -rep "Выберите [0-2]: " NC_CHOICE
    case "$NC_CHOICE" in
      1) rn_node_logging ;;
      2) rn_install_edge_stub ;;
      0) return ;;
      *) echo "Неверный выбор." ;;
    esac
    echo ""
    read -e -p "Нажмите Enter для возврата..."
  done
}


setup_remnanode() {
  while true; do
    print_header
    echo "╔══════════════════════════════════════════╗"
    echo "║   Установка / настройка нод              ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    echo "  1) Встроенный установщик"
    echo "     remnanode + Caddy 2, OOM watcher, logrotate,"
    echo "     Cloudflare DNS Challenge (опционально)"
    echo ""
    echo "  2) eGamesAPI reverse-proxy скрипт"
    echo "     github.com/eGamesAPI/remnawave-reverse-proxy"
    echo "     Nginx/Caddy reverse proxy + автонастройка"
    echo ""
    echo "  3) Классическая установка (по docs.rw)"
    echo "     Только remnanode без reverse proxy."
    echo "     Нужно вручную вставить docker-compose.yml из панели."
    echo ""
    echo "  4) Настройка нод (точечные действия)"
    echo "     логирование (Docker+зеркала+volume+logrotate), заглушка"
    echo ""
    echo "  5) Torrent-бан для haproxy-пар (BS ↔ relay)"
    echo "     бан торрентщиков на BS + журнал банов/разбанов"
    echo ""
    echo "  0) Назад"
    echo ""
    read -e -p "Выберите [0-5]: " RN_METHOD

    case $RN_METHOD in
        1) setup_remnanode_builtin ;;
        2) setup_remnanode_egames ;;
        3) setup_remnanode_classic ;;
        4) setup_node_config ;;
        5) setup_tbsync ;;
        0) return ;;
        *) echo "Неверный выбор." ;;
    esac

    # методы 1-3 завершаются сами; после них возврат в это подменю
    [[ "$RN_METHOD" =~ ^[123]$ ]] && { echo ""; read -e -p "Нажмите Enter для возврата..."; }
  done
}

setup_remnanode_builtin() {
    print_header
    echo "╔══════════════════════════════════════╗"
    echo "║   Установка remnanode + Caddy        ║"
    echo "╚══════════════════════════════════════╝"
    echo ""
    echo "  Будет установлено:"
    echo "    • remnawave/node  (xray-core)"
    echo "    • Caddy 2         (TLS + заглушка)"
    echo "    • logrotate       (/var/log/remnanode)"
    echo "    • OOM watcher     (опционально, для XHTTP)"
    echo ""

    rn_choose_install_dir || return
    rn_ask_params         || return
    rn_ask_cloudflare
    rn_install_deps || { rn_error "Установка остановлена: Docker/Compose недоступен"; return 1; }
    rn_prepare_dirs
    rn_create_stub
    rn_create_dockerfile
    rn_create_caddyfile
    rn_create_compose
    rn_setup_oom_watcher
    rn_setup_logrotate
    rn_open_panel_port
    rn_start_services || { rn_error "Установка остановлена: контейнеры не запущены"; return 1; }
    rn_print_summary
}

setup_remnanode_egames() {
    print_header
    echo "╔══════════════════════════════════════════════╗"
    echo "║   remnanode — eGamesAPI reverse-proxy       ║"
    echo "╚══════════════════════════════════════════════╝"
    echo ""
    echo "  Источник: github.com/eGamesAPI/remnawave-reverse-proxy"
    echo "  Скрипт настроит reverse proxy и запустит remnanode."
    echo ""
    read -e -p "Запустить установщик? [Y/n]: " _eg_confirm
    if [[ "${_eg_confirm,,}" =~ ^(n|no)$ ]]; then
        echo "Отменено."
        return
    fi
    echo ""
    log_section "Запуск eGamesAPI remnawave-reverse-proxy installer"
    local _eg_installer="/tmp/eg-install_remnawave.sh"
    if ! vps_fetch_github eGamesAPI remnawave-reverse-proxy main \
        install_remnawave.sh "$_eg_installer"; then
        echo "ОШИБКА: не удалось скачать installer (github недоступен с этого VPS)."
        return
    fi
    bash "$_eg_installer"
    rm -f "$_eg_installer"
}

setup_remnanode_classic() {
    print_header
    echo "╔══════════════════════════════════════════════╗"
    echo "║   remnanode — классическая установка        ║"
    echo "╚══════════════════════════════════════════════╝"
    echo ""
    echo "  По инструкции: docs.rw/docs/install/remnawave-node"
    echo ""
    echo "  Шаги:"
    echo "    1. Создать директорию /opt/remnanode"
    echo "    2. В панели Remnawave: Nodes → Management → +"
    echo "    3. Заполнить форму, нажать [Copy docker-compose.yml]"
    echo "    4. Вставить в /opt/remnanode/docker-compose.yml"
    echo "    5. docker compose up -d"
    echo ""
    echo "  Скрипт выполнит шаги 1 и 5 — docker-compose.yml"
    echo "  нужно вставить вручную из панели."
    echo ""

    # Шаг 1 — установка Docker если нет
    rn_install_deps || return

    # Создаём директорию
    local install_dir="/opt/remnanode"
    echo ""
    read -rep "Директория установки [Enter = /opt/remnanode]: " _cl_dir
    install_dir="${_cl_dir:-/opt/remnanode}"
    install_dir="${install_dir%/}"
    mkdir -p "$install_dir"
    mkdir -p /var/log/remnanode
    chmod 750 /var/log/remnanode
    echo "✓ Директория создана: ${install_dir}"

    # logrotate
    rn_setup_logrotate

    echo ""
    echo "══════════════════════════════════════════════"
    echo "  Теперь:"
    echo ""
    echo "  1. Открой панель Remnawave"
    echo "  2. Nodes → Management → + (добавить ноду)"
    echo "  3. Нажми [Copy docker-compose.yml]"
    echo "  4. Выполни:"
    echo ""
    echo "     nano ${install_dir}/docker-compose.yml"
    echo "     # вставь содержимое и сохрани (Ctrl+O, Enter, Ctrl+X)"
    echo ""
    echo "  5. Скрипт допишет логирование и запустит ноду (см. ниже)"
    echo ""
    echo "══════════════════════════════════════════════"
    echo ""
    echo "  После запуска ноды не забудь добавить в конфиг xray"
    echo "  (через панель Remnawave) секцию логов:"
    echo ""
    echo '     "log": {'
    echo '       "error": "/var/log/remnanode/error.log",'
    echo '       "access": "/var/log/remnanode/access.log",'
    echo '       "loglevel": "warning"'
    echo '     }'
    echo ""

    local _compose="${install_dir}/docker-compose.yml"
    read -e -p "Нажми Enter когда docker-compose.yml будет вставлен в ${_compose}..."

    if [ ! -f "${_compose}" ]; then
        echo ""
        rn_warn "docker-compose.yml не найден в ${install_dir}"
        echo "  Когда вставишь файл — запусти вручную:"
        echo "    bash $0   # → 10 → 3, либо:"
        echo "    cd ${install_dir} && docker compose up -d"
        return
    fi

    # ── Автопатч логирования ──
    echo ""
    read -rep "Дописать логирование (volume /var/log/remnanode + logrotate)? [Y/n]: " _log_choice
    if rn_is_yes "$_log_choice"; then
        rn_patch_compose_logging "${_compose}"
    else
        rn_warn "Логирование пропущено по выбору пользователя"
    fi

    echo ""
    read -rep "Запустить ноду сейчас (docker compose up -d)? [Y/n]: " _up_choice
    if rn_is_yes "$_up_choice"; then
        cd "${install_dir}"
        docker compose up -d && docker compose logs -f || true
    else
        echo "  Запусти когда будешь готов:"
        echo "    cd ${install_dir} && docker compose up -d"
    fi
}


# =====================================================
# МОДУЛЬ 10.5: TORRENT-БАН ДЛЯ HAPROXY-ПАР (BS ↔ relay)
# =====================================================
# Схема: BS = haproxy TCP (send-proxy-v2) → relay = remnanode (Reality).
# Torrent Blocker на relay видит реальный IP (PROXY protocol), но банит его
# в nft на relay — а пакеты туда идут с приватного IP BS, бан не работает.
# tbsync: relay каждые 15с отдаёт ПОЛНЫЙ список банов на BS по SSH
# (ключ с command=...,restrict), BS зеркалит его в nft и дропает на 443.
# Длительность бана задаёт плагин (blockDuration в панели), BS лишь повторяет.
# TTL на BS — страховка: если relay умерла, баны на BS сами сойдут.

TBS_CONF=/etc/tbsync.conf
TBS_TOOL=/usr/local/lib/tbsync/tbsync.py
TBS_KEY=/root/.ssh/tbsync
TBS_LOG=/var/log/tbsync.log

tbs_role() { [ -f "$TBS_CONF" ] && (. "$TBS_CONF"; echo "${ROLE:-}"); }

tbs_valid_ip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

tbs_local_ips() {
    ip -4 -o addr show 2>/dev/null | awk '$2!="lo" && $2!~/^docker|^br-|^veth/ {print "    "$2": "$4}'
}

# Общий python-инструмент (ставится на обе роли)
tbs_write_tool() {
    command -v python3 >/dev/null 2>&1 || apt-get install -y python3 >/dev/null 2>&1
    mkdir -p /usr/local/lib/tbsync /var/lib/tbsync
    cat > "$TBS_TOOL" << 'PYEOF'
#!/usr/bin/env python3
# tbsync — зеркалирование банов Torrent Blocker relay → BS (vps-setup.sh)
import ipaddress, json, os, subprocess, sys, time

STATE_DIR = "/var/lib/tbsync"
LOG = "/var/log/tbsync.log"
WL = "/etc/tbsync.whitelist"


def nft_json(args):
    r = subprocess.run(["nft", "-j"] + args, capture_output=True, text=True)
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except ValueError:
        return None


def set_elems(family, table, name):
    d = nft_json(["list", "set", family, table, name])
    if d is None:
        return None
    out = {}
    for o in d.get("nftables", []):
        s = o.get("set")
        if not s:
            continue
        for e in s.get("elem") or []:
            if isinstance(e, str):
                out[e] = None
            elif isinstance(e, dict) and isinstance(e.get("elem"), dict):
                v = e["elem"].get("val")
                if isinstance(v, str):
                    out[v] = e["elem"].get("expires")
    return out


def find_tb():
    d = nft_json(["list", "sets"])
    if d is None:
        return "ERR"
    for o in d.get("nftables", []):
        s = o.get("set")
        if s and s.get("name") == "torrent-blocker":
            return s["family"], s["table"]
    return None


def whitelist():
    nets = []
    try:
        with open(WL) as f:
            for line in f:
                line = line.split("#")[0].strip()
                if line:
                    try:
                        nets.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        pass
    except OSError:
        pass
    return nets


def read_input():
    wl = whitelist()
    cur = {}
    for line in sys.stdin:
        p = line.split()
        if not p:
            continue
        try:
            a = ipaddress.IPv4Address(p[0])
        except ValueError:
            continue
        if not a.is_global or any(a in n for n in wl):
            continue
        secs = 0
        if len(p) > 1 and p[1].isdigit():
            secs = int(p[1])
        cur[str(a)] = secs
        if len(cur) >= 5000:
            break
    return cur


def fmt(sec):
    if sec is None or sec < 0:
        return "—"
    sec = int(sec)
    h, r = divmod(sec, 3600)
    m, s = divmod(r, 60)
    if h:
        return f"{h}ч {m:02d}м"
    if m:
        return f"{m}м {s:02d}с"
    return f"{s}с"


def log(event, ip, extra=""):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG, "a") as f:
        f.write(f"{ts}\t{event}\t{ip}\t{extra}\n")


def state_path(role):
    return os.path.join(STATE_DIR, role + ".json")


def load_state(role):
    try:
        with open(state_path(role)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(role, st):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = state_path(role) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
    os.replace(tmp, state_path(role))


def track(role, cur):
    now = int(time.time())
    st = load_state(role)
    for ip, secs in cur.items():
        until = now + secs if secs else None
        if ip not in st:
            st[ip] = {"since": now, "until": until}
            log("BAN", ip, f"осталось {fmt(secs)}" if secs else "")
        else:
            st[ip]["until"] = until
    for ip in [i for i in st if i not in cur]:
        dur = now - st[ip].get("since", now)
        log("UNBAN", ip, f"длился {fmt(dur)}")
        del st[ip]
    save_state(role, st)


def cmd_relay_dump():
    tb = find_tb()
    if tb == "ERR":
        sys.exit(2)
    if tb is None:
        return
    el = set_elems(tb[0], tb[1], "torrent-blocker")
    if el is None:
        sys.exit(2)
    for ip, ex in el.items():
        print(f"{ip} {int(ex) if isinstance(ex, (int, float)) else 0}")


def cmd_bs_apply(ttl):
    cur = read_input()
    have = set_elems("inet", "tbsync", "banned")
    if have is None:
        sys.exit(2)
    batch = []
    if cur:
        ips = ", ".join(cur)
        # add → delete → add в одной транзакции = атомарный сброс таймаута
        batch.append(f"add element inet tbsync banned {{ {ips} }}")
        batch.append(f"delete element inet tbsync banned {{ {ips} }}")
        batch.append("add element inet tbsync banned { "
                     + ", ".join(f"{ip} timeout {ttl}s" for ip in cur) + " }")
    stale = [ip for ip in have if ip not in cur]
    if stale:
        batch.append("delete element inet tbsync banned { " + ", ".join(stale) + " }")
    if batch:
        r = subprocess.run(["nft", "-f", "-"], input="\n".join(batch) + "\n",
                           capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stderr)
            sys.exit(1)
    track("bs", cur)


def cmd_unban(ip):
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        print("Некорректный IP"); sys.exit(1)
    tb = find_tb()
    if not tb or tb == "ERR":
        print("Сет torrent-blocker не найден"); sys.exit(1)
    r = subprocess.run(["nft", "delete", "element", tb[0], tb[1], "torrent-blocker",
                        "{ " + ip + " }"], capture_output=True, text=True)
    if r.returncode != 0:
        print("IP не в бане или ошибка nft:", r.stderr.strip()); sys.exit(1)
    log("MANUAL-UNBAN", ip, "вручную")
    print(f"{ip} снят с бана на relay; BS снимет при следующей синхронизации (≤15с)")


def cmd_show(role, n):
    now = int(time.time())
    st = load_state(role)
    print(f"  Сейчас в бане: {len(st)}")
    if st:
        print(f"  {'IP':<16} {'Забанен':<20} {'Прошло':<10} {'Осталось':<10}")
        print("  " + "─" * 58)
        for ip, v in sorted(st.items(), key=lambda x: x[1].get("since", 0)):
            since = v.get("since", now)
            until = v.get("until")
            left = until - now if until else None
            print(f"  {ip:<16} {time.strftime('%d.%m %H:%M:%S', time.localtime(since)):<20} "
                  f"{fmt(now - since):<10} {fmt(left):<10}")
    if n <= 0:
        return
    print("")
    print(f"  Последние события (до {n}):")
    try:
        with open(LOG) as f:
            lines = f.readlines()[-n:]
    except OSError:
        lines = []
    if not lines:
        print("    журнал пуст")
    for line in reversed(lines):
        p = line.rstrip("\n").split("\t")
        if len(p) >= 3:
            print(f"    {p[0]}  {p[1]:<13} {p[2]:<16} {p[3] if len(p) > 3 else ''}")


def main():
    if len(sys.argv) < 2:
        sys.exit(1)
    c = sys.argv[1]
    if c == "relay-dump":
        cmd_relay_dump()
    elif c == "track":
        track(sys.argv[2], read_input())
    elif c == "bs-apply":
        cmd_bs_apply(int(sys.argv[2]) if len(sys.argv) > 2 else 120)
    elif c == "unban":
        cmd_unban(sys.argv[2])
    elif c == "show":
        cmd_show(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 30)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
PYEOF
    chmod 755 "$TBS_TOOL"
    touch "$TBS_LOG"
    cat > /etc/logrotate.d/tbsync << 'EOF'
/var/log/tbsync.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
}
EOF
}

tbs_install_relay() {
    print_header
    echo "╔══════════════════════════════════════════════╗"
    echo "║   Torrent-бан: установка на RELAY            ║"
    echo "╚══════════════════════════════════════════════╝"
    echo ""
    echo "  Relay = нода с remnanode, куда BS (haproxy) шлёт трафик."
    echo "  Сначала ставим здесь, потом — на BS (тот же пункт меню)."
    echo ""

    if ! command -v nft >/dev/null 2>&1; then
        rn_error "nft не найден — это точно relay с remnanode?"; return
    fi
    if nft list sets 2>/dev/null | grep -q "set torrent-blocker "; then
        rn_success "Сет torrent-blocker найден (плагин remnanode активен)"
    else
        rn_warn "Сет torrent-blocker пока не найден."
        echo "       Включи Torrent Blocker в плагинах Remnawave — синхронизация"
        echo "       начнёт работать сама, как только сет появится."
        read -rep "  Продолжить установку? [Y/n]: " _a
        rn_is_yes "$_a" || return
    fi

    local cur_bs="" cur_port="$DEFAULT_SSH_PORT"
    if [ "$(tbs_role)" = "relay" ]; then
        cur_bs=$(. "$TBS_CONF"; echo "$BS_IPS"); cur_port=$(. "$TBS_CONF"; echo "$SSH_PORT")
        rn_info "Найдена прежняя установка — значения подставлены по умолчанию"
    fi

    echo ""
    echo "  Приватные адреса этой машины (для справки):"
    tbs_local_ips
    echo ""
    local bs_ips="" x ok
    while true; do
        read -rep "  Приватный IP BS (несколько — через пробел)${cur_bs:+ [Enter = $cur_bs]}: " bs_ips
        bs_ips="${bs_ips:-$cur_bs}"
        ok=1
        [ -z "$bs_ips" ] && ok=0
        for x in $bs_ips; do tbs_valid_ip "$x" || { rn_warn "Некорректный IP: $x"; ok=0; }; done
        [ "$ok" = 1 ] && break
    done
    local ssh_port
    read -rep "  SSH-порт на BS [Enter = $cur_port]: " ssh_port
    ssh_port="${ssh_port:-$cur_port}"
    [[ "$ssh_port" =~ ^[0-9]+$ ]] || { rn_error "Порт должен быть числом"; return; }

    echo ""
    rn_info "Ставлю компоненты..."
    tbs_write_tool

    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    if [ ! -f "$TBS_KEY" ]; then
        ssh-keygen -t ed25519 -N "" -f "$TBS_KEY" -C "tbsync@$(hostname)" -q
        rn_success "Ключ создан: $TBS_KEY"
    else
        rn_success "Ключ уже есть: $TBS_KEY"
    fi

    cat > "$TBS_CONF" << EOF
ROLE=relay
BS_IPS="$bs_ips"
SSH_PORT="$ssh_port"
EOF

    cat > /usr/local/bin/tbsync-push << 'EOF'
#!/bin/bash
. /etc/tbsync.conf
T=/usr/local/lib/tbsync/tbsync.py
CUR=$(python3 "$T" relay-dump) || exit 0
printf '%s\n' "$CUR" | python3 "$T" track relay
rc=0
for BS in $BS_IPS; do
  printf '%s\n' "$CUR" | ssh -T -i /root/.ssh/tbsync -p "$SSH_PORT" \
      -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new \
      "root@$BS" 2>/dev/null || { logger -t tbsync "push to $BS failed"; rc=1; }
done
exit $rc
EOF
    chmod +x /usr/local/bin/tbsync-push

    cat > /etc/systemd/system/tbsync.service << 'EOF'
[Unit]
Description=tbsync: push torrent-blocker bans to BS

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tbsync-push
EOF
    cat > /etc/systemd/system/tbsync.timer << 'EOF'
[Unit]
Description=tbsync every 15s

[Timer]
OnBootSec=30s
OnUnitActiveSec=15s
AccuracySec=1s

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now tbsync.timer >/dev/null 2>&1
    rn_success "Таймер синхронизации запущен (каждые 15с)"

    echo ""
    echo "══════════════════════════════════════════════════════════════"
    echo "  Теперь на КАЖДОЙ BS ($bs_ips):"
    echo "    bash vps-setup.sh → 10 → 5 → 2 (установить на BS)"
    echo ""
    echo "  Скрипт спросит приватный IP этой relay и ключ. Ключ:"
    echo ""
    echo -e "  ${_RN_BOLD}$(cat ${TBS_KEY}.pub)${_RN_RESET}"
    echo ""
    echo "  IP этой relay в приватке — см. список выше."
    echo "══════════════════════════════════════════════════════════════"
    echo ""
    read -rep "  Когда BS настроена — нажми Enter, проверю связь (или 'n' — пропустить): " _a
    [[ "${_a,,}" == n* ]] && return
    local b fail=0
    for b in $bs_ips; do
        if python3 "$TBS_TOOL" relay-dump 2>/dev/null | ssh -T -i "$TBS_KEY" -p "$ssh_port" \
             -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new "root@$b" 2>/dev/null; then
            rn_success "BS $b — синхронизация работает"
        else
            rn_warn "BS $b — нет связи. Проверь: установку на BS, ufw ($ssh_port с этой relay), fleet_v4 в vpsguard"
            fail=1
        fi
    done
    [ "$fail" = 0 ] && log "tbsync relay installed (BS: $bs_ips)"
}

tbs_install_bs() {
    print_header
    echo "╔══════════════════════════════════════════════╗"
    echo "║   Torrent-бан: установка на BS (haproxy)     ║"
    echo "╚══════════════════════════════════════════════╝"
    echo ""
    echo "  BS = витрина с haproxy, куда подключаются клиенты."
    echo "  Перед этим поставь relay-часть — она выдаст ключ."
    echo ""

    if ! command -v haproxy >/dev/null 2>&1 && ! docker ps 2>/dev/null | grep -qi haproxy; then
        rn_warn "haproxy не найден на этой машине."
        read -rep "  Это точно BS? Продолжить? [y/N]: " _a
        [[ "${_a,,}" == y* ]] || return
    fi

    local cur_relay="" cur_port="$DEFAULT_SSH_PORT" cur_ttl=120
    if [ "$(tbs_role)" = "bs" ]; then
        cur_relay=$(. "$TBS_CONF"; echo "$RELAY_IP")
        cur_port=$(. "$TBS_CONF"; echo "$SSH_PORT")
        cur_ttl=$(. "$TBS_CONF"; echo "$BAN_TTL")
        rn_info "Найдена прежняя установка — значения подставлены по умолчанию"
    fi

    echo ""
    echo "  Приватные адреса этой машины (для справки):"
    tbs_local_ips
    echo ""
    local relay_ip
    while true; do
        read -rep "  Приватный IP relay${cur_relay:+ [Enter = $cur_relay]}: " relay_ip
        relay_ip="${relay_ip:-$cur_relay}"
        tbs_valid_ip "$relay_ip" && break
        rn_warn "Некорректный IP"
    done
    local ssh_port
    read -rep "  SSH-порт этой машины [Enter = $cur_port]: " ssh_port
    ssh_port="${ssh_port:-$cur_port}"
    [[ "$ssh_port" =~ ^[0-9]+$ ]] || { rn_error "Порт должен быть числом"; return; }

    local pubkey
    while true; do
        read -rep "  Вставь ключ relay (ssh-ed25519 AAAA... tbsync@...): " pubkey
        [[ "$pubkey" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+ ]] && break
        rn_warn "Это не похоже на ключ ed25519, попробуй ещё раз"
    done

    echo ""
    echo "  Страховочный TTL бана на BS. Реальную длительность задаёт плагин"
    echo "  (blockDuration); TTL срабатывает, только если relay перестала"
    echo "  синхронизироваться. Должен быть заметно больше 15с."
    local ttl
    read -rep "  TTL, секунд [Enter = $cur_ttl]: " ttl
    ttl="${ttl:-$cur_ttl}"
    [[ "$ttl" =~ ^[0-9]+$ ]] && [ "$ttl" -ge 45 ] || { rn_warn "TTL некорректный — ставлю 120"; ttl=120; }

    echo ""
    echo "  IP, которые НИКОГДА не банить (свои, jump-хосты)."
    local me; me=$(ad_ssh_client_ip 2>/dev/null)
    local wl_default=""
    [ -f /etc/tbsync.whitelist ] && wl_default=$(grep -v '^#' /etc/tbsync.whitelist | xargs)
    [ -z "$wl_default" ] && wl_default="$me"
    local wl
    read -rep "  Через пробел${wl_default:+ [Enter = $wl_default]}: " wl
    wl="${wl:-$wl_default}"

    echo ""
    rn_info "Ставлю компоненты..."
    tbs_write_tool

    {
        echo "# tbsync: эти IP/подсети никогда не банятся на BS"
        local w; for w in $wl; do echo "$w"; done
    } > /etc/tbsync.whitelist

    cat > "$TBS_CONF" << EOF
ROLE=bs
RELAY_IP="$relay_ip"
SSH_PORT="$ssh_port"
BAN_TTL="$ttl"
EOF

    cat > /etc/tbsync.nft << 'EOF'
table inet tbsync {
    set banned {
        type ipv4_addr
        flags timeout
    }
    chain input {
        type filter hook input priority -200; policy accept;
        ip saddr @banned tcp dport 443 drop
    }
}
EOF
    cat > /etc/systemd/system/tbsync-table.service << 'EOF'
[Unit]
Description=tbsync nft table
After=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/sbin/nft delete table inet tbsync
ExecStart=/usr/sbin/nft -f /etc/tbsync.nft

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    if nft list table inet tbsync >/dev/null 2>&1; then
        systemctl enable tbsync-table >/dev/null 2>&1
    else
        systemctl enable --now tbsync-table >/dev/null 2>&1
    fi
    nft list table inet tbsync >/dev/null 2>&1 && rn_success "nft-таблица tbsync активна" \
        || { rn_error "nft-таблица не загрузилась"; return; }

    cat > /usr/local/bin/tbsync-recv << 'EOF'
#!/bin/bash
. /etc/tbsync.conf
exec python3 /usr/local/lib/tbsync/tbsync.py bs-apply "${BAN_TTL:-120}"
EOF
    chmod +x /usr/local/bin/tbsync-recv

    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
    local body; body=$(echo "$pubkey" | awk '{print $2}')
    sed -i "\#${body}#d" /root/.ssh/authorized_keys
    echo "command=\"/usr/local/bin/tbsync-recv\",restrict $pubkey" >> /root/.ssh/authorized_keys
    rn_success "Ключ relay добавлен (может только передавать список IP)"

    if command -v ufw >/dev/null 2>&1; then
        ufw allow from "$relay_ip" to any port "$ssh_port" proto tcp comment 'tbsync' >/dev/null
        rn_success "ufw: $ssh_port/tcp открыт для $relay_ip"
    fi

    local vg=/etc/vpsguard/vpsguard.nft net="${relay_ip%.*}.0/24"
    if [ -f "$vg" ]; then
        if grep -qE 'set fleet_v4 \{ type ipv4_addr; flags interval; auto-merge; \}' "$vg"; then
            sed -i "s|set fleet_v4 { type ipv4_addr; flags interval; auto-merge; }|set fleet_v4 { type ipv4_addr; flags interval; auto-merge; elements = { $net } }|" "$vg"
            nft -c -f "$vg" && systemctl restart vpsguard-firewall
            rn_success "vpsguard: $net добавлена в fleet_v4"
        elif nft list set inet vpsguard fleet_v4 2>/dev/null | grep -q "${relay_ip%.*}\."; then
            rn_success "vpsguard: приватка уже в fleet_v4"
        else
            rn_warn "vpsguard: проверь вручную, что $net есть в fleet_v4 — иначе bogon-фильтр съест SSH от relay"
        fi
    fi

    local prl; prl=$(sshd -T 2>/dev/null | awk '/^permitrootlogin /{print $2}')
    if [[ "$prl" == "no" ]]; then
        rn_warn "sshd: PermitRootLogin no — relay не сможет зайти. Нужно prohibit-password"
    else
        rn_success "sshd: root по ключу разрешён ($prl)"
    fi

    log "tbsync BS installed (relay: $relay_ip)"
    echo ""
    echo "══════════════════════════════════════════════════════════════"
    echo "  BS готова. Вернись на relay и нажми Enter для проверки связи"
    echo "  (или сам: systemctl status tbsync.timer на relay)."
    echo ""
    echo "  Свои IP также добавь в Remnawave → Torrent Blocker →"
    echo "  ignoreLists.ip, чтобы relay не резала тебе SSH."
    echo "══════════════════════════════════════════════════════════════"
}

tbs_show() {
    local role; role=$(tbs_role)
    [ -z "$role" ] && { rn_warn "tbsync не установлен на этой машине"; return; }
    while true; do
        print_header
        echo "╔══════════════════════════════════════════════╗"
        printf "║   Torrent-баны — роль: %-22s║\n" "$role"
        echo "╚══════════════════════════════════════════════╝"
        echo ""
        python3 "$TBS_TOOL" show "$role" 30
        echo ""
        echo "  Обновлено: $(date '+%H:%M:%S').  r — обновить, 0 — назад"
        read -rep "  > " _a
        [[ "$_a" == "0" ]] && return
    done
}

tbs_status() {
    print_header
    local role; role=$(tbs_role)
    echo "  Роль: ${role:-не установлен}"
    [ -z "$role" ] && return
    echo ""
    sed 's/^/  /' "$TBS_CONF"
    echo ""
    if [ "$role" = "relay" ]; then
        systemctl --no-pager list-timers tbsync.timer 2>/dev/null | head -2 | sed 's/^/  /'
        echo ""
        echo "  Последние ошибки отправки:"
        journalctl -t tbsync -n 5 --no-pager 2>/dev/null | sed 's/^/    /' || true
        echo ""
        nft list sets 2>/dev/null | grep -q "set torrent-blocker " \
            && rn_success "Сет torrent-blocker на месте" \
            || rn_warn "Сет torrent-blocker не найден — плагин выключен?"
    else
        systemctl is-active --quiet tbsync-table && rn_success "tbsync-table активен" || rn_warn "tbsync-table не активен"
        echo ""
        nft list set inet tbsync banned 2>/dev/null | sed 's/^/  /'
        echo ""
        echo "  Whitelist:"; grep -v '^#' /etc/tbsync.whitelist 2>/dev/null | sed 's/^/    /'
    fi
}

tbs_unban() {
    local role; role=$(tbs_role)
    if [ "$role" = "bs" ]; then
        rn_warn "Разбан делается на RELAY — BS лишь зеркалит её."
        echo "  Если снять здесь, relay вернёт бан через ≤15с."
        echo "  Чтобы IP не банился вообще — добавь его в whitelist BS"
        echo "  (повторная установка BS) или в ignoreLists.ip плагина."
        return
    fi
    [ "$role" != "relay" ] && { rn_warn "tbsync не установлен"; return; }
    python3 "$TBS_TOOL" show relay 0 | head -20
    echo ""
    local ip
    read -rep "  IP для разбана: " ip
    tbs_valid_ip "$ip" || { rn_warn "Некорректный IP"; return; }
    python3 "$TBS_TOOL" unban "$ip"
    echo "  Примечание: плагин может забанить снова при новой торрент-активности."
}

tbs_remove() {
    local role; role=$(tbs_role)
    [ -z "$role" ] && { rn_warn "tbsync не установлен"; return; }
    read -rep "  Удалить tbsync (роль: $role)? [y/N]: " _a
    [[ "${_a,,}" == y* ]] || return
    if [ "$role" = "relay" ]; then
        systemctl disable --now tbsync.timer >/dev/null 2>&1
        rm -f /etc/systemd/system/tbsync.timer /etc/systemd/system/tbsync.service /usr/local/bin/tbsync-push
        read -rep "  Удалить и SSH-ключ $TBS_KEY? [y/N]: " _k
        [[ "${_k,,}" == y* ]] && rm -f "$TBS_KEY" "${TBS_KEY}.pub"
    else
        local relay_ip ssh_port
        relay_ip=$(. "$TBS_CONF"; echo "$RELAY_IP"); ssh_port=$(. "$TBS_CONF"; echo "$SSH_PORT")
        systemctl disable --now tbsync-table >/dev/null 2>&1
        nft delete table inet tbsync 2>/dev/null
        rm -f /etc/systemd/system/tbsync-table.service /etc/tbsync.nft /usr/local/bin/tbsync-recv /etc/tbsync.whitelist
        sed -i '\#/usr/local/bin/tbsync-recv#d' /root/.ssh/authorized_keys 2>/dev/null
        command -v ufw >/dev/null 2>&1 && ufw delete allow from "$relay_ip" to any port "$ssh_port" proto tcp >/dev/null 2>&1
    fi
    systemctl daemon-reload
    rm -rf /usr/local/lib/tbsync /var/lib/tbsync /etc/logrotate.d/tbsync "$TBS_CONF"
    rn_success "tbsync удалён (журнал $TBS_LOG оставлен)"
    log "tbsync removed (role: $role)"
}

setup_tbsync() {
    while true; do
        print_header
        local role; role=$(tbs_role)
        echo "╔══════════════════════════════════════════════╗"
        echo "║   Torrent-бан для haproxy-пар (BS ↔ relay)   ║"
        echo "╚══════════════════════════════════════════════╝"
        echo ""
        echo "  Torrent Blocker на relay ловит юзера, но банить его надо"
        echo "  на BS — туда клиенты приходят со своими IP."
        echo "  Порядок: сначала relay (1), затем каждая BS (2)."
        echo ""
        echo "  Эта машина: ${role:-не настроена}"
        echo ""
        echo "  1) Установить на RELAY (remnanode)"
        echo "  2) Установить на BS (haproxy)"
        echo "  3) Баны и разбаны — текущий список и журнал"
        echo "  4) Статус / диагностика"
        echo "  5) Снять бан вручную (relay)"
        echo "  6) Удалить"
        echo ""
        echo "  0) Назад"
        echo ""
        read -rep "Выберите [0-6]: " _c
        case "$_c" in
            1) tbs_install_relay ;;
            2) tbs_install_bs ;;
            3) tbs_show; continue ;;
            4) tbs_status ;;
            5) tbs_unban ;;
            6) tbs_remove ;;
            0) return ;;
            *) echo "Неверный выбор." ;;
        esac
        echo ""
        read -e -p "Нажмите Enter для возврата..."
    done
}


# =====================================
# МОДУЛЬ 11: ШЕЙПЕР СКОРОСТИ
# =====================================
setup_speed_shaper() {
    print_header
    echo "╔══════════════════════════════════════╗"
    echo "║   Шейпер скорости (Traffic Shaper)  ║"
    echo "╚══════════════════════════════════════╝"
    echo ""
    echo "  DonMatteoVPN / Reshala-Remnawave-Bedolaga"
    echo "  Ограничение скорости пользователей на уровне ядра (tc / nft)"
    echo ""
    echo "  1) Скачать и запустить"
    echo "  0) Назад"
    echo ""
    read -e -p "Выберите [0-1]: " SS_CHOICE

    case $SS_CHOICE in
        1)
            log_section "Установка шейпера скорости"
            SHAPER_INSTALLER="/tmp/speed-shaper-install.sh"

            # ── PREFLIGHT: bpftool ──
            # Reshala работает через eBPF и требует bpftool. На стоковых ядрах он есть
            # в linux-tools-$(uname -r). Но на XanMod-ядрах пакета под ядро в apt НЕТ
            # (deb.xanmod.org часто заблокирован из РФ) → установщик падает "BPFTOOL НЕ НАЙДЕН".
            # Фикс: ставим linux-tools-generic — его bpftool ABI-совместим с любым ядром
            # для базовых map/prog операций, которых шейперу достаточно.
            if ! command -v bpftool >/dev/null 2>&1; then
                rn_warn "bpftool не найден — нужен для eBPF-шейпера. Ставлю linux-tools-generic…"
                apt-get install -y bpftool 2>/dev/null || true
                if ! command -v bpftool >/dev/null 2>&1; then
                    apt-get install -y linux-tools-common linux-tools-generic 2>/dev/null || true
                    local _bpf
                    _bpf="$(find /usr/lib/linux-tools* -name bpftool 2>/dev/null | head -1)"
                    [ -z "$_bpf" ] && _bpf="$(find /usr -name bpftool -type f 2>/dev/null | head -1)"
                    if [ -n "$_bpf" ]; then
                        ln -sf "$_bpf" /usr/sbin/bpftool 2>/dev/null || true
                    fi
                fi
                if command -v bpftool >/dev/null 2>&1 && bpftool version >/dev/null 2>&1; then
                    rn_success "bpftool доступен: $(bpftool version 2>/dev/null | head -1)"
                else
                    rn_warn "bpftool установить не удалось — шейпер может не запуститься."
                    rn_info  "На XanMod-ядре вручную: apt install linux-tools-generic, затем ln -sf \$(find /usr -name bpftool|head -1) /usr/sbin/bpftool"
                fi
            fi

            if ! vps_fetch_github DonMatteoVPN Reshala-Remnawave-Bedolaga main \
                install.sh "$SHAPER_INSTALLER"; then
                echo "ОШИБКА: не удалось скачать installer (github недоступен с этого VPS)."
                return
            fi

            chmod +x "$SHAPER_INSTALLER"
            log "Шейпер скачан: $SHAPER_INSTALLER"
            echo ""
            bash "$SHAPER_INSTALLER"
            ;;
        0) return ;;
        *) echo "Неверный выбор." ;;
    esac
}


# =====================================
# МОДУЛЬ 17: PROBE-СЕРВЕР (доступность из РФ)
# =====================================
# Поднимает временный HTTP/HTTPS сервер и логирует каждое подключение.
# Зачем: проверить, доходит ли трафик из РФ до этого IP и не рвётся ли TLS
# (DPI/SNI-блок РКН, «грязный» IP с историей блокировок). Полезно ПЕРЕД тем,
# как вешать домен на новый IP.
# Порты произвольные: 80/443 обычно заняты nginx/caddy/xray selfsteal-нодой.
PROBE_PY="/usr/local/sbin/probe-server.py"

_probe_write_py() {
    cat > "$PROBE_PY" <<'PROBE_PY_EOF'
#!/usr/bin/env python3
"""probe-server — диагностика доступности (HTTP + HTTPS с самоподписанным сертом)."""
import argparse, datetime, http.server, json, os, socket, ssl, subprocess, sys, threading

CERT = "/tmp/probe-cert.pem"
KEY = "/tmp/probe-key.pem"
G, Y, R, C, B, N = "\033[0;32m", "\033[1;33m", "\033[0;31m", "\033[0;36m", "\033[0;34m", "\033[0m"


def gen_cert():
    if os.path.exists(CERT) and os.path.exists(KEY):
        return True
    print(f"{B}·{N} Генерирую самоподписанный сертификат...")
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", KEY, "-out", CERT, "-days", "30", "-nodes",
             "-subj", "/CN=probe-test"],
            check=True, capture_output=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"{R}✗{N} Не смог сгенерировать сертификат: {e}")
        return False


def server_ip():
    try:
        import urllib.request
        return urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode()
    except Exception:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("1.1.1.1", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "?"


PAGE = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>it works</title>
<style>
body{{font-family:-apple-system,system-ui,sans-serif;max-width:560px;margin:40px auto;padding:0 20px;line-height:1.6}}
h1{{font-size:2.4em;margin:0 0 .2em;color:#0a7d28}}
.i{{background:#f4f4f4;padding:16px;border-radius:8px;margin-top:24px;font-family:ui-monospace,Menlo,monospace;font-size:13px}}
.i div{{margin:4px 0;word-break:break-all}}
.l{{color:#666;display:inline-block;min-width:100px}}
</style></head><body>
<h1>&check; it works</h1>
<p>Соединение с сервером установлено{tls_note}.</p>
<div class="i">
<div><span class="l">Your IP:</span> {ip}</div>
<div><span class="l">Protocol:</span> {proto}</div>
<div><span class="l">Server time:</span> {ts}</div>
<div><span class="l">Host header:</span> {host}</div>
<div><span class="l">Via/XFF:</span> {via}</div>
</div>
</body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "probe/1.0"
    is_tls = False

    def log_message(self, fmt, *args):
        pass

    def _log(self):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        ip = self.client_address[0]
        scheme = f"{G}HTTPS{N}" if self.is_tls else f"{Y}HTTP {N}"
        ua = self.headers.get("User-Agent", "-")[:60]
        host = self.headers.get("Host", "-")
        xff = self.headers.get("X-Forwarded-For") or self.headers.get("Via") or ""
        print(f"{B}{ts}{N} {scheme} {C}{ip:<16}{N} {self.command} {self.path}")
        print(f"          Host: {host}  UA: {ua}")
        if xff:
            print(f"          {Y}⚠ XFF/Via: {xff}{N}")

    def do_GET(self):
        self._log()
        via = self.headers.get("X-Forwarded-For") or self.headers.get("Via") or "—"
        if self.path == "/whoami":
            body = json.dumps({
                "ip": self.client_address[0],
                "proto": self.request_version,
                "tls": self.is_tls,
                "host": self.headers.get("Host", ""),
                "headers": dict(self.headers),
            }, ensure_ascii=False, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
        else:
            body = PAGE.format(
                ip=self.client_address[0],
                proto=("HTTPS " if self.is_tls else "HTTP ") + self.request_version,
                ts=datetime.datetime.now().isoformat(timespec="seconds"),
                host=self.headers.get("Host", "—"),
                via=via,
                tls_note=" по TLS (самоподписанный сертификат)" if self.is_tls else " по обычному HTTP",
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    do_HEAD = do_GET


class TLSHandler(Handler):
    is_tls = True


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve_http(port):
    try:
        Server(("0.0.0.0", port), Handler).serve_forever()
    except Exception as e:
        print(f"{R}✗{N} HTTP :{port} — {e}")


def serve_https(port):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
        srv = Server(("0.0.0.0", port), TLSHandler)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        srv.serve_forever()
    except Exception as e:
        print(f"{R}✗{N} HTTPS :{port} — {e}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--http", type=int, default=80)
    p.add_argument("--https", type=int, default=443)
    p.add_argument("--no-https", action="store_true")
    a = p.parse_args()
    ip = server_ip()
    print(f"\n{C}╔{'═' * 54}╗{N}")
    print(f"{C}║{N}  probe-server — диагностика доступности")
    print(f"{C}╚{'═' * 54}╝{N}\n")
    threads = []
    t = threading.Thread(target=serve_http, args=(a.http,), daemon=True)
    t.start(); threads.append(t)
    print(f"  {G}▸{N} HTTP   http://{ip}:{a.http}/")
    if not a.no_https:
        if gen_cert():
            t = threading.Thread(target=serve_https, args=(a.https,), daemon=True)
            t.start(); threads.append(t)
            print(f"  {G}▸{N} HTTPS  https://{ip}:{a.https}/  {Y}(самоподписанный — браузер ругнётся){N}")
    print(f"\n  {B}JSON-эндпоинт:{N} /whoami")
    print(f"  {B}Ctrl+C для выхода{N}")
    print(f"\n{B}{'─' * 56}{N}")
    print(f"  Жду подключений...\n")
    try:
        while True:
            for t in threads:
                t.join(0.5)
    except KeyboardInterrupt:
        print(f"\n{B}Остановлено.{N}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
PROBE_PY_EOF
    chmod +x "$PROBE_PY"
}

# Открыть порт в слоях фильтрации (UFW + vpsguard + iptables),
# иначе пробник будет недоступен снаружи и диагностика соврёт.
_probe_open_port() {
    local port="$1"
    [ -z "$port" ] || [ "$port" = "0" ] && return 0
    command -v ufw >/dev/null 2>&1 && ufw allow "${port}/tcp" >/dev/null 2>&1
    if command -v nft >/dev/null 2>&1 && nft list table inet vpsguard >/dev/null 2>&1; then
        nft insert rule inet vpsguard input tcp dport "$port" accept comment "probe-tmp-${port}" 2>/dev/null
    fi
    iptables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null
    ip6tables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null
}

_probe_close_port() {
    local port="$1"
    [ -z "$port" ] || [ "$port" = "0" ] && return 0
    command -v ufw >/dev/null 2>&1 && ufw delete allow "${port}/tcp" >/dev/null 2>&1
    if command -v nft >/dev/null 2>&1 && nft list table inet vpsguard >/dev/null 2>&1; then
        local h
        h="$(nft -a list chain inet vpsguard input 2>/dev/null | grep "probe-tmp-${port}" | grep -oE 'handle [0-9]+' | awk '{print $2}' | head -1)"
        [ -n "$h" ] && nft delete rule inet vpsguard input handle "$h" 2>/dev/null
    fi
    iptables -D INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null
    ip6tables -D INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null
}

setup_probe_server() {
    print_header
    echo "╔══════════════════════════════════════════════╗"
    echo "║  Probe-сервер — доступность IP снаружи/из РФ ║"
    echo "╚══════════════════════════════════════════════╝"
    echo ""
    rn_info "Поднимает временный HTTP/HTTPS-сервер и логирует КАЖДОЕ подключение:"
    rn_info "  IP клиента, TLS или нет, Host-заголовок, XFF/Via (признак прокси)."
    echo ""
    rn_info "Зачем: понять, доходит ли трафик из РФ до этого IP и не рвётся ли TLS."
    rn_info "  • подключение есть, страница открылась  → IP чистый, путь свободен"
    rn_info "  • TCP коннектится, но TLS рвётся        → DPI/SNI-блок (РКН)"
    rn_info "  • вообще не коннектится                 → IP заблокирован / фаервол"
    echo ""
    rn_warn "Проверяй НОВЫЙ IP этим пробником ДО того, как вешать на него домен."
    echo ""

    if ! command -v python3 >/dev/null 2>&1; then
        rn_warn "python3 не найден — ставлю."
        apt-get install -y python3 >/dev/null 2>&1
        command -v python3 >/dev/null 2>&1 || { rn_error "python3 не установился."; return 1; }
    fi

    echo "  Порты, занятые сейчас (80/443 обычно у nginx/caddy/xray):"
    echo -n "    "
    ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un | tr '\n' ' '
    echo ""; echo ""

    local p_http p_https
    read -e -p "HTTP порт [8080]: " p_http
    p_http=${p_http:-8080}
    read -e -p "HTTPS порт (0 = без HTTPS) [8443]: " p_https
    p_https=${p_https:-8443}

    # проверка занятости
    local busy=0
    if ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | grep -qx "$p_http"; then
        rn_error "Порт ${p_http} уже занят — выбери другой."; busy=1
    fi
    if [ "$p_https" != "0" ] && ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | grep -qx "$p_https"; then
        rn_error "Порт ${p_https} уже занят — выбери другой."; busy=1
    fi
    [ "$busy" -eq 1 ] && return 1

    _probe_write_py
    _probe_open_port "$p_http"
    [ "$p_https" != "0" ] && _probe_open_port "$p_https"

    # гарантированно закрыть порты при любом выходе (Ctrl+C тоже)
    trap '_probe_close_port "'"$p_http"'"; [ "'"$p_https"'" != "0" ] && _probe_close_port "'"$p_https"'"; trap - INT TERM EXIT' INT TERM EXIT

    local myip
    myip="$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null || echo '<IP-ноды>')"
    echo ""
    rn_success "Порты открыты в UFW/nft/iptables на время теста (закроются при выходе)."
    echo ""
    echo "  Проверь С РФ-КОМПА (не под VPN):"
    echo "    curl -v --connect-timeout 8 http://${myip}:${p_http}/"
    [ "$p_https" != "0" ] && echo "    curl -vk --connect-timeout 8 https://${myip}:${p_https}/"
    echo "    (или открой в браузере — увидишь страницу 'it works')"
    echo ""
    rn_info "Ctrl+C — остановить пробник и закрыть порты."
    echo ""
    log "Probe-сервер запущен: http=${p_http} https=${p_https}"

    if [ "$p_https" = "0" ]; then
        python3 "$PROBE_PY" --http "$p_http" --no-https
    else
        python3 "$PROBE_PY" --http "$p_http" --https "$p_https"
    fi

    _probe_close_port "$p_http"
    [ "$p_https" != "0" ] && _probe_close_port "$p_https"
    trap - INT TERM EXIT
    echo ""
    rn_success "Пробник остановлен, временные правила фаервола убраны."
    log "Probe-сервер остановлен, порты закрыты."
}

# =====================================
# МОДУЛЬ 12: AS_Network_List BLACKLIST
# =====================================
setup_as_blacklist() {
    print_header
    echo "╔══════════════════════════════════════════╗"
    echo "║   AS_Network_List — блокировка госсетей ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    echo "  Блокирует входящий трафик с подсетей российских"
    echo "  госструктур (РКН, ФСБ, МВД и др.)."
    echo "  Списки обновляются автором ежедневно на GitHub."
    echo ""
    echo "  1) Установить / обновить (iptables + ipset)"
    echo "     Совместимо с CrowdSec"
    echo "  2) Установить / обновить (nftables)"
    echo "  3) Статус"
    echo "  4) Удалить правила"
    echo "  5) Управление автообновлением (systemd / cron)"
    echo "  0) Назад"
    echo ""
    read -e -p "Выберите [0-5]: " ASB_CHOICE

    case $ASB_CHOICE in
        1) asb_install_iptables ;;
        2) asb_install_nftables ;;
        3) asb_status ;;
        4) asb_remove ;;
        5) asb_cron_menu ;;
        0) return ;;
        *) echo "Неверный выбор." ;;
    esac
}

ASB_DIR="/etc/as-blacklist"
ASB_LOG="/var/log/as-blacklist-update.log"
ASB_CRON_SCRIPT="/usr/local/bin/as-blacklist-update.sh"

asb_detect_crowdsec() {
    # Debian's bouncer uses mode: ${BACKEND} in the base file and
    # mode: nftables in .yaml.local. The local override takes precedence.
    if ! systemctl is-active --quiet crowdsec-firewall-bouncer 2>/dev/null; then
        echo ""
        return 0
    fi
    local cfg="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
    local override="${cfg}.local"
    local mode=""
    if [ -f "$override" ]; then
        mode=$(sed -nE 's/^[[:space:]]*mode:[[:space:]]*["\x27]?([a-zA-Z0-9_-]+).*$/\1/p' "$override" | tail -n 1)
    fi
    if [ -z "$mode" ] && [ -f "$cfg" ]; then
        mode=$(sed -nE 's/^[[:space:]]*mode:[[:space:]]*["\x27]?([a-zA-Z0-9_-]+).*$/\1/p' "$cfg" | tail -n 1)
    fi
    case "$mode" in
        nftables|iptables) echo "$mode" ;;
        *) echo "unknown" ;;
    esac
}

asb_detect_trafficguard() {
    # Traffic-Guard выпилен из скрипта — всегда ставим правила в INPUT, не в SCANNERS-BLOCK.
    # (даже если на старой ноде остался призрак цепочки SCANNERS-BLOCK — игнорируем его)
    return 1
}

asb_print_env() {
    local cs_mode="$1"
    echo ""
    echo "  Обнаруженное окружение:"
    if [ -n "$cs_mode" ]; then
        echo "    • CrowdSec bouncer: ${cs_mode} (активен)"
    else
        echo "    • CrowdSec: не активен"
    fi
    echo "    • Правила → INPUT (Traffic-Guard выпилен)"
    echo ""
}

asb_install_iptables() {
    echo ""
    log_section "AS_Network_List — установка через iptables/ipset"

    local cs_mode
    cs_mode=$(asb_detect_crowdsec)
    asb_print_env "$cs_mode"

    # CrowdSec nftables bouncer and dedicated iptables/ipset AS rules can coexist.
    # Do not stop ONE-BUTTON or manual installation for an unnecessary prompt.
    if [ "$cs_mode" = "nftables" ]; then
        echo "  ℹ CrowdSec использует nftables; AS_Network_List использует iptables/ipset."
        echo "    Оба механизма могут работать параллельно. Продолжаю установку."
        echo ""
    fi

    # Зависимости
    for pkg in ipset iptables; do
        command -v $pkg &>/dev/null || apt-get install -y -qq $pkg
    done

    mkdir -p "$ASB_DIR"

    echo "  Скачиваю blacklist-v4.ipset..."
    # Гарантируем loopback ACCEPT (иначе при INPUT DROP сломается системный DNS)
    ensure_loopback_accept

    vps_fetch_github C24Be AS_Network_List main \
        blacklists_iptables/blacklist-v4.ipset \
        "$ASB_DIR/blacklist-v4.ipset" || {
        if [ -s "$ASB_DIR/blacklist-v4.ipset" ]; then
            rn_warn "Скачать v4 не вышло — использую локальную копию ($ASB_DIR/blacklist-v4.ipset)"
        else
            echo "ОШИБКА: не удалось скачать blacklist-v4.ipset и локальной копии нет"; return 1
        fi
    }
    echo "  Скачиваю blacklist-v6.ipset..."
    vps_fetch_github C24Be AS_Network_List main \
        blacklists_iptables/blacklist-v6.ipset \
        "$ASB_DIR/blacklist-v6.ipset" || {
        if [ -s "$ASB_DIR/blacklist-v6.ipset" ]; then
            rn_warn "Скачать v6 не вышло — использую локальную копию"
        else
            echo "  ⚠ v6 не скачан и копии нет — ставлю только v4"
        fi
    }

    # Загрузка sets. Самый надёжный путь (как в рабочем threat-модуле): извлекаем
    # CIDR из файла репо (строки "add blacklist-vN <cidr>") и грузим ipset add в цикле.
    # НЕ swap (требует идентичных параметров → "type does not match" на v6),
    # НЕ restore целиком. flush целевого совместим с активным правилом в iptables.
    _asb_load() { # <suffix v4|v6>
        local suf="$1" fam="inet" name stage cidr actual minimum=100
        name="asn-blacklist-${suf}"
        stage="asbstage-${suf}-$$"
        if [ "$suf" = "v6" ]; then fam="inet6"; minimum=5; fi
        if [ ! -s "$ASB_DIR/blacklist-${suf}.ipset" ]; then
            rn_warn "$suf: файл отсутствует или пуст"
            return 1
        fi

        # Populate staging completely before changing any live firewall set.
        ipset create "$stage" hash:net family "$fam" maxelem 262144 || return 1
        while IFS= read -r cidr; do
            [ -n "$cidr" ] || continue
            if ! ipset add "$stage" "$cidr" -exist; then
                rn_error "$suf: некорректная подсеть $cidr"
                ipset destroy "$stage" 2>/dev/null || true
                return 1
            fi
        done < <(awk '$1=="add" && $2=="blacklist-'"${suf}"'" {print $3}' "$ASB_DIR/blacklist-${suf}.ipset")

        actual=$(ipset list "$stage" | awk '/^Number of entries:/ {print $4}')
        if ! [[ "$actual" =~ ^[0-9]+$ ]] || (( actual < minimum )); then
            rn_error "$suf: подозрительно короткий список ($actual)"
            ipset destroy "$stage" 2>/dev/null || true
            return 1
        fi
        # For first installs create the target only after validation.
        if ! ipset list "$name" >/dev/null 2>&1; then
            if ! ipset create "$name" hash:net family "$fam" maxelem 262144; then
                ipset destroy "$stage" 2>/dev/null || true
                return 1
            fi
        fi
        if ! ipset swap "$stage" "$name"; then
            rn_error "$suf: ipset swap не выполнен; прежний список сохранён"
            ipset destroy "$stage" 2>/dev/null || true
            return 1
        fi
        ipset destroy "$stage" 2>/dev/null || true
        echo "  ✓ $suf: атомарно загружено $actual подсетей"
    }
    if ! _asb_load v4; then
        rn_error "IPv4 AS-список не применён."
        return 1
    fi
    if ! _asb_load v6; then
        rn_warn "IPv6 AS-список не обновлён; прежние правила сохранены."
    fi
    # Проверка: сет реально создан и непуст, иначе нет смысла ставить правило
    if ! ipset list asn-blacklist-v4 &>/dev/null || \
       [ "$(ipset list asn-blacklist-v4 2>/dev/null | awk '/Number of entries/{print $4}')" = "0" ]; then
        rn_error "asn-blacklist-v4 не создан/пуст — список не применён. Проверь доступность github/jsdelivr."
        log "AS_Network_List: FAIL — сет пуст"
        return 1
    fi
    echo "  ✓ ipset sets загружены (asn-blacklist-v4 / asn-blacklist-v6)"

    # Если активен Traffic-Guard — встраиваемся в SCANNERS-BLOCK (не трогаем INPUT)
    if asb_detect_trafficguard; then
        echo "  Traffic-Guard обнаружен — добавляю правила в цепочку SCANNERS-BLOCK"
        if ! iptables -C SCANNERS-BLOCK -m set --match-set asn-blacklist-v4 src -j DROP 2>/dev/null; then
            iptables -I SCANNERS-BLOCK 1 -m set --match-set asn-blacklist-v4 src -j DROP
            echo "  ✓ IPv4 правило добавлено в SCANNERS-BLOCK"
        else
            echo "  ✓ IPv4 правило уже в SCANNERS-BLOCK"
        fi
        if ! ip6tables -C SCANNERS-BLOCK -m set --match-set asn-blacklist-v6 src -j DROP 2>/dev/null; then
            ip6tables -I SCANNERS-BLOCK 1 -m set --match-set asn-blacklist-v6 src -j DROP 2>/dev/null &&                 echo "  ✓ IPv6 правило добавлено в SCANNERS-BLOCK" || true
        else
            echo "  ✓ IPv6 правило уже в SCANNERS-BLOCK"
        fi
        echo "iptables-tg" > "$ASB_DIR/mode"
    else
        # Стандартный INPUT
        if ! iptables -C INPUT -m set --match-set asn-blacklist-v4 src -m conntrack --ctstate NEW -j DROP 2>/dev/null; then
            iptables -I INPUT -m set --match-set asn-blacklist-v4 src -m conntrack --ctstate NEW -j DROP
            echo "  ✓ IPv4 правило добавлено в INPUT"
        else
            echo "  ✓ IPv4 правило уже в INPUT"
        fi
        if ! ip6tables -C INPUT -m set --match-set asn-blacklist-v6 src -m conntrack --ctstate NEW -j DROP 2>/dev/null; then
            ip6tables -I INPUT -m set --match-set asn-blacklist-v6 src -m conntrack --ctstate NEW -j DROP
            echo "  ✓ IPv6 правило добавлено в INPUT"
        else
            echo "  ✓ IPv6 правило уже в INPUT"
        fi
        echo "iptables" > "$ASB_DIR/mode"
    fi

    # КРИТИЧНО: вернуть lo ACCEPT на позицию 1 (наш -I INPUT мог сдвинуть его вниз).
    # Иначе DROP-правило окажется выше loopback → рвётся DNS через systemd-resolved.
    ensure_loopback_accept

    persist_ipsets || { rn_error "Не удалось сохранить IPSet"; return 1; }
    managed_remove_legacy_cron "$ASB_CRON_SCRIPT" || return 1
    enable_managed_blocklist_timer as || return 1
    echo "  ✓ Безопасное восстановление IPSet и systemd timer AS включены"

    local v4count v6count
    v4count=$(ipset list asn-blacklist-v4 2>/dev/null | grep "Number of entries" | awk '{print $4}')
    v6count=$(ipset list asn-blacklist-v6 2>/dev/null | grep "Number of entries" | awk '{print $4}')

    echo ""
    echo "✓ Установлено (iptables/ipset)"
    echo "  IPv4 подсетей: ${v4count}"
    echo "  IPv6 подсетей: ${v6count}"
    log "AS_Network_List (iptables) установлен. IPv4: ${v4count}, IPv6: ${v6count}"

    # Самопроверка: правило реально в INPUT И сет непуст — иначе FAIL (для one-button)
    if iptables -C INPUT -m set --match-set asn-blacklist-v4 src -m conntrack --ctstate NEW -j DROP 2>/dev/null \
       && [ "${v4count:-0}" -gt 0 ] 2>/dev/null; then
        return 0
    else
        rn_error "Проверка не прошла: правило в INPUT отсутствует или сет пуст."
        log "AS_Network_List: FAIL самопроверки (rule/set)"
        return 1
    fi
}

asb_create_update_script_iptables() {
    cat > "$ASB_CRON_SCRIPT" <<'UPDATER'
#!/usr/bin/env bash
# Ежедневное обновление AS_Network_List (iptables/ipset)
ASB_DIR="/etc/as-blacklist"
LOG="/var/log/as-blacklist-update.log"

# fetch <path-in-repo> <output>: jsDelivr → raw.githubusercontent fallback, таймауты
fetch() {
    local p="$1" out="$2" tmp="${2}.tmp.$$"
    if curl -fsSL --connect-timeout 5 --max-time 60 -o "$tmp" \
        "https://cdn.jsdelivr.net/gh/C24Be/AS_Network_List@main/$p" 2>/dev/null \
        && [ -s "$tmp" ]; then
        mv -f "$tmp" "$out"; return 0
    fi
    rm -f "$tmp"
    if curl -fsSL --connect-timeout 5 --max-time 60 -o "$tmp" \
        "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/$p" 2>/dev/null \
        && [ -s "$tmp" ]; then
        mv -f "$tmp" "$out"; return 0
    fi
    rm -f "$tmp"
    return 1
}

echo "$(date '+%Y-%m-%d %H:%M:%S') [START] Обновление AS blacklist (iptables)" >> "$LOG"

fetch blacklists_iptables/blacklist-v4.ipset "$ASB_DIR/blacklist-v4.ipset.new" || {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERR] Не удалось скачать v4 (jsdelivr+github)" >> "$LOG"; exit 1
}
fetch blacklists_iptables/blacklist-v6.ipset "$ASB_DIR/blacklist-v6.ipset.new" || {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERR] Не удалось скачать v6 (jsdelivr+github)" >> "$LOG"; exit 1
}

# Атомарная загрузка с переименованием blacklist-* → asn-blacklist-* (как в установщике).
# Через временный сет + swap: не падает на "already exists" и не оставляет дыру.
as_load() { # <suffix v4|v6>
    local suf="$1"; local fam="inet" c n=0
    local name="asn-blacklist-${suf}"
    [ "$suf" = "v6" ] && fam="inet6"
    [ -s "$ASB_DIR/blacklist-${suf}.ipset.new" ] || return 1
    ipset create "$name" hash:net family "$fam" maxelem 262144 -exist 2>/dev/null || true
    ipset flush "$name" 2>/dev/null || true
    while IFS= read -r c; do
        [ -n "$c" ] && ipset add "$name" "$c" -exist 2>/dev/null && n=$((n+1))
    done < <(grep -E '^add ' "$ASB_DIR/blacklist-${suf}.ipset.new" 2>/dev/null | awk '{print $3}')
    [ "$n" -gt 0 ] && return 0 || return 1
}

as_load v4 || echo "$(date '+%Y-%m-%d %H:%M:%S') [ERR] v4 restore не прошёл" >> "$LOG"
as_load v6 || echo "$(date '+%Y-%m-%d %H:%M:%S') [ERR] v6 restore не прошёл" >> "$LOG"

mv -f "$ASB_DIR/blacklist-v4.ipset.new" "$ASB_DIR/blacklist-v4.ipset"
mv -f "$ASB_DIR/blacklist-v6.ipset.new" "$ASB_DIR/blacklist-v6.ipset"

V4=$(ipset list asn-blacklist-v4 2>/dev/null | grep "Number of entries" | awk '{print $4}')
V6=$(ipset list asn-blacklist-v6 2>/dev/null | grep "Number of entries" | awk '{print $4}')
[ -d /etc/iptables ] && { iptables-save > /etc/iptables/rules.v4; ip6tables-save > /etc/iptables/rules.v6; }
ipset save > /etc/ipset.conf 2>/dev/null || true
if [ "${V4:-0}" -gt 0 ] 2>/dev/null; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Обновлено. IPv4: ${V4}, IPv6: ${V6}" >> "$LOG"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERR] asn-blacklist-v4 пуст после обновления!" >> "$LOG"
fi
UPDATER
    chmod +x "$ASB_CRON_SCRIPT"
}

asb_install_nftables() {
    echo ""
    log_section "AS_Network_List — установка через nftables"

    if ! command -v nft &>/dev/null; then
        echo "  Устанавливаю nftables..."
        apt-get install -y -qq nftables
    fi

    mkdir -p "$ASB_DIR"

    echo "  Скачиваю blacklist-v4.nft..."
    vps_fetch_github C24Be AS_Network_List main \
        blacklists_nftables/blacklist-v4.nft \
        "$ASB_DIR/blacklist-v4.nft" || {
        echo "ОШИБКА: не удалось скачать blacklist-v4.nft (проверь интернет/прокси)"; return
    }

    echo "  Скачиваю blacklist-v6.nft..."
    vps_fetch_github C24Be AS_Network_List main \
        blacklists_nftables/blacklist-v6.nft \
        "$ASB_DIR/blacklist-v6.nft" || {
        echo "ОШИБКА: не удалось скачать blacklist-v6.nft (проверь интернет/прокси)"; return
    }

    echo "  Загружаю sets в nftables..."
    nft -f "$ASB_DIR/blacklist-v4.nft"
    nft -f "$ASB_DIR/blacklist-v6.nft"

    # Добавляем chain и правила если нет
    nft add table inet filter 2>/dev/null || true
    nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true

    if ! nft list chain inet filter input 2>/dev/null | grep -q "blacklist_v4"; then
        nft add rule inet filter input ip saddr @blacklist_v4 counter drop
        echo "  ✓ nftables IPv4 правило добавлено"
    else
        echo "  ✓ nftables IPv4 правило уже существует"
    fi

    if ! nft list chain inet filter input 2>/dev/null | grep -q "blacklist_v6"; then
        nft add rule inet filter input ip6 saddr @blacklist_v6 counter drop
        echo "  ✓ nftables IPv6 правило добавлено"
    else
        echo "  ✓ nftables IPv6 правило уже существует"
    fi

    echo "nftables" > "$ASB_DIR/mode"

    # Создаём скрипт обновления
    asb_create_update_script_nftables

    asb_cron_setup

    echo ""
    echo "✓ Установлено (nftables)"
    log "AS_Network_List (nftables) установлен."
}

asb_create_update_script_nftables() {
    cat > "$ASB_CRON_SCRIPT" <<'UPDATER'
#!/usr/bin/env bash
# Ежедневное обновление AS_Network_List (nftables)
ASB_DIR="/etc/as-blacklist"
LOG="/var/log/as-blacklist-update.log"

# fetch <path-in-repo> <output>: jsDelivr → raw.githubusercontent fallback, таймауты
fetch() {
    local p="$1" out="$2" tmp="${2}.tmp.$$"
    if curl -fsSL --connect-timeout 5 --max-time 60 -o "$tmp" \
        "https://cdn.jsdelivr.net/gh/C24Be/AS_Network_List@main/$p" 2>/dev/null \
        && [ -s "$tmp" ]; then
        mv -f "$tmp" "$out"; return 0
    fi
    rm -f "$tmp"
    if curl -fsSL --connect-timeout 5 --max-time 60 -o "$tmp" \
        "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/$p" 2>/dev/null \
        && [ -s "$tmp" ]; then
        mv -f "$tmp" "$out"; return 0
    fi
    rm -f "$tmp"
    return 1
}

echo "$(date '+%Y-%m-%d %H:%M:%S') [START] Обновление AS blacklist (nftables)" >> "$LOG"

fetch blacklists_nftables/blacklist-v4.nft "$ASB_DIR/blacklist-v4.nft.new" || {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERR] Не удалось скачать v4 (jsdelivr+github)" >> "$LOG"; exit 1
}
fetch blacklists_nftables/blacklist-v6.nft "$ASB_DIR/blacklist-v6.nft.new" || {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERR] Не удалось скачать v6 (jsdelivr+github)" >> "$LOG"; exit 1
}

nft -f "$ASB_DIR/blacklist-v4.nft.new" && mv "$ASB_DIR/blacklist-v4.nft.new" "$ASB_DIR/blacklist-v4.nft"
nft -f "$ASB_DIR/blacklist-v6.nft.new" && mv "$ASB_DIR/blacklist-v6.nft.new" "$ASB_DIR/blacklist-v6.nft"

echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] nftables blacklist обновлён" >> "$LOG"
UPDATER
    chmod +x "$ASB_CRON_SCRIPT"
}

asb_cron_setup() {
    if [[ -f "$ASB_DIR/mode" ]] && [[ $(cat "$ASB_DIR/mode") != nftables ]]; then
        enable_managed_blocklist_timer as
        return $?
    fi
    local cron_line="0 4 * * * $ASB_CRON_SCRIPT >> $ASB_LOG 2>&1"
    local existing
    existing=$(crontab -l 2>/dev/null || true)
    if echo "$existing" | grep -qF "$ASB_CRON_SCRIPT"; then
        echo "  ✓ Cron уже настроен"
    else
        ( echo "$existing"; echo "$cron_line" ) | crontab -
        echo "  ✓ Cron добавлен (каждый день в 04:00)"
    fi
    log "AS_Network_List cron настроен."
}

asb_cron_menu() {
    echo ""
    local mode=""
    [[ -f "$ASB_DIR/mode" ]] && mode=$(cat "$ASB_DIR/mode")
    if [[ "$mode" == nftables ]]; then
        echo "Для nftables сохранён прежний механизм обновления."
        echo "Управление cron выполняется отдельно; для iptables используется systemd."
        return 0
    fi
    echo "  1) Включить автообновление AS (каждые 12 часов)"
    echo "  2) Выключить автообновление AS"
    echo "  3) Обновить AS сейчас"
    echo "  4) Статус таймера"
    echo "  0) Назад"
    local choice
    read -r -e -p "Выберите [0-4]: " choice
    case "$choice" in
        1) [[ "$mode" == iptables || "$mode" == iptables-tg ]] || { echo "Сначала установите AS iptables"; return 1; }
           enable_managed_blocklist_timer as ;;
        2) systemctl disable --now as-blacklist-update.timer ;;
        3) systemctl start as-blacklist-update.service ;;
        4) systemctl list-timers --all as-blacklist-update.timer --no-pager ;;
        0) return 0 ;;
        *) echo "Неверный выбор" ;;
    esac
}

asb_status() {
    echo ""
    echo "══════════════════════════════════════"
    echo " AS_Network_List — статус"
    echo "══════════════════════════════════════"

    local mode=""
    [ -f "$ASB_DIR/mode" ] && mode=$(cat "$ASB_DIR/mode")

    if [ -z "$mode" ]; then
        echo "  Статус: НЕ УСТАНОВЛЕН"
        return
    fi

    echo "  Режим: ${mode}"
    echo ""

    if [ "$mode" = "iptables" ] || [ "$mode" = "iptables-tg" ]; then
        if ipset list asn-blacklist-v4 &>/dev/null; then
            local v4 v6
            v4=$(ipset list asn-blacklist-v4 | grep "Number of entries" | awk '{print $4}')
            v6=$(ipset list asn-blacklist-v6 2>/dev/null | grep "Number of entries" | awk '{print $4}')
            echo "  IPv4 подсетей в ipset: ${v4}"
            echo "  IPv6 подсетей в ipset: ${v6}"
            echo ""
            if [ "$mode" = "iptables-tg" ]; then
                echo "  Правила в SCANNERS-BLOCK (Traffic-Guard):"
                iptables -L SCANNERS-BLOCK -n --line-numbers 2>/dev/null | grep "asn-blacklist" || echo "  (не найдены)"
            else
                echo "  Правила в INPUT:"
                iptables -L INPUT -n --line-numbers 2>/dev/null | grep "asn-blacklist" || echo "  (не найдены)"
            fi
        else
            echo "  ipset не загружен (перезагрузка сервера?)"
            echo "  Запусти пункт 1 для повторной загрузки."
        fi
    elif [ "$mode" = "nftables" ]; then
        if nft list set inet filter blacklist_v4 &>/dev/null; then
            echo "  nftables set blacklist_v4: загружен"
            echo "  nftables set blacklist_v6: $(nft list set inet filter blacklist_v6 &>/dev/null && echo загружен || echo НЕ загружен)"
        else
            echo "  nftables sets не загружены."
            echo "  Запусти пункт 2 для повторной загрузки."
        fi
    fi

    echo ""
    echo "  Cron:"
    crontab -l 2>/dev/null | grep "$ASB_CRON_SCRIPT" || echo "  (не настроен)"
    echo ""
    echo "  Последнее обновление:"
    tail -3 "$ASB_LOG" 2>/dev/null || echo "  (лог пуст)"
}

asb_remove() {
    echo ""
    read -r -e -p "Удалить все правила AS_Network_List? (y/n): " CONFIRM
    [[ "$CONFIRM" == y ]] || { echo "Отменено."; return 0; }
    local mode=""
    [[ -f "$ASB_DIR/mode" ]] && mode=$(cat "$ASB_DIR/mode")
    if [[ "$mode" == nftables ]]; then
        # Legacy nftables path, never modify unrelated ipsets.
        nft delete set inet filter blacklist_v4 2>/dev/null || true
        nft delete set inet filter blacklist_v6 2>/dev/null || true
    else
        systemctl disable --now as-blacklist-update.timer || return 1
        managed_remove_ipsets asn-blacklist-v4 asn-blacklist-v6 || return 1
        persist_ipsets || { rn_error "Не удалось сохранить состояние IPSet"; return 1; }
    fi
    managed_remove_legacy_cron "$ASB_CRON_SCRIPT" || return 1
    rm -f "$ASB_CRON_SCRIPT"
    rm -rf "$ASB_DIR"
    log "AS_Network_List удалён."
    echo "✓ AS_Network_List удалён."
}

# =====================================================
# МОДУЛЬ 13: WARP-NATIVE (Cloudflare WARP через wgcf)
# =====================================================
# Оборачивает выбранный трафик (например Gemini) через Cloudflare WARP.
# Ставит WireGuard-интерфейс 'warp' оригинальным install.sh от distillium
# (с watchdog'ом). Маршрутизацию в xray НЕ трогает — это делается отдельно
# в конфиге xray / панели Remnawave (outbound freedom + sockopt.interface=warp).
#
# Источник: github.com/distillium/warp-native

WARP_INSTALL_URL="https://raw.githubusercontent.com/distillium/warp-native/main/install.sh"

# ── Проверка статуса WARP локально ──
warp_local_status() {
  echo ""
  echo "══════════════════════════════════════"
  echo " WARP — локальный статус"
  echo "══════════════════════════════════════"
  if ! command -v wg &>/dev/null; then
    echo "  WireGuard не установлен → WARP не развёрнут"
    return
  fi
  if wg show warp &>/dev/null; then
    echo "  Интерфейс warp: ПОДНЯТ"
    echo ""
    wg show warp | sed 's/^/  /'
    echo ""
    echo "  Проверка выхода через WARP:"
    local trace
    trace=$(curl -fsSL --interface warp --max-time 8 \
      https://www.cloudflare.com/cdn-cgi/trace/ 2>/dev/null | grep -E '^warp=' || true)
    if [[ -n "$trace" ]]; then
      echo "    ${trace}  (warp=on/plus — трафик идёт через WARP)"
    else
      echo "    Не удалось проверить (нет ответа от Cloudflare)"
    fi
  else
    echo "  Интерфейс warp: НЕ поднят"
    echo "  Подними: systemctl start wg-quick@warp"
  fi
  echo ""
  echo "  Автозапуск:"
  systemctl is-enabled wg-quick@warp 2>/dev/null | sed 's/^/    /' || echo "    (юнит не найден)"
  echo ""
  echo "  Watchdog (cron):"
  if [[ -f /etc/cron.d/warp-native ]]; then
    echo "    /etc/cron.d/warp-native — присутствует"
  else
    echo "    (не настроен)"
  fi
}

# ── Локальная установка ──
warp_install_local() {
  echo ""
  log_section "Установка warp-native (локально)"

  if ! command -v curl &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq curl
  fi

  if command -v wg &>/dev/null && wg show warp &>/dev/null; then
    rn_warn "Интерфейс warp уже поднят на этой машине."
    read -rep "Переустановить поверх? [y/N]: " _w_re
    if ! { [[ "${_w_re,,}" == "y" || "${_w_re,,}" == "yes" ]]; }; then
      echo "Отменено."
      return
    fi
  fi

  echo ""
  echo "  Запускаю оригинальный install.sh от distillium."
  echo "  Он интерактивный — спросит:"
  echo "    • WARP+ ключ (жми Enter чтобы пропустить — нужен free-аккаунт)"
  echo "    • интервал watchdog (выбери любой, рекомендую 2 или 4)"
  echo ""
  read -rep "Продолжить? [Y/n]: " _w_go
  if [[ "${_w_go,,}" =~ ^(n|no)$ ]]; then
    echo "Отменено."
    return
  fi

  local installer="/tmp/warp-native-install.sh"
  rn_info "Скачиваю install.sh..."
  # warp-native только на серверах вне РФ (US/EU exit) — raw github обычно доступен.
  # Но на всякий случай пробуем через vps_fetch_github (jsdelivr → github).
  if ! vps_fetch_github distillium warp-native main install.sh "$installer"; then
    rn_error "Не удалось скачать install.sh (github/jsdelivr недоступны с этого VPS)"
    return
  fi

  bash "$installer"
  local rc=$?
  rm -f "$installer"

  echo ""
  if [[ $rc -eq 0 ]] && wg show warp &>/dev/null; then
    log "warp-native установлен локально."
    rn_success "WARP развёрнут. Проверка:"
    warp_local_status
    echo ""
    echo -e "  ${_RN_YELLOW}Следующий шаг — маршрутизация в xray:${_RN_RESET}"
    warp_print_xray_hint
  else
    rn_error "Установка завершилась с ошибкой (rc=${rc}) или интерфейс не поднялся."
    echo "  Проверь вручную: wg show warp ; systemctl status wg-quick@warp"
  fi
}

# ── Подсказка по xray-маршрутизации ──
warp_print_xray_hint() {
  cat <<'HINT'
  В конфиг xray ноды добавь outbound:

    {
      "tag": "warp",
      "protocol": "freedom",
      "settings": { "domainStrategy": "ForceIPv4" },
      "streamSettings": { "sockopt": { "interface": "warp" } }
    }

  И правило роутинга (выше правил direct/block), напр. для Gemini:

    {
      "type": "field",
      "outboundTag": "warp",
      "domain": ["domain:gemini.google.com","domain:googleapis.com", ...]
    }

  Для Docker-нод (remnanode): нужен network_mode: host + cap_add NET_ADMIN
  (в твоём compose уже есть). На голом systemd-xray — работает как есть.
  Не забудь sniffing на inbound, иначе домены не матчатся.
HINT
}

# ── Сбор SSH-профиля ноды (без сохранения между запусками) ──
# Заполняет глобальные: WSSH_TARGET (строка вида user@host или alias),
# WSSH_OPTS (массив доп. опций ssh), WSSH_DESC (человекочит. описание)
warp_collect_ssh_profile() {
  WSSH_TARGET=""
  WSSH_OPTS=()
  WSSH_DESC=""

  echo ""
  echo -e "${_RN_BOLD}Способ подключения к ноде:${_RN_RESET}"
  echo "  1) По IP/хосту + путь к ключу"
  echo "  2) По алиасу из ~/.ssh/config"
  echo "  0) Отмена"
  echo ""
  read -rep "Выбор [0-2]: " _wssh_mode

  case "$_wssh_mode" in
    1)
      local host user port key
      while true; do
        read -rep "  IP или хост ноды: " host
        [[ -n "$host" ]] && break
        rn_warn "Хост не может быть пустым"
      done
      read -rep "  SSH пользователь [Enter = root]: " user
      user="${user:-root}"
      read -rep "  SSH порт [Enter = 22]: " port
      port="${port:-22}"
      if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        rn_warn "Некорректный порт, использую 22"; port=22
      fi
      while true; do
        read -rep "  Путь к приватному ключу [Enter = ~/.ssh/id_ed25519]: " key
        key="${key:-$HOME/.ssh/id_ed25519}"
        # разворачиваем ~
        key="${key/#\~/$HOME}"
        if [[ -f "$key" ]]; then
          break
        fi
        rn_warn "Файл ключа не найден: ${key}"
        read -rep "  Попробовать другой путь? [Y/n]: " _retry
        [[ "${_retry,,}" =~ ^(n|no)$ ]] && { rn_error "Ключ не задан"; return 1; }
      done
      WSSH_TARGET="${user}@${host}"
      WSSH_OPTS=(-p "$port" -i "$key" -o IdentitiesOnly=yes)
      WSSH_DESC="${user}@${host}:${port} (key: ${key})"
      ;;
    2)
      local alias
      while true; do
        read -rep "  Алиас из ~/.ssh/config: " alias
        [[ -n "$alias" ]] && break
        rn_warn "Алиас не может быть пустым"
      done
      WSSH_TARGET="$alias"
      WSSH_OPTS=()
      WSSH_DESC="ssh alias: ${alias}"
      ;;
    0|"") return 1 ;;
    *) rn_error "Неверный выбор"; return 1 ;;
  esac
  return 0
}

# ── Установка по SSH ──
warp_install_ssh() {
  if ! command -v ssh &>/dev/null; then
    rn_error "ssh-клиент не найден на этой машине"
    return
  fi

  warp_collect_ssh_profile || { echo "Отменено."; return; }

  echo ""
  rn_info "Цель: ${WSSH_DESC}"
  rn_info "Проверяю SSH-соединение..."
  # BatchMode для проверки — но ключ может требовать passphrase, поэтому без BatchMode,
  # просто короткий connect-тест с таймаутом.
  if ! ssh "${WSSH_OPTS[@]}" -o ConnectTimeout=10 "$WSSH_TARGET" 'echo __WARP_SSH_OK__' 2>/dev/null | grep -q __WARP_SSH_OK__; then
    rn_error "Не удалось подключиться к ${WSSH_TARGET}"
    echo "  Проверь хост/порт/ключ/алиас и доступность ноды."
    return
  fi
  rn_success "SSH-соединение работает"

  echo ""
  echo "  На ноде будет запущен install.sh от distillium (интерактивно)."
  echo "  Ты ответишь на его вопросы прямо здесь через проброшенный терминал."
  echo ""
  read -rep "Продолжить установку warp-native на ${WSSH_TARGET}? [Y/n]: " _go
  if [[ "${_go,,}" =~ ^(n|no)$ ]]; then
    echo "Отменено."
    return
  fi

  log_section "Установка warp-native по SSH → ${WSSH_DESC}"

  # Ключевой момент: install.sh интерактивный → нужен TTY (-t).
  # Запускаем через bash <(curl ...) на удалённой стороне.
  # Если raw github недоступен с ноды — fallback на jsdelivr.
  local remote_cmd
  remote_cmd='set -e
if ! command -v curl >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq curl; fi
URL_RAW="https://raw.githubusercontent.com/distillium/warp-native/main/install.sh"
URL_JSD="https://cdn.jsdelivr.net/gh/distillium/warp-native@main/install.sh"
TMP=$(mktemp)
if curl -fsSL --max-time 30 "$URL_JSD" -o "$TMP" && [ -s "$TMP" ]; then :;
elif curl -fsSL --max-time 30 "$URL_RAW" -o "$TMP" && [ -s "$TMP" ]; then :;
else echo "ERR: не удалось скачать install.sh на ноде"; exit 1; fi
bash "$TMP"; rc=$?
rm -f "$TMP"
echo ""
echo "=== Проверка интерфейса warp ==="
wg show warp 2>/dev/null || echo "warp не поднят"
exit $rc'

  ssh -t "${WSSH_OPTS[@]}" "$WSSH_TARGET" "$remote_cmd"
  local rc=$?

  echo ""
  if [[ $rc -eq 0 ]]; then
    log "warp-native установлен по SSH на ${WSSH_TARGET}"
    rn_success "Готово на ${WSSH_TARGET}"
    echo ""
    echo -e "  ${_RN_YELLOW}Следующий шаг — маршрутизация в xray на этой ноде:${_RN_RESET}"
    warp_print_xray_hint
  else
    rn_error "Установка на ${WSSH_TARGET} завершилась с ошибкой (rc=${rc})"
  fi
}

# ── Статус по SSH ──
warp_status_ssh() {
  if ! command -v ssh &>/dev/null; then
    rn_error "ssh-клиент не найден"
    return
  fi
  warp_collect_ssh_profile || { echo "Отменено."; return; }
  echo ""
  rn_info "Статус WARP на ${WSSH_TARGET}:"
  ssh "${WSSH_OPTS[@]}" -o ConnectTimeout=10 "$WSSH_TARGET" '
    if wg show warp >/dev/null 2>&1; then
      echo "  warp: ПОДНЯТ"
      wg show warp | sed "s/^/  /"
      echo ""
      curl -fsSL --interface warp --max-time 8 https://www.cloudflare.com/cdn-cgi/trace/ 2>/dev/null | grep "^warp=" | sed "s/^/  /" || echo "  (проверка выхода не удалась)"
    else
      echo "  warp: НЕ поднят"
    fi
  ' 2>/dev/null || rn_error "Не удалось получить статус (проверь подключение)"
}

setup_warp() {
  while true; do
    print_header
    echo "╔══════════════════════════════════════════╗"
    echo "║   WARP-native (Cloudflare WARP)          ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    echo "  Оборачивает выбранный трафик через Cloudflare WARP."
    echo "  Ставит интерфейс 'warp' (wgcf + WireGuard) с watchdog'ом."
    echo "  Маршрутизация в xray настраивается отдельно (подсказка после установки)."
    echo ""
    echo "  ── Локально (на этой машине) ──"
    echo "  1) Установить warp-native"
    echo "  2) Статус WARP"
    echo ""
    echo "  ── По SSH (на другую ноду) ──"
    echo "  3) Установить warp-native на ноду"
    echo "  4) Статус WARP на ноде"
    echo ""
    echo "  5) Показать подсказку по xray-маршрутизации"
    echo "  0) Назад"
    echo ""
    read -rep "Выберите [0-5]: " WARP_CHOICE
    case "$WARP_CHOICE" in
      1) warp_install_local ;;
      2) warp_local_status ;;
      3) warp_install_ssh ;;
      4) warp_status_ssh ;;
      5) echo ""; warp_print_xray_hint ;;
      0) return ;;
      *) echo "Неверный выбор." ;;
    esac
    echo ""
    read -e -p "Нажмите Enter для возврата в меню WARP..."
  done
}

# =====================================================
# МОДУЛЬ 14: ТЮНИНГ ЯДРА / СЕТИ (RPS/XPS, conntrack, sysctl)
# =====================================================
# Снимает потолок по юзерам и PPS. НЕ трогает фаервол — чистый тюнинг,
# уживается с UFW / CrowdSec / GeoBlock / AS_blacklist.
# Идеи и часть техник: github.com/jestivald/node-accelerator (optimize.sh)

KT_REBOOT_NEEDED=0

# ── детект основного интерфейса ──
kt_default_iface() { ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}'; }

# ── уровень x86-64 psABI (1..4) по флагам CPU — для выбора сборки XanMod ──
kt_psabi_level() {
    local flags lvl=1 x ok
    flags=" $(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null | cut -d: -f2) "
    ok=1; for x in cx16 lahf_lm popcnt sse4_1 sse4_2 ssse3; do [[ "$flags" == *" $x "* ]] || ok=0; done
    [ "$ok" = 1 ] && lvl=2
    if [ "$lvl" = 2 ]; then
        ok=1; for x in avx avx2 bmi1 bmi2 f16c fma abm movbe xsave; do [[ "$flags" == *" $x "* ]] || ok=0; done
        [ "$ok" = 1 ] && lvl=3
    fi
    if [ "$lvl" = 3 ]; then
        ok=1; for x in avx512f avx512bw avx512cd avx512dq avx512vl; do [[ "$flags" == *" $x "* ]] || ok=0; done
        [ "$ok" = 1 ] && lvl=4
    fi
    echo "$lvl"
}

# ── контейнер? (делит ядро хоста → кастомное ядро не поставить) ──
kt_is_container() {
    local v="unknown"
    command -v systemd-detect-virt >/dev/null 2>&1 && v="$(systemd-detect-virt 2>/dev/null || echo none)"
    case "$v" in openvz|lxc|lxc-libvirt|docker|podman|systemd-nspawn|wsl|rkt) return 0;; *) return 1;; esac
}

# =====================================================
# 14.1 — sysctl + conntrack
# =====================================================
kt_strip_old_sysctl() {
    # Снимаем блок sysctl из Модуля 1 (базовая настройка), чтобы был один источник правды.
    local f=/etc/sysctl.conf tmp
    [ -f "$f" ] || return 0
    tmp="$(mktemp)"
    grep -vE '^# === (Производительность сети|BBR|Безопасность IPv4) ===' "$f" \
      | grep -vE '^\s*net\.(core\.(somaxconn|netdev_max_backlog|default_qdisc)|ipv4\.(tcp_max_syn_backlog|tcp_fin_timeout|tcp_tw_reuse|ip_local_port_range|tcp_congestion_control|icmp_echo_ignore_all|tcp_syncookies|conf\.(all|default)\.(rp_filter|accept_redirects|send_redirects)|conf\.all\.accept_source_route)|ipv6\.conf\.all\.accept_redirects)\s*=' \
      > "$tmp" && cat "$tmp" > "$f"
    rm -f "$tmp"
}

kt_apply_sysctl() {
    echo ""
    log_section "Тюнинг: sysctl + conntrack"

    local mem_kb sock_max sock_def ct_max ct_buckets tfo
    mem_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null)
    [[ "$mem_kb" =~ ^[0-9]+$ ]] || mem_kb=2097152

    # буфер сокета масштабируем от RAM (мелкие ноды не раздуваем)
    if   [ "$mem_kb" -ge 8388608 ]; then sock_max=67108864; sock_def=1048576
    elif [ "$mem_kb" -ge 4194304 ]; then sock_max=33554432; sock_def=524288
    elif [ "$mem_kb" -ge 2097152 ]; then sock_max=16777216; sock_def=262144
    else                                 sock_max=8388608;  sock_def=131072
    fi
    # conntrack: ~320Б/запись, держим таблицу ≤ ~1/8 RAM
    ct_max=$(( mem_kb * 1024 / 8 / 320 ))
    [ "$ct_max" -lt 65536 ]   && ct_max=65536
    [ "$ct_max" -gt 4194304 ] && ct_max=4194304
    ct_buckets=$(( ct_max / 4 ))
    tfo=3; [ -f /proc/sys/net/ipv4/tcp_fastopen ] || tfo=0

    kt_strip_old_sysctl

    cat > /etc/sysctl.d/99-vps-tune.conf <<SYSCTL
# vps-tune: сеть / BBR / буферы (под ~$(( mem_kb / 1024 )) MB RAM)
net.core.default_qdisc            = fq
net.core.netdev_max_backlog       = 250000
net.core.somaxconn                = 65535
net.core.rmem_default             = $sock_def
net.core.wmem_default             = $sock_def
net.core.rmem_max                 = $sock_max
net.core.wmem_max                 = $sock_max
net.core.optmem_max               = 65536
net.core.netdev_budget            = 600
net.core.netdev_budget_usecs      = 8000
net.core.rps_sock_flow_entries    = 32768

net.ipv4.tcp_congestion_control   = bbr
net.ipv4.tcp_fastopen             = $tfo
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse             = 1
net.ipv4.tcp_fin_timeout          = 15
net.ipv4.tcp_keepalive_time       = 1200
net.ipv4.tcp_keepalive_intvl      = 30
net.ipv4.tcp_keepalive_probes     = 5
net.ipv4.tcp_max_syn_backlog      = 65535
net.ipv4.tcp_max_tw_buckets       = 2000000
net.ipv4.tcp_mtu_probing          = 1
net.ipv4.tcp_min_snd_mss          = 512
net.ipv4.tcp_no_metrics_save      = 1
net.ipv4.tcp_rfc1337              = 1
net.ipv4.tcp_sack                 = 1
net.ipv4.tcp_window_scaling       = 1
net.ipv4.tcp_rmem                 = 4096 87380 $sock_max
net.ipv4.tcp_wmem                 = 4096 65536 $sock_max
net.ipv4.tcp_notsent_lowat        = 131072
net.ipv4.ip_local_port_range      = 10000 65535
net.ipv4.udp_rmem_min             = 16384
net.ipv4.udp_wmem_min             = 16384

# форвардинг (нужно прокси-нодам / WARP / bridge)
net.ipv4.ip_forward               = 1
net.ipv4.conf.all.forwarding      = 1

# SYN-flood (мягкий уровень ядра; основное — Модуль 15)
net.ipv4.tcp_syncookies           = 1
net.ipv4.tcp_synack_retries       = 2
net.ipv4.tcp_syn_retries          = 2

# anti-spoof. rp_filter=2 (loose): strict (1) дропает обратку при
# policy-routing (WARP-native / bridge с асимметричным выходом).
net.ipv4.conf.all.rp_filter                = 2
net.ipv4.conf.default.rp_filter            = 2
net.ipv4.conf.all.accept_source_route      = 0
net.ipv4.conf.default.accept_source_route  = 0
net.ipv4.conf.all.send_redirects           = 0
net.ipv4.conf.default.send_redirects       = 0
net.ipv4.conf.all.accept_redirects         = 0
net.ipv4.conf.default.accept_redirects     = 0
net.ipv4.icmp_echo_ignore_broadcasts       = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# vm / fs
vm.swappiness                = 10
vm.dirty_ratio               = 10
vm.dirty_background_ratio    = 5
vm.max_map_count             = 262144
fs.file-max                   = 2097152
fs.nr_open                    = 2097152
fs.inotify.max_user_watches   = 524288
fs.inotify.max_user_instances = 8192
SYSCTL

    # IPv6-форвардинг только если IPv6 жив
    if [ -d /proc/sys/net/ipv6 ]; then
        echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/99-vps-tune.conf
    fi

    # conntrack — отдельным drop-in (требует загруженного модуля)
    modprobe nf_conntrack 2>/dev/null || true
    cat > /etc/sysctl.d/99-vps-tune-conntrack.conf <<CT
# vps-tune: ёмкость conntrack под RAM ноды
net.netfilter.nf_conntrack_max     = $ct_max
net.netfilter.nf_conntrack_buckets = $ct_buckets
net.netfilter.nf_conntrack_tcp_timeout_established = 7440
CT
    echo "options nf_conntrack hashsize=$ct_buckets" > /etc/modprobe.d/99-vps-tune-conntrack.conf

    modprobe tcp_bbr 2>/dev/null || true
    echo "tcp_bbr"      > /etc/modules-load.d/vps-tune-bbr.conf
    echo "nf_conntrack" > /etc/modules-load.d/vps-tune-conntrack.conf

    sysctl --system >/dev/null 2>&1 || true

    if sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -qx bbr; then
        rn_success "BBR + fq активны"
    else
        rn_warn "BBR не подхватился (нужен модуль tcp_bbr / перезагрузка)"
    fi
    rn_info "conntrack: max=$ct_max buckets=$ct_buckets, буфер сокета до $(( sock_max / 1048576 )) MB"
    log "sysctl/conntrack применены (RAM ~$(( mem_kb / 1024 )) MB)"
}

# =====================================================
# 14.2 — лимиты nofile/nproc → 1048576
# =====================================================
kt_apply_limits() {
    echo ""
    log_section "Тюнинг: nofile/nproc → 1048576"
    # снять блок Модуля 1 (65535) и наш прошлый
    sed -i '/# === vps-tune limits ===/,/# === \/vps-tune limits ===/d' /etc/security/limits.conf 2>/dev/null || true
    sed -i -E '/^(\*|root)[[:space:]]+(soft|hard)[[:space:]]+nofile[[:space:]]+65535/d' /etc/security/limits.conf 2>/dev/null || true
    cat >> /etc/security/limits.conf <<'LIM'
# === vps-tune limits ===
*       soft    nofile  1048576
*       hard    nofile  1048576
*       soft    nproc   1048576
*       hard    nproc   1048576
root    soft    nofile  1048576
root    hard    nofile  1048576
# === /vps-tune limits ===
LIM
    mkdir -p /etc/systemd/system.conf.d /etc/systemd/user.conf.d
    cat > /etc/systemd/system.conf.d/99-vps-tune-limits.conf <<'L'
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=1048576
L
    cp /etc/systemd/system.conf.d/99-vps-tune-limits.conf /etc/systemd/user.conf.d/99-vps-tune-limits.conf
    local pam f
    for pam in common-session common-session-noninteractive; do
        f="/etc/pam.d/$pam"
        [ -f "$f" ] && ! grep -q '^session.*pam_limits.so' "$f" && echo "session required pam_limits.so" >> "$f"
    done
    systemctl daemon-reexec 2>/dev/null || true
    rn_success "nofile/nproc → 1048576 (shell-сессии подхватят после перелогина)"
    log "лимиты nofile/nproc → 1048576"
}

# =====================================================
# 14.3 — RPS/RFS/XPS (раскидываем softirq по ядрам)
# =====================================================
kt_apply_rps() {
    echo ""
    log_section "Тюнинг: RPS/RFS/XPS"
    cat > /usr/local/sbin/vps-rps-setup <<'RPS'
#!/usr/bin/env bash
# RPS/RFS/XPS на основном интерфейсе. На virtio/single-queue VPS весь RX-softirq
# иначе висит на cpu0 — это и есть реальный потолок PPS.
set -e
NIC="${1:-$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')}"
[ -z "$NIC" ] && exit 0
ncpu="$(nproc)"
mask="$(awk -v n="$ncpu" 'BEGIN{
    s=""; while(n>0){ b=(n>=32?32:n); n-=32;
        v=(b>=32?4294967295:(2^b)-1);
        s=(s==""?sprintf("%x",v):sprintf("%x,%s",v,s)); } print (s==""?"0":s) }')"
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true
for q in /sys/class/net/"$NIC"/queues/rx-*; do
    [ -e "$q/rps_cpus" ]     && echo "$mask" > "$q/rps_cpus"     2>/dev/null || true
    [ -e "$q/rps_flow_cnt" ] && echo 4096    > "$q/rps_flow_cnt" 2>/dev/null || true
done
for q in /sys/class/net/"$NIC"/queues/tx-*; do
    [ -e "$q/xps_cpus" ] && echo "$mask" > "$q/xps_cpus" 2>/dev/null || true
done
echo "vps-rps: NIC=$NIC mask=$mask cpus=$ncpu"
RPS
    chmod +x /usr/local/sbin/vps-rps-setup
    cat > /etc/systemd/system/vps-rps.service <<'EOF'
[Unit]
Description=vps-tune RPS/RFS/XPS
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/vps-rps-setup

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now vps-rps.service >/dev/null 2>&1 || true
    rn_success "RPS/RFS/XPS включены ($(nproc) ядер, NIC=$(kt_default_iface))"
    log "RPS/RFS/XPS включены"
}

# =====================================================
# 14.4 — NIC tune + THP off + governor + irqbalance
# =====================================================
kt_apply_nic_misc() {
    echo ""
    log_section "Тюнинг: NIC + THP + governor + irqbalance"
    apt install -y ethtool irqbalance >/dev/null 2>&1 || true
    local NIC; NIC="$(kt_default_iface || true)"
    if [ -n "$NIC" ]; then
        cat > /etc/systemd/system/vps-nic-tune.service <<EOF
[Unit]
Description=vps-tune NIC tuning ($NIC)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'ethtool -G $NIC rx 4096 tx 4096 2>/dev/null || true; ethtool -K $NIC gro on gso on tso on 2>/dev/null || true; ip link set $NIC txqueuelen 10000 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now vps-nic-tune.service >/dev/null 2>&1 || true
        rn_success "NIC=$NIC: ring 4096, GRO/GSO/TSO on, txqueuelen 10000"
    else
        rn_warn "Основной интерфейс не определён — NIC tuning пропущен"
    fi

    cat > /etc/systemd/system/vps-thp.service <<'EOF'
[Unit]
Description=vps-tune disable THP
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true; echo never > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/vps-governor.service <<'EOF'
[Unit]
Description=vps-tune CPU governor performance
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'for c in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$c" 2>/dev/null || true; done'

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now vps-thp.service >/dev/null 2>&1 || true
    systemctl enable --now vps-governor.service >/dev/null 2>&1 || true
    systemctl enable --now irqbalance >/dev/null 2>&1 || true
    rn_success "THP=never, governor=performance, irqbalance запущены"
    log "NIC/THP/governor/irqbalance применены"
}

# =====================================================
# 14.5 — zram-swap (вместо дискового на слабых нодах)
# =====================================================
kt_setup_zram() {
    echo ""
    log_section "Тюнинг: zram-swap"
    if ! modprobe zram 2>/dev/null; then
        rn_warn "Модуль zram недоступен в ядре — пропускаю"
        return
    fi
    cat > /usr/local/sbin/vps-zram-setup <<'ZR'
#!/usr/bin/env bash
# zram-swap ~50% RAM (lz4). Идемпотентно: если наш zram-swap уже активен — выходим.
modprobe zram 2>/dev/null || exit 0
swapon --show=NAME --noheadings 2>/dev/null | grep -q '/dev/zram' && exit 0
RAM_KB=$(awk '/MemTotal/{print $2}' /proc/meminfo)
SIZE=$(( RAM_KB / 2 ))K
DEV="$(zramctl --find --size "$SIZE" --algorithm lz4 2>/dev/null || zramctl --find --size "$SIZE" 2>/dev/null || true)"
[ -z "$DEV" ] && exit 0
mkswap "$DEV" >/dev/null 2>&1 || exit 0
swapon --priority 100 "$DEV" 2>/dev/null || exit 0
echo "vps-zram: $DEV size=$SIZE"
ZR
    chmod +x /usr/local/sbin/vps-zram-setup
    cat > /etc/systemd/system/vps-zram.service <<'EOF'
[Unit]
Description=vps-tune zram-swap
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/vps-zram-setup
ExecStop=/bin/sh -c 'for d in $(swapon --show=NAME --noheadings 2>/dev/null | grep /dev/zram); do swapoff "$d" 2>/dev/null || true; done'

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now vps-zram.service >/dev/null 2>&1 || true
    if swapon --show 2>/dev/null | grep -q zram; then
        rn_success "zram-swap включён ($(swapon --show=NAME,SIZE --noheadings 2>/dev/null | grep zram | tr '\n' ' '))"
    else
        rn_warn "zram не поднялся"
    fi
    log "zram-swap настроен"
}

# =====================================================
# 14.6 — XanMod-ядро (BBRv3) — opt-in, требует reboot
# =====================================================
kt_install_xanmod() {
    echo ""
    log_section "Тюнинг: XanMod-ядро (BBRv3)"
    if kt_is_container; then
        rn_warn "Контейнер ($(systemd-detect-virt 2>/dev/null)) — ядро общее с хостом, XanMod не применим."
        rn_warn "BBR (v1) при этом берётся из стокового ядра — оно уже включено в sysctl."
        return
    fi
    if [ "$(uname -m)" != "x86_64" ]; then
        rn_warn "Не x86_64 ($(uname -m)) — XanMod поддерживается только на x86_64."
        return
    fi
    if uname -r | grep -q xanmod; then
        rn_success "XanMod уже стоит ($(uname -r))."
        return
    fi
    # Детект виртуализации: в VM (kvm/qemu/proxmox) польза XanMod маргинальна —
    # планировщик/NUMA/IRQ виртуализированы гипервизором, а BBR уже есть из
    # стокового ядра. BBRv3 даёт ничтожный прирост на VPN-трафике. По умолчанию пропускаем.
    local _virt; _virt="$(systemd-detect-virt 2>/dev/null || echo none)"
    if [ "$_virt" != "none" ] && [ "$_virt" != "" ]; then
        local _cc; _cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
        rn_warn "Это виртуалка ($_virt). В VM XanMod даёт мало: BBR уже работает (текущий: ${_cc:-?})."
        rn_warn "BBRv3 vs BBR на VPN-трафике — разница ничтожна, а замена ядра в VM = лишний риск."
        if [ "${KT_ASSUME_YES:-0}" = "1" ]; then
            rn_info "Пропускаю XanMod в VM (одна кнопка). Стоковый BBR+fq уже активны — этого достаточно."
            return
        fi
        read -e -p "Всё равно ставить XanMod в VM? (y/N): " _xmvm
        [[ "$_xmvm" == "y" || "$_xmvm" == "Y" ]] || { rn_success "Пропущено. BBR+fq из стокового ядра уже дают нужный эффект."; return; }
    fi
    echo ""
    rn_warn "XanMod ЗАМЕНИТ ядро. После установки нужна ПЕРЕЗАГРУЗКА."
    rn_warn "На проде — сначала проверь на одной ноде, не на всех сразу."
    if [ "${KT_ASSUME_YES:-0}" = "1" ]; then
        rn_info "Базовая настройка: XanMod ставится автоматически (KT_ASSUME_YES=1)."
    else
        read -e -p "Ставить XanMod-ядро? (y/n): " _xm
        [[ "$_xm" == "y" ]] || { echo "Отменено."; return; }
    fi

    apt install -y ca-certificates curl gnupg >/dev/null 2>&1 || true
    local keyring=/etc/apt/keyrings/xanmod-archive-keyring.gpg
    local list=/etc/apt/sources.list.d/xanmod-release.list
    local fp="D38D7D1DA1349567ADED882D86F7D09EE734E623"
    mkdir -p /etc/apt/keyrings

    # ВАЖНО: чистим старый файл — gpg --dearmor ДОПИСЫВАЕТ ключ, иначе keyring задваивается.
    rm -f "$keyring"
    # ключ: сначала напрямую, при CF-блоке — через Ubuntu keyserver.
    # Что бы ни сработало — сверяем ПОЛНЫЙ отпечаток (64-битный keyid подделать дёшево).
    if ! curl -fsSL --connect-timeout 5 --max-time 20 https://dl.xanmod.org/archive.key 2>/dev/null \
            | gpg --dearmor -o "$keyring" 2>/dev/null; then
        rn_warn "dl.xanmod.org недоступен — пробую keyserver.ubuntu.com…"
        rm -f "$keyring"
        curl -fsSL --connect-timeout 5 --max-time 20 \
            "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${fp: -16}" 2>/dev/null \
            | gpg --dearmor -o "$keyring" 2>/dev/null \
            || { rn_error "Ключ XanMod недоступен ни напрямую, ни с keyserver"; return; }
    fi
    if ! gpg --show-keys --with-colons "$keyring" 2>/dev/null | awk -F: '/^fpr:/{print $10}' | grep -qx "$fp"; then
        rn_error "Отпечаток ключа XanMod не совпал с $fp — отказываюсь использовать"
        rm -f "$keyring"; return
    fi
    chmod 0644 "$keyring"

    # Suite в репо XanMod = КОДИНЕЙМ дистрибутива (noble/bookworm/trixie/...), НЕ слово 'releases'.
    # Проверяем наличие dists/<codename>/Release реальным запросом; если нет — fallback bookworm (LTS).
    local codename=""
    [ -f /etc/os-release ] && codename="$(. /etc/os-release; echo "${VERSION_CODENAME:-}")"
    [ -z "$codename" ] && command -v lsb_release >/dev/null 2>&1 && codename="$(lsb_release -sc 2>/dev/null)"
    [ -z "$codename" ] && codename="bookworm"
    local orig_codename="$codename"
    if ! curl -fsSI --connect-timeout 5 --max-time 15 "http://deb.xanmod.org/dists/${codename}/Release" >/dev/null 2>&1; then
        rn_warn "Кодинейм '$codename' в репо XanMod не найден — пробую 'bookworm' (LTS)"
        codename="bookworm"
        if ! curl -fsSI --connect-timeout 5 --max-time 15 "http://deb.xanmod.org/dists/bookworm/Release" >/dev/null 2>&1; then
            if [ "$orig_codename" != "bookworm" ]; then
                rn_warn "Репо XanMod недоступен (ни '$orig_codename', ни 'bookworm'). Вероятно блокировка deb.xanmod.org."
            else
                rn_warn "Репо XanMod недоступен ('bookworm'). Вероятно блокировка deb.xanmod.org."
            fi
            local _cc2; _cc2="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
            rn_info "Это НЕ критично: BBR из стокового ядра уже работает (текущий: ${_cc2:-?}), нода полностью функциональна."
            rn_info "XanMod (BBRv3) — опциональный бонус; без него весь остальной тюнинг применён."
            rm -f "$list"; return
        fi
    fi
    rn_info "Suite репозитория XanMod: $codename"
    echo "deb [signed-by=$keyring] http://deb.xanmod.org $codename main" > "$list"
    if ! apt-get update -qq 2>/dev/null; then
        rn_error "apt-get update по репо XanMod не прошёл (suite=$codename)"
        rm -f "$list"; return
    fi

    # psABI → список кандидатов (деградация v3→v2→v1), lts-сборка (стабильная для прода)
    local lvl candidates pkg="" p
    lvl="$(kt_psabi_level)"; [[ "$lvl" =~ ^[1-4]$ ]] || lvl=2
    case "$lvl" in
        4|3) candidates="linux-xanmod-lts-x64v3 linux-xanmod-lts-x64v2 linux-xanmod-lts-x64v1" ;;
        2)   candidates="linux-xanmod-lts-x64v2 linux-xanmod-lts-x64v1" ;;
        *)   candidates="linux-xanmod-lts-x64v1" ;;
    esac
    rn_info "psABI уровень CPU: x86-64-v$lvl"
    for p in $candidates; do
        apt-cache show "$p" >/dev/null 2>&1 || continue
        rn_info "Ставлю $p (надолго — собирает initramfs)…"
        if DEBIAN_FRONTEND=noninteractive apt-get install -y "$p" >/dev/null 2>&1; then
            pkg="$p"; break
        else
            rn_warn "$p не встал — пробую следующую сборку"
        fi
    done
    if [ -z "$pkg" ]; then
        rn_error "Ни одна сборка XanMod не установилась"
        return
    fi
    update-grub >/dev/null 2>&1 || true
    rn_success "XanMod установлен: $pkg (активируется ПОСЛЕ перезагрузки)"
    rn_info "Проверка после reboot: uname -r — должно содержать 'xanmod'"
    log "XanMod установлен: $pkg"
    KT_REBOOT_NEEDED=1
}

# =====================================================
# 14.7 — статус тюнинга
# =====================================================
kt_status() {
    echo ""
    echo "── Ядро / BBR ──"
    echo "  ядро:    $(uname -r)"
    echo "  qdisc:   $(sysctl -n net.core.default_qdisc 2>/dev/null)"
    echo "  cc:      $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
    echo "  rp_filter: all=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)"
    echo ""
    echo "── conntrack ──"
    echo "  использовано: $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo '?') / $(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo '?')"
    echo ""
    echo "── лимиты ──"
    echo "  nofile (текущая сессия): $(ulimit -n)"
    echo "  systemd DefaultLimitNOFILE: $(systemctl show -p DefaultLimitNOFILE --value 2>/dev/null)"
    echo ""
    echo "── юниты vps-tune ──"
    for u in vps-rps vps-nic-tune vps-thp vps-governor vps-zram irqbalance; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${u}.service"; then
            printf "  %-16s %s\n" "$u" "$(systemctl is-active ${u}.service 2>/dev/null)"
        fi
    done
    echo ""
    echo "── RPS-маска ──"
    journalctl -u vps-rps.service -n1 --no-pager -o cat 2>/dev/null | sed 's/^/  /' || true
    echo ""
    echo "── swap ──"
    swapon --show 2>/dev/null | sed 's/^/  /' || echo "  нет"
}

# =====================================================
# 14.8 — откат тюнинга
# =====================================================
kt_rollback() {
    echo ""
    read -e -p "Снять тюнинг ядра/сети (sysctl drop-in + юниты vps-*)? XanMod НЕ удаляется. (y/n): " _r
    [[ "$_r" == "y" ]] || { echo "Отменено."; return; }
    log_section "Откат тюнинга ядра/сети"
    for u in vps-rps vps-nic-tune vps-thp vps-governor vps-zram; do
        systemctl disable --now ${u}.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/${u}.service
    done
    rm -f /usr/local/sbin/vps-rps-setup /usr/local/sbin/vps-zram-setup
    rm -f /etc/sysctl.d/99-vps-tune.conf /etc/sysctl.d/99-vps-tune-conntrack.conf
    rm -f /etc/modprobe.d/99-vps-tune-conntrack.conf
    rm -f /etc/modules-load.d/vps-tune-bbr.conf /etc/modules-load.d/vps-tune-conntrack.conf
    rm -f /etc/systemd/system.conf.d/99-vps-tune-limits.conf /etc/systemd/user.conf.d/99-vps-tune-limits.conf
    sed -i '/# === vps-tune limits ===/,/# === \/vps-tune limits ===/d' /etc/security/limits.conf 2>/dev/null || true
    systemctl daemon-reload
    systemctl daemon-reexec 2>/dev/null || true
    sysctl --system >/dev/null 2>&1 || true
    rn_success "Тюнинг снят (sysctl вернётся к дефолтам после перезагрузки; XanMod, если ставился, остался)"
    log "тюнинг ядра/сети откатан"
}

setup_kernel_tuning() {
    while true; do
        print_header
        echo "╔══════════════════════════════════════════╗"
        echo "║   Тюнинг ядра / сети (потолок юзеров)    ║"
        echo "╚══════════════════════════════════════════╝"
        echo ""
        echo "  Ускорение ноды без вмешательства в фаервол."
        echo "  Уживается с UFW / CrowdSec / GeoBlock / AS_blacklist."
        echo ""
        echo "  1) Всё сразу (sysctl + conntrack + лимиты + RPS + NIC/THP/gov)"
        echo "     — рекомендуется, без reboot, на все ноды"
        echo ""
        echo "  2) Только RPS/RFS/XPS  ← топ по приросту на virtio-VPS"
        echo "  3) Только sysctl + conntrack + nofile"
        echo "  4) Только NIC tune + THP + governor + irqbalance"
        echo "  5) zram-swap (для слабых нод вместо дискового swap)"
        echo ""
        echo "  6) XanMod-ядро (BBRv3)  ← требует reboot, скип на контейнерах"
        echo ""
        echo "  7) Статус тюнинга"
        echo "  8) Откат (снять тюнинг; XanMod не трогает)"
        echo "  0) Назад"
        echo ""
        read -e -p "Выберите [0-8]: " KT_CHOICE
        case $KT_CHOICE in
            1) kt_apply_sysctl; kt_apply_limits; kt_apply_rps; kt_apply_nic_misc ;;
            2) kt_apply_rps ;;
            3) kt_apply_sysctl; kt_apply_limits ;;
            4) kt_apply_nic_misc ;;
            5) kt_setup_zram ;;
            6) kt_install_xanmod ;;
            7) kt_status ;;
            8) kt_rollback ;;
            0) return ;;
            *) echo "Неверный выбор." ;;
        esac
        echo ""
        if [ "$KT_REBOOT_NEEDED" = "1" ]; then
            read -e -p "XanMod требует перезагрузки. Перезагрузить сейчас? (y/n): " _rb
            [[ "$_rb" == "y" ]] && reboot
            KT_REBOOT_NEEDED=0
        fi
        read -e -p "Нажмите Enter для возврата в меню тюнинга..."
    done
}

# =====================================================
# МОДУЛЬ 15: ANTI-DDOS (nft per-IP flood limits + fleet)
# =====================================================
# Отдельная nft-таблица 'inet vpsguard' (priority -150, policy ACCEPT) — НЕ второй
# фаервол: только per-IP rate-limit флуда поверх твоего UFW/CrowdSec. Легит-трафик
# проходит насквозь к UFW; режутся только источники, превышающие лимит.
# То, чего НЕ делают UFW (статичный allow/deny), CrowdSec (по логам) и fail2ban:
#   • per-IP SYN-rate и connlimit на сервисных портах,
#   • per-IP UDP-rate (QUIC / Hysteria2 / TUIC — fail2ban UDP не видит вообще).
# SSH-брут и portscan НЕ дублируем — их держат твои fail2ban + CrowdSec.
# Идея и nft-паттерны: github.com/jestivald/node-accelerator (protect.sh)

AD_CONF_DIR=/etc/vpsguard
AD_NFT_FILE="$AD_CONF_DIR/vpsguard.nft"
AD_STATE_DIR=/var/lib/vpsguard

ad_ssh_client_ip() {
    local ip="${SSH_CONNECTION:-}"; ip="${ip%% *}"
    [ -z "$ip" ] && { ip="${SSH_CLIENT:-}"; ip="${ip%% *}"; }
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$ip" == *:* ]] && [ "$ip" != "127.0.0.1" ] && [ "$ip" != "::1" ]; then
        echo "$ip"
    fi
}

# Разбор whitelist-строки в v4/v6 списки (с валидацией — значение уходит в nft-heredoc)
ad_parse_wl() {
    local in="$1" x
    AD_WL4=""; AD_WL6=""
    for x in ${in//,/ }; do
        [ -z "$x" ] && continue
        if [[ "$x" == *:* ]]; then
            [[ "$x" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]] && AD_WL6+="${AD_WL6:+, }$x"
        elif [[ "$x" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
            AD_WL4+="${AD_WL4:+, }$x"
        fi
    done
}

ad_install() {
    print_header
    echo "╔══════════════════════════════════════════╗"
    echo "║   Anti-DDoS: установка per-IP лимитов    ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    rn_info "Это НЕ заменяет UFW — добавляет слой per-IP rate-limit поверх."
    echo ""

    apt install -y nftables curl >/dev/null 2>&1 || true

    # ── параметры ──
    local ssh_port tcp_ports udp_ports wl conn_limit syn_rate syn_burst udp_rate udp_burst safety antispoof
    read -e -p "SSH порт (исключим из лимитов) [${DEFAULT_SSH_PORT}]: " ssh_port
    ssh_port=${ssh_port:-$DEFAULT_SSH_PORT}
    read -e -p "TCP сервисные порты через запятую [443]: " tcp_ports
    tcp_ports=${tcp_ports:-443}
    read -e -p "UDP сервисные порты через запятую (Hysteria2/TUIC) [443]: " udp_ports
    udp_ports=${udp_ports:-443}
    echo ""
    echo "Whitelist: панель, мониторинг, доверенные IP (через запятую, можно CIDR)."
    echo "Твой текущий SSH-IP добавится автоматически."
    read -e -p "Whitelist IP/CIDR [пусто]: " wl
    echo ""
    echo "CONN_LIMIT — потолок ОДНОВРЕМЕННЫХ коннектов с одного IP."
    echo "За CGNAT (RU-мобильные) один IP = много абонентов → держим с запасом."
    read -e -p "CONN_LIMIT [2048]: " conn_limit
    conn_limit=${conn_limit:-2048}
    read -e -p "SYN rate per-IP /сек [200]: " syn_rate
    syn_rate=${syn_rate:-200}
    read -e -p "SYN burst [400]: " syn_burst
    syn_burst=${syn_burst:-400}
    read -e -p "UDP rate per-IP /сек [200]: " udp_rate
    udp_rate=${udp_rate:-200}
    read -e -p "UDP burst [400]: " udp_burst
    udp_burst=${udp_burst:-400}
    read -e -p "Сейфти-таймер (сек до авто-сноса при потере SSH) [300]: " safety
    safety=${safety:-300}
    echo ""
    read -e -p "Включить anti-spoofing (drop bogon-источников на WAN)? (y/n) [n]: " antispoof

    # валидация чисел
    local k
    for k in ssh_port conn_limit syn_rate syn_burst udp_rate udp_burst safety; do
        [[ "${!k}" =~ ^[0-9]+$ ]] || { rn_error "Параметр $k='${!k}' — не число. Отмена."; return; }
    done
    for k in $tcp_ports $udp_ports; do
        [[ "$k" =~ ^[0-9,]+$ ]] || { rn_error "Порт '$k' невалиден. Отмена."; return; }
    done

    # whitelist + авто-IP текущей SSH-сессии
    local admin_ip; admin_ip="$(ad_ssh_client_ip || true)"
    ad_parse_wl "${wl}${admin_ip:+,$admin_ip}"
    [ -n "$admin_ip" ] && rn_info "Авто-whitelist твоего SSH-IP: $admin_ip"

    local WAN; WAN="$(kt_default_iface || true)"

    # ── сборка per-port правил ──
    local TCP_RULES="" UDP_RULES="" p
    for p in ${tcp_ports//,/ }; do
        [ -z "$p" ] && continue
        TCP_RULES+="
        tcp dport ${p} ct state new meter cc4_${p} { ip saddr ct count over ${conn_limit} } drop
        tcp dport ${p} ct state new meter cc6_${p} { ip6 saddr ct count over ${conn_limit} } drop
        tcp dport ${p} ct state new meter syn4_${p} { ip saddr limit rate over ${syn_rate}/second burst ${syn_burst} packets } drop
        tcp dport ${p} ct state new meter syn6_${p} { ip6 saddr limit rate over ${syn_rate}/second burst ${syn_burst} packets } drop"
    done
    for p in ${udp_ports//,/ }; do
        [ -z "$p" ] && continue
        UDP_RULES+="
        udp dport ${p} meter udp4_${p} { ip saddr limit rate over ${udp_rate}/second burst ${udp_burst} packets } drop
        udp dport ${p} meter udp6_${p} { ip6 saddr limit rate over ${udp_rate}/second burst ${udp_burst} packets } drop"
    done

    local ANTISPOOF=""
    if [[ "$antispoof" == "y" && -n "$WAN" ]]; then
        ANTISPOOF="        iifname \"${WAN}\" ip saddr @bogon_v4 drop
        iifname \"${WAN}\" ip6 saddr @bogon_v6 drop"
    fi

    local WL4_LINE="" WL6_LINE=""
    [ -n "$AD_WL4" ] && WL4_LINE="elements = { $AD_WL4 }"
    [ -n "$AD_WL6" ] && WL6_LINE="elements = { $AD_WL6 }"

    mkdir -p "$AD_CONF_DIR" "$AD_STATE_DIR"

    # ── генерация nft (своя таблица, idempotent create→delete→recreate) ──
    cat > "$AD_NFT_FILE" <<NFT
#!/usr/sbin/nft -f
# vpsguard / anti-DDoS @ $(date -Is)
# Своя таблица, policy ACCEPT, priority -150 (раньше UFW/CrowdSec).
# Режем ТОЛЬКО per-IP флуд; остальное отдаём дальше в UFW.

table inet vpsguard {}
delete table inet vpsguard

table inet vpsguard {

    set whitelist_v4 { type ipv4_addr; flags interval; auto-merge; $WL4_LINE }
    set whitelist_v6 { type ipv6_addr; flags interval; auto-merge; $WL6_LINE }

    # ноды флота (наполняется vpsguard-fleet-sync из Remnawave)
    set fleet_v4 { type ipv4_addr; flags interval; auto-merge; }
    set fleet_v6 { type ipv6_addr; flags interval; auto-merge; }

    set bogon_v4 {
        type ipv4_addr; flags interval; auto-merge
        elements = {
            0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
            169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24,
            192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
            224.0.0.0/3
        }
    }
    set bogon_v6 {
        type ipv6_addr; flags interval; auto-merge
        elements = { ::1/128, ::/128, ::ffff:0:0/96, 100::/64, 2001:db8::/32, fc00::/7 }
    }

    chain input {
        type filter hook input priority -150; policy accept;

        iif lo accept
        ct state established,related accept

        # доверенные (твой SSH-IP, панель, ноды флота) — никогда не лимитируем
        ip  saddr @whitelist_v4 accept
        ip6 saddr @whitelist_v6 accept
        ip  saddr @fleet_v4 accept
        ip6 saddr @fleet_v6 accept

$ANTISPOOF

        # flag-drop: аномальные TCP-флаги (сканеры XMAS/NULL/FIN и битые пакеты).
        # Легитимный трафик таких комбинаций не шлёт — дропаем до сервисных правил.
        tcp flags & (fin|syn) == (fin|syn) drop
        tcp flags & (syn|rst) == (syn|rst) drop
        tcp flags & (fin|rst) == (fin|rst) drop
        tcp flags & (fin|ack) == fin drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop

        # ICMP rate-limit: пинг жив, но флуд режется (per-IP было бы дороже — тут глобально мягко)
        ip  protocol icmp   icmp   type echo-request limit rate over 20/second burst 40 packets drop
        ip6 nexthdr  icmpv6 icmpv6 type echo-request limit rate over 20/second burst 40 packets drop

        # SSH-порт ${ssh_port} НЕ трогаем — брут держат fail2ban + CrowdSec
        tcp dport ${ssh_port} accept

        # сервисные TCP: per-IP connlimit + SYN-rate (превышение → drop, без бана IP — CGNAT-safe)
$TCP_RULES

        # сервисные UDP: per-IP rate (QUIC / Hysteria2 / TUIC)
$UDP_RULES

        # остальное — policy accept → уходит в UFW/CrowdSec
    }

    chain forward { type filter hook forward priority -150; policy accept; }
    chain output  { type filter hook output  priority -150; policy accept; }
}
NFT

    # ── проверка синтаксиса ДО применения ──
    if ! nft -c -f "$AD_NFT_FILE"; then
        rn_error "Сгенерированный ruleset не прошёл nft -c. Файл: $AD_NFT_FILE (ничего не применено)."
        return
    fi
    rn_success "nft -c: синтаксис валиден"

    # ── сейфти-таймер от самоблокировки ──
    if command -v systemd-run >/dev/null 2>&1; then
        systemctl stop vpsguard-safety.timer 2>/dev/null || true
        systemd-run --quiet --unit=vpsguard-safety --on-active="${safety}s" \
            /usr/sbin/nft delete table inet vpsguard >/dev/null 2>&1 \
            && rn_warn "Сейфти: при потере SSH таблица снесётся через ${safety}s (доступ вернётся)"
    fi

    # Применение выполняется через systemd после создания unit-файла.

    # ── boot-persist своим сервисом (не трогаем /etc/nftables.conf и чужие таблицы) ──
    cat > /etc/systemd/system/vpsguard-firewall.service <<EOF
[Unit]
Description=vpsguard anti-DDoS (nftables)
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $AD_NFT_FILE
ExecReload=/usr/sbin/nft -f $AD_NFT_FILE
ExecStop=/usr/sbin/nft delete table inet vpsguard

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload

    if ! systemctl enable vpsguard-firewall.service; then
        rn_error "Не удалось включить автозагрузку vpsguard"
        return 1
    fi

    if systemctl is-active --quiet vpsguard-firewall.service; then
        if ! systemctl reload vpsguard-firewall.service; then
            rn_error "Не удалось обновить правила vpsguard"
            return 1
        fi

        # Reload пересоздаёт nft-таблицу и очищает fleet_v4/fleet_v6.
        # Восстанавливаем доверенные IP нод из Remnawave.
        if [ -x /usr/local/sbin/vpsguard-fleet-sync ]; then
            if ! /usr/local/sbin/vpsguard-fleet-sync; then
                rn_warn "Fleet-sync не завершился успешно после reload"
            fi
        fi
    elif ! systemctl start vpsguard-firewall.service; then
        rn_error "Не удалось запустить vpsguard-firewall.service"
        return 1
    fi

    rn_success "nftables vpsguard применён и служба активна"

    # ── status-хелпер ──
    cat > /usr/local/sbin/vpsguard-status <<'ST'
#!/usr/bin/env bash
echo "── table inet vpsguard ──"
nft list table inet vpsguard 2>/dev/null | grep -E 'policy|counter|meter|elements' | head -40
echo ""
echo "── whitelist ──"
echo "v4: $(nft list set inet vpsguard whitelist_v4 2>/dev/null | grep -oE '[0-9.]+' | wc -l)   v6: $(nft list set inet vpsguard whitelist_v6 2>/dev/null | grep -c ':')"
echo ""
echo "── fleet (ноды флота) ──"
echo "v4: $(nft list set inet vpsguard fleet_v4 2>/dev/null | grep -coE '[0-9.]+')   v6: $(nft list set inet vpsguard fleet_v6 2>/dev/null | grep -c ':')   (синк: $(journalctl -t vpsguard-fleet -n1 --no-pager -o cat 2>/dev/null | head -c 70))"
echo ""
echo "── активные meter'ы (per-IP счётчики флуда) ──"
nft list meters table inet vpsguard 2>/dev/null | grep -E 'meter|elements' | head -30
ST
    chmod +x /usr/local/sbin/vpsguard-status

    # ── top-talkers (кандидаты в whitelist если нода за LB/CDN) ──
    cat > /usr/local/sbin/vpsguard-top <<'TT'
#!/usr/bin/env bash
# Топ удалённых IP по established TCP. Если нода за реверс-прокси/LB/CDN — легит-трафик
# идёт с горстки IP; занеси их в whitelist, чтобы per-IP лимиты их не резали.
PORTS="${1:-443}"; N="${2:-25}"
filt=""
for p in ${PORTS//,/ }; do [ -n "$p" ] && filt="${filt:+$filt or }sport = :$p"; done
[ -n "$filt" ] || { echo "нет портов"; exit 1; }
echo "── Топ-$N IP по established TCP на портах: $PORTS ──"
ss -Hnt state established "( $filt )" 2>/dev/null | awk '{print $5}' \
    | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//' | sort | uniq -c | sort -rn | head -n "$N"
TT
    chmod +x /usr/local/sbin/vpsguard-top

    # маркер с параметрами
    cat > "$AD_STATE_DIR/installed" <<EOF
installed_at=$(date -Is)
ssh_port=$ssh_port
tcp_ports=$tcp_ports
udp_ports=$udp_ports
conn_limit=$conn_limit
EOF

    log "vpsguard anti-DDoS установлен (tcp=$tcp_ports udp=$udp_ports conn=$conn_limit)"

    # ── подтверждение (защита от самоблокировки) ──
    echo ""
    rn_warn "ПРОВЕРЬ из НОВОГО окна: ssh root@<этот сервер> (порт $ssh_port)"
    read -e -p "SSH работает? (y/n): " _ok
    if [[ "$_ok" == "y" ]]; then
        systemctl stop vpsguard-safety.timer 2>/dev/null || true
        rn_success "Сейфти-таймер снят. Anti-DDoS активен и переживёт reboot."
        rn_info "Статус: vpsguard-status   |   топ источников: vpsguard-top $tcp_ports"
    else
        rn_warn "Сейфти оставлен: через ${safety}s таблица vpsguard снесётся сама."
        rn_warn "Если всё ок — сними вручную: systemctl stop vpsguard-safety.timer"
    fi
}

# ── 15.2 fleet-sync: ноды флота из Remnawave /api/nodes → nft-сет fleet_* ──
ad_fleet_setup() {
    print_header
    echo "╔══════════════════════════════════════════╗"
    echo "║   Anti-DDoS: fleet-sync (Remnawave)      ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    if ! nft list table inet vpsguard >/dev/null 2>&1; then
        rn_error "Сначала установи anti-DDoS (пункт 1) — нет таблицы vpsguard."
        return
    fi
    echo "  Тянет адреса нод флота из панели Remnawave (GET /api/nodes по Bearer)"
    echo "  и держит их в whitelist, чтобы межнодовый трафик не попадал под лимиты."
    echo "  Токен уходит ТОЛЬКО на твой URL. Fail-safe: панель недоступна → last-known-good."
    echo ""
    local url token interval
    read -e -p "URL панели (https://panel.example.com): " url
    [[ "$url" =~ ^https?://[A-Za-z0-9._~:/?#=%@-]+$ ]] || { rn_error "URL невалиден"; return; }
    read -e -p "API-токен (Bearer): " token
    [ -n "$token" ] || { rn_error "Токен пуст"; return; }
    read -e -p "Интервал синка [5min]: " interval
    interval=${interval:-5min}
    [[ "$interval" =~ ^[0-9]+(s|sec|m|min|h|hr|d|day)?$ ]] || { rn_error "Интервал невалиден (напр. 5min)"; return; }

    apt install -y jq curl >/dev/null 2>&1 || true

    umask 077; mkdir -p "$AD_CONF_DIR"
    printf 'REMNAWAVE_URL=%s\nREMNAWAVE_TOKEN=%s\n' "$url" "$token" > "$AD_CONF_DIR/fleet.env"
    chmod 0600 "$AD_CONF_DIR/fleet.env"
    rn_success "Токен сохранён в $AD_CONF_DIR/fleet.env (0600)"

    cat > /usr/local/sbin/vpsguard-fleet-sync <<'FSYNC'
#!/usr/bin/env bash
# vpsguard-fleet-sync — адреса нод из Remnawave (GET /api/nodes, Bearer) → nft fleet_v4/v6.
# Fail-safe: панель недоступна / 0 валидных IP → текущий whitelist нод НЕ трогаем.
set -u
TAG=vpsguard-fleet
ENVF=/etc/vpsguard/fleet.env
[ -r "$ENVF" ] || { logger -t "$TAG" "нет $ENVF — выкл"; exit 0; }
. "$ENVF"
URL="${REMNAWAVE_URL:-}"; TOKEN="${REMNAWAVE_TOKEN:-}"
[ -n "$URL" ] && [ -n "$TOKEN" ] || { logger -t "$TAG" "URL/TOKEN пуст"; exit 0; }
URL="${URL%/}"
command -v curl >/dev/null 2>&1 || { logger -t "$TAG" "нет curl"; exit 1; }
command -v jq   >/dev/null 2>&1 || { logger -t "$TAG" "нет jq"; exit 1; }
nft list set inet vpsguard fleet_v4 >/dev/null 2>&1 || { logger -t "$TAG" "нет сета fleet — выкл"; exit 0; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
HTTP="$(curl -fsS --max-time 15 -o "$TMP/r.json" -w '%{http_code}' \
        -H "Authorization: Bearer $TOKEN" -H "Accept: application/json" \
        "$URL/api/nodes" 2>/dev/null || true)"
[ "$HTTP" = "200" ] && [ -s "$TMP/r.json" ] || { logger -t "$TAG" "панель недоступна (HTTP=$HTTP) — last-known-good"; exit 0; }
jq -r '.. | objects | .address? // empty' "$TMP/r.json" 2>/dev/null | awk 'NF' | sort -u > "$TMP/addr"
[ -s "$TMP/addr" ] || { logger -t "$TAG" "в ответе нет address — last-known-good"; exit 0; }
: > "$TMP/v4"; : > "$TMP/v6"
while IFS= read -r a; do
    [ -n "$a" ] || continue
    if printf '%s' "$a" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then echo "$a" >> "$TMP/v4"; continue; fi
    if printf '%s' "$a" | grep -qE '^[0-9a-fA-F:]+$' && printf '%s' "$a" | grep -q ':'; then echo "$a" >> "$TMP/v6"; continue; fi
    getent ahostsv4 "$a" 2>/dev/null | awk '{print $1}' >> "$TMP/v4"
    getent ahostsv6 "$a" 2>/dev/null | awk '{print $1}' >> "$TMP/v6"
done < "$TMP/addr"
V4="$(grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$TMP/v4" 2>/dev/null | sort -u | paste -sd, -)"
V6="$(grep -E '^[0-9a-fA-F:]+$' "$TMP/v6" 2>/dev/null | grep ':' | sort -u | paste -sd, -)"
[ -n "$V4" ] || [ -n "$V6" ] || { logger -t "$TAG" "0 валидных IP — last-known-good"; exit 0; }
{
    echo "flush set inet vpsguard fleet_v4"
    [ -n "$V4" ] && echo "add element inet vpsguard fleet_v4 { $V4 }"
    echo "flush set inet vpsguard fleet_v6"
    [ -n "$V6" ] && echo "add element inet vpsguard fleet_v6 { $V6 }"
} > "$TMP/upd.nft"
n4=$(printf '%s' "$V4" | tr ',' '\n' | grep -c . || true)
n6=$(printf '%s' "$V6" | tr ',' '\n' | grep -c . || true)
if nft -f "$TMP/upd.nft" 2>/dev/null; then
    logger -t "$TAG" "whitelist нод обновлён: ${n4} v4 + ${n6} v6"
else
    logger -t "$TAG" "nft apply не прошёл — last-known-good"
fi
FSYNC
    chmod +x /usr/local/sbin/vpsguard-fleet-sync

    cat > /etc/systemd/system/vpsguard-fleet-sync.service <<'EOF'
[Unit]
Description=vpsguard fleet whitelist sync (Remnawave /api/nodes)
After=vpsguard-firewall.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vpsguard-fleet-sync
EOF
    cat > /etc/systemd/system/vpsguard-fleet-sync.timer <<EOF
[Unit]
Description=vpsguard fleet sync timer
[Timer]
OnBootSec=60s
OnUnitActiveSec=$interval
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now vpsguard-fleet-sync.timer >/dev/null 2>&1 || true
    /usr/local/sbin/vpsguard-fleet-sync >/dev/null 2>&1 || true
    sleep 1
    rn_success "Fleet-sync включён (интервал $interval). Лог: journalctl -t vpsguard-fleet"
    rn_info "Если у твоей версии панели путь не /api/nodes — поправь в /usr/local/sbin/vpsguard-fleet-sync"
    log "vpsguard fleet-sync настроен (interval=$interval)"
}

ad_status() {
    echo ""
    if ! nft list table inet vpsguard >/dev/null 2>&1; then
        rn_warn "Таблица vpsguard не загружена (anti-DDoS не установлен или снят)."
        return
    fi
    if [ -x /usr/local/sbin/vpsguard-status ]; then
        /usr/local/sbin/vpsguard-status
    else
        nft list table inet vpsguard 2>/dev/null | head -50
    fi
    echo ""
    local tcp_ports=443
    [ -r "$AD_STATE_DIR/installed" ] && tcp_ports="$(awk -F= '/^tcp_ports=/{print $2}' "$AD_STATE_DIR/installed")"
    echo "── топ источников (кандидаты в whitelist за LB/CDN) ──"
    /usr/local/sbin/vpsguard-top "$tcp_ports" 15 2>/dev/null || true
}

ad_rollback() {
    echo ""
    read -e -p "Снять anti-DDoS (таблица vpsguard + сервисы + fleet-sync)? (y/n): " _r
    [[ "$_r" == "y" ]] || { echo "Отменено."; return; }
    log_section "Откат anti-DDoS (vpsguard)"
    systemctl disable --now vpsguard-fleet-sync.timer >/dev/null 2>&1 || true
    systemctl stop vpsguard-fleet-sync.service 2>/dev/null || true
    systemctl stop vpsguard-safety.timer 2>/dev/null || true
    systemctl disable --now vpsguard-firewall.service >/dev/null 2>&1 || true
    nft delete table inet vpsguard 2>/dev/null || true
    rm -f /etc/systemd/system/vpsguard-firewall.service \
          /etc/systemd/system/vpsguard-fleet-sync.service \
          /etc/systemd/system/vpsguard-fleet-sync.timer
    rm -f /usr/local/sbin/vpsguard-status /usr/local/sbin/vpsguard-top /usr/local/sbin/vpsguard-fleet-sync
    systemctl daemon-reload
    rn_success "Anti-DDoS снят. UFW/CrowdSec/GeoBlock не тронуты."
    rn_info "Токен fleet ($AD_CONF_DIR/fleet.env) оставлен. Удалить: rm -f $AD_CONF_DIR/fleet.env"
    log "vpsguard anti-DDoS откатан"
}

setup_antiddos() {
    while true; do
        print_header
        echo "╔══════════════════════════════════════════╗"
        echo "║   Anti-DDoS (nft per-IP flood limits)    ║"
        echo "╚══════════════════════════════════════════╝"
        echo ""
        echo "  Слой per-IP rate-limit ПОВЕРХ UFW (своя таблица, policy accept)."
        echo "  Закрывает дыру, которой нет у UFW/CrowdSec/fail2ban:"
        echo "    • per-IP SYN-rate + connlimit на сервисных портах"
        echo "    • per-IP UDP-rate (QUIC / Hysteria2 / TUIC)"
        echo "  SSH-брут и portscan НЕ дублирует — их держат fail2ban + CrowdSec."
        echo ""
        echo "  1) Установить / обновить (per-IP flood limits)"
        echo "  2) Fleet-sync whitelist (ноды флота из Remnawave /api/nodes)"
        echo "  3) Статус (баны, meter'ы, топ источников)"
        echo "  4) Снять защиту (откат)"
        echo "  0) Назад"
        echo ""
        read -e -p "Выберите [0-4]: " AD_CHOICE
        case $AD_CHOICE in
            1) ad_install ;;
            2) ad_fleet_setup ;;
            3) ad_status ;;
            4) ad_rollback ;;
            0) return ;;
            *) echo "Неверный выбор." ;;
        esac
        echo ""
        read -e -p "Нажмите Enter для возврата в меню Anti-DDoS..."
    done
}

# =====================================================
# МОДУЛЬ 16: THREAT-INTEL БЛОКЛИСТ (Spamhaus DROP + FireHOL L1)
# =====================================================
# Статичные репутационные CIDR-фиды известных вредоносных сетей (botnet C2,
# хайджекнутые диапазоны, спам-сети). По механике — близнец AS_Network_List:
# ipset hash:net + прямой DROP в iptables (O(1)-матч, без CrowdSec-decisions/TTL).
# НЕ дублирует AS_blacklist: тот — РФ-госсети, этот — глобальный malware.
# Источники: Spamhaus DROP (v4+v6 json) + FireHOL Level 1 (v4).
# Идея фидов: github.com/jestivald/node-accelerator (protect.sh), но через ipset.

TIB_DIR="/etc/threat-blocklist"
TIB_LOG="/var/log/threat-blocklist-update.log"
TIB_CRON_SCRIPT="/usr/local/bin/threat-blocklist-update.sh"

tib_detect_trafficguard() { return 1; }  # TG выпилен — threat-block всегда в INPUT

tib_detect_crowdsec() {
    if systemctl is-active --quiet crowdsec-firewall-bouncer 2>/dev/null; then
        local cfg="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
        [ -f "$cfg" ] && grep -m1 "^mode:" "$cfg" 2>/dev/null | awk '{print $2}' | tr -d '"' || echo "iptables"
    else
        echo ""
    fi
}

tib_print_env() {
    local cs_mode="$1"
    echo ""
    echo "  Обнаруженное окружение:"
    [ -n "$cs_mode" ] && echo "    • CrowdSec bouncer: ${cs_mode} (активен)" || echo "    • CrowdSec: не активен"
    tib_detect_trafficguard >/dev/null 2>&1; echo "    • Правила → INPUT (Traffic-Guard выпилен)"
    echo ""
}

# fetch_spamhaus_firehol <dir>: качает фиды в <dir>/threat-v4.cidr и threat-v6.cidr
# (по одной CIDR на строку). Возвращает 1 если НИ ОДИН фид не скачался (fail-safe).
tib_build_lists() {
    local dir="$1" tmp4 tmp6 got=0
    tmp4="$dir/threat-v4.cidr.tmp.$$"; tmp6="$dir/threat-v6.cidr.tmp.$$"
    : > "$tmp4"; : > "$tmp6"

    _tib_fetch() { curl -fsSL --connect-timeout 10 --max-time 60 "$1" 2>/dev/null; }

    # Spamhaus DROP (json: {"cidr":"1.2.3.0/24",...} построчно). jq желателен, но не обязателен.
    local sh4 sh6
    sh4="$(_tib_fetch https://www.spamhaus.org/drop/drop_v4.json)"
    sh6="$(_tib_fetch https://www.spamhaus.org/drop/drop_v6.json)"
    if [ -n "$sh4" ]; then
        if command -v jq >/dev/null 2>&1; then
            printf '%s\n' "$sh4" | jq -r '.cidr // empty' 2>/dev/null >> "$tmp4"
        else
            printf '%s\n' "$sh4" | grep -oE '"cidr"[[:space:]]*:[[:space:]]*"[0-9./]+"' | grep -oE '[0-9.]+/[0-9]+' >> "$tmp4"
        fi
        got=1
    fi
    if [ -n "$sh6" ]; then
        if command -v jq >/dev/null 2>&1; then
            printf '%s\n' "$sh6" | jq -r '.cidr // empty' 2>/dev/null >> "$tmp6"
        else
            printf '%s\n' "$sh6" | grep -oE '"cidr"[[:space:]]*:[[:space:]]*"[0-9a-fA-F:./]+"' | grep -oE '[0-9a-fA-F:]+/[0-9]+' >> "$tmp6"
        fi
        got=1
    fi

    # FireHOL Level 1 (v4, high-confidence; комменты с '#')
    local fh
    fh="$(_tib_fetch https://iplists.firehol.org/files/firehol_level1.netset)"
    if [ -n "$fh" ]; then
        printf '%s\n' "$fh" | grep -vE '^[[:space:]]*#' | grep -E '[0-9]' >> "$tmp4"
        got=1
    fi

    if [ "$got" != "1" ]; then
        rm -f "$tmp4" "$tmp6"
        return 1
    fi

    # нормализация: одиночный IP → /32 (v4) /128 (v6), убрать дубли/пустые
    # КРИТИЧНО: вычищаем bogon/loopback/private — FireHOL L1 содержит 0.0.0.0/8 и
    # 127.0.0.0/8, которые блокируют systemd-resolved (127.0.0.53/54) → рвут DNS ноды.
    # Также RFC1918 и link-local — нода не должна блокировать свои служебные адреса.
    awk 'NF{ if ($0 !~ /\//){ $0=$0"/32" } print }' "$tmp4" | sort -u \
        | grep -vE '^(0\.|127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|100\.6[4-9]\.|100\.[7-9][0-9]\.|100\.1[01][0-9]\.|100\.12[0-7]\.|255\.255\.255\.255)' \
        > "$dir/threat-v4.cidr.new"
    awk 'NF{ if ($0 !~ /\//){ $0=$0"/128" } print }' "$tmp6" | sort -u \
        | grep -ivE '^(::1?/|::ffff:|fe80:|fc00:|fd00:|fec0:)' \
        > "$dir/threat-v6.cidr.new"
    rm -f "$tmp4" "$tmp6"
    return 0
}

# Загрузка cidr-файла в ipset атомарно через swap (без дыры в защите).
# tib_load_set <set_name> <family inet|inet6> <cidr_file>
tib_load_set() {
    local set="$1" fam="$2" file="$3" tmp="${1}-tmp"
    ipset create "$set" hash:net family "$fam" maxelem 262144 -exist 2>/dev/null || true
    ipset destroy "$tmp" 2>/dev/null || true
    ipset create "$tmp" hash:net family "$fam" maxelem 262144 2>/dev/null || true
    local c
    while IFS= read -r c; do
        [ -n "$c" ] && ipset add "$tmp" "$c" -exist 2>/dev/null || true
    done < "$file"
    ipset swap "$tmp" "$set" 2>/dev/null || true
    ipset destroy "$tmp" 2>/dev/null || true
}

tib_install() {
    echo ""
    log_section "Threat-Intel блоклист — установка (Spamhaus + FireHOL L1)"

    local cs_mode; cs_mode=$(tib_detect_crowdsec)
    tib_print_env "$cs_mode"

    for pkg in ipset iptables curl; do
        command -v "$pkg" &>/dev/null || apt-get install -y -qq "$pkg"
    done
    command -v jq &>/dev/null || apt-get install -y -qq jq 2>/dev/null || true

    ensure_loopback_accept   # гарантируем loopback ACCEPT (иначе INPUT DROP ломает DNS)
    mkdir -p "$TIB_DIR"

    echo "  Качаю фиды (Spamhaus DROP v4/v6 + FireHOL L1)..."
    if ! tib_build_lists "$TIB_DIR"; then
        rn_error "Ни один фид не скачался (нет сети/блокировка). Ничего не применено."
        return 1
    fi
    mv -f "$TIB_DIR/threat-v4.cidr.new" "$TIB_DIR/threat-v4.cidr"
    mv -f "$TIB_DIR/threat-v6.cidr.new" "$TIB_DIR/threat-v6.cidr"

    tib_load_set threat-block-v4 inet  "$TIB_DIR/threat-v4.cidr"
    tib_load_set threat-block-v6 inet6 "$TIB_DIR/threat-v6.cidr"
    echo "  ✓ ipset sets загружены (threat-block-v4 / threat-block-v6)"

    # Встраивание: при Traffic-Guard — в SCANNERS-BLOCK, иначе в INPUT (как AS_blacklist)
    if tib_detect_trafficguard; then
        iptables -C SCANNERS-BLOCK -m set --match-set threat-block-v4 src -j DROP 2>/dev/null \
            || iptables -I SCANNERS-BLOCK 1 -m set --match-set threat-block-v4 src -j DROP
        ip6tables -C SCANNERS-BLOCK -m set --match-set threat-block-v6 src -j DROP 2>/dev/null \
            || ip6tables -I SCANNERS-BLOCK 1 -m set --match-set threat-block-v6 src -j DROP 2>/dev/null || true
        echo "iptables-tg" > "$TIB_DIR/mode"
        echo "  ✓ Правила добавлены в SCANNERS-BLOCK"
    else
        iptables -C INPUT -m set --match-set threat-block-v4 src -m conntrack --ctstate NEW -j DROP 2>/dev/null \
            || iptables -I INPUT -m set --match-set threat-block-v4 src -m conntrack --ctstate NEW -j DROP
        ip6tables -C INPUT -m set --match-set threat-block-v6 src -m conntrack --ctstate NEW -j DROP 2>/dev/null \
            || ip6tables -I INPUT -m set --match-set threat-block-v6 src -m conntrack --ctstate NEW -j DROP 2>/dev/null || true
        echo "iptables" > "$TIB_DIR/mode"
        echo "  ✓ Правила добавлены в INPUT"
    fi

    # КРИТИЧНО: вернуть lo ACCEPT на позицию 1 (наш -I INPUT сдвинул его вниз).
    # Без этого threat-DROP оказывается выше loopback → systemd-resolved (127.0.0.x)
    # отрезан → DNS ноды умирает. Это корневая причина всех проблем со скачиванием.
    ensure_loopback_accept

    persist_ipsets || { rn_error "Не удалось сохранить IPSet"; return 1; }
    managed_remove_legacy_cron "$TIB_CRON_SCRIPT" || return 1
    enable_managed_blocklist_timer threat || return 1
    echo "  ✓ Безопасное восстановление IPSet и systemd timer Threat включены"

    local v4 v6
    v4=$(ipset list threat-block-v4 2>/dev/null | awk '/Number of entries/{print $4}')
    v6=$(ipset list threat-block-v6 2>/dev/null | awk '/Number of entries/{print $4}')
    echo ""
    echo "✓ Threat-Intel блоклист установлен"
    echo "  IPv4 сетей: ${v4:-0}"
    echo "  IPv6 сетей: ${v6:-0}"
    rn_info "Не дублирует AS_blacklist (РФ-госсети) — это глобальный malware-фид."
    log "Threat-Intel блоклист установлен. v4: ${v4:-0}, v6: ${v6:-0}"

    # Самопроверка: правило в INPUT И сет непуст — иначе FAIL (для one-button)
    if iptables -C INPUT -m set --match-set threat-block-v4 src -m conntrack --ctstate NEW -j DROP 2>/dev/null \
       && [ "${v4:-0}" -gt 0 ] 2>/dev/null; then
        return 0
    else
        rn_error "Проверка не прошла: правило threat-block в INPUT отсутствует или сет пуст."
        log "Threat-Intel: FAIL самопроверки (rule/set)"
        return 1
    fi
}

tib_create_update_script() {
    cat > "$TIB_CRON_SCRIPT" <<'UPDATER'
#!/usr/bin/env bash
# Обновление Threat-Intel блоклиста (Spamhaus DROP + FireHOL L1).
# Fail-safe: фид(ы) недоступны → старые ipset НЕ трогаем (last-known-good).
TIB_DIR="/etc/threat-blocklist"
LOG="/var/log/threat-blocklist-update.log"
ts(){ date '+%Y-%m-%d %H:%M:%S'; }
_fetch(){ curl -fsSL --connect-timeout 10 --max-time 60 "$1" 2>/dev/null; }

echo "$(ts) [START] Обновление threat-blocklist" >> "$LOG"
t4="$TIB_DIR/threat-v4.cidr.tmp.$$"; t6="$TIB_DIR/threat-v6.cidr.tmp.$$"
: > "$t4"; : > "$t6"; got=0

sh4="$(_fetch https://www.spamhaus.org/drop/drop_v4.json)"
sh6="$(_fetch https://www.spamhaus.org/drop/drop_v6.json)"
if [ -n "$sh4" ]; then
    if command -v jq >/dev/null 2>&1; then printf '%s\n' "$sh4" | jq -r '.cidr // empty' 2>/dev/null >> "$t4"
    else printf '%s\n' "$sh4" | grep -oE '[0-9.]+/[0-9]+' >> "$t4"; fi
    got=1
fi
if [ -n "$sh6" ]; then
    if command -v jq >/dev/null 2>&1; then printf '%s\n' "$sh6" | jq -r '.cidr // empty' 2>/dev/null >> "$t6"
    else printf '%s\n' "$sh6" | grep -oE '[0-9a-fA-F:]+/[0-9]+' >> "$t6"; fi
    got=1
fi
fh="$(_fetch https://iplists.firehol.org/files/firehol_level1.netset)"
if [ -n "$fh" ]; then printf '%s\n' "$fh" | grep -vE '^[[:space:]]*#' | grep -E '[0-9]' >> "$t4"; got=1; fi

if [ "$got" != "1" ]; then
    echo "$(ts) [ERR] Ни один фид не скачался — last-known-good" >> "$LOG"
    rm -f "$t4" "$t6"; exit 1
fi

awk 'NF{ if ($0 !~ /\//){ $0=$0"/32" } print }'  "$t4" | sort -u | grep -vE '^(0\.|127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|100\.6[4-9]\.|100\.[7-9][0-9]\.|100\.1[01][0-9]\.|100\.12[0-7]\.|255\.255\.255\.255)' > "$TIB_DIR/threat-v4.cidr.new"
awk 'NF{ if ($0 !~ /\//){ $0=$0"/128" } print }' "$t6" | sort -u | grep -ivE '^(::1?/|::ffff:|fe80:|fc00:|fd00:|fec0:)' > "$TIB_DIR/threat-v6.cidr.new"
rm -f "$t4" "$t6"

load_set(){ # <set> <inet|inet6> <file>
    local set="$1" fam="$2" file="$3" tmp="${1}-tmp"
    ipset create "$set" hash:net family "$fam" maxelem 262144 -exist 2>/dev/null || true
    ipset destroy "$tmp" 2>/dev/null || true
    ipset create "$tmp" hash:net family "$fam" maxelem 262144 2>/dev/null || true
    while IFS= read -r c; do [ -n "$c" ] && ipset add "$tmp" "$c" -exist 2>/dev/null || true; done < "$file"
    ipset swap "$tmp" "$set" 2>/dev/null || true
    ipset destroy "$tmp" 2>/dev/null || true
}
load_set threat-block-v4 inet  "$TIB_DIR/threat-v4.cidr.new"
load_set threat-block-v6 inet6 "$TIB_DIR/threat-v6.cidr.new"
mv -f "$TIB_DIR/threat-v4.cidr.new" "$TIB_DIR/threat-v4.cidr"
mv -f "$TIB_DIR/threat-v6.cidr.new" "$TIB_DIR/threat-v6.cidr"

V4=$(ipset list threat-block-v4 2>/dev/null | awk '/Number of entries/{print $4}')
V6=$(ipset list threat-block-v6 2>/dev/null | awk '/Number of entries/{print $4}')
[ -d /etc/iptables ] && { iptables-save > /etc/iptables/rules.v4; ip6tables-save > /etc/iptables/rules.v6; }
ipset save > /etc/ipset.conf 2>/dev/null || true
echo "$(ts) [OK] Обновлено. IPv4: ${V4}, IPv6: ${V6}" >> "$LOG"
UPDATER
    chmod +x "$TIB_CRON_SCRIPT"
}

tib_cron_setup() {
    # Spamhaus/FireHOL обновляются часто; берём раз в 12ч (в :30 чтобы не совпасть с AS в 04:00)
    local cron_line="30 */12 * * * $TIB_CRON_SCRIPT >> $TIB_LOG 2>&1"
    ( crontab -l 2>/dev/null | grep -v "$TIB_CRON_SCRIPT"; echo "$cron_line" ) | crontab -
    echo "  ✓ Cron: автообновление каждые 12ч"
}

tib_status() {
    echo ""
    echo "── Threat-Intel блоклист ──"
    if ! ipset list threat-block-v4 &>/dev/null; then
        rn_warn "Не установлен (нет ipset threat-block-v4)."
        return
    fi
    local v4 v6
    v4=$(ipset list threat-block-v4 2>/dev/null | awk '/Number of entries/{print $4}')
    v6=$(ipset list threat-block-v6 2>/dev/null | awk '/Number of entries/{print $4}')
    echo "  IPv4 сетей: ${v4:-0}   IPv6 сетей: ${v6:-0}"
    echo "  Режим: $(cat "$TIB_DIR/mode" 2>/dev/null || echo '?')"
    echo "  Правила DROP:"
    iptables-save  2>/dev/null | grep threat-block | sed 's/^/    /'
    ip6tables-save 2>/dev/null | grep threat-block | sed 's/^/    /'
    echo "  Последнее обновление:"
    tail -n2 "$TIB_LOG" 2>/dev/null | sed 's/^/    /' || echo "    (лог пуст)"
    echo "  Cron: $(crontab -l 2>/dev/null | grep "$TIB_CRON_SCRIPT" || echo 'не настроен')"
}

tib_remove() {
    echo ""
    read -r -e -p "Удалить Threat-Intel (правила, IPSet и таймер)? (y/n): " _r
    [[ "$_r" == y ]] || { echo "Отменено."; return 0; }
    log_section "Удаление Threat-Intel блоклиста"
    systemctl disable --now threat-blacklist-update.timer || return 1
    managed_remove_ipsets threat-block-v4 threat-block-v6 || return 1
    persist_ipsets || { rn_error "Не удалось сохранить состояние IPSet"; return 1; }
    managed_remove_legacy_cron "$TIB_CRON_SCRIPT" || return 1
    rm -f "$TIB_CRON_SCRIPT"
    rm -rf "$TIB_DIR"
    rn_success "Threat-Intel удалён; AS и CrowdSec сохранены."
    log "Threat-Intel блоклист удалён"
}

setup_threat_blocklist() {
    while true; do
        print_header
        echo "╔══════════════════════════════════════════╗"
        echo "║  Threat-Intel блоклист (Spamhaus/FireHOL)║"
        echo "╚══════════════════════════════════════════╝"
        echo ""
        echo "  Глобальные malware-фиды (botnet C2, спам-сети, хайджек)."
        echo "  ipset+iptables, как AS_blacklist. Совместимо с CrowdSec."
        echo "  НЕ дублирует AS_blacklist (там РФ-госсети)."
        echo ""
        echo "  1) Установить / обновить (Spamhaus DROP + FireHOL L1)"
        echo "  2) Статус"
        echo "  3) Удалить"
        echo "  0) Назад"
        echo ""
        read -e -p "Выберите [0-3]: " TIB_CHOICE
        case $TIB_CHOICE in
            1) tib_install ;;
            2) tib_status ;;
            3) tib_remove ;;
            0) return ;;
            *) echo "Неверный выбор." ;;
        esac
        echo ""
        read -e -p "Нажмите Enter для возврата..."
    done
}

# =====================================================
# МОДУЛЬ 0: ОДНА КНОПКА (полный prod-стек) + ПОЛНАЯ ВЫЧИСТКА
# =====================================================
# Накатывает весь стек в правильной последовательности с логами, пошаговой
# диагностикой и сводным отчётом. Без TG. Продолжает при ошибках (не падает),
# в конце печатает OK/FAIL по каждому шагу.

# ── раннер шага: логирует, ловит код возврата, не роняет скрипт ──
ONEBTN_RESULTS=()
onebtn_step() {
    local name="$1"; shift
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "▶ ${name}"
    echo "════════════════════════════════════════════════════════════"
    log "[ONE-BUTTON] СТАРТ: ${name}"
    local rc=0
    # шаг выполняется в текущем шелле (нужно — меняет глобалы вроде KT_REBOOT_NEEDED),
    # но ошибку не пропускаем наружу: оборачиваем в группу с || 
    { "$@"; rc=$?; } || rc=$?
    if [ "$rc" -eq 0 ]; then
        echo ""
        rn_success "✔ ${name} — OK"
        log "[ONE-BUTTON] OK: ${name}"
        ONEBTN_RESULTS+=("OK   | ${name}")
    elif [ "$rc" -eq 2 ]; then
        # код 2 = шаг осознанно пропущен (напр. CrowdSec на РФ-ноде), не ошибка
        echo ""
        rn_warn "⊘ ${name} — ПРОПУЩЕНО (недоступно в этой среде)"
        log "[ONE-BUTTON] SKIP: ${name}"
        ONEBTN_RESULTS+=("SKIP | ${name} (недоступно)")
    else
        echo ""
        rn_error "✗ ${name} — FAIL (код ${rc})"
        log "[ONE-BUTTON] FAIL(${rc}): ${name}"
        ONEBTN_RESULTS+=("FAIL | ${name} (код ${rc})")
    fi
    return 0
}

setup_one_button() {
    print_header
    echo "╔══════════════════════════════════════════╗"
    echo "║   🚀 УСТАНОВИТЬ ВСЁ (полный prod-стек)   ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    echo "  Накатит в правильной последовательности:"
    echo "    1. База: SSH+UFW+тюнинг ядра+XanMod(BBRv3)+fail2ban"
    echo "    2. CrowdSec (поведенческий IPS, БЕЗ Traffic-Guard)"
    echo "    3. AS_Network_List — РФ-госсети → INPUT"
    echo "    4. Threat-Intel — Spamhaus+FireHOL L1 → INPUT"
    echo "    5. Anti-DDoS vpsguard — nft per-IP лимиты"
    echo ""
    rn_warn "ВНИМАНИЕ: ставить ТОЛЬКО на свежую ноду / эталон."
    rn_warn "CrowdSec сохраняет существующий UFW; другие шаги полного стека могут изменить firewall."
    rn_warn "XanMod заменит ядро (reboot спросим в конце)."
    rn_warn "vpsguard спросит порты/лимиты на своём шаге."
    echo ""
    echo "  Порядок при ошибке шага: ПРОДОЛЖАТЬ, отчёт в конце."
    echo ""
    read -e -p "Поехали? Введи 'yes' для старта: " _go
    [[ "$_go" == "yes" ]] || { echo "Отменено."; return; }

    ONEBTN_RESULTS=()
    KT_REBOOT_NEEDED=0
    local _start; _start=$(date +%s)
    log "=== [ONE-BUTTON] НАЧАЛО полного наката ==="

    # Preflight: гарантируем loopback ACCEPT и ждём готовности DNS (после ребута resolved
    # стартует с гонкой — без этого скачивание списков ловит таймаут резолвинга).
    ensure_loopback_accept
    echo ""
    echo "▶ Preflight: проверка DNS…"
    if wait_for_dns 15; then
        rn_success "DNS резолвит — продолжаю"
    else
        rn_warn "DNS не резолвит за 30с — сетевые шаги могут упасть (используется локальный fallback где есть)"
    fi

    # ── Шаг 1: база (вкл. тюнинг ядра + XanMod автоматически) ──
    onebtn_step "База: пакеты" do_update_packages
    onebtn_step "База: SSH (ключ+порт ${DEFAULT_SSH_PORT})" do_ssh_setup
    if [[ "${ONEBTN_RESULTS[-1]}" == FAIL* ]]; then
        rn_error "SSH не настроен; полный накат остановлен во избежание потери доступа."
        return 1
    fi
    onebtn_step "База: UFW" do_ufw_setup
    if [[ "${ONEBTN_RESULTS[-1]}" == FAIL* ]]; then
        rn_error "UFW не настроен; полный накат остановлен во избежание потери доступа."
        return 1
    fi
    onebtn_step "База: тюнинг ядра/сети + XanMod" do_sysctl_setup
    onebtn_step "База: автообновления" do_autoupgrade
    onebtn_step "База: fail2ban" do_fail2ban

    # ── Шаг 2: CrowdSec (без TG) ──
    onebtn_step "CrowdSec (поведенческий IPS)" crowdsec_install

    # ── Шаг 3: AS_Network_List (РФ-госсети → INPUT) ──
    onebtn_step "AS_Network_List (РФ-госсети)" asb_install_iptables

    # ── Шаг 4: Threat-Intel (Spamhaus+FireHOL → INPUT) ──
    onebtn_step "Threat-Intel (Spamhaus+FireHOL L1)" tib_install

    # ── Шаг 5: Anti-DDoS vpsguard (интерактивный — спросит параметры) ──
    echo ""
    rn_info "Следующий шаг (vpsguard) спросит порты/лимиты."
    onebtn_step "Anti-DDoS vpsguard (nft per-IP)" ad_install

    # ── Сводный отчёт ──
    local _end; _end=$(date +%s)
    print_header
    echo "╔══════════════════════════════════════════╗"
    echo "║   ОТЧЁТ: полный накат завершён           ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    local okc=0 failc=0 skipc=0 line
    for line in "${ONEBTN_RESULTS[@]}"; do
        if [[ "$line" == OK* ]]; then
            echo "  ✔ ${line}"; okc=$((okc+1))
        elif [[ "$line" == SKIP* ]]; then
            echo "  ⊘ ${line}"; skipc=$((skipc+1))
        else
            echo "  ✗ ${line}"; failc=$((failc+1))
        fi
    done
    echo ""
    echo "  Итого: ${okc} OK, ${failc} FAIL, ${skipc} SKIP   (за $(( _end - _start ))с)"
    log "=== [ONE-BUTTON] КОНЕЦ: ${okc} OK, ${failc} FAIL, ${skipc} SKIP ==="
    echo ""
    if [ "$failc" -gt 0 ]; then
        rn_warn "Есть упавшие шаги — глянь лог: $LOG_FILE"
        rn_warn "Каждый шаг можно доустановить вручную из главного меню."
    else
        rn_success "Все шаги прошли. Проверь: nft list table inet vpsguard | grep -c meter"
    fi
    echo ""
    echo "  Быстрая проверка стека:"
    echo "    • BBR:        sysctl net.ipv4.tcp_congestion_control"
    echo "    • CrowdSec:   cscli metrics | head"
    echo "    • AS-список:  ipset list asn-blacklist-v4 | grep entries"
    echo "    • Threat:     ipset list threat-block-v4 | grep entries"
    echo "    • vpsguard:   vpsguard-status"
    echo "    • Ноды/xray:  docker ps; ss -tlnp | grep -E ':443|:10085'"
    echo ""

    # ── XanMod reboot (как обычно — спрашиваем) ──
    if [ "${KT_REBOOT_NEEDED:-0}" = "1" ]; then
        rn_warn "XanMod установлен — для активации BBRv3 нужна ПЕРЕЗАГРУЗКА."
        read -e -p "Перезагрузить сейчас? (y/n): " _rb
        [[ "$_rb" == "y" ]] && { log "[ONE-BUTTON] reboot по запросу"; reboot; }
    fi
}

# =====================================================
# ПОЛНАЯ ВЫЧИСТКА (откат всех модулей старой версии начисто)
# =====================================================
# Снимает ВСЁ, что мог поставить скрипт (старый и новый), включая legacy
# Traffic-Guard и его залежи. Цель — чистый старт перед новым накатом.
# Идемпотентно. НЕ трогает: твои ноды/remnanode, xray-конфиги, SSH-ключи.

cleanup_legacy() {
    print_header
    echo "╔══════════════════════════════════════════╗"
    echo "║   🧹 ПОЛНАЯ ВЫЧИСТКА (откат всего)       ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    echo "  Снесёт ВСЕ слои защиты/тюнинга, что ставил скрипт:"
    echo "    • Traffic-Guard (legacy) + SCANNERS-BLOCK + antiscan-таймеры"
    echo "    • CrowdSec + firewall-bouncer"
    echo "    • AS_Network_List (asn-blacklist)"
    echo "    • Threat-Intel (threat-block)"
    echo "    • Anti-DDoS vpsguard (nft) + fleet-sync"
    echo "    • Тюнинг ядра/сети (sysctl drop-in, vps-* юниты)"
    echo "    • GeoBlock (если стоит)"
    echo ""
    rn_warn "НЕ трогает: remnanode/ноды, xray-конфиги, SSH-ключи, swap."
    rn_warn "XanMod-ядро НЕ удаляется (нужен reboot для смены)."
    echo ""
    rn_error "Это вернёт фаервол к голому состоянию. Делай ПЕРЕД новым накатом."
    echo ""
    read -e -p "Точно вычистить всё? Введи 'WIPE' для подтверждения: " _w
    [[ "$_w" == "WIPE" ]] || { echo "Отменено."; return; }

    log "=== [CLEANUP] НАЧАЛО полной вычистки ==="
    echo ""

    # ── 1. Traffic-Guard (legacy) ──
    echo "── [1/8] Traffic-Guard (legacy) ──"
    systemctl stop antiscan-aggregate.timer antiscan-aggregate.service \
        antiscan-ipset-restore.service 2>/dev/null || true
    systemctl disable antiscan-aggregate.timer antiscan-aggregate.service \
        antiscan-ipset-restore.service 2>/dev/null || true
    iptables  -D INPUT -j SCANNERS-BLOCK 2>/dev/null || true
    ip6tables -D INPUT -j SCANNERS-BLOCK 2>/dev/null || true
    # снять из ufw-before-input если там
    iptables  -D ufw-before-input -j SCANNERS-BLOCK 2>/dev/null || true
    ip6tables -D ufw-before-input -j SCANNERS-BLOCK 2>/dev/null || true
    iptables  -F SCANNERS-BLOCK 2>/dev/null || true; iptables  -X SCANNERS-BLOCK 2>/dev/null || true
    ip6tables -F SCANNERS-BLOCK 2>/dev/null || true; ip6tables -X SCANNERS-BLOCK 2>/dev/null || true
    ipset destroy SCANNERS-BLOCK-V4 2>/dev/null || true
    ipset destroy SCANNERS-BLOCK-V6 2>/dev/null || true
    rm -f /usr/local/bin/traffic-guard /usr/local/bin/antiscan-aggregate-logs.sh
    rm -f /etc/systemd/system/antiscan-aggregate.service /etc/systemd/system/antiscan-aggregate.timer
    rm -f /etc/systemd/system/antiscan-ipset-restore.service
    rm -f /var/log/iptables-scanners-aggregate.csv
    echo "  ✓ Traffic-Guard вычищен"

    # ── 2. Threat-Intel ──
    echo "── [2/8] Threat-Intel блоклист ──"
    if declare -f tib_remove >/dev/null 2>&1; then
        echo "y" | tib_remove >/dev/null 2>&1 || true
    fi
    iptables  -D INPUT -m set --match-set threat-block-v4 src -m conntrack --ctstate NEW -j DROP 2>/dev/null || true
    ip6tables -D INPUT -m set --match-set threat-block-v6 src -m conntrack --ctstate NEW -j DROP 2>/dev/null || true
    ipset destroy threat-block-v4 2>/dev/null || true
    ipset destroy threat-block-v6 2>/dev/null || true
    crontab -l 2>/dev/null | grep -v threat-blocklist-update | crontab - 2>/dev/null || true
    rm -f /usr/local/bin/threat-blocklist-update.sh; rm -rf /etc/threat-blocklist
    echo "  ✓ Threat-Intel вычищен"

    # ── 3. AS_Network_List ──
    echo "── [3/8] AS_Network_List ──"
    iptables  -D INPUT -m set --match-set asn-blacklist-v4 src -m conntrack --ctstate NEW -j DROP 2>/dev/null || true
    ip6tables -D INPUT -m set --match-set asn-blacklist-v6 src -m conntrack --ctstate NEW -j DROP 2>/dev/null || true
    nft delete table inet as_blacklist 2>/dev/null || true
    ipset destroy asn-blacklist-v4 2>/dev/null || true
    ipset destroy asn-blacklist-v6 2>/dev/null || true
    ipset destroy asn-blacklist-v4-tmp 2>/dev/null || true
    ipset destroy asn-blacklist-v6-tmp 2>/dev/null || true
    # зомби-сеты от старого \b-sed бага (имя обрезалось до "asn-blacklist-") + имена из файла репо
    ipset destroy "asn-blacklist-" 2>/dev/null || true
    ipset destroy blacklist-v4 2>/dev/null || true
    ipset destroy blacklist-v6 2>/dev/null || true
    crontab -l 2>/dev/null | grep -v 'as-blacklist-update' | crontab - 2>/dev/null || true
    rm -f /usr/local/bin/as-blacklist-update.sh; rm -rf /etc/as-blacklist
    echo "  ✓ AS_Network_List вычищен"

    # ── 4. Anti-DDoS vpsguard ──
    echo "── [4/8] Anti-DDoS vpsguard ──"
    systemctl disable --now vpsguard-fleet-sync.timer 2>/dev/null || true
    systemctl stop vpsguard-fleet-sync.service vpsguard-safety.timer 2>/dev/null || true
    systemctl disable --now vpsguard-firewall.service 2>/dev/null || true
    nft delete table inet vpsguard 2>/dev/null || true
    rm -f /etc/systemd/system/vpsguard-firewall.service \
          /etc/systemd/system/vpsguard-fleet-sync.service \
          /etc/systemd/system/vpsguard-fleet-sync.timer
    rm -f /usr/local/sbin/vpsguard-status /usr/local/sbin/vpsguard-top /usr/local/sbin/vpsguard-fleet-sync
    rm -rf /etc/vpsguard /var/lib/vpsguard
    echo "  ✓ vpsguard вычищен"

    # ── 5. CrowdSec ──
    echo "── [5/8] CrowdSec ──"
    systemctl stop crowdsec crowdsec-firewall-bouncer 2>/dev/null || true
    systemctl disable crowdsec crowdsec-firewall-bouncer 2>/dev/null || true
    iptables  -D INPUT -j CROWDSEC_CHAIN 2>/dev/null || true
    iptables  -F CROWDSEC_CHAIN 2>/dev/null || true; iptables  -X CROWDSEC_CHAIN 2>/dev/null || true
    ip6tables -F CROWDSEC_CHAIN 2>/dev/null || true; ip6tables -X CROWDSEC_CHAIN 2>/dev/null || true
    for s in $(ipset list -n 2>/dev/null | grep -i crowdsec); do ipset destroy "$s" 2>/dev/null || true; done
    if command -v apt-get >/dev/null 2>&1; then
        apt-get purge -y crowdsec crowdsec-firewall-bouncer-iptables crowdsec-firewall-bouncer-nftables >/dev/null 2>&1 || true
    fi
    rm -rf /etc/crowdsec /var/lib/crowdsec
    echo "  ✓ CrowdSec вычищен"

    # ── 6. Тюнинг ядра/сети ──
    echo "── [6/8] Тюнинг ядра/сети ──"
    if declare -f kt_rollback >/dev/null 2>&1; then
        echo "y" | kt_rollback >/dev/null 2>&1 || true
    else
        for u in vps-rps vps-nic-tune vps-thp vps-governor vps-zram; do
            systemctl disable --now ${u}.service >/dev/null 2>&1 || true
            rm -f /etc/systemd/system/${u}.service
        done
        rm -f /usr/local/sbin/vps-rps-setup /usr/local/sbin/vps-zram-setup
        rm -f /etc/sysctl.d/99-vps-tune.conf /etc/sysctl.d/99-vps-tune-conntrack.conf
    fi
    echo "  ✓ Тюнинг откатан (XanMod-ядро остаётся до reboot на сток)"

    # ── 7. GeoBlock ──
    echo "── [7/8] GeoBlock ──"
    iptables  -D ufw-before-input -j GEO-BLOCK 2>/dev/null || true
    ip6tables -D ufw-before-input -j GEO-BLOCK 2>/dev/null || true
    iptables  -D INPUT -j GEO-BLOCK 2>/dev/null || true
    ip6tables -D INPUT -j GEO-BLOCK 2>/dev/null || true
    iptables  -F GEO-BLOCK 2>/dev/null || true; iptables  -X GEO-BLOCK 2>/dev/null || true
    ip6tables -F GEO-BLOCK 2>/dev/null || true; ip6tables -X GEO-BLOCK 2>/dev/null || true
    for s in $(ipset list -n 2>/dev/null | grep -iE 'geo'); do ipset destroy "$s" 2>/dev/null || true; done
    crontab -l 2>/dev/null | grep -v 'geoblock' | crontab - 2>/dev/null || true
    echo "  ✓ GeoBlock вычищен (если был)"

    # ── 8. Сохранение чистого состояния ──
    echo "── [8/8] Финализация ──"
    # снять юнит восстановления ipset + почистить сохранёнку
    systemctl disable --now ipset-persistent.service 2>/dev/null || true
    rm -f /etc/systemd/system/ipset-persistent.service
    rm -f /usr/local/sbin/fw-restore.sh
    rm -f /etc/ipset.conf
    systemctl daemon-reload 2>/dev/null || true
    if [ -d /etc/iptables ]; then
        iptables-save  > /etc/iptables/rules.v4 2>/dev/null || true
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    fi
    ipset save > /etc/ipset.conf 2>/dev/null || true  # пустое состояние, чтобы не грузить старое
    nft list ruleset >/dev/null 2>&1 || true
    echo "  ✓ Чистое состояние сохранено"

    log "=== [CLEANUP] КОНЕЦ полной вычистки ==="
    echo ""
    rn_success "Вычистка завершена. Фаервол в голом состоянии."
    rn_info "Теперь можно ставить начисто: пункт 0 (одна кнопка) или модули по отдельности."
    echo ""
    echo "  Проверка чистоты:"
    echo "    ipset list -n            (не должно быть asn/threat/SCANNERS/crowdsec)"
    echo "    nft list ruleset | grep -c vpsguard   (должно быть 0)"
    echo "    iptables -S INPUT        (только ufw-* и базовое)"
}

# =====================================
# БЕЗОПАСНЫЙ ТЕСТ CROWDSEC: preflight / install + полное логирование
# =====================================
cs_test_snapshot() {
    local dir="$1" phase="$2"
    mkdir -p "$dir/$phase" || return 1
    { date -Is; uname -a; cat /etc/os-release; } > "$dir/$phase/system.txt" 2>&1 || true
    { ss -ltnp; systemctl is-active ssh; } > "$dir/$phase/ssh.txt" 2>&1 || true
    ufw status verbose > "$dir/$phase/ufw.txt" 2>&1 || true
    iptables-save > "$dir/$phase/iptables-v4.rules" 2>&1 || true
    ip6tables-save > "$dir/$phase/iptables-v6.rules" 2>&1 || true
    ipset save > "$dir/$phase/ipset.rules" 2>&1 || true
    nft list ruleset > "$dir/$phase/nft-ruleset.txt" 2>&1 || true
    { dpkg-query -W crowdsec crowdsec-firewall-bouncer-iptables ipset 2>&1 || true; } > "$dir/$phase/packages.txt"
}
cs_test_preflight() {
    local failures=0 pkg
    echo "===== CROWDSEC TEST PREFLIGHT ====="
    if (( EUID != 0 )); then echo "FAIL: требуется root"; failures=$((failures+1)); fi
    if ! bash -n "${BASH_SOURCE[0]}"; then echo "FAIL: bash syntax"; failures=$((failures+1)); fi
    if ! systemctl is-active --quiet ssh; then echo "FAIL: SSH неактивен"; failures=$((failures+1)); fi
    if ! ss -ltn | grep -Eq ':62152[[:space:]]'; then echo "FAIL: SSH :62152 не слушает"; failures=$((failures+1)); fi
    if ! command -v curl >/dev/null; then echo "FAIL: curl отсутствует"; failures=$((failures+1)); fi
    for pkg in crowdsec crowdsec-firewall-bouncer-iptables; do
        if ! apt-cache policy "$pkg" | grep -Eq 'Candidate: [^ (]+$'; then
            echo "FAIL: недоступен пакет $pkg"; failures=$((failures+1))
        fi
    done
    if ! apt-get -s install --no-remove crowdsec crowdsec-firewall-bouncer-iptables ipset > /dev/null; then
        echo "FAIL: APT simulation"; failures=$((failures+1))
    fi
    if ! curl -fsSL --connect-timeout 6 --max-time 15 -o /dev/null https://hub.crowdsec.net/; then
        echo "FAIL: CrowdSec Hub недоступен"; failures=$((failures+1))
    fi
    if ! command -v iptables-save >/dev/null || ! command -v ipset >/dev/null; then
        echo "FAIL: отсутствуют инструменты firewall"; failures=$((failures+1))
    fi
    if (( failures )); then echo "PREFLIGHT FAIL: $failures"; return 1; fi
    echo "PREFLIGHT PASS"
}
cs_test_run() {
    local mode="$1" dir rc=0
    dir="/root/crowdsec-test-$(date +%Y%m%d-%H%M%S)-$$"
    mkdir -p "$dir" || return 1
    chmod 700 "$dir"
    exec > >(tee -a "$dir/run.log") 2>&1
    echo "TEST_LOG_DIR=$dir"
    echo "MODE=$mode DATE=$(date -Is)"
    cs_test_snapshot "$dir" before
    if ! cs_test_preflight; then
        echo "TEST ABORTED: preflight failed; install not started"
        return 1
    fi
    if [[ "$mode" == dry ]]; then
        echo "DRY RUN PASS: проверены предпосылки, установка не выполнялась"
        return 0
    fi
    echo "Будут установлены CrowdSec и bouncer; пакет bouncer изменит iptables/ipset."
    echo "Это не атомарная операция и не гарантирует сохранения SSH при любых сбоях."
    local answer
    read -r -e -p "Введите INSTALL-CROWDSEC для запуска на тестовом VPS: " answer
    if [[ "$answer" != INSTALL-CROWDSEC ]]; then
        echo "CANCELLED"; return 0
    fi
    echo "===== INSTALL START $(date -Is) ====="
    crowdsec_install || rc=$?
    echo "===== INSTALL END rc=$rc $(date -Is) ====="
    cs_test_snapshot "$dir" after
    systemctl status crowdsec crowdsec-firewall-bouncer --no-pager -l > "$dir/services.txt" 2>&1 || true
    journalctl -u crowdsec -u crowdsec-firewall-bouncer --since '-30 min' --no-pager -n 250 > "$dir/journal.txt" 2>&1 || true
    cscli bouncers list > "$dir/bouncers.txt" 2>&1 || true
    cscli collections list > "$dir/collections.txt" 2>&1 || true
    cscli metrics > "$dir/metrics.txt" 2>&1 || true
    echo "RESULT_RC=$rc"
    echo "TEST_LOG_DIR=$dir"
    return "$rc"
}
if [[ ${1:-} == --dry-run-crowdsec ]]; then
    cs_test_run dry
    exit $?
elif [[ ${1:-} == --test-crowdsec ]]; then
    cs_test_run install
    exit $?
fi

# Optional C2 IP:port feed, independent of CrowdSec and existing firewall.
# Self-contained C2 module: works with a private GitHub repo and without a second token.
# The single-file launcher must not try to access private Contents after unset TOKEN.
xtls_c2_write_embedded_module() {
    cat <<'XTLS_C2_EMBEDDED_MODULE_END_2026'
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
XTLS_C2_EMBEDDED_MODULE_END_2026
}

setup_c2_feed() {
    local file choice rc=0
    file=$(mktemp /tmp/xtls-c2-menu.XXXXXX.sh) || return 1
    chmod 600 "$file"
    if ! xtls_c2_write_embedded_module > "$file" || ! bash -n "$file"; then
        rm -f "$file"
        echo "Ошибка проверки встроенного C2-модуля"
        return 1
    fi
    echo "  1) Установить / обновить и включить C2-блокировку TCP"
    echo "  2) Статус"
    echo "  3) Обновить IP:port сейчас"
    echo "  4) Включить блокировку TCP"
    echo "  5) Отключить блокировку TCP"
    echo "  0) Назад"
    read -e -r -p "Выбор: " choice
    case "$choice" in
        1)
            if bash "$file" install; then
                if [[ "$(cat /etc/xtls-c2-feed/mode 2>/dev/null)" == block ]] &&
                   nft list chain ip xtls_c2_feed output 2>/dev/null | grep -q 'xtls-c2-block'; then
                    echo "C2 Anti-Abuse: блокировка уже активна."
                else
                    # Automatic enable specifically requested by menu item 1.
                    # The embedded module asks for a confirmation phrase; provide it non-interactively.
                    printf 'ENABLE-C2-BLOCK\n' | bash "$file" enable-block || rc=$?
                fi
            else
                rc=$?
            fi
            ;;
        2) bash "$file" status || rc=$? ;;
        3) bash "$file" update || rc=$? ;;
        4) bash "$file" enable-block || rc=$? ;;
        5) bash "$file" disable-block || rc=$? ;;
        0) ;;
        *) echo "Неверный выбор" ;;
    esac
    rm -f "$file"
    return "$rc"
}

# Independent UDP monitor; no DROP and no unverified C2 port copying.
xtls_udp_write_embedded_module() {
cat <<'XTLS_UDP_EMBEDDED_END'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
TABLE=xtls_udp_abuse
ROOT=/etc/xtls-udp-abuse
CSV="$ROOT/confirmed-udp.csv"
prepare() {
  nft list table ip "$TABLE" >/dev/null 2>&1 || nft add table ip "$TABLE"
  nft list set ip "$TABLE" udp_pairs >/dev/null 2>&1 || nft 'add set ip xtls_udp_abuse udp_pairs { type ipv4_addr . inet_service; }'
  nft list chain ip "$TABLE" output >/dev/null 2>&1 || nft 'add chain ip xtls_udp_abuse output { type filter hook output priority -19; policy accept; }'
  if ! nft list chain ip "$TABLE" output | grep -q 'xtls-udp-observe'; then
     nft add rule ip "$TABLE" output meta l4proto udp counter comment '"xtls-udp-observe"'
  fi
  if ! nft list chain ip "$TABLE" output | grep -q 'xtls-udp-matches'; then
     nft add rule ip "$TABLE" output ip daddr . udp dport @udp_pairs counter comment '"xtls-udp-matches"'
  fi
}
load() {
  local tmp count
  [[ -f "$CSV" ]] || { echo 'No confirmed UDP feed; monitoring only'; return 0; }
  tmp=$(mktemp -d)
  python3 - "$CSV" "$tmp/batch" <<'PY' || { rm -rf "$tmp"; return 1; }
import csv,ipaddress,pathlib,sys
src=pathlib.Path(sys.argv[1])
out=pathlib.Path(sys.argv[2])
pairs=set()
with src.open(newline='') as f:
    for n,row in enumerate(csv.reader(f),1):
        if not row or row[0].strip().startswith('#'): continue
        if len(row)<3 or row[2].strip().lower()!='udp': raise ValueError(f'Line {n}: require IP,port,udp')
        ip=ipaddress.ip_address(row[0].strip())
        port=int(row[1].strip())
        if ip.version!=4 or not ip.is_global or not 1<=port<=65535: raise ValueError(f'Line {n}: invalid address or port')
        pairs.add((str(ip),port))
if len(pairs)>50000:raise ValueError('Too many entries')
with out.open('w') as f:
    f.write('flush set ip xtls_udp_abuse udp_pairs\n')
    if pairs:
        f.write('add element ip xtls_udp_abuse udp_pairs { '+', '.join(f'{ip} . {port}' for ip,port in sorted(pairs))+' }\n')
print('Confirmed UDP pairs:',len(pairs))
PY
  if [[ ! -s "$tmp/batch" ]] || ! nft -c -f "$tmp/batch"; then rm -rf "$tmp"; return 1; fi
  nft -f "$tmp/batch"
  rm -rf "$tmp"
}
status() {
  echo 'UDP monitoring:'
  nft -a list chain ip "$TABLE" output 2>/dev/null || echo 'not installed'
  if [[ -f "$CSV" ]];then wc -l "$CSV";else echo 'Confirmed feed: none';fi
}
install_module() {
  install -d -m 700 "$ROOT"
  prepare
  load
  if [[ -f "$ROOT/mode" && $(cat "$ROOT/mode") == block && -s "$CSV" ]]; then enable_block; fi
  install -m 755 "$0" /usr/local/sbin/xtls-udp-abuse
  cat > /etc/systemd/system/xtls-udp-abuse-restore.service <<'UNIT'
[Unit]
Description=Restore xtlsproVPN UDP abuse monitoring
After=local-fs.target
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xtls-udp-abuse restore
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable xtls-udp-abuse-restore.service
  echo 'UDP monitoring installed; blocking disabled'
}
restore() { prepare; load; if [[ -f "$ROOT/mode" && $(cat "$ROOT/mode") == block && -s "$CSV" ]]; then enable_block; fi; }
udp_drop_handle() {
 nft -a list chain ip "$TABLE" output 2>/dev/null | awk '/comment "xtls-udp-block"/ {for(i=1;i<=NF;i++) if($i=="handle") {print $(i+1); exit}}'
}
enable_block() {
  install -d -m 700 "$ROOT"
  [[ -s "$CSV" ]] || { echo 'Нет подтверждённых UDP IP:port; DROP не включён'; return 1; }
  prepare
  load || return 1
  local h
  h=$(udp_drop_handle)
  [[ -n "$h" ]] || nft add rule ip "$TABLE" output ip daddr . udp dport @udp_pairs counter drop comment '"xtls-udp-block"'
  printf '%s\n' block > "$ROOT/mode"
  echo 'UDP DROP active'
}
disable_block() {
  local h
  printf '%s\n' observe > "$ROOT/mode"
  while :; do
    h=$(udp_drop_handle)
    [[ -n "$h" ]] || break
    nft delete rule ip "$TABLE" output handle "$h"
  done
  echo 'UDP DROP disabled'
}
[[ $(id -u) == 0 ]] || { echo 'Run as root' >&2; exit 1; }
case "${1:-}" in
  install) install_module;;
  restore) restore;;
  status) status;;
  enable-block) enable_block;;
  disable-block) disable_block;;
  *) echo 'Usage: xtls-udp-abuse {install|restore|status}' >&2;exit 2;;
esac
XTLS_UDP_EMBEDDED_END
}
setup_udp_abuse() {
    local f choice rc=0
    f=$(mktemp /tmp/xtls-udp.XXXXXX.sh) || return 1
    chmod 600 "$f"
    xtls_udp_write_embedded_module > "$f"
    if ! bash -n "$f"; then rm -f "$f"; return 1; fi
    echo "  1) Установить UDP-наблюдение (без DROP)"
    echo "  2) Статус и счётчики"
    echo "  3) Перезагрузить подтверждённый UDP CSV"
    echo "  4) Включить UDP DROP (только подтверждённые IP:port)"
    echo "  5) Отключить UDP DROP"
    echo "  0) Назад"
    read -e -r -p "Выбор: " choice
    case "$choice" in
      1) bash "$f" install || rc=$? ;;
      2) bash "$f" status || rc=$? ;;
      3) if [[ -x /usr/local/sbin/xtls-udp-abuse ]]; then /usr/local/sbin/xtls-udp-abuse restore || rc=$?; else echo "Сначала установите"; fi ;;
      4) bash "$f" enable-block || rc=$? ;;
      5) bash "$f" disable-block || rc=$? ;;
      0) ;;
      *) echo 'Неверный выбор' ;;
    esac
    rm -f "$f"
    return "$rc"
}

# Unified management only: no migration or firewall changes.
xtls_spamhaus_out_write_module() {
    cat <<'XTLS_SPAMHAUS_OUTPUT_MODULE_END'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT=/etc/xtls-spamhaus-output
TABLE=xtls_spamhaus_out
LOCK=/run/xtls-spamhaus-output.lock
URL4=https://www.spamhaus.org/drop/drop_v4.json
URL6=https://www.spamhaus.org/drop/drop_v6.json

# Keep the oldest counter for each exact owned marker. Duplicates count the
# same packet, so summing them would inflate telemetry. Never replace DROP/logs.
ensure_counters() (
  local d
  d=$(mktemp -d /tmp/xtls-spamhaus-counters.XXXXXXXX)
  trap 'rm -rf "$d"' EXIT
  nft -j -a list chain inet "$TABLE" output > "$d/chain.json"
  python3 - "$d/chain.json" > "$d/batch" <<'PY_COUNTERS'
import json,sys
rows=[item['rule'] for item in json.load(open(sys.argv[1]))['nftables'] if 'rule' in item]
for version in (4,6):
    marker=f'xtls-sh-out-v{version}'
    owned=[row for row in rows if row.get('comment')==marker]
    if not owned:
        family='ip' if version==4 else 'ip6'
        print(f'add rule inet xtls_spamhaus_out output {family} daddr @v{version} counter comment "{marker}"')
    for row in owned[1:]:
        handle=row['handle']
        if type(handle) is not int or handle<0: raise ValueError('Invalid nft rule handle')
        print(f'delete rule inet xtls_spamhaus_out output handle {handle}')
PY_COUNTERS
  if [[ -s "$d/batch" ]]; then
    nft -c -f "$d/batch"
    nft -f "$d/batch"
  fi
)

prepare() {
  nft list table inet "$TABLE" >/dev/null 2>&1 || nft add table inet "$TABLE"
  nft list set inet "$TABLE" v4 >/dev/null 2>&1 || nft 'add set inet xtls_spamhaus_out v4 { type ipv4_addr; flags interval; auto-merge; }'
  nft list set inet "$TABLE" v6 >/dev/null 2>&1 || nft 'add set inet xtls_spamhaus_out v6 { type ipv6_addr; flags interval; auto-merge; }'
  nft list chain inet "$TABLE" output >/dev/null 2>&1 || nft 'add chain inet xtls_spamhaus_out output { type filter hook output priority -18; policy accept; }'
  ensure_counters
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
  echo "Spamhaus destination sets updated; existing filtering rules and UDP mode unchanged"
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
diagnostics_enable() (
  install -d -m 700 "$ROOT"
  exec 9>"$LOCK"
  flock -x 9
  prepare
  local d
  d=$(mktemp -d /tmp/xtls-spamhaus-diag.XXXXXXXX)
  trap 'rm -rf "$d"' EXIT
  # Replace only our exact diagnostic markers, including legacy duplicates.
  # One nft transaction preserves the old rules if validation/apply fails.
  nft -j -a list chain inet "$TABLE" output > "$d/rules.json"
  python3 - "$d/rules.json" > "$d/batch" <<'PY'
import json,sys
markers={'xtls-sh-diag-v4','xtls-sh-diag-v6'}
for item in json.load(open(sys.argv[1]))['nftables']:
    rule=item.get('rule',{})
    if rule.get('comment') in markers:
        handle=rule['handle']
        if type(handle) is not int or handle < 0: raise ValueError('invalid rule handle')
        print(f'delete rule inet xtls_spamhaus_out output handle {handle}')
for version,family in [(4,'ip'),(6,'ip6')]:
    print(f'add rule inet xtls_spamhaus_out output ct direction original {family} daddr @v{version} limit rate 2/minute burst 5 packets log prefix "XTLS-SH{version} " level notice comment "xtls-sh-diag-v{version}"')
PY
  nft -c -f "$d/batch"
  nft -f "$d/batch"
  printf '%s\n' enabled > "$ROOT/diagnostics-mode"
  echo "Spamhaus original-direction logging enabled (2/minute per family, burst 5); filtering rules unchanged"
)
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
LIMIT_ACCESS=100000
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
XTLS_SPAMHAUS_OUTPUT_MODULE_END
}
spamhaus_udp_require_installed() {
    local target=/usr/local/sbin/xtls-spamhaus-udp
    [[ -f "$target" && ! -L "$target" ]] || { echo 'Сначала установите UDP-расширение'; return 1; }
    printf '%s  %s\n' 3a9a538570385684e01514cb38f48937870780dae7f593983b3f6b6b55479f5a "$target" |
        sha256sum -c --status || { echo 'Неизвестная версия UDP-модуля: требуется ручная проверка'; return 1; }
}

spamhaus_udp_install() (
    set -euo pipefail
    umask 077
    local target=/usr/local/sbin/xtls-spamhaus-udp
    local unit=/etc/systemd/system/xtls-spamhaus-udp-restore.service
    local config=/etc/xtls-spamhaus-udp work path
    local base=https://raw.githubusercontent.com/djing1e/universal-vps-setup/0dbef9a93c7b9ff109bd584856e45dbe2807419e/modules
    nft list chain inet xtls_spamhaus_out output >/dev/null || return 1
    [[ "$(systemctl show --value --property=LoadState xtls-spamhaus-output-restore.service)" == loaded ]] || {
        echo 'Сначала установите Spamhaus OUTPUT Observe'; return 1;
    }
    [[ ! -L "$config" ]] || { echo 'Каталог UDP — symlink; требуется ручная проверка'; return 1; }
    for path in "$target" "$unit"; do
        [[ ! -L "$path" ]] || { echo "Symlink: $path; требуется ручная проверка"; return 1; }
    done
    work=$(mktemp -d /tmp/xtls-spamhaus-udp-install.XXXXXX) || return 1
    trap 'rm -rf "$work"' EXIT
    curl -fsSL --connect-timeout 10 --max-time 60 "$base/xtls-spamhaus-udp.py" -o "$work/module.py" || return 1
    curl -fsSL --connect-timeout 10 --max-time 60 "$base/xtls-spamhaus-udp-restore.service" -o "$work/xtls-spamhaus-udp-restore.service" || return 1
    printf '%s  %s\n' \
        3a9a538570385684e01514cb38f48937870780dae7f593983b3f6b6b55479f5a "$work/module.py" \
        2395eb59df4a071216290710407605053493f6201933b35a6c0884194f078d3e "$work/xtls-spamhaus-udp-restore.service" | sha256sum -c - || return 1
    python3 -c 'import sys; compile(open(sys.argv[1], "rb").read(), sys.argv[1], "exec")' "$work/module.py" || return 1
    [[ ! -e "$target" ]] || cmp -s "$target" "$work/module.py" || { echo 'Неизвестный установленный UDP-модуль; замена отменена'; return 1; }
    [[ ! -e "$unit" ]] || cmp -s "$unit" "$work/xtls-spamhaus-udp-restore.service" || { echo 'Нестандартный UDP unit; замена отменена'; return 1; }
    systemd-analyze verify "$work/xtls-spamhaus-udp-restore.service" || return 1
    install -d -m 700 "$config" || return 1
    if [[ ! -e "$target" ]]; then install -m 755 "$work/module.py" "$target" || return 1; fi
    if [[ ! -e "$unit" ]]; then install -m 644 "$work/xtls-spamhaus-udp-restore.service" "$unit" || return 1; fi
    systemctl daemon-reload || return 1
    # Fresh installations restore observe; existing explicit block is preserved.
    systemctl enable --now xtls-spamhaus-udp-restore.service || return 1
    echo 'UDP-расширение установлено. Существующие режим и исключения сохранены.'
    if [[ ! -f "$config/exemptions.txt" ]]; then
        echo 'Перед включением DROP задайте исключения через пункт 4 этого подменю.'
    fi
)

spamhaus_udp_exemptions() (
    set -euo pipefail
    local config=/etc/xtls-spamhaus-udp entries work
    [[ ! -L "$config" && ! -L "$config/exemptions.txt" && ! -L "$config/mode" ]] || {
        echo 'Symlink в конфигурации UDP; требуется ручная проверка'; return 1;
    }
    [[ "$(cat "$config/mode" 2>/dev/null || echo observe)" == observe ]] || {
        echo 'Сначала отключите UDP DROP; активные исключения автоматически не меняются'; return 1;
    }
    echo 'IP/CIDR через пробел или запятую; NONE — явно без исключений.'
    echo 'Укажите необходимые адреса панели, входных нод и других сервисов.'
    read -e -r -p 'Исключения: ' entries || return 1
    [[ -n "$entries" ]] || { echo 'Отменено'; return 0; }
    work=$(mktemp /tmp/xtls-spamhaus-udp-exempt.XXXXXX) || return 1
    trap 'rm -f "$work"' EXIT
    python3 - "$entries" > "$work" <<'PY' || return 1
import ipaddress,sys
raw=sys.argv[1]
if raw=='NONE':
    print('# Explicitly reviewed empty exemption list')
else:
    nets=set()
    for value in raw.replace(',', ' ').split():
        net=ipaddress.ip_network(value,strict=False)
        if net.prefixlen==0: raise ValueError('/0 exemption is not allowed')
        nets.add(str(net))
    for net in sorted(nets): print(net)
PY
    install -d -m 700 "$config" || return 1
    # Only change exemptions while observe, under the same lock as the module.
    exec 9>/run/xtls-spamhaus-udp.lock
    flock -x 9 || return 1
    [[ "$(cat "$config/mode" 2>/dev/null || echo observe)" == observe ]] || { echo 'Режим изменился; сохранение отменено'; return 1; }
    if [[ -e "$config/exemptions.txt" ]]; then
        cp -p "$config/exemptions.txt" "$config/exemptions.txt.bak-$(date +%Y%m%d-%H%M%S)" || return 1
    fi
    install -m 600 "$work" "$config/.exemptions.new" || return 1
    mv -f "$config/.exemptions.new" "$config/exemptions.txt" || return 1
    echo 'Исключения сохранены; UDP DROP не включён.'
)


spamhaus_udp_enable() {
    local answer mode
    spamhaus_udp_require_installed || return 1
    mode=$(cat /etc/xtls-spamhaus-udp/mode 2>/dev/null || echo observe)
    if [[ "$mode" == block ]]; then
        echo 'Block уже сохранён. Проверьте статус; новый таймер не создаётся.'
        /usr/bin/python3 /usr/local/sbin/xtls-spamhaus-udp status
        return
    fi
    [[ "$mode" == observe ]] || { echo 'Неизвестный режим; требуется ручная проверка'; return 1; }
    [[ -f /etc/xtls-spamhaus-udp/exemptions.txt ]] || { echo 'Сначала задайте исключения через пункт 4'; return 1; }
    echo 'UDP к сетям Spamhaus будет заблокирован. Через 5 минут сработает автоотключение.'
    read -e -r -p 'Введите ENABLE-SPAMHAUS-UDP-DROP: ' answer || return 1
    [[ "$answer" == ENABLE-SPAMHAUS-UDP-DROP ]] || { echo 'Отменено'; return 0; }
    systemd-run --collect --unit=xtls-sh-udp-safety --on-active=5m --timer-property=AccuracySec=1s --timer-property=RemainAfterElapse=no \
        /usr/bin/python3 /usr/local/sbin/xtls-spamhaus-udp disable-block || return 1
    /usr/bin/python3 /usr/local/sbin/xtls-spamhaus-udp enable-block || {
        echo 'Включение не завершено; защитный таймер оставлен для возврата в Observe'; return 1;
    }
    echo 'Проверьте SSH, VPN и UDP-приложения. Затем пункт 6 отменит автоотключение.'
}

spamhaus_udp_keep() {
    local answer
    spamhaus_udp_require_installed || return 1
    [[ "$(cat /etc/xtls-spamhaus-udp/mode 2>/dev/null || true)" == block ]] || {
        echo 'Block не сохранён: возможно, автоотключение уже сработало. DROP не включается.'; return 1;
    }
    read -e -r -p 'Если SSH/VPN/UDP работают, введите KEEP-UDP-DROP: ' answer || return 1
    [[ "$answer" == KEEP-UDP-DROP ]] || { echo 'Защитный таймер оставлен'; return 0; }
    if systemctl is-active --quiet xtls-sh-udp-safety.timer; then
        systemctl stop xtls-sh-udp-safety.timer || return 1
        echo 'Таймер автоотключения остановлен. Текущий режим:'
    else
        echo 'Активного таймера автоотключения нет. Текущий режим:'
    fi
    /usr/bin/python3 /usr/local/sbin/xtls-spamhaus-udp status
}

setup_spamhaus_udp_drop() {
    local choice
    while true; do
        echo '=== UDP DROP по сетям Spamhaus ==='
        echo '1) Статус и счётчики'
        echo '2) Включить DROP (с автоотключением через 5 минут)'
        echo '3) Отключить DROP'
        echo '4) Исключения: разрешённые адреса (при Observe)'
        echo '6) Доступ проверен: оставить DROP включённым'
        echo '9) Установка / проверка расширения'
        echo '0) Назад'
        read -e -r -p 'Выбор [1-4, 6, 9 / 0]: ' choice || return 0
        case "$choice" in
            1) if spamhaus_udp_require_installed; then /usr/bin/python3 /usr/local/sbin/xtls-spamhaus-udp status || echo 'Не удалось прочитать UDP-статус'; fi ;;
            2) spamhaus_udp_enable || echo 'Проверьте статус и защитный таймер' ;;
            3) if spamhaus_udp_require_installed; then /usr/bin/python3 /usr/local/sbin/xtls-spamhaus-udp disable-block || echo 'Отключение не подтверждено; проверьте статус'; fi ;;
            4) spamhaus_udp_exemptions || echo 'Исключения не изменены' ;;
            6) spamhaus_udp_keep || echo 'Подтверждение не завершено' ;;
            9) spamhaus_udp_install || echo 'Установка не завершена' ;;
            0) return 0 ;;
            *) echo 'Неверный выбор' ;;
        esac
    done
}

spamhaus_output_summary() {
    local version file
    echo '===== SPAMHAUS OUTPUT ====='
    for version in 4 6; do
        file="/etc/xtls-spamhaus-output/cidr$version"
        if [[ -f "$file" ]]; then printf 'Cached IPv%s CIDRs: %s\n' "$version" "$(wc -l < "$file")"; fi
    done
    printf 'Last successful update: %s\n' "$(cat /etc/xtls-spamhaus-output/last-success 2>/dev/null || echo unknown)"
    nft -a list chain inet xtls_spamhaus_out output || return 1
    if [[ -f /usr/local/sbin/xtls-spamhaus-udp ]]; then
        if spamhaus_udp_require_installed; then /usr/bin/python3 /usr/local/sbin/xtls-spamhaus-udp status; fi
    else
        echo 'Spamhaus UDP DROP extension: not installed'
    fi
}

setup_spamhaus_out_observe() {
    local f choice rc=0
    f=$(mktemp /tmp/xtls-spamhaus-out.XXXXXX.sh) || return 1
    chmod 700 "$f"
    xtls_spamhaus_out_write_module > "$f"
    if ! bash -n "$f"; then rm -f "$f"; return 1; fi
    while true; do
        rc=0
        echo "=== Spamhaus: сети и журнал совпадений ==="
        echo "Журналирование не меняет режим UDP DROP (управление: 16 → 3)."
        echo "1) Установить / обновить Spamhaus OUTPUT (режим UDP сохраняется)"
        echo "2) Обновить фид сейчас"
        echo "3) Статус и счётчики"
        echo "4) Включить ограниченное журналирование совпадений"
        echo "5) Отключить журналирование"
        echo "6) Последние события (2 часа)"
        echo "7) Отчёт: Spamhaus + Remnanode (по запросу)"
        echo "0) Назад"
        read -e -r -p "Выбор [0-7]: " choice || break
        case "$choice" in
            1) bash "$f" install || rc=$? ;;
            2) if [[ -x /usr/local/sbin/xtls-spamhaus-output ]]; then /usr/local/sbin/xtls-spamhaus-output update || rc=$?; else echo "Сначала установите"; rc=1; fi ;;
            3) spamhaus_output_summary || rc=$? ;;
            4) bash "$f" diagnostics-enable || rc=$? ;;
            5) bash "$f" diagnostics-disable || rc=$? ;;
            6) bash "$f" diagnostics-show || rc=$? ;;
            7) bash "$f" diagnostics-report || rc=$? ;;
            0) break ;;
            *) echo "Неверный выбор" ;;
        esac
        if (( rc != 0 )); then echo "Действие завершилось с ошибкой ($rc); проверьте статус."; fi
    done
    rm -f "$f"
    return 0
}

guard_engine_menu_action() (
    local action=${1:-} work base status answer
    case "$action" in check|apply) ;; *) echo 'Неизвестное действие обновления Guard'; return 1 ;; esac
    umask 077
    command -v python3 >/dev/null || { echo 'Требуется Python 3'; return 1; }
    work=$(mktemp -d /tmp/xtls-guard-upgrade.XXXXXX) || return 1
    trap 'rm -rf "$work"' EXIT
    base=https://raw.githubusercontent.com/djing1e/universal-vps-setup/6973b97f4a172aa99b87527af28ce92b57159f92
    curl -fsSL --connect-timeout 10 --max-time 60 "$base/lib/guard_engine_upgrade.py" -o "$work/guard_engine_upgrade.py" || return 1
    curl -fsSL --connect-timeout 10 --max-time 60 "$base/lib/guard_engine_policy.json" -o "$work/guard_engine_policy.json" || return 1
    curl -fsSL --connect-timeout 10 --max-time 60 "$base/lib/vps_inventory.py" -o "$work/vps_inventory.py" || return 1
    curl -fsSL --connect-timeout 10 --max-time 60 "$base/modules/xtls-auto-abuse-guard.py" -o "$work/candidate.py" || return 1
    printf '%s  %s\n' \
        2b446ae307a76b87f18f577919841779981c6f131d73bec47b9aa2f4aa25726d "$work/guard_engine_upgrade.py" \
        3f87a241f4f4aa5b309bc2354e9c22ec192772deffac4df083facb6c464ba5ec "$work/guard_engine_policy.json" \
        a182c62db4cd8fd6f6e364d992d468ce2a2647724acf0e7444de41c205824ed9 "$work/vps_inventory.py" \
        f9eb32909626917a708a66907df0debf7cfc1943e626e7974e03e697996bcd03 "$work/candidate.py" | sha256sum -c - || return 1
    echo '===== ПРОВЕРКА ОБНОВЛЕНИЯ GUARD (без замены и запусков) ====='
    PYTHONDONTWRITEBYTECODE=1 python3 "$work/guard_engine_upgrade.py" check --candidate "$work/candidate.py" > "$work/check.json" || return 1
    cat "$work/check.json"
    status=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$work/check.json") || return 1
    case "$status" in
        noop) echo 'Движок Guard уже актуален. Замена и перезапуск не требуются.'; return 0 ;;
        ready_for_explicit_apply) ;;
        *) echo 'Проверка не разрешила обновление'; return 1 ;;
    esac
    if [[ "$action" == check ]]; then
        echo 'Доступно обновление движка. Для применения выберите пункт 6.'
        return 0
    fi
    echo 'Будет обновлён только движок Guard с резервной копией и откатом при ошибке.'
    echo 'Активный Guard временно остановится для замены и проверки. Неактивный останется неактивным.'
    read -e -r -p 'Для обновления введите UPDATE-GUARD-ENGINE: ' answer || return 0
    [[ "$answer" == UPDATE-GUARD-ENGINE ]] || { echo 'Обновление отменено'; return 0; }
    PYTHONDONTWRITEBYTECODE=1 python3 "$work/guard_engine_upgrade.py" apply --candidate "$work/candidate.py" --confirm UPDATE-GUARD-ENGINE || return 1
)

setup_auto_abuse_guard() {
    local choice installer
    installer=$(mktemp /tmp/xtls-auto-guard.XXXXXX.sh) || return 1
    chmod 700 "$installer"
    if ! curl -fsSL --connect-timeout 10 --max-time 40 "https://raw.githubusercontent.com/djing1e/universal-vps-setup/b9d57bc8f252422ac6c51a7a9fc33e7407c18b9d/modules/xtls-auto-abuse-guard-install.sh" -o "$installer"; then
        rm -f "$installer"
        echo "Не удалось загрузить установщик Auto Abuse Guard"
        return 1
    fi
    if ! bash -n "$installer"; then rm -f "$installer"; return 1; fi
    while true; do
        echo "=== Auto Abuse Guard (только Observe, без блокировок) ==="
        echo "1) Установить / включить таймер"
        echo "2) Статус / последние наблюдения"
        echo "3) Проверить сейчас: Spamhaus + поведение подписок"
        echo "4) Отключить и удалить сервис (логи сохранить)"
        echo "5) Проверить обновление движка (без изменений)"
        echo "6) Обновить движок: резервная копия и откат"
        echo "0) Назад"
        read -e -r -p "Выбор: " choice || break
        case "$choice" in
            1) bash "$installer" install ;;
            2) bash "$installer" status ;;
            3) if [[ -x /usr/local/sbin/xtls-auto-abuse-guard ]]; then
                   if systemctl start xtls-auto-abuse-guard.service; then
                       echo "Проверка завершена. Последний результат:"
                       systemctl show xtls-auto-abuse-guard.service --no-pager -p Result -p ExecMainStatus
                       journalctl -u xtls-auto-abuse-guard.service -n 8 --no-pager -o cat
                   else
                       echo "Проверка не завершена; проверьте журнал службы."
                   fi
               else echo "Сначала установите модуль"; fi ;;
            4) bash "$installer" remove ;;
            5) guard_engine_menu_action check || echo "Проверка не завершена; изменения не применялись" ;;
            6) guard_engine_menu_action apply || echo "Обновление не завершено. Проверьте сообщение об откате и состоянии Guard." ;;
            0) break ;;
            *) echo "Неверный выбор" ;;
        esac
    done
    rm -f "$installer"
}

setup_smtp25_guard() {
    local choice f
    f=$(mktemp /tmp/xtls-smtp25.XXXXXX.sh) || return 1
    chmod 700 "$f"
    if ! curl -fsSL --connect-timeout 10 --max-time 40 "https://raw.githubusercontent.com/djing1e/universal-vps-setup/08d02d30789344b532aa260515c107ed93393b33/modules/xtls-smtp25-guard.sh" -o "$f"; then
        rm -f "$f"; echo "Ошибка загрузки SMTP25 Guard"; return 1
    fi
    if ! bash -n "$f"; then rm -f "$f"; return 1; fi
    while true; do
        echo "=== SMTP25 Anti-Abuse (исходящий TCP/25) ==="
        echo "1) Установить (Observe по умолчанию)"
        echo "2) Статус и счётчики"
        echo "3) Observe (без блокировок)"
        echo "4) Блокировать только исходящий TCP/25 (явное подтверждение)"
        echo "5) Отключить защиту"
        echo "0) Назад"
        read -e -r -p "Выбор: " choice || break
        case "$choice" in
            1) bash "$f" install ;;
            2) if [[ -x /usr/local/sbin/xtls-smtp25-guard ]]; then /usr/local/sbin/xtls-smtp25-guard status; else echo "Не установлен"; fi ;;
            3) if [[ -x /usr/local/sbin/xtls-smtp25-guard ]]; then /usr/local/sbin/xtls-smtp25-guard observe; else echo "Сначала установите"; fi ;;
            4) read -e -r -p "Введите BLOCK-SMTP25 для подтверждения: " confirm
               if [[ "$confirm" == "BLOCK-SMTP25" ]]; then /usr/local/sbin/xtls-smtp25-guard block; else echo "Отменено"; fi ;;
            5) if [[ -x /usr/local/sbin/xtls-smtp25-guard ]]; then /usr/local/sbin/xtls-smtp25-guard disable; else echo "Не установлен"; fi ;;
            0) break ;;
            *) echo "Неверный выбор" ;;
        esac
    done
    rm -f "$f"
}

setup_portscan_observe() {
    local choice f
    f=$(mktemp /tmp/xtls-portscan.XXXXXX.sh) || return 1
    chmod 700 "$f"
    if ! curl -fsSL --connect-timeout 10 --max-time 40 "https://raw.githubusercontent.com/djing1e/universal-vps-setup/08d02d30789344b532aa260515c107ed93393b33/modules/xtls-portscan-observe.sh" -o "$f"; then
        rm -f "$f"; echo "Ошибка загрузки Port Scan Observe"; return 1
    fi
    if ! bash -n "$f"; then rm -f "$f"; return 1; fi
    while true; do
        echo "=== Port Scan Guard — Observe (без блокировок) ==="
        echo "1) Установить / включить Observe"
        echo "2) Статус / счётчики"
        echo "3) Отключить Observe"
        echo "0) Назад"
        read -e -r -p "Выбор: " choice || break
        case "$choice" in
            1) bash "$f" install ;;
            2) if [[ -x /usr/local/sbin/xtls-portscan-observe ]]; then /usr/local/sbin/xtls-portscan-observe status; else echo "Не установлен"; fi ;;
            3) if [[ -x /usr/local/sbin/xtls-portscan-observe ]]; then /usr/local/sbin/xtls-portscan-observe disable; else echo "Не установлен"; fi ;;
            0) break ;;
            *) echo "Неверный выбор" ;;
        esac
    done
    rm -f "$f"
}

setup_antiabuse_center() {
    local choice
    while true; do
        echo ""
        echo "=== Anti-Abuse & Threat Intelligence ==="
        echo "  1) Spamhaus + FireHOL L1 (INPUT)"
        echo "  2) TCP DROP — C2 IP:порт"
        echo "  3) UDP DROP — сети Spamhaus"
        echo "  4) Общий статус (только чтение)"
        echo "  5) Spamhaus — обновление сетей и журнал совпадений"
        echo "  6) Анализ подписок — Auto Abuse Guard (без автобана)"
        echo "  7) SMTP25 Guard (опциональная исходящая защита)"
        echo "  8) Port Scan Guard (Observe)"
        echo "  9) Дополнительно: UDP IP:порт (нужен отдельный фид)"
        echo "  0) Назад"
        read -e -r -p "Выберите [0-9]: " choice || return 0
        case "$choice" in
            1) setup_threat_blocklist ;;
            2) setup_c2_feed ;;
            3) setup_spamhaus_udp_drop ;;
            4) antiabuse_center_status ;;
            5) setup_spamhaus_out_observe ;;
            6) setup_auto_abuse_guard ;;
            7) setup_smtp25_guard ;;
            8) setup_portscan_observe ;;
            9) setup_udp_abuse ;;
            0) return 0 ;;
            *) echo "Неверный выбор" ;;
        esac
    done
}
antiabuse_center_status() {
    local name count
    echo "===== THREAT-INTEL INPUT ====="
    for name in threat-block-v4 threat-block-v6; do
        if ipset list "$name" >/dev/null 2>&1; then
            count=$(ipset list "$name" | awk '/^Number of entries:/ {print $4}')
            printf '%s: %s entries\n' "$name" "$count"
        else
            printf '%s: not installed\n' "$name"
        fi
    done
    iptables -C INPUT -m set --match-set threat-block-v4 src -m conntrack --ctstate NEW -j DROP >/dev/null 2>&1 \
        && echo "IPv4 INPUT DROP: active" || echo "IPv4 INPUT DROP: inactive"
    ip6tables -C INPUT -m set --match-set threat-block-v6 src -m conntrack --ctstate NEW -j DROP >/dev/null 2>&1 \
        && echo "IPv6 INPUT DROP: active" || echo "IPv6 INPUT DROP: inactive"
    echo "Threat timer:"
    systemctl is-enabled threat-blacklist-update.timer 2>/dev/null || true
    echo "===== TCP C2 OUTPUT ====="
    if [[ -x /usr/local/sbin/xtls-c2-feed ]]; then
        /usr/local/sbin/xtls-c2-feed status
    else
        echo "Not installed"
    fi
    echo "===== UDP IP:PORT OBSERVER (SEPARATE FEED) ====="
    if [[ -x /usr/local/sbin/xtls-udp-abuse ]]; then
        /usr/local/sbin/xtls-udp-abuse status
    else
        echo "Not installed"
    fi
    spamhaus_output_summary || true
    echo "===== AUTO ABUSE GUARD (АНАЛИЗ, БЕЗ АВТОБАНА) ====="
    if [[ -x /usr/local/sbin/xtls-auto-abuse-guard ]]; then
        systemctl show xtls-auto-abuse-guard.timer --no-pager -p UnitFileState -p ActiveState
        systemctl show xtls-auto-abuse-guard.service --no-pager -p Result -p ExecMainStatus
    else
        echo "Не установлен"
    fi
    echo "===== SMTP25 GUARD ====="
    if [[ -x /usr/local/sbin/xtls-smtp25-guard ]]; then
        /usr/local/sbin/xtls-smtp25-guard status || echo "Не удалось прочитать статус"
    else
        echo "Не установлен (опционально)"
    fi
    echo "===== PORT SCAN OBSERVE ====="
    if [[ -x /usr/local/sbin/xtls-portscan-observe ]]; then
        printf 'Mode: %s\n' "$(cat /etc/xtls-portscan-observe/enabled 2>/dev/null || echo unknown)"
        nft -a list chain inet xtls_portscan_observe out || echo "Цепочка наблюдения отсутствует"
    else
        echo "Не установлен (опционально)"
    fi
}

# =====================================
# ГЛАВНОЕ МЕНЮ
# =====================================
# Инициализация лога
mkdir -p "$(dirname $LOG_FILE)"
log "=== Запуск vps-setup.sh ==="

while true; do
    print_header
    echo " 00) 🚀 УСТАНОВИТЬ ВСЁ (полный prod-стек, одна кнопка)"
    echo "     база+тюнинг+XanMod+CrowdSec+AS+Threat+vpsguard"
    echo ""
    echo "  1) Базовая настройка сервера"
    echo "     SSH, UFW, sysctl, BBR, fail2ban, автообновления"
    echo ""
    echo "  2) Управление IPv6"
    echo "     включить / отключить"
    echo ""
    echo "  3) CrowdSec (поведенческий IPS)"
    echo "     установить / удалить / статус"
    echo ""
    echo "  4) NextDNS"
    echo "     включить / отключить DoT через systemd-resolved"
    echo ""
    echo "  5) Журнал атак"
    echo "     SSH брутфорс, fail2ban, CrowdSec"
    echo ""
    echo "  6) Статус системы"
    echo ""
    echo "  7) Лог действий скрипта"
    echo "     $LOG_FILE"
    echo ""
    echo "  8) GeoBlock"
    echo "     блокировка по странам (whitelist)"
    echo ""
    echo "  9) Swap"
    echo "     создать / удалить / настроить"
    echo ""
    echo " 10) Установка remnanode"
    echo "     встроенный / eGamesAPI / классический (docs.rw)"
    echo ""
    echo " 11) Шейпер скорости"
    echo "     ограничение скорости пользователей (tc/nft)"
    echo ""
    echo " 12) AS_Network_List — блокировка госсетей РФ"
    echo "     iptables/ipset + systemd timer; nftables + cron"
    echo ""
    echo " 13) WARP-native (Cloudflare WARP)"
    echo "     wgcf-туннель для обхода geo-блоков (Gemini и т.п.)"
    echo "     локально или по SSH на выбранную ноду"
    echo ""
    echo " 14) Тюнинг ядра/сети — RPS/conntrack/sysctl/BBR"
    echo "     потолок юзеров и PPS; не трогает фаервол"
    echo ""
    echo " 15) Anti-DDoS — nft per-IP лимиты + fleet-sync"
    echo "     поверх UFW/CrowdSec: SYN/UDP-флуд, connlimit"
    echo ""
    echo " 16) Anti-Abuse & Threat Intelligence — Spamhaus / TCP C2 / UDP"
    echo "     единый раздел управления и общий статус"
    echo ""
    echo " 17) Probe-сервер — доступность IP снаружи/из РФ"
    echo "     временный HTTP/HTTPS на своих портах, лог подключений;"
    echo "     проверить новый IP на блок ДО того как вешать домен"
    echo ""
    echo " 18) TCP C2 Anti-Abuse — прямой вход (также в п.16)"
    echo "     обновление раз в 6 часов; блокировка включается вручную"
    echo ""
    echo " 19) UDP Anti-Abuse — прямой вход (также в п.16)"
    echo ""
    echo "  W) 🧹 Полная вычистка (откат всего начисто)"
    echo "     снести все слои перед чистым накатом"
    echo ""
    echo "  0) Выход"
    echo ""
    read -e -p "Выберите действие [00=всё / 0-19 / W=вычистка]: " MAIN_CHOICE

    case $MAIN_CHOICE in
        00|s|S|star|"*"|★) setup_one_button ;;
        1) setup_base ;;
        2) setup_ipv6 ;;
        3) setup_crowdsec ;;
        4) setup_nextdns ;;
        5) show_security_log ;;
        6) show_system_status ;;
        7) show_script_log ;;
        8) setup_geoblock ;;
        9) setup_swap ;;
       10) setup_remnanode ;;
       11) setup_speed_shaper ;;
       12) setup_as_blacklist ;;
       13) setup_warp ;;
       14) setup_kernel_tuning ;;
       15) setup_antiddos ;;
       16) setup_antiabuse_center ;;
       17) setup_probe_server ;;
       18) setup_c2_feed ;;
       19) setup_udp_abuse ;;
        W|w|wipe|WIPE) cleanup_legacy ;;
        0) log "=== Выход из vps-setup.sh ==="; echo "Выход."; exit 0 ;;
        *) echo "Неверный выбор." ;;
    esac

    echo ""
    read -e -p "Нажмите Enter для возврата в меню..."
done
