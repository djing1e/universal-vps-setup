#!/usr/bin/env bash
# Bootstrap the VPS manager, then enter installation or the menu with terminal input.
set -euo pipefail
umask 077

# Pin the payload independently of the mutable bootstrap URL.
SOURCE_REVISION=61c93bb424ac08a325147bd852fcec7210553463
SCRIPT_SHA256=1da7046f81a8675af341d22cae4db422abf72f08827efdeb06e049057e03a01b
SOURCE_URL="https://raw.githubusercontent.com/djing1e/universal-vps-setup/${SOURCE_REVISION}/vps-setup.sh"
TARGET=/usr/local/sbin/vps-setup
LAUNCHER=/usr/local/bin/vps-setup

case "${1:---install}" in
    --install|--menu) action="${1:---install}" ;;
    --help|-h) echo 'Usage: bash install.sh [--install|--menu]'; exit 0 ;;
    *) echo 'Usage: bash install.sh [--install|--menu]' >&2; exit 2 ;;
esac
(( $# <= 1 )) || { echo 'Лишние аргументы.' >&2; exit 2; }
(( EUID == 0 )) || { echo 'Запускайте от root: sudo -i' >&2; exit 1; }
if ! command -v curl >/dev/null || [[ ! -s /etc/ssl/certs/ca-certificates.crt ]]; then
    command -v apt-get >/dev/null || { echo 'Требуется Debian / Ubuntu с APT.' >&2; exit 1; }
    apt-get update
    apt-get -o DPkg::Lock::Timeout=600 install -y --no-remove curl ca-certificates
fi

[[ ! -L "$TARGET" ]] || { echo "Symlink: $TARGET; требуется ручная проверка." >&2; exit 1; }
if [[ -e "$LAUNCHER" || -L "$LAUNCHER" ]]; then
    [[ -L "$LAUNCHER" && "$(readlink "$LAUNCHER")" == "$TARGET" ]] || {
        echo "$LAUNCHER уже занят другим файлом; замена отменена." >&2; exit 1;
    }
fi
work=$(mktemp -d /tmp/vps-setup-install.XXXXXXXX)
stage=''
trap 'rm -rf "$work"; [[ -z "$stage" ]] || rm -f "$stage"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 --connect-timeout 10 --max-time 120 "$SOURCE_URL" -o "$work/vps-setup.sh"
printf '%s  %s\n' "$SCRIPT_SHA256" "$work/vps-setup.sh" | sha256sum -c -
bash -n "$work/vps-setup.sh"
install -d -m 0755 /usr/local/sbin /usr/local/bin
if [[ -e "$TARGET" ]]; then
    [[ -f "$TARGET" ]] || { echo "Нестандартный файл: $TARGET" >&2; exit 1; }
    backup=$(mktemp -d /root/vps-setup-backup.XXXXXXXX)
    cp -a "$TARGET" "$backup/vps-setup"
    echo "Резервная копия менеджера: $backup/vps-setup"
fi
# Replace only after a complete download, checksum and syntax validation.
stage=$(mktemp /usr/local/sbin/.vps-setup.XXXXXXXX)
install -m 0755 "$work/vps-setup.sh" "$stage"
mv -f "$stage" "$TARGET"
stage=''
if [[ ! -L "$LAUNCHER" ]]; then ln -s "$TARGET" "$LAUNCHER"; fi
printf 'Установлено: %s\nПовторный запуск меню: vps-setup\n' "$TARGET"
if [[ "$action" == --install ]]; then
    (umask 022; "$TARGET" --install)
else
    (umask 022; "$TARGET")
fi
