#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if (( EUID != 0 )); then
  echo 'Run as root (sudo -i)' >&2
  exit 1
fi
exec bash ./vps-setup.sh
