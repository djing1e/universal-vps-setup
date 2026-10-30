# Universal VPS Setup

Интерактивный установщик VPS для Debian 13 / Ubuntu 24.04.

**Файл установщика:** [vps-setup.sh](./vps-setup.sh)

## Запуск с приватного GitHub

Запускать от `root`. Для загрузки требуется GitHub Fine-grained Personal Access Token с правом **Contents: Read-only** только к этому репозиторию.

```bash
TOKEN='ВСТАВЬ_СВОЙ_ТОКЕН'; F=$(mktemp /tmp/vps-setup.XXXXXX.sh) && curl -fsSL -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github.raw+json" "https://api.github.com/repos/djing1e/universal-vps-setup/contents/vps-setup.sh" -o "$F" && unset TOKEN && bash -n "$F" && bash "$F"; R=$?; unset TOKEN; [ -n "${F:-}" ] && rm -f "$F"; (exit "$R")
```

**Безопасность:** токен, вставленный в команду, может сохраниться в истории shell. Не публикуйте его в репозитории и не передавайте третьим лицам. Перед запуском с правами root проверяйте изменения установщика и сохраняйте консольный доступ у провайдера.

## Разработка

Доработки — через ветки и Pull Request. В `main` находится рабочая версия.

## Proxmox Host (Audit-first)

Для Proxmox VE 9.2 / Debian 13 используйте **полный checkout проверенной
ревизии**, а не загрузку одного `vps-setup.sh`. При признаках Proxmox основной
скрипт автоматически переходит в **Audit only**, до записи лога и запуска меню.
VPS-модули заблокированы также в исполняемых функциях и отдельных entrypoint.

```bash
python3 lib/proxmox_host.py audit
python3 lib/proxmox_host.py plan ssh
```

План ничего не применяет. Apply — отдельная команда с подтверждениями, проверкой
свежести плана, резервной копией и таймером отката. Native firewall управляет
только `nodes/<local-node>/host.fw`; включение Datacenter firewall и миграция
чужих правил требуют отдельной ручной проверки. Нельзя использовать публичный
IP сервера вместо адресов администратора.

**До использования на production Proxmox обязательны ручное ревью PR и
проверка на отдельном стенде.** Настройка не запускается на работающем Hetzner
сервере автоматически. Процедура, ограничения и восстановление:
[docs/proxmox-host.md](docs/proxmox-host.md).
