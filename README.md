# Universal VPS Setup

Интерактивный установщик и администрирование VPS (Debian 13 / Ubuntu 24.04).

## Запуск (приватный репозиторий)

На VPS должен быть настроен SSH Deploy Key **только для чтения** с доступом к этому репозиторию и установлен git.

```bash
clear; bash -c 'set -e; d=$(mktemp -d); trap '\''rm -rf "$d"'\'' EXIT; git clone --depth 1 git@github.com:djing1e/universal-vps-setup.git "$d/repo"; bash "$d/repo/vps-setup.sh"'
```

Запускайте от `root`; команда загружает актуальную версию из `main`.

**Осторожно:** скрипт изменяет DNS, SSH, firewall и сетевые сервисы. Перед запуском на удалённом VPS сохраните доступ через консоль провайдера. Проверяйте изменения перед выполнением с правами root.

## Разработка

Правки в отдельных ветках с Pull Request. Проверка синтаксиса: `bash -n vps-setup.sh`.
