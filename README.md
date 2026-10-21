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
