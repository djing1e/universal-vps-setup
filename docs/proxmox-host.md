# Proxmox Host: Audit → Plan → Apply

Профиль рассчитан на Proxmox VE **9.2 / Debian 13**. Это отдельный allowlist
операций, не запуск «базовой настройки VPS» с отключёнными пунктами меню.
Сначала вручную проверьте PR и исходный код; затем испытайте на отдельном
Proxmox стенде с консолью. Из этого репозитория нельзя автоматически применять
изменения к работающему Hetzner хосту. Не выполняйте приведённые Apply-команды
до такого ревью и испытания.

## Архитектура и границы

- `vps-setup.sh`: при `/etc/pve`, `pveversion`, установленном `pve-manager`
  или PVE-ядре выбирает Audit до создания лога. Отсутствие соседнего
  `lib/proxmox_host.py` приводит к отказу, без скачивания/установки зависимостей.
- `lib/proxmox_host.py`: детектирование, аудит, детерминированный план,
  транзакция Apply, commit и rollback. Подтверждённый профиль требует и пакета,
  и успешного `pveversion`; частичные признаки не дают разрешения Apply.
- `lib/vps_inventory.py`: добавляет `host_profile` и Proxmox-раздел; старый
  offline update planner блокирует планы обновления VPS-модулей на Proxmox.
- Внутренние функции настройки и standalone entrypoint модулей проверяют хост
  непосредственно перед исполнением. Переменная окружения с выбором VPS не
  отключает проверку. Это защита от ошибочного запуска, не sandbox против root,
  который намеренно редактирует исходники.

Запрещены UFW/firewalld, VPSGuard, custom nft/iptables/ipset, ASN/Threat Intel,
C2/Spamhaus OUTPUT, SMTP/UDP/portscan/Auto Abuse Guard, Docker/Remnanode,
NextDNS, изменение DNS, kernel/XanMod, мостов, маршрутов, interfaces/netplan,
VM/CT и NIC firewall flags. Старые установленные версии посторонних скриптов
эта ветка ретроактивно не защищает. Не запускайте их на PVE-хосте.

## Audit и dry-run

Из корня полного checkout (для полного наблюдения нужны права root):

```bash
python3 lib/proxmox_host.py audit > /root/proxmox-audit.json
python3 lib/proxmox_host.py plan ssh > /root/proxmox-ssh-plan.json
```

`audit` и `plan` не устанавливают пакеты, не пишут системные конфиги, не
перезапускают службы и не меняют firewall. `plan` — dry-run с содержимым
кандидатного файла, его назначением, блокирующими условиями, хешами исходного
состояния и защищёнными областями. Не редактируйте JSON для обхода ограничений:
Apply заново строит план и требует полного совпадения.

Аудит содержит pveversion, qm/pct list, pve-firewall status, существующие
cluster/host firewall настройки, ограниченный набор эффективных SSH-параметров,
слушающие порты, мосты, адреса, IPv4/IPv6 маршруты. Для первых 128 работающих VM
делается только `qm agent <id> ping`; guest-exec не используется. Каждый probe
ограничен временем (5 секунд) и объёмом (32 KiB). Ошибка, timeout и отсутствие
инструмента означают неизвестное состояние. Конфиги VM/CT, ключи, пароли,
переменные контейнеров и содержимое SSH-конфига не выводятся. Сетевой отчёт
содержит приватную топологию: проверьте его перед публикацией.

## Host firewall

Примерные адреса ниже принадлежат публичным DNS-сервисам, **это не ваши admin IP**.
Замените их вашими реальными стабильными IPv4/IPv6 адресами или доверенными
сетями. Используйте узкие CIDR. Адреса сервера/шлюза и SSH_CONNECTION не
используются для угадывания allowlist.

```bash
python3 lib/proxmox_host.py plan firewall \
  --admin '<ADMIN_IPV4>/32' --admin '<ADMIN_IPV6>/128' \
  > /root/proxmox-firewall-plan.json
# Добавьте --spice только если действительно нужен TCP 3128.
```

Нужны явные allowlist **обоих** семейств. `/0`, неглобальные адреса,
неканонические CIDR и строки с командами отвергаются. Если адрес администратора
динамический, `--dynamic-admin` создаёт заблокированный план: сначала организуйте
стабильный доверенный egress или пересмотрите диапазоны вручную. Не разрешайте
весь Интернет ради временного доступа.

Условия активации:

1. Datacenter firewall уже включён и проверен человеком; этот инструмент
   **никогда не меняет `/etc/pve/firewall/cluster.fw`**. Если cluster config
   отсутствует, Apply блокируется. Для исходного Hetzner стенда из Issue #21
   это ожидаемый стоп до отдельного ручного решения по Datacenter firewall.
2. `pve-firewall` уже enabled/running; альтернативный `proxmox-firewall` не
   активен и nftables backend не включён. Никакой замены backend или установки
   пакетов не происходит.
3. SSH использует ровно порт 22. Host-файл отсутствует либо ранее создан этим
   профилем. Чужие host rules не перезаписываются, требуется ручная миграция.
4. IPv4/IPv6 allowlist, console/rescue, rollback и действующий SSH key login
   проверены. Сохраните существующее SSH-соединение, откройте консоль провайдера.

Кандидат содержит только host INPUT ACCEPT TCP 22, 8006 и опционально 3128 от
allowlist. В Host OPTIONS записывается **только `enable: 1`**. Политики
`policy_in`/`policy_out` принадлежат Datacenter, не Host. Audit/Plan показывают
явные значения и отдельно предположения о defaults для pve-firewall 6.0.6;
предположение не считается проверенным эффективным значением. Для планирования
активации требуются явные Datacenter `policy_in: DROP`, `policy_out: ACCEPT`,
но даже они не доказывают отсутствие более ранних ACCEPT. Системные правила PVE для
established traffic, ICMP/NDP остаются ответственностью native backend. Это не
изолированный генератор всех правил PVE: существующие cluster rules и встроенные
management exceptions могут разрешать доступ в обход Host allowlist.
Поэтому **firewall Apply сейчас всегда заблокирован**: пока нет валидатора
эффективных compiled management-путей и стендового подтверждения, статус
`management_access.activation_allowed` остаётся false. Флага ручного обхода
этой блокировки нет. Другие allowlisted операции этим ограничением не меняются. FORWARD, bridges, VM rules, MAC, диски и NIC flags
не меняются. Изменение файла может быть подхвачено daemon автоматически: поэтому
таймер отката запускается **до** записи активного файла.

## Allowlisted операции

- `ssh`: managed drop-in, `PermitRootLogin prohibit-password`, key auth on,
  password и keyboard-interactive off. Порт/ключи не меняются. Выполняются
  `sshd -t` до/после записи и `sshd -T` для проверки приоритетов Include;
  затем только reload, без restart. Неожиданные эффективные параметры вызывают
  откат. Match-конфигурации требуют отдельного ручного анализа и нового key login.
- `fail2ban`: только уже установленный fail2ban, SSH jail с systemd backend и
  **dummy action**, без записи nft/iptables. Это наблюдение, не автоблокировка.
  Чужой managed-path не перезаписывается; общий конфиг проверяется `-t`.
  Dry-run `fail2ban-client -d` до/после записи должен исключать любые другие
  enabled jail и любые actions, кроме dummy. Стандартный SSH jail с nftables
  action тоже блокируется; сначала требуется отдельная ручная миграция в observe.
- `crowdsec-observe`: только запуск уже установленного CrowdSec без установки
  пакетов и bouncers. Список пакетов и `cscli bouncers list` должны исключать
  bouncers; неизвестное состояние блокирует операцию. Нет установки bouncer,
  правок firewall или добавления удалённых интеграций. Внешние потребители решений
  вне этого хоста требуют отдельной проверки.
- `sysctl-advice`: совет сохранить PVE defaults, без системных записей и Apply.

## Apply, проверка и откат

Ниже — процедура для отдельно проверенного стенда, не команда для автоматического
запуска на сервере из Issue. Выполняйте одну операцию за раз из root-shell:

```bash
python3 lib/proxmox_host.py apply /root/proxmox-ssh-plan.json \
  --confirm 'APPLY PROXMOX HOST' \
  --console-confirmed --rollback-confirmed --key-login-confirmed \
  --rollback-seconds 180
```

Окно отката 60–600 секунд. Хеши файлов/cluster config и наблюдаемая топология
проверяются повторно; чужой или устаревший план отклоняется. Backup и состояние
транзакции сохраняются в `/var/lib/proxmox-host/<id>/` (root, 0700). Копия
rollback-кода сохраняется там же: таймер не зависит от последующих правок checkout.
Для firewall кандидат сначала проверяет штатный Perl parser/compiler PVE из
отдельного staging-файла, не записывая активный host.fw. Ошибки/предупреждения
компиляции блокируют запись. Preflight требует единственный JSON-export compiled rulesets/ipsets и отвергает
любой дополнительный stdout/stderr, даже при exit 0: PVE может перехватить
parser exception и продолжить compile. Пустой вывод тоже не считается успехом.
Каждое ожидаемое правило сверяется по семейству, source CIDR, TCP, порту и
нативному действию RETURN в PVEFW-HOST-IN; наличие строки в чужой цепочке
или другом семействе не засчитывается. `__WARN__` устанавливается до импорта модулей и перед parse.
На данной облачной машине этот PVE compiler
недоступен: протокол проверен mocks, реальная совместимость требует стенда PVE 9.2.

Затем независимый systemd timer запускается **до** изменения системного файла.
Отказ запуска таймера предотвращает Apply. При ошибке validation/reload выполняется
немедленный откат; без commit таймер восстановит прежний файл (или удалит вновь
созданный) и перезагрузит нужную службу. Backup сохраняется. Глобальные reset/flush
nftables/iptables не используются. Для PVE firewall вызывается только штатный
compile/restart/status, без изменения FORWARD policy инструментами VPS.

Из **другой сессии**, до истечения таймера, проверьте:

- новый SSH login по ключу и UI 8006 по IPv4 **и** IPv6 от разрешённых адресов;
- VM 101 и VM 102: SSH и внешний доступ, прежние MAC/bridge/route settings;
- отсутствие неожиданных правил и службы/backend, статус PVE firewall.

После успешных проверок подтвердите именно выданный ID транзакции:

```bash
python3 lib/proxmox_host.py commit /var/lib/proxmox-host/<id> \
  --verified 'VERIFIED SSH UI IPV4 IPV6 AND GUESTS'
```

Автоматический локальный probe не заменяет проверку удалённого доступа. Commit
после deadline/отката запрещён. Повторное применение уже совпадающего файла —
no-op; старый план после изменения исходного состояния требует пересоздания.
Новая транзакция запрещена, пока предыдущая не завершена подтверждением или откатом.

Ручной откат из консоли/rescue (или дождитесь таймера):

```bash
python3 /var/lib/proxmox-host/<id>/proxmox_host.py _rollback /var/lib/proxmox-host/<id>
```

Откат идемпотентен, после commit ничего не меняет. Если сами исходные файлы были
невалидны или штатная служба не может восстановиться, изучите backup `before` и
`state.json` через консоль и восстановите конфигурацию вручную. Не удаляйте
транзакцию до проверки. Таймер transient: **не перезагружайте хост до commit или
rollback**; после аварийной перезагрузки выполните ручное восстановление из backup.
Сбой/ребут хоста, изменение конфигурации сторонним администратором и потерю консоли
невозможно компенсировать гарантией из приложения.

## Проверки разработки

```bash
for f in vps-setup.sh modules/*.sh; do bash -n "$f" || exit; done
PYTHONPYCACHEPREFIX=/tmp/vps-pycache python3 -m py_compile lib/*.py modules/*.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Новые тесты используют временные деревья файлов и mocks для PVE, systemd,
firewall и SSH. В них нет изменений live firewall и обращений к Hetzner.
Существующим installer-тестам нужен root; существующим реальным nftables-тестам
из CI нужны привилегии и **отдельное** сетевое пространство имён. Не запускайте
их в namespace рабочего хоста. Успешные mocks не доказывают сохранность реального
трафика: перед production обязателен отдельный PVE стенд и ручное ревью PR.

## Предварительное security-review PR #22

`commit --verified ...` — **ручное свидетельство оператора**, не автоматический
тест SSH/UI или гостей. Commit дополнительно требует завершённый Apply.
Watchdog не ждёт транзакционный lock во время длительных проверок служб Apply;
это проверено вторым процессом с реальным flock, но не заменяет real-systemd test.

Актуальные результаты, незакрытые проверки PVE и процедура стендового испытания:
[pr22-security-validation.md](pr22-security-validation.md). При отсутствии такого
стенда критические операции остаются **не подтверждены для production**.

## Повторная проверка кандидата без применения

На машине с установленным pve-firewall используйте полный checkout текущей
ветки и кандидат, созданный **исправленным** генератором:

```sh
python3 lib/proxmox_host.py plan firewall \
  --admin '<ADMIN_IPV4>/32' --admin '<ADMIN_IPV6>/128' > /tmp/pve-plan.json
python3 -c 'import json,pathlib; p=json.load(open("/tmp/pve-plan.json")); pathlib.Path("/tmp/pve-candidate.fw").write_text(p["content"])'
python3 lib/proxmox_host.py validate-candidate /tmp/pve-candidate.fw
```

Команда `validate-candidate` читает отдельный файл и использует PVE parser/compiler;
не записывает активные host/cluster rules и не вызывает reload/restart/apply.
Она проверяет, что единственная Host option — `enable: 1`, отвергает любые
parser diagnostics независимо от exit status и сверяет ожидаемые правила с
compiled JSON. Тихое исчезновение правила — ошибка. Успех семантической сверки возвращает
`management_access_verified: false`: это **не** доказательство соответствия
реального доступа allowlist. Изменение Datacenter RULES, security groups,
management ipset и встроенных local_network/management exceptions должно быть
проверено по эффективным IPv4/IPv6 rulesets и внешним тестам на отдельном стенде.
На рабочем `hilocaladmin` в этой задаче не выполнялось ни Apply, ни эта проверка.

## Офлайн-анализ compiled артефактов

```sh
python3 lib/proxmox_host.py analyze-compiled candidate.fw compiled.json
```

`compiled.json` должен содержать `schema_version: 1`, `ipv4` и `ipv6` — словари
filter chain → массив строк `-A <chain> ...`, и `ipsets` — словарь имени ipset →
массив native `create`/`add` команд, полученных из той же компиляции кандидата.
Текстовый вывод CLI `pve-firewall compile` не является этим JSON-форматом.
Native exporter встроен в `validate-candidate`; эта задача не запускала его на
production и не получила полный raw JSON с хоста. Не преобразовывайте
артефакты с потерей неизвестных цепочек/правил ради успешного анализа.

Отчёт содержит missing rules, members management-v4/v6, неизвестные set entries,
порядок вызовов цепочек с индексом продолжения caller и потенциальные пути к
management-портам вне запрошенного scope. RETURN — native реализация host ACCEPT,
**не окончательный вердикт**; анализ фиксирует необходимость продолжить caller.
Даже target ACCEPT в одной цепочке не доказывает отсутствие последующих drop в
полной системе. Этот анализ структурный и консервативный, не symbolic packet
simulator: unknown match/target, goto, cycles, отсутствующий set или входная
цепочка не могут дать разрешение Apply. Возможны ложноположительные риски, когда
предшествующие правила или caller conditions исключают пакет.

Порты 3128, 5900:5999 и 60000:60050 могут появляться из **встроенных management
exceptions PVE**, независимо от запроса SPICE в кандидате. Флаг `--spice`
управляет только сгенерированными host rules и не выключает встроенные правила.
Их наличие отмечается как потенциальное дополнительное разрешение, а не как
доказанная доступность сервиса. Необходим анализ всех caller/return путей,
содержимого set, kernel INPUT hooks и live policy; эти проверки не завершены.
`activation_allowed` и `management_access_verified` остаются false.

Production-проверки на `hilocaladmin` остановлены. Для следующего этапа нужны
сохранённые артефакты и/или отдельный disposable PVE-стенд, не новые испытания
на рабочем сервере.
