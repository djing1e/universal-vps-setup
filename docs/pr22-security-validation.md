# PR #22: предварительное security-review и статус проверки

PR остаётся draft. Этот документ **не разрешает production Apply** и не
подтверждает реальную совместимость с Proxmox. Пользователь подтвердил, что
отдельного PVE-стенда пока нет. Работающий Hetzner не использовался.

## Исправления после ревью

В исходном Apply транзакционный flock удерживался не только при записи файла,
но и во время ожидания `pve-firewall compile`, `systemctl restart`, `sshd`.
Независимый watchdog мог ждать освобождения этого flock при зависшем restart.
Теперь блокировка защищает запись и переходы состояния; ожидание служб идёт
без неё. Watchdog может восстановить файл, пока Apply ждёт службу. После
проверок Apply снова берёт lock и отклоняет истёкшую или уже отменённую откатом транзакцию.

Commit требует отметку завершённого Apply и остаётся **ручным свидетельством
оператора**. Фраза `VERIFIED SSH UI IPV4 IPV6 AND GUESTS` не выполняет SSH,
HTTP или сетевые проверки и не доказывает доступность. В результате Apply это
также явно обозначено полем `verification`.

Новые тесты проверяют откат из реального второго Python-процесса с настоящим
flock во время имитируемого restart, expiry во время проверки службы и отказ
commit до завершения Apply. Сами PVE/systemd-команды в этих тестах заменены
mocks. Это проверка координации процессов, **не реального systemd timer**.

## Матрица замечаний

| Участок | Что подтверждено | Что остаётся открытым |
| --- | --- | --- |
| PVE candidate parser/compiler | В Apply передаётся staging-путь в `load_hostfw_conf($c, $path)`, затем полученный `$h` в `compile($c, $h)`; staged file не является активным host.fw | Реальная сигнатура и отрицательный тест на установленном PVE 9.2; код upstream из другой версии не является доказательством |
| Watchdog | Проверены порядок timer-before-write, отказ запуска таймера, повторный откат, независимый flock и expiry | Настоящий systemd timer, failed/hung restart и поведение daemon на PVE |
| Сеть | Проверены только генерируемые INPUT-правила двух семейств и отсутствие записи мостов/VM fixtures | Реальные established, ICMPv6/NDP, SSH/UI/SPICE, FORWARD и трафик гостей |
| Commit | Ручное подтверждение явно названо; до окончания Apply и после expiry/rollback запрещено | Доступ с разрешённых и запрещённых внешних адресов должен проверить оператор |
| fail2ban | `dummy` означает observe-only, без активного бана; другие jail/actions блокируются | Реальная интеграция и локальные overrides пакета на тестовом PVE |
| Регрессии | Root-зависимые installer-тесты повторены в одноразовом Debian 13 Docker; тесты не отключались | PVE и systemd не запускались как реальные службы в этом контейнере |

## Воспроизводимая root-проверка

Использован локальный managed Docker, отдельный контейнер Debian 13, checkout
смонтирован read-only в `/src`. Контейнер не privileged, без host networking,
без подключения `/etc/pve`, сокета Docker или устройств хоста внутрь контейнера.
Установлены Python 3 и systemd (включая `systemd-analyze`), затем выполнено:

```sh
cd /src
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Первый root-прогон до трёх дополнительных regression-тестов: **130/130 OK**,
включая три installer-теста, ранее падавшие из-за uid 1000. Итоговый root-прогон после исправлений: **133/133 OK**, без skipped/disabled
тестов; 27 Proxmox-тестов входят в этот набор. Результат unittest:

```text
Ran 133 tests in 10.481s

OK
```

Bash syntax для `vps-setup.sh` и всех `modules/*.sh`, Python compilation для
`lib/*.py` и `modules/*.py` также прошли. Отдельная статическая проверка полного
Bash entrypoint обнаружила 179 защищённых функций с gate и ни одного пропуска
среди проверяемых семейств. Heredoc payloads исключались из этой проверки;
standalone entrypoints проверяются существующими тестами. Это проверка наличия
gate, не доказательство отсутствия всех возможных обходов и не полный аудит. Наличие пакета systemd для unit validation
не означает, что systemd был PID 1 или timer реально запускался.

## Протокол будущего изолированного PVE 9.2 стенда

1. Нужен одноразовый PVE 9.2 / Debian 13 с консолью и двумя гостями, отдельными
   management IPv4/IPv6 и внешними клиентами. Никакого моста/маршрута в production.
   Сохранить точные `pveversion -v`, версии `pve-firewall` и systemd, SHA ветки,
   guest MAC/NIC flags, bridge/routes и исходные host/cluster правила.
2. Создать кандидата через Plan. Извлечь из Apply тот же Perl parser/compiler
   вызов и запустить против staging-файла с отличающимся от активного allowlist.
   Сохранить parsed host config и возвращённые IPv4/IPv6 rulesets: они должны
   содержать **кандидатные**, а не активные source/port правила. Затем повторить
   с намеренно невалидным кандидатом — процесс обязан завершиться ошибкой,
   хеш активного host.fw и firewall должны остаться прежними. Проверка stdout
   только от `pve-firewall compile` не доказывает проверку кандидата.
3. На том же изолированном стенде проверить создание transient timer до записи,
   expiry без commit, повторный rollback, неуспешный restart и зависание restart.
   Инъекция задержки/ошибки допустима только в disposable службе/копии стенда,
   не на production. При зависании watchdog должен восстановить файл, не ожидая
   flock Apply; после возобновления Apply не должен вернуть успех или commit.
   Сохранить journal и время восстановления файла/реального применения правил.
4. Проверить новый SSH key login :22, UI :8006 и опциональный SPICE :3128 с
   разрешённых IPv4/IPv6 клиентов; новые подключения с запрещённых адресов
   должны отклоняться с учётом явно записанных native PVE exceptions. Проверить
   existing TCP connection, ICMPv6/NDP/RA, исходящие соединения и обнаружение
   соседей после очистки тестового neighbor cache. Не считать один ping полным
   доказательством ICMPv6/NDP.
5. Проверить двусторонний трафик обоих гостей через vmbr0, изолированный vmbr1,
   IPv4/IPv6 и FORWARD до/после Apply/rollback. Сравнить VM/CT config, NIC flags,
   MAC, bridge membership, routes и FORWARD policy. Сохранить сырые результаты
   запросов и счётчики, а не только отсутствие изменений конфигов.
6. Отдельно проверить SSH Include/Match и новый key login после hardening;
   затем ручной commit, expiry, повторный rollback и отказ раннего commit.
7. **Transient timer не переживает reboot.** Не перезагружать до commit/rollback.
   На disposable стенде отдельно проверить recovery из persistent backup после
   аварийного reboot; не представлять его как автоматический rollback.

Для каждого пункта записать PASS/FAIL/NOT RUN, версии, SHA, команды и вывод.
Любой NOT RUN в критических PVE/network/systemd пунктах сохраняет запрет на
production rollout. Ручное ревью всего diff, а не только выбранных функций,
по-прежнему необходимо перед снятием draft.

## Исправление Host policies после проверки pve-firewall 6.0.6

Проверка установленного pve-firewall 6.0.6, сообщённая пользователем, выявила
дефект: `policy_in`/`policy_out` относятся к Datacenter/VM, а не Host.
`enable_host_firewall()` использует cluster options. Поэтому прежний генератор
не задавал обещанную host policy; parser diagnostics могли сопровождаться
успешным выходом compiler. Прежнее утверждение «compile прошёл — кандидат
корректен» отозвано.

Исправлено:

- В генерируемом Host OPTIONS остаётся только `enable: 1`.
- Audit и Plan показывают политики Datacenter, явный источник либо отдельно
  помеченное предположение о defaults 6.0.6. Defaults не считаются проверенным
  эффективным состоянием. Противоречивые/отсутствующие явные политики блокируют
  план; cluster config инструмент не меняет.
- Общий quiet preflight для Apply и `validate-candidate` отвергает любой
  непустой stdout/stderr, даже при exit 0. `__WARN__` устанавливается до import
  PVE и перед parse; перехваченные внутри PVE ошибки не обходят проверку вывода.
- Наличие Host ACCEPT-правил не доказывает ограничение доступа: Datacenter RULES,
  security groups, management ipset и встроенные management/local_network
  exceptions могут открывать путь раньше Host allowlist. Пока нет проверки
  эффективных compiled правил, **native firewall Apply всегда заблокирован**.
  Ручного флага обхода нет. Конфигурации и генерация кандидата доступны для ревью.
- Добавлена read-only команда `validate-candidate`; её успех явно возвращает
  `management_access_verified: false`. Инструкция в `proxmox-host.md`.

Проверки после исправления: **139/139 OK** от root в отдельном одноразовом
Debian 13 контейнере, без пропусков. Proxmox tests: **33/33 OK**. Шесть новых
регрессий проверяют Host options, Datacenter policy sources/defaults/duplicates,
нулевой exit с parser diagnostics, отсутствие timer/write после такого отказа
и блокировку непроверенных management exceptions/Datacenter ACCEPT/IPSET.
Bash syntax и Python compilation также прошли.

Повторный запуск candidate preflight на `hilocaladmin` здесь **NOT RUN**:
подключение к нему не использовалось. Реальное подтверждение отсутствия обходов
allowlist и сетевой доступности по-прежнему **NOT RUN**. Черновой статус PR и
запрет production rollout остаются в силе; эти пункты не выдаются за закрытые.

## Semantic validation после обнаружения тихого пропуска правил

Данные пользователя об установленном pve-firewall 6.0.6 показали: отсутствие
diagnostics также не доказывает корректность. Невалидный source/protocol может
исчезнуть из compiled rulesets без ошибки. Проверка quiet exit из предыдущего
раздела заменена строгим JSON-export и семантической сверкой.

Текущий preflight получает filter chain maps IPv4/IPv6 и ipsets непосредственно
из возвращаемых значений той же `compile($cluster,$candidate)`; требует полный
поддерживаемый JSON, отвергает диагностику до/после JSON и отсутствие экспорта.
Для каждого expected Host ACCEPT требуется соответствующее native RETURN-правило
в PVEFW-HOST-IN нужного семейства с теми же source CIDR, TCP и dport. Совпадение
в другой цепочке/семействе, другой source/port/protocol/action или тихое
исчезновение — отказ. Некорректные candidate source/protocol отвергаются ещё
до запуска компилятора. Неизвестные форматы не засчитываются как совпадения.

`lib/pve_compiled.py` дополнительно извлекает management-v4/v6 members и обходит
compiled input call graph в порядке правил. В отчёте есть caller, индекс jump,
callee и индекс продолжения. RETURN не объявляется окончательным ACCEPT;
unknown targets/goto/cycles/missing sets и потенциальные широкие management
пути сохраняют запрещающее состояние. Для ipset проверяются семейство и
покрытие известными admin CIDR; nomatch/неизвестные форматы не дают положительного
доказательства. Диапазоны 5900:5999, 60000:60050 и SPICE 3128 выявляются отдельно
как возможные native management exceptions, не запрошенные генератором.

**Это структурный консервативный анализ, не полноценная симуляция пакета.**
Он не подтверждает kernel INPUT hooks, все caller predicates/continuations,
другие таблицы и окончательный live verdict. Потенциальный путь RETURN может
завершиться DROP в caller; отчёт не объявляет его доказанной доступностью.
Ни чистая семантическая сверка, ни пустой список найденных рисков не открывают
Apply: `activation_allowed=false`, `management_access_verified=false`.

Офлайн-команда и формат snapshot описаны в `proxmox-host.md`:
`analyze-compiled candidate.fw compiled.json`. Новые fixtures **синтетические**,
соответствуют форме native compiler output и наблюдениям пользователя, но не
выдаются за raw capture с hilocaladmin. Полный реальный JSON в эту задачу пока
не передан; проверка его установленной версией остаётся NOT RUN.

Итоговые проверки: **148/148 OK** от root в одноразовом Debian 13 Docker,
без skipped/disabled. Включены 33 теста профиля и 9 новых тестов compiled
semantics/management graph. Bash syntax, Python compilation и `git diff --check`
прошли. Root suite:

```text
Ran 148 tests in 9.667s

OK
```

Тесты на production остановлены. Никаких подключений/команд на hilocaladmin
не выполнялось; дальнейшая разработка — по сохранённым артефактам и на отдельном
стенде. PR остаётся draft, production rollout запрещён.

## Разделение Datacenter-входов для проверки

Добавлены два несмешиваемых CLI-режима:

- `validate-candidate`: действующий Datacenter, без аргумента override;
  disabled/absent policy и missing Host chains означают отказ.
- `validate-offline --datacenter TEST`: явно указанный enabled тестовый файл
  вне `/etc/pve`, передаётся в PVE loader исключительно для этого compile.
  Нет копирования/записи в live config и нет activation/reload/restart.

Offline report сохраняет compiled JSON, provenance, хеши файлов и запрещающие
флаги. Изменение входных файлов во время compile отвергается. Operation Apply
явно отклоняет validation results; CLI не допускает test Datacenter override
в production/Apply. Повторный artifact analysis сохраняет offline происхождение
и не разрешает Apply.

Новые tests проверяют выбор live/test loader inputs, disabled live + enabled test,
отсутствующие цепочки, обязательность external test-файла, изменение входа,
CLI isolation, непригодность offline result для Apply и повторный offline analysis.
В двух тестах исполняется **настоящий Perl**, но PVE::Cluster/PVE::Firewall —
синтетические stub packages; проверяются Perl exporter и маршрутизация аргументов,
**не установленная реализация PVE 6.0.6**. Действующий fixture config остаётся
неизменённым, disabled production не достигает compile.

Реальный положительный JSON-export с enabled test Datacenter: **NOT RUN**.
Отсутствие live compiled IPv4 Host chain не обходится в production; именно для
этого отдельный offline режим существует. PR Draft и общий запрет Apply сохранены.

Проверки этой итерации: **157/157 OK** от root в одноразовом Debian 13
контейнере (Python 3, systemd для unit validation, Perl/JSON::PP), без пропусков.
В том числе 9 новых mode-isolation тестов. Вне контейнера профильные тесты:
51/51 OK. Bash syntax, Python compilation, `git diff --check` прошли.

```text
Ran 157 tests in 11.296s

OK
```

Эти результаты не изменяют NOT RUN для реального положительного PVE exporter.
