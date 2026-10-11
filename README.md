# Библиотека проверок wscan

Отдельный репозиторий данных для собственного движка wscan.
Содержит `nuclei-templates/`, `nmap/scripts/`, `nmap/nselib/`, справочники,
`categories.json`, `products.json` и документацию. Бинарников сканеров здесь нет.

Установка и обновление: `wscan library update`. Библиотека хранится в
`~/.config/wscan/library/`; после скачивания доступна без интернета.
Для первого скачивания нужен Git и доступ к GitHub.

# wscan-library

Библиотека проверок для [wscan](https://github.com/ushst/wscan): шаблоны Nuclei, скрипты Nmap NSE и единый индекс категорий.

Софт скачивает/обновляет этот репозиторий целиком. Правки категорий и новые проверки делайте здесь — после `wscan library update` они появятся у клиентов.

## Состав

Свежие проверки MikroTik / GitLab: [список CVE, затронутые порты и условия](security/vendor-cves.md).
Прямой WinBox контроль CVE-2024-54772 и наличие PoC описаны в [аудите MikroTik](security/mikrotik-protocol-checks.md).
`mikrotik-routeros-cve-2024-54772.nse` — активная ограниченная проверка WinBox (обычно TCP 8291), без словаря;
`mikrotik-routeros-username-brute.nse` остаётся только в «Подбор учётных данных».
Kyocera: `kyocera-netviewer-address-book-interface` в Web читает WSDL на TCP 9091 без создания экспорта.
Исходный CVE-2022-1026 шаблон создания экспорта отмечен `exploit` и требует отдельного разрешения проекта.
Срез от 05.10.2026 содержит 60 проверок по публично обнаруженной версии и 4 позиции для ручной проверки.
В Web → CVE ищите `mikrotik-version` / `gitlab-version` или CVE ID. Новые шаблоны используют GET без учётной записи;
совпадение версии обозначает потенциальный риск. Если версия скрыта, отсутствие находки не подтверждает исправление.
Порт HTTP(S) проверки и порт затронутого сервиса указаны отдельно в описании каждого шаблона.

| Путь | Назначение |
|------|------------|
| `nuclei-templates/` | Upstream Nuclei templates (MIT) |
| `nuclei-templates/custom/` | Свои проверки, не upstream — см. `custom/README.md` |
| `nmap/scripts/` | NSE-скрипты |
| `nmap/nselib/` | Lua-библиотеки NSE |
| `nmap/nmap-*` | Служебные данные Nmap (ports/services) |
| `categories.json` | Индекс: сервис / тип / impact для проверок внешних целей |
| `tools/gen_categories.py` | Пересборка `categories.json` |
| `security/vendor-cves.json` | Проверенный срез диапазонов CVE MikroTik / GitLab и первичные источники |
| `tools/gen_vendor_cves.py` | Генерация проверок версии и списка покрытия из среза CVE |
| `tools/gen_msf_scanner.py` | Codegen MSF `auxiliary/scanner` → `custom/msf-scanner/` |
| `tools/refresh_msf_scanner.sh` | MSF → YAML + categories (если есть checkout MSF) |
| `MANIFEST.json` | Версия и метаданные снимка |

## Metasploit scanners (без msfconsole)

msfconsole / `msfrpcd` **не** подключены. Дешёвый и устойчивый путь:

| Источник MSF | Что делаем |
|---|---|
| `auxiliary/scanner` Tcp/Udp/UDPScanner с константным probe | codegen → `tcp:`/`udp:` в `custom/msf-scanner/*.yaml` (**45** сейчас) |
| Модули, которым нужен реальный протокольный клиент (SMB, Redis) | codegen → `javascript:`, на уже готовых нативных клиентах движка (`require("nuclei/smb")`, `require("nuclei/redis")`, см. `internal/engine/js/`) — см. `JS_OVERRIDES` в `gen_msf_scanner.py` |
| HTTP scanners (~329) | **не** портим — уже есть upstream `nuclei-templates` |
| Остальные SMB/MSSQL/Postgres/LDAP/Kerberos/DCERPC и т.п. | не портированы: нет курируемого `JS_OVERRIDES` (SMB enum/vuln — см. NSE `smb-vuln-ms17-010`, `smb-enum-*`), либо нативный клиент пока неполный (MSSQL — не настоящий TDS, Postgres — нет pre-auth fingerprint) |
| login / brute / DoS / amplification (DRDoS) / file-write | пропускаем намеренно |

### Как подхватываются новые проверки

1. Любой новый YAML под `nuclei-templates/` (в т.ч. `custom/`) каталог видит сам (`WalkDir`) — правки в Go не нужны.
2. Новые **portable** модули MSF появляются после refresh и коммита в library-репо:

```bash
# нужен локальный Metasploit (или MSF_ROOT=...)
bash tools/refresh_msf_scanner.sh
# закоммитить custom/msf-scanner/ + categories.json + GENERATED.md
```

Клиенты получают обновление через `wscan library update` — у них MSF не нужен.

## Metasploit exploits — Phase 1 (trigger-only, без payload/сессии)

`modules/exploits/` в MSF — 2657 модулей, из них **1664** требуют `Payload` (shellcode + handler + сессия — это отдельная, ещё не начатая подсистема: генерация пейлоадов, bind/reverse listener, интерактивные сессии). Остальные **994** ничего не доставляют — просто триггерят баг и подтверждают эффект (crash/leak/auth-bypass/blind RCE). Эти портируются так же, как MSF HTTP-сканеры: **не кодогеном**, а вручную, по одному — см. `custom/msf-exploit/`.

| Что | Как |
|---|---|
| Формат | `exploit:`-шаблон — это обычный `http:`/`tcp:`/`javascript:` шаблон с тегом `tags: exploit,...` |
| Безопасность | Тег `exploit` — это hard-gate в движке (`domain.Project.AllowExploit`, по умолчанию `false`), не просто лейбл. Без явного включения оператором (TUI: Настройки → "exploit: проверки, триггерящие уязвимость", с экраном-предупреждением) такой шаблон **не выполнится**, даже если он есть в выборке — см. `internal/engine/exec.go` |
| Курирование | Каждый файл верифицирован вручную против реального исходника MSF-модуля, как `PROBE_OVERRIDES`/`JS_OVERRIDES` — никакого авто-перевода Ruby → YAML для эксплойтов |
| Пилот | `msf-exploit-opennetadmin-ping-cmd-injection.yaml` (CVE-2019-25065) — blind time-based RCE confirmation (`sleep 6` + `duration>=5`), без дампа/записи файлов |
| Дедупликация с nuclei | Как и для HTTP-сканеров — прежде чем портировать HTTP-эксплойт, стоит проверить, нет ли уже готового PoC в `nuclei-templates/http/` (CVE-индекс/токены) |
| Дальше | 307 кандидатов (HTTP, no-payload, с CVE, не найдены в CVE-индексе nuclei) см. в истории чата/scratch-анализа — портируются по одному, это открытый процесс, как и `msf-scanner` |

## Категории

`categories.json` — источник правды для группировки в UI (ось «по сервису»: Web, SMB, SSH, …).

Пересобрать после добавления скриптов:

```bash
python3 tools/gen_categories.py
```

Правила матчинга — по **целым** токенам имени (`smb`, `samba`), без ложных срабатываний вроде `sambar` → SMB.

Сейчас в индексе ~14 400 проверок. SMB включает все `smb*` / `samba*` NSE и связанные nuclei-проверки (в т.ч. javascript/code — они видны в каталоге, но могут быть недоступны нативному движку).

## Обновление в wscan

```bash
# первый раз
wscan library update https://github.com/<you>/wscan-library

# дальше
wscan library update

# или через окружение
export WSCAN_LIBRARY_URL=https://github.com/<you>/wscan-library
wscan library update
```

Библиотека кладётся в `~/.config/wscan/library` (или `$WSCAN_LIBRARY_DIR`). URL сохраняется в `~/.config/wscan/library-remote.json`.

## Лицензии

- Nuclei templates: `nuclei-templates/LICENSE.md` (MIT)
- Nmap NSE: `nmap/LICENSE` (Nmap Public Source License 0.95)

Не удаляйте файлы лицензий upstream при обновлении снимков.

## Индекс продуктов и рекомендации

`products.json` индексирует все самостоятельные Nuclei/NSE проверки, включая custom
и протоколы вне Web. YAML workflow и служебные файлы также учтены в inventory.
Канонические продукты, алиасы, CPE и основания привязок отделены от протоколов,
воздействия, требований и метода подтверждения. Неизвестные значения сохраняются
как null; слабые совпадения требуют ручного рассмотрения.

```bash
# Python 3.9+, PyYAML 6.x
python3 tools/gen_categories.py
python3 tools/gen_products.py
```

Ручные правила живут в [security/product-rules.json](security/product-rules.json);
они применяются обоими генераторами и переживают пересборку. Схема categories.json
сохранена. Три словарные NSE (Kerberos, SMTP и HTTP userdir) выделены только в подбор;
GET проверки версии отнесены к обнаружению потенциального риска. Kyocera экспорт
сохраняет exploit и отдельно отмечен как изменение состояния; WSDL только обнаруживает интерфейс.

[Контракт и примеры для wscan](security/product-index-integration.md) описывают
выбор по конкретному сервису, GitLab/AI Gateway, WebFig/WinBox, Kyocera HTTPS9091,
Windows/AD и нестандартные порты. Для рекомендаций в TUI нужны изменения основного
приложения: загрузка индекса, service selector, capabilities и фильтры воздействия.
Индекс не запускает проверки и не подтверждает поддержку движком.

[Отчёт покрытия](security/product-index-report.md) содержит точные количества и ограничения;
[полный список проблем](security/product-index-issues.json) — ошибки и неоднозначности.
Этот аудит выполняет локальную генерацию: тесты, сборка и проверки на целях не запускались.

### Каталог внешнего сканера

`categories.json` и исполняемая часть `products.json` исключают локальный аудит
Windows/Linux/macOS, локальное повышение привилегий, поиск локальных файлов,
облачный аудит и все `self-contained` проверки без выбранной внешней цели.
Единая политика: `security/catalog-scope.json`, реализация: `tools/catalog_scope.py`.
Исходники upstream сохраняются; исключённые файлы остаются только в inventory
`products.json` со статусом `excluded_scope` и причиной. Удалённые клиенты
`code`/`javascript` не исключаются по одному лишь языку исполнения.

WinRM выделен в сервис `WinRM`: `http/technologies/winrm-detect.yaml`.
Четыре локальных WinRM-аудита исключены. OMI не относится к категории WinRM.

Приложение должно предлагать и запускать только записи каталога, а не выполнять
все YAML рекурсивно. При использовании `products.json` выбирать только `checks`,
а не `inventory`; отсутствие записи запрещает включать файл в выборку запуска.
Индекс не гарантирует поддержку движком и не отменяет фильтры воздействия.
Пересборка: `python3 tools/gen_categories.py`, затем `python3 tools/gen_products.py`.

В сервисе `Web` добавлен тип `Path Traversal / LFI`: точные теги `lfi`,
`traversal`, `path-traversal`, `directory-traversal`, соответствующие целые
токены пути/ID и явные названия Path/Directory Traversal, Local File Inclusion,
Arbitrary File Read. Тип добавляется к существующему CVE/DAST/Уязвимости;
воздействие сохраняется. Это метка каталога по исходным обозначениям, а не
доказательство метода каждого шаблона. Проверки подбора остаются только в подборе.

## Реализация MSSQL / SMB / Web LFI в приложении

Актуальный функционал, ограничения и ручной список проверок: [security/external-audit-implementation.md](security/external-audit-implementation.md). Код изменён также в соседнем приложении `../internal`; библиотека сама не реализует UI. Каталог приложения применяет `categories.json` как allowlist. После изменения исходников/правил:

```sh
python3 tools/gen_categories.py
python3 tools/gen_products.py
```

Авторизованный аудит MSSQL читает фиксированные системные представления; произвольный SQL в интерактивной консоли требует AllowExploit. Шаблоны подбора остаются в отдельной категории.

## WinRM

Отдельная категория сетевых проверок WinRM: upstream `winrm-detect` и три собственные challenge-пробы в `nuclei-templates/custom/winrm/`. [Покрытие, ограничения и дальнейшие проверки](security/winrm-checks.md). Локальные `code/windows/audit/winrm-*` не включаются в сетевой каталог.

Локальные исправления проверок доступа к СУБД описаны в [security/database-access-checks.md](security/database-access-checks.md).
