# Отчёт индекса продуктов

Генерируется `python3 tools/gen_products.py`; источники локальные, сетевых запросов нет.

## Выполнено

- Полная инвентаризация YAML/YML Nuclei и самостоятельных NSE, включая custom и все протоколы.
- Разбор метаданных/CPE, точных токенов, курируемых исключений; стабильные пути, ID и SHA-256.
- Разделены протокол проверки, порты запроса и затронутый сервис, доказательство и воздействие.
- Курируемые категории применяются обоими генераторами; контракт интеграции и примеры описаны отдельно.

## Покрытие

```json
{
  "inventory_files": 14822,
  "checks": 12251,
  "products": 3930,
  "parse_errors": 0,
  "nselib_lua_files_not_checks": 147,
  "products_with_checks": 3927,
  "by_kind": {
    "nse": 612,
    "nuclei": 11639
  },
  "inventory_status": {
    "non_check": 44,
    "excluded_scope": 2320,
    "indexed": 12251,
    "workflow": 207
  },
  "bindings_by_confidence": {
    "inferred": 4579,
    "curated": 86,
    "explicit": 6333
  },
  "product_status": {
    "unresolved": 3384,
    "bound": 8854,
    "generic": 13
  },
  "issues_by_kind": {
    "ambiguous_token": 1258,
    "multiple_product_bindings": 1433,
    "ambiguous_product_tag": 892,
    "duplicate_source_id": 4
  },
  "unknown": {
    "protocols": 478,
    "request_ports": 959,
    "affected_ports": 12251,
    "affected_protocols": 12175,
    "affected_typical_ports": 12178,
    "account": 12171,
    "privileges": 12250,
    "version": 12191,
    "components": 12184,
    "user_interaction": 12187,
    "evidence": 8219,
    "wscan_support": 12251,
    "brute_force": 11771,
    "exploit": 12124,
    "state_change": 12173,
    "dos": 12155,
    "external_interaction": 11610,
    "authentication_attempts": 12170
  }
}
```

## Исправленные категории и разобранные случаи

- `mikrotik-winbox-differential` (1 файлов): CVE-2024-54772 NSE: три пары candidate/control, без словаря и паролей; прямой oracle, попытки аутентификации. Исправлено brute → vuln,auth и активное воздействие.
- `mikrotik-winbox-dictionary` (1 файлов): username-brute читает словарь и делает запрос для каждого имени; остаётся только в подборе, сильное воздействие.
- `vendor-version-impact` (38 файлов): Сгенерированные vendor-version шаблоны делают GET и сравнение версии; обнаружение потенциального риска, а не активное подтверждение CVE.
- `kyocera-wsdl` (1 файлов): GET выбранного HTTP(S) WSDL, namespace и операции; доступный интерфейс, не подтверждение CVE. Канонизированы net_viewer/net-viewer.
- `kyocera-export` (1 файлов): CVE-2022-1026 SOAP POST создаёт экспорт: exploit и state_change=true, сильное воздействие; matcher SOAP/200 не доказывает успешный экспорт.
- `mikrotik-ssh-banner` (1 файлов): ROSSSH fingerprint относится к RouterOS SSH; не разрешает WinBox/API/WebFig на SSH. Исходный port:22 требует сверки с выбранным сервисом.
- `mikrotik-api` (1 файлов): Бинарный API probe, не HTTP REST; ответ not logged in обнаруживает интерфейс, не CVE. Фиксированный 8728 требует контроля порта.
- `mikrotik-webfig` (1 файлов): HTTP интерфейс RouterOS; upstream AND требует одновременно old-router/Hotspot/proxy признаки и может пропускать обычный WebFig. Не подтверждает доступность других компонентов.
- `gitlab-login-panel` (1 файлов): GitLab login panel GET; относится к GitLab CE/EE, не AI Gateway и не SSH. Редиректы требуют контроля выбранного сервиса.
- `windows-winrm` (1 файлов): HTTP /wsman и auth headers — предположение WinRM, не доказательство DC; типичные 5985/5986 не ограничивают выбранный HTTP порт.
- `windows-ms17-010` (1 файлов): smb-vuln-ms17-010 отправляет SMB транзакцию и анализирует STATUS_INSUFF_SERVER_RESOURCES; Windows SMB, не доказательство DC; hostrule выбирает порт через smb library.
- `krb5-enum-users-dictionary` (1 файлов): unpwdb.usernames(), цикл по словарю и AS-REQ; нужны REALM и отдельный выбор подбора. Исправлена категория auth/intrusive → только brute.
- `smtp-enum-users-dictionary` (1 файлов): unpwdb.usernames() и цикл SMTP VRFY/EXPN/RCPT по именам; словарный подбор, только brute.
- `http-userdir-enum-dictionary` (1 файлов): datafiles usernames.lst, цикл HEAD/GET /~username; словарь логинов, только brute.
- `generic-protocol-checks` (12 файлов): SMB/LDAP/RDP/TLS/SSH/HTTP общие проверки не получают выдуманный продукт; Windows fingerprint не доказывает DC, LDAP не означает AD.
- `mikrotik-version-impact` (22 файлов): RouterOS GET version checks: потенциально по версии; обнаружение, не прямое подтверждение и не запуск затронутого протокола.
- `CVE-2024-54772-affected-service` (1 файлов): CVE-2024-54772: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2024-54952-affected-service` (1 файлов): CVE-2024-54952: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2025-6443-affected-service` (1 файлов): CVE-2025-6443: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2023-47310-affected-service` (1 файлов): CVE-2023-47310: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2025-6563-affected-service` (1 файлов): CVE-2025-6563: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2025-10948-affected-service` (1 файлов): CVE-2025-10948: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2025-61481-affected-service` (1 файлов): CVE-2025-61481: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2026-7668-affected-service` (1 файлов): CVE-2026-7668: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2026-39042-affected-service` (1 файлов): CVE-2026-39042: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2026-67276-affected-service` (1 файлов): CVE-2026-67276: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2026-67277-affected-service` (1 файлов): CVE-2026-67277: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2026-67278-affected-service` (1 файлов): CVE-2026-67278: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2026-67279-affected-service` (1 файлов): CVE-2026-67279: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2026-67281-affected-service` (1 файлов): CVE-2026-67281: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2026-86060-affected-service` (1 файлов): CVE-2026-86060: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2026-89020-affected-service` (1 файлов): CVE-2026-89020: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2026-89021-affected-service` (1 файлов): CVE-2026-89021: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2026-56719-affected-service` (1 файлов): CVE-2026-56719: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2026-89028-affected-service` (1 файлов): CVE-2026-89028: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2026-52346-affected-service` (1 файлов): CVE-2026-52346: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2026-93345-affected-service` (1 файлов): CVE-2026-93345: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `CVE-2024-27686-affected-service` (1 файлов): CVE-2024-27686: протокол и типичные затронутые порты из локального security/vendor-cves.json; входящий HTTP GET остаётся отдельным. Типичные порты не ограничивают выбор цели.
- `mssql-core-tds-bindings` (12 файлов): MSSQL helper/TDS requests identify SQL Server Database Engine; Browser/HTTP interfaces are separate. Source reviewed; runtime untested.
- `mssql-hashdump-impact` (1 файлов): SELECT SQL login password hashes exposes credential material; upstream safe does not make this ordinary discovery. Requires explicit exploitation choice.
- `mssql-config-state-change` (1 файлов): Script creates/inserts/drops a temporary SQL table; native audit reads sys.configurations directly instead.
- `mssql-arbitrary-query-impact` (1 файлов): Default query reads version, but operator script argument permits arbitrary SQL, including state changes; execution is gated with AllowExploit.
- `mssql-xp-cmdshell-impact` (1 файлов): Script executes an OS command via xp_cmdshell (default ipconfig /all); not a read-only configuration check.
- `mssql-browser-interface` (1 файлов): SQL Browser SSRP is UDP discovery; advertised instance ports are observations, not permission to connect to them.
- `smb-anonymous-read-only` (1 файлов): Local adaptation uses ListSharesReadOnly and an empty username/password; root directory reads only, no write test. Requested null identity may be mapped/rejected by the server; negotiated mode not exposed.
- `winrm-network-audit` (3 файлов): Сетевые WinRM challenge-пробы: объявленная конфигурация, без входа, делегирования и подтверждения CVE.
- `winrm-basic-http-category` (1 файлов): Basic challenge на HTTP — потенциально опасная конфигурация, без проверки пароля.
- `database-noauth-probes` (2 файлов): Выделенные проверки без пароля: PostgreSQL AuthenticationOk до запроса пароля; Redis INFO без AUTH.
- `database-empty-password-probes` (3 файлов): Точный пустой пароль; PostgreSQL учитывает запрос аутентификации, Redis действительно отправляет AUTH пустой строкой.
- `database-empty-password-nse` (2 файлов): Нативная проверка конкретных пустых паролей вместо неподдерживаемого/устаревшего NSE-клиента.
- `elasticsearch-rest-credentials` (1 файлов): REST API Elasticsearch; перед попытками требуется 401 без учётки, успешный ответ подтверждает elastic.

## Ошибки и неоднозначности

Полный перечень путей, ошибок разбора, конфликтов CPE/metadata, неоднозначных токенов и дублированных upstream ID: [product-index-issues.json](product-index-issues.json). Ошибочные файлы остаются в inventory, а не исчезают.

## Ограничения и оставшаяся работа

- Это полная автоматизированная инвентаризация, а не ручная верификация поведения каждой проверки. Вручную разобраны перечисленные курируемые случаи. Остальные сведения по тегам имеют inferred/unknown.
- Непривязанные проверки разделены на явно общие и unresolved. Unresolved нельзя объявлять общими или безопасными.
- У неоднозначных привязок остаются все кандидаты. Несколько CPE/metadata не доказывают, что запрос подходит каждому продукту.
- Внешние источники не загружались; ссылки взяты из локальных шаблонов и ранее подготовленного CVE-среза. Диапазоны перенесены со ссылкой на этот срез; их свежесть заново не проверялась.
- Порты из TCP YAML сохраняются как source_literal, а не как разрешение переходить на соседний сервис. Lua не исполняется; portrule хранится буквально, hostrule/global запрещают обычную рекомендацию для сервиса.
- Теги safe и severity не доказывают отсутствие побочных эффектов. Неизвестные флаги воздействия остаются null. Общая классификация остальных исходных категорий сохранена и требует дальнейшего курирования.
- Поведение requirements/components и affected_service.description может оставаться исходным текстом; потребитель не должен превращать текст или типичный порт в машинное условие.
- Код основного wscan здесь отсутствует: поддержка движка везде unknown. Нужны capability handshake, контроль выбранного сервиса, фильтры воздействия и отображение доказательств; см. [product-index-integration.md](product-index-integration.md).
- Каталог внешних целей исключает локальные, облачные и self-contained проверки по security/catalog-scope.json; причины сохранены в inventory (excluded_scope).
- Файлы workflow/profile/helper/config включены в inventory отдельно от исполняемых проверок; nselib — библиотеки.
- Ручные CVE-позиции без диапазона не создают проверок и рекомендаций (включая GitLab AI Gateway).
- Дальше: вручную разобрать unresolved и конфликты, установить неизвестные требования/порты/воздействие, подключить индекс в wscan. Эти неизвестные факты невозможно достоверно установить эвристикой.

## Выполненные действия

Чтение исходников и генерация products.json/categories.json. Тесты, сборка, запуск шаблонов, NSE и обращения к целевым устройствам не выполнялись. Коммит и публикация не выполнялись.
