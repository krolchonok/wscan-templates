# WinRM: сетевое покрытие и план аудита

Обновлено 2026-10-05. Категория сервиса **WinRM** в wscan; стандартные TCP 5985
(HTTP), 5986 (HTTPS), нестандартный порт задаётся выбранным сервисом.
Проверки не переключаются на соседний порт и не отправляют учётные данные.

## Реализовано

| ID | Метод и доказательство | Вывод и ограничение |
| --- | --- | --- |
| `winrm-detect` (upstream) | POST `/wsman`, 401, Microsoft-HTTPAPI, NTLM/Negotiate | Обнаружение; строгий upstream matcher может пропустить другие auth-конфигурации |
| `microsoft-winrm-auth-methods` | Один POST `/wsman`, 401, Microsoft-HTTPAPI, WWW-Authenticate | Объявленные методы; именованный extractor `advertised-authentication` |
| `microsoft-winrm-basic-over-http` | Те же признаки + Basic + HTTP URL | Потенциально опасное предложение Basic без TLS; не доказательство AllowUnencrypted или принятия пароля; IPsec неизвестен |
| `microsoft-winrm-credssp-advertised` | Те же признаки + CredSSP | Информационный результат: проверить необходимость делегирования; не доказательство CVE |

Новые проверки: HTTP-протокол, без аккаунта/прав, по одному запросу,
редиректы отключены, `max-size: 65536`, таймаут/повторы задаются настройками скана.
Нет входа, создания shell, команд, изменения состояния и внешних запросов.
Методы поддерживаются штатными HTTP matcher/extractor/DSL приложения;
совместимость с настоящей Windows пока не проверена.
Прокси, иной URL prefix, скрытый Server header и фильтрация дают пропуски.
Отсутствие результата не означает безопасную конфигурацию.

HTTP сам по себе не равен незашифрованному WinRM: NTLM/Kerberos могут защищать
сообщения. Заголовок Negotiate не доказывает использование Kerberos.
Объявление NTLM не доказывает успешную relay-атаку, отсутствие CBT/EPA или
применённой политики. Basic по HTTPS не отмечается Basic-over-HTTP проверкой.

## Что ещё имеет смысл проверять

| Проверка | Как подтверждать | Статус |
| --- | --- | --- |
| TLS версии, слабые шифры, сертификат, срок и имя | TLS handshake к выбранному HTTPS listener; учитывать имя подключения | Использовать существующую категорию TLS / SSL на том же порту; отдельные копии общих проверок не созданы |
| `AllowUnencrypted=True` | С предоставленной учёткой прочитать `WSMan:\localhost\Service\AllowUnencrypted` | Требует отдельного удалённого read-only аудита; сетевой challenge не подтверждает |
| Basic/CredSSP реально включены | Прочитать `WSMan:\localhost\Service\Auth`; сопоставить с выбранным listener | Следующий этап с учёткой; не отправлять Basic-пароль по HTTP |
| CBT / Extended Protection | Прочитать `WSMan:\localhost\Service\CbtHardeningLevel`, политики и transport | Следующий этап с учёткой; ослабление политики — риск, не доказательство relay |
| Избыточные права remoting | ACL PowerShell endpoints, SDDL, группы Remote Management Users/Administrators, JEA/RunAs | Следующий этап с учёткой; учитывать право чтения и назначение endpoint |
| Слишком широкая доступность | Listener Address, ListeningOn, IPv4/IPv6Filter и эффективные firewall rules | Следующий этап с учёткой; `*` отдельно не доказывает доступность извне |
| `TrustedHosts=*` | Читать клиентскую настройку только на целевой Windows | Риск исходящих соединений этой Windows; не свойство серверного listener |
| Remote shell разрешён | Читать AllowRemoteShellAccess | Нормальная функция remoting; информационный результат, не уязвимость сама по себе |
| CVE-2018-0886 (CredSSP) | Сверить ОС, обновления и политику Encryption Oracle Remediation с advisory Microsoft | Не реализована; CredSSP header не подтверждает отсутствие патча |
| CVE HTTP.sys, включая CVE-2021-31166 | Сверить точный Windows build, применимые обновления и наличие затронутого компонента | Не реализованы; Microsoft-HTTPAPI/2.0 не является версией ОС; crash/RCE пробы не добавлены |

Локальные upstream `code/windows/audit/winrm-*` сохранены, но исключены из
сетевого каталога: они проверяют Windows, на которой выполняется PowerShell,
а не автоматически выбранный удалённый хост. Для удалённого аудита нужен
явный запуск фиксированных read-only команд через авторизованный WinRM-сеанс.
Ошибки доступа/разбора должны быть UNKNOWN, а не «настройка безопасна».
Подбор остаётся в отдельном режиме подбора учётных данных.

## Источники

- [Microsoft: безопасность PowerShell Remoting](https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/winrmsecurity)
- [Microsoft: аутентификация WinRM](https://learn.microsoft.com/en-us/windows/win32/winrm/authentication-for-remote-connections)
- [Microsoft: конфигурация WinRM](https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)
- [Microsoft: Basic вместе с AllowUnencrypted](https://devblogs.microsoft.com/powershell/compromising-yourself-with-winrms-allowunencrypted-true/)
- [Microsoft: CredSSP / CVE-2018-0886](https://support.microsoft.com/en-US/servicing/os/windows-server/2019/09/credssp-updates-for-cve-2018-0886)
- [Microsoft: CVE-2021-31166](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31166)

## Выполненная проверка

Пересобраны индексы категорий и продуктов (ошибок разбора: 0), собран `wscan`.
Пройдены Go-тесты приложения: catalog, discovery, workflow, tui; добавлена
регрессионная проверка группировки WinRM и приоритета известного протокола над портом.
Тесты шаблонов и сканы на устройствах не выполнялись.
