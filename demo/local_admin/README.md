# Демо локального анализа

Эта папка содержит практический сквозной сценарий для режима
локального анализа `webconf-audit`.

Демо показывает:

- рабочий сценарий локального администратора;
- передачу основного конфигурационного файла в CLI;
- разрешение include-файлов и наследования от этой точки входа;
- проверку тех же деревьев конфигураций настоящими серверными
  бинарными файлами внутри Docker-контейнеров.

## Покрытые серверы

- Nginx
- Apache HTTP Server
- Lighttpd
- Microsoft IIS

Compose-сервисы (только Nginx, Apache и Lighttpd; для IIS нет Docker-проверки
родным сервером):

- `nginx`
- `apache`
- `lighttpd`

В каждом сценарии используется основной конфигурационный файл и,
если это требуется моделью сервера, дополнительные include-файлы или
артефакты наследования:

- `nginx/nginx.conf`
- `apache/conf/httpd.conf`
- `lighttpd/lighttpd.conf`
- `iis/web.config`
- `iis/machine.config`

## Структура каталогов

```text
demo/local_admin/
|-- docker-compose.yml
|-- README.md
|-- nginx/
|   |-- nginx.conf
|   `-- conf.d/insecure.conf
|-- apache/
|   `-- conf/
|       |-- httpd.conf
|       `-- extra/insecure.conf
|-- apache\htdocs/
|   `-- .htaccess
|-- lighttpd/
|   |-- lighttpd.conf
|   |-- conf.d/insecure.conf
|   `-- docker/Dockerfile
|-- iis/
|   |-- machine.config
|   `-- web.config
`-- reports/
```

## Что намеренно демонстрируется

### Nginx

Основная точка входа: `nginx/nginx.conf`

Подключаемый файл: `nginx/conf.d/insecure.conf`

Ожидаемые находки:

- `nginx.server_tokens_on`
- `nginx.autoindex_on`
- `nginx.if_in_location`

### Apache HTTP Server

Основная точка входа: `apache/conf/httpd.conf`

Подключаемый файл: `apache/conf/extra/insecure.conf`

Дополнительная распределенная конфигурация: `apache\htdocs/.htaccess`

Ожидаемые находки:

- `apache.options_indexes`
- `apache.options_includes_enabled`
- `apache.index_options_fancyindexing_enabled`
- `apache.index_options_scanhtmltitles_enabled`
- `apache.allowoverride_all_in_directory`
- `apache.htaccess_enables_directory_listing`
- `apache.htaccess_enables_cgi`
- `apache.htaccess_disables_security_headers`
- `apache.htaccess_rewrite_without_limit`
- `apache.htaccess_weakens_security`
- `apache.htaccess_contains_security_directive` (3 раза: Options, Options, Header)
- `apache.server_status_exposed`

Демо Apache проверяет не только плоскую глобальную конфигурацию:

- `VirtualHost` с `ServerName` / `ServerAlias`;
- `Location` внутри `VirtualHost`;
- обнаружение `.htaccess` через `DocumentRoot`;
- находки из `.htaccess`, управляемые `AllowOverride`;
- глобальный `/server-status`, заданный через подключаемый файл.

### Lighttpd

Основная точка входа: `lighttpd/lighttpd.conf`

Подключаемый файл: `lighttpd/conf.d/insecure.conf`

Ожидаемые находки:

- `lighttpd.dir_listing_enabled` (из `conf.d/insecure.conf`)
- `lighttpd.weak_ssl_cipher_list` (из `conf.d/insecure.conf`)
- `lighttpd.ssl_honor_cipher_order_missing` (из `conf.d/insecure.conf`)
- `lighttpd.missing_strict_transport_security` (находка по отсутствию настройки)
- `lighttpd.missing_x_content_type_options` (находка по отсутствию настройки)
- `lighttpd.url_access_deny_missing` (находка по отсутствию настройки)
- `lighttpd.mod_status_public` (из `lighttpd.conf`, без ограничения remoteip)
- `lighttpd.access_log_missing` (mod_accesslog загружен без accesslog.filename)
- `lighttpd.max_request_size_missing` (находка по отсутствию настройки)
- `lighttpd.max_connections_missing` (находка по отсутствию настройки)
- `lighttpd.mod_cgi_enabled` (из `lighttpd.conf`)

Демо Lighttpd показывает раскрытие переменных (`var.basedir`), находки
из разных файлов, корректный, но слабый TLS-слушатель на `:8443` с
самоподписанным PEM внутри demo-образа, а также правила, которые
срабатывают при отсутствии директив усиления защиты.

### Microsoft IIS

Основная точка входа: `iis/web.config`

Наследуемая базовая конфигурация: `iis/machine.config`

Docker-проверки родным IIS-сервером нет, потому что IIS не запускается в
Linux-контейнерах. При этом XML-конфигурации IIS проверяются самим
`webconf-audit` как часть локального анализа.

Ожидаемые находки:

- `iis.directory_browse_enabled` (directoryBrowse enabled="true")
- `iis.http_errors_detailed` (errorMode="Detailed")
- `iis.ssl_not_required` (sslFlags="None")
- `iis.ssl_weak_cipher_strength` (sslFlags="Ssl" без Ssl128 в location "api")
- `iis.request_filtering_allow_double_escaping` (allowDoubleEscaping="true")
- `iis.request_filtering_allow_high_bit` (allowHighBitCharacters="true")
- `iis.max_allowed_content_length_missing` (requestLimits без maxAllowedContentLength)
- `iis.logging_not_configured` (dontLog="true")
- `iis.custom_headers_expose_server` (X-Powered-By + X-AspNetMvc-Version)
- `iis.missing_hsts_header` (нет Strict-Transport-Security в customHeaders)
- `iis.asp_script_error_sent_to_browser` (scriptErrorSentToBrowser="true")
- `iis.webdav_module_enabled` (WebDAVModule в коллекции modules)
- `iis.cgi_handler_enabled` (привязка обработчика для CgiModule)
- `iis.custom_errors_off` (customErrors mode="Off")
- `iis.compilation_debug_enabled` (debug="true")
- `iis.trace_enabled` (trace enabled="true")
- `iis.http_runtime_version_header_enabled` (enableVersionHeader="true")
- `iis.forms_auth_require_ssl_missing` (requireSSL="false")
- `iis.session_state_cookieless` (cookieless="UseUri")
- `iis.anonymous_auth_enabled` (комбинация anonymous + basic auth)

Демо IIS покрывает все 20 локальных IIS-правил: проверки атрибутов,
проверки коллекций и дочерних элементов (WebDAV, CGI, пользовательские заголовки),
проверки отсутствующих настроек (HSTS, logging, content length),
межсекционные проверки (комбинация anonymous auth) и находки,
привязанные к location (слабый TLS на пути "api"). Также проверяется
трехуровневая цепочка наследования, используемая анализатором:
`machine.config -> applicationHost.config`-эквивалентная база ->
`web.config`.

## Сценарий Docker Compose

Поднять окружение для проверки:

```powershell
docker compose -f demo/local_admin/docker-compose.yml up -d --build
```

Сервисы используют фиксированные имена Compose и фиксированные имена
контейнеров:

- `nginx` -> `webconf-audit-validation-nginx`
- `apache` -> `webconf-audit-validation-apache`
- `lighttpd` -> `webconf-audit-validation-lighttpd`

Также используется `restart: unless-stopped`, чтобы стенд мог оставаться
запущенным между ручными проверками.

Остановить и удалить контейнеры:

```powershell
docker compose -f demo/local_admin/docker-compose.yml down --remove-orphans
```

## Проверки синтаксиса средствами серверов

Nginx:

```powershell
docker compose -f demo/local_admin/docker-compose.yml run --rm nginx nginx -t -c /etc/nginx/nginx.conf
```

Apache:

```powershell
docker compose -f demo/local_admin/docker-compose.yml run --rm apache httpd -t -f /usr/local/apache2/conf/httpd.conf
```

Lighttpd:

```powershell
docker compose -f demo/local_admin/docker-compose.yml run --rm lighttpd lighttpd -tt -f /etc/lighttpd/lighttpd.conf
```

## Запуск `webconf-audit`

Nginx:

```powershell
.\.venv\Scripts\python.exe -m webconf_audit.cli analyze-nginx .\demo\local_admin\nginx\nginx.conf
```

Apache:

```powershell
.\.venv\Scripts\python.exe -m webconf_audit.cli analyze-apache .\demo\local_admin\apache\conf\httpd.conf
```

Lighttpd:

```powershell
.\.venv\Scripts\python.exe -m webconf_audit.cli analyze-lighttpd .\demo\local_admin\lighttpd\lighttpd.conf
```

IIS:

```powershell
.\.venv\Scripts\python.exe -m webconf_audit.cli analyze-iis .\demo\local_admin\iis\web.config --machine-config .\demo\local_admin\iis\machine.config
```

### JSON-вывод

Все команды `analyze-*` поддерживают `--format json` или `-f json`
для машинно-читаемого вывода:

```powershell
.\.venv\Scripts\python.exe -m webconf_audit.cli analyze-nginx .\demo\local_admin\nginx\nginx.conf --format json
.\.venv\Scripts\python.exe -m webconf_audit.cli analyze-apache .\demo\local_admin\apache\conf\httpd.conf -f json
```

JSON-ответ содержит `generated_at`, `summary`, `results`, `findings`
(отсортированы по серьезности) и `issues` (отсортированы по уровню).

## Вспомогательные скрипты

### Локальный анализ

Для одного воспроизводимого сквозного запуска локального анализа по
файлам:

```powershell
.\scripts\run_local_admin_demo.ps1
```

Скрипт:

1. собирает или скачивает нужные образы;
2. проверяет каждую конфигурацию родным серверным бинарником;
3. запускает три контейнера через Docker Compose;
4. запускает `webconf-audit` по основному конфигурационному файлу
   каждого сервера, включая IIS;
5. генерирует текстовый и JSON-отчет для каждого сервера;
6. сохраняет наблюдаемые результаты в `demo/local_admin/reports/`;
7. оставляет Compose-стенд запущенным для ручной проверки.

### Внешний анализ

Когда Compose-стенд уже запущен, можно проверить серверы снаружи:

```powershell
.\scripts\run_external_demo.ps1
```

Скрипт:

1. проверяет, что Compose-контейнеры запущены;
2. проверяет каждый сервер через `analyze-external localhost:PORT --no-scan-ports`;
3. генерирует текстовый и JSON-отчет для nginx (18080), apache (18081),
   lighttpd (18082);
4. сохраняет отчеты в `demo/local_admin/reports/`.

Так как контейнеры работают на localhost без TLS, TLS-специфичные
находки не появятся. Для локального демо это ожидаемо.

## Результат текущего запуска

Текущий сценарий был выполнен в локальной среде и подтвердил, что:

- все три набора Linux-конфигураций проходят проверку синтаксиса
  родными серверными бинарниками;
- все три контейнера успешно запускаются;
- `webconf-audit` анализирует каждый сценарий от основного пути
  конфигурации;
- находки из подключенных файлов выводятся с путем к подключенному файлу;
- анализ Apache видит глобальную конфигурацию, подключенную конфигурацию,
  `VirtualHost` и `.htaccess` вместе;
- анализ IIS запускается от `web.config` с явным наследованием
  `machine.config`, без Docker.

Наблюдаемые находки в подтвержденном запуске
(серверные + универсальные):

- Nginx: `4 находки / 0 проблем` (3 серверные + 1 универсальная, 1 подавлена)
- Apache: `19 находок / 0 проблем` (14 серверных + 5 универсальных)
- Lighttpd: `16 находок / 0 проблем` (11 серверных + 5 универсальных, 3 подавлены)
- IIS: `20 находок / 0 проблем` (20 серверных + 0 универсальных, 6 подавлены)

Результат IIS выше относится к запуску анализатора по `web.config` и
`machine.config`; это не Docker-проверка работающего IIS-сервера.

Универсальные находки с идентификатором правила, начинающимся на
`universal.`, приходят из слоя нормализации и являются общими для всех
серверов. Они покрывают
TLS-конфигурацию, заголовки безопасности, directory listing, раскрытие
идентификации сервера и аудит адресов прослушивания.

## Проброс портов

Compose-стенд публикует host-порты для внешней проверки:

| Сервис | Порт хоста | Порт контейнера |
|--------|-----------|----------------|
| nginx | 18080 | 80 |
| apache | 18081 | 80 |
| lighttpd | 18082 | 8080 |

Эти порты позволяют `analyze-external` проверять запущенные серверы
с хоста.

## Ограничения

- Это практический demo-сценарий, а не универсальный интеграционный фреймворк.
- Сценарий намеренно покрывает только небольшую часть реализованных правил.
- Сценарий Apache использует минимальную реальную конфигурацию,
  совместимую с текущим парсером, а не полный стандартный `httpd.conf`
  из официального образа.
- Контейнеры работают на localhost без TLS, поэтому TLS-специфичные
  внешние находки не появятся.
