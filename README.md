# webconf-audit

Инструмент для аудита безопасности конфигураций веб-серверов.

`webconf-audit` поддерживает два независимых режима анализа:

- **Локальный** - статический анализ конфигурационных файлов на хосте,
  где работает веб-сервер.
- **Внешний** - проверка запущенного веб-узла методом черного ящика через
  наблюдаемые HTTP, HTTPS и TLS-признаки.

## Поддерживаемые серверы

Локальный анализ поддерживает четыре веб-сервера:

- Nginx
- Apache HTTP Server
- Lighttpd
- Microsoft IIS

## Установка

### Windows

1. Установите Python 3.10 или новее с
   [python.org](https://www.python.org/downloads/windows/) и включите
   опцию "Add python.exe to PATH" во время установки.
2. Установите [Git for Windows](https://git-scm.com/download/win).
3. Откройте PowerShell и склонируйте репозиторий:

```powershell
git clone https://github.com/armanersultanov8-cmd/webconf-audit.git
cd webconf-audit
```

4. Создайте и активируйте виртуальное окружение:

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Если PowerShell блокирует запуск скриптов активации в текущей сессии,
выполните:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

5. Установите пакет и проверьте, что команда доступна:

```powershell
python -m pip install --upgrade pip
pip install .
webconf-audit --help
```

### Linux

1. Установите Python 3.10 или новее, `venv`, `pip` и Git. Для
   Debian/Ubuntu:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip git
```

2. Склонируйте репозиторий:

```bash
git clone https://github.com/armanersultanov8-cmd/webconf-audit.git
cd webconf-audit
```

3. Создайте и активируйте виртуальное окружение:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

4. Установите пакет и проверьте, что команда доступна:

```bash
python -m pip install --upgrade pip
pip install .
webconf-audit --help
```

Пакет добавляет консольную команду `webconf-audit`. Все команды также
можно запускать через `python -m webconf_audit.cli`.

## Быстрый старт

### Локальный анализ

```bash
webconf-audit analyze-nginx /etc/nginx/nginx.conf
webconf-audit analyze-apache /etc/apache2/httpd.conf
webconf-audit analyze-lighttpd /etc/lighttpd/lighttpd.conf
webconf-audit analyze-iis C:\inetpub\wwwroot\web.config
```

### Внешний анализ

```bash
webconf-audit analyze-external https://example.com
webconf-audit analyze-external example.com --ports 80,443,8443
webconf-audit analyze-external example.com --no-scan-ports
```

### Форматы вывода

Каждая команда `analyze-*` поддерживает текстовый вывод по умолчанию
и JSON:

```bash
webconf-audit analyze-nginx config.conf --format json
webconf-audit analyze-external example.com -f json
```

JSON-ответ содержит время генерации, сводку, результаты по целям,
дедуплицированный список находок и список технических проблем.

## Процесс локального анализа

Каждый локальный анализатор:

1. Читает основной конфигурационный файл, переданный в командной строке.
2. Разрешает include-файлы или восстанавливает цепочку наследования.
3. Строит эффективную конфигурацию, если этого требует модель сервера.
4. Запускает серверные правила по разобранной или эффективной форме.
5. Запускает универсальные правила по нормализованному представлению,
   общему для всех четырех серверов.
6. Возвращает структурированный результат с находками, техническими
   проблемами и метаданными источника.

Что обрабатывают анализаторы:

- **Nginx** - токенизатор, парсер, разрешение `include` с поддержкой
  glob-шаблонов и обнаружением циклов, обход AST, привязка каждой
  директивы к исходной строке.
- **Apache** - `Include` и `IncludeOptional`, поиск `.htaccess` через
  блоки `Directory` и `DocumentRoot`, фильтрация по `AllowOverride`,
  отдельные контексты анализа для `VirtualHost`, слои `Location` и
  `LocationMatch`, семантика объединения заголовков.
- **Lighttpd** - раскрытие переменных, разрешение `include`,
  обработка `include_shell` (по умолчанию пропускается с предупреждением),
  условные блоки вида `$HTTP["host"] == "..."`, опциональный
  таргетированный анализ по хосту через `--host`.
- **IIS** - безопасный XML-парсинг через `defusedxml`, трехуровневая
  цепочка наследования `machine.config` -> `applicationHost.config` ->
  `web.config`, семантика коллекций `<add>` / `<remove>` / `<clear>`,
  наследование `<location>`, опция `--machine-config` для явного выбора
  базовой конфигурации.

Каждая находка содержит серьезность, описание, рекомендацию по
исправлению и ссылку на источник: файл и строку для текстовых
конфигураций, файл и XML-путь для IIS, наблюдаемую конечную точку или
заголовок для внешнего режима.

## Внешний анализ

Внешний режим проверяет цель без доступа к ее конфигурации. Он выполняет:

- Поиск портов для целей, заданных только доменным именем или IP
  (порты по умолчанию: 80, 443, 8080, 8443, 8000, 8888, 3000, 5000,
  9443; список можно изменить через `--ports` или отключить через
  `--no-scan-ports`).
- HTTP- и HTTPS-проверки с резервным переходом `HEAD` -> `GET`, а также
  отдельный поток `OPTIONS`.
- Анализ TLS-параметров: согласованный протокол и шифр, поддерживаемые версии
  TLS, полнота цепочки сертификатов, извлечение SAN.
- Определение сервера по заголовкам ответа, стандартным страницам
  ошибок и реакции на намеренно некорректные запросы.
- Проверку чувствительных путей, например `/.git/HEAD`, `/.env`,
  `/.htaccess`, `/phpinfo.php`, `/web.config`, `/robots.txt`,
  `/sitemap.xml`.
- Анализ цепочек редиректов: циклы, смена схемы, переходы на другой
  домен.

Внешние правила покрывают доступность HTTPS и HSTS, распространенные
заголовки безопасности, раскрытие информации о сервере, cookies, CORS,
HTTP-методы, чувствительные пути, версии TLS-протоколов и валидность
сертификатов.

## Каталог правил

Каталог правил можно просмотреть через CLI:

```bash
webconf-audit list-rules
webconf-audit list-rules --category local --server-type nginx
webconf-audit list-rules --severity high --tag tls
```

Фильтры: `--category` (`local`, `external`, `universal`),
`--server-type` (`nginx`, `apache`, `lighttpd`, `iis`),
`--severity` (`critical`, `high`, `medium`, `low`, `info`),
`--tag`.

Сейчас каталог содержит 183 правила:

| Категория | Правил |
|-----------|------:|
| Локальные - Nginx | 41 |
| Локальные - Apache | 27 |
| Локальные - Lighttpd | 15 |
| Локальные - IIS | 20 |
| Универсальные (локальные) | 11 |
| Внешние | 69 |

## Отчетность

Результаты собираются в структуру `ReportData` со сводкой по
серьезности, режиму анализа и типу сервера. Доступны два форматтера:

- `TextFormatter` - человекочитаемый вывод для командной строки.
- `JsonFormatter` - машинно-читаемый вывод для дальнейшей обработки.

Находки универсальных правил дедуплицируются, если более конкретное
серверное правило уже сообщило о той же проблеме в том же месте.

## Демо

Рабочий demo-стенд для локального анализа с воспроизводимыми
проверками синтаксиса на базе Docker находится в `demo/local_admin/`.
Полное описание запуска см. в
[demo/local_admin/README.md](demo/local_admin/README.md).

## Разработка

Запустить тесты:

```bash
pytest -q
```

Запустить линтер:

```bash
ruff check .
```
