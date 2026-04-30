## Интеграционный слой внешнего анализа

В этом каталоге находится интеграционная проверка конвейера `external`
с использованием Docker.

Область проверки:

- проверка `analyze-external` на запущенных стандартных контейнерах `nginx`,
  `httpd` и `lighttpd`;
- небольшой пользовательский обработчик на Python для детерминированных
  IIS-подобных сигналов и пограничного HTTP-поведения, которое сложно
  воспроизвести только стандартными контейнерами.

Этот слой намеренно отделен от `demo/local_admin/`, который остается
проверкой только локального режима.

Типичные команды:

- PowerShell: `.\.venv\Scripts\python.exe -m pytest -q tests/integration_external`
- POSIX shell: `python -m pytest -q tests/integration_external`
- `docker compose -p webconf_audit_external_it -f tests/integration_external/docker-compose.yml up -d --build`
- `docker compose -p webconf_audit_external_it -f tests/integration_external/docker-compose.yml down -v --remove-orphans`
