# Проверка кандидата Uter от 23 ноября 2026

Статус: **карантин, выпуск заблокирован**. Образы относятся к исходному коммиту
`fe68f920c69fe982763fb25ba2baf76c95591d10`, который прошёл
[unit-, API- и deployment-тесты](https://github.com/prince174/uter_deploy/actions/runs/45125730842).
Это не опубликованный установочный комплект и не разрешённый путь обновления.

Кандидатные image ID:

- Agent: `sha256:6b5ac0ada89a910efd1084fdd83fda76b2b81c4f9c118eefd583f9c24d266915`.
- Guardrail: `sha256:e7b6410338a911c374b4c97b50d1ded495be2ccdf546fd970f062d9b9a21eb4f`.

[Отчёт сканирования](https://github.com/prince174/uter_deploy/actions/runs/45127748906):
в каждом из двух образов Trivy 0.74.0 обнаружил четыре High, Critical и секреты
не обнаружены. Redis прошёл строгий gate. Результаты без VEX-фильтрации:

- `CVE-2026-119373`, `CVE-2026-119374`, `CVE-2026-119379`: SQLite. В обоих
  образах проверена фактически загруженная SQLite 3.54.1 и SHA-256 библиотеки
  `225ceb839db2c1dd484cfcaa5ef9fbdd429eb1d5f1e0c39fbd50150bca5fc7bc`;
  пакет Debian sid `3.54.1-2`. [Debian security tracker](https://security-tracker.debian.org/tracker/source-package/sqlite3)
  отмечает исправление в sid; Trivy продолжает учитывать эти CVE для trixie.
- `CVE-2026-124709`: установленный `libssl3t64 3.5.9-1~deb13u1`, OpenSSL
  3.5.9. [OpenSSL](https://www.openssl-library.org/news/vulnerabilities/) описывает
  проблему в сервере QUIC; исправление указано для 3.5.10. Trivy классифицирует
  находку как High. Неприменимость к конкретной конфигурации Uter требует
  отдельного подтверждения; текущее правило SQLite её не покрывает. Полный
  upstream patch `22291a6af12f158fbb13bfbd572a33dbdbf290d2`, включая regression
  tests, не применился без изменений к дереву исходного выпуска OpenSSL 3.5.9.
  Проверка применимости патча не является сборкой исправленной библиотеки.

Семантический анализ исходного снимка с Semgrep проверил 80 файлов без ошибок
анализа и сообщил одно предупреждение об urllib в локальном healthcheck:
[результат](https://github.com/prince174/uter_deploy/actions/runs/45126876732).
Semgrep не проверяет скомпилированный код внутри образов.

[Независимая Compose-проверка](https://github.com/prince174/uter_deploy/actions/runs/45128887736)
прошла для этих image ID с тестовым LLM. [Изолированная проверка Kubernetes](https://github.com/prince174/uter_deploy/actions/runs/45130130103)
подтвердила эти же image ID, работу установщика и запросы внутри кластера с тестовым
LLM и временным локальным registry; использован Redis из 0.1.8. Это не проверка
публичного подписанного релиза, реальной LLM или обновления данных.
Экспериментальная проверка протокола обслуживания в Kubernetes
[завершилась ошибкой preflight](https://github.com/prince174/uter_deploy/actions/runs/45129693272);
её нельзя считать подтверждением безопасного обновления.

Строгий security gate оставлен без исключений. До его прохождения или отдельного
явно утверждённого решения по каждому точному образу публикация заблокирована.
