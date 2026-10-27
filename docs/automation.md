# Автоматизация без изменений основного репозитория

## Локальные файлы

Watcher запускается вручную, не устанавливает службу и не запускает контейнеры:

```powershell
cd G:\code\uter_deploy
python scripts/watch_source.py --source G:\code\uter\llm-guardrail --command-json examples/watch-command.json
```

Для единичной проверки добавьте `--once`. Ctrl+C останавливает watcher.
Изменение учитывается после 10 секунд тишины. Одновременно работает один процесс;
последующие изменения проверяются после завершения текущего запуска. Состояние и логи
в `work/watch`, этот каталог не коммитится. Снимки сохраняются для диагностики;
очищайте старые снимки после проверки отсутствия активных процессов.

Команда тестов из JSON запускается в снимке, не в Uter. Укажите абсолютный путь Python
из отдельного test venv и установите туда requirements продукта и requirements-test.txt.
Пример использует python из PATH и абсолютный путь к scripts/check_source.py в uter_deploy.
Если репозиторий расположен иначе, измените этот путь. Helper запускает unit и API
тесты отдельными процессами, как штатный CI продукта, чтобы их mocks не смешивались.
Watcher не устанавливает зависимости автоматически.
Он отслеживает текстовые исходники и конфигурацию, включая неигнорируемые новые файлы;
игнорирует .env, certs, secrets, logs, models, venv и symlink.
Он не отслеживает веса моделей и не подтверждает воспроизводимость dirty-снимка.
Проверки продукта могут обращаться к сети, если это предусмотрено самими тестами.

Watcher не пушит коммиты и не передаёт незакоммиченный код GitHub. Для следующего этапа
разработчик коммитит и пушит Uter обычным способом.

## GitHub Actions

Весь workflow находится в `uter_deploy/.github/workflows/source-sync.yml`.
Путь к исходному репозиторию фиксирован: prince174/uter; ветка по умолчанию master.
Параметр SOURCE_REF может указывать доверенную ветку или release tag.

Настройка один раз:

1. Создать fine-grained PAT, ограниченный `prince174/uter`, Contents: Read-only.
2. В uter_deploy → Settings → Secrets and variables → Actions добавить secret
   `SOURCE_READ_TOKEN`. Токен не писать в файлы или сообщения.
3. Для периодического запуска добавить repository variable `SOURCE_SYNC_ENABLED=true`.
   Workflow проверяет upstream примерно раз в час (GitHub может задерживать расписание).
4. Разрешить GitHub Actions создавать pull requests в настройках Actions → General.

Для проверки без расписания: Actions → Test upstream and propose deployment candidate → Run workflow.
Либо `gh workflow run source-sync.yml --repo prince174/uter_deploy`.

Событие `repository_dispatch` с типом `uter-source-updated` также поддерживается.
Payload не исполняется и не выбирает произвольный repo: берётся SOURCE_REF.
Отправитель должен иметь отдельные права на dispatch в uter_deploy. В основной проект
никакие hooks/workflow сейчас не добавлены.

Workflow читает точный SHA, проверяет unit/API тесты Uter в чистом checkout и проверки
деплоя в отдельном job. Только затем другой job с write-правами создаёт ветку/PR
`automation/source-<sha>`. Продуктовые тесты не получают write-token и ключ подписи.
После merge SHA считается обработанным. Если PR уже существует, второй не создаётся.
Повторные проверки до merge возможны; это не выпуск новой версии операторам.

PR от GITHUB_TOKEN может не запустить следующий workflow автоматически; поэтому
обязательные deployment-проверки вызываются прямо в source-sync до создания PR.
Для обычного CI есть push, pull_request и ручной запуск.

## От PR до обновления оператора

1. Source-sync читает точный commit Uter и запускает unit/API + deployment checks.
2. PR меняет `candidates/source.json`: это выбор исходной версии для сборки,
   а не выпуск продукта. Merge фиксирует этот выбор и не обновляет локальные стенды.
3. Оператор запускает `protected-images.yml`. Временные GitHub runners собирают
   и компилируют продукт, сохраняют только финальные образы и доказательства проверок.
4. `verify-image-artifacts.yml` повторно проверяет точные сохранённые образы;
   `image-security.yml` формирует SBOM и отчёты. Ошибка не превращается в release.
   При необходимости dependency overlay создаёт новые image ID, которые проверяются заново.
5. После разбора security findings, проверки Compose/Helm и upgrade/rollback
   сопровождающий публикует образы в registry, фиксирует реальные manifest digest,
   назначает версию комплекта и подписывает его по `releasing.md`.
6. Оператор получает комплект, проверяет подпись, конфигурацию и совместимость,
   делает резервную копию и запускает `uterctl apply`. Контроллер использует выбранный
   backend Compose/Helm и ждёт readiness и локального acceptance-теста.
   При ошибке сохраняется pending; откат выполняется явно по инструкции.

Сейчас автоматически выполняется обнаружение upstream и создание кандидата.
Сборка и повторная проверка запускаются вручную. Публикация registry,
подпись выпуска и установка у оператора не запускаются вслед за merge.
Изменение локального файла само по себе также не создаёт локальный релиз.
Версия комплекта и версия шаблонов Helm независимы; commit продукта и digest
образов входят в состав конкретного неизменяемого комплекта.

Официальная документация:
- https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow
- https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
