# Реальные образы: сборка и проверка

Workflow `protected-images.yml` запускается вручную в uter_deploy после merge кандидата.
Он читает `candidates/source.json` из того же commit деплоя, а не последнюю ветку Uter.
Исходники скачиваются на временный GitHub-hosted Ubuntu runner; исходный рабочий каталог
и локальный Docker разработчика не используются.

## Этапы

1. Guardrail и Agent собираются отдельно штатными Dockerfile зафиксированного продукта.
   Исходные промежуточные образы остаются на runner и не загружаются в artifacts/registry.
2. Nuitka компилирует собственные runtime-модули. Финальная стадия получает только `.so`,
   зависимости Python и home/cache приложения. Компилятор и исходники не копируются.
3. Финальный образ запускается с `--network none`, non-root, read-only filesystem,
   ограничениями CPU/RAM. Проверяются все скомпилированные модули и OpenAPI schema.
   Guardrail дополнительно загружает реальную toxicity-модель и выполняет inference офлайн.
4. `docker save` экспортирует финальный образ. Сканер проверяет каждый слой, включая
   файлы, удалённые в последующих слоях. Запрещены `.py/.pyc/.pyo`, `.git` и `.env` в `/app`.
   Это структурная проверка, не доказательство невозможности реверса и не полный DLP-аудит.
5. Финальные архивы загружаются в private GitHub artifacts с image ID, SHA архива,
   source commit и результатами проверки. Затем другой runner загружает именно эти
   образы, сверяет image ID и запускает disposable Compose-проект.
6. Integration проверяет readiness, JWT auth, обычный чат, блокировку инъекции и PII,
   OpenAI endpoint, защиту Agent, доступность реальной toxicity-модели, цепочку аудита,
   перезапуск Guardrail и повторные проверки. Redis настоящий, LLM — детерминированный
   HTTP fixture. Внешние RAG/Confluence, качество LLM, TLS и нагрузочные SLO не подтверждаются.

`image-security.yml` принимает успешный run ID сборки, проверяет workflow/conclusion,
сверяет архив и image ID, затем формирует SBOM и Trivy findings. Exit code сканирования
не блокирует получение отчёта: успех workflow аудита не равен отсутствию уязвимостей.
Перед клиентским release все результаты требуют разбора.

## Запуск

```bash
gh workflow run protected-images.yml --repo prince174/uter_deploy
gh run list --repo prince174/uter_deploy --workflow protected-images.yml
gh workflow run image-security.yml --repo prince174/uter_deploy -f build_run_id=RUN_ID
```

Архивы образов сохраняются на 3 дня, интеграционные отчёты на 7 дней, security-отчёты
на 14 дней. Для долгосрочного хранения скачайте artifacts в `dist/` либо перенесите
проверенные образы в приватный registry. Публикация в registry и подпись клиентского
релиза не выполняются этими workflow автоматически.

Docker image ID в отчёте — digest конфигурации образа. Это **не** registry manifest
digest, который требуется `uterctl` для выпуска. Не подставляйте image ID в release
manifest. После push в registry зафиксируйте возвращённый repo digest и проверьте его.

## Ограничения

Helm в основном CI пока проверяется lint/template и контрактными тестами, а не живым
кластером. Успешный Compose integration не заменяет проверку Helm/PVC/NetworkPolicy.
Сценарий restart не является тестом перехода между двумя разными версиями продукта.
Лицензии сторонних библиотек и моделей необходимо сохранить в клиентской поставке.
