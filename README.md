# Uter Deploy

Отдельный репозиторий поставки Uter: Compose, Helm, проверка подписанного комплекта,
обновление и откат. Основной проект `G:\code\uter` используется только для чтения.
Исходники продукта, модели и клиентские секреты сюда не копируются.

## Текущий статус

Реализованы Compose, Helm и контроллер `uterctl.py`. Реальные Guardrail и Agent
собраны на GitHub-hosted Linux runner из зафиксированного commit продукта.
Проверены загрузка скомпилированных модулей, OpenAPI и офлайн inference toxicity-модели;
проверка всех слоёв не обнаружила собственных Python-файлов в `/app`.
Клиентский релиз ещё не выпущен: security-аудит выявил уязвимости зависимостей,
Compose acceptance и restart прошли; живой Helm и межверсионное обновление ещё не проверены.
Пример manifest остаётся неустанавливаемым.
Доказательства и границы проверок: [проверка образов](docs/image-validation.md).
[Усиление защиты кода и измерение реверса](docs/image-protection.md): полный обход слоёв,
проверка точных копий исходников, явный состав runtime, docstrings и ELF-отчёты.

Первый профиль: Guardrail + Agent + Redis; LLM заказчика подключается по API.
vLLM, LiteLLM, Qdrant, Confluence, GPU-драйверы и PKI здесь не устанавливаются.
Их интеграционные параметры задаёт заказчик. Это не готовый полностью автономный RAG-стенд.

## Файлы

| Каталог | Назначение |
|---|---|
| `compose/` | Самостоятельный Compose без build и доступа к исходникам |
| `charts/uter/` | Helm chart, ClusterIP, NetworkPolicy, PVC |
| `releases/` | Версии продукта и точные digest всех образов |
| `packaging/` | Экспериментальный рецепт компиляции собственных Python-модулей |
| `scripts/` | Подпись комплекта, проверки, watcher, кандидат поставки |
| `examples/` | Шаблоны клиентских настроек без секретов |
| `docs/` | Инструкции поставщика и заказчика |

## Можно ли уже развернуть клиентский пилот?

**Пока нет готового клиентского релиза.** `git clone` и `docker compose up` недостаточно:
в `releases/` находится только неустанавливаемый `example.json`, а не выпущенный manifest.
Архивы CI — кандидаты для проверки, не подписанный комплект установки.

| Проверка | Состояние |
|---|---|
| Реальные Guardrail/Agent без собственных Python-файлов в `/app` | Проверены все слои; runtime прошёл |
| Compose: первый запуск, API/auth, блокировки, аудит, restart | Прошёл в изолированном CI с тестовым LLM |
| Helm | Только lint/template; живой кластер ещё не проверен |
| Security образов | Guardrail: 0 Critical / 44 High; Agent: 5 Critical / 67 High |
| Redis, tooling, все внешние сервисы | Не покрыты двумя отчётами образов Guardrail/Agent |
| Registry, действительный release manifest, подпись и доверенный ключ | Клиентский комплект ещё не выпущен |
| Межверсионное обновление, откат данных, реальный LLM/RAG | Требуют проверки перед соответствующим сценарием пилота |

Состояние и границы аудита с обновлением 26–27.10.2026: [готовность и защита кода](docs/readiness.md).
Счётчики означают findings сканера, а не доказанную эксплуатацию через API.

## Первая установка (после выпуска подписанного комплекта)

1. Получить от поставщика tooling с `uterctl.py`, подписанный bundle, независимый
   публичный ключ, доступ к образам по digest, runtime-политики/профили/модели и acceptance-тест.
   Номера `1.0.0`/`1.1.0` в документации — примеры, а не существующие релизы.
2. Подготовить отдельный Linux amd64 сервер: Python 3.12, Compose >=2.30 либо
   согласованный кластер и Helm 3.17.3. Для Compose текущий лимит Guardrail требует
   минимум 4 логических CPU; сумма лимитов памяти трёх сервисов — 5 GiB, плюс запас
   для ОС и прочих процессов. Это не подтверждённый нагрузочным тестом sizing.
3. Создать `/srv/uter/customer`, заполнить конфигурацию по
   [пошаговой инструкции](docs/customer.md#первая-установка-compose).
   Для Helm использовать раздел [Helm](docs/customer.md#helm), сменить backend в site.json.
4. Проверить доступ к registry и внешнему LLM, настроить TLS, права на секреты,
   постоянные хранилища и клиентский acceptance-тест. Сам репозиторий TLS/LLM не устанавливает.
5. Выполнить `verify`, затем `check` и `apply` с фактическими путями ниже.
6. Проверить клиентский acceptance и внешний TLS endpoint; сохранить исходную
   конфигурацию, публичный ключ и процедуру восстановления.

Из каталога установленного tooling (Linux, пути к уже полученным файлам):

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
# Заменить VERSION на фактическую выпущенную версию.
BUNDLE=/srv/incoming/uter-VERSION
KEY=/etc/uter/publisher.pub
.venv/bin/python uterctl.py verify --bundle "$BUNDLE" --key "$KEY"
.venv/bin/python uterctl.py check --home /srv/uter --bundle "$BUNDLE" --key "$KEY"
.venv/bin/python uterctl.py apply --home /srv/uter --bundle "$BUNDLE" --key "$KEY"
.venv/bin/python uterctl.py status --home /srv/uter
```

При первой установке receipt не нужен; при обновлении существующей — обязателен.
`check` проверяет конфигурацию/рендеринг, но не доступность registry, LLM, Secret/PVC
в Kubernetes и не пригодность резервной копии. `status` не заменяет live health.

## Быстрый старт разработки

Python 3.12, Docker Compose >=2.30 (поддержка raw env_file), Helm 3.17.3.
Helm 4 пока не входит в проверенный контракт контроллера.

```powershell
cd G:\code\uter_deploy
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m unittest discover -s tests -v
.\.venv\Scripts\python scripts/validate_assets.py
```

Последняя команда вызывает только `docker compose config`, `helm lint` и `helm template`.
Docker daemon, кластер и исходный стенд не используются.

## Обновление клиента

Подробно: [инструкция клиента](docs/customer.md).

```bash
python uterctl.py verify --bundle /srv/incoming/uter-1.1.0 --key /etc/uter/publisher.pub
python uterctl.py check --home /srv/uter --bundle /srv/incoming/uter-1.1.0 --key /etc/uter/publisher.pub
python uterctl.py apply --home /srv/uter --bundle /srv/incoming/uter-1.1.0 --key /etc/uter/publisher.pub --backup-receipt /srv/backup/receipt.json
python uterctl.py status --home /srv/uter
python uterctl.py rollback --home /srv/uter --key /etc/uter/publisher.pub --backup-receipt /srv/backup/after-failure.json
```

`verify` проверяет подпись и инвентарь. `check` дополнительно проверяет конфигурацию,
но не подключается к работающим сервисам. `apply` ждёт готовности и запускает
клиентский acceptance-тест. `status` показывает записанное состояние, а не live health.
На ошибке оставляется `pending`; нет ложной отметки об успешном обновлении.

## Изменения основного проекта → проверки → поставка

1. Изменения локальных файлов: [watcher](docs/automation.md) после паузы запускает
   тесты на копии. Ничего не публикует и не меняет в исходном каталоге.
2. Push Uter: workflow этого репозитория проверяет актуальный upstream commit по
   расписанию (после включения), вручную или через `repository_dispatch`.
3. После тестов открывает PR с кандидатом. Совместимость готовых образов и клиентских
   обновлений проверяется до выпуска подписанного комплекта.
4. Клиент выбирает конкретную версию. Автоустановки вслед за push нет.

[Настройка автоматизации](docs/automation.md) · [Выпуск версии](docs/releasing.md)

[Сборка и проверка реальных защищённых образов](docs/image-validation.md)
