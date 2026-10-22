# Uter Deploy

Отдельный репозиторий поставки Uter: Compose, Helm, проверка подписанного комплекта,
обновление и откат. Основной проект `G:\code\uter` используется только для чтения.
Исходники продукта, модели и клиентские секреты сюда не копируются.

## Текущий статус

Реализованы оба deployment backend и контроллер `uterctl.py`. Пример manifest
намеренно не устанавливается: опубликованных и проверенных образов Uter без
исходников ещё нет. Рецепт компиляции находится в `packaging/`, но его совместимость
с реальными ML-зависимостями должна быть проверена на отдельном Linux builder.
Успешные unit/render тесты не означают проверенную установку продукта.

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
