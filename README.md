# Uter Deploy

Отдельный репозиторий развёртывания Uter: Compose, Helm, проверка подписанного комплекта,
обновление и откат. Основной проект `G:\code\uter` используется только для чтения.
Исходники продукта, модели и локальные секреты сюда не копируются.

## Автоматическая первая установка

Установщик `scripts/install.py` готовит Compose или Kubernetes/Helm из одинаковых
параметров. Три шага: **prepare → check → install**. По умолчанию ничего не запускается.
Команды ниже выполняются на отдельном Linux amd64 сервере или Linux-машине управления
кластером. Нужны Python 3.11+ (рекомендуется 3.12), для Compose — Docker и Compose >=2.30,
для Kubernetes — kubectl, Helm 3.17.3, рабочий kubeconfig, доступ к registry и StorageClass.
Для Compose: минимум 4 логических CPU, лимиты контейнеров суммарно 5 GiB RAM плюс ОС.

### Что нужно получить заранее

- Три опубликованных образа Guardrail, Agent, Redis с **настоящими registry digest**.
  Docker image ID из `docker load` не является registry digest. Теги `latest` не принимаются.
- `policy.toml` и `model_profiles.toml` из runtime-артефактов той же сборки.
  Установщик проверяет TOML-синтаксис; семантическая совместимость проверяется сервисом.
- Адрес OpenAI-совместимого LLM, имя модели и API-ключ, если он требуется.
  Например, base URL `https://llm.example/v1`; `/chat/completions` добавляет сервис.
  Локальный LLM, RAG, GPU, TLS и загрузка дополнительных моделей не устанавливаются.
- Защищённые образы с встроенной toxicity-моделью. Установщик использует offline-режим;
  каталог `/app/models` пустой. Для дополнительных моделей настройте отдельное хранилище
  по [расширенной инструкции](docs/deployment.md).

**Registry-релиз пока не опубликован.** Установщик уже можно проверять и готовить,
но установка требует доступных образов. Он не объявляет архивы CI выпущенным релизом
и не заменяет проверку подписи: для управляемого обновления используется `uterctl.py`.
При прямой первой установке доверие к digest и runtime-файлам проверяется оператором.
Известные findings образов и границы тестирования перечислены ниже.

```bash
git clone https://github.com/prince174/uter_deploy.git
cd uter_deploy
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

В `/srv/incoming/images.json` сохраните объект следующей формы, заменив **все** значения
реальными digest. Этот пример намеренно не устанавливается:

```json
{
  "guardrail": "REGISTRY/uter-guardrail@sha256:REAL_DIGEST",
  "agent": "REGISTRY/uter-agent@sha256:REAL_DIGEST",
  "redis": "REGISTRY/redis@sha256:REAL_DIGEST"
}
```

### Compose: подготовить и запустить

Выполняйте из корня checkout. Для bind-mount установщик поддерживает только локальный
Docker context `default` с Unix socket. Имя проекта должно быть новым; существующие
контейнеры, сети или volumes с тем же Compose project запрещены.

```bash
sudo .venv/bin/python scripts/install.py prepare \
  --home /srv/uter-instance --backend compose --name uter-instance \
  --images /srv/incoming/images.json \
  --policy /srv/incoming/policy.toml \
  --profiles /srv/incoming/model_profiles.toml
```

Мастер спросит адрес LLM, имя модели и скрыто API-ключ. Для сервиса без авторизации
оставьте API-ключ пустым. В доверенной внутренней сети HTTP требует `--allow-http-llm`.
Для автоматизированного запуска задайте `--llm-url`, `--llm-model` и `--llm-key-file`
с путём к защищённому файлу; секрет не помещается в аргументы процесса.
`--port 18000` задаёт локальный HTTP-порт (это значение по умолчанию).

```bash
sudo .venv/bin/python scripts/install.py check --home /srv/uter-instance
# Для приватного registry выполните docker login в том же контексте пользователя root.
# Используйте --password-stdin; пароль не помещайте в командную строку.
sudo .venv/bin/python scripts/install.py install --home /srv/uter-instance
curl --fail http://127.0.0.1:18000/ready
```

`check` только рендерит конфигурацию, не обращается к Docker daemon/LLM и не запускает
контейнеры. `install` скачивает три образа, выставляет права bind-mount файлов,
запускает сервисы и ждёт readiness до 300 секунд. Исходники не нужны, сборки отсутствуют.
Доступ снаружи настройте через TLS reverse proxy; порт слушает только `127.0.0.1`.

### Kubernetes: подготовить и запустить

Используйте **новый namespace**, равный `--name`, и явный `--context` из kubeconfig.
Установщик не переключает текущий context и отказывается использовать существующий
namespace. Права нужны на создание namespace, Secret, ConfigMap, PVC, Deployment,
Service и NetworkPolicy. CNI должен поддерживать NetworkPolicy, узлы — linux/amd64.

```bash
.venv/bin/python scripts/install.py prepare \
  --home "$HOME/uter-k8s" --backend kubernetes --name uter-instance \
  --context MY_CONTEXT \
  --images /srv/incoming/images.json \
  --policy /srv/incoming/policy.toml \
  --profiles /srv/incoming/model_profiles.toml \
  --storage-class MY_STORAGE_CLASS
.venv/bin/python scripts/install.py check --home "$HOME/uter-k8s"
.venv/bin/python scripts/install.py install --home "$HOME/uter-k8s"
kubectl --context MY_CONTEXT -n uter-instance get pods,pvc
kubectl --context MY_CONTEXT -n uter-instance port-forward svc/uter-instance-guardrail 18000:8000
# В другом терминале:
curl --fail http://127.0.0.1:18000/ready
```

Если в кластере есть default StorageClass, `--storage-class` можно опустить. Создаются
PVC для Redis (2 GiB) и аудита (10 GiB); модель читается из образа, отдельный models PVC
не нужен. Для приватного registry добавьте к `prepare`
`--registry-config /secure/registry-config.json`: отдельный Docker config.json с inline
`auths` для нужного registry. Он превращается в imagePullSecret нового namespace;
внешние credential helpers не поддерживаются. Не передавайте общий конфиг со всеми
вашими registry. Для публичных образов этот параметр не нужен.

Установщик создаёт namespace и ресурсы, затем запускает Helm install с ожиданием 5 минут.
ClusterIP доступен внутри кластера; для внешнего доступа настройте Ingress/TLS в namespace
`ingress-nginx` либо измените `ingressNamespace` в сгенерированном `values.yaml` до установки.
Настройки Secrets уже включают LLM: изменяйте одноимённые поля `guardrailEnv` согласованно,
поскольку явный `env` в Deployment имеет приоритет над `envFrom`.
Живой кластер в этой работе не запускался: проверены генерация, Helm lint/template и
контракты, а не интеграция с конкретным CSI/CNI/registry.

### Что генерируется и как хранить

В `--home` создаются `runtime/`, `credentials.json`, `install.json`, копии Compose/Helm
и пустой `empty.env`. Для Kubernetes дополнительно — `resources.yaml` и `values.yaml`.
Каталог `runtime/` содержит env-файлы, согласованные пароли Redis, политики, профили и
ключ HMAC аудита. Случайные секреты независимы; пароли admin/user/service хранятся в
сервисе как bcrypt-хеши. Пароли для первого входа (`admin`, `user`) и ingress API-ключ
находятся в `credentials.json`; сервисная учётная запись — `agent-service`.

На POSIX каталог создаётся с правами 0700, секретные файлы — 0600. При Compose install
права читаемых контейнерами файлов ограничиваются UID/GID 10001 и Redis 999/1000.
Не используйте `chmod -R 777`. На Windows `prepare/check` пригодны для проверки;
эквивалентную защиту ACL настройте отдельно, запуск установки поддержан на Linux.

Весь `--home` храните вне Git, резервируйте зашифрованным способом. `resources.yaml`
содержит настоящие секреты, Kubernetes Secret не является шифрованием данных сам по себе.
Повторный `prepare` в существующий каталог запрещён и не меняет пароли. До install
можно отредактировать подготовленные параметры; копии шаблонов фиксируются на момент
prepare, поэтому `git pull` не меняет существующее окружение автоматически.

### Если установка не завершилась

Ошибки внешних команд выводятся без их stdout/stderr: вывод может содержать секреты.
`install-state.json` остаётся `pending`, повторный install блокируется. Уже созданные
ресурсы и volumes сохраняются. Для диагностики проверьте занятость порта, доступ к
registry/LLM, Secret, события Pod и состояние PVC. Не публикуйте необработанные логи:
они могут содержать конфиденциальные данные.

В Kubernetes используйте `kubectl --context MY_CONTEXT -n uter-instance describe pod POD`
и `get events`; исправьте причину, затем осознанно продолжите через Helm с теми же
`values.yaml`/Secret. В Compose используйте те же `install.json`, `RUNTIME_DIR`, имена
образов и project name при ручной диагностике. Не удаляйте каталог и volumes ради повтора:
это потеря ключей аудита и состояния. Автоматического удаления/отката данных нет.

Readiness не заменяет проверку поведения: после запуска проверьте вход, обычный запрос
к реальному LLM, блокировку запрещённого ввода/вывода и целостность аудита.
Обновление существующих версий выполняется через подписанный комплект и `uterctl.py`
с резервной копией. Для перехода от прямой установки к управляемой нужен отдельный
проверенный план переноса состояния; автоматического принятия такой установки пока нет.
Новый формат конфигурации использует `runtime/`, `RUNTIME_DIR` и `runtime.toml`;
старые подготовленные каталоги не переименовываются автоматически. Chart: 0.2.0.

## Текущий статус

Реализованы Compose, Helm и контроллер `uterctl.py`. Реальные Guardrail и Agent
собраны на GitHub-hosted Linux runner из зафиксированного commit продукта.
Проверены загрузка скомпилированных модулей, OpenAPI и офлайн inference toxicity-модели;
проверка всех слоёв не обнаружила собственных Python-файлов в `/app`.
Локальный релиз ещё не опубликован: security-аудит выявил уязвимости зависимостей,
Compose acceptance и restart прошли; живой Helm и межверсионное обновление ещё не проверены.
Пример manifest остаётся неустанавливаемым.
Доказательства и границы проверок: [проверка образов](docs/image-validation.md).
[Усиление защиты кода и измерение реверса](docs/image-protection.md): полный обход слоёв,
проверка точных копий исходников, явный состав runtime, docstrings и ELF-отчёты.

Первый профиль: Guardrail + Agent + Redis; LLM окружения подключается по API.
vLLM, LiteLLM, Qdrant, Confluence, GPU-драйверы и PKI здесь не устанавливаются.
Их интеграционные параметры задаёт оператор. Это не готовый полностью автономный RAG-стенд.

## Файлы

| Каталог | Назначение |
|---|---|
| `compose/` | Самостоятельный Compose без build и доступа к исходникам |
| `charts/uter/` | Helm chart, ClusterIP, NetworkPolicy, PVC |
| `releases/` | Версии продукта и точные digest всех образов |
| `packaging/` | Экспериментальный рецепт компиляции собственных Python-модулей |
| `scripts/` | Подпись комплекта, проверки, watcher, кандидат версии |
| `examples/` | Шаблоны локальных настроек без секретов |
| `docs/` | Инструкции по выпуску и эксплуатации |

## Готовность образов и релиза

**Пока нет готового локального релиза.** `git clone` и `docker compose up` недостаточно:
в `releases/` находится только неустанавливаемый `example.json`, а не выпущенный manifest.
Архивы CI — кандидаты для проверки, не подписанный комплект установки.

| Проверка | Состояние |
|---|---|
| Реальные Guardrail/Agent без собственных Python-файлов в `/app` | Проверены все слои; runtime прошёл |
| Compose: первый запуск, API/auth, блокировки, аудит, restart | Прошёл в изолированном CI с тестовым LLM |
| Helm | Только lint/template; живой кластер ещё не проверен |
| Security образов | Guardrail: 0 Critical / 44 High; Agent: 5 Critical / 67 High |
| Redis, tooling, все внешние сервисы | Не покрыты двумя отчётами образов Guardrail/Agent |
| Registry, действительный release manifest, подпись и доверенный ключ | Локальный комплект ещё не выпущен |
| Межверсионное обновление, откат данных, реальный LLM/RAG | Требуют проверки перед соответствующим сценарием развёртывания |

Состояние и границы аудита с обновлением 26–27.10.2026: [готовность и защита кода](docs/readiness.md).
Счётчики означают findings сканера, а не доказанную эксплуатацию через API.

## Первая установка (после выпуска подписанного комплекта)

1. Получить от сопровождающего tooling с `uterctl.py`, подписанный bundle, независимый
   публичный ключ, доступ к образам по digest, runtime-политики/профили/модели и acceptance-тест.
   Номера `1.0.0`/`1.1.0` в документации — примеры, а не существующие релизы.
2. Подготовить отдельный Linux amd64 сервер: Python 3.12, Compose >=2.30 либо
   согласованный кластер и Helm 3.17.3. Для Compose текущий лимит Guardrail требует
   минимум 4 логических CPU; сумма лимитов памяти трёх сервисов — 5 GiB, плюс запас
   для ОС и прочих процессов. Это не подтверждённый нагрузочным тестом sizing.
3. Создать `/srv/uter/runtime`, заполнить конфигурацию по
   [пошаговой инструкции](docs/deployment.md#первая-установка-compose).
   Для Helm использовать раздел [Helm](docs/deployment.md#helm), сменить backend в site.json.
4. Проверить доступ к registry и внешнему LLM, настроить TLS, права на секреты,
   постоянные хранилища и локальный acceptance-тест. Сам репозиторий TLS/LLM не устанавливает.
5. Выполнить `verify`, затем `check` и `apply` с фактическими путями ниже.
6. Проверить локальный acceptance и внешний TLS endpoint; сохранить исходную
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

## Обновление оператора

Подробно: [инструкция оператора](docs/deployment.md).

```bash
python uterctl.py verify --bundle /srv/incoming/uter-1.1.0 --key /etc/uter/publisher.pub
python uterctl.py check --home /srv/uter --bundle /srv/incoming/uter-1.1.0 --key /etc/uter/publisher.pub
python uterctl.py apply --home /srv/uter --bundle /srv/incoming/uter-1.1.0 --key /etc/uter/publisher.pub --backup-receipt /srv/backup/receipt.json
python uterctl.py status --home /srv/uter
python uterctl.py rollback --home /srv/uter --key /etc/uter/publisher.pub --backup-receipt /srv/backup/after-failure.json
```

`verify` проверяет подпись и инвентарь. `check` дополнительно проверяет конфигурацию,
но не подключается к работающим сервисам. `apply` ждёт готовности и запускает
локальный acceptance-тест. `status` показывает записанное состояние, а не live health.
На ошибке оставляется `pending`; нет ложной отметки об успешном обновлении.

## Изменения основного проекта → проверки → выпуск

1. Изменения локальных файлов: [watcher](docs/automation.md) после паузы запускает
   тесты на копии. Ничего не публикует и не меняет в исходном каталоге.
2. Push Uter: workflow этого репозитория проверяет актуальный upstream commit по
   расписанию (после включения), вручную или через `repository_dispatch`.
3. После тестов открывает PR с кандидатом. Совместимость готовых образов и локальных
   обновлений проверяется до выпуска подписанного комплекта.
4. Оператор выбирает конкретную версию. Автоустановки вслед за push нет.

[Настройка автоматизации](docs/automation.md) · [Выпуск версии](docs/releasing.md)

[Сборка и проверка реальных защищённых образов](docs/image-validation.md)
