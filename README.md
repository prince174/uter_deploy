# Uter Deploy

Самостоятельное развёртывание Guardrail + Agent + Redis через Docker Compose или
Kubernetes/Helm. Для запуска нужны готовые образы, настройки и внешний LLM API.
Исходники сервиса и сборка на машине установки не требуются.

Если LiteLLM и vLLM уже работают в инфраструктуре, начните с
[подробной инструкции подключения и развёртывания](docs/corporate-litellm-deployment.md).
В ней описаны сетевые требования, входные данные, Compose, Kubernetes, проверки и
ограничения автоматизации. Инструкция находится в текущей ветке `main`: ранее
опубликованный тег и подписанный комплект `0.1.4` она не изменяет.

## Схемы

| Тема | Интерактивный HTML | Редактируемый draw.io |
|---|---|---|
| Развёртывание Compose / Kubernetes | [Открыть схему](docs/uter-deployment.html) | [Две страницы](docs/diagrams/uter-deployment.drawio) |
| Работа Uter и пути защиты запросов | [Карта сервиса](docs/uter-service-map.html) | [Защита запроса](docs/diagrams/uter-request-protection.drawio) |

HTML открывается локально в браузере без внешних библиотек. В схеме развёртывания
переключаются Compose/Kubernetes, этапы и подробности компонентов. Карта сервиса —
адаптированная архитектурная справка; дополнительные интеграции не входят в базовую
установку. Адреса исходного репозитория в схемах отсутствуют; указаны только пути
образов GHCR. Доступность registry отражается в отчёте проверки ниже.

## Что уже проверено

Образы опубликованы в **публичном GHCR** и доступны без авторизации; установка
использует неизменяемые digest. [Анонимная установка Compose и Kubernetes](https://github.com/prince174/uter_deploy/actions/runs/40642468640) проверена в изолированном CI.
Старые версии образов также публичны и содержат известные Critical/High; используйте
только digest актуального установочного комплекта.
В [изолированном CI](https://github.com/prince174/uter_deploy/actions/runs/40627054284)
успешно выполнены обе установки с помощью `scripts/install.py`:

- Compose: все сервисы healthy, `/ready` доступен на локальном порту.
- Kubernetes 1.35.8 / kind 0.33.0: три Ready Pod, PVC Redis и аудита подключены,
  `/ready` доступен через port-forward.
- Вход с сгенерированным паролем, обычный запрос, блокировка инъекции и PII в ответе,
  OpenAI API с проверкой ingress-secret, защита Agent, реальная toxicity-модель.
- Перезапуск Redis, Agent и Guardrail, повторный прогон и проверка сохранённой
  HMAC-цепочки аудита.

В основном установочном прогоне LLM — детерминированный HTTP-сервис. Отдельный CI
проверил настоящую Qwen через Ollama и обновление тестовой управляемой установки
на обоих backend: [условия и результаты](docs/real-llm-upgrade-validation.md).
Это не подтверждает качество других LLM/RAG, Ollama judge, TLS, нагрузку или HA.
Для цепочки Uter → LiteLLM → CPU vLLM проведена отдельная [проверка в CI](docs/ci-litellm-vllm.md): оба backend прошли с небольшой моделью, а более крупная Qwen — по одному разу в отдельных заданиях. Это проверка интеграции, не производительности.
kind использует стандартный CNI без применения NetworkPolicy:
правила рендерятся, но их сетевое действие этим тестом не проверено.

Проверка всех трёх образов от 28.10.2026: **0 Critical / 0 High**, без исключений CVE.
Остаются Medium/Low: Guardrail — 24/11, Agent — 22/10, Redis — 0/0.
[Исправления, проверки и отчёты](docs/security-remediation.md). Это результат
конкретного сканирования на указанную дату, а не гарантия отсутствия новых или
неизвестных уязвимостей.
[Границы готовности](docs/readiness.md).

## 1. Получить установочные файлы

На Linux amd64 установите Python 3.11+ (рекомендуется 3.12), поддержку создания
`venv` и `pip`, Git и curl. Например, в Ubuntu модуль `venv` может поставляться
отдельным пакетом для используемой версии Python. Для Compose нужны Docker и Compose >=2.30;
для Kubernetes — kubectl, kubeconfig и Helm 3.17.3. Узлы должны поддерживать linux/amd64,
создание PVC и исходящие соединения к registry и LLM.

Получите и **независимо сверьте** SHA-256 публичного ключа издателя:
`65be6fd9613fa7e879735fe5b453bfcb8c0e38911cd7429c9aac9c9afba676a2`.
Значение, полученное только из этого же репозитория, не подтверждает доверие к ключу.
Для первой проверки также нужны доверенные Git-репозиторий, Python и зависимости;
сами эти инструменты не могут удостоверить собственное происхождение.

```bash
git clone https://github.com/prince174/uter_deploy.git
cd uter_deploy
git checkout deploy-2026.10.28-signed-5
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
mkdir -p incoming signed
curl -fL -o signed/publisher-public.pem \
  https://github.com/prince174/uter_deploy/releases/download/deploy-2026.10.28-signed-5/publisher-public.pem
curl -fL -o signed/signed-bundle.tar.gz \
  https://github.com/prince174/uter_deploy/releases/download/deploy-2026.10.28-signed-5/signed-bundle.tar.gz
echo '65be6fd9613fa7e879735fe5b453bfcb8c0e38911cd7429c9aac9c9afba676a2  signed/publisher-public.pem' | sha256sum -c -
.venv/bin/python scripts/extract_signed_bundle.py \
  --archive signed/signed-bundle.tar.gz --key signed/publisher-public.pem \
  --output signed/0.1.4
curl -fL -o incoming/installation-inputs.tar.gz \
  https://github.com/prince174/uter_deploy/releases/download/deploy-2026.10.28-signed-5/installation-inputs.tar.gz
curl -fL -o incoming/installation-inputs.tar.gz.sha256 \
  https://github.com/prince174/uter_deploy/releases/download/deploy-2026.10.28-signed-5/installation-inputs.tar.gz.sha256
.venv/bin/python signed/0.1.4/scripts/extract_release_inputs.py \
  incoming/installation-inputs.tar.gz incoming/installation-inputs.tar.gz.sha256 incoming/inputs \
  --bundle signed/0.1.4 --key signed/publisher-public.pem
```

Команда проверяет подпись комплекта и подписанный SHA-256 архива **до** его
распаковки. Установочные данные содержат `images.json`, `policy.toml`,
`model_profiles.toml` и метаданные публикации. Установщик и шаблоны ниже берутся
из проверенного комплекта. Подписанный выпуск `0.1.4` допускает переход с `0.1.2`;
переходы с остальных управляемых версий не заявлены.

Из доверенной копии текущего `main` выпуск можно также получить одной командой:

```bash
.venv/bin/python scripts/fetch_release.py --release deploy-2026.10.28-signed-5 \
  --version 0.1.4 --fingerprint "$UTER_PUBLISHER_SHA256" --output ./verified-release
```

Переменная `UTER_PUBLISHER_SHA256` должна содержать отпечаток, полученный и
сверенный по независимому доверенному каналу. Каталог назначения должен быть новым.
В Linux его родитель должен принадлежать оператору и быть защищён от записи других
пользователей; проверяются и родительские каталоги. В Windows оператор отдельно
проверяет ACL родительского каталога: команда не умеет подтверждать его приватность.
Результат содержит `bundle/`, `inputs/` и `downloads/publisher-public.pem`;
для команд установки укажите эти пути вместо `signed/0.1.4` и `incoming/inputs`.
Команда принимает выпуски с подписанным хешем входного архива и не заменяет доверие
к самой копии tooling, Python и зависимостям. Она появится в следующем подписанном
комплекте; в уже выпущенном `0.1.4` её нет.

Образы этой версии:

| Сервис | Registry reference |
|---|---|
| Guardrail | `ghcr.io/prince174/uter-guardrail@sha256:2b157a9d01f454cd7fdaf67345b5d872cd26e8f5785132cce933ee22c9fa296e` |
| Agent | `ghcr.io/prince174/uter-agent@sha256:a6f03a1f102fcc941b1aad0a0ada9f664b2451c0e0acb06a46c5aaaedee86da1` |
| Redis | `ghcr.io/prince174/uter-redis@sha256:b4a3dd93f2f7e276b98131e947d2c30e4b237d964c87a948cf808f160eef2fcc` |

Подробный порядок принятия установки, обновления и восстановления описан в
[инструкции](docs/managed-update-recovery.md). Предварительные версии
`deploy-2026.10.28-signed-1` и `deploy-2026.10.28-signed-2` использовать не следует.

## 2A. Установить через Compose

Используйте отдельный сервер и новое имя проекта. Ориентир по ресурсам: 4 логических
CPU, лимиты контейнеров суммарно 5 GiB RAM плюс запас ОС. В CI проверен малый профиль
с `--guardrail-cpus 2`; это не оценка производительности под нагрузкой.
Поддерживается локальный Docker context `default` с Unix socket; удалённый daemon
для установки с bind-mount не поддерживается.

Для публичных образов вход в GHCR и токен не требуются.

```bash
sudo .venv/bin/python signed/0.1.4/scripts/install.py prepare \
  --home /srv/uter-instance --backend compose --name uter-instance \
  --inputs "$PWD/incoming/inputs"
sudo .venv/bin/python signed/0.1.4/scripts/install.py check --home /srv/uter-instance
sudo .venv/bin/python signed/0.1.4/scripts/install.py install --home /srv/uter-instance
curl --fail http://127.0.0.1:18000/ready
```

Мастер спросит URL OpenAI-совместимого LLM, имя модели и скрыто API-ключ.
Пример base URL: `https://llm.example/v1`. Путь `/chat/completions` добавляется сервисом.
Для существующего LiteLLM укажите его адрес, а в качестве модели — разрешённый
alias LiteLLM, маршрутизированный на vLLM. Адрес должен быть доступен и доверен по TLS
именно из контейнера или Pod Uter. Мастер не настраивает корпоративные CA, mTLS,
сеть и прокси; их применимость и поддержку нужно проверить отдельно.
Если ключ не нужен, оставьте его пустым. HTTP разрешается только явным
`--allow-http-llm` для доверенной внутренней сети.

`prepare` генерирует пароли и конфигурацию, ничего не запускает. `check` проверяет
рендеринг без обращения к daemon/LLM. `install` скачивает образы, выставляет права,
запускает сервисы и ждёт готовности до 300 секунд. Порт по умолчанию — 18000, изменить
можно через `prepare --port 18001`. Он привязан к `127.0.0.1`; для внешнего доступа
нужен TLS reverse proxy. Agent и Redis наружу не публикуются.

## 2B. Установить в Kubernetes

Нужен **новый namespace**, равный `--name`. `--context` обязателен; текущий context
в kubeconfig установщик не меняет. Нужны права создавать namespace, Secret, ConfigMap,
PVC, Deployment, Service и NetworkPolicy. Ingress и TLS настраиваются отдельно.

Публичные образы не требуют файла доступа к registry:

```bash
.venv/bin/python signed/0.1.4/scripts/install.py prepare \
  --home "$HOME/uter-k8s" --backend kubernetes --name uter-instance \
  --context MY_CONTEXT --inputs "$PWD/incoming/inputs"
.venv/bin/python signed/0.1.4/scripts/install.py check --home "$HOME/uter-k8s"
.venv/bin/python signed/0.1.4/scripts/install.py install --home "$HOME/uter-k8s"
kubectl --context MY_CONTEXT -n uter-instance get pods,pvc
kubectl --context MY_CONTEXT -n uter-instance port-forward svc/uter-instance-guardrail 18000:8000
# В другом терминале:
curl --fail http://127.0.0.1:18000/ready
```

При отсутствии default StorageClass добавьте `prepare --storage-class YOUR_CLASS`.
Создаются PVC Redis 2 GiB и аудита 10 GiB, Secret и ConfigMap.
Проверенные образы содержат toxicity-модель; отдельный models PVC не нужен.
Для дополнительных моделей — [расширенные настройки](docs/deployment.md).

Если используется отдельный приватный registry, `--registry-config` принимает файл
с inline `auths`; credential helpers внутри Kubernetes не запускаются.
Для внешнего Ingress используется namespace `ingress-nginx`; если он другой,
измените `ingressNamespace` в сгенерированном `values.yaml` **до** install.

## 3. Проверить работу с реальным LLM

Пароли учётных записей `admin`, `user`, `agent-service` и ключ OpenAI ingress записаны
в `credentials.json` внутри `--home`. Файл приватный; не пересылайте его и не коммитьте.
Возьмите пароль admin в защищённом терминале/редакторе и выполните:

```bash
.venv/bin/python signed/0.1.4/scripts/smoke_http.py --url http://127.0.0.1:18000
```

Скрипт спросит пароль скрыто, проверит readiness, вход, зависимости и обычный `/chat`
запрос. Токены и текст ответа не печатаются. Запрос поступает в настроенную LLM и может
расходовать её квоту. Это первичная проверка, не полноценный нагрузочный или security-тест.

Для `/v1/chat/completions` нужны **оба** заголовка: `Authorization: Bearer <JWT>` и
`X-Uter-Ingress-Secret: <openai_ingress_key>`. Последний обычно добавляет доверенный
reverse proxy. Без него endpoint отвечает 403. `/auth/token` принимает form-urlencoded
`username` и `password`; `/chat` использует JWT.

Отдельный LLM judge по умолчанию отключён — это отдельная зависимость, а не основной
LLM API. Для его включения добавьте `prepare --judge-url http://HOST:11434 --judge-model MODEL`.
Требуется Ollama API, модель должна быть уже загружена; включается fail-closed.
Toxicity-модель, проверки ввода/вывода и аудит работают независимо от него.

## Автоматизация и секреты

| Этап | Что выполняется автоматически | Что остаётся оператору |
|---|---|---|
| Подготовка | `prepare` создаёт конфигурацию, ключи Uter и ресурсы для выбранного backend. | Выбрать среду, подготовить LiteLLM, имя модели, ключ, сеть и доверие к сертификатам. |
| Первая установка | `check` проверяет рендеринг; `install` скачивает образы, запускает компоненты и ожидает готовности. | Проверить доступ к registry и LLM, выполнить smoke и настроить TLS-доступ. `check` не проверяет соединения; smoke автоматически не выполняется. |
| Обновление | Контроллер проверяет подпись и совместимость, создаёт зашифрованную копию, обновляет компоненты и выполняет smoke. | Получить и проверить подписанные комплекты и ключ издателя; безопасно хранить и отдельно вынести копию и её ключ. |
| Восстановление | Создаются отдельные проект или namespace и тома; данные восстанавливаются, запускается smoke. | Проверить данные и внешние зависимости, выбрать момент и вручную переключить трафик. |

Из доверенной копии текущего `main` доступна предварительная проверка с машины
оператора:

```bash
python3 scripts/preflight.py --backend compose --llm-url "$LLM_URL" \
  --llm-model "$LLM_MODEL" --llm-key-file "$LLM_KEY_FILE"
```

Для Kubernetes укажите `--backend kubernetes --context MY_CONTEXT`. Проверка отправляет реальный короткий
запрос и может расходовать квоту. Она не создаёт контейнеры или Pod и явно сообщает,
что сеть и доверие сертификатам внутри них, registry и CNI/CSI/RBAC не проверены.
Команда появится в следующем подписанном выпуске; ранее выпущенный `0.1.4` её не содержит.

Автоматической настройки корпоративных CA/mTLS, Ingress, DNS и правил сети,
ротации секретов, плановых резервных копий и миграции внешних систем здесь нет.
Наличие функций и примеры проверок не подтверждают работу в конкретном окружении.
Подробнее, включая закрытый контур и действия при сбое:
[инструкция для LiteLLM и vLLM](docs/corporate-litellm-deployment.md).

Для неинтерактивного prepare задайте `--llm-url`, `--llm-model`, `--llm-key-file`.
Файл ключа может быть пустым для LLM без авторизации. Секреты не передавайте в командной
строке. Вместо `--inputs` можно указать `--images`, `--policy`, `--profiles` отдельно.

В `--home` сохраняются `runtime/`, `credentials.json`, `install.json`, копии Compose/Helm
и `empty.env`; для Kubernetes дополнительно `resources.yaml`, `values.yaml`.
POSIX-права каталога — 0700, секретных файлов — 0600; install выставляет читаемые
контейнерами UID/GID для bind-mount. Не используйте `chmod -R 777`.
`resources.yaml` содержит секреты открытым текстом; Kubernetes Secret сам по себе
не является шифрованием. Резервируйте весь каталог зашифрованным способом.

Повторный prepare в существующий каталог запрещён, ключи не ротируются автоматически.
`git pull` не меняет копии шаблонов существующей установки. Уже существующие Compose
project или Kubernetes namespace не принимаются автоматически. На Windows поддержаны
подготовка/рендеринг с отдельно настроенными ACL; install выполняется на Linux.

## Ошибки, повторный запуск и обновление

При ошибке `install-state.json` остаётся `pending`. Повторный install блокируется;
ресурсы, данные и ключи сохраняются. Вывод команд скрывается, поскольку он может
содержать секреты. Диагностируйте занятость порта, доступ к registry/LLM, PVC и события
Pod. В Kubernetes: `kubectl --context MY_CONTEXT -n uter-instance get events` и
`describe pod POD`; после устранения причины осознанно продолжите Helm с теми же
values и Secret. Не удаляйте каталог или volumes ради повтора.

Readiness не заменяет проверку поведения. До открытия доступа проверьте свои запросы,
политику блокировок, TLS и резервное копирование.

Установку `install.py` можно передать под управление `uterctl.py`: команда adoption
сверяет работающие образы, файлы развёртывания и подписанный комплект, затем выполняет
проверку сервиса. При обновлении контроллер создаёт зашифрованную резервную копию
перед заменой компонентов. Для этого нужны выпущенные подписанные комплекты и отдельно
полученный и проверенный доверенный ключ. Тестовые ключи
и версии из CI не предназначены для эксплуатации. Детали проверок и ограничений:
[реальная LLM и обновление](docs/real-llm-upgrade-validation.md).
Команды восстановления создают новую отдельную установку из проверенной копии;
переключение трафика и внешние зависимости остаются за оператором. См.
[обновление и восстановление](docs/managed-update-recovery.md).
`releases/example.json` не устанавливается.
Новый формат: `runtime/`, `RUNTIME_DIR`, `runtime.toml`, chart 0.2.0; старые каталоги
автоматически не переименовываются.

## Registry и CI

- `publish-images.yml`: проверка исходного CI run, SHA256 архивов и слоёв, публикация
  трёх образов GHCR, проверка выбранной видимости, обе установки.
- `verify-installation.yml`: проверяет установку из CI-артефакта.
- `verify-released-installation.yml`: повторяет проверку из архива GitHub Release
  и checkout его тега; job не имеет токена доступа к исходному проекту.
Основной и единственный используемый registry — публичный GHCR.
Docker Hub не используется. Результаты установки: [отчёт проверки](docs/registry-installation.md).

CI использует только временные runner, namespace и volumes. Локальный Docker и
основной проект при разработке развёртывания не запускаются и не изменяются.

## Разработка

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/validate_assets.py
```

Вторая команда вызывает только Compose config и Helm lint/template. Тесты live CI
намеренно отказываются работать вне GitHub Actions и удаляют только свои временные
ресурсы. Не используйте их для обслуживания постоянной установки.

[Выпуск версии](docs/releasing.md) · [Автоматизация upstream](docs/automation.md) ·
[Проверка образов](docs/image-validation.md) · [Защита реализации](docs/image-protection.md)
