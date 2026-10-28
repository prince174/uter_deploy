# Uter Deploy

Самостоятельное развёртывание Guardrail + Agent + Redis через Docker Compose или
Kubernetes/Helm. Для запуска нужны готовые образы, настройки и внешний LLM API.
Исходники сервиса и сборка на машине установки не требуются.

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

28.10.2026 обновлённые образы опубликованы в **приватный GHCR**. Анонимное скачивание
запрещено; установка скачивает образы с авторизацией по неизменяемым digest.
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
kind использует стандартный CNI без применения NetworkPolicy:
правила рендерятся, но их сетевое действие этим тестом не проверено.

Свежая проверка всех трёх образов: **0 Critical / 0 High**, без исключений CVE.
Остаются Medium/Low: Guardrail — 24/11, Agent — 22/10, Redis — 0/0.
[Исправления, проверки и отчёты](docs/security-remediation.md). Это результат
конкретного сканирования, а не гарантия отсутствия неизвестных уязвимостей.
[Границы готовности](docs/readiness.md).

## 1. Получить установочные файлы

Нужен доступ к приватному репозиторию и registry. На Linux amd64 установите Python
3.11+ (рекомендуется 3.12), Git и GitHub CLI. Для Compose нужны Docker и Compose >=2.30;
для Kubernetes — kubectl, kubeconfig и Helm 3.17.3. Узлы должны поддерживать linux/amd64,
создание PVC и исходящие соединения к registry и LLM.

```bash
gh auth login
gh repo clone prince174/uter_deploy
cd uter_deploy
git checkout deploy-2026.10.28-2
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
mkdir -p incoming
gh release download deploy-2026.10.28-2 --repo prince174/uter_deploy \
  --pattern 'installation-inputs.tar.gz*' --dir incoming
(cd incoming && sha256sum -c installation-inputs.tar.gz.sha256)
tar -xzf incoming/installation-inputs.tar.gz -C incoming
```

Комплект содержит `images.json`, `policy.toml`, `model_profiles.toml` и метаданные
публикации, а также security-summary для каждого образа. Digest уже заполнены — ничего придумывать или копировать из Docker image ID
не нужно. SHA256 архива выявляет повреждение; это не независимая подпись. Доступ и
подлинность комплекта здесь опираются на доверенный GitHub-репозиторий и HTTPS.
Подписанный комплект для `uterctl.py` пока не выпущен.

Образы этой версии:

| Сервис | Registry reference |
|---|---|
| Guardrail | `ghcr.io/prince174/uter-guardrail@sha256:2b157a9d01f454cd7fdaf67345b5d872cd26e8f5785132cce933ee22c9fa296e` |
| Agent | `ghcr.io/prince174/uter-agent@sha256:a6f03a1f102fcc941b1aad0a0ada9f664b2451c0e0acb06a46c5aaaedee86da1` |
| Redis | `ghcr.io/prince174/uter-redis@sha256:b4a3dd93f2f7e276b98131e947d2c30e4b237d964c87a948cf808f160eef2fcc` |

## 2A. Установить через Compose

Используйте отдельный сервер и новое имя проекта. Ориентир по ресурсам: 4 логических
CPU, лимиты контейнеров суммарно 5 GiB RAM плюс запас ОС. В CI проверен малый профиль
с `--guardrail-cpus 2`; это не оценка производительности под нагрузкой.
Поддерживается локальный Docker context `default` с Unix socket; удалённый daemon
для установки с bind-mount не поддерживается.

Для скачивания из GHCR используйте GitHub PAT classic с `read:packages` и доступом
к пакетам. Вход в `gh` не заменяет вход Docker. Пароль в приглашении — PAT, не пароль
аккаунта. Ввод скрыт, токен не передавайте в аргументах процесса.

```bash
sudo docker login ghcr.io --username YOUR_GITHUB_LOGIN
sudo .venv/bin/python scripts/install.py prepare \
  --home /srv/uter-instance --backend compose --name uter-instance \
  --inputs "$PWD/incoming"
sudo .venv/bin/python scripts/install.py check --home /srv/uter-instance
sudo .venv/bin/python scripts/install.py install --home /srv/uter-instance
curl --fail http://127.0.0.1:18000/ready
```

Мастер спросит URL OpenAI-совместимого LLM, имя модели и скрыто API-ключ.
Пример base URL: `https://llm.example/v1`. Путь `/chat/completions` добавляется сервисом.
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

Создайте отдельный файл доступа к registry:

```bash
REGISTRY_CONFIG_DIR="$HOME/.config/uter-registry"
mkdir -p "$REGISTRY_CONFIG_DIR"
chmod 700 "$REGISTRY_CONFIG_DIR"
docker --config "$REGISTRY_CONFIG_DIR" login ghcr.io --username YOUR_GITHUB_LOGIN
.venv/bin/python scripts/install.py prepare \
  --home "$HOME/uter-k8s" --backend kubernetes --name uter-instance \
  --context MY_CONTEXT --inputs "$PWD/incoming" \
  --registry-config "$REGISTRY_CONFIG_DIR/config.json"
.venv/bin/python scripts/install.py check --home "$HOME/uter-k8s"
.venv/bin/python scripts/install.py install --home "$HOME/uter-k8s"
kubectl --context MY_CONTEXT -n uter-instance get pods,pvc
kubectl --context MY_CONTEXT -n uter-instance port-forward svc/uter-instance-guardrail 18000:8000
# В другом терминале:
curl --fail http://127.0.0.1:18000/ready
```

При отсутствии default StorageClass добавьте `prepare --storage-class YOUR_CLASS`.
Создаются PVC Redis 2 GiB и аудита 10 GiB, Secret/ConfigMap и imagePullSecret.
Проверенные образы содержат toxicity-модель; отдельный models PVC не нужен.
Для дополнительных моделей — [расширенные настройки](docs/deployment.md).

Файл registry должен содержать inline `auths`; credential helpers внутри Kubernetes
не запускаются. Не передавайте общий конфиг с доступами ко всем registry.
Для внешнего Ingress используется namespace `ingress-nginx`; если он другой,
измените `ingressNamespace` в сгенерированном `values.yaml` **до** install.

## 3. Проверить работу с реальным LLM

Пароли учётных записей `admin`, `user`, `agent-service` и ключ OpenAI ingress записаны
в `credentials.json` внутри `--home`. Файл приватный; не пересылайте его и не коммитьте.
Возьмите пароль admin в защищённом терминале/редакторе и выполните:

```bash
.venv/bin/python scripts/smoke_http.py --url http://127.0.0.1:18000
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

Новый установщик предназначен для первой установки. Межверсионное обновление и
откат выполняются через `uterctl.py` с подписанным комплектом и backup receipt;
[инструкция](docs/deployment.md). Для прямой установки автоматический переход под
управление `uterctl` пока не реализован. `releases/example.json` не устанавливается.
Новый формат: `runtime/`, `RUNTIME_DIR`, `runtime.toml`, chart 0.2.0; старые каталоги
автоматически не переименовываются.

## Registry и CI

- `publish-images.yml`: проверка исходного CI run, SHA256 архивов и слоёв, публикация
  трёх приватных образов GHCR, проверка запрета анонимного скачивания, обе установки.
- `verify-installation.yml`: проверяет установку из CI-артефакта.
- `verify-released-installation.yml`: повторяет проверку из архива GitHub Release
  и checkout его тега; job не имеет токена доступа к исходному проекту.
Основной и единственный используемый registry — приватный GHCR.
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
