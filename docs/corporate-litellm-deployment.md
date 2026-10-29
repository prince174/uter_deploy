# Развёртывание Uter с существующими LiteLLM и vLLM

Этот сценарий рассчитан на окружение, где LiteLLM и vLLM уже установлены и
администрируются отдельно. Uter поставляется из готовых образов: исходный код и
сборка Uter на целевой машине не нужны. Выберите **один** вариант установки —
Compose или Kubernetes — и выполните проверку до открытия доступа.

```text
приложение → TLS reverse proxy / Ingress → Uter → LiteLLM → vLLM → модель
```

В базовую установку Uter входят Guardrail, Agent и Redis. Установка не разворачивает
и не изменяет LiteLLM, vLLM и их модели. Подключать приложения следует через Uter;
доступ к LiteLLM, vLLM, Agent и Redis ограничьте сетевыми правилами окружения.

## 1. Подготовить данные и инфраструктуру

Согласуйте с администраторами инфраструктуры и LiteLLM:

| Необходимо | Что проверить |
|---|---|
| Адрес LiteLLM | HTTPS base URL OpenAI-совместимого API, например `https://litellm.example.internal/v1`. Это адрес **LiteLLM**, а не vLLM. Домен, путь и порт ниже являются примерами. |
| Имя модели | Точный alias, опубликованный LiteLLM и направленный на нужную модель vLLM. Это значение передаётся как `--llm-model`. |
| Ключ LiteLLM | Отдельный ключ с минимальными нужными правами, доступом к alias и необходимым API и проверке состояния. Не используйте административный master key, если достаточно ограниченного ключа. |
| TLS | Сертификат LiteLLM соответствует его DNS-имени; цепочка проверяется доверенным CA. Убедитесь, что доверие настроено именно внутри Guardrail, а не только на хосте. |
| Сеть | Из Guardrail должны разрешаться DNS и исходящие соединения к LiteLLM; LiteLLM должен достигать vLLM. Учитывайте firewall, proxy и ограничения кластера. `localhost` внутри контейнера означает сам контейнер, а не сервер установки. |
| Проверка LLM | LiteLLM и vLLM готовы, alias существует, разрешённый ключ позволяет выполнить небольшой реальный запрос. Uter также проверяет доступность upstream через `/health`; согласуйте доступ к этому пути. |
| Выпуск и образы | Доступны публичный подписанный выпуск и указанные в нём образы GHCR по digest, либо проверенные артефакты доставлены разрешённым способом. |

Проверка из терминала хоста полезна до установки, но сама по себе не подтверждает
маршрут, DNS и доверенные CA **внутри** контейнера или Pod. При обращении к HTTPS
не отключайте проверку сертификата и имени сервера.

Установщик выпуска `0.1.4` не настраивает корпоративный CA внутри образа, клиентский сертификат
mTLS, внешний proxy, TLS reverse proxy/Ingress или правила egress. Эти интеграции
требуют отдельной настройки и проверки в конкретном окружении; штатный вариант
передачи корпоративного CA или клиентского сертификата данным установщиком не
подтверждён. Не считать ранее проверенный HTTP-сценарий проверкой HTTPS/mTLS.

В текущей ветке разработки добавляется параметр `prepare --llm-ca-bundle PATH`:
он предназначен для полного PEM-набора доверенных корней, а не только добавочного
сертификата. Набор применяется ко всем HTTPS-соединениям процесса Guardrail;
включите корни, необходимые другим его HTTPS-интеграциям. На опубликованных образах
Uter с тестовым HTTPS-сервисом проверены доверенный CA, отклонение недоверенного CA
и несовпадающего имени в [изолированном CI](https://github.com/prince174/uter_deploy/actions/runs/40860550006)
для Compose и Kubernetes. Это не проверка реального корпоративного CA, mTLS или LLM.
Подписанный выпуск `0.1.4` этого
параметра не содержит; использовать его можно только с новым проверенным выпуском.
Клиентские сертификаты mTLS этот параметр не настраивает.

Для Compose нужен отдельный Linux amd64 сервер с Python 3.11+ (рекомендуется 3.12),
Git, curl, Docker и Compose версии не ниже 2.30; для создания виртуальной среды
может понадобиться системный пакет `python3-venv`. Нужен локальный Docker context
`default` с Unix socket. Ориентир: 4 логических CPU и суммарные лимиты сервисов
5 GiB RAM плюс запас ОС и других процессов. Это не расчёт требуемых ресурсов внешних
LiteLLM и vLLM и не оценка производительности.

Для Kubernetes нужны linux/amd64 узлы, доступный `kubectl` context, Helm 3.17.3,
права создавать ресурсы в **новом** namespace, работающий StorageClass и PVC:
Redis 2 GiB и аудит 10 GiB по умолчанию. Для действия NetworkPolicy нужен CNI с
её поддержкой; отдельно проверьте DNS и разрешение исходящего трафика к LiteLLM.

## 2. Получить и проверить выпуск

Это руководство находится в ветке `main`, а не в ранее опубликованном теге
`deploy-2026.10.28-signed-5`. Перед выполнением README откройте его
[отдельно в браузере](https://github.com/prince174/uter_deploy/blob/main/docs/corporate-litellm-deployment.md)
или сохраните отдельную копию: после `git checkout` на тег этого файла в локальной
копии не будет. Аналогично держите открытой актуальную инструкцию по обновлению
[из `main`](https://github.com/prince174/uter_deploy/blob/main/docs/managed-update-recovery.md).

Сначала выполните раздел **«1. Получить установочные файлы»** в [README](../README.md).
Он создаёт `.venv`, загружает `deploy-2026.10.28-signed-5`, проверяет подпись
комплекта `0.1.4` и подписанный хеш входных данных до распаковки. Дальнейшие команды
предполагают, что текущий каталог — полученный `uter_deploy`, а результаты находятся в
`signed/0.1.4`, `signed/publisher-public.pem` и `incoming/inputs`.

**Отпечаток ключа издателя необходимо получить и сверить по независимому доверенному
каналу.** Отпечаток из того же репозитория, что архив, не устанавливает доверие к
ключу. Первоначальная проверка также зависит от доверенных Git, Python и зависимостей.

Если сервер не имеет доступа к GitHub или GHCR, артефакты, Python-зависимости и
образы необходимо доставить по разрешённому каналу и проверить в целевом окружении.
Первичная команда `install.py install` в опубликованном `0.1.4` выполняет pull.
В текущей ветке разработки для Compose добавлен `install --offline`: до установки
каждый точный `registry@sha256` должен разрешаться в локальном Docker daemon, иначе
команда откажется от запуска до изменения состояния. В этом режиме Compose получает
`--pull never`; доступ к LLM остаётся отдельным требованием. Возможность переноса
образов с сохранением именно этих ссылок нужно проверить в выбранной инфраструктуре.
Новый режим проходит отдельную проверку в изолированном CI и появится только в новом
подписанном выпуске. Kubernetes в этом режиме не поддерживается: kubelet может
загружать образы на узлы. При изменении адреса registry нужен согласованный
подписанный комплект с соответствующими ссылками на образы; не редактируйте
подписанный manifest. Учитывайте доступ kubelet к registry на всех узлах.

После появления выпуска с поддержкой offline и обычных `prepare`/`check` команда
для Compose будет выглядеть так (`/path/to/verified-bundle` — новый проверенный
комплект, не `0.1.4`):

```bash
sudo /path/to/venv/bin/python /path/to/verified-bundle/scripts/install.py install \
  --home /srv/uter-instance --offline
```

## 3. Подготовить адрес, модель и ключ LiteLLM

Замените значения адреса и alias на согласованные с администратором LiteLLM. В одном
терминале Bash из каталога release-checkout `uter_deploy` выполните:

```bash
export LLM_URL='https://litellm.example.internal/v1'
export LLM_MODEL='protected-model'
export LLM_KEY_FILE="$HOME/.config/uter/litellm.key"
install -d -m 700 "$HOME/.config/uter"
umask 077
.venv/bin/python - <<'PY'
import getpass
import os
from pathlib import Path

path = Path(os.environ['LLM_KEY_FILE'])
if path.exists() or path.is_symlink():
    raise SystemExit('Файл уже существует: проверьте путь и права или выберите другой')
key = getpass.getpass('Ключ LiteLLM: ')
if not key:
    raise SystemExit('Пустой ключ: файл не создан, установку не продолжайте')
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w', encoding='utf-8') as output:
    output.write(key)
print('Файл ключа создан с правами 0600')
PY
```

Введите ключ скрыто, не вставляйте его в команду, URL, историю shell или сообщения.
Путь к файлу можно передавать в аргументах, значение ключа — нет. Если ключ уже
подготовлен защищённым способом, задайте `LLM_KEY_FILE` на существующий файл с
правами `0600`. Каталог установки, включая сгенерированные учётные данные и копию
ключа в runtime-конфигурации, также является секретным. Ограничьте доступ и
резервируйте его зашифрованным способом.

Если создание файла завершилось ошибкой, устраните её до продолжения. При повторном
использовании существующего файла оператор должен отдельно проверить его владельца,
права, содержимое и разрешения ключа, не выводя сам ключ.

При необходимости предварительно проверьте модель с **хоста** следующим примером.
Он читает ключ из файла в память, не выводит ключ или текст ответа и действительно
обращается к модели. Запрос может расходовать квоту; проверка соединения из Guardrail
после установки всё равно обязательна.

```bash
.venv/bin/python - <<'PY'
import json
import os
from pathlib import Path
from urllib import error, request

base = os.environ['LLM_URL'].rstrip('/')
model = os.environ['LLM_MODEL']
key = Path(os.environ['LLM_KEY_FILE']).read_text().rstrip('\r\n')
headers = {'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'}
body = json.dumps({'model': model, 'messages': [{'role': 'user', 'content': 'Hello'}],
                   'max_tokens': 4, 'temperature': 0}).encode()
try:
    req = request.Request(base + '/chat/completions', data=body, headers=headers)
    with request.urlopen(req, timeout=120) as response:
        result = json.load(response)
    if not result.get('choices'):
        raise SystemExit('LiteLLM ответил без choices; проверьте alias и модель')
    print('Тестовый запрос через LiteLLM: OK')
except error.HTTPError as exc:
    raise SystemExit(f'LiteLLM вернул HTTP {exc.code}; тело ответа скрыто') from None
except (error.URLError, TimeoutError):
    raise SystemExit('LiteLLM недоступен или TLS-проверка не прошла') from None
PY
```

Для HTTPS этот пример использует доверенные сертификаты Python на хосте; его
успех не подтверждает доверие CA в образе Guardrail. Не отключайте TLS-проверку
ради прохождения теста.

## 4A. Установить через Compose

Выберите **новые** каталог установки и имя проекта: повторный `prepare` не
перезаписывает существующие секреты, а `install` не принимает существующий проект.
В текущей ветке дополнительно проверяются зарезервированные имена контейнеров,
сетей и томов даже при отсутствии меток Compose. Проверка не атомарна относительно
других администраторов Docker: используйте отдельный daemon или согласованное окно
без параллельного создания ресурсов. В опубликованном `0.1.4` этой дополнительной
проверки ещё нет.
Из каталога `uter_deploy`:

```bash
sudo .venv/bin/python signed/0.1.4/scripts/install.py prepare \
  --home /srv/uter-instance --backend compose --name uter-instance \
  --inputs "$PWD/incoming/inputs" \
  --llm-url "$LLM_URL" --llm-model "$LLM_MODEL" --llm-key-file "$LLM_KEY_FILE"
sudo .venv/bin/python signed/0.1.4/scripts/install.py check --home /srv/uter-instance
sudo .venv/bin/python signed/0.1.4/scripts/install.py install --home /srv/uter-instance
curl --fail http://127.0.0.1:18000/ready
```

`prepare` создаёт секреты и конфигурацию, `check` проверяет только рендеринг
Compose, а не доступ к Docker daemon или LiteLLM. `install` загружает образы,
запускает контейнеры и ожидает готовность до 300 секунд. Порт Guardrail по
умолчанию `127.0.0.1:18000`; для другого порта задайте `--port` при `prepare`.
Для внешнего доступа нужен отдельно настроенный доверенный TLS reverse proxy.

## 4B. Установить в Kubernetes

Замените `MY_CONTEXT` на проверенный context. Namespace, равный `--name`, должен
быть новым. Оператору нужны права создания Namespace на уровне кластера, а также
создания, чтения и изменения Secret, ConfigMap, PVC, Deployment, Service и
NetworkPolicy, включая Secret, используемый Helm для состояния выпуска. При
отсутствии default StorageClass добавьте к команде `prepare` параметр
`--storage-class YOUR_CLASS`.

```bash
.venv/bin/python signed/0.1.4/scripts/install.py prepare \
  --home "$HOME/uter-k8s" --backend kubernetes --name uter-instance \
  --context MY_CONTEXT --inputs "$PWD/incoming/inputs" \
  --llm-url "$LLM_URL" --llm-model "$LLM_MODEL" --llm-key-file "$LLM_KEY_FILE"
```

До `install` проверьте `ingressNamespace` в созданном `$HOME/uter-k8s/values.yaml`:
по умолчанию разрешён namespace `ingress-nginx`. Если контроллер находится в другом
namespace, укажите его точное имя в этом файле. Затем выполните:

```bash
.venv/bin/python signed/0.1.4/scripts/install.py check --home "$HOME/uter-k8s"
.venv/bin/python signed/0.1.4/scripts/install.py install --home "$HOME/uter-k8s"
kubectl --context MY_CONTEXT -n uter-instance get pods,pvc
kubectl --context MY_CONTEXT -n uter-instance port-forward svc/uter-instance-guardrail 18000:8000
```

В другом терминале выполните `curl --fail http://127.0.0.1:18000/ready`. `check`
делает Helm lint/template; он не проверяет наличие реального namespace, PVC,
сети или LiteLLM. Для приватного registry Kubernetes использует
`--registry-config` с inline `auths`; credential helper в Pod не запускается.

Chart создаёт политики входящего трафика, но не создаёт Ingress и не ограничивает
egress. По умолчанию вход к Guardrail разрешается из namespace `ingress-nginx` и
от Agent. Настройте Ingress, TLS,
маршруты и дополнительные сетевые ограничения отдельно. Их действие, включая
`port-forward`, проверьте на своём CNI: успешный kind-тест с другим CNI не доказывает
работу политики вашего кластера. `resources.yaml` содержит секреты открытым
текстом; Kubernetes Secret сам по себе не обеспечивает шифрование.

## 5. Проверить установленный сервис

Найдите файл `credentials.json` внутри выбранного `--home` и получите пароль `admin`
в защищённом терминале или редакторе. Файл также содержит другие секреты; не
пересылайте его и не записывайте значения в журнал. Из каталога `uter_deploy`:

```bash
.venv/bin/python signed/0.1.4/scripts/smoke_http.py --url http://127.0.0.1:18000
```

Для Kubernetes предварительно оставьте `port-forward` работающим в другом терминале;
для Compose используйте выбранный при `prepare` порт. Скрипт скрыто запросит пароль,
проверит готовность, вход, зависимости и выполнит реальный `/chat` к подключённой
LLM. Успешный `/ready` или статус контейнера `healthy` не заменяет эту проверку.
Тайм-аут каждого запроса smoke — 60 секунд; при холодном запуске CPU-модели
проверьте прогрев и ресурсы LLM, если запрос не успевает завершиться.
На целевом окружении отдельно проверьте применяемую политику, обычные и блокируемые
запросы, аудит, TLS и доступ к реальным данным при необходимости.

`install-state.json` после первичной установки может содержать
`"acceptance":"not-run"`; отдельный ручной smoke не означает, что это поле
автоматически изменено. До включения внешнего трафика зафиксируйте результаты
приёмки и согласуйте доступ через TLS proxy/Ingress. Для `/v1/chat/completions`
нужны оба заголовка: `Authorization: Bearer <JWT>` и
`X-Uter-Ingress-Secret: <openai_ingress_key>`; последний обычно добавляет доверенный
reverse proxy. `/auth/token` принимает `username` и `password` как form-urlencoded,
а `/chat` использует JWT. Не публикуйте Agent, Redis, ключ LiteLLM и ingress-secret.

Например, после настройки TLS-прокси оператор может проверить вход и `/chat` через
его адрес. Замените адрес на свой; пароль вводится скрыто, JWT хранится только в
памяти процесса, а содержимое ответа не печатается:

```bash
export UTER_URL='https://uter.example.internal'
.venv/bin/python - <<'PY'
import getpass
import json
import os
from urllib import error, parse, request

base = os.environ['UTER_URL'].rstrip('/')
username = input('Имя пользователя Uter: ')
password = getpass.getpass('Пароль Uter: ')
form = parse.urlencode({'username': username, 'password': password}).encode()
try:
    req = request.Request(base + '/auth/token', data=form,
                          headers={'Content-Type': 'application/x-www-form-urlencoded'})
    with request.urlopen(req, timeout=60) as response:
        token = json.load(response)['access_token']
    body = json.dumps({'message': 'Hello', 'user_id': 'operator-check'}).encode()
    req = request.Request(base + '/chat', data=body,
                          headers={'Content-Type': 'application/json',
                                   'Authorization': 'Bearer ' + token})
    with request.urlopen(req, timeout=60) as response:
        result = json.load(response)
    print('Вход выполнен; запрос обработан. blocked =', result.get('blocked'))
except error.HTTPError as exc:
    raise SystemExit(f'Uter вернул HTTP {exc.code}; тело ответа скрыто') from None
except (error.URLError, TimeoutError):
    raise SystemExit('Uter недоступен или TLS-проверка не прошла') from None
PY
```

Этот пример не проверяет OpenAI endpoint: для него дополнительно требуется секрет
ingress, который должен добавлять доверенный proxy. Не помещайте этот секрет в
командную строку или клиентский код, доступный недоверенным пользователям.

## 6. Обновление и восстановление

До обновления получите подписанные комплекты текущей и новой версий, независимо
проверьте ключ издателя и допустимость перехода. Создайте отдельные защищённые
каталоги для копий и ключа, проверьте свободное место и согласуйте окно: компоненты
могут быть временно остановлены. Пошаговые команды принятия установки под управление,
обновления, создания зашифрованной копии и её восстановления приведены в
[инструкции по обновлению и восстановлению](managed-update-recovery.md).

Ключ копии храните отдельно и сохраните его защищённую копию вне сервера установки:
без ключа восстановление невозможно. Восстановление создаёт новый проект или namespace
с данными на момент копирования и не переключает трафик автоматически. Внешние
LiteLLM/vLLM, их модели, базы и RAG, ingress, DNS, сертификаты и внешние секреты
резервируются отдельно. Перед переключением проверьте ваши данные и интеграции.
Снимок Redis в текущей реализации ограничен 100 MiB.

Поддерживаемый переход `0.1.2 → 0.1.4` проверялся, но digest образов продукта в
этих выпусках одинаковы. Он подтверждает проверенный процесс обновления и копирования,
а не миграцию данных между различными сборками или совместимость произвольных данных.

## Если что-то не работает

| Симптом | Что проверить |
|---|---|
| `401` от LiteLLM | Правильный ключ, его срок, права на alias и используемые маршруты; не выводите ключ в лог. |
| `403` на OpenAI endpoint Uter | JWT и наличие корректного `X-Uter-Ingress-Secret` от доверенного proxy. |
| `/ready` возвращает `503`, upstream не готов | DNS и сеть из Guardrail, URL и alias LiteLLM, ключ, `/health`, доступ LiteLLM к vLLM и время ответа. Проверка состояния модели может быть медленнее на CPU; не подменяйте её проверкой, которая скрывает отказ vLLM. |
| Ошибка сертификата | DNS/SAN, цепочку и доверенный CA именно внутри Guardrail. Не применяйте `-k` или отключение проверки TLS. Подключение частного CA/mTLS требует отдельного проверенного решения. |
| Pod не готов или PVC Pending | `kubectl ... get pods,pvc`, события, права, StorageClass и доступ к registry; проверьте поддержку NetworkPolicy вашим CNI. |
| Install завершился ошибкой, статус `pending` | Сохраните каталог, данные и секреты; см. раздел «Ошибки, повторный запуск и обновление» в [README](../README.md). Повторный install блокируется, не удаляйте состояние или volumes для обхода проверки. |

Базовая установка — по одному экземпляру каждого сервиса. Внешние TLS, HA,
производительность, пользовательские сетевые политики, RAG и совместимость
конкретных моделей необходимо проверять отдельно; эти шаги не подтверждены одной
успешной установкой.
