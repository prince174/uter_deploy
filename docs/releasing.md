# Выпуск поставки

## Версии

Версия `manifest.version` — версия всего устанавливаемого продукта. Chart.yaml version —
версия шаблонов упаковки. Они независимы. Состав включает ровно три закреплённых образа
первого профиля, исходный commit, config_schema, data_epoch и явный список upgrade_from.
Любое изменение подписанного комплекта требует новой версии manifest. Существующие
релизы не переписываются. Новая сборка образа также получает новый digest и выпуск.

`status=example` не устанавливается. Не меняйте status на released без выполненных
проверок ниже. Сторонние Python-исходники в зависимостях могут оставаться в образе;
цель — исключить собственные исходники Uter, а не нарушить лицензии зависимостей.

## Изолированная сборка продукта

Рецепт `packaging/Dockerfile.protected` — экспериментальная компиляция Nuitka-модулей
под Linux amd64 / CPython 3.12. На реальных образах проверены imports/OpenAPI и офлайн toxicity inference;
полный выпуск требует всех проверок ниже (см. image-validation.md).
Никакого docker build в активном основном стенде не выполнять.

На отдельном Linux builder клонируйте `prince174/uter` в рабочую папку и checkout
точный SHA из кандидата. Этот checkout можно свободно менять: он не является
`G:\code\uter`. Создайте из него исходные base images штатными Dockerfile.
Они содержат исходники — держать только внутри builder, не публиковать:

```bash
docker build -t uter-guardrail-buildbase --build-arg PRELOAD_MODELS=true work/upstream/guardrail
docker build -t uter-agent-buildbase work/upstream/agent
docker build --build-arg SOURCE_IMAGE=uter-guardrail-buildbase -f packaging/Dockerfile.protected -t uter-guardrail-protected packaging
docker build --build-arg SOURCE_IMAGE=uter-agent-buildbase -f packaging/Dockerfile.protected -t uter-agent-protected-base packaging
docker build --build-arg PROTECTED_IMAGE=uter-agent-protected-base -f packaging/Dockerfile.agent -t uter-agent-protected packaging
```

Эти команды скачивают base images, apt/pip зависимости, компилятор и toxicity-модель;
потребляют CPU/RAM/диск и сеть. Результаты не считаются готовыми только потому, что
docker build завершился. Требуется проверить imports, FastAPI/Pydantic, health, auth,
ML, политики, RAG и audit. Runtime ресурсы копировать только по явному списку.
Произвольные JSON/датасеты не копируются. В частности встроенный rag_seed_documents.json
не поставляется: для ingest нужен явно выбранный клиентский набор данных.
CLI-модули скомпилированы, вызывать как `python -c 'import rag_ingest; raise SystemExit(rag_ingest.main())' ...`,
а не `python rag_ingest.py`. TLS завершается на инфраструктуре заказчика.

Компиляция усложняет чтение реализации, не гарантирует защиту от реверса. Строки правил,
промпты и веса моделей могут быть доступны администратору целевого сервера.

## Обязательные проверки перед released

1. Unit/API тесты exact source SHA; затем тесты уже защищённых образов.
2. Экспорт образов, проверка всех слоёв на собственные .py/.pyc, .git, секреты, датасеты.
   `scripts/scan_image_archive.py` — базовый запрет исходников в /app, не полный secrets scanner.
3. Сканирование уязвимостей и секретов, SBOM, перечень лицензий, provenance и runtime-ресурсов.
4. Чистая установка Compose и Helm на отдельном стенде. Проверка рабочего UID, PVC,
   сетей, чтения секретов, хранения аудита, upstream и политик.
5. Обновление с каждой версии из upgrade_from, проверка неудачного обновления и отката.
6. Для air-gap — запуск с пустыми runtime-кешами при запрещённой внешней сети.
7. Записать реальные digest опубликованных образов в новый manifest.

## Подпись

Для первого ключа на защищённой машине:

```python
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
key = Ed25519PrivateKey.generate()
Path('publisher.key').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
Path('publisher.pub').write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
```

Приватный ключ не коммитить; ограничить ACL и перенести в защищённое хранилище.
Публичный ключ передать клиентам независимым доверенным каналом. Это bootstrap-процедура;
автоматическая ротация ключей пока не реализована.

```bash
python scripts/bundle.py --manifest releases/1.0.0.json --output dist/uter-1.0.0 --key /secure/publisher.key
python uterctl.py verify --bundle dist/uter-1.0.0 --key /secure/publisher.pub
```

Подписываются хеши manifest, Compose, chart и документации. Скачиваемые образы проверяются
runtime по digest. Контроллер и его Python-зависимости устанавливаются отдельно из
доверенного tooling release; bundle не исполняет обновлённый контроллер из самого себя.
Пакуйте готовый каталог и выдавайте с release notes и результатами acceptance.
SBOM и provenance храните рядом; перед подписью добавьте их в каталог комплекта, если
расширяете bundle builder. Архив распаковывает оператор доверенным средством.
