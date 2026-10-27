# Проверка registry и реальной установки — 27.10.2026

## Подтверждённые результаты

Образы из hardening run `40382405393` опубликованы в приватный GHCR без пересборки
продукта. Проверены SHA256 архивов, image ID, отсутствие собственных исходных файлов
по правилам сканера, совпадение source commit Guardrail/Agent и запрет анонимного pull.
Source commit: `04c13238e2182ddb870d39d499d677e0a539d21f`.

[Повторная реальная установка](https://github.com/prince174/uter_deploy/actions/runs/40531415005)
прошла для Compose и Kubernetes. Использовались `prepare`, `check`, `install` из
репозитория, сгенерированные секреты и настоящие registry digest. Конфигурация сервисов
после prepare не подменялась. Compose использовал документированный CPU-параметр 2.

| Проверка | Compose | Kubernetes |
|---|---|---|
| Скачивание приватных образов по digest | PASS | PASS через imagePullSecret |
| Первый запуск и readiness | PASS | PASS; PVC Redis/audit Bound |
| Внешний локальный `/ready` | PASS | PASS через port-forward |
| Вход с сгенерированным паролем | PASS | PASS |
| Обычный запрос и блокировка инъекции | PASS | PASS |
| Блокировка PII в ответе LLM | PASS | PASS |
| OpenAI API, отказ без ingress-secret | PASS | PASS |
| Agent требует авторизацию | PASS | PASS |
| Реальная offline toxicity-модель | PASS | PASS |
| Перезапуск Redis, Agent, Guardrail | PASS | PASS |
| Повторные запросы и HMAC-цепочка аудита | PASS | PASS |

Kubernetes: kind 0.33.0, node 1.35.8, один узел, standard/local-path PVC.
Сравниваются начальный SHA256 первой строки аудита и рост количества записей после
перезапуска; цепочка проверяется кодом аудита сервиса. Это не тест восстановления
из резервной копии и не межверсионное обновление.

Первый прогон `40530426483` успешно опубликовал образы и установил оба окружения,
но API-тест завершился ошибкой: не передавал включённый установщиком ingress-secret.
Исправлен именно тест, защита endpoint не отключалась. Полный первый run не считается
успешным; успешная повторная проверка приведена выше.

## Выбор registry

Основной registry — приватный GHCR. Полный workflow публикации и обеих установок:
[40531593278](https://github.com/prince174/uter_deploy/actions/runs/40531593278), success.
Docker Hub не используется: создание отдельных приватных репозиториев недоступно
в текущих настройках аккаунта. Образы туда не публиковались, подписки не менялись.

## Границы результата

- LLM — HTTP fixture; качество реальной модели, Ollama judge и RAG не проверены.
- kind default CNI не обеспечивает NetworkPolicy; проверено создание ресурсов,
  а не фактическая изоляция трафика этим механизмом.
- TLS/Ingress, другой CSI/CNI, arm64, HA, нагрузка и upgrade/rollback версий не проверены.
- Findings зависимостей не устранены этой публикацией. Последний security-отчёт:
  Guardrail 0 Critical / 44 High; Agent 5 Critical / 67 High. Это не security approval.
- Подписанный bundle `uterctl` пока не выпущен. Установочный архив и SHA256
  распространяются в приватном GitHub release; checksum не заменяет независимую подпись.
- Локальный стенд и основной checkout не запускались и не изменялись.

## Воспроизведение

В Actions запустите `verify-installation.yml`: `artifact_run_id` — run с артефактом
`installation-inputs`, `registry` — `ghcr.io`. Создаются только временные
ресурсы GitHub runner. К реальному окружению эти CI-скрипты применять нельзя.
Артефакты `installation-*-evidence` содержат результаты и очищенные диагностические
логи; секретные env/YAML, kubeconfig и Docker credentials туда не включаются.
