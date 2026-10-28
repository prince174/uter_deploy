# Проверка registry и реальной установки — 28.10.2026

## Подтверждённые результаты

Образы из remediation run `40626538293` опубликованы в приватный GHCR без пересборки
продукта. Проверены SHA256 архивов, image ID, отсутствие собственных исходных файлов
по правилам сканера, совпадение source commit Guardrail/Agent и запрет анонимного pull.
Source commit: `2b9590aa2b03d94de94f0db1e63144a0e87aafff`.

[Повторная реальная установка](https://github.com/prince174/uter_deploy/actions/runs/40627054284)
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

Предыдущая версия `deploy-2026.10.28` сохраняется отдельно. Текущая проверка относится
к новым digest из `publication.json` нового установочного комплекта.

## Выбор registry

Основной registry — приватный GHCR. Полный workflow публикации и обеих установок:
[40627054284](https://github.com/prince174/uter_deploy/actions/runs/40627054284), success.
Docker Hub не используется: создание отдельных приватных репозиториев недоступно
в текущих настройках аккаунта. Образы туда не публиковались, подписки не менялись.

## Заключительный прогон

[40627054284](https://github.com/prince174/uter_deploy/actions/runs/40627054284):
оба backend — success. Проверен актуальный `--inputs` и HTTP smoke через опубликованный
локальный порт/port-forward, включая вход и обычный запрос. Результаты:
`installation-compose-evidence/http-smoke.json` и
`installation-kubernetes-evidence/http-smoke.json` — все проверки pass.

Установочный комплект закреплён в prerelease `deploy-2026.10.28-2`:
`installation-inputs.tar.gz` и SHA256. Это не подписанный bundle uterctl.

## Границы результата

- LLM — HTTP fixture; качество реальной модели, Ollama judge и RAG не проверены.
- kind default CNI не обеспечивает NetworkPolicy; проверено создание ресурсов,
  а не фактическая изоляция трафика этим механизмом.
- TLS/Ingress, другой CSI/CNI, arm64, HA, нагрузка и upgrade/rollback версий не проверены.
- Critical/High устранены в проверенных образах. Medium/Low: Guardrail 24/11,
  Agent 22/10, Redis 0/0. [Security-отчёт](security-remediation.md) фиксирует дату
  и границы сканирования; неизвестные уязвимости этим не исключаются.
- Подписанный bundle `uterctl` пока не выпущен. Установочный архив и SHA256
  распространяются в приватном GitHub release; checksum не заменяет независимую подпись.
- Локальный стенд и основной checkout не запускались и не изменялись.

## Воспроизведение

Для проверки из Release в Actions запустите `verify-released-installation.yml`:
выберите release tag как ref и укажите тот же `release_tag`. Для промежуточной
проверки CI-артефакта можно использовать `verify-installation.yml`. Создаются только временные
ресурсы GitHub runner. К реальному окружению эти CI-скрипты применять нельзя.
Артефакты `installation-*-evidence` содержат результаты и очищенные диагностические
логи; секретные env/YAML, kubeconfig и Docker credentials туда не включаются.
