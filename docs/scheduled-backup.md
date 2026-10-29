# Отдельное резервное копирование

Команда `backup_installation.py` создаёт одну зашифрованную копию принятой под
управление установки, не меняя её версию и не устанавливая расписание. Она включается
в следующий подписанный выпуск; опубликованный `0.1.4` её не содержит. Получите и
проверьте новый комплект и ключ издателя независимо, как описано в [README](../README.md).

Во время копирования Guardrail и Agent останавливаются и запускаются снова. Согласуйте
окно и остановите внешние приложения, которые напрямую записывают в Redis или аудит:
команда управляет только компонентами Uter. При сбое проверьте `backup-operation.json`,
состояние компонентов и копии до повторного запуска. Не удаляйте данные и журнал для
обхода проверки. Успех команды проверяет шифрование и структуру копии, но не заменяет
периодическое восстановление и проверку ваших данных. Автоматический smoke при этой
команде не запускается.

## Подготовка и регистрация

Следующий пример предназначен для Linux Compose и выполняется от root. Пути и имена
необходимо заменить на свои. `TOOL` — скрипт из **проверенного подписанного комплекта**,
`PYTHON` — доверенное окружение с зависимостями этого комплекта. Не используйте их из
непроверенного архива. Установка должна быть ранее принята под управление `uterctl`;
см. [принятие и обновление](managed-update-recovery.md).

```bash
sudo install -d -m 700 /srv/uter-backups /srv/uter-backup-keys /srv/uter-backup-identity
# Отдельно скопируйте независимо проверенный публичный ключ в защищённый каталог:
sudo install -m 600 /path/to/trusted-publisher.pem /srv/uter-backup-identity/publisher.pem
```

В родительских каталогах не должно быть записи других пользователей. Каталоги
установки, копий и ключа должны быть раздельными. Файл identity находится вне
установки и каталога копий; для ключа и файла identity требуются приватные каталоги.
Например, указанные здесь абсолютные пути — аргументы команд:

```bash
sudo /path/to/venv/bin/python /path/to/verified-bundle/scripts/backup_installation.py create-key \
  --home /srv/uter-instance --backup-root /srv/uter-backups \
  --backup-key /srv/uter-backup-keys/backup.key

sudo /path/to/venv/bin/python /path/to/verified-bundle/scripts/backup_installation.py register \
  --home /srv/uter-instance --identity-file /srv/uter-backup-identity/identity.json \
  --publisher-key /srv/uter-backup-identity/publisher.pem \
  --expected-backend compose --expected-name uter-instance --expected-context default
```

`create-key` создаёт новый ключ один раз и отказывается его перезаписывать. Если
ключ уже создан при обновлении, используйте его путь и не создавайте новый.
`register` проверяет подпись текущего комплекта, работающие образы и записывает
привязку к выбранной установке без изменения сервисов. В Compose фиксируются ID
daemon и контейнеров, ожидаемые тома и их метки; для Kubernetes — UID namespace,
Deployment и PVC, а также привязка PVC. Регистрация существующий файл не перезаписывает.

Для Kubernetes запускайте команды от владельца каталога установки и kubeconfig,
задайте `--expected-backend kubernetes`, имя установки и явный context. Потребуются
права читать namespace `kube-system`, namespace установки, Deployment, Pod и PVC,
а при копировании — требуемые Secret и ConfigMap. Kubernetes Secret при этом читаются
для шифрования; их значения не должны выводиться в журналы.

Привязка защищает от случайной смены контекста и пересоздания ресурсов, но не от
администратора, контролирующего daemon, кластер или файлы. Не изменяйте kubeconfig,
context и ресурсы параллельно с регистрацией или копированием: проверка и остановка
не являются атомарной операцией инфраструктуры. При замене контейнеров, Deployment,
PVC или восстановлении в новый проект нужно заново подтвердить контур и зарегистрировать
его в **новый** файл identity; старый автоматически не заменяется.

## Создать копию

```bash
sudo /path/to/venv/bin/python /path/to/verified-bundle/scripts/backup_installation.py backup \
  --home /srv/uter-instance --backup-root /srv/uter-backups \
  --backup-key /srv/uter-backup-keys/backup.key \
  --identity-file /srv/uter-backup-identity/identity.json \
  --publisher-key /srv/uter-backup-identity/publisher.pem \
  --expected-backend compose --expected-name uter-instance --expected-context default
```

Команда отказывается от работы при `pending`, смене идентификаторов, неверной подписи,
опасных путях или неподходящем ключе. Вывод содержит путь и ID копии, не ключ.
Снимок Redis пока ограничен 100 МиБ: структурная проверка выполняется во временном
пространстве контейнера Redis. Внешние LLM, модели, RAG, базы, ingress и DNS не
входят в эту копию. Храните копию и ключ на независимых защищённых хранилищах,
проверяйте доступность и периодически выполняйте восстановление в отдельный проект.
Команда не передаёт файлы на другое хранилище и не удаляет старые копии.

## Подключить планировщик

После успешной ручной проверки администратор может добавить **показанную выше команду**
в корпоративный планировщик или `systemd` timer на выбранном сервере. Пример ниже —
шаблон, который нужно заполнить на целевой машине. `/path/to/...` не является рабочим
путём; используйте абсолютные пути доверенного Python и проверенного комплекта.

`/etc/systemd/system/uter-backup.service`:

```ini
[Unit]
Description=Uter verified encrypted backup

[Service]
Type=oneshot
User=root
ExecStart=/path/to/venv/bin/python /path/to/verified-bundle/scripts/backup_installation.py backup --home /srv/uter-instance --backup-root /srv/uter-backups --backup-key /srv/uter-backup-keys/backup.key --identity-file /srv/uter-backup-identity/identity.json --publisher-key /srv/uter-backup-identity/publisher.pem --expected-backend compose --expected-name uter-instance --expected-context default
```

`/etc/systemd/system/uter-backup.timer`:

```ini
[Unit]
Description=Schedule Uter backup

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true
RandomizedDelaySec=5m
Unit=uter-backup.service

[Install]
WantedBy=timers.target
```

Время задаётся в часовом поясе сервера. После сохранения и проверки путей оператор
сам выполняет `sudo systemctl daemon-reload`, затем
`sudo systemctl enable --now uter-backup.timer` и проверяет
`systemctl list-timers uter-backup.timer` и результаты сервиса. Для Kubernetes нужны
свой пользователь, kubeconfig и RBAC; приведённый root-unit не следует без проверки
переносить на кластер. При использовании сетевого хранилища отдельно обеспечьте его
монтирование и доступность до запуска сервиса.

Не помещайте
значение ключа в unit, переменные окружения или аргументы — передаются только пути.
Настройте мониторинг ненулевого exit code, возраста последней успешно восстановленной
копии и свободного места. Планировщик и передача на независимое хранилище сами по себе
не включаются. При несовпадении identity или ошибке резервирования разберите причину;
не создавайте новый pin автоматически ради обхода проверки.

Восстановление и ограничения момента снимка описаны в
[инструкции по обновлению и восстановлению](managed-update-recovery.md).
