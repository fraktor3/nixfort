# S-002 — Развёртывание контроллера NIXFORT на nx-controller (выполняет Cursor)

| Поле | Значение |
|---|---|
| Зависит от | S-001; репозиторий запушен на GitHub (`fraktor3/nixfort`, private) |
| Код | **не менять** `app/`, `agent/`, `deploy/`. Ошибки — в отчёт с полным выводом |
| Читать | `README.md` (раздел «Запуск контроллера»), `docs/ARCHITECTURE.md` §1, §10, `docs/DECISIONS.md` ADR-020, ADR-021 |

## Цель
Поднять контроллер в Docker Compose на nx-controller, прогнать тесты внутри контейнера, войти в веб-интерфейс с Windows и завести модель стенда.

## Шаги
1. **Сохранить ключ из S-001.** На nx-controller: `mv ~/nixfort ~/nixfort-s001` (там `secrets/controller_ed25519` — его публичную часть уже знают агенты; ключ НЕ пересоздавать).
2. **Доступ к приватному репозиторию.** На nx-controller: `ssh-keygen -t ed25519 -N "" -C nx-controller-deploy -f ~/.ssh/github_nixfort` и вывести `~/.ssh/github_nixfort.pub`. **Руководитель** добавляет эту строку на GitHub: репозиторий → Settings → Deploy keys → Add deploy key (без права записи). Затем на nx-controller в `~/.ssh/config`:
   ```
   Host github.com
     IdentityFile ~/.ssh/github_nixfort
     IdentitiesOnly yes
   ```
   и `git clone git@github.com:fraktor3/nixfort.git ~/nixfort`.
3. **Перенести ключ:** `mkdir -p ~/nixfort/secrets && cp ~/nixfort-s001/secrets/controller_ed25519* ~/nixfort/secrets/`.
4. На nx-controller в `~/nixfort`: `make env`, `make tls`, `make keys`, `make up`. Сборка займёт несколько минут (нужен интернет через NAT-адаптер).
5. Проверки (сохранить вывод):
   - `make ps` — postgres/redis/web healthy, воркеры, beat и nginx running;
   - `docker compose exec web id` → `uid=10001(nixfort)`;
   - `docker compose exec worker-mutation ls -l /run/secrets/` → ключ читается только uid 10001;
   - `curl -sk https://127.0.0.1/healthz` → `{"status": "ok"}`;
   - `curl -sI http://127.0.0.1/` → 301 на https;
   - `make itest` → все тесты passed (указать число).
6. **Руководитель** выполняет `make createadmin` (пароль вводит сам, не через Cursor).
7. С Windows открыть `https://127.0.0.1:8443` (самоподписанный сертификат — принять исключение), войти администратором.
8. В интерфейсе (руководитель или Cursor через браузер — по желанию руководителя):
   - проект «Стенд NIXFORT»: подсети `10.77.0.0/24, 10.88.0.0/24, 10.99.0.0/24`, контроллер `10.77.0.10`;
   - узлы: `nx-gateway` 10.77.0.20, рабочие 10.88.0.1, 10.99.0.1, роли «Шлюз» + «Датчик IDS», интерфейс `enp0s9`, порты 22; `nx-server` 10.77.0.30, рабочий 10.99.0.10, роль «Сервер», порты 22, 80; `nx-client` 10.77.0.40, рабочий 10.88.0.10, роль «Тестовый клиент», порты 22;
   - для каждого узла вставить открытый ключ (`ssh nx-server cat /etc/ssh/ssh_host_ed25519_key.pub` и т.д.), сверить отпечаток с `lab/reports/S-001-*.md` и подтвердить;
   - политика: (1) «Веб-сервер» 10.88.0.0/24 → nx-server 10.99.0.10:80 ALLOW, критичный, проба с nx-client; (2) «Лишний сервис» 10.88.0.0/24 → 10.99.0.10:8080 DENY, проба с nx-client; (3) «SSH из сети пользователей» 10.88.0.0/24 → 10.99.0.10:22 DENY, проба с nx-client. Активировать.
   - на странице проекта нажать «Тестовое задание» → состояние «Успешно».
   - **Негатив:** создать пользователя-наблюдателя, войти им и убедиться, что кнопок изменения нет, а прямой URL `/projects/<id>/edit/` даёт 403; 6 неверных паролей подряд → блокировка; всё видно в «Журнале действий».
9. Скриншоты ключевых страниц — в `lab/reports/S-002/` (без паролей).

## Отчёт
`lab/reports/S-002-<дата>.md`: вывод команд п.5, число тестов, что сделано в п.8, любые ошибки целиком. Руководитель коммитит и пишет архитектору «S-002 готово».
